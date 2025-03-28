use std::io::Write;

use namada_sdk::arith::checked;
use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_sdk::hash::{Hash, Sha256Hasher};
use namada_sdk::state::{BlockHeight, StorageRead};

use super::SnapshotSync;
use crate::shell::Shell;
use crate::storage;
use crate::storage::{DbSnapshot, DbSnapshotMeta};
use crate::tendermint::abci::types::Snapshot;
use crate::tendermint::abci::{
    ApplySnapshotChunkResult, request as tm_request, response as tm_response,
};

pub const MAX_SENDER_STRIKES: u64 = 5;

impl Shell<storage::PersistentDB, Sha256Hasher> {
    /// List the snapshot files held locally. Furthermore, the number
    /// of chunks, as hash of each chunk, and a hash of the chunk
    /// metadata are provided so that syncing nodes can verify
    /// snapshots they receive.
    pub fn list_snapshots(&self) -> tm_response::ListSnapshots {
        if self.blocks_between_snapshots.is_none() {
            Default::default()
        } else {
            tracing::info!("Request for snapshots received.");
            let Ok(snapshot_heights) =
                DbSnapshot::heights_of_stored_snapshots(&self.base_dir)
            else {
                tracing::debug!("Could not read heights of stored snapshots");
                return Default::default();
            };
            let snapshots = DbSnapshot::load_snapshot_metadata(
                &self.base_dir,
                snapshot_heights,
            );
            let Ok(snapshots) = snapshots
                .map(|result| {
                    let DbSnapshotMeta {
                        height,
                        chunk_hashes,
                        root_hash,
                    } = result?;
                    std::io::Result::Ok(Snapshot {
                        height: u32::try_from(height.0).unwrap().into(),
                        format: DbSnapshot::FORMAT_MAGIC,
                        #[allow(clippy::cast_possible_truncation)]
                        chunks: chunk_hashes.len() as u32,
                        hash: root_hash.0.to_vec().into(),
                        metadata: chunk_hashes.serialize_to_vec().into(),
                    })
                })
                .collect()
            else {
                tracing::debug!("Could not read stored snapshot meta");
                return Default::default();
            };

            tm_response::ListSnapshots { snapshots }
        }
    }

    /// Load the bytes of a requested chunk and return them
    /// to cometbft.
    pub fn load_snapshot_chunk(
        &self,
        req: tm_request::LoadSnapshotChunk,
    ) -> tm_response::LoadSnapshotChunk {
        let chunk = match DbSnapshot::load_chunk(
            BlockHeight(req.height.into()),
            u64::from(req.chunk),
            &self.base_dir,
        ) {
            Ok(chunk) => chunk,
            Err(err) => {
                tracing::debug!(
                    ?req,
                    error = %err,
                    "Received a request for a snapshot we do not possess"
                );
                // N.B. if the snapshot is no longer present,
                // this will not match the hash in the metadata and will
                // be rejected by syncing nodes. We don't return an error
                // so as not to crash this node.
                return Default::default();
            }
        };
        tracing::info!(
            "Loading snapshot at height {}, chunk number {}",
            req.height,
            req.chunk,
        );
        tm_response::LoadSnapshotChunk {
            chunk: chunk.into(),
        }
    }

    /// Decide if a snapshot should be accepted to sync the node forward in time
    pub fn offer_snapshot(
        &mut self,
        req: tm_request::OfferSnapshot,
    ) -> tm_response::OfferSnapshot {
        if req.snapshot.format != DbSnapshot::FORMAT_MAGIC {
            tracing::debug!(
                format = req.snapshot.format,
                "Received snapshot with an incompatible format"
            );
            return tm_response::OfferSnapshot::Reject;
        }
        match self.syncing.as_ref() {
            None => {
                #[allow(clippy::disallowed_methods)]
                if self.state.get_block_height().unwrap_or_default().0
                    < u64::from(req.snapshot.height)
                {
                    let Ok(chunks) =
                        Vec::<Hash>::try_from_slice(&req.snapshot.metadata)
                    else {
                        return tm_response::OfferSnapshot::Reject;
                    };
                    self.syncing = Some(SnapshotSync {
                        next_chunk: 0,
                        height: u64::from(req.snapshot.height).into(),
                        expected: chunks,
                        strikes: 0,
                        snapshot: tempfile::tempfile()
                            .expect("Failed to create snapshot temp file"),
                    });
                    tracing::info!("Accepting snapshot offer");
                    tm_response::OfferSnapshot::Accept
                } else {
                    tracing::info!("Rejecting snapshot offer");
                    tm_response::OfferSnapshot::Reject
                }
            }
            Some(snapshot_sync) => {
                if snapshot_sync.height.0 < u64::from(req.snapshot.height) {
                    let Ok(chunks) =
                        Vec::<Hash>::try_from_slice(&req.snapshot.metadata)
                    else {
                        tracing::info!("Rejecting snapshot offer");
                        return tm_response::OfferSnapshot::Reject;
                    };
                    self.syncing = Some(SnapshotSync {
                        next_chunk: 0,
                        height: u64::from(req.snapshot.height).into(),
                        expected: chunks,
                        strikes: 0,
                        snapshot: tempfile::tempfile()
                            .expect("Failed to create snapshot temp file"),
                    });
                    tracing::info!("Accepting snapshot offer");
                    tm_response::OfferSnapshot::Accept
                } else {
                    tracing::info!("Rejecting snapshot offer");
                    tm_response::OfferSnapshot::Reject
                }
            }
        }
    }

    /// Write a snapshot chunk to the database
    pub fn apply_snapshot_chunk(
        &mut self,
        req: tm_request::ApplySnapshotChunk,
    ) -> tm_response::ApplySnapshotChunk {
        let Some(snapshot_sync) = self.syncing.as_mut() else {
            tracing::warn!("Received a snapshot although none were requested");
            // if we are not currently syncing, abort this sync protocol the
            // syncing status is set by `OfferSnapshot`.
            return tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::Abort,
                refetch_chunks: vec![],
                reject_senders: vec![],
            };
        };

        // make sure we have been given the correct chunk
        if u64::from(req.index) != snapshot_sync.next_chunk {
            tracing::error!(
                "Received wrong chunk, expected {}, got {}",
                snapshot_sync.next_chunk,
                req.index,
            );
            return tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::Unknown,
                refetch_chunks: vec![
                    u32::try_from(snapshot_sync.next_chunk).unwrap(),
                ],
                reject_senders: vec![],
            };
        }

        let Some(expected_hash) =
            snapshot_sync.expected.get(req.index as usize)
        else {
            tracing::error!(
                "Received more chunks than expected; rejecting snapshot"
            );
            self.syncing = None;
            // if we get more chunks than expected, there is something wrong
            // with this snapshot and we should reject it.
            return tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::RejectSnapshot,
                refetch_chunks: vec![],
                reject_senders: vec![],
            };
        };

        // check that the chunk matches the expected hash, otherwise
        // re-fetch it in case it was corrupted. If the chunk fails
        // to validate too many times, we reject the snapshot and sender.
        let chunk_hash = Hash::sha256(&req.chunk);
        if *expected_hash != chunk_hash {
            tracing::error!(
                "Hash of chunk did not match, expected {}, got {}",
                expected_hash,
                chunk_hash,
            );
            snapshot_sync.strikes =
                checked!(snapshot_sync.strikes + 1).unwrap();
            if snapshot_sync.strikes == MAX_SENDER_STRIKES {
                snapshot_sync.strikes = 0;
                self.syncing = None;

                tracing::info!(
                    "Max number of strikes reached on chunk, rejecting \
                     snapshot"
                );
                return tm_response::ApplySnapshotChunk {
                    result: ApplySnapshotChunkResult::RejectSnapshot,
                    refetch_chunks: vec![],
                    reject_senders: vec![req.sender],
                };
            } else {
                return tm_response::ApplySnapshotChunk {
                    result: ApplySnapshotChunkResult::Retry,
                    refetch_chunks: vec![req.index],
                    reject_senders: vec![],
                };
            }
        } else {
            snapshot_sync.strikes = 0;
        };

        // write snapshot chunk
        snapshot_sync
            .snapshot
            .write_all(&req.chunk)
            .expect("Failed to save snapshot chunk");

        // increment the chunk counter
        snapshot_sync.next_chunk =
            checked!(snapshot_sync.next_chunk + 1).unwrap();

        // check if all chunks have been saved, and restore the
        // database from the fetched tar archive
        if snapshot_sync.next_chunk == snapshot_sync.expected.len() as u64 {
            self.restore_database_from_state_sync();
            self.syncing = None;
            tracing::info!("Snapshot completely applied");
        }

        tm_response::ApplySnapshotChunk {
            result: ApplySnapshotChunkResult::Accept,
            refetch_chunks: vec![],
            reject_senders: vec![],
        }
    }
}
