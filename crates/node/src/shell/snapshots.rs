use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use namada::core::arith::checked;
use namada::hash::{Hash, Sha256Hasher};
use namada::state::{BlockHeight, StorageRead, DB};

use super::{Error, Result, SnapshotSync};
use crate::facade::tendermint::abci::response::ApplySnapshotChunkResult;
use crate::facade::tendermint::abci::types::Snapshot;
use crate::facade::tendermint::v0_37::abci::{
    request as tm_request, response as tm_response,
};
use crate::shell::Shell;
use crate::storage;
use crate::storage::{DbSnapshot, SnapshotMetadata};

pub const MAX_SENDER_STRIKES: u64 = 5;
impl Shell<storage::PersistentDB, Sha256Hasher> {
    /// List the snapshot files held locally. Furthermore, the number
    /// of chunks, as hash of each chunk, and a hash of the chunk
    /// metadata are provided so that syncing nodes can verify can verify
    /// snapshots they receive.
    pub fn list_snapshots(&self) -> Result<tm_response::ListSnapshots> {
        if self.blocks_between_snapshots.is_none() {
            Ok(Default::default())
        } else {
            let snapshots = DbSnapshot::files(&self.base_dir)
                .map_err(Error::Snapshot)?
                .into_iter()
                .map(|SnapshotMetadata { height, chunks, .. }| {
                    let hashes =
                        chunks.iter().map(|c| c.hash).collect::<Vec<_>>();
                    let hash = Hash::sha256(hashes.serialize_to_vec()).0;
                    Snapshot {
                        height: u32::try_from(height.0).unwrap().into(),
                        format: 0,
                        #[allow(clippy::cast_possible_truncation)]
                        chunks: chunks.len() as u32,
                        hash: hash.into_iter().collect(),
                        metadata: hashes.serialize_to_vec().into(),
                    }
                })
                .collect();

            Ok(tm_response::ListSnapshots { snapshots })
        }
    }

    /// Load the bytes of a requested chunk and return them
    /// to cometbft.
    pub fn load_snapshot_chunk(
        &self,
        req: tm_request::LoadSnapshotChunk,
    ) -> Result<tm_response::LoadSnapshotChunk> {
        let chunk = DbSnapshot::load_chunk(
            BlockHeight(req.height.into()),
            u64::from(req.chunk),
            &self.base_dir,
        )
        .map_err(Error::Snapshot)?;
        Ok(tm_response::LoadSnapshotChunk {
            chunk: chunk.into_iter().collect(),
        })
    }

    /// Decide if a snapshot should be accepted to sync the node forward in time
    pub fn offer_snapshot(
        &mut self,
        req: tm_request::OfferSnapshot,
    ) -> tm_response::OfferSnapshot {
        match self.syncing.as_ref() {
            None => {
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
                    });
                    tm_response::OfferSnapshot::Accept
                } else {
                    tm_response::OfferSnapshot::Reject
                }
            }
            Some(snapshot_sync) => {
                if snapshot_sync.height.0 < u64::from(req.snapshot.height) {
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
                    });
                    tm_response::OfferSnapshot::Accept
                } else {
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
            // if we are not currently syncing, abort this sync protocol
            // the syncing status is set by `OfferSnapshot`.
            return tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::Abort,
                refetch_chunks: vec![],
                reject_senders: vec![],
            };
        };

        // make sure we have been given the correct chunk
        if u64::from(req.index) != snapshot_sync.next_chunk {
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
            snapshot_sync.strikes =
                checked!(snapshot_sync.strikes + 1).unwrap();
            if snapshot_sync.strikes == MAX_SENDER_STRIKES {
                snapshot_sync.strikes = 0;
                self.syncing = None;

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
        };
        // when we first start applying a snapshot,
        // clear the existing db.
        if req.index == 0 {
            self.state.db_mut().clear(snapshot_sync.height).unwrap();
        }
        // apply snapshot changes to the database
        // retry if an error occurs
        let mut batch = Default::default();
        for (cf, key, value) in DbSnapshot::parse_chunk(&req.chunk) {
            if self
                .state
                .db()
                .insert_entry(&mut batch, None, &cf, &key, value)
                .is_err()
            {
                return tm_response::ApplySnapshotChunk {
                    result: ApplySnapshotChunkResult::Retry,
                    refetch_chunks: vec![],
                    reject_senders: vec![],
                };
            }
        }
        if self.state.db().exec_batch(batch).is_err() {
            return tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::Retry,
                refetch_chunks: vec![],
                reject_senders: vec![],
            };
        }

        // increment the chunk counter
        snapshot_sync.next_chunk =
            checked!(snapshot_sync.next_chunk + 1).unwrap();
        // check if all chunks have been applied
        if snapshot_sync.next_chunk == snapshot_sync.expected.len() as u64 {
            self.syncing = None;
            // rebuild the in-memory state
            self.state.load_last_state();
        }

        tm_response::ApplySnapshotChunk {
            result: ApplySnapshotChunkResult::Accept,
            refetch_chunks: vec![],
            reject_senders: vec![],
        }
    }
}
