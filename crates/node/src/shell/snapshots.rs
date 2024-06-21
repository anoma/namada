use borsh_ext::BorshSerializeExt;
use namada_sdk::hash::{Hash, Sha256Hasher};
use namada_sdk::state::BlockHeight;

use super::{Error, Result};
use crate::facade::tendermint::abci::types::Snapshot;
use crate::facade::tendermint::v0_37::abci::{
    request as tm_request, response as tm_response,
};
use crate::shell::Shell;
use crate::storage;
use crate::storage::{DbSnapshot, SnapshotMetadata};

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
                    let hash = Hash::sha256(chunks.serialize_to_vec()).0;
                    Snapshot {
                        height: u32::try_from(height.0).unwrap().into(),
                        format: 0,
                        #[allow(clippy::cast_possible_truncation)]
                        chunks: chunks.len() as u32,
                        hash: hash.into_iter().collect(),
                        metadata: Default::default(),
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
}
