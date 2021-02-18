mod storage;
mod tendermint;

use self::storage::{Balance, BasicAddress, Storage, ValidatorAddress};
use anoma::{
    config::Config,
    types::{Message, Transaction},
};
use std::path::Path;

pub fn run(config: Config) {
    // run our shell via Tendermint ABCI
    let db_path = config.home_dir.join("store.db");
    let shell = Shell::new(db_path);
    let addr = "127.0.0.1:26658".parse().unwrap();
    tendermint::run(config, addr, shell)
}

pub fn reset(config: Config) {
    tendermint::reset(config)
}

pub struct Shell {
    storage: storage::Storage,
}

pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
    NewTransaction,
    /// A transaction that has been validated at some previous level that may
    /// need to be validated again
    RecheckTransaction,
}
pub type MempoolValidationResult<'a> = Result<(), String>;
pub type ApplyResult<'a> = Result<(), String>;

pub struct MerkleRoot(pub Vec<u8>);

impl Shell {
    pub fn new<P: AsRef<Path>>(_db_path: P) -> Self {
        let mut storage = Storage::new();
        storage
            .update_balance(
                ValidatorAddress::new_address("va".to_owned()),
                Balance::new(10000),
            )
            .unwrap();
        storage
            .update_balance(
                BasicAddress::new_address("ba".to_owned()),
                Balance::new(100),
            )
            .unwrap();
        Self { storage }
    }
}

impl Shell {
    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    pub fn mempool_validate(
        &mut self,
        tx_bytes: &[u8],
        _prevalidation_type: MempoolTxType,
    ) -> MempoolValidationResult {
        let _tx = Transaction::decode(&tx_bytes[..]).map_err(|e| {
            format!(
                "Error decoding a transaction: {}, from bytes  from bytes {:?}",
                e, tx_bytes
            )
        })?;

        // Validation logic
        // TODO if c != self.count + 1 {
        //     return Err(String::from("Count must be incremental!"));
        // }
        // Update state to keep state correct for next validation call
        // TODO
        Ok(())
    }

    /// Validate and apply a transaction.
    pub fn apply_tx(&mut self, tx_bytes: &[u8]) -> ApplyResult {
        let tx = Transaction::decode(&tx_bytes[..]).map_err(|e| {
            format!(
                "Error decoding a transaction: {}, from bytes  from bytes {:?}",
                e, tx_bytes
            )
        })?;

        let src_addr = BasicAddress::new_address(tx.src);
        let dest_addr = BasicAddress::new_address(tx.dest);
        self.storage.transfer(src_addr, dest_addr, tx.amount)?;

        Ok(())
    }

    /// Persist the application state and return the Merkle root hash.
    pub fn commit(&mut self) -> MerkleRoot {
        // TODO store the block's data in DB
        let root = self.storage.merkle_root();
        MerkleRoot(root.as_slice().to_vec())
    }

    /// Load the Merkle root hash and the height of the last committed block, if
    /// any.
    pub fn last_state(&self) -> Option<(MerkleRoot, u64)> {
        // TODO
        None
    }
}
