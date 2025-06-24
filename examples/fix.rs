use borsh::BorshDeserialize;
use namada_apps_lib::state::FullAccessState;
use namada_apps_lib::tendermint_config::DbBackend::RocksDb;
use namada_core::borsh::BorshSerializeExt;
use namada_core::chain::BlockHeight;
use namada_core::storage::SUBSPACE_CF;
use namada_node::storage;
use namada_node::storage::{
    PersistentDB, PersistentStorageHasher, RocksDBWriteBatch,
};
use namada_parameters::ReadError;
use namada_sdk::storage::DB;
use std::path::PathBuf;

pub fn main() {
    let db =
        storage::PersistentDB::open("housefire-alpaca.cc0d3e0c033be/db", None);
    let max_tx_bytes_key = namada_parameters::storage::get_max_tx_bytes_key();

    let value = db.read_subspace_val(&max_tx_bytes_key).unwrap().unwrap();
    let val = u64::try_from_slice(&value).unwrap();
    let val = val as u32;
    println!("value: {val}");
    let mut batch = RocksDBWriteBatch::default();
    let subspace_cf = db.get_column_family(SUBSPACE_CF).unwrap();
    batch.0.put_cf(
        subspace_cf,
        max_tx_bytes_key.to_string(),
        val.serialize_to_vec(),
    );
    db.exec_batch(batch).unwrap();
    db.flush(true).unwrap();
}
