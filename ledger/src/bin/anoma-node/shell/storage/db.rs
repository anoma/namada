use rocksdb::{BlockBasedOptions, Options, DB};
use std::path::Path;

#[derive(Debug, Clone)]
pub enum Error {
    RocksDBError(rocksdb::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn open<P: AsRef<Path>>(path: P) -> Result<DB> {
    let mut cf_opts = Options::default();
    // ! recommended initial setup https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#other-general-options
    cf_opts.set_level_compaction_dynamic_level_bytes(true);
    // compactions + flushes
    cf_opts.set_max_background_jobs(6);
    cf_opts.set_bytes_per_sync(1048576);
    // TODO the recommended default `options.compaction_pri =
    // kMinOverlappingRatio` doesn't seem to be available in Rust
    let mut table_opts = BlockBasedOptions::default();
    table_opts.set_block_size(16 * 1024);
    table_opts.set_cache_index_and_filter_blocks(true);
    table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
    // latest format versions https://github.com/facebook/rocksdb/blob/d1c510baecc1aef758f91f786c4fbee3bc847a63/include/rocksdb/table.h#L394
    table_opts.set_format_version(5);
    cf_opts.set_block_based_table_factory(&table_opts);

    cf_opts.create_missing_column_families(true);
    cf_opts.create_if_missing(true);

    // TODO use column families
    DB::open_cf_descriptors(&cf_opts, path, vec![]).map_err(Error::RocksDBError)
}

// pub fn write_batch(db: DB, data: Vec<(Box<[u8]>, Box<[u8]>)>) -> Result<()> {
//     let mut batch = WriteBatch::default();
//     data.iter().for_each(|(key, value)| batch.put(key, value));
//     db.write(batch).map_err(Error::RocksDBError)
// }
