use std::path::Path;

#[allow(dead_code)]
pub struct DB {}

#[allow(dead_code)]
impl DB {
    pub fn new<P: AsRef<Path>>(_path: P) -> Self {
        Self {}
    }
}

// use rocksdb::{ColumnFamilyDescriptor, BlockBasedOptions, Options, DB,
// DBError};

// pub fn open() -> Result<DB, DBError>
//  {
//     let path = "./.anoma/db";
//     let mut cf_opts = Options::default();
//     // ! recommended initial setup https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#other-general-options
//     cf_opts.set_level_compaction_dynamic_level_bytes(true);
//     // compactions + flushes
//     cf_opts.set_max_background_jobs(6);
//     cf_opts.set_bytes_per_sync(1048576);
//     // TODO the recommended `options.compaction_pri = kMinOverlappingRatio`
// doesn't     // seem to be available in Rust
//     let mut table_options = BlockBasedOptions::default();
//     table_options.set_block_size(16 * 1024);
//     table_options.set_cache_index_and_filter_blocks(true);
//     table_options.set_pin_l0_filter_and_index_blocks_in_cache(true);
//     // format versions https://github.com/facebook/rocksdb/blob/d1c510baecc1aef758f91f786c4fbee3bc847a63/include/rocksdb/table.h#L394
//     table_options.set_format_version(5);
//     cf_opts.set_block_based_table_factory(&table_options);

//     cf_opts.create_missing_column_families(true);
//     cf_opts.create_if_missing(true);

//     let cf = ColumnFamilyDescriptor::new("cf1", cf_opts);
//     DB::open_cf_descriptors(&db_opts, path, vec![cf])
// }
