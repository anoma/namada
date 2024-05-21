//! Node utils commands handlers

use std::str::FromStr;

use namada_apps_lib::cli::args::TestGenesis;
use namada_apps_lib::config::genesis;

pub fn test_genesis(args: TestGenesis) {
    use crate::facade::tendermint::Timeout;

    let templates = genesis::templates::load_and_validate(&args.path).unwrap();
    let genesis = genesis::chain::finalize(
        templates,
        FromStr::from_str("namada-dryrun").unwrap(),
        Default::default(),
        Timeout::from_str("30s").unwrap(),
    );
    let chain_id = &genesis.metadata.chain_id;
    let test_dir = tempfile::tempdir().unwrap();
    let config = crate::config::Config::load(test_dir.path(), chain_id, None);
    genesis
        .write_toml_files(&test_dir.path().join(chain_id.to_string()))
        .unwrap();
    crate::test_genesis_files(config.ledger, genesis, args.wasm_dir);
}
