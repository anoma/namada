use std::collections::BTreeMap;
use std::path::PathBuf;

use data_encoding::HEXLOWER;
use namada_sdk::signing::to_ledger_vector;
use namada_sdk::testing::arb_signed_tx;
use namada_sdk::wallet::fs::FsWalletUtils;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};

#[tokio::main]
async fn main() -> Result<(), Reason> {
    let mut runner = TestRunner::default();
    let wallet = FsWalletUtils::new(PathBuf::from("wallet.toml"));
    let mut debug_vectors = vec![];
    let mut test_vectors = vec![];
    for i in 0..1000 {
        let (tx, tx_data) = arb_signed_tx().new_tree(&mut runner)?.current();
        let mut ledger_vector = to_ledger_vector(&wallet, &tx)
            .await
            .expect("unable to construct test vector");
        let sechashes = tx.sechashes();
        let mut sechash_map = BTreeMap::new();
        for (idx, sechash) in sechashes.iter().enumerate() {
            sechash_map.insert(idx as u8, HEXLOWER.encode(&sechash.0));
        }
        sechash_map.insert(0xff, HEXLOWER.encode(&tx.raw_header_hash().0));
        ledger_vector.name = format!("{}_{}", i, ledger_vector.name);
        test_vectors.push(ledger_vector.clone());
        debug_vectors.push((ledger_vector, tx, tx_data, sechash_map));
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: namada-generator <vectors.json> <debugs.txt>");
        return Result::Err(Reason::from("Incorrect command line arguments."));
    }
    let json = serde_json::to_string(&test_vectors)
        .expect("unable to serialize test vectors");
    std::fs::write(&args[1], json).expect("unable to save test vectors");
    std::fs::write(&args[2], format!("{:#?}", debug_vectors))
        .expect("unable to save test vectors");
    Ok(())
}
