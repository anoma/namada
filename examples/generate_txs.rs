use std::path::PathBuf;

use data_encoding::HEXLOWER;
use namada_sdk::signing::to_ledger_vector;
use namada_sdk::testing::arb_signed_tx;
use namada_sdk::wallet::fs::FsWalletUtils;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};
use serde::{Deserialize, Serialize};

/// Represents the transaction data that is necessary for testing signing
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
struct ZemuTestData {
    // Name of the test case
    name: String,
    // Serialization of test case transaction
    blob: String,
    // Indices of the sections of this transaction
    #[serde(rename = "sectionIndices")]
    section_indices: Vec<u8>,
    // Hashes of the sections of this transaction
    #[serde(rename = "sectionHashes")]
    section_hashes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Reason> {
    let args: Vec<_> = std::env::args().collect();
    let usage = "Usage: generate-txs <N> <vectors.json> <zemu_vectors.json> \
                 <debugs.txt> <txs.json (optional)>";
    if args.len() < 5 {
        eprintln!("{}", usage);
        return Result::Err(Reason::from("Incorrect command line arguments."));
    }
    let Ok(num_vectors) = args[1].parse() else {
        eprintln!("{}", usage);
        return Result::Err(Reason::from("Incorrect command line arguments."));
    };
    let mut runner = TestRunner::deterministic();
    let wallet = FsWalletUtils::new(PathBuf::from("wallet.toml"));
    let mut debug_vectors = vec![];
    let mut zemu_test_vectors = vec![];
    let mut test_vectors = vec![];
    let mut serialized_txs = vec![];
    for i in 0..num_vectors {
        let (tx, tx_data) = arb_signed_tx().new_tree(&mut runner)?.current();
        let mut ledger_vector = to_ledger_vector(&wallet, &tx)
            .await
            .expect("unable to construct test vector");
        let mut zemu_test_data = ZemuTestData::default();
        let sechashes = tx.sechashes();
        for (idx, sechash) in sechashes.iter().enumerate() {
            zemu_test_data.section_indices.push(idx as u8);
            zemu_test_data
                .section_hashes
                .push(HEXLOWER.encode(&sechash.0));
        }
        zemu_test_data.section_indices.push(0xff);
        zemu_test_data
            .section_hashes
            .push(HEXLOWER.encode(&tx.raw_header_hash().0));
        ledger_vector.name = format!("{}_{}", i, ledger_vector.name);
        zemu_test_data.name = ledger_vector.name.clone();
        zemu_test_data.blob = ledger_vector.blob.clone();
        test_vectors.push(ledger_vector.clone());
        zemu_test_vectors.push(zemu_test_data);
        debug_vectors.push((ledger_vector, tx.clone(), tx_data));
        serialized_txs.push(HEXLOWER.encode(tx.to_bytes().as_ref()));
    }
    let json = serde_json::to_string(&test_vectors)
        .expect("unable to serialize test vectors");
    std::fs::write(&args[2], json).expect("unable to save test vectors");
    let zemu_json = serde_json::to_string(&zemu_test_vectors)
        .expect("unable to serialize test vectors");
    std::fs::write(&args[3], zemu_json)
        .expect("unable to save Zemu test vectors");
    std::fs::write(&args[4], format!("{:#?}", debug_vectors))
        .expect("unable to save test vectors");
    if args.len() > 5 {
        std::fs::write(
            &args[5],
            serde_json::to_string(&serialized_txs).unwrap(),
        )
        .expect("unable to save test vectors");
    }
    Ok(())
}
