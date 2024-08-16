#![no_main]
#![allow(clippy::disallowed_methods)]

use data_encoding::HEXUPPER;
use libfuzzer_sys::fuzz_target;
use namada_apps_lib::wallet;
use namada_core::address::Address;
use namada_core::key::PublicKeyTmRawHash;
use namada_core::time::DateTimeUtc;
use namada_node::shell;
use namada_node::shell::test_utils::TestShell;
use namada_node::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use namada_node::shims::abcipp_shim_types::shim::TxBytes;
use namada_tx::data::TxType;
use namada_tx::Tx;

static mut SHELL: Option<TestShell> = None;

fuzz_target!(|txs: Vec<Tx>| {
    let mut txs_bytes: Vec<TxBytes> = Vec::with_capacity(txs.len());
    for tx in txs {
        // Skip raw transactions, they should never be included by an honest
        // prepare_proposal
        if let TxType::Raw = tx.header().tx_type {
            continue;
        }
        // Only use transactions that can be encoded
        if let Ok(tx_bytes) = tx.try_to_bytes() {
            txs_bytes.push(tx_bytes.into());
        }
    }

    let shell = unsafe {
        match SHELL.as_mut() {
            Some(shell) => shell,
            None => {
                let (shell, _recv, _, _) = shell::test_utils::setup();
                SHELL = Some(shell);
                SHELL.as_mut().unwrap()
            }
        }
    };

    let proposer_pk = wallet::defaults::validator_keypair().to_public();
    let proposer_address = Address::from(&proposer_pk);
    let block_time = DateTimeUtc::now();
    let processing_results =
        shell.process_txs(&txs_bytes, block_time, &proposer_address);
    let mut txs = Vec::with_capacity(txs_bytes.len());
    for (result, tx) in
        processing_results.into_iter().zip(txs_bytes.into_iter())
    {
        txs.push(ProcessedTx { tx, result });
    }

    let proposer_address_bytes = HEXUPPER
        .decode(proposer_pk.tm_raw_hash().as_bytes())
        .unwrap();
    let req = FinalizeBlock {
        txs,
        proposer_address: proposer_address_bytes,
        ..Default::default()
    };
    let _events = shell.finalize_block(req).unwrap();

    // Commit the block
    shell.commit();
});
