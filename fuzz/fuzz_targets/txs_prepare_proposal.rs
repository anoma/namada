#![no_main]

use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use namada_node::facade::tendermint_proto::v0_37::abci::RequestPrepareProposal;
use namada_node::shell;
use namada_node::shell::test_utils::TestShell;
use namada_node::shims::abcipp_shim_types::shim::TxBytes;
use namada_tx::Tx;

lazy_static! {
    static ref SHELL: TestShell = {
        let (shell, _recv, _, _) = shell::test_utils::setup();
        shell
    };
}

fuzz_target!(|txs: Vec<Tx>| {
    let mut txs_bytes: Vec<TxBytes> = Vec::with_capacity(txs.len());
    for tx in txs {
        if let Ok(tx_bytes) = tx.try_to_bytes() {
            txs_bytes.push(tx_bytes.into());
        } else {
            return;
        }
    }

    let req = RequestPrepareProposal {
        txs: txs_bytes,
        ..Default::default()
    };
    SHELL.prepare_proposal(req);
});
