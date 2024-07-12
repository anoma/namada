#![no_main]

use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use namada_node::shell;
use namada_node::shell::test_utils::TestShell;
use namada_node::shell::MempoolTxType;
use namada_tx::Tx;

lazy_static! {
    static ref SHELL: TestShell = {
        let (shell, _recv, _, _) = shell::test_utils::setup();
        shell
    };
}

fuzz_target!(|tx: Tx| {
    // Sometimes the generated `Tx` cannot be serialized (due to e.g. broken
    // invariants in the `Section::MaspTx`) so we have to use the non-panicking
    // serialization
    if let Ok(tx_bytes) = tx.try_to_bytes() {
        SHELL.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
    }
});
