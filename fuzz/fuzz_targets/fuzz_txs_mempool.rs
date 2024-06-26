#![no_main]

use libfuzzer_sys::fuzz_target;
use namada_node::shell;
use namada_node::shell::MempoolTxType;
use namada_tx::Tx;

fuzz_target!(|tx: Tx| {
    let (shell, _recv, _, _) = shell::test_utils::setup();
    shell.mempool_validate(&tx.to_bytes(), MempoolTxType::NewTransaction);
});
