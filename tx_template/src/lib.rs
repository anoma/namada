use anoma_data_template::*;
use anoma_vm_env::{transaction, tx_prelude::*};

transaction! {
    fn apply_tx(tx_data: vm_memory::Data) {
        let tx = TxData::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("apply_tx called with tx_data: {:#?}", tx));
        for Transfer {
            source,
            target,
            token,
            amount,
        } in tx.transfers
        {
            apply_transfer(source, target, token, amount);
        }
    }
}

fn apply_transfer(src: String, dest: String, token: String, amount: u64) -> bool {
    let src_key = vec![format!("@{}", src), String::from("balance"), token.clone()].join("/");
    let dest_key = vec![format!("@{}", dest), String::from("balance"), token].join("/");

    let src_bal: Option<u64> = read(&src_key);
    let dest_bal: Option<u64> = read(&dest_key);
    match (src_bal, dest_bal) {
        (Some(src_bal), Some(dest_bal)) => {
            let src_new_bal = src_bal - amount;
            let dest_new_bal = dest_bal + amount;
            write(&src_key, src_new_bal);
            write(&dest_key, dest_new_bal);
            true
        }
        _ => false,
    }
}
