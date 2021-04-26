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

fn apply_transfer(src: String, dest: String, token: String, amount: u64) {
    // TODO use typed data in the crafted tx
    let src = Address::from_raw(src);
    let dest = Address::from_raw(dest);
    let token = Address::from_raw(token);
    let amount = token::Amount::from(amount);

    token_transfer(
        &src,
        &dest,
        &token,
        amount,
        log_string,
        |key| read(key),
        |key, val| write(key, val),
    )
}
