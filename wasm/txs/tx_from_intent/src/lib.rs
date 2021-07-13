use anoma_vm_env::tx_prelude::*;

#[transaction]
fn apply_tx(tx_data: Vec<u8>) {
    let signed =
        key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    let tx_data =
        intent::IntentTransfers::try_from_slice(&signed.data.unwrap()[..])
            .unwrap();
    log_string(format!(
        "apply_tx called with intent transfers: {:#?}",
        tx_data
    ));

    // make sure that the matchmaker has to validate this tx
    insert_verifier(address::matchmaker());

    for token::Transfer {
        source,
        target,
        token,
        amount,
    } in tx_data.transfers
    {
        token::transfer(&source, &target, &token, amount);
    }

    tx_data
        .exchanges
        .values()
        .into_iter()
        .for_each(intent::invalidate_exchange);
}
