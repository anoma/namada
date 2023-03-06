use borsh::BorshDeserialize;
use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::types::address;
use namada::core::types::token::{Amount, Transfer};
use namada_apps::wallet::defaults;
use namada_benches::{generate_tx, TX_TRANSFER_WASM};

use namada::core::proto::SignedTxData;
use namada::core::types::key::RefTo;

fn tx_signature_validation(c: &mut Criterion) {
    let tx = generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            sub_prefix: None,
            amount: Amount::whole(500),
            key: None,
            shielded: None,
        },
        &defaults::albert_keypair(),
    );

    let SignedTxData { data: _, ref sig } =
        SignedTxData::try_from_slice(&tx.data.as_ref().unwrap()).unwrap();

    c.bench_function("tx_signature_validation", |b| {
        b.iter(|| {
            tx.verify_sig(&defaults::albert_keypair().ref_to(), sig)
                .unwrap()
        })
    });
}

criterion_group!(host_env, tx_signature_validation);
criterion_main!(host_env);
