use borsh::BorshDeserialize;
use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::types::address;
use namada::core::types::key::RefTo;
use namada::core::types::token::{Amount, Transfer};
use namada::proto::Section;
use namada::types::token::DenominatedAmount;
use namada_apps::wallet::defaults;
use namada_benches::{generate_tx, TX_TRANSFER_WASM};

fn tx_signature_validation(c: &mut Criterion) {
    let tx = generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            amount: Amount::native_whole(500).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    let data_hash = [tx.data_sechash().to_owned()];

    c.bench_function("tx_signature_validation", |b| {
        b.iter(|| {
            tx.verify_signature(
                &defaults::albert_keypair().ref_to(),
                &data_hash[..],
            )
            .unwrap()
        })
    });
}

criterion_group!(host_env, tx_signature_validation);
criterion_main!(host_env);
