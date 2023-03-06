use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::types::address;
use namada::core::types::token::{Amount, Transfer};
use namada::ledger::gas::BlockGasMeter;
use namada::ledger::storage::TempWlStorage;
use namada::types::chain::ChainId;
use namada::types::time::DateTimeUtc;
use std::collections::BTreeMap;

use namada::types::transaction::{Fee, WrapperTx};
use namada_apps::node::ledger::shell::process_proposal::ValidationMeta;
use namada_apps::wallet::defaults;
use namada_benches::{generate_tx, BenchShell, TX_TRANSFER_WASM};

fn process_tx(c: &mut Criterion) {
    let shell = BenchShell::new();
    let tx = generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            sub_prefix: None,
            amount: Amount::whole(1000),
            key: None,
            shielded: None,
        },
        &defaults::albert_keypair(),
    );

    let wrapper = WrapperTx::new(
        Fee {
            token: address::nam(),
            amount: Amount::whole(200),
        },
        &defaults::albert_keypair(),
        0.into(),
        1000.into(),
        tx,
        Default::default(),
        None,
    )
    .sign(&defaults::albert_keypair(), ChainId::default(), None)
    .unwrap()
    .to_bytes();

    let datetime = DateTimeUtc::now();
    let gas_table = BTreeMap::default();

    c.bench_function("wrapper_tx_validation", |b| {
        b.iter_batched(
            || {
                (
                    shell.wl_storage.storage.tx_queue.clone(),
                    // Prevent block out of gas and replay protection
                    TempWlStorage::new(&shell.wl_storage.storage),
                    BlockGasMeter::new(u64::MAX),
                    ValidationMeta::default(),
                )
            },
            |(
                tx_queue,
                mut temp_wl_storage,
                mut block_gas_meter,
                mut validation_meta,
            )| {
                assert_eq!(
                    // Assert that the wrapper transaction was valid
                    shell
                        .process_single_tx(
                            &wrapper,
                            &mut tx_queue.iter(),
                            &mut validation_meta,
                            &mut temp_wl_storage,
                            &mut block_gas_meter,
                            datetime,
                            &gas_table,
                            &mut 0,
                        )
                        .code,
                    0
                )
            },
            criterion::BatchSize::LargeInput,
        )
    });
}

criterion_group!(process_wrapper, process_tx);
criterion_main!(process_wrapper);
