use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::types::address;
use namada::core::types::token::{Amount, Transfer};
use namada::ledger::storage::TempWlStorage;
use namada::proto::Signature;
use namada::types::key::RefTo;
use namada::types::storage::BlockHeight;
use namada::types::time::DateTimeUtc;
use namada::types::transaction::{Fee, WrapperTx};
use namada_apps::node::ledger::shell::process_proposal::ValidationMeta;
use namada_apps::wallet::defaults;
use namada_benches::{generate_tx, BenchShell, TX_TRANSFER_WASM};

fn process_tx(c: &mut Criterion) {
    let mut shell = BenchShell::default();
    // Advance chain height to allow the inclusion of wrapper txs by the block
    // space allocator
    shell.wl_storage.storage.last_block.as_mut().unwrap().height =
        BlockHeight(2);

    let mut tx = generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            amount: Amount::native_whole(1).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    tx.update_header(namada::types::transaction::TxType::Wrapper(Box::new(
        WrapperTx::new(
            Fee {
                token: address::nam(),
                amount_per_gas_unit: 1.into(),
            },
            defaults::albert_keypair().ref_to(),
            0.into(),
            1000.into(),
            None,
        ),
    )));
    tx.add_section(namada::proto::Section::Signature(Signature::new(
        tx.sechashes(),
        [(0, defaults::albert_keypair())].into_iter().collect(),
        None,
    )));
    let wrapper = tx.to_bytes();

    let datetime = DateTimeUtc::now();

    c.bench_function("wrapper_tx_validation", |b| {
        b.iter_batched(
            || {
                (
                    shell.wl_storage.storage.tx_queue.clone(),
                    // Prevent block out of gas and replay protection
                    TempWlStorage::new(&shell.wl_storage.storage),
                    ValidationMeta::from(&shell.wl_storage),
                    shell.vp_wasm_cache.clone(),
                    shell.tx_wasm_cache.clone(),
                    defaults::daewon_address(),
                )
            },
            |(
                tx_queue,
                mut temp_wl_storage,
                mut validation_meta,
                mut vp_wasm_cache,
                mut tx_wasm_cache,
                block_proposer,
            )| {
                assert_eq!(
                    // Assert that the wrapper transaction was valid
                    shell
                        .check_proposal_tx(
                            &wrapper,
                            &mut tx_queue.iter(),
                            &mut validation_meta,
                            &mut temp_wl_storage,
                            datetime,
                            &mut vp_wasm_cache,
                            &mut tx_wasm_cache,
                            &block_proposer
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
