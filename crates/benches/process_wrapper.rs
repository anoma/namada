use criterion::{criterion_group, criterion_main, Criterion};
use namada_apps_lib::address;
use namada_apps_lib::key::RefTo;
use namada_apps_lib::state::TxIndex;
use namada_apps_lib::storage::BlockHeight;
use namada_apps_lib::time::DateTimeUtc;
use namada_apps_lib::token::{Amount, DenominatedAmount, Transfer};
use namada_apps_lib::tx::data::{Fee, WrapperTx};
use namada_apps_lib::tx::Authorization;
use namada_apps_lib::wallet::defaults;
use namada_node::bench_utils::{BenchShell, TX_TRANSFER_WASM};
use namada_node::shell::process_proposal::ValidationMeta;

fn process_tx(c: &mut Criterion) {
    let mut shell = BenchShell::default();
    // Advance chain height to allow the inclusion of wrapper txs by the block
    // space allocator
    shell.state.in_mem_mut().last_block.as_mut().unwrap().height =
        BlockHeight(2);

    let mut batched_tx = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer::default()
            .transfer(
                defaults::albert_address(),
                defaults::bertha_address(),
                address::testing::nam(),
                Amount::native_whole(1).native_denominated(),
            )
            .unwrap(),
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    batched_tx
        .tx
        .update_header(namada_apps_lib::tx::data::TxType::Wrapper(Box::new(
            WrapperTx::new(
                Fee {
                    token: address::testing::nam(),
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                },
                defaults::albert_keypair().ref_to(),
                1_000_000.into(),
            ),
        )));
    batched_tx
        .tx
        .add_section(namada_apps_lib::tx::Section::Authorization(
            Authorization::new(
                batched_tx.tx.sechashes(),
                [(0, defaults::albert_keypair())].into_iter().collect(),
                None,
            ),
        ));
    let wrapper = batched_tx.tx.to_bytes();

    #[allow(clippy::disallowed_methods)]
    let datetime = DateTimeUtc::now();

    c.bench_function("wrapper_tx_validation", |b| {
        b.iter_batched_ref(
            || {
                // This is safe because nothing else is using `shell.state`
                // concurrently.
                let temp_state =
                    unsafe { shell.state.with_static_temp_write_log() };
                (
                    // Prevent block out of gas and replay protection
                    temp_state,
                    ValidationMeta::from(shell.state.read_only()),
                    shell.vp_wasm_cache.clone(),
                    shell.tx_wasm_cache.clone(),
                    defaults::daewon_address(),
                )
            },
            |(
                temp_state,
                validation_meta,
                vp_wasm_cache,
                tx_wasm_cache,
                block_proposer,
            )| {
                assert_eq!(
                    // Assert that the wrapper transaction was valid
                    shell
                        .check_proposal_tx(
                            &wrapper,
                            &TxIndex::default(),
                            validation_meta,
                            temp_state,
                            datetime,
                            vp_wasm_cache,
                            tx_wasm_cache,
                            block_proposer
                        )
                        .code,
                    0
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(process_wrapper, process_tx);
criterion_main!(process_wrapper);
