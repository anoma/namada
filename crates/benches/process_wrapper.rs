use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::address;
use namada::core::key::RefTo;
use namada::core::storage::BlockHeight;
use namada::core::time::DateTimeUtc;
use namada::token::{Amount, DenominatedAmount, Transfer};
use namada::tx::data::{Fee, WrapperTx};
use namada::tx::Signature;
use namada_apps::bench_utils::{BenchShell, TX_TRANSFER_WASM};
use namada_apps::node::ledger::shell::process_proposal::ValidationMeta;
use namada_apps::wallet::defaults;

fn process_tx(c: &mut Criterion) {
    let mut shell = BenchShell::default();
    // Advance chain height to allow the inclusion of wrapper txs by the block
    // space allocator
    shell.state.in_mem_mut().last_block.as_mut().unwrap().height =
        BlockHeight(2);

    let mut tx = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::testing::nam(),
            amount: Amount::native_whole(1).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    tx.update_header(namada::tx::data::TxType::Wrapper(Box::new(
        WrapperTx::new(
            Fee {
                token: address::testing::nam(),
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
            },
            defaults::albert_keypair().ref_to(),
            0.into(),
            1_000_000.into(),
            // NOTE: The unshield operation has to be gas-free so don't include
            // it here
            None,
        ),
    )));
    tx.add_section(namada::tx::Section::Signature(Signature::new(
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
                    shell.state.in_mem().tx_queue.clone(),
                    // Prevent block out of gas and replay protection
                    shell.state.with_temp_write_log(),
                    ValidationMeta::from(shell.state.read_only()),
                    shell.vp_wasm_cache.clone(),
                    shell.tx_wasm_cache.clone(),
                    defaults::daewon_address(),
                )
            },
            |(
                tx_queue,
                mut temp_state,
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
                            &mut temp_state,
                            datetime,
                            &mut vp_wasm_cache,
                            &mut tx_wasm_cache,
                            &block_proposer
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
