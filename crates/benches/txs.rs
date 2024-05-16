use std::str::FromStr;

use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::address::Address;
use namada::core::masp::{TransferSource, TransferTarget};
use namada::ibc::core::channel::types::channel::Order;
use namada::ibc::core::channel::types::msgs::MsgChannelOpenInit;
use namada::ibc::core::channel::types::Version as ChannelVersion;
use namada::ibc::core::commitment_types::commitment::CommitmentPrefix;
use namada::ibc::core::connection::types::msgs::MsgConnectionOpenInit;
use namada::ibc::core::connection::types::version::Version;
use namada::ibc::core::connection::types::Counterparty;
use namada::ibc::core::host::types::identifiers::{
    ClientId, ConnectionId, PortId,
};
use namada::ibc::primitives::ToProto;
use namada::proof_of_stake::KeySeg;
use namada::token::Amount;
use namada_apps::bench_utils::{
    BenchShieldedCtx, ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY, TX_IBC_WASM,
};
use namada_apps::wallet::defaults;

fn ibc(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_ibc");

    // NOTE: Ibc encompass a variety of different messages that can be executed,
    // here we only benchmark a few of those
    for bench_name in [
        "open_connection",
        "open_channel",
        "outgoing_transfer",
        "outgoing_shielded_action",
    ] {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shielded_ctx = BenchShieldedCtx::default();
                    // Initialize the state according to the target tx
                    let (shielded_ctx, signed_tx) = match bench_name {
                        "open_connection" => {
                            let _ = shielded_ctx.shell.init_ibc_client_state(
                                namada::core::storage::Key::from(
                                    Address::Internal(namada::core::address::InternalAddress::Ibc).to_db_key(),
                                ),
                            );
                            // Connection handshake
                            let msg = MsgConnectionOpenInit {
                                client_id_on_a: ClientId::new("07-tendermint", 1).unwrap(),
                                counterparty: Counterparty::new(
                                    ClientId::from_str("07-tendermint-1").unwrap(),
                                    None,
                                    CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap(),
                                ),
                                version: Some(Version::compatibles().first().unwrap().clone()),
                                delay_period: std::time::Duration::new(100, 0),
                                signer: defaults::albert_address().to_string().into(),
                            };
                            let mut data = vec![];
                            prost::Message::encode(&msg.to_any(), &mut data).unwrap();
                            let open_connection = shielded_ctx.shell.generate_ibc_tx(TX_IBC_WASM, data);
                            (shielded_ctx, open_connection)
                        }
                        "open_channel" => {
                            let _ = shielded_ctx.shell.init_ibc_connection();
                            // Channel handshake
                            let msg = MsgChannelOpenInit {
                                port_id_on_a: PortId::transfer(),
                                connection_hops_on_a: vec![ConnectionId::new(1)],
                                port_id_on_b: PortId::transfer(),
                                ordering: Order::Unordered,
                                signer: defaults::albert_address().to_string().into(),
                                version_proposal: ChannelVersion::new("ics20-1".to_string()),
                            };

                            // Avoid serializing the data again with borsh
                            let mut data = vec![];
                            prost::Message::encode(&msg.to_any(), &mut data).unwrap();
                            let open_channel = shielded_ctx.shell.generate_ibc_tx(TX_IBC_WASM, data);
                            (shielded_ctx, open_channel)
                        }
                        "outgoing_transfer" => {
                            shielded_ctx.shell.init_ibc_channel();
                            let outgoing_transfer = shielded_ctx.shell.generate_ibc_transfer_tx();
                            (shielded_ctx, outgoing_transfer)
                        }
                        "outgoing_shielded_action" => {
                            shielded_ctx.shell.init_ibc_channel();
                            let albert_payment_addr = shielded_ctx
                                .wallet
                                .find_payment_addr(ALBERT_PAYMENT_ADDRESS)
                                .unwrap()
                                .to_owned();
                            let albert_spending_key = shielded_ctx
                                .wallet
                                .find_spending_key(ALBERT_SPENDING_KEY, None)
                                .unwrap()
                                .to_owned();
                            // Shield some tokens for Albert
                            let (mut shielded_ctx, shield_tx) = shielded_ctx.generate_masp_tx(
                                Amount::native_whole(500),
                                TransferSource::Address(defaults::albert_address()),
                                TransferTarget::PaymentAddress(albert_payment_addr),
                            );
                            shielded_ctx.shell.execute_tx(&shield_tx.to_ref());
                            shielded_ctx.shell.commit_masp_tx(shield_tx.tx);
                            shielded_ctx.shell.commit_block();

                            shielded_ctx.generate_shielded_action(
                                Amount::native_whole(10),
                                TransferSource::ExtendedSpendingKey(albert_spending_key),
                                TransferTarget::Address(defaults::bertha_address()),
                            )
                        }
                        _ => panic!("Unexpected bench test"),
                    };
                    (shielded_ctx, signed_tx)
                },
                |(shielded_ctx, signed_tx)| shielded_ctx.shell.execute_tx(&signed_tx.to_ref()),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(allowed_txs, ibc);
criterion_main!(allowed_txs);
