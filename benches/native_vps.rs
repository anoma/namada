use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::ledger::ibc::actions;
use namada::core::types::address::{self, Address};
use namada::ibc::core::ics02_client::client_type::ClientType;
use namada::ibc::core::ics03_connection::connection::Counterparty;
use namada::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use namada::ibc::core::ics03_connection::version::Version;
use namada::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChannelCounterparty, Order, State,
};
use namada::ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
use namada::ibc::core::ics04_channel::Version as ChannelVersion;
use namada::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use namada::ibc::signer::Signer;
use namada::ibc::tx_msg::Msg;
use namada::ledger::gas::VpGasMeter;
use namada::ledger::governance;
use namada::ledger::ibc::vp::{Ibc, IbcToken};
use namada::ledger::native_vp::replay_protection::ReplayProtectionVp;
use namada::ledger::native_vp::slash_fund::SlashFundVp;
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::proto::Tx;
use namada::types::address::InternalAddress;
use namada::types::chain::ChainId;
use namada::types::governance::{ProposalVote, VoteType};
use namada::types::storage::TxIndex;
use namada::types::transaction::governance::ProposalType;
use namada_apps::wasm_loader;
use namada_benches::{
    generate_foreign_key_tx, generate_ibc_transfer_tx, generate_tx, BenchShell,
    TX_IBC_WASM, TX_INIT_PROPOSAL_WASM, TX_VOTE_PROPOSAL_WASM, WASM_DIR,
};
use std::collections::BTreeSet;

use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_apps::wallet::defaults;

fn replay_protection(c: &mut Criterion) {
    // Write a random key under the replay protection subspace
    let tx = generate_foreign_key_tx(&defaults::albert_keypair());
    let mut shell = BenchShell::new();

    shell.execute_tx(&tx);
    let (verifiers, keys_changed) = shell
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&BTreeSet::default());

    let replay_protection = ReplayProtectionVp {
        ctx: Ctx::new(
            &Address::Internal(InternalAddress::ReplayProtection),
            &shell.wl_storage.storage,
            &shell.wl_storage.write_log,
            &tx,
            &TxIndex(0),
            VpGasMeter::new(u64::MAX, 0),
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
        ),
    };

    c.bench_function("vp_replay_protection", |b| {
        b.iter(|| {
            // NOTE: thiv VP will always fail when triggered so don't assert here
            replay_protection
                .validate_tx(
                    tx.data.as_ref().unwrap(),
                    replay_protection.ctx.keys_changed,
                    replay_protection.ctx.verifiers,
                )
                .unwrap()
        })
    });
}

fn governance(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_governance");

    for bench_name in [
        "foreign_key_write",
        "delegator_vote",
        "validator_vote",
        "minimal_proposal",
        "complete_proposal",
    ] {
        let mut shell = BenchShell::new();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                generate_foreign_key_tx(&defaults::albert_keypair())
            }
            "delegator_vote" => generate_tx(
                TX_VOTE_PROPOSAL_WASM,
                VoteProposalData {
                    id: 0,
                    vote: ProposalVote::Yay(VoteType::Default),
                    voter: defaults::albert_address(),
                    delegations: vec![defaults::validator_address()],
                },
                &defaults::albert_keypair(),
            ),
            "validator_vote" => generate_tx(
                TX_VOTE_PROPOSAL_WASM,
                VoteProposalData {
                    id: 0,
                    vote: namada::types::governance::ProposalVote::Nay,
                    voter: defaults::validator_address(),
                    delegations: vec![],
                },
                &defaults::validator_keypair(),
            ),
            "minimal_proposal" => generate_tx(
                TX_INIT_PROPOSAL_WASM,
                InitProposalData {
                    id: None,
                    content: vec![],
                    author: defaults::albert_address(),
                    r#type: ProposalType::Default(None),
                    voting_start_epoch: 12.into(),
                    voting_end_epoch: 15.into(),
                    grace_epoch: 18.into(),
                },
                &defaults::albert_keypair(),
            ),
            "complete_proposal" => {
                let max_code_size_key =
                    governance::storage::get_max_proposal_code_size_key();
                let max_proposal_content_key =
                    governance::storage::get_max_proposal_content_key();
                let max_code_size =
                    shell.read_storage_key(&max_code_size_key).unwrap();
                let max_proposal_content_size =
                    shell.read_storage_key(&max_proposal_content_key).unwrap();

                generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        id: Some(1),
                        content: vec![0; max_proposal_content_size],
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default(Some(vec![
                            0;
                            max_code_size
                        ])),
                        voting_start_epoch: 12.into(),
                        voting_end_epoch: 15.into(),
                        grace_epoch: 18.into(),
                    },
                    &defaults::albert_keypair(),
                )
            }
            _ => panic!("Unexpected bench test"),
        };

        // Run the tx to validate
        shell.execute_tx(&signed_tx);

        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let governance = SlashFundVp {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::Governance),
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                &signed_tx,
                &TxIndex(0),
                VpGasMeter::new(u64::MAX, 0),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(governance
                    .validate_tx(
                        signed_tx.data.as_ref().unwrap(),
                        governance.ctx.keys_changed,
                        governance.ctx.verifiers,
                    )
                    .unwrap())
            })
        });
    }

    group.finish();
}

fn slash_fund(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_slash_fund");

    // Write a random key under a foreign subspace
    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());

    let governance_proposal = generate_tx(
        TX_INIT_PROPOSAL_WASM,
        InitProposalData {
            id: None,
            content: vec![],
            author: defaults::albert_address(),
            r#type: ProposalType::Default(None),
            voting_start_epoch: 12.into(),
            voting_end_epoch: 15.into(),
            grace_epoch: 18.into(),
        },
        &defaults::albert_keypair(),
    );

    for (tx, bench_name) in [foreign_key_write, governance_proposal]
        .into_iter()
        .zip(["foreign_key_write", "governance_proposal"])
    {
        let mut shell = BenchShell::new();

        // Run the tx to validate
        shell.execute_tx(&tx);

        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let slash_fund = SlashFundVp {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::SlashFund),
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                &tx,
                &TxIndex(0),
                VpGasMeter::new(u64::MAX, 0),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(slash_fund
                    .validate_tx(
                        tx.data.as_ref().unwrap(),
                        slash_fund.ctx.keys_changed,
                        slash_fund.ctx.verifiers,
                    )
                    .unwrap())
            })
        });
    }

    group.finish();
}

fn ibc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc");

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());

    // Connection handshake
    let msg = MsgConnectionOpenInit {
        client_id: ClientId::new(ClientType::Tendermint, 1).unwrap(),
        counterparty: Counterparty::new(
            ClientId::new(ClientType::Tendermint, 1).unwrap(),
            Some(ConnectionId::new(1)),
            actions::commitment_prefix(),
        ),
        version: Some(Version::default()),
        delay_period: std::time::Duration::new(100, 0),
        signer: Signer::new(defaults::albert_address()),
    };
    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .expect("Encoding tx data shouldn't fail");

    // Avoid serializing the data again with borsh
    let open_connection = Tx::new(
        wasm_loader::read_wasm_or_exit(WASM_DIR, TX_IBC_WASM),
        Some(data),
        ChainId::default(),
        None,
    )
    .sign(&defaults::albert_keypair());

    // Channel handshake
    let counterparty =
        ChannelCounterparty::new(PortId::transfer(), Some(ChannelId::new(5)));
    let channel = ChannelEnd::new(
        State::Init,
        Order::Unordered,
        counterparty,
        vec![ConnectionId::new(1)],
        ChannelVersion::ics20(),
    );
    let msg = MsgChannelOpenInit {
        port_id: PortId::transfer(),
        channel: channel.clone(),
        signer: Signer::new(defaults::albert_address()),
    };

    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .expect("Encoding tx data shouldn't fail");

    // Avoid serializing the data again with borsh
    let open_channel = Tx::new(
        wasm_loader::read_wasm_or_exit(WASM_DIR, TX_IBC_WASM),
        Some(data),
        ChainId::default(),
        None,
    )
    .sign(&defaults::albert_keypair());

    // Ibc transfer
    let outgoing_transfer = generate_ibc_transfer_tx();

    for (signed_tx, bench_name) in [
        foreign_key_write,
        open_connection,
        open_channel,
        outgoing_transfer,
    ]
    .iter()
    .zip([
        "foreign_key_write",
        "open_connection",
        "open_channel",
        "outgoing_transfer",
    ]) {
        let mut shell = BenchShell::new();
        shell.init_ibc_channel();

        shell.execute_tx(signed_tx);
        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let ibc = Ibc {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::Ibc),
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                signed_tx,
                &TxIndex(0),
                VpGasMeter::new(u64::MAX, 0),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(ibc
                    .validate_tx(
                        signed_tx.data.as_ref().unwrap(),
                        ibc.ctx.keys_changed,
                        ibc.ctx.verifiers,
                    )
                    .unwrap())
            })
        });
    }

    group.finish();
}

fn ibc_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc_token");

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());
    let outgoing_transfer = generate_ibc_transfer_tx();

    for (signed_tx, bench_name) in [foreign_key_write, outgoing_transfer]
        .iter()
        .zip(["foreign_key_write", "outgoing_transfer"])
    {
        let mut shell = BenchShell::new();
        shell.init_ibc_channel();

        shell.execute_tx(&signed_tx);

        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let ibc_token_address =
            namada::core::types::address::InternalAddress::ibc_token_address(
                PortId::transfer().to_string(),
                ChannelId::new(5).to_string(),
                &address::nam(),
            );
        let internal_address = Address::Internal(ibc_token_address);

        let ibc = IbcToken {
            ctx: Ctx::new(
                &internal_address,
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                &signed_tx,
                &TxIndex(0),
                VpGasMeter::new(u64::MAX, 0),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(ibc
                    .validate_tx(
                        signed_tx.data.as_ref().unwrap(),
                        ibc.ctx.keys_changed,
                        ibc.ctx.verifiers,
                    )
                    .unwrap())
            })
        });
    }

    group.finish();
}

criterion_group!(
    native_vps,
    replay_protection,
    governance,
    slash_fund,
    ibc,
    ibc_token
);
criterion_main!(native_vps);
