use std::collections::HashMap;
use std::str::FromStr;

use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::ledger::governance::storage::proposal::ProposalType;
use namada::core::ledger::governance::storage::vote::ProposalVote;
use namada::core::ledger::pgf::storage::steward::StewardDetail;
use namada::core::types::key::{
    common, SecretKey as SecretKeyInterface, SigScheme,
};
use namada::core::types::token::Amount;
use namada::core::types::transaction::account::{InitAccount, UpdateAccount};
use namada::core::types::transaction::pos::{BecomeValidator, MetaDataChange};
use namada::ibc::core::channel::types::channel::Order;
use namada::ibc::core::channel::types::msgs::MsgChannelOpenInit;
use namada::ibc::core::channel::types::Version as ChannelVersion;
use namada::ibc::core::commitment_types::commitment::CommitmentPrefix;
use namada::ibc::core::connection::types::msgs::MsgConnectionOpenInit;
use namada::ibc::core::connection::types::version::Version;
use namada::ibc::core::connection::types::Counterparty;
use namada::ibc::core::host::types::identifiers::{
    ClientId, ClientType, ConnectionId, PortId,
};
use namada::ledger::eth_bridge::read_native_erc20_address;
use namada::ledger::storage_api::{StorageRead, StorageWrite};
use namada::proof_of_stake::storage::read_pos_params;
use namada::proof_of_stake::types::SlashType;
use namada::proof_of_stake::{self, KeySeg};
use namada::proto::{Code, Section};
use namada::types::address::{self, Address};
use namada::types::eth_bridge_pool::{GasFee, PendingTransfer};
use namada::types::hash::Hash;
use namada::types::key::{ed25519, secp256k1, PublicKey, RefTo};
use namada::types::masp::{TransferSource, TransferTarget};
use namada::types::storage::Key;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::pos::{
    Bond, CommissionChange, ConsensusKeyChange, Redelegation, Withdraw,
};
use namada_apps::bench_utils::{
    BenchShell, BenchShieldedCtx, ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY,
    BERTHA_PAYMENT_ADDRESS, TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM,
    TX_BRIDGE_POOL_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
    TX_CHANGE_VALIDATOR_COMMISSION_WASM, TX_CHANGE_VALIDATOR_METADATA_WASM,
    TX_CLAIM_REWARDS_WASM, TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL_WASM, TX_REACTIVATE_VALIDATOR_WASM,
    TX_REDELEGATE_WASM, TX_RESIGN_STEWARD, TX_REVEAL_PK_WASM, TX_UNBOND_WASM,
    TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL_WASM, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
use namada_apps::wallet::defaults;
use sha2::Digest;

fn transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer");
    let amount = Amount::native_whole(500);

    for bench_name in ["transparent", "shielding", "unshielding", "shielded"] {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shielded_ctx = BenchShieldedCtx::default();

                    let albert_spending_key = shielded_ctx
                        .wallet
                        .find_spending_key(ALBERT_SPENDING_KEY, None)
                        .unwrap()
                        .to_owned();
                    let albert_payment_addr = shielded_ctx
                        .wallet
                        .find_payment_addr(ALBERT_PAYMENT_ADDRESS)
                        .unwrap()
                        .to_owned();
                    let bertha_payment_addr = shielded_ctx
                        .wallet
                        .find_payment_addr(BERTHA_PAYMENT_ADDRESS)
                        .unwrap()
                        .to_owned();

                    // Shield some tokens for Albert
                    let (mut shielded_ctx, shield_tx) = shielded_ctx
                        .generate_masp_tx(
                            amount,
                            TransferSource::Address(defaults::albert_address()),
                            TransferTarget::PaymentAddress(albert_payment_addr),
                        );
                    shielded_ctx.shell.execute_tx(&shield_tx);
                    shielded_ctx.shell.wl_storage.commit_tx();
                    shielded_ctx.shell.commit();

                    let (shielded_ctx, signed_tx) = match bench_name {
                        "transparent" => shielded_ctx.generate_masp_tx(
                            amount,
                            TransferSource::Address(defaults::albert_address()),
                            TransferTarget::Address(defaults::bertha_address()),
                        ),
                        "shielding" => shielded_ctx.generate_masp_tx(
                            amount,
                            TransferSource::Address(defaults::albert_address()),
                            TransferTarget::PaymentAddress(albert_payment_addr),
                        ),
                        "unshielding" => shielded_ctx.generate_masp_tx(
                            amount,
                            TransferSource::ExtendedSpendingKey(
                                albert_spending_key,
                            ),
                            TransferTarget::Address(defaults::albert_address()),
                        ),
                        "shielded" => shielded_ctx.generate_masp_tx(
                            amount,
                            TransferSource::ExtendedSpendingKey(
                                albert_spending_key,
                            ),
                            TransferTarget::PaymentAddress(bertha_payment_addr),
                        ),
                        _ => panic!("Unexpected bench test"),
                    };

                    (shielded_ctx, signed_tx)
                },
                |(shielded_ctx, signed_tx)| {
                    shielded_ctx.shell.execute_tx(signed_tx);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bond(c: &mut Criterion) {
    let mut group = c.benchmark_group("bond");

    let shell = BenchShell::default();
    let bond = shell.generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let self_bond = shell.generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: None,
        },
        None,
        None,
        vec![&defaults::validator_keypair()],
    );

    for (signed_tx, bench_name) in
        [bond, self_bond].iter().zip(["bond", "self_bond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn unbond(c: &mut Criterion) {
    let mut group = c.benchmark_group("unbond");

    let shell = BenchShell::default();
    let unbond = shell.generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let self_unbond = shell.generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: None,
        },
        None,
        None,
        vec![&defaults::validator_keypair()],
    );

    for (signed_tx, bench_name) in
        [unbond, self_unbond].iter().zip(["unbond", "self_unbond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn withdraw(c: &mut Criterion) {
    let mut group = c.benchmark_group("withdraw");
    let shell = BenchShell::default();

    let withdraw = shell.generate_tx(
        TX_WITHDRAW_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let self_withdraw = shell.generate_tx(
        TX_WITHDRAW_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: None,
        },
        None,
        None,
        vec![&defaults::validator_keypair()],
    );

    for (signed_tx, bench_name) in [withdraw, self_withdraw]
        .iter()
        .zip(["withdraw", "self_withdraw"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shell = BenchShell::default();

                    // Unbond funds
                    let unbond_tx = match bench_name {
                        "withdraw" => shell.generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::native_whole(1000),
                                source: Some(defaults::albert_address()),
                            },
                            None,
                            None,
                            vec![&defaults::albert_keypair()],
                        ),
                        "self_withdraw" => shell.generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::native_whole(1000),
                                source: None,
                            },
                            None,
                            None,
                            vec![&defaults::validator_keypair()],
                        ),
                        _ => panic!("Unexpected bench test"),
                    };

                    shell.execute_tx(&unbond_tx);
                    shell.wl_storage.commit_tx();

                    // Advance Epoch for pipeline and unbonding length
                    let params = proof_of_stake::storage::read_pos_params(
                        &shell.wl_storage,
                    )
                    .unwrap();
                    let advance_epochs =
                        params.pipeline_len + params.unbonding_len;

                    for _ in 0..=advance_epochs {
                        shell.advance_epoch();
                    }

                    shell
                },
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn redelegate(c: &mut Criterion) {
    let shell = BenchShell::default();

    let redelegation = |dest_validator| {
        shell.generate_tx(
            TX_REDELEGATE_WASM,
            Redelegation {
                src_validator: defaults::validator_address(),
                dest_validator,
                owner: defaults::albert_address(),
                amount: Amount::from(1),
            },
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    c.bench_function("redelegate", |b| {
        b.iter_batched_ref(
            || {
                let shell = BenchShell::default();
                // Find the other genesis validator
                let current_epoch = shell.wl_storage.get_block_epoch().unwrap();
                let validators = namada::proof_of_stake::storage::read_consensus_validator_set_addresses(&shell.inner.wl_storage, current_epoch).unwrap();
                let validator_2 = validators.into_iter().find(|addr| addr != &defaults::validator_address()).expect("There must be another validator to redelegate to");
                // Prepare the redelegation tx
                (shell, redelegation(validator_2))
            },
            |(shell, tx)| shell.execute_tx(tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn reveal_pk(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let new_implicit_account: common::SecretKey =
        ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap();
    let shell = BenchShell::default();

    let tx = shell.generate_tx(
        TX_REVEAL_PK_WASM,
        new_implicit_account.to_public(),
        None,
        None,
        vec![],
    );

    c.bench_function("reveal_pk", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn update_account(c: &mut Criterion) {
    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_USER_WASM))
        .unwrap();
    let extra_section = Section::ExtraData(Code::from_hash(
        vp_code_hash,
        Some(VP_USER_WASM.to_string()),
    ));
    let data = UpdateAccount {
        addr: defaults::albert_address(),
        vp_code_hash: Some(Hash(
            extra_section
                .hash(&mut sha2::Sha256::new())
                .finalize_reset()
                .into(),
        )),
        public_keys: vec![defaults::albert_keypair().ref_to()],
        threshold: None,
    };
    let vp = shell.generate_tx(
        TX_UPDATE_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("update_account", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&vp),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn init_account(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let new_account: common::SecretKey =
        ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap();

    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_USER_WASM))
        .unwrap();
    let extra_section = Section::ExtraData(Code::from_hash(
        vp_code_hash,
        Some(VP_USER_WASM.to_string()),
    ));
    let extra_hash = Hash(
        extra_section
            .hash(&mut sha2::Sha256::new())
            .finalize_reset()
            .into(),
    );
    let data = InitAccount {
        public_keys: vec![new_account.to_public()],
        vp_code_hash: extra_hash,
        threshold: 1,
    };
    let tx = shell.generate_tx(
        TX_INIT_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("init_account", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn init_proposal(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_proposal");

    for bench_name in ["minimal_proposal", "complete_proposal"] {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let shell = BenchShell::default();

                    let signed_tx = match bench_name {
                        "minimal_proposal" => {
                            let content_section =
                                Section::ExtraData(Code::new(vec![], None));
                            shell.generate_tx(
                                TX_INIT_PROPOSAL_WASM,
                                InitProposalData {
                                    id: None,
                                    content: content_section.get_hash(),
                                    author: defaults::albert_address(),
                                    r#type: ProposalType::Default(None),
                                    voting_start_epoch: 12.into(),
                                    voting_end_epoch: 15.into(),
                                    grace_epoch: 18.into(),
                                },
                                None,
                                Some(vec![content_section]),
                                vec![&defaults::albert_keypair()],
                            )
                        }
                        "complete_proposal" => {
                            let max_code_size_key =
                namada::core::ledger::governance::storage::keys::get_max_proposal_code_size_key();
                            let max_proposal_content_key =
                    namada::core::ledger::governance::storage::keys::get_max_proposal_content_key();
                            let max_code_size: u64 = shell
                                .wl_storage
                                .read(&max_code_size_key)
                                .expect("Error while reading from storage")
                                .expect(
                                    "Missing max_code_size parameter in \
                                     storage",
                                );
                            let max_proposal_content_size: u64 = shell
                                .wl_storage
                                .read(&max_proposal_content_key)
                                .expect("Error while reading from storage")
                                .expect(
                                    "Missing max_proposal_content parameter \
                                     in storage",
                                );
                            let content_section =
                                Section::ExtraData(Code::new(vec![
                                    0;
                                    max_proposal_content_size
                                        as _
                                ], None));
                            let wasm_code_section =
                                Section::ExtraData(Code::new(vec![
                                    0;
                                    max_code_size
                                        as _
                                ], None));

                            shell.generate_tx(
                                TX_INIT_PROPOSAL_WASM,
                                InitProposalData {
                                    id: Some(1),
                                    content: content_section.get_hash(),
                                    author: defaults::albert_address(),
                                    r#type: ProposalType::Default(Some(
                                        wasm_code_section.get_hash(),
                                    )),
                                    voting_start_epoch: 12.into(),
                                    voting_end_epoch: 15.into(),
                                    grace_epoch: 18.into(),
                                },
                                None,
                                Some(vec![content_section, wasm_code_section]),
                                vec![&defaults::albert_keypair()],
                            )
                        }
                        _ => panic!("unexpected bench test"),
                    };

                    (shell, signed_tx)
                },
                |(shell, signed_tx)| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn vote_proposal(c: &mut Criterion) {
    let mut group = c.benchmark_group("vote_proposal");
    let shell = BenchShell::default();
    let delegator_vote = shell.generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Yay,
            voter: defaults::albert_address(),
            delegations: vec![defaults::validator_address()],
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let validator_vote = shell.generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Nay,
            voter: defaults::validator_address(),
            delegations: vec![],
        },
        None,
        None,
        vec![&defaults::validator_keypair()],
    );

    for (signed_tx, bench_name) in [delegator_vote, validator_vote]
        .iter()
        .zip(["delegator_vote", "validator_vote"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn become_validator(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let address = address::testing::established_address_1();
    let consensus_key_sk = ed25519::SigScheme::generate(&mut csprng)
        .try_to_sk::<common::SecretKey>()
        .unwrap();
    let consensus_key = consensus_key_sk.to_public();

    let eth_cold_key_sk = &secp256k1::SigScheme::generate(&mut csprng)
        .try_to_sk::<common::SecretKey>()
        .unwrap();
    let eth_cold_key =
        secp256k1::PublicKey::try_from_pk(&eth_cold_key_sk.to_public())
            .unwrap();

    let eth_hot_key_sk = &secp256k1::SigScheme::generate(&mut csprng)
        .try_to_sk::<common::SecretKey>()
        .unwrap();
    let eth_hot_key =
        secp256k1::PublicKey::try_from_pk(&eth_hot_key_sk.to_public()).unwrap();

    let protocol_key_sk = ed25519::SigScheme::generate(&mut csprng)
        .try_to_sk::<common::SecretKey>()
        .unwrap();
    let protocol_key = protocol_key_sk.to_public();

    let shell = BenchShell::default();
    let data = BecomeValidator {
        address: address.clone(),
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        protocol_key,
        commission_rate: namada::types::dec::Dec::default(),
        max_commission_rate_change: namada::types::dec::Dec::default(),
        email: "null@null.net".to_string(),
        description: None,
        website: None,
        discord_handle: None,
    };
    let tx = shell.generate_tx(
        TX_BECOME_VALIDATOR_WASM,
        data,
        None,
        None,
        vec![
            &defaults::albert_keypair(),
            &consensus_key_sk,
            eth_cold_key_sk,
            eth_hot_key_sk,
            &protocol_key_sk,
        ],
    );

    c.bench_function("become_validator", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();
                // Initialize the account to be able to use it
                shell
                    .wl_storage
                    .write_bytes(
                        &namada::types::storage::Key::validity_predicate(
                            &address,
                        ),
                        vec![],
                    )
                    .unwrap();
                shell
            },
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn change_validator_commission(c: &mut Criterion) {
    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_CHANGE_VALIDATOR_COMMISSION_WASM,
        CommissionChange {
            validator: defaults::validator_address(),
            new_rate: namada::types::dec::Dec::new(6, 2).unwrap(),
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("change_validator_commission", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn change_consensus_key(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let consensus_sk = ed25519::SigScheme::generate(&mut csprng)
        .try_to_sk::<common::SecretKey>()
        .unwrap();
    let consensus_pk = consensus_sk.to_public();

    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_CHANGE_CONSENSUS_KEY_WASM,
        ConsensusKeyChange {
            validator: defaults::validator_address(),
            consensus_key: consensus_pk,
        },
        None,
        None,
        vec![&defaults::validator_keypair(), &consensus_sk],
    );

    c.bench_function("change_consensus_key", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn change_validator_metadata(c: &mut Criterion) {
    // Choose just one piece of data arbitrarily to change
    let metadata_change = MetaDataChange {
        validator: defaults::validator_address(),
        email: None,
        description: Some("I will change this piece of data".to_string()),
        website: None,
        discord_handle: None,
        commission_rate: None,
    };

    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_CHANGE_VALIDATOR_METADATA_WASM,
        metadata_change,
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("change_validator_metadata", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn ibc(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_ibc");
    let shell = BenchShell::default();

    // Connection handshake
    let msg = MsgConnectionOpenInit {
        client_id_on_a: ClientId::new(
            ClientType::new("01-tendermint").unwrap(),
            1,
        )
        .unwrap(),
        counterparty: Counterparty::new(
            ClientId::from_str("01-tendermint-1").unwrap(),
            None,
            CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap(),
        ),
        version: Some(Version::default()),
        delay_period: std::time::Duration::new(100, 0),
        signer: defaults::albert_address().to_string().into(),
    };
    let open_connection = shell.generate_ibc_tx(TX_IBC_WASM, msg);

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
    let open_channel = shell.generate_ibc_tx(TX_IBC_WASM, msg);

    // Ibc transfer
    let outgoing_transfer = shell.generate_ibc_transfer_tx();

    // NOTE: Ibc encompass a variety of different messages that can be executed,
    // here we only benchmark a few of those
    for (signed_tx, bench_name) in
        [open_connection, open_channel, outgoing_transfer]
            .iter()
            .zip(["open_connection", "open_channel", "outgoing_transfer"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shell = BenchShell::default();
                    // Initialize the state according to the target tx
                    match bench_name {
                        "open_connection" => {
                            let _ = shell.init_ibc_client_state(
                                namada::core::types::storage::Key::from(
                                    Address::Internal(namada::types::address::InternalAddress::Ibc).to_db_key(),
                                ),
                            );
                        }
                        "open_channel" => {
                            let _ = shell.init_ibc_connection();
                        }
                        "outgoing_transfer" => shell.init_ibc_channel(),
                        _ => panic!("Unexpected bench test"),
                    }
                    shell
                },
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn unjail_validator(c: &mut Criterion) {
    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_UNJAIL_VALIDATOR_WASM,
        defaults::validator_address(),
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("unjail_validator", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();

                // Jail the validator
                let pos_params = read_pos_params(&shell.wl_storage).unwrap();
                let current_epoch = shell.wl_storage.storage.block.epoch;
                let evidence_epoch = current_epoch.prev();
                proof_of_stake::slashing::slash(
                    &mut shell.wl_storage,
                    &pos_params,
                    current_epoch,
                    evidence_epoch,
                    0u64,
                    SlashType::DuplicateVote,
                    &defaults::validator_address(),
                    current_epoch.next(),
                )
                .unwrap();

                shell.wl_storage.commit_tx();
                shell.commit();
                // Advance by slash epoch offset epochs
                for _ in 0..=pos_params.slash_processing_epoch_offset() {
                    shell.advance_epoch();
                }

                shell
            },
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn tx_bridge_pool(c: &mut Criterion) {
    let shell = BenchShell::default();

    let data = PendingTransfer {
        transfer: namada::types::eth_bridge_pool::TransferToEthereum {
            kind: namada::types::eth_bridge_pool::TransferToEthereumKind::Erc20,
            asset: read_native_erc20_address(&shell.wl_storage).unwrap(),
            recipient: namada::types::ethereum_events::EthAddress([1u8; 20]),
            sender: defaults::albert_address(),
            amount: Amount::from(1),
        },
        gas_fee: GasFee {
            amount: Amount::from(100),
            payer: defaults::albert_address(),
            token: shell.wl_storage.storage.native_token.clone(),
        },
    };
    let tx = shell.generate_tx(
        TX_BRIDGE_POOL_WASM,
        data,
        None,
        None,
        vec![&defaults::albert_keypair()],
    );
    c.bench_function("bridge pool", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn resign_steward(c: &mut Criterion) {
    c.bench_function("resign steward", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();
                namada::core::ledger::pgf::storage::keys::stewards_handle()
                    .insert(
                        &mut shell.wl_storage,
                        defaults::albert_address(),
                        StewardDetail::base(defaults::albert_address()),
                    )
                    .unwrap();

                let tx = shell.generate_tx(
                    TX_RESIGN_STEWARD,
                    defaults::albert_address(),
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                );

                (shell, tx)
            },
            |(shell, tx)| shell.execute_tx(tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn update_steward_commission(c: &mut Criterion) {
    c.bench_function("update steward commission", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();
                namada::core::ledger::pgf::storage::keys::stewards_handle()
                    .insert(
                        &mut shell.wl_storage,
                        defaults::albert_address(),
                        StewardDetail::base(defaults::albert_address()),
                    )
                    .unwrap();

                let data =
                    namada::types::transaction::pgf::UpdateStewardCommission {
                        steward: defaults::albert_address(),
                        commission: HashMap::from([(
                            defaults::albert_address(),
                            namada::types::dec::Dec::zero(),
                        )]),
                    };
                let tx = shell.generate_tx(
                    TX_UPDATE_STEWARD_COMMISSION,
                    data,
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                );

                (shell, tx)
            },
            |(shell, tx)| shell.execute_tx(tx),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn deactivate_validator(c: &mut Criterion) {
    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_DEACTIVATE_VALIDATOR_WASM,
        defaults::validator_address(),
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("deactivate_validator", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn reactivate_validator(c: &mut Criterion) {
    let shell = BenchShell::default();
    let signed_tx = shell.generate_tx(
        TX_REACTIVATE_VALIDATOR_WASM,
        defaults::validator_address(),
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    c.bench_function("reactivate_validator", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();

                // Deactivate the validator
                let pos_params = read_pos_params(&shell.wl_storage).unwrap();
                let current_epoch = shell.wl_storage.storage.block.epoch;
                proof_of_stake::deactivate_validator(
                    &mut shell.wl_storage,
                    &defaults::validator_address(),
                    current_epoch,
                )
                .unwrap();

                shell.wl_storage.commit_tx();
                shell.commit();
                // Advance by slash epoch offset epochs
                for _ in 0..=pos_params.pipeline_len {
                    shell.advance_epoch();
                }

                shell
            },
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn claim_rewards(c: &mut Criterion) {
    let mut group = c.benchmark_group("claim_rewards");
    let shell = BenchShell::default();

    let claim = shell.generate_tx(
        TX_CLAIM_REWARDS_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let self_claim = shell.generate_tx(
        TX_CLAIM_REWARDS_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: None,
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    for (signed_tx, bench_name) in
        [claim, self_claim].iter().zip(["claim", "self_claim"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shell = BenchShell::default();

                    // Advance Epoch for pipeline and unbonding length
                    let params = proof_of_stake::storage::read_pos_params(
                        &shell.wl_storage,
                    )
                    .unwrap();
                    let advance_epochs =
                        params.pipeline_len + params.unbonding_len;

                    for _ in 0..=advance_epochs {
                        shell.advance_epoch();
                    }

                    shell
                },
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

criterion_group!(
    whitelisted_txs,
    transfer,
    bond,
    unbond,
    withdraw,
    redelegate,
    reveal_pk,
    update_account,
    init_account,
    init_proposal,
    vote_proposal,
    become_validator,
    change_validator_commission,
    ibc,
    unjail_validator,
    tx_bridge_pool,
    resign_steward,
    update_steward_commission,
    deactivate_validator,
    reactivate_validator,
    change_validator_metadata,
    claim_rewards,
    change_consensus_key
);
criterion_main!(whitelisted_txs);
