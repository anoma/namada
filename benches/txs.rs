use borsh::BorshSerialize;
use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::types::key::{
    common, SecretKey as SecretKeyInterface, SigScheme,
};
use namada::core::types::token::Amount;
use namada::ledger::governance;
use namada::proof_of_stake;
use namada::proto::Tx;
use namada::types::chain::ChainId;
use namada::types::governance::{ProposalVote, VoteType};
use namada::types::key::{ed25519, secp256k1};
use namada::types::masp::{TransferSource, TransferTarget};
use namada::types::transaction::governance::{
    InitProposalData, ProposalType, VoteProposalData,
};
use namada::types::transaction::pos::{Bond, CommissionChange, Withdraw};
use namada::types::transaction::EllipticCurve;
use namada::types::transaction::{InitAccount, InitValidator, UpdateVp};
use namada_apps::wallet::defaults;
use namada_apps::wasm_loader;
use namada_benches::{
    generate_ibc_transfer_tx, generate_tx, BenchShell, BenchShieldedCtx,
    ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY, BERTHA_PAYMENT_ADDRESS,
    TX_BOND_WASM, TX_CHANGE_VALIDATOR_COMMISSION_WASM, TX_INIT_PROPOSAL_WASM,
    TX_REVEAL_PK_WASM, TX_UNBOND_WASM, TX_UPDATE_VP_WASM,
    TX_VOTE_PROPOSAL_WASM, WASM_DIR,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rust_decimal::Decimal;

const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";

fn transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer");
    let amount = Amount::whole(500);

    for bench_name in ["transparent", "shielding", "unshielding", "shielded"] {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shielded_ctx = BenchShieldedCtx::new();

                    let albert_spending_key = shielded_ctx
                        .ctx
                        .wallet
                        .find_spending_key(ALBERT_SPENDING_KEY)
                        .unwrap()
                        .to_owned();
                    let albert_payment_addr = shielded_ctx
                        .ctx
                        .wallet
                        .find_payment_addr(ALBERT_PAYMENT_ADDRESS)
                        .unwrap()
                        .to_owned();
                    let bertha_payment_addr = shielded_ctx
                        .ctx
                        .wallet
                        .find_payment_addr(BERTHA_PAYMENT_ADDRESS)
                        .unwrap()
                        .to_owned();

                    // Shield some tokens for Albert
                    let shield_tx = shielded_ctx.generate_masp_tx(
                        amount,
                        TransferSource::Address(defaults::albert_address()),
                        TransferTarget::PaymentAddress(albert_payment_addr),
                    );
                    shielded_ctx.shell.execute_tx(&shield_tx);
                    shielded_ctx.shell.wl_storage.commit_tx();
                    shielded_ctx.shell.commit();

                    let signed_tx = match bench_name {
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
                    shielded_ctx.shell.execute_tx(&signed_tx);
                },
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

fn bond(c: &mut Criterion) {
    let mut group = c.benchmark_group("bond");

    let bond = generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::whole(1000),
            source: Some(defaults::albert_address()),
        },
        &defaults::albert_keypair(),
    );

    let self_bond = generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::whole(1000),
            source: None,
        },
        &defaults::validator_keypair(),
    );

    for (signed_tx, bench_name) in
        [bond, self_bond].iter().zip(["bond", "self_bond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::new,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

fn unbond(c: &mut Criterion) {
    let mut group = c.benchmark_group("unbond");

    let unbond = generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::whole(1000),
            source: Some(defaults::albert_address()),
        },
        &defaults::albert_keypair(),
    );

    let self_unbond = generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::whole(1000),
            source: None,
        },
        &defaults::validator_keypair(),
    );

    for (signed_tx, bench_name) in
        [unbond, self_unbond].iter().zip(["unbond", "self_unbond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::new,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

fn withdraw(c: &mut Criterion) {
    let mut group = c.benchmark_group("withdraw");

    let withdraw = generate_tx(
        TX_WITHDRAW_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: Some(defaults::albert_address()),
        },
        &defaults::albert_keypair(),
    );

    let self_withdraw = generate_tx(
        TX_WITHDRAW_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: None,
        },
        &defaults::validator_keypair(),
    );

    for (signed_tx, bench_name) in [withdraw, self_withdraw]
        .iter()
        .zip(["withdraw", "self_withdraw"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let mut shell = BenchShell::new();

                    // Unbond funds
                    let unbond_tx = match bench_name {
                        "withdraw" => generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::whole(1000),
                                source: Some(defaults::albert_address()),
                            },
                            &defaults::albert_keypair(),
                        ),
                        "self_withdraw" => generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::whole(1000),
                                source: None,
                            },
                            &defaults::validator_keypair(),
                        ),
                        _ => panic!("Unexpected bench test"),
                    };

                    shell.execute_tx(&unbond_tx);

                    // Advance Epoch for pipeline and unbonding length
                    let params =
                        proof_of_stake::read_pos_params(&shell.wl_storage)
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

fn reveal_pk(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let new_implicit_account: common::SecretKey =
        ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap();

    let tx = Tx::new(
        wasm_loader::read_wasm_or_exit(WASM_DIR, TX_REVEAL_PK_WASM),
        Some(new_implicit_account.to_public().try_to_vec().unwrap()),
        ChainId("bench".to_string()),
        None,
    );

    c.bench_function("reveal_pk", |b| {
        b.iter_batched_ref(
            BenchShell::new,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn update_vp(c: &mut Criterion) {
    let signed_tx = generate_tx(
        TX_UPDATE_VP_WASM,
        UpdateVp {
            addr: defaults::albert_address(),
            vp_code: wasm_loader::read_wasm_or_exit(
                WASM_DIR,
                "vp_validator.wasm",
            ),
        },
        &defaults::albert_keypair(),
    );

    c.bench_function("update_vp", |b| {
        b.iter_batched_ref(
            BenchShell::new,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn init_account(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let new_account: common::SecretKey =
        ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap();

    let signed_tx = generate_tx(
        TX_INIT_ACCOUNT_WASM,
        InitAccount {
            public_key: new_account.to_public(),
            vp_code: wasm_loader::read_wasm_or_exit(WASM_DIR, "vp_user.wasm"),
        },
        &new_account,
    );

    c.bench_function("init_account", |b| {
        b.iter_batched_ref(
            BenchShell::new,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn init_proposal(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_proposal");

    for bench_name in ["minimal_proposal", "complete_proposal"] {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                || {
                    let shell = BenchShell::new();

                    let signed_tx = match bench_name {
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
                            let max_code_size = shell
                                .read_storage_key(&max_code_size_key)
                                .unwrap();
                            let max_proposal_content_size = shell
                                .read_storage_key(&max_proposal_content_key)
                                .unwrap();

                            generate_tx(
                                TX_INIT_PROPOSAL_WASM,
                                InitProposalData {
                                    id: Some(1),
                                    content: vec![0; max_proposal_content_size],
                                    author: defaults::albert_address(),
                                    r#type: ProposalType::Default(Some(
                                        vec![0; max_code_size],
                                    )),
                                    voting_start_epoch: 12.into(),
                                    voting_end_epoch: 15.into(),
                                    grace_epoch: 18.into(),
                                },
                                &defaults::albert_keypair(),
                            )
                        }
                        _ => panic!("unexpected bench test"),
                    };

                    (shell, signed_tx)
                },
                |(shell, signed_tx)| shell.execute_tx(signed_tx),
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

fn vote_proposal(c: &mut Criterion) {
    let mut group = c.benchmark_group("vote_proposal");
    let delegator_vote = generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Yay(VoteType::Default),
            voter: defaults::albert_address(),
            delegations: vec![defaults::validator_address()],
        },
        &defaults::albert_keypair(),
    );

    let validator_vote = generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Nay,
            voter: defaults::validator_address(),
            delegations: vec![],
        },
        &defaults::validator_keypair(),
    );

    for (signed_tx, bench_name) in [delegator_vote, validator_vote]
        .iter()
        .zip(["delegator_vote", "validator_vote"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::new,
                |shell| shell.execute_tx(signed_tx),
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

fn init_validator(c: &mut Criterion) {
    let mut csprng = rand::rngs::OsRng {};
    let consensus_key: common::PublicKey =
        secp256k1::SigScheme::generate(&mut csprng)
            .try_to_sk::<common::SecretKey>()
            .unwrap()
            .to_public();

    let protocol_key: common::PublicKey =
        secp256k1::SigScheme::generate(&mut csprng)
            .try_to_sk::<common::SecretKey>()
            .unwrap()
            .to_public();

    let dkg_key = ferveo_common::Keypair::<EllipticCurve>::new(
        &mut StdRng::from_entropy(),
    )
    .public()
    .into();

    let signed_tx = generate_tx(
        TX_INIT_VALIDATOR_WASM,
        InitValidator {
            account_key: defaults::albert_keypair().to_public(),
            consensus_key,
            protocol_key,
            dkg_key,
            commission_rate: Decimal::default(),
            max_commission_rate_change: Decimal::default(),
            validator_vp_code: wasm_loader::read_wasm_or_exit(
                WASM_DIR,
                "vp_validator.wasm",
            ),
        },
        &defaults::albert_keypair(),
    );

    c.bench_function("init_validator", |b| {
        b.iter_batched_ref(
            BenchShell::new,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn change_validator_commission(c: &mut Criterion) {
    let signed_tx = generate_tx(
        TX_CHANGE_VALIDATOR_COMMISSION_WASM,
        CommissionChange {
            validator: defaults::validator_address(),
            new_rate: Decimal::new(6, 2),
        },
        &defaults::validator_keypair(),
    );

    c.bench_function("change_validator_commission", |b| {
        b.iter_batched_ref(
            BenchShell::new,
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn ibc(c: &mut Criterion) {
    let signed_tx = generate_ibc_transfer_tx();

    c.bench_function("ibc_transfer", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::new();
                shell.init_ibc_channel();

                shell
            },
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

criterion_group!(
    whitelisted_txs,
    transfer,
    bond,
    unbond,
    withdraw,
    reveal_pk,
    update_vp,
    init_account,
    init_proposal,
    vote_proposal,
    init_validator,
    change_validator_commission,
    ibc
);
criterion_main!(whitelisted_txs);
