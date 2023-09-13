use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::ledger::governance::storage::proposal::ProposalType;
use namada::core::ledger::governance::storage::vote::{
    StorageProposalVote, VoteType,
};
use namada::core::types::key::{
    common, SecretKey as SecretKeyInterface, SigScheme,
};
use namada::core::types::token::Amount;
use namada::core::types::transaction::account::{InitAccount, UpdateAccount};
use namada::core::types::transaction::pos::InitValidator;
use namada::ledger::storage_api::StorageRead;
use namada::proof_of_stake::types::SlashType;
use namada::proof_of_stake::{self, read_pos_params};
use namada::proto::{Code, Section};
use namada::types::hash::Hash;
use namada::types::key::{ed25519, secp256k1, PublicKey, RefTo};
use namada::types::masp::{TransferSource, TransferTarget};
use namada::types::storage::Key;
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada::types::transaction::pos::{Bond, CommissionChange, Withdraw};
use namada::types::transaction::EllipticCurve;
use namada_apps::wallet::defaults;
use namada_benches::{
    generate_ibc_transfer_tx, generate_tx, BenchShell, BenchShieldedCtx,
    ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY, BERTHA_PAYMENT_ADDRESS,
    TX_BOND_WASM, TX_CHANGE_VALIDATOR_COMMISSION_WASM, TX_INIT_PROPOSAL_WASM,
    TX_REVEAL_PK_WASM, TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM,
    TX_UPDATE_ACCOUNT_WASM, TX_VOTE_PROPOSAL_WASM, VP_VALIDATOR_WASM,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::Digest;

const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";

// TODO: need to benchmark tx_bridge_pool.wasm
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
                    shielded_ctx.shell.execute_tx(signed_tx);
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
            amount: Amount::native_whole(1000),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    let self_bond = generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: None,
        },
        None,
        None,
        Some(&defaults::validator_keypair()),
    );

    for (signed_tx, bench_name) in
        [bond, self_bond].iter().zip(["bond", "self_bond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
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
            amount: Amount::native_whole(1000),
            source: Some(defaults::albert_address()),
        },
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    let self_unbond = generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: None,
        },
        None,
        None,
        Some(&defaults::validator_keypair()),
    );

    for (signed_tx, bench_name) in
        [unbond, self_unbond].iter().zip(["unbond", "self_unbond"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
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
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    let self_withdraw = generate_tx(
        TX_WITHDRAW_WASM,
        Withdraw {
            validator: defaults::validator_address(),
            source: None,
        },
        None,
        None,
        Some(&defaults::validator_keypair()),
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
                        "withdraw" => generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::native_whole(1000),
                                source: Some(defaults::albert_address()),
                            },
                            None,
                            None,
                            Some(&defaults::albert_keypair()),
                        ),
                        "self_withdraw" => generate_tx(
                            TX_UNBOND_WASM,
                            Bond {
                                validator: defaults::validator_address(),
                                amount: Amount::native_whole(1000),
                                source: None,
                            },
                            None,
                            None,
                            Some(&defaults::validator_keypair()),
                        ),
                        _ => panic!("Unexpected bench test"),
                    };

                    shell.execute_tx(&unbond_tx);
                    shell.wl_storage.commit_tx();

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

    let tx = generate_tx(
        TX_REVEAL_PK_WASM,
        new_implicit_account.to_public(),
        None,
        None,
        None,
    );

    c.bench_function("reveal_pk", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn update_vp(c: &mut Criterion) {
    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_VALIDATOR_WASM))
        .unwrap();
    let extra_section = Section::ExtraData(Code::from_hash(vp_code_hash));
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
    let vp = generate_tx(
        TX_UPDATE_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        Some(&defaults::albert_keypair()),
    );

    c.bench_function("update_vp", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&vp),
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

    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_VALIDATOR_WASM))
        .unwrap();
    let extra_section = Section::ExtraData(Code::from_hash(vp_code_hash));
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
    let tx = generate_tx(
        TX_INIT_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        Some(&defaults::albert_keypair()),
    );

    c.bench_function("init_account", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
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
                    let shell = BenchShell::default();

                    let signed_tx = match bench_name {
                        "minimal_proposal" => {
                            let content_section =
                                Section::ExtraData(Code::new(vec![]));
                            generate_tx(
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
                                Some(&defaults::albert_keypair()),
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
                                ]));
                            let wasm_code_section =
                                Section::ExtraData(Code::new(vec![
                                    0;
                                    max_code_size
                                        as _
                                ]));

                            generate_tx(
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
                                Some(&defaults::albert_keypair()),
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
            vote: StorageProposalVote::Yay(VoteType::Default),
            voter: defaults::albert_address(),
            delegations: vec![defaults::validator_address()],
        },
        None,
        None,
        Some(&defaults::albert_keypair()),
    );

    let validator_vote = generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: StorageProposalVote::Nay,
            voter: defaults::validator_address(),
            delegations: vec![],
        },
        None,
        None,
        Some(&defaults::validator_keypair()),
    );

    for (signed_tx, bench_name) in [delegator_vote, validator_vote]
        .iter()
        .zip(["delegator_vote", "validator_vote"])
    {
        group.bench_function(bench_name, |b| {
            b.iter_batched_ref(
                BenchShell::default,
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

    let eth_cold_key = secp256k1::PublicKey::try_from_pk(
        &secp256k1::SigScheme::generate(&mut csprng)
            .try_to_sk::<common::SecretKey>()
            .unwrap()
            .to_public(),
    )
    .unwrap();
    let eth_hot_key = secp256k1::PublicKey::try_from_pk(
        &secp256k1::SigScheme::generate(&mut csprng)
            .try_to_sk::<common::SecretKey>()
            .unwrap()
            .to_public(),
    )
    .unwrap();
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

    let shell = BenchShell::default();
    let validator_vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_VALIDATOR_WASM))
        .unwrap();
    let extra_section =
        Section::ExtraData(Code::from_hash(validator_vp_code_hash));
    let extra_hash = Hash(
        extra_section
            .hash(&mut sha2::Sha256::new())
            .finalize_reset()
            .into(),
    );
    let data = InitValidator {
        account_keys: vec![defaults::albert_keypair().to_public()],
        threshold: 1,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        protocol_key,
        dkg_key,
        commission_rate: namada::types::dec::Dec::default(),
        max_commission_rate_change: namada::types::dec::Dec::default(),
        validator_vp_code_hash: extra_hash,
    };
    let tx = generate_tx(
        TX_INIT_VALIDATOR_WASM,
        data,
        None,
        Some(vec![extra_section]),
        Some(&defaults::albert_keypair()),
    );

    c.bench_function("init_validator", |b| {
        b.iter_batched_ref(
            BenchShell::default,
            |shell| shell.execute_tx(&tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn change_validator_commission(c: &mut Criterion) {
    let signed_tx = generate_tx(
        TX_CHANGE_VALIDATOR_COMMISSION_WASM,
        CommissionChange {
            validator: defaults::validator_address(),
            new_rate: namada::types::dec::Dec::new(6, 2).unwrap(),
        },
        None,
        None,
        Some(&defaults::validator_keypair()),
    );

    c.bench_function("change_validator_commission", |b| {
        b.iter_batched_ref(
            BenchShell::default,
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
                let mut shell = BenchShell::default();
                shell.init_ibc_channel();

                shell
            },
            |shell| shell.execute_tx(&signed_tx),
            criterion::BatchSize::LargeInput,
        )
    });
}

fn unjail_validator(c: &mut Criterion) {
    let signed_tx = generate_tx(
        TX_UNJAIL_VALIDATOR_WASM,
        defaults::validator_address(),
        None,
        None,
        Some(&defaults::validator_keypair()),
    );

    c.bench_function("unjail_validator", |b| {
        b.iter_batched_ref(
            || {
                let mut shell = BenchShell::default();

                // Jail the validator
                let pos_params = read_pos_params(&shell.wl_storage).unwrap();
                let current_epoch = shell.wl_storage.storage.block.epoch;
                let evidence_epoch = current_epoch.prev();
                proof_of_stake::slash(
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
    ibc,
    unjail_validator
);
criterion_main!(whitelisted_txs);
