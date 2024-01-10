use std::collections::BTreeSet;

use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::ledger::governance::storage::vote::ProposalVote;
use namada::core::types::address::{self, Address};
use namada::core::types::key::{
    common, SecretKey as SecretKeyInterface, SigScheme,
};
use namada::core::types::token::{Amount, Transfer};
use namada::core::types::transaction::account::UpdateAccount;
use namada::ledger::gas::{TxGasMeter, VpGasMeter};
use namada::proto::{Code, Section};
use namada::types::hash::Hash;
use namada::types::key::ed25519;
use namada::types::storage::{Key, TxIndex};
use namada::types::transaction::governance::VoteProposalData;
use namada::types::transaction::pos::{Bond, CommissionChange};
use namada::vm::wasm::run;
use namada_apps::bench_utils::{
    generate_foreign_key_tx, BenchShell, TX_BOND_WASM,
    TX_CHANGE_VALIDATOR_COMMISSION_WASM, TX_REVEAL_PK_WASM, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UPDATE_ACCOUNT_WASM, TX_VOTE_PROPOSAL_WASM,
    VP_USER_WASM,
};
use namada_apps::wallet::defaults;
use sha2::Digest;

const VP_IMPLICIT_WASM: &str = "vp_implicit.wasm";

fn vp_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_user");
    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_USER_WASM))
        .unwrap();

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());

    let transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::albert_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            amount: Amount::native_whole(1000).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    let received_transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::bertha_address(),
            target: defaults::albert_address(),
            token: address::nam(),
            amount: Amount::native_whole(1000).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::bertha_keypair()],
    );

    let vp_validator_hash = shell
        .read_storage_key(&Key::wasm_hash(VP_USER_WASM))
        .unwrap();
    let extra_section = Section::ExtraData(Code::from_hash(
        vp_validator_hash,
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
        public_keys: vec![defaults::albert_keypair().to_public()],
        threshold: None,
    };
    let vp = shell.generate_tx(
        TX_UPDATE_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        vec![&defaults::albert_keypair()],
    );

    let vote = shell.generate_tx(
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

    let pos = shell.generate_tx(
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

    for (signed_tx, bench_name) in [
        foreign_key_write,
        transfer,
        received_transfer,
        vote,
        pos,
        vp,
    ]
    .iter()
    .zip([
        "foreign_key_write",
        "transfer",
        "received_transfer",
        "governance_vote",
        "pos",
        "vp",
    ]) {
        let mut shell = BenchShell::default();
        shell.execute_tx(signed_tx);
        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    // NOTE: the wasm code is always in cache so we don't
                    // include here the cost to read and compile the vp code
                    run::vp(
                        vp_code_hash,
                        signed_tx,
                        &TxIndex(0),
                        &defaults::albert_address(),
                        &shell.wl_storage.storage,
                        &shell.wl_storage.write_log,
                        &mut VpGasMeter::new_from_tx_meter(
                            &TxGasMeter::new_from_sub_limit(u64::MAX.into())
                        ),
                        &keys_changed,
                        &verifiers,
                        shell.vp_wasm_cache.clone(),
                    )
                    .unwrap(),
                    "VP \"{bench_name}\" bench call failed"
                );
            })
        });
    }

    group.finish();
}

fn vp_implicit(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_implicit");

    let mut csprng = rand::rngs::OsRng {};
    let implicit_account: common::SecretKey =
        ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap();

    let foreign_key_write = generate_foreign_key_tx(&implicit_account);

    let shell = BenchShell::default();
    let transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: Address::from(&implicit_account.to_public()),
            target: defaults::bertha_address(),
            token: address::nam(),
            amount: Amount::native_whole(500).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&implicit_account],
    );

    let received_transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::bertha_address(),
            target: Address::from(&implicit_account.to_public()),
            token: address::nam(),
            amount: Amount::native_whole(1000).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::bertha_keypair()],
    );

    let reveal_pk = shell.generate_tx(
        TX_REVEAL_PK_WASM,
        &implicit_account.to_public(),
        None,
        None,
        vec![],
    );

    let pos = shell.generate_tx(
        TX_BOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: Some(Address::from(&implicit_account.to_public())),
        },
        None,
        None,
        vec![&implicit_account],
    );

    let vote = shell.generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Yay,
            voter: Address::from(&implicit_account.to_public()),
            delegations: vec![], /* NOTE: no need to bond tokens because the
                                  * implicit vp doesn't check that */
        },
        None,
        None,
        vec![&implicit_account],
    );

    for (tx, bench_name) in [
        &foreign_key_write,
        &reveal_pk,
        &transfer,
        &received_transfer,
        &pos,
        &vote,
    ]
    .into_iter()
    .zip([
        "foreign_key_write",
        "reveal_pk",
        "transfer",
        "received_transfer",
        "pos",
        "governance_vote",
    ]) {
        let mut shell = BenchShell::default();
        let vp_code_hash: Hash = shell
            .read_storage_key(&Key::wasm_hash(VP_IMPLICIT_WASM))
            .unwrap();

        if bench_name != "reveal_pk" {
            // Reveal public key
            shell.execute_tx(&reveal_pk);
            shell.wl_storage.commit_tx();
            shell.commit();
        }

        if bench_name == "transfer" || bench_name == "pos" {
            // Transfer some tokens to the implicit address
            shell.execute_tx(&received_transfer);
            shell.wl_storage.commit_tx();
            shell.commit();
        }

        // Run the tx to validate
        shell.execute_tx(tx);
        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    run::vp(
                        vp_code_hash,
                        tx,
                        &TxIndex(0),
                        &Address::from(&implicit_account.to_public()),
                        &shell.wl_storage.storage,
                        &shell.wl_storage.write_log,
                        &mut VpGasMeter::new_from_tx_meter(
                            &TxGasMeter::new_from_sub_limit(u64::MAX.into())
                        ),
                        &keys_changed,
                        &verifiers,
                        shell.vp_wasm_cache.clone(),
                    )
                    .unwrap()
                )
            })
        });
    }

    group.finish();
}

fn vp_validator(c: &mut Criterion) {
    let shell = BenchShell::default();
    let vp_code_hash: Hash = shell
        .read_storage_key(&Key::wasm_hash(VP_USER_WASM))
        .unwrap();
    let mut group = c.benchmark_group("vp_validator");

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::validator_account_keypair());

    let transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::validator_address(),
            target: defaults::bertha_address(),
            token: address::nam(),
            amount: Amount::native_whole(1000).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::validator_account_keypair()],
    );

    let received_transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer {
            source: defaults::bertha_address(),
            target: defaults::validator_address(),
            token: address::nam(),
            amount: Amount::native_whole(1000).native_denominated(),
            key: None,
            shielded: None,
        },
        None,
        None,
        vec![&defaults::bertha_keypair()],
    );

    let extra_section = Section::ExtraData(Code::from_hash(
        vp_code_hash,
        Some(VP_USER_WASM.to_string()),
    ));
    let data = UpdateAccount {
        addr: defaults::validator_address(),
        vp_code_hash: Some(Hash(
            extra_section
                .hash(&mut sha2::Sha256::new())
                .finalize_reset()
                .into(),
        )),
        public_keys: vec![defaults::validator_account_keypair().to_public()],
        threshold: None,
    };
    let vp = shell.generate_tx(
        TX_UPDATE_ACCOUNT_WASM,
        data,
        None,
        Some(vec![extra_section]),
        vec![&defaults::validator_account_keypair()],
    );

    let commission_rate = shell.generate_tx(
        TX_CHANGE_VALIDATOR_COMMISSION_WASM,
        CommissionChange {
            validator: defaults::validator_address(),
            new_rate: namada::types::dec::Dec::new(6, 2).unwrap(),
        },
        None,
        None,
        vec![&defaults::validator_account_keypair()],
    );

    let vote = shell.generate_tx(
        TX_VOTE_PROPOSAL_WASM,
        VoteProposalData {
            id: 0,
            vote: ProposalVote::Yay,
            voter: defaults::validator_address(),
            delegations: vec![],
        },
        None,
        None,
        vec![&defaults::validator_account_keypair()],
    );

    let pos = shell.generate_tx(
        TX_UNBOND_WASM,
        Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: None,
        },
        None,
        None,
        vec![&defaults::validator_account_keypair()],
    );

    for (signed_tx, bench_name) in [
        foreign_key_write,
        transfer,
        received_transfer,
        vote,
        pos,
        commission_rate,
        vp,
    ]
    .iter()
    .zip([
        "foreign_key_write",
        "transfer",
        "received_transfer",
        "governance_vote",
        "pos",
        "commission_rate",
        "vp",
    ]) {
        let mut shell = BenchShell::default();

        shell.execute_tx(signed_tx);
        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    run::vp(
                        vp_code_hash,
                        signed_tx,
                        &TxIndex(0),
                        &defaults::validator_address(),
                        &shell.wl_storage.storage,
                        &shell.wl_storage.write_log,
                        &mut VpGasMeter::new_from_tx_meter(
                            &TxGasMeter::new_from_sub_limit(u64::MAX.into())
                        ),
                        &keys_changed,
                        &verifiers,
                        shell.vp_wasm_cache.clone(),
                    )
                    .unwrap()
                );
            })
        });
    }

    group.finish();
}

criterion_group!(whitelisted_vps, vp_user, vp_implicit, vp_validator,);
criterion_main!(whitelisted_vps);
