use std::collections::BTreeSet;
use std::str::FromStr;

use criterion::{criterion_group, criterion_main, Criterion};
use namada::core::ledger::governance::storage::proposal::ProposalType;
use namada::core::ledger::governance::storage::vote::{
    StorageProposalVote, VoteType,
};
use namada::core::types::address::{self, Address};
use namada::core::types::token::{Amount, Transfer};
use namada::ibc::core::ics02_client::client_type::ClientType;
use namada::ibc::core::ics03_connection::connection::Counterparty;
use namada::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use namada::ibc::core::ics03_connection::version::Version;
use namada::ibc::core::ics04_channel::channel::Order;
use namada::ibc::core::ics04_channel::msgs::MsgChannelOpenInit;
use namada::ibc::core::ics04_channel::Version as ChannelVersion;
use namada::ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use namada::ibc::core::ics24_host::identifier::{
    ClientId, ConnectionId, PortId,
};
use namada::ledger::gas::{TxGasMeter, VpGasMeter};
use namada::ledger::governance::GovernanceVp;
use namada::ledger::native_vp::ibc::Ibc;
use namada::ledger::native_vp::multitoken::MultitokenVp;
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::ledger::storage_api::StorageRead;
use namada::proto::{Code, Section};
use namada::types::address::InternalAddress;
use namada::types::storage::{Epoch, TxIndex};
use namada::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_apps::wallet::defaults;
use namada_benches::{
    generate_foreign_key_tx, generate_ibc_transfer_tx, generate_ibc_tx,
    generate_tx, BenchShell, TX_IBC_WASM, TX_INIT_PROPOSAL_WASM,
    TX_TRANSFER_WASM, TX_VOTE_PROPOSAL_WASM,
};

fn governance(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_governance");

    for bench_name in [
        "foreign_key_write",
        "delegator_vote",
        "validator_vote",
        "minimal_proposal",
        "complete_proposal",
    ] {
        let mut shell = BenchShell::default();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                generate_foreign_key_tx(&defaults::albert_keypair())
            }
            "delegator_vote" => {
                // Advance to the proposal voting period
                shell.advance_epoch();
                generate_tx(
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
                )
            }
            "validator_vote" => {
                // Advance to the proposal voting period
                shell.advance_epoch();
                generate_tx(
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
                )
            }
            "minimal_proposal" => {
                let content_section = Section::ExtraData(Code::new(vec![]));
                let voting_start_epoch = Epoch(25);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.wl_storage.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        id: None,
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default(None),
                        voting_start_epoch,
                        voting_end_epoch: 28.into(),
                        grace_epoch: 34.into(),
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
                    .expect("Missing max_code_size parameter in storage");
                let max_proposal_content_size: u64 = shell
                    .wl_storage
                    .read(&max_proposal_content_key)
                    .expect("Error while reading from storage")
                    .expect(
                        "Missing max_proposal_content parameter in storage",
                    );
                let content_section = Section::ExtraData(Code::new(vec![
                        0;
                        max_proposal_content_size
                            as _
                    ]));
                let wasm_code_section =
                    Section::ExtraData(Code::new(vec![0; max_code_size as _]));

                let voting_start_epoch = Epoch(25);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.wl_storage.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        id: Some(1),
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default(Some(
                            wasm_code_section.get_hash(),
                        )),
                        voting_start_epoch,
                        voting_end_epoch: 28.into(),
                        grace_epoch: 34.into(),
                    },
                    None,
                    Some(vec![content_section, wasm_code_section]),
                    Some(&defaults::albert_keypair()),
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

        let governance = GovernanceVp {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::Governance),
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                &signed_tx,
                &TxIndex(0),
                VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
                    u64::MAX.into(),
                )),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    governance
                        .validate_tx(
                            &signed_tx,
                            governance.ctx.keys_changed,
                            governance.ctx.verifiers,
                        )
                        .unwrap()
                )
            })
        });
    }

    group.finish();
}

// TODO: missing native vps
//    - pos
//    - parameters
//    - eth bridge
//    - eth bridge pool

// TODO: uncomment when SlashFund internal address is brought back
// fn slash_fund(c: &mut Criterion) {
//      let mut group = c.benchmark_group("vp_slash_fund");

//      // Write a random key under a foreign subspace
//      let foreign_key_write =
//          generate_foreign_key_tx(&defaults::albert_keypair());

//      let content_section = Section::ExtraData(Code::new(vec![]));
//      let governance_proposal = generate_tx(
//          TX_INIT_PROPOSAL_WASM,
//          InitProposalData {
//              id: None,
//              content: content_section.get_hash(),
//              author: defaults::albert_address(),
//              r#type: ProposalType::Default(None),
//              voting_start_epoch: 12.into(),
//              voting_end_epoch: 15.into(),
//              grace_epoch: 18.into(),
//          },
//          None,
//          Some(vec![content_section]),
//          Some(&defaults::albert_keypair()),
//      );

//      for (tx, bench_name) in [foreign_key_write, governance_proposal]
//          .into_iter()
//          .zip(["foreign_key_write", "governance_proposal"])
//      {
//          let mut shell = BenchShell::default();

//          // Run the tx to validate
//          shell.execute_tx(&tx);

//          let (verifiers, keys_changed) = shell
//              .wl_storage
//              .write_log
//              .verifiers_and_changed_keys(&BTreeSet::default());

//          let slash_fund = SlashFundVp {
//              ctx: Ctx::new(
//                  &Address::Internal(InternalAddress::SlashFund),
//                  &shell.wl_storage.storage,
//                  &shell.wl_storage.write_log,
//                  &tx,
//                  &TxIndex(0),
//
// VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
// u64::MAX.into(),                  )),
//                  &keys_changed,
//                  &verifiers,
//                  shell.vp_wasm_cache.clone(),
//              ),
//          };

//          group.bench_function(bench_name, |b| {
//              b.iter(|| {
//                  assert!(
//                      slash_fund
//                          .validate_tx(
//                              &tx,
//                              slash_fund.ctx.keys_changed,
//                              slash_fund.ctx.verifiers,
//                          )
//                          .unwrap()
//                  )
//              })
//          });
//      }

//      group.finish();
//  }

fn ibc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc");

    // Connection handshake
    let msg = MsgConnectionOpenInit {
        client_id_on_a: ClientId::new(
            ClientType::new("01-tendermint".to_string()).unwrap(),
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
    let open_connection = generate_ibc_tx(TX_IBC_WASM, msg);

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
    let open_channel = generate_ibc_tx(TX_IBC_WASM, msg);

    // Ibc transfer
    let outgoing_transfer = generate_ibc_transfer_tx();

    for (signed_tx, bench_name) in
        [open_connection, open_channel, outgoing_transfer]
            .iter()
            .zip(["open_connection", "open_channel", "outgoing_transfer"])
    {
        let mut shell = BenchShell::default();
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
                VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
                    u64::MAX.into(),
                )),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    ibc.validate_tx(
                        signed_tx,
                        ibc.ctx.keys_changed,
                        ibc.ctx.verifiers,
                    )
                    .unwrap()
                )
            })
        });
    }

    group.finish();
}

fn vp_multitoken(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_token");

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());

    let transfer = generate_tx(
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
        Some(&defaults::albert_keypair()),
    );

    for (signed_tx, bench_name) in [foreign_key_write, transfer]
        .iter()
        .zip(["foreign_key_write", "transfer"])
    {
        let mut shell = BenchShell::default();
        shell.execute_tx(signed_tx);
        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let multitoken = MultitokenVp {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::Multitoken),
                &shell.wl_storage.storage,
                &shell.wl_storage.write_log,
                signed_tx,
                &TxIndex(0),
                VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
                    u64::MAX.into(),
                )),
                &keys_changed,
                &verifiers,
                shell.vp_wasm_cache.clone(),
            ),
        };

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    multitoken
                        .validate_tx(
                            signed_tx,
                            multitoken.ctx.keys_changed,
                            multitoken.ctx.verifiers,
                        )
                        .unwrap()
                )
            })
        });
    }
}

criterion_group!(
    native_vps,
    governance,
    // slash_fund,
    ibc,
    vp_multitoken
);
criterion_main!(native_vps);
