use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::str::FromStr;

use criterion::{criterion_group, criterion_main, Criterion};
use masp_primitives::bls12_381;
use masp_primitives::sapling::Node;
use namada::core::types::address::{self, Address};
use namada::core::types::token::{Amount, Transfer};
use namada::eth_bridge::storage::whitelist;
use namada::governance::pgf::storage::steward::StewardDetail;
use namada::governance::storage::proposal::ProposalType;
use namada::governance::storage::vote::{StorageProposalVote, VoteType};
use namada::governance::{InitProposalData, VoteProposalData};
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
use namada::ibc::{IbcActions, TransferModule};
use namada::ledger::eth_bridge::read_native_erc20_address;
use namada::ledger::gas::{TxGasMeter, VpGasMeter};
use namada::ledger::governance::GovernanceVp;
use namada::ledger::native_vp::ethereum_bridge::bridge_pool_vp::BridgePoolVp;
use namada::ledger::native_vp::ethereum_bridge::nut::NonUsableTokens;
use namada::ledger::native_vp::ethereum_bridge::vp::EthBridge;
use namada::ledger::native_vp::ibc::context::PseudoExecutionContext;
use namada::ledger::native_vp::ibc::Ibc;
use namada::ledger::native_vp::masp::MaspVp;
use namada::ledger::native_vp::multitoken::MultitokenVp;
use namada::ledger::native_vp::parameters::ParametersVp;
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::ledger::pgf::PgfVp;
use namada::ledger::pos::PosVP;
use namada::proof_of_stake;
use namada::proof_of_stake::KeySeg;
use namada::sdk::masp::verify_shielded_tx;
use namada::sdk::masp_primitives::merkle_tree::CommitmentTree;
use namada::sdk::masp_primitives::transaction::Transaction;
use namada::state::{StorageRead, StorageWrite};
use namada::token::storage_key::{
    MASP_NOTE_COMMITMENT_ANCHOR_PREFIX, MASP_NOTE_COMMITMENT_TREE_KEY,
};
use namada::tx::{Code, Section, Tx};
use namada::types::address::{InternalAddress, MASP};
use namada::types::eth_bridge_pool::{GasFee, PendingTransfer};
use namada::types::masp::{TransferSource, TransferTarget};
use namada::types::storage::{Epoch, TxIndex};
use namada_apps::bench_utils::{
    generate_foreign_key_tx, BenchShell, BenchShieldedCtx,
    ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY, BERTHA_PAYMENT_ADDRESS,
    TX_BRIDGE_POOL_WASM, TX_IBC_WASM, TX_INIT_PROPOSAL_WASM, TX_RESIGN_STEWARD,
    TX_TRANSFER_WASM, TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL_WASM,
};
use namada_apps::wallet::defaults;

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
                shell.generate_tx(
                    TX_VOTE_PROPOSAL_WASM,
                    VoteProposalData {
                        id: 0,
                        vote: StorageProposalVote::Yay(VoteType::Default),
                        voter: defaults::albert_address(),
                        delegations: vec![defaults::validator_address()],
                    },
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                )
            }
            "validator_vote" => {
                // Advance to the proposal voting period
                shell.advance_epoch();
                shell.generate_tx(
                    TX_VOTE_PROPOSAL_WASM,
                    VoteProposalData {
                        id: 0,
                        vote: StorageProposalVote::Nay,
                        voter: defaults::validator_address(),
                        delegations: vec![],
                    },
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                )
            }
            "minimal_proposal" => {
                let content_section =
                    Section::ExtraData(Code::new(vec![], None));
                let params =
                    proof_of_stake::storage::read_pos_params(&shell.wl_storage)
                        .unwrap();
                let voting_start_epoch =
                    Epoch(2 + params.pipeline_len + params.unbonding_len);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.wl_storage.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                shell.generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        id: None,
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default(None),
                        voting_start_epoch,
                        voting_end_epoch: voting_start_epoch + 3_u64,
                        grace_epoch: voting_start_epoch + 9_u64,
                    },
                    None,
                    Some(vec![content_section]),
                    vec![&defaults::albert_keypair()],
                )
            }
            "complete_proposal" => {
                let max_code_size_key =
                namada::governance::storage::keys::get_max_proposal_code_size_key();
                let max_proposal_content_key =
                    namada::governance::storage::keys::get_max_proposal_content_key();
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
                let content_section = Section::ExtraData(Code::new(
                    vec![0; max_proposal_content_size as _],
                    None,
                ));
                let wasm_code_section = Section::ExtraData(Code::new(
                    vec![0; max_code_size as _],
                    None,
                ));

                let params =
                    proof_of_stake::storage::read_pos_params(&shell.wl_storage)
                        .unwrap();
                let voting_start_epoch =
                    Epoch(2 + params.pipeline_len + params.unbonding_len);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.wl_storage.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                shell.generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        id: Some(1),
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default(Some(
                            wasm_code_section.get_hash(),
                        )),
                        voting_start_epoch,
                        voting_end_epoch: voting_start_epoch + 3_u64,
                        grace_epoch: voting_start_epoch + 9_u64,
                    },
                    None,
                    Some(vec![content_section, wasm_code_section]),
                    vec![&defaults::albert_keypair()],
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

// TODO: uncomment when SlashFund internal address is brought back
// fn slash_fund(c: &mut Criterion) {
//      let mut group = c.benchmark_group("vp_slash_fund");

//      // Write a random key under a foreign subspace
//      let foreign_key_write =
//          generate_foreign_key_tx(&defaults::albert_keypair());

//      let content_section = Section::ExtraData(Code::new(vec![]));
//      let governance_proposal = shell.generate_tx(
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
    let shell = BenchShell::default();

    // NOTE: Ibc encompass a variety of different messages that can be executed,
    // here we only benchmark a few of those Connection handshake
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

    for (signed_tx, bench_name) in
        [open_connection, open_channel, outgoing_transfer]
            .iter()
            .zip(["open_connection", "open_channel", "outgoing_transfer"])
    {
        let mut shell = BenchShell::default();
        // Initialize the state according to the target tx
        match bench_name {
            "open_connection" => {
                let _ = shell.init_ibc_client_state(
                    namada::core::types::storage::Key::from(
                        Address::Internal(InternalAddress::Ibc).to_db_key(),
                    ),
                );
            }
            "open_channel" => {
                let _ = shell.init_ibc_connection();
            }
            "outgoing_transfer" => shell.init_ibc_channel(),
            _ => panic!("Unexpected bench test"),
        }

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
    let mut group = c.benchmark_group("vp_multitoken");
    let shell = BenchShell::default();

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

// Generate and run masp transaction to be verified
fn setup_storage_for_masp_verification(
    bench_name: &str,
) -> (BenchShieldedCtx, Tx) {
    let amount = Amount::native_whole(500);
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
    let (mut shielded_ctx, shield_tx) = shielded_ctx.generate_masp_tx(
        amount,
        TransferSource::Address(defaults::albert_address()),
        TransferTarget::PaymentAddress(albert_payment_addr),
    );
    shielded_ctx.shell.execute_tx(&shield_tx);
    shielded_ctx.shell.wl_storage.commit_tx();

    // Update the anchor in storage
    let tree_key = namada::core::types::storage::Key::from(MASP.to_db_key())
        .push(&MASP_NOTE_COMMITMENT_TREE_KEY.to_owned())
        .expect("Cannot obtain a storage key");
    let updated_tree: CommitmentTree<Node> = shielded_ctx
        .shell
        .wl_storage
        .read(&tree_key)
        .unwrap()
        .unwrap();
    let anchor_key = namada::core::types::storage::Key::from(MASP.to_db_key())
        .push(&MASP_NOTE_COMMITMENT_ANCHOR_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&namada::core::types::hash::Hash(
            bls12_381::Scalar::from(updated_tree.root()).to_bytes(),
        ))
        .expect("Cannot obtain a storage key");
    shielded_ctx
        .shell
        .wl_storage
        .write(&anchor_key, ())
        .unwrap();

    shielded_ctx.shell.commit();

    let (mut shielded_ctx, signed_tx) = match bench_name {
        "shielding" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::Address(defaults::albert_address()),
            TransferTarget::PaymentAddress(albert_payment_addr),
        ),
        "unshielding" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::ExtendedSpendingKey(albert_spending_key),
            TransferTarget::Address(defaults::albert_address()),
        ),
        "shielded" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::ExtendedSpendingKey(albert_spending_key),
            TransferTarget::PaymentAddress(bertha_payment_addr),
        ),
        _ => panic!("Unexpected bench test"),
    };
    shielded_ctx.shell.execute_tx(&signed_tx);

    (shielded_ctx, signed_tx)
}

fn masp(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_masp");

    for bench_name in ["shielding", "unshielding", "shielded"] {
        group.bench_function(bench_name, |b| {
            let (shielded_ctx, signed_tx) =
                setup_storage_for_masp_verification(bench_name);
            let (verifiers, keys_changed) = shielded_ctx
                .shell
                .wl_storage
                .write_log
                .verifiers_and_changed_keys(&BTreeSet::default());

            let masp = MaspVp {
                ctx: Ctx::new(
                    &Address::Internal(InternalAddress::Masp),
                    &shielded_ctx.shell.wl_storage.storage,
                    &shielded_ctx.shell.wl_storage.write_log,
                    &signed_tx,
                    &TxIndex(0),
                    VpGasMeter::new_from_tx_meter(
                        &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
                    ),
                    &keys_changed,
                    &verifiers,
                    shielded_ctx.shell.vp_wasm_cache.clone(),
                ),
            };

            b.iter(|| {
                assert!(
                    masp.validate_tx(
                        &signed_tx,
                        masp.ctx.keys_changed,
                        masp.ctx.verifiers,
                    )
                    .unwrap()
                );
            })
        });
    }

    group.finish();
}

fn masp_verify_shielded_tx(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_masp_verify_shielded_tx");

    for bench_name in ["shielding", "unshielding", "shielded"] {
        group.bench_function(bench_name, |b| {
            let (_, signed_tx) =
                setup_storage_for_masp_verification(bench_name);

            let transaction = signed_tx
                .sections
                .into_iter()
                .filter_map(|section| match section {
                    Section::MaspTx(transaction) => Some(transaction),
                    _ => None,
                })
                .collect::<Vec<Transaction>>()
                .first()
                .unwrap()
                .to_owned();
            b.iter(|| {
                assert!(verify_shielded_tx(&transaction));
            })
        });
    }

    group.finish();
}

fn pgf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_pgf");

    for bench_name in [
        "foreign_key_write",
        "remove_steward",
        "steward_inflation_rate",
    ] {
        let mut shell = BenchShell::default();
        namada::governance::pgf::storage::keys::stewards_handle()
            .insert(
                &mut shell.wl_storage,
                defaults::albert_address(),
                StewardDetail::base(defaults::albert_address()),
            )
            .unwrap();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                generate_foreign_key_tx(&defaults::albert_keypair())
            }
            "remove_steward" => shell.generate_tx(
                TX_RESIGN_STEWARD,
                defaults::albert_address(),
                None,
                None,
                vec![&defaults::albert_keypair()],
            ),
            "steward_inflation_rate" => {
                let data = namada::tx::data::pgf::UpdateStewardCommission {
                    steward: defaults::albert_address(),
                    commission: HashMap::from([(
                        defaults::albert_address(),
                        namada::types::dec::Dec::zero(),
                    )]),
                };
                shell.generate_tx(
                    TX_UPDATE_STEWARD_COMMISSION,
                    data,
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
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

        let pgf = PgfVp {
            ctx: Ctx::new(
                &Address::Internal(InternalAddress::Pgf),
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
                    pgf.validate_tx(
                        &signed_tx,
                        pgf.ctx.keys_changed,
                        pgf.ctx.verifiers,
                    )
                    .unwrap()
                )
            })
        });
    }

    group.finish();
}

fn eth_bridge_nut(c: &mut Criterion) {
    let mut shell = BenchShell::default();
    let native_erc20_addres =
        read_native_erc20_address(&shell.wl_storage).unwrap();

    let signed_tx = {
        let data = PendingTransfer{
        transfer: namada::types::eth_bridge_pool::TransferToEthereum {
            kind: namada::types::eth_bridge_pool::TransferToEthereumKind::Erc20,
            asset: native_erc20_addres,
            recipient: namada::types::ethereum_events::EthAddress([1u8; 20]),
            sender: defaults::albert_address(),
            amount: Amount::from(1),
        },
        gas_fee: GasFee{
            amount: Amount::from(100),
            payer: defaults::albert_address(),
            token: shell.wl_storage.storage.native_token.clone(),
        },
    };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    shell.execute_tx(&signed_tx);

    let (verifiers, keys_changed) = shell
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&BTreeSet::default());

    let vp_address =
        Address::Internal(InternalAddress::Nut(native_erc20_addres));
    let nut = NonUsableTokens {
        ctx: Ctx::new(
            &vp_address,
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

    c.bench_function("vp_eth_bridge_nut", |b| {
        b.iter(|| {
            assert!(
                nut.validate_tx(
                    &signed_tx,
                    nut.ctx.keys_changed,
                    nut.ctx.verifiers,
                )
                .unwrap()
            )
        })
    });
}

fn eth_bridge(c: &mut Criterion) {
    let mut shell = BenchShell::default();
    let native_erc20_addres =
        read_native_erc20_address(&shell.wl_storage).unwrap();

    let signed_tx = {
        let data = PendingTransfer{
                transfer: namada::types::eth_bridge_pool::TransferToEthereum {
                    kind: namada::types::eth_bridge_pool::TransferToEthereumKind::Erc20,
                    asset: native_erc20_addres,
                    recipient: namada::types::ethereum_events::EthAddress([1u8; 20]),
                    sender: defaults::albert_address(),
                    amount: Amount::from(1),
                },
                gas_fee: GasFee{
                    amount: Amount::from(100),
                    payer: defaults::albert_address(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
            };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    shell.execute_tx(&signed_tx);

    let (verifiers, keys_changed) = shell
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&BTreeSet::default());

    let vp_address = Address::Internal(InternalAddress::EthBridge);
    let eth_bridge = EthBridge {
        ctx: Ctx::new(
            &vp_address,
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

    c.bench_function("vp_eth_bridge", |b| {
        b.iter(|| {
            assert!(
                eth_bridge
                    .validate_tx(
                        &signed_tx,
                        eth_bridge.ctx.keys_changed,
                        eth_bridge.ctx.verifiers,
                    )
                    .unwrap()
            )
        })
    });
}

fn eth_bridge_pool(c: &mut Criterion) {
    // NOTE: this vp is one of the most expensive but its cost comes from the
    // numerous accesses to storage that we already account for, so no need to
    // benchmark specific sections of it like for the ibc native vp
    let mut shell = BenchShell::default();
    let native_erc20_addres =
        read_native_erc20_address(&shell.wl_storage).unwrap();

    // Whitelist NAM token
    let cap_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Cap,
    }
    .into();
    shell
        .wl_storage
        .write(&cap_key, Amount::from(1_000))
        .unwrap();

    let whitelisted_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Whitelisted,
    }
    .into();
    shell.wl_storage.write(&whitelisted_key, true).unwrap();

    let denom_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Denomination,
    }
    .into();
    shell.wl_storage.write(&denom_key, 0).unwrap();

    let signed_tx = {
        let data = PendingTransfer{
        transfer: namada::types::eth_bridge_pool::TransferToEthereum {
            kind: namada::types::eth_bridge_pool::TransferToEthereumKind::Erc20,
            asset: native_erc20_addres,
            recipient: namada::types::ethereum_events::EthAddress([1u8; 20]),
            sender: defaults::albert_address(),
            amount: Amount::from(1),
        },
        gas_fee: GasFee{
            amount: Amount::from(100),
            payer: defaults::albert_address(),
            token: shell.wl_storage.storage.native_token.clone(),
        },
    };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    shell.execute_tx(&signed_tx);

    let (verifiers, keys_changed) = shell
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&BTreeSet::default());

    let vp_address = Address::Internal(InternalAddress::EthBridgePool);
    let bridge_pool = BridgePoolVp {
        ctx: Ctx::new(
            &vp_address,
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

    c.bench_function("vp_eth_bridge_pool", |b| {
        b.iter(|| {
            assert!(
                bridge_pool
                    .validate_tx(
                        &signed_tx,
                        bridge_pool.ctx.keys_changed,
                        bridge_pool.ctx.verifiers,
                    )
                    .unwrap()
            )
        })
    });
}

fn parameters(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_parameters");

    for bench_name in ["foreign_key_write", "parameter_change"] {
        let mut shell = BenchShell::default();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                let tx = generate_foreign_key_tx(&defaults::albert_keypair());
                // Run the tx to validate
                shell.execute_tx(&tx);
                tx
            }
            "parameter_change" => {
                // Simulate governance proposal to modify a parameter
                let min_proposal_fund_key =
            namada::governance::storage::keys::get_min_proposal_fund_key();
                shell
                    .wl_storage
                    .write(&min_proposal_fund_key, 1_000)
                    .unwrap();

                let proposal_key = namada::governance::storage::keys::get_proposal_execution_key(0);
                shell.wl_storage.write(&proposal_key, 0).unwrap();

                // Return a dummy tx for validation
                let mut tx =
                    Tx::from_type(namada::tx::data::TxType::Decrypted(
                        namada::tx::data::DecryptedTx::Decrypted,
                    ));
                tx.set_data(namada::tx::Data::new(borsh::to_vec(&0).unwrap()));
                tx
            }
            _ => panic!("Unexpected bench test"),
        };

        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let vp_address = Address::Internal(InternalAddress::Parameters);
        let parameters = ParametersVp {
            ctx: Ctx::new(
                &vp_address,
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
                    parameters
                        .validate_tx(
                            &signed_tx,
                            parameters.ctx.keys_changed,
                            parameters.ctx.verifiers,
                        )
                        .unwrap()
                )
            })
        });
    }

    group.finish();
}

fn pos(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_pos");

    for bench_name in ["foreign_key_write", "parameter_change"] {
        let mut shell = BenchShell::default();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                let tx = generate_foreign_key_tx(&defaults::albert_keypair());
                // Run the tx to validate
                shell.execute_tx(&tx);
                tx
            }
            "parameter_change" => {
                // Simulate governance proposal to modify a parameter
                let min_proposal_fund_key =
            namada::governance::storage::keys::get_min_proposal_fund_key();
                shell
                    .wl_storage
                    .write(&min_proposal_fund_key, 1_000)
                    .unwrap();

                let proposal_key = namada::governance::storage::keys::get_proposal_execution_key(0);
                shell.wl_storage.write(&proposal_key, 0).unwrap();

                // Return a dummy tx for validation
                let mut tx =
                    Tx::from_type(namada::tx::data::TxType::Decrypted(
                        namada::tx::data::DecryptedTx::Decrypted,
                    ));
                tx.set_data(namada::tx::Data::new(borsh::to_vec(&0).unwrap()));
                tx
            }
            _ => panic!("Unexpected bench test"),
        };

        let (verifiers, keys_changed) = shell
            .wl_storage
            .write_log
            .verifiers_and_changed_keys(&BTreeSet::default());

        let vp_address = Address::Internal(InternalAddress::PoS);
        let pos = PosVP {
            ctx: Ctx::new(
                &vp_address,
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
                    pos.validate_tx(
                        &signed_tx,
                        pos.ctx.keys_changed,
                        pos.ctx.verifiers,
                    )
                    .unwrap()
                )
            })
        });
    }

    group.finish();
}

fn ibc_vp_validate_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc_validate_action");
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

    for (signed_tx, bench_name) in
        [open_connection, open_channel, outgoing_transfer]
            .iter()
            .zip(["open_connection", "open_channel", "outgoing_transfer"])
    {
        let mut shell = BenchShell::default();
        // Initialize the state according to the target tx
        match bench_name {
            "open_connection" => {
                let _ = shell.init_ibc_client_state(
                    namada::core::types::storage::Key::from(
                        Address::Internal(InternalAddress::Ibc).to_db_key(),
                    ),
                );
            }
            "open_channel" => {
                let _ = shell.init_ibc_connection();
            }
            "outgoing_transfer" => shell.init_ibc_channel(),
            _ => panic!("Unexpected bench test"),
        }

        shell.execute_tx(signed_tx);
        let tx_data = signed_tx.data().unwrap();
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
        let exec_ctx = PseudoExecutionContext::new(ibc.ctx.pre());
        let ctx = Rc::new(RefCell::new(exec_ctx));
        let mut actions = IbcActions::new(ctx.clone());
        actions.set_validation_params(ibc.validation_params().unwrap());

        let module = TransferModule::new(ctx);
        actions.add_transfer_module(module.module_id(), module);

        group.bench_function(bench_name, |b| {
            b.iter(|| actions.validate(&tx_data).unwrap())
        });
    }

    group.finish();
}

fn ibc_vp_execute_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc_execute_action");
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

    for (signed_tx, bench_name) in
        [open_connection, open_channel, outgoing_transfer]
            .iter()
            .zip(["open_connection", "open_channel", "outgoing_transfer"])
    {
        let mut shell = BenchShell::default();
        // Initialize the state according to the target tx
        match bench_name {
            "open_connection" => {
                let _ = shell.init_ibc_client_state(
                    namada::core::types::storage::Key::from(
                        Address::Internal(InternalAddress::Ibc).to_db_key(),
                    ),
                );
            }
            "open_channel" => {
                let _ = shell.init_ibc_connection();
            }
            "outgoing_transfer" => shell.init_ibc_channel(),
            _ => panic!("Unexpected bench test"),
        }

        shell.execute_tx(signed_tx);
        let tx_data = signed_tx.data().unwrap();
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
        let exec_ctx = PseudoExecutionContext::new(ibc.ctx.pre());
        let ctx = Rc::new(RefCell::new(exec_ctx));
        let mut actions = IbcActions::new(ctx.clone());
        actions.set_validation_params(ibc.validation_params().unwrap());

        let module = TransferModule::new(ctx);
        actions.add_transfer_module(module.module_id(), module);

        group.bench_function(bench_name, |b| {
            b.iter(|| actions.execute(&tx_data).unwrap())
        });
    }

    group.finish();
}

criterion_group!(
    native_vps,
    governance,
    // slash_fund,
    ibc,
    masp,
    masp_verify_shielded_tx,
    vp_multitoken,
    pgf,
    eth_bridge_nut,
    eth_bridge,
    eth_bridge_pool,
    parameters,
    pos,
    ibc_vp_validate_action,
    ibc_vp_execute_action
);
criterion_main!(native_vps);
