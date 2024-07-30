//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::ibc_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.

use core::str::FromStr;
use core::time::Duration;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use color_eyre::eyre::Result;
use eyre::eyre;
use namada_apps_lib::cli::context::ENV_VAR_CHAIN_ID;
use namada_apps_lib::client::rpc::{
    query_pos_parameters, query_storage_value, query_storage_value_bytes,
};
use namada_apps_lib::client::utils::id_from_pk;
use namada_apps_lib::config::genesis::{chain, templates};
use namada_apps_lib::config::utils::set_port;
use namada_apps_lib::config::{ethereum_bridge, TendermintMode};
use namada_apps_lib::facade::tendermint::block::Header as TmHeader;
use namada_apps_lib::facade::tendermint::merkle::proof::ProofOps as TmProof;
use namada_apps_lib::facade::tendermint_rpc::{Client, HttpClient, Url};
use namada_core::string_encoding::StringEncoded;
use namada_sdk::address::{Address, InternalAddress};
use namada_sdk::events::extend::ReadFromEventAttributes;
use namada_sdk::governance::cli::onchain::PgfFunding;
use namada_sdk::governance::pgf::ADDRESS as PGF_ADDRESS;
use namada_sdk::governance::storage::proposal::{PGFIbcTarget, PGFTarget};
use namada_sdk::ibc::apps::transfer::types::VERSION as ICS20_VERSION;
use namada_sdk::ibc::clients::tendermint::client_state::ClientState as TmClientState;
use namada_sdk::ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use namada_sdk::ibc::clients::tendermint::types::{
    AllowUpdate, ClientState as TmClientStateType, Header as IbcTmHeader,
    TrustThreshold,
};
use namada_sdk::ibc::core::channel::types::channel::Order as ChanOrder;
use namada_sdk::ibc::core::channel::types::msgs::{
    MsgAcknowledgement, MsgChannelOpenAck, MsgChannelOpenConfirm,
    MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket as IbcMsgRecvPacket,
    MsgTimeout as IbcMsgTimeout,
};
use namada_sdk::ibc::core::channel::types::packet::Packet;
use namada_sdk::ibc::core::channel::types::Version as ChanVersion;
use namada_sdk::ibc::core::client::context::client_state::ClientStateCommon;
use namada_sdk::ibc::core::client::types::msgs::{
    MsgCreateClient, MsgUpdateClient,
};
use namada_sdk::ibc::core::client::types::Height;
use namada_sdk::ibc::core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentProofBytes,
};
use namada_sdk::ibc::core::commitment_types::merkle::MerkleProof;
use namada_sdk::ibc::core::connection::types::msgs::{
    MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit,
    MsgConnectionOpenTry,
};
use namada_sdk::ibc::core::connection::types::version::Version as ConnVersion;
use namada_sdk::ibc::core::connection::types::Counterparty as ConnCounterparty;
use namada_sdk::ibc::core::host::types::identifiers::{
    ChainId, ChannelId, ClientId, ConnectionId, PortId,
};
use namada_sdk::ibc::event as ibc_events;
use namada_sdk::ibc::event::IbcEventType;
use namada_sdk::ibc::primitives::proto::Any;
use namada_sdk::ibc::primitives::{Signer, ToProto};
use namada_sdk::ibc::storage::*;
use namada_sdk::key::PublicKey;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::parameters::{storage as param_storage, EpochDuration};
use namada_sdk::queries::RPC;
use namada_sdk::state::ics23_specs::ibc_proof_specs;
use namada_sdk::state::Sha256Hasher;
use namada_sdk::storage::{BlockHeight, Epoch, Key};
use namada_sdk::tendermint::abci::Event as AbciEvent;
use namada_sdk::tendermint::block::Height as TmHeight;
use namada_sdk::token::Amount;
use namada_test_utils::TestWasms;
use prost::Message;
use setup::constants::*;
use sha2::{Digest, Sha256};
use tendermint_light_client::components::io::{Io, ProdIo as TmLightClientIo};

use crate::e2e::helpers::{
    epochs_per_year_from_min_duration, find_address, find_gaia_address,
    get_actor_rpc, get_epoch, get_established_addr_from_pregenesis,
    get_validator_pk, wait_for_wasm_pre_compile,
};
use crate::e2e::ledger_tests::{prepare_proposal_data, write_json_file};
use crate::e2e::setup::{
    self, run_gaia_cmd, run_hermes_cmd, set_ethereum_bridge_mode, setup_gaia,
    setup_hermes, sleep, Bin, NamadaCmd, Test, Who,
};
use crate::strings::{
    LEDGER_STARTED, TX_APPLIED_SUCCESS, TX_FAILED, VALIDATOR_NODE,
};
use crate::{run, run_as};

#[test]
fn run_ledger_ibc() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0)
        };
    let (ledger_a, ledger_b, test_a, test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    let (client_id_a, client_id_b) = create_client(&test_a, &test_b)?;

    let (conn_id_a, conn_id_b) =
        connection_handshake(&test_a, &test_b, &client_id_a, &client_id_b)?;

    let ((port_id_a, channel_id_a), (port_id_b, channel_id_b)) =
        channel_handshake(
            &test_a,
            &test_b,
            &client_id_a,
            &client_id_b,
            &conn_id_a,
            &conn_id_b,
        )?;

    // Transfer 100000 from the normal account on Chain A to Chain B
    transfer_token(
        &test_a,
        &test_b,
        &client_id_a,
        &client_id_b,
        &port_id_a,
        &channel_id_a,
    )?;
    check_balances(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Try invalid transfers and they will fail
    try_invalid_transfers(&test_a, &test_b, &port_id_a, &channel_id_a)?;

    // Transfer 50000 received over IBC on Chain B
    let token = format!("{port_id_b}/{channel_id_b}/nam");
    transfer_on_chain(
        &test_b,
        "transparent-transfer",
        BERTHA,
        ALBERT,
        token,
        50_000_000_000,
        BERTHA_KEY,
    )?;
    check_balances_after_non_ibc(&port_id_b, &channel_id_b, &test_b)?;

    // Transfer 50000 back from the origin-specific account on Chain B to Chain
    // A
    transfer_back(
        &test_a,
        &test_b,
        &client_id_a,
        &client_id_b,
        &port_id_b,
        &channel_id_b,
    )?;
    check_balances_after_back(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Transfer a token and it will time out and refund
    transfer_timeout(
        &test_a,
        &test_b,
        &client_id_a,
        &port_id_a,
        &channel_id_a,
    )?;
    // The balance should not be changed
    check_balances_after_back(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Shielded transfers are tested with Hermes

    // Skip tests for closing a channel and timeout_on_close since the transfer
    // channel cannot be closed

    Ok(())
}

#[test]
fn run_ledger_ibc_with_hermes() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0)
        };
    let (ledger_a, ledger_b, test_a, test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    setup_hermes(&test_a, &test_b)?;
    let port_id_a = "transfer".parse().unwrap();
    let port_id_b = "transfer".parse().unwrap();
    let (channel_id_a, channel_id_b) =
        create_channel_with_hermes(&test_a, &test_b)?;

    // Start relaying
    let hermes = run_hermes(&test_a)?;
    let bg_hermes = hermes.background();

    // Transfer 100000 from the normal account on Chain A to Chain B
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let receiver = find_address(&test_b, BERTHA)?;
    transfer(
        &test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        100000.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;
    check_balances(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Transfer 50000 received over IBC on Chain B
    let token = format!("{port_id_b}/{channel_id_b}/nam");
    transfer_on_chain(
        &test_b,
        "transparent-transfer",
        BERTHA,
        ALBERT,
        token,
        50_000_000_000,
        BERTHA_KEY,
    )?;
    check_balances_after_non_ibc(&port_id_b, &channel_id_b, &test_b)?;

    // Transfer 50000 back from the origin-specific account on Chain B to Chain
    // A
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let receiver = find_address(&test_a, ALBERT)?;
    // Chain A was the source for the sent token
    let ibc_denom = format!("{port_id_b}/{channel_id_b}/nam");
    // Send a token from Chain B
    transfer(
        &test_b,
        BERTHA,
        receiver.to_string(),
        ibc_denom,
        50_000_000_000.0,
        Some(BERTHA_KEY),
        &port_id_b,
        &channel_id_b,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;
    check_balances_after_back(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Send a token to the shielded address on Chain A
    transfer_on_chain(
        &test_a,
        "shield",
        ALBERT,
        AA_PAYMENT_ADDRESS,
        BTC,
        100,
        ALBERT_KEY,
    )?;
    // Send some token for masp fee payment
    transfer_on_chain(
        &test_a,
        "shield",
        ALBERT,
        AA_PAYMENT_ADDRESS,
        NAM,
        10_000,
        ALBERT_KEY,
    )?;
    shielded_sync(&test_a, AA_VIEWING_KEY)?;
    // Shieded transfer from Chain A to Chain B
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let token_addr = find_address(&test_a, BTC)?.to_string();
    let shielding_data_path = gen_ibc_shielding_data(
        &test_b,
        AB_PAYMENT_ADDRESS,
        token_addr,
        1_000_000_000,
        &port_id_b,
        &channel_id_b,
    )?;
    transfer(
        &test_a,
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        BTC,
        10.0,
        None,
        &port_id_a,
        &channel_id_a,
        None,
        Some(shielding_data_path),
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;
    check_shielded_balances(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Shielded transfer to an invalid receiver address (refund)
    transfer(
        &test_a,
        A_SPENDING_KEY,
        "invalid_receiver",
        BTC,
        10.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;
    // The balance should not be changed
    check_shielded_balances(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Send transfer will be timed out (refund)
    transfer(
        &test_a,
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        BTC,
        10.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        Some(Duration::new(10, 0)),
        None,
        None,
        false,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&test_a)?;
    let _bg_hermes = hermes.background();

    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;
    // The balance should not be changed
    check_shielded_balances(&port_id_b, &channel_id_b, &test_a, &test_b)?;

    Ok(())
}

#[test]
fn ibc_namada_gaia() -> Result<()> {
    // epoch per 100 seconds
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0)
        };
    let (ledger, mut ledger_b, test, _test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger = ledger.background();
    // chain B isn't used
    ledger_b.interrupt()?;

    // gaia
    let test_gaia = setup_gaia()?;
    let gaia = run_gaia(&test_gaia)?;
    sleep(5);
    let _bg_gaia = gaia.background();

    setup_hermes(&test, &test_gaia)?;
    let port_id_namada = "transfer".parse().unwrap();
    let port_id_gaia = "transfer".parse().unwrap();
    let (channel_id_namada, channel_id_gaia) =
        create_channel_with_hermes(&test, &test_gaia)?;

    // Start relaying
    let hermes = run_hermes(&test)?;
    let _bg_hermes = hermes.background();

    // Transfer from Namada to Gaia
    let receiver = find_gaia_address(&test_gaia, GAIA_USER)?;
    transfer(
        &test,
        ALBERT,
        receiver,
        APFEL,
        200.0,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;

    // Check the received token on Gaia
    let token_addr = find_address(&test, APFEL)?;
    let ibc_denom = format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");
    check_gaia_balance(&test_gaia, GAIA_USER, &ibc_denom, 200000000)?;

    // Transfer back from Gaia to Namada
    let receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        receiver,
        get_gaia_denom_hash(ibc_denom),
        100000000,
        &port_id_gaia,
        &channel_id_gaia,
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    check_balance(&test, ALBERT, APFEL, 999900)?;

    // Transfer a token from Gaia to Namada
    let receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        receiver,
        GAIA_COIN,
        200,
        &port_id_gaia,
        &channel_id_gaia,
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    let ibc_denom = format!("{port_id_namada}/{channel_id_namada}/{GAIA_COIN}");
    check_balance(&test, ALBERT, &ibc_denom, 200)?;

    // Transfer back from Namada to Gaia
    let receiver = find_gaia_address(&test_gaia, GAIA_USER)?;
    transfer(
        &test,
        ALBERT,
        &receiver,
        ibc_denom,
        100.0,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    // Check the received token on Gaia
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 900)?;

    // Shielding transfer from Gaia to Namada
    let memo_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        GAIA_COIN,
        100,
        &port_id_namada,
        &channel_id_namada,
    )?;
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        AA_PAYMENT_ADDRESS,
        GAIA_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        Some(memo_path),
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test_gaia)?;

    // Check the token on Namada
    let ibc_denom = format!("{port_id_namada}/{channel_id_namada}/{GAIA_COIN}");
    check_balance(&test, AA_VIEWING_KEY, &ibc_denom, 100)?;

    // Shielded transfer on Namada
    transfer_on_chain(
        &test,
        "transfer",
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        &ibc_denom,
        50,
        ALBERT_KEY,
    )?;
    check_balance(&test, AA_VIEWING_KEY, &ibc_denom, 50)?;
    check_balance(&test, AB_VIEWING_KEY, &ibc_denom, 50)?;

    // Unshielding transfer from Namada to Gaia
    transfer(
        &test,
        B_SPENDING_KEY,
        &receiver,
        &ibc_denom,
        10.0,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    check_balance(&test, AB_VIEWING_KEY, &ibc_denom, 40)?;
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 810)?;

    Ok(())
}

#[test]
fn pgf_over_ibc_with_hermes() -> Result<()> {
    let update_genesis = |mut genesis: templates::All<
        templates::Unvalidated,
    >,
                          base_dir: &_| {
        genesis.parameters.parameters.epochs_per_year =
            epochs_per_year_from_min_duration(20);
        // for the trusting period of IBC client
        genesis.parameters.pos_params.pipeline_len = 5;
        genesis.parameters.parameters.max_proposal_bytes = Default::default();
        genesis.parameters.pgf_params.stewards =
            BTreeSet::from_iter([get_established_addr_from_pregenesis(
                ALBERT_KEY, base_dir, &genesis,
            )
            .unwrap()]);
        genesis.parameters.ibc_params.default_mint_limit = Amount::max_signed();
        genesis
            .parameters
            .ibc_params
            .default_per_epoch_throughput_limit = Amount::max_signed();
        setup::set_validators(1, genesis, base_dir, |_| 0)
    };
    let (ledger_a, ledger_b, test_a, test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    setup_hermes(&test_a, &test_b)?;
    let port_id_a = "transfer".parse().unwrap();
    let port_id_b = "transfer".parse().unwrap();
    let (channel_id_a, channel_id_b) =
        create_channel_with_hermes(&test_a, &test_b)?;

    // Start relaying
    let hermes = run_hermes(&test_a)?;
    let _bg_hermes = hermes.background();

    // Transfer to PGF account
    transfer_on_chain(
        &test_a,
        "transparent-transfer",
        ALBERT,
        PGF_ADDRESS.to_string(),
        NAM,
        100,
        ALBERT_KEY,
    )?;

    // Proposal on Chain A
    // Delegate some token
    delegate_token(&test_a)?;
    let rpc_a = get_actor_rpc(&test_a, Who::Validator(0));
    let mut epoch = get_epoch(&test_a, &rpc_a).unwrap();
    let delegated = epoch + 5u64;
    while epoch <= delegated {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }
    // funding proposal
    let start_epoch =
        propose_funding(&test_a, &test_b, &port_id_a, &channel_id_a)?;
    let mut epoch = get_epoch(&test_a, &rpc_a).unwrap();
    // Vote
    while epoch <= start_epoch {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }
    submit_votes(&test_a)?;

    // wait for the grace
    let activation_epoch = start_epoch + 12u64 + 6u64 + 1u64;
    while epoch <= activation_epoch {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }

    // Check balances after funding over IBC
    check_funded_balances(&port_id_b, &channel_id_b, &test_b)?;

    Ok(())
}

#[test]
fn proposal_ibc_token_inflation() -> Result<()> {
    const MASP_EPOCH_MULTIPLIER: u64 = 2;
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(60);
            genesis.parameters.parameters.masp_epoch_multiplier =
                MASP_EPOCH_MULTIPLIER;
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0)
        };
    let (ledger_a, ledger_b, test_a, test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    // Proposal on the destination (Chain B)
    // Delegate some token
    delegate_token(&test_b)?;
    let rpc_b = get_actor_rpc(&test_b, Who::Validator(0));
    let mut epoch = get_epoch(&test_b, &rpc_b).unwrap();
    let delegated = epoch + 2u64;
    while epoch <= delegated {
        sleep(10);
        epoch = get_epoch(&test_b, &rpc_b).unwrap_or_default();
    }
    // inflation proposal on Chain B
    let start_epoch = propose_inflation(&test_b)?;
    let mut epoch = get_epoch(&test_b, &rpc_b).unwrap();
    // Vote
    while epoch <= start_epoch {
        sleep(10);
        epoch = get_epoch(&test_b, &rpc_b).unwrap_or_default();
    }
    submit_votes(&test_b)?;

    // wait for the next epoch of the grace
    wait_epochs(&test_b, 6 + 1)?;

    setup_hermes(&test_a, &test_b)?;
    let port_id_a = "transfer".parse().unwrap();
    let port_id_b = "transfer".parse().unwrap();
    let (channel_id_a, channel_id_b) =
        create_channel_with_hermes(&test_a, &test_b)?;

    // Start relaying
    let hermes = run_hermes(&test_a)?;
    let _bg_hermes = hermes.background();

    // wait the next epoch not to update the epoch during the IBC transfer
    wait_epochs(&test_b, 1)?;

    // Transfer 1 from Chain A to a z-address on Chain B
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let token_addr = find_address(&test_a, APFEL)?.to_string();
    let shielding_data_path = gen_ibc_shielding_data(
        &test_b,
        AB_PAYMENT_ADDRESS,
        token_addr,
        1_000_000,
        &port_id_b,
        &channel_id_b,
    )?;
    transfer(
        &test_a,
        ALBERT,
        AB_PAYMENT_ADDRESS,
        APFEL,
        1.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        Some(shielding_data_path),
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;

    // wait the next masp epoch to dispense the reward
    wait_epochs(&test_b, MASP_EPOCH_MULTIPLIER)?;

    // Check balances
    check_inflated_balance(&test_b)?;

    Ok(())
}

#[test]
fn ibc_rate_limit() -> Result<()> {
    // Mint limit 2 transfer/channel-0/nam, per-epoch throughput limit 1 NAM
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(50);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::from_u64(2_000_000);
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit =
                Amount::from_u64(1_000_000);
            setup::set_validators(1, genesis, base_dir, |_| 0)
        };
    let (ledger_a, ledger_b, test_a, test_b) = run_two_nets(update_genesis)?;
    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    setup_hermes(&test_a, &test_b)?;
    let port_id_a = "transfer".parse().unwrap();
    let port_id_b: PortId = "transfer".parse().unwrap();
    let (channel_id_a, channel_id_b) =
        create_channel_with_hermes(&test_a, &test_b)?;

    // Start relaying
    let hermes = run_hermes(&test_a)?;
    let _bg_hermes = hermes.background();

    // wait for the next epoch
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let rpc_a = get_actor_rpc(&test_a, Who::Validator(0));
    let mut epoch = get_epoch(&test_a, &rpc_a).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }

    // Transfer 1 NAM from Chain A to Chain B
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let receiver = find_address(&test_b, BERTHA)?;
    transfer(
        &test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        1.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        None,
        None,
        false,
    )?;

    // Transfer 1 NAM from Chain A to Chain B again will fail
    transfer(
        &test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        1.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        None,
        // expect an error of the throughput limit
        Some(
            "Transfer exceeding the per-epoch throughput limit is not allowed",
        ),
        false,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test_a, &rpc_a).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }

    // Transfer 1 NAM from Chain A to Chain B will succeed in the new epoch
    transfer(
        &test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        1.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        None,
        None,
        None,
        false,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test_a, &rpc_a).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test_a, &rpc_a).unwrap();
    }

    // Transfer 1 NAM from Chain A to Chain B will succeed, but Chain B can't
    // receive due to the mint limit and the packet will be timed out
    transfer(
        &test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        1.0,
        Some(ALBERT_KEY),
        &port_id_a,
        &channel_id_a,
        Some(Duration::new(20, 0)),
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_a, &channel_id_a, &test_a)?;

    // Check the balance on Chain B
    let ibc_denom = format!("{port_id_b}/{channel_id_b}/nam");
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let rpc_b = get_actor_rpc(&test_b, Who::Validator(0));
    let query_args = vec![
        "balance", "--owner", BERTHA, "--token", &ibc_denom, "--node", &rpc_b,
    ];
    let expected = format!("{ibc_denom}: 2");
    let mut client = run!(test_b, Bin::Client, query_args, Some(40))?;
    client.exp_string(&expected)?;
    client.assert_success();

    Ok(())
}

fn run_two_nets(
    update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
) -> Result<(NamadaCmd, NamadaCmd, Test, Test)> {
    let (test_a, test_b) = setup_two_single_node_nets(update_genesis)?;
    set_ethereum_bridge_mode(
        &test_a,
        &test_a.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test_b,
        &test_b.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // Run Chain A
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let mut ledger_a =
        run_as!(test_a, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    ledger_a.exp_string(LEDGER_STARTED)?;
    ledger_a.exp_string(VALIDATOR_NODE)?;
    // Run Chain B
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let mut ledger_b =
        run_as!(test_b, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    ledger_b.exp_string(LEDGER_STARTED)?;
    ledger_b.exp_string(VALIDATOR_NODE)?;

    wait_for_wasm_pre_compile(&mut ledger_a)?;
    wait_for_wasm_pre_compile(&mut ledger_b)?;

    sleep(5);

    Ok((ledger_a, ledger_b, test_a, test_b))
}

/// Set up two Namada chains to talk to each other via IBC.
fn setup_two_single_node_nets(
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
) -> Result<(Test, Test)> {
    const ANOTHER_PROXY_APP: u16 = 27659u16;
    const ANOTHER_RPC: u16 = 27660u16;
    const ANOTHER_P2P: u16 = 26655u16;
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    let test_a = setup::network(&mut update_genesis, None)?;
    let test_b = setup::network(update_genesis, None)?;
    let genesis_b_dir = test_b
        .test_dir
        .path()
        .join(namada_apps_lib::client::utils::NET_ACCOUNTS_DIR)
        .join("validator-0");
    let mut genesis_b = chain::Finalized::read_toml_files(
        &genesis_b_dir.join(test_b.net.chain_id.as_str()),
    )
    .map_err(|_| eyre!("Could not read genesis files from test b"))?;
    // chain b's validator needs to listen on a different port than chain a's
    // validator
    let validator_pk = get_validator_pk(&test_b, Who::Validator(0)).unwrap();
    let validator_addr = genesis_b
        .transactions
        .established_account
        .as_ref()
        .unwrap()
        .iter()
        .find_map(|acct| {
            acct.tx
                .public_keys
                .contains(&StringEncoded::new(validator_pk.clone()))
                .then(|| acct.address.clone())
        })
        .unwrap();
    let validator_tx = genesis_b
        .transactions
        .validator_account
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|val| {
            Address::Established(val.tx.data.address.raw.clone())
                == validator_addr
        })
        .unwrap();
    let new_port = validator_tx.tx.data.net_address.port()
        + setup::ANOTHER_CHAIN_PORT_OFFSET;
    validator_tx.tx.data.net_address.set_port(new_port);
    genesis_b
        .write_toml_files(&genesis_b_dir.join(test_b.net.chain_id.as_str()))
        .map_err(|_| eyre!("Could not write genesis toml files for test_b"))?;
    // modify chain b to use different ports for cometbft
    let mut config = namada_apps_lib::config::Config::load(
        &genesis_b_dir,
        &test_b.net.chain_id,
        Some(TendermintMode::Validator),
    );
    let proxy_app = &mut config.ledger.cometbft.proxy_app;
    set_port(proxy_app, ANOTHER_PROXY_APP);
    let rpc_addr = &mut config.ledger.cometbft.rpc.laddr;
    set_port(rpc_addr, ANOTHER_RPC);
    let p2p_addr = &mut config.ledger.cometbft.p2p.laddr;
    set_port(p2p_addr, ANOTHER_P2P);
    config
        .write(&genesis_b_dir, &test_b.net.chain_id, true)
        .map_err(|e| {
            eyre!("Unable to modify chain b's config file due to {}", e)
        })?;
    Ok((test_a, test_b))
}

fn create_channel_with_hermes(
    test_a: &Test,
    test_b: &Test,
) -> Result<(ChannelId, ChannelId)> {
    let args = [
        "create",
        "channel",
        "--a-chain",
        &test_a.net.chain_id.to_string(),
        "--b-chain",
        &test_b.net.chain_id.to_string(),
        "--a-port",
        "transfer",
        "--b-port",
        "transfer",
        "--new-client-connection",
        "--yes",
    ];

    let mut hermes = run_hermes_cmd(test_a, args, Some(240))?;
    let (channel_id_a, channel_id_b) =
        get_channel_ids_from_hermes_output(&mut hermes)?;
    hermes.assert_success();

    Ok((channel_id_a, channel_id_b))
}

fn get_channel_ids_from_hermes_output(
    hermes: &mut NamadaCmd,
) -> Result<(ChannelId, ChannelId)> {
    let (_, matched) =
        hermes.exp_regex("channel handshake already finished .*")?;

    let regex = regex::Regex::new(r"channel-[0-9]+").unwrap();
    let mut iter = regex.find_iter(&matched);
    let channel_id_a = iter.next().unwrap().as_str().parse().unwrap();
    let channel_id_b = iter.next().unwrap().as_str().parse().unwrap();

    Ok((channel_id_a, channel_id_b))
}

fn run_hermes(test: &Test) -> Result<NamadaCmd> {
    let args = ["start"];
    let mut hermes = run_hermes_cmd(test, args, Some(40))?;
    hermes.exp_string("Hermes has started")?;
    Ok(hermes)
}

fn run_gaia(test: &Test) -> Result<NamadaCmd> {
    let args = [
        "start",
        "--pruning",
        "nothing",
        "--grpc.address",
        "0.0.0.0:9090",
    ];
    let gaia = run_gaia_cmd(test, args, Some(40))?;
    Ok(gaia)
}

fn wait_for_packet_relay(
    port_id: &PortId,
    channel_id: &ChannelId,
    test: &Test,
) -> Result<()> {
    let args = [
        "--json",
        "query",
        "packet",
        "pending",
        "--chain",
        test.net.chain_id.as_str(),
        "--port",
        port_id.as_str(),
        "--channel",
        channel_id.as_str(),
    ];
    for _ in 0..10 {
        sleep(10);
        let mut hermes = run_hermes_cmd(test, args, Some(40))?;
        // Check no pending packet
        if hermes
            .exp_string(
                "\"dst\":{\"unreceived_acks\":[],\"unreceived_packets\":[]},",
            )
            .is_ok()
            && hermes
                .exp_string(
                    "\"src\":{\"unreceived_acks\":[],\"unreceived_packets\":\
                     []}",
                )
                .is_ok()
        {
            return Ok(());
        }
    }
    Err(eyre!("Pending packet is still left"))
}

fn wait_epochs(test: &Test, duration_epochs: u64) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let mut epoch = None;
    for _ in 0..10 {
        match get_epoch(test, &rpc) {
            Ok(e) => {
                epoch = Some(e);
                break;
            }
            Err(_) => sleep(10),
        }
    }
    let (mut epoch, target_epoch) = match epoch {
        Some(e) => (e, e + duration_epochs),
        None => return Err(eyre!("Query epoch failed")),
    };
    while epoch < target_epoch {
        sleep(10);
        epoch = get_epoch(test, &rpc).unwrap_or_default();
    }
    Ok(())
}

fn create_client(test_a: &Test, test_b: &Test) -> Result<(ClientId, ClientId)> {
    let height = query_height(test_b)?;
    let client_state = make_client_state(test_b, height);
    let height = client_state.latest_height();
    let message = MsgCreateClient {
        client_state: client_state.into(),
        consensus_state: make_consensus_state(test_b, height)?.into(),
        signer: signer(),
    };
    let height_a = submit_ibc_tx(
        test_a,
        make_ibc_data(message.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    let height = query_height(test_a)?;
    let client_state = make_client_state(test_a, height);
    let height = client_state.latest_height();
    let message = MsgCreateClient {
        client_state: client_state.into(),
        consensus_state: make_consensus_state(test_a, height)?.into(),
        signer: signer(),
    };
    let height_b = submit_ibc_tx(
        test_b,
        make_ibc_data(message.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    let events = get_events(test_a, height_a)?;
    let client_id_a =
        get_client_id_from_events(&events).ok_or(eyre!(TX_FAILED))?;
    let events = get_events(test_b, height_b)?;
    let client_id_b =
        get_client_id_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    // `client_id_a` represents the ID of the B's client on Chain A
    Ok((client_id_a, client_id_b))
}

fn make_client_state(test: &Test, height: Height) -> TmClientState {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();

    let pos_params =
        test.async_runtime().block_on(query_pos_parameters(&client));
    let pipeline_len = pos_params.pipeline_len;

    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration = test
        .async_runtime()
        .block_on(query_storage_value::<HttpClient, EpochDuration>(
            &client, &key,
        ))
        .unwrap();
    let unbonding_period = pipeline_len * epoch_duration.min_duration.0;

    let trusting_period = 2 * unbonding_period / 3;
    let max_clock_drift = Duration::new(60, 0);
    let chain_id = ChainId::from_str(test.net.chain_id.as_str()).unwrap();

    TmClientStateType::new(
        chain_id,
        TrustThreshold::TWO_THIRDS,
        Duration::from_secs(trusting_period),
        Duration::from_secs(unbonding_period),
        max_clock_drift,
        height,
        ibc_proof_specs::<Sha256Hasher>().try_into().unwrap(),
        vec![],
        AllowUpdate {
            after_expiry: true,
            after_misbehaviour: true,
        },
    )
    .unwrap()
    .into()
}

fn make_consensus_state(
    test: &Test,
    height: Height,
) -> Result<TmConsensusState> {
    let header = query_header(test, height)?;
    Ok(TmConsensusState::from(header))
}

fn update_client_with_height(
    src_test: &Test,
    target_test: &Test,
    target_client_id: &ClientId,
    target_height: Height,
) -> Result<()> {
    // check the current(stale) state on the target chain
    let key = client_state_key(target_client_id);
    let (value, _) = query_value_with_proof(target_test, &key, None)?;
    let cs = match value {
        Some(v) => Any::decode(&v[..])
            .map_err(|e| eyre!("Decoding the client state failed: {}", e))?,
        None => {
            return Err(eyre!(
                "The client state doesn't exist: client ID {}",
                target_client_id
            ));
        }
    };
    let client_state = TmClientState::try_from(cs)
        .expect("the state should be a TmClientState");
    let trusted_height = client_state.latest_height();

    update_client(
        src_test,
        target_test,
        target_client_id,
        trusted_height,
        target_height,
    )
}

fn update_client(
    src_test: &Test,
    target_test: &Test,
    client_id: &ClientId,
    trusted_height: Height,
    target_height: Height,
) -> Result<()> {
    let io = make_light_client_io(src_test);

    let height = TmHeight::try_from(trusted_height.revision_height())
        .expect("invalid height");
    let trusted_block = io
        .fetch_light_block(height.into())
        .expect("the light client couldn't get a light block");

    let height = TmHeight::try_from(target_height.revision_height())
        .expect("invalid height");
    let target_block = io
        .fetch_light_block(height.into())
        .expect("the light client couldn't get a light block");

    let header = IbcTmHeader {
        signed_header: target_block.signed_header,
        validator_set: target_block.validators,
        trusted_height: Height::new(0, u64::from(trusted_block.height()))
            .expect("invalid height"),
        trusted_next_validator_set: trusted_block.next_validators,
    };

    let message = MsgUpdateClient {
        client_id: client_id.clone(),
        client_message: header.into(),
        signer: signer(),
    };
    submit_ibc_tx(
        target_test,
        make_ibc_data(message.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    check_ibc_update_query(
        target_test,
        client_id,
        BlockHeight(target_height.revision_height()),
    )?;
    Ok(())
}

fn make_light_client_io(test: &Test) -> TmLightClientIo {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let rpc_addr = Url::from_str(&rpc).unwrap();
    let rpc_client = HttpClient::new(rpc_addr).unwrap();
    let rpc_timeout = Duration::new(10, 0);

    let pk = get_validator_pk(test, Who::Validator(0)).unwrap();
    let peer_id = id_from_pk(&PublicKey::try_from_pk(&pk).unwrap());

    TmLightClientIo::new(peer_id, rpc_client, Some(rpc_timeout))
}

fn connection_handshake(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    client_id_b: &ClientId,
) -> Result<(ConnectionId, ConnectionId)> {
    let msg = MsgConnectionOpenInit {
        client_id_on_a: client_id_a.clone(),
        counterparty: ConnCounterparty::new(
            client_id_b.clone(),
            None,
            commitment_prefix(),
        ),
        version: Some(ConnVersion::compatibles().first().unwrap().clone()),
        delay_period: Duration::new(0, 0),
        signer: signer(),
    };
    // OpenInitConnection on Chain A
    let height = submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_a, height)?;
    let conn_id_a = get_connection_id_from_events(&events)
        .ok_or(eyre!("No connection ID is set"))?;

    // get the proofs from Chain A
    let height_a = query_height(test_a)?;
    let conn_proof = get_connection_proof(test_a, &conn_id_a, height_a)?;
    let (client_state, client_state_proof, consensus_proof) =
        get_client_states(test_a, client_id_a, height_a)?;
    let counterparty = ConnCounterparty::new(
        client_id_a.clone(),
        Some(conn_id_a.clone()),
        commitment_prefix(),
    );
    #[allow(deprecated)]
    let msg = MsgConnectionOpenTry {
        client_id_on_b: client_id_b.clone(),
        client_state_of_b_on_a: client_state.clone().into(),
        counterparty,
        versions_on_a: ConnVersion::compatibles(),
        proofs_height_on_a: height_a,
        proof_conn_end_on_a: conn_proof,
        proof_client_state_of_b_on_a: client_state_proof,
        proof_consensus_state_of_b_on_a: consensus_proof,
        consensus_height_of_b_on_a: client_state.latest_height(),
        delay_period: Duration::from_secs(0),
        signer: "test".to_string().into(),
        proof_consensus_state_of_b: None,
        previous_connection_id: ConnectionId::zero().to_string(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // OpenTryConnection on Chain B
    let height = submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_b, height)?;
    let conn_id_b = get_connection_id_from_events(&events)
        .ok_or(eyre!("No connection ID is set"))?;

    // get the A's proofs on Chain B
    let height_b = query_height(test_b)?;
    let conn_proof = get_connection_proof(test_b, &conn_id_b, height_b)?;
    let (client_state, client_state_proof, consensus_proof) =
        get_client_states(test_b, client_id_b, height_b)?;
    let consensus_height_of_a_on_b = client_state.latest_height();
    let msg = MsgConnectionOpenAck {
        conn_id_on_a: conn_id_a.clone(),
        conn_id_on_b: conn_id_b.clone(),
        client_state_of_a_on_b: client_state.into(),
        proof_conn_end_on_b: conn_proof,
        proof_client_state_of_a_on_b: client_state_proof,
        proof_consensus_state_of_a_on_b: consensus_proof,
        proofs_height_on_b: height_b,
        consensus_height_of_a_on_b,
        version: ConnVersion::compatibles().first().unwrap().clone(),
        signer: signer(),
        proof_consensus_state_of_a: None,
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // OpenAckConnection on Chain A
    submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    // get the proofs on Chain A
    let height_a = query_height(test_a)?;
    let proof = get_connection_proof(test_a, &conn_id_a, height_a)?;
    let msg = MsgConnectionOpenConfirm {
        conn_id_on_b: conn_id_b.clone(),
        proof_conn_end_on_a: proof,
        proof_height_on_a: height_a,
        signer: signer(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // OpenConfirmConnection on Chain B
    submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    Ok((conn_id_a, conn_id_b))
}

// get the proofs on the target height
fn get_connection_proof(
    test: &Test,
    conn_id: &ConnectionId,
    target_height: Height,
) -> Result<CommitmentProofBytes> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key = connection_key(conn_id);
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    convert_proof(tm_proof)
}

fn channel_handshake(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    client_id_b: &ClientId,
    conn_id_a: &ConnectionId,
    conn_id_b: &ConnectionId,
) -> Result<((PortId, ChannelId), (PortId, ChannelId))> {
    // OpenInitChannel on Chain A
    let port_id = PortId::transfer();
    let connection_hops_on_a = vec![conn_id_a.clone()];
    let channel_version = ChanVersion::new(ICS20_VERSION.to_string());
    let msg = MsgChannelOpenInit {
        port_id_on_a: port_id.clone(),
        connection_hops_on_a,
        port_id_on_b: port_id.clone(),
        ordering: ChanOrder::Unordered,
        signer: signer(),
        version_proposal: channel_version.clone(),
    };
    let height = submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_a, height)?;
    let channel_id_a =
        get_channel_id_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    // get the proofs from Chain A
    let height_a = query_height(test_a)?;
    let proof_chan_end_on_a =
        get_channel_proof(test_a, &port_id, &channel_id_a, height_a)?;
    let connection_hops_on_b = vec![conn_id_b.clone()];
    #[allow(deprecated)]
    let msg = MsgChannelOpenTry {
        port_id_on_b: port_id.clone(),
        connection_hops_on_b,
        port_id_on_a: port_id.clone(),
        chan_id_on_a: channel_id_a.clone(),
        version_supported_on_a: channel_version.clone(),
        proof_chan_end_on_a,
        proof_height_on_a: height_a,
        ordering: ChanOrder::Unordered,
        signer: signer(),
        version_proposal: channel_version.clone(),
    };

    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // OpenTryChannel on Chain B
    let height = submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_b, height)?;
    let channel_id_b =
        get_channel_id_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    // get the A's proofs on Chain B
    let height_b = query_height(test_b)?;
    let proof_chan_end_on_b =
        get_channel_proof(test_b, &port_id, &channel_id_b, height_b)?;
    let msg = MsgChannelOpenAck {
        port_id_on_a: port_id.clone(),
        chan_id_on_a: channel_id_a.clone(),
        chan_id_on_b: channel_id_b.clone(),
        version_on_b: channel_version,
        proof_chan_end_on_b,
        proof_height_on_b: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // OpenAckChannel on Chain A
    submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    // get the proofs on Chain A
    let height_a = query_height(test_a)?;
    let proof_chan_end_on_a =
        get_channel_proof(test_a, &port_id, &channel_id_a, height_a)?;
    let msg = MsgChannelOpenConfirm {
        port_id_on_b: port_id.clone(),
        chan_id_on_b: channel_id_b.clone(),
        proof_chan_end_on_a,
        proof_height_on_a: height_a,
        signer: signer(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // OpenConfirmChannel on Chain B
    submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    Ok(((port_id.clone(), channel_id_a), (port_id, channel_id_b)))
}

fn get_channel_proof(
    test: &Test,
    port_id: &PortId,
    channel_id: &ChannelId,
    target_height: Height,
) -> Result<CommitmentProofBytes> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key = channel_key(port_id, channel_id);
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    convert_proof(tm_proof)
}

// get the client state, the proof of the client state, and the proof of the
// consensus state
fn get_client_states(
    test: &Test,
    client_id: &ClientId,
    target_height: Height, // should have been already decremented
) -> Result<(TmClientState, CommitmentProofBytes, CommitmentProofBytes)> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key = client_state_key(client_id);
    let (value, tm_proof) =
        query_value_with_proof(test, &key, Some(query_height))?;
    let cs = match value {
        Some(v) => Any::decode(&v[..])
            .map_err(|e| eyre!("Decoding the client state failed: {}", e))?,
        None => {
            return Err(eyre!(
                "The client state doesn't exist: client ID {}",
                client_id
            ));
        }
    };
    let client_state = TmClientState::try_from(cs)
        .expect("the state should be a TmClientState");
    let client_state_proof = convert_proof(tm_proof)?;

    let height = client_state.latest_height();
    let ibc_height = Height::new(0, height.revision_height()).unwrap();
    let key = consensus_state_key(client_id, ibc_height);
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    let consensus_proof = convert_proof(tm_proof)?;

    Ok((client_state, client_state_proof, consensus_proof))
}

fn transfer_token(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    client_id_b: &ClientId,
    port_id_a: &PortId,
    channel_id_a: &ChannelId,
) -> Result<()> {
    // Send a token from Chain A
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let receiver = find_address(test_b, BERTHA)?;
    let height = transfer(
        test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        100000.0,
        Some(ALBERT_KEY),
        port_id_a,
        channel_id_a,
        None,
        None,
        None,
        false,
    )?;
    let events = get_events(test_a, height)?;
    let packet = get_packet_from_events(&events).ok_or(eyre!(TX_FAILED))?;
    check_ibc_packet_query(test_a, "send_packet", &packet)?;

    let height_a = query_height(test_a)?;
    let proof_commitment_on_a =
        get_commitment_proof(test_a, &packet, height_a)?;
    let msg = IbcMsgRecvPacket {
        packet,
        proof_commitment_on_a,
        proof_height_on_a: height_a,
        signer: signer(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // Receive the token on Chain B
    let height = submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_b, height)?;
    let packet = get_packet_from_events(&events).ok_or(eyre!(TX_FAILED))?;
    let ack = get_ack_from_events(&events).ok_or(eyre!(TX_FAILED))?;
    check_ibc_packet_query(test_b, "write_acknowledgement", &packet)?;

    // get the proof on Chain B
    let height_b = query_height(test_b)?;
    let proof_acked_on_b = get_ack_proof(test_b, &packet, height_b)?;
    let msg = MsgAcknowledgement {
        packet,
        acknowledgement: ack.try_into().expect("invalid ack"),
        proof_acked_on_b,
        proof_height_on_b: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // Acknowledge on Chain A
    submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    Ok(())
}

fn try_invalid_transfers(
    test_a: &Test,
    test_b: &Test,
    port_id_a: &PortId,
    channel_id_a: &ChannelId,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let receiver = find_address(test_b, BERTHA)?;

    // invalid port
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let nam_addr = find_address(test_a, NAM)?;
    transfer(
        test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        10.0,
        Some(ALBERT_KEY),
        &"port".parse().unwrap(),
        channel_id_a,
        None,
        None,
        // the IBC denom can't be parsed when using an invalid port
        Some(&format!("Invalid IBC denom: {nam_addr}")),
        false,
    )?;

    // invalid channel
    transfer(
        test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        10.0,
        Some(ALBERT_KEY),
        port_id_a,
        &"channel-42".parse().unwrap(),
        None,
        None,
        Some("IBC token transfer error: context error: `ICS04 Channel error"),
        false,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_on_chain(
    test: &Test,
    kind: impl AsRef<str>,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    signer: impl AsRef<str>,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let amount = amount.to_string();
    let tx_args = vec![
        kind.as_ref(),
        "--source",
        sender.as_ref(),
        "--target",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--signing-keys",
        signer.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(120))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    Ok(())
}

/// Give the token back after transfer_token
fn transfer_back(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    client_id_b: &ClientId,
    port_id_b: &PortId,
    channel_id_b: &ChannelId,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let receiver = find_address(test_a, ALBERT)?;

    // Chain A was the source for the sent token
    let ibc_denom = format!("{port_id_b}/{channel_id_b}/nam");
    // Send a token from Chain B
    let height = transfer(
        test_b,
        BERTHA,
        receiver.to_string(),
        ibc_denom,
        50_000_000_000.0,
        Some(BERTHA_KEY),
        port_id_b,
        channel_id_b,
        None,
        None,
        None,
        false,
    )?;
    let events = get_events(test_b, height)?;
    let packet = get_packet_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    let height_b = query_height(test_b)?;
    let proof = get_commitment_proof(test_b, &packet, height_b)?;
    let msg = IbcMsgRecvPacket {
        packet,
        proof_commitment_on_a: proof,
        proof_height_on_a: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // Receive the token on Chain A
    let height = submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;
    let events = get_events(test_a, height)?;
    let packet = get_packet_from_events(&events).ok_or(eyre!(TX_FAILED))?;
    let ack = get_ack_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    // get the proof on Chain A
    let height_a = query_height(test_a)?;
    let proof_acked_on_b = get_ack_proof(test_a, &packet, height_a)?;
    let msg = MsgAcknowledgement {
        packet,
        acknowledgement: ack.try_into().expect("invalid ack"),
        proof_acked_on_b,
        proof_height_on_b: height_a,
        signer: signer(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // Acknowledge on Chain B
    submit_ibc_tx(
        test_b,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    Ok(())
}

fn transfer_timeout(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    port_id_a: &PortId,
    channel_id_a: &ChannelId,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let receiver = find_address(test_b, BERTHA)?;

    // Send a token from Chain A
    let height = transfer(
        test_a,
        ALBERT,
        receiver.to_string(),
        NAM,
        100000.0,
        Some(ALBERT_KEY),
        port_id_a,
        channel_id_a,
        Some(Duration::new(5, 0)),
        None,
        None,
        false,
    )?;
    let events = get_events(test_a, height)?;
    let packet = get_packet_from_events(&events).ok_or(eyre!(TX_FAILED))?;

    // wait for the timeout
    sleep(5);

    let height_b = query_height(test_b)?;
    let proof_unreceived_on_b =
        get_receipt_absence_proof(test_b, &packet, height_b)?;
    let msg = IbcMsgTimeout {
        packet,
        next_seq_recv_on_b: 1.into(), // not used
        proof_unreceived_on_b,
        proof_height_on_b: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // Timeout on Chain A
    submit_ibc_tx(
        test_a,
        make_ibc_data(msg.to_any()),
        ALBERT,
        ALBERT_KEY,
        false,
    )?;

    Ok(())
}

fn get_commitment_proof(
    test: &Test,
    packet: &Packet,
    target_height: Height,
) -> Result<CommitmentProofBytes> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key = commitment_key(
        &packet.port_id_on_a,
        &packet.chan_id_on_a,
        packet.seq_on_a,
    );
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    convert_proof(tm_proof)
}

fn get_ack_proof(
    test: &Test,
    packet: &Packet,
    target_height: Height,
) -> Result<CommitmentProofBytes> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key =
        ack_key(&packet.port_id_on_b, &packet.chan_id_on_b, packet.seq_on_a);
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    convert_proof(tm_proof)
}

fn get_receipt_absence_proof(
    test: &Test,
    packet: &Packet,
    target_height: Height,
) -> Result<CommitmentProofBytes> {
    // we need proofs at the height of the previous block
    let query_height = target_height.decrement().unwrap();
    let key = receipt_key(
        &packet.port_id_on_b,
        &packet.chan_id_on_b,
        packet.seq_on_a,
    );
    let (_, tm_proof) = query_value_with_proof(test, &key, Some(query_height))?;
    convert_proof(tm_proof)
}

fn commitment_prefix() -> CommitmentPrefix {
    CommitmentPrefix::try_from(b"ibc".to_vec())
        .expect("the prefix should be parsable")
}

fn submit_ibc_tx(
    test: &Test,
    data: Vec<u8>,
    owner: &str,
    signer: &str,
    wait_reveal_pk: bool,
) -> Result<u32> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let data_path = test.test_dir.path().join("tx.data");
    std::fs::write(&data_path, data).expect("writing data failed");

    let data_path = data_path.to_string_lossy();
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let mut client = run!(
        test,
        Bin::Client,
        [
            "tx",
            "--code-path",
            TX_IBC_WASM,
            "--data-path",
            &data_path,
            "--owner",
            owner,
            "--signing-keys",
            signer,
            "--gas-token",
            NAM,
            "--gas-limit",
            "150000",
            "--node",
            &rpc
        ],
        Some(40)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    if wait_reveal_pk {
        client.exp_string(TX_APPLIED_SUCCESS)?;
    }
    check_tx_height(test, &mut client)
}

#[allow(clippy::too_many_arguments)]
fn transfer(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: f64,
    signer: Option<&str>,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout_sec: Option<Duration>,
    shielding_data_path: Option<PathBuf>,
    expected_err: Option<&str>,
    wait_reveal_pk: bool,
) -> Result<u32> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let channel_id = channel_id.to_string();
    let port_id = port_id.to_string();
    let amount = amount.to_string();
    let mut tx_args = vec![
        "ibc-transfer",
        "--source",
        sender.as_ref(),
        "--receiver",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--channel-id",
        &channel_id,
        "--port-id",
        &port_id,
        "--gas-limit",
        "150000",
        "--node",
        &rpc,
    ];

    if let Some(signer) = signer {
        tx_args.extend_from_slice(&["--signing-keys", signer]);
    } else {
        tx_args.push("--disposable-gas-payer");
    }

    let timeout = timeout_sec.unwrap_or_default().as_secs().to_string();
    if timeout_sec.is_some() {
        tx_args.push("--timeout-sec-offset");
        tx_args.push(&timeout);
    }

    let memo = shielding_data_path
        .as_ref()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_default();
    if shielding_data_path.is_some() {
        tx_args.push("--ibc-shielding-data");
        tx_args.push(&memo);
    }

    let mut client = run!(test, Bin::Client, tx_args, Some(300))?;
    match expected_err {
        Some(err) => {
            client.exp_string(err)?;
            Ok(0)
        }
        None => {
            client.exp_string(TX_APPLIED_SUCCESS)?;
            if wait_reveal_pk {
                client.exp_string(TX_APPLIED_SUCCESS)?;
            }
            check_tx_height(test, &mut client)
        }
    }
}

fn delegate_token(test: &Test) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(())
}

fn propose_funding(
    test_a: &Test,
    test_b: &Test,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
) -> Result<Epoch> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    let bertha = find_address(test_b, BERTHA)?;
    let christel = find_address(test_b, CHRISTEL)?;

    let pgf_funding = PgfFunding {
        continuous: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(10),
            target: bertha.to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
        retro: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(5),
            target: christel.to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
    };

    std::env::set_var(ENV_VAR_CHAIN_ID, test_a.net.chain_id.to_string());
    let albert = find_address(test_a, ALBERT)?;
    let rpc_a = get_actor_rpc(test_a, Who::Validator(0));
    let epoch = get_epoch(test_a, &rpc_a)?;
    let start_epoch = (epoch.0 + 6) / 3 * 3;
    let proposal_json_path = prepare_proposal_data(
        test_a.test_dir.path(),
        albert,
        pgf_funding,
        start_epoch,
    );

    let submit_proposal_args = vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--node",
        &rpc_a,
    ];
    let mut client = run!(test_a, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_inflation(test: &Test) -> Result<Epoch> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "TheTitle",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
                "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
                "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 6_u64,
        },
        "data": TestWasms::TxProposalIbcTokenInflation.read_bytes()
    });

    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "2000000",
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(100))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn submit_votes(test: &Test) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--node",
        &rpc,
    ];
    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        submit_proposal_vote,
        Some(40)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--node",
        &rpc,
    ];
    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_from_gaia(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    port_id: &PortId,
    channel_id: &ChannelId,
    memo_path: Option<PathBuf>,
) -> Result<()> {
    let port_id = port_id.to_string();
    let channel_id = channel_id.to_string();
    let amount = format!("{}{}", amount, token.as_ref());
    let rpc = format!("tcp://{GAIA_RPC}");
    let mut args = vec![
        "tx",
        "ibc-transfer",
        "transfer",
        &port_id,
        &channel_id,
        receiver.as_ref(),
        &amount,
        "--from",
        sender.as_ref(),
        "--gas-prices",
        "0.001stake",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        GAIA_CHAIN_ID,
        "--yes",
    ];

    let memo = memo_path
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).expect("Reading memo file failed")
        })
        .unwrap_or_default();
    if memo_path.is_some() {
        args.push("--memo");
        args.push(&memo);
    }

    let mut gaia = run_gaia_cmd(test, args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn check_tx_height(test: &Test, client: &mut NamadaCmd) -> Result<u32> {
    let (_unread, matched) = client.exp_regex(r"height .*")?;
    // Expecting e.g. "height 1337, consuming x gas units."
    let height_str = matched
        .trim()
        .split_once(' ')
        .unwrap()
        .1
        .split_once(',')
        .unwrap()
        .0;
    let height: u32 = height_str.parse().unwrap();

    // wait for the next block to use the app hash
    while height as u64 + 1 > query_height(test)?.revision_height() {
        sleep(1);
    }

    Ok(height)
}

fn make_ibc_data(message: Any) -> Vec<u8> {
    let mut tx_data = vec![];
    prost::Message::encode(&message, &mut tx_data)
        .expect("encoding IBC message shouldn't fail");
    tx_data
}

fn query_height(test: &Test) -> Result<Height> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();

    let status = test
        .async_runtime()
        .block_on(client.status())
        .map_err(|e| eyre!("Getting the status failed: {}", e))?;

    Ok(Height::new(0, status.sync_info.latest_block_height.into()).unwrap())
}

fn query_header(test: &Test, height: Height) -> Result<TmHeader> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    let height = height.revision_height() as u32;
    let result = test
        .async_runtime()
        .block_on(client.blockchain(height, height));
    match result {
        Ok(mut response) => match response.block_metas.pop() {
            Some(meta) => Ok(meta.header),
            None => Err(eyre!("No meta exists")),
        },
        Err(e) => Err(eyre!("Header query failed: {}", e)),
    }
}

fn check_ibc_update_query(
    test: &Test,
    client_id: &ClientId,
    consensus_height: BlockHeight,
) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    match test.async_runtime().block_on(RPC.shell().ibc_client_update(
        &client,
        client_id,
        &consensus_height,
    )) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(eyre!("No update event for the client {}", client_id)),
        Err(e) => Err(eyre!("IBC update event query failed: {}", e)),
    }
}

fn check_ibc_packet_query(
    test: &Test,
    event_type: &str,
    packet: &Packet,
) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    match test.async_runtime().block_on(RPC.shell().ibc_packet(
        &client,
        &IbcEventType(event_type.to_owned()),
        &packet.port_id_on_a,
        &packet.chan_id_on_a,
        &packet.port_id_on_b,
        &packet.chan_id_on_b,
        &packet.seq_on_a,
    )) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(eyre!("No packet event for the packet {}", packet)),
        Err(e) => Err(eyre!("IBC packet event query failed: {}", e)),
    }
}

fn query_value_with_proof(
    test: &Test,
    key: &Key,
    height: Option<Height>,
) -> Result<(Option<Vec<u8>>, TmProof)> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    let result = test.async_runtime().block_on(query_storage_value_bytes(
        &client,
        key,
        height.map(|h| BlockHeight(h.revision_height())),
        true,
    ));
    match result {
        (value, Some(proof)) => Ok((value, proof)),
        _ => Err(eyre!("Query failed: key {}", key)),
    }
}

fn convert_proof(tm_proof: TmProof) -> Result<CommitmentProofBytes> {
    let mut proofs = Vec::new();
    for op in &tm_proof.ops {
        let mut parsed = ics23::CommitmentProof { proof: None };
        prost::Message::merge(&mut parsed, op.data.as_slice())
            .expect("merging CommitmentProof failed");
        proofs.push(parsed);
    }

    let merkle_proof = MerkleProof { proofs };
    CommitmentProofBytes::try_from(merkle_proof).map_err(|e| {
        eyre!("Proof conversion to CommitmentProofBytes failed: {}", e)
    })
}

fn check_balance(
    test: &Test,
    owner: impl AsRef<str>,
    token: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));

    if owner.as_ref().starts_with("zvk") {
        shielded_sync(test, owner.as_ref())?;
    }

    let query_args = vec![
        "balance",
        "--owner",
        owner.as_ref(),
        "--token",
        token.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, query_args, Some(40))?;
    let expected =
        format!("{}: {expected_amount}", token.as_ref().to_lowercase());
    client.exp_string(&expected)?;
    client.assert_success();
    Ok(())
}

/// Check balances after IBC transfer
fn check_balances(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_a: &Test,
    test_b: &Test,
) -> Result<()> {
    // Check the balances on Chain A
    let escrow = Address::Internal(InternalAddress::Ibc).to_string();
    check_balance(test_a, escrow, NAM, 100000)?;
    // Check the source balance
    check_balance(test_a, ALBERT, NAM, 1900000)?;

    // Check the balance on Chain B
    let ibc_denom = format!("{dest_port_id}/{dest_channel_id}/nam");
    check_balance(test_b, BERTHA, ibc_denom, 100_000_000_000)?;

    Ok(())
}

fn get_gaia_denom_hash(denom: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(denom.as_ref());
    let hash = hasher.finalize();
    format!("ibc/{hash:X}")
}

fn check_gaia_balance(
    test: &Test,
    owner: impl AsRef<str>,
    denom: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
    let addr = find_gaia_address(test, owner)?;
    let args = [
        "query",
        "bank",
        "balances",
        &addr,
        "--node",
        &format!("tcp://{GAIA_RPC}"),
    ];
    let mut gaia = run_gaia_cmd(test, args, Some(40))?;
    gaia.exp_string(&format!("amount: \"{expected_amount}\""))?;
    let expected_denom = if denom.as_ref().contains('/') {
        get_gaia_denom_hash(denom)
    } else {
        denom.as_ref().to_string()
    };
    gaia.exp_string(&format!("denom: {expected_denom}"))?;
    Ok(())
}

/// Check balances after non IBC transfer
fn check_balances_after_non_ibc(
    port_id: &PortId,
    channel_id: &ChannelId,
    test_b: &Test,
) -> Result<()> {
    // Check the source on Chain B
    let ibc_denom = format!("{port_id}/{channel_id}/nam");
    check_balance(test_b, BERTHA, &ibc_denom, 50_000_000_000)?;

    // Check the traget on Chain B
    check_balance(test_b, ALBERT, &ibc_denom, 50_000_000_000)?;

    Ok(())
}

/// Check balances after IBC transfer back
fn check_balances_after_back(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_a: &Test,
    test_b: &Test,
) -> Result<()> {
    // Check the escrowed balance on Chain A
    let escrow = Address::Internal(InternalAddress::Ibc).to_string();
    check_balance(test_a, escrow, NAM, 50000)?;
    // Check the source balance on Chain A
    check_balance(test_a, ALBERT, NAM, 1950000)?;

    // Check the balance on Chain B
    let ibc_denom = format!("{dest_port_id}/{dest_channel_id}/nam");
    check_balance(test_b, BERTHA, ibc_denom, 0)?;

    Ok(())
}

/// Check balances after IBC shielded transfer
fn check_shielded_balances(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_a: &Test,
    test_b: &Test,
) -> Result<()> {
    // Check the shielded balance on Chain A
    check_balance(test_a, AA_VIEWING_KEY, BTC, 90)?;

    // Check the shielded balance on Chain B
    let ibc_denom = format!("{dest_port_id}/{dest_channel_id}/btc");
    check_balance(test_b, AB_VIEWING_KEY, ibc_denom, 1_000_000_000)?;

    Ok(())
}

fn check_funded_balances(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_b: &Test,
) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test_b.net.chain_id.to_string());
    // Check the balances on Chain B
    let ibc_denom = format!("{dest_port_id}/{dest_channel_id}/nam");
    let rpc_b = get_actor_rpc(test_b, Who::Validator(0));
    let query_args = vec![
        "balance", "--owner", BERTHA, "--token", &ibc_denom, "--node", &rpc_b,
    ];
    let mut client = run!(test_b, Bin::Client, query_args, Some(40))?;
    let regex = format!("{ibc_denom}: .*");
    let (_, matched) = client.exp_regex(&regex)?;
    let regex = regex::Regex::new(r"[0-9]+").unwrap();
    let iter = regex.find_iter(&matched);
    let balance: u64 = iter.last().unwrap().as_str().parse().unwrap();
    assert!(balance >= 10);
    client.assert_success();

    let query_args = vec![
        "balance", "--owner", CHRISTEL, "--token", &ibc_denom, "--node", &rpc_b,
    ];
    let mut client = run!(test_b, Bin::Client, query_args, Some(40))?;
    let regex = format!("{ibc_denom}: .*");
    let (_, matched) = client.exp_regex(&regex)?;
    let regex = regex::Regex::new(r"[0-9]+").unwrap();
    let iter = regex.find_iter(&matched);
    let balance: u64 = iter.last().unwrap().as_str().parse().unwrap();
    assert!(balance >= 5);
    client.assert_success();

    Ok(())
}

fn check_inflated_balance(test: &Test) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = vec![
        "shielded-sync",
        "--viewing-keys",
        AB_VIEWING_KEY,
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(120))?;
    client.assert_success();

    let query_args = vec![
        "balance",
        "--owner",
        AB_VIEWING_KEY,
        "--token",
        NAM,
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, query_args, Some(100))?;
    let (_, matched) = client.exp_regex("nam: .*")?;
    let regex = regex::Regex::new(r"[0-9]+").unwrap();
    let mut iter = regex.find_iter(&matched);
    let balance: f64 = iter.next().unwrap().as_str().parse().unwrap();
    assert!(balance > 0.0);
    client.assert_success();

    Ok(())
}

fn signer() -> Signer {
    "signer".to_string().into()
}

fn get_client_id_from_events(events: &[AbciEvent]) -> Option<ClientId> {
    get_attribute_from_events::<ibc_events::ClientId>(events)
}

fn get_connection_id_from_events(events: &[AbciEvent]) -> Option<ConnectionId> {
    get_attribute_from_events::<ibc_events::ConnectionId>(events)
}

fn get_channel_id_from_events(events: &[AbciEvent]) -> Option<ChannelId> {
    get_attribute_from_events::<ibc_events::ChannelId>(events)
}

fn get_ack_from_events(events: &[AbciEvent]) -> Option<Vec<u8>> {
    get_attribute_from_events::<ibc_events::PacketAck>(events)
        .map(String::into_bytes)
}

fn get_attribute_from_events<'value, DATA>(
    events: &[AbciEvent],
) -> Option<<DATA as ReadFromEventAttributes<'value>>::Value>
where
    DATA: ReadFromEventAttributes<'value>,
{
    events.iter().find_map(|event| {
        DATA::read_from_event_attributes(&event.attributes).ok()
    })
}

fn get_packet_from_events(events: &[AbciEvent]) -> Option<Packet> {
    events.iter().find_map(|event| {
        ibc_events::packet_from_event_attributes(&event.attributes).ok()
    })
}

fn get_events(test: &Test, height: u32) -> Result<Vec<AbciEvent>> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();

    let response = test
        .async_runtime()
        .block_on(client.block_results(height))
        .map_err(|e| eyre!("block_results() for an IBC event failed: {}", e))?;
    let tx_results = response.txs_results.ok_or_else(|| {
        eyre!("No transaction has been executed: height {}", height)
    })?;
    for result in tx_results {
        if result.code.is_err() {
            return Err(eyre!(
                "The transaction failed: code {:?}, log {}",
                result.code,
                result.log
            ));
        }
    }

    response
        .end_block_events
        .ok_or_else(|| eyre!("IBC event was not found: height {}", height))
}

fn shielded_sync(test: &Test, viewing_key: impl AsRef<str>) -> Result<()> {
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = vec![
        "shielded-sync",
        "--viewing-keys",
        viewing_key.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(120))?;
    client.assert_success();
    Ok(())
}

/// Get IBC shielding data for the following IBC transfer from the destination
/// chain
fn gen_ibc_shielding_data(
    dst_test: &Test,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<PathBuf> {
    std::env::set_var(ENV_VAR_CHAIN_ID, dst_test.net.chain_id.to_string());
    let rpc = get_actor_rpc(dst_test, Who::Validator(0));
    let output_folder = dst_test.test_dir.path().to_string_lossy();

    let amount = amount.to_string();
    let args = vec![
        "ibc-gen-shielding",
        "--output-folder-path",
        &output_folder,
        "--target",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--port-id",
        port_id.as_ref(),
        "--channel-id",
        channel_id.as_ref(),
        "--node",
        &rpc,
    ];

    let mut client = run!(dst_test, Bin::Client, args, Some(120))?;
    let (_unread, matched) =
        client.exp_regex("Output IBC shielding transfer .*")?;
    let file_path = matched.trim().split(' ').last().expect("invalid output");
    client.assert_success();

    Ok(PathBuf::from_str(file_path).expect("invalid file path"))
}
