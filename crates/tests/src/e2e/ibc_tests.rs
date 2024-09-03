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
use std::path::{Path, PathBuf};

use color_eyre::eyre::Result;
use eyre::eyre;
use namada_apps_lib::client::rpc::query_storage_value_bytes;
use namada_apps_lib::config::ethereum_bridge;
use namada_apps_lib::config::genesis::templates;
use namada_apps_lib::tendermint_rpc::{Client, HttpClient, Url};
use namada_sdk::address::MASP;
use namada_sdk::chain::Epoch;
use namada_sdk::governance::cli::onchain::PgfFunding;
use namada_sdk::governance::pgf::ADDRESS as PGF_ADDRESS;
use namada_sdk::governance::storage::proposal::{PGFIbcTarget, PGFTarget};
use namada_sdk::ibc::clients::tendermint::client_state::ClientState as TmClientState;
use namada_sdk::ibc::core::client::types::Height;
use namada_sdk::ibc::core::host::types::identifiers::{
    ChannelId, ClientId, PortId,
};
use namada_sdk::ibc::primitives::proto::Any;
use namada_sdk::ibc::storage::*;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::token::Amount;
use namada_test_utils::TestWasms;
use namada_token::masp::PaymentAddress;
use prost::Message;
use setup::constants::*;
use sha2::{Digest, Sha256};

use crate::e2e::helpers::{
    epochs_per_year_from_min_duration, find_address, find_gaia_address,
    get_actor_rpc, get_epoch, get_gaia_gov_address,
};
use crate::e2e::ledger_tests::{
    start_namada_ledger_node_wait_wasm, write_json_file,
};
use crate::e2e::setup::{
    self, apply_use_device, run_gaia_cmd, run_hermes_cmd,
    set_ethereum_bridge_mode, setup_gaia, setup_hermes, sleep, Bin, NamadaCmd,
    Test, Who,
};
use crate::strings::TX_APPLIED_SUCCESS;
use crate::{run, run_as};

const IBC_REFUND_TARGET_ALIAS: &str = "ibc-refund-target";
const IBC_CLINET_ID: &str = "07-tendermint-0";
const UPGRADED_CHAIN_ID: &str = "upgraded-chain";

/// IBC transfer tests:
/// 1. Transparent transfers
///   - Namada -> Gaia -> Namada
///   - Gaia -> Namada -> Gaia
/// 2. Invalid transfers
/// 3. Shielding/Unshielding transfers
///   - Gaia -> Namada -> (shielded transfer) -> Namada -> Gaia
/// 4. Shielding transfer the received token back to a shielded account on
///    Namada
/// 5. Refunding when transfer failure
///   - Ack with an error (invalid receiver)
///   - Timeout
///   - When unshielding transfer failure,
///     - Mint the IBC token for the refund
///     - Unescrow the token for the refund
#[test]
fn ibc_transfers() -> Result<()> {
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
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) = run_namada_gaia(update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    setup_hermes(&test, &test_gaia)?;
    let port_id_namada = "transfer".parse().unwrap();
    let port_id_gaia = "transfer".parse().unwrap();
    let (channel_id_namada, channel_id_gaia) =
        create_channel_with_hermes(&test, &test_gaia)?;

    // Start relaying
    let hermes = run_hermes(&test)?;
    let bg_hermes = hermes.background();

    // 1. Transparent transfers

    // Transfer 2 APFEL from Namada to Gaia
    let gaia_receiver = find_gaia_address(&test_gaia, GAIA_USER)?;
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        APFEL,
        2,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;

    check_balance(&test, ALBERT, APFEL, 999_998)?;
    let token_addr = find_address(&test, APFEL)?;
    let ibc_denom_on_gaia =
        format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");
    check_gaia_balance(&test_gaia, GAIA_USER, &ibc_denom_on_gaia, 2_000_000)?;

    // Transfer 1 APFEL back from Gaia to Namada
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        &namada_receiver,
        get_gaia_denom_hash(&ibc_denom_on_gaia),
        1_000_000,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // Check the balances
    check_balance(&test, ALBERT, APFEL, 999_999)?;
    check_gaia_balance(&test_gaia, GAIA_USER, &ibc_denom_on_gaia, 1_000_000)?;

    // Transfer 200 samoleans from Gaia to Namada
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        &namada_receiver,
        GAIA_COIN,
        200,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{GAIA_COIN}");
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 200)?;
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 800)?;

    // Transfer 100 samoleans back from Namada to Gaia
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        &ibc_denom_on_namada,
        100,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;

    // Check the balances
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 100)?;
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 900)?;

    // 2. Invalid transfers
    try_invalid_transfers(
        &test,
        &gaia_receiver,
        &port_id_namada,
        &channel_id_namada,
    )?;

    // 3. Shielding/Unshielding transfers

    // Shielding transfer 100 samoleans from Gaia to Namada
    let shielding_data_path = gen_ibc_shielding_data(
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
        Some(shielding_data_path),
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test_gaia)?;
    // Check the token on Namada
    check_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 800)?;

    // Shielded transfer 50 samoleans on Namada
    transfer_on_chain(
        &test,
        "transfer",
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        &ibc_denom_on_namada,
        50,
        ALBERT_KEY,
    )?;
    check_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 50)?;
    check_balance(&test, AB_VIEWING_KEY, &ibc_denom_on_namada, 50)?;

    // Unshielding transfer 10 samoleans from Namada to Gaia
    transfer(
        &test,
        B_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        10,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    check_balance(&test, AB_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_gaia_balance(&test_gaia, GAIA_USER, GAIA_COIN, 810)?;

    // 4. Shielding transfer the received token back to a shielded account on
    //    Namada
    let memo_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        &ibc_denom_on_gaia,
        1,
        &port_id_namada,
        &channel_id_namada,
    )?;
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        AA_PAYMENT_ADDRESS,
        get_gaia_denom_hash(&ibc_denom_on_gaia),
        1_000_000,
        &port_id_gaia,
        &channel_id_gaia,
        Some(memo_path),
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;
    // Check the token on Namada
    check_balance(&test, AA_VIEWING_KEY, APFEL, 1)?;

    // 5. Refunding when transfer failure

    // Transfer to an invalid receiver address to check the refund for the
    // escrowed token
    transfer(
        &test,
        ALBERT,
        "invalid_receiver",
        APFEL,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    // The balance should not be changed
    check_balance(&test, ALBERT, APFEL, 999_999)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Transfer will be timed out to check the refund for the burned IBC token
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        &ibc_denom_on_namada,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        Some(Duration::new(10, 0)),
        None,
        None,
        false,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&test)?;
    let bg_hermes = hermes.background();

    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    // The balance should not be changed
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 100)?;

    // Unshielding transfer to Gaia's invalid account to check the refund for
    // the burned IBC token
    transfer(
        &test,
        A_SPENDING_KEY,
        "invalid_receiver",
        &ibc_denom_on_namada,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    // Check the token has been refunded to the refund target
    check_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_balance(&test, IBC_REFUND_TARGET_ALIAS, &ibc_denom_on_namada, 10)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Unshielding transfer will be timed out to check the refund for the
    // escrowed IBC token
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        APFEL,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        Some(Duration::new(10, 0)),
        None,
        None,
        false,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&test)?;
    let _bg_hermes = hermes.background();

    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;
    // Check the token has been refunded to the refund target
    check_balance(&test, AA_VIEWING_KEY, APFEL, 0)?;
    check_balance(&test, IBC_REFUND_TARGET_ALIAS, APFEL, 1)?;

    Ok(())
}

#[test]
fn pgf_over_ibc() -> Result<()> {
    const PIPELINE_LEN: u64 = 5;
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(20);
            // for the trusting period of IBC client
            genesis.parameters.pos_params.pipeline_len = PIPELINE_LEN;
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) = run_namada_gaia(update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    setup_hermes(&test, &test_gaia)?;
    let port_id_namada = "transfer".parse().unwrap();
    let port_id_gaia: PortId = "transfer".parse().unwrap();
    let (channel_id_namada, channel_id_gaia) =
        create_channel_with_hermes(&test, &test_gaia)?;

    // Start relaying
    let hermes = run_hermes(&test)?;
    let _bg_hermes = hermes.background();

    // Transfer to PGF account
    transfer_on_chain(
        &test,
        "transparent-transfer",
        ALBERT,
        PGF_ADDRESS.to_string(),
        NAM,
        100,
        ALBERT_KEY,
    )?;

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }
    // funding proposal
    let continuous_receiver = find_gaia_address(&test_gaia, GAIA_RELAYER)?;
    let retro_receiver = find_gaia_address(&test_gaia, GAIA_USER)?;
    let start_epoch = propose_funding(
        &test,
        continuous_receiver,
        retro_receiver,
        &port_id_namada,
        &channel_id_namada,
    )?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }
    submit_votes(&test)?;

    // wait for the grace
    let grace_epoch = start_epoch + 6u64;
    while epoch < grace_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }
    wait_for_packet_relay(&port_id_namada, &channel_id_namada, &test)?;

    // Check balances after funding over IBC
    let token_addr = find_address(&test, NAM)?;
    let ibc_denom = format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");
    check_gaia_balance(&test_gaia, GAIA_RELAYER, &ibc_denom, 10_000_000)?;
    check_gaia_balance(&test_gaia, GAIA_USER, &ibc_denom, 5_000_000)?;

    Ok(())
}

/// IBC token inflation test
/// - Propose the inflation of an IBC token received from Gaia
/// - Shielding transfer of the token from Gaia
/// - Check the inflation
#[test]
fn ibc_token_inflation() -> Result<()> {
    const PIPELINE_LEN: u64 = 2;
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
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) = run_namada_gaia(update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        sleep(10);
        epoch = get_epoch(&test, &rpc).unwrap_or_default();
    }
    // inflation proposal on Namada
    let start_epoch = propose_inflation(&test)?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        sleep(10);
        epoch = get_epoch(&test, &rpc).unwrap_or_default();
    }
    submit_votes(&test)?;

    // Create an IBC channel while waiting the grace epoch
    setup_hermes(&test, &test_gaia)?;
    let port_id_namada = "transfer".parse().unwrap();
    let port_id_gaia = "transfer".parse().unwrap();
    let (channel_id_namada, channel_id_gaia) =
        create_channel_with_hermes(&test, &test_gaia)?;
    // Start relaying
    let hermes = run_hermes(&test)?;
    let _bg_hermes = hermes.background();

    // wait for the grace
    let grace_epoch = start_epoch + 6u64;
    while epoch < grace_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }

    // Check the target balance is zero before the inflation
    check_balance(&test, AA_VIEWING_KEY, NAM, 0)?;
    // Shielding transfer 1 samoleans from Gaia to Namada
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        GAIA_COIN,
        1,
        &port_id_namada,
        &channel_id_namada,
    )?;
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        AA_PAYMENT_ADDRESS,
        GAIA_COIN,
        1,
        &port_id_gaia,
        &channel_id_gaia,
        Some(shielding_data_path),
        None,
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // wait the next masp epoch to dispense the reward
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let new_epoch = epoch + MASP_EPOCH_MULTIPLIER;
    while epoch < new_epoch {
        sleep(10);
        epoch = get_epoch(&test, &rpc).unwrap_or_default();
    }

    // Check balances
    check_inflated_balance(&test, AA_VIEWING_KEY)?;

    Ok(())
}

#[test]
fn ibc_upgrade_client() -> Result<()> {
    const UPGRADE_HEIGHT_OFFSET: u64 = 20;

    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) = run_namada_gaia(update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    setup_hermes(&test, &test_gaia)?;
    create_channel_with_hermes(&test, &test_gaia)?;

    let height = query_height(&test_gaia)?;
    let upgrade_height = height.revision_height() + UPGRADE_HEIGHT_OFFSET;

    // upgrade proposal
    propose_upgrade_client(&test, &test_gaia, upgrade_height)?;

    // vote
    vote_on_gaia(&test_gaia)?;
    wait_for_pass(&test_gaia)?;

    // wait for the halt height
    let mut height = query_height(&test_gaia)?;
    while height.revision_height() < upgrade_height {
        sleep(5);
        height = query_height(&test_gaia)?;
    }

    // Upgrade the IBC client of Gaia on Namada with Hermes
    upgrade_client(&test, test.net.chain_id.to_string(), upgrade_height)?;

    // Check the upgraded client
    let upgraded_client_state =
        get_client_state(&test, &IBC_CLINET_ID.parse().unwrap())?;
    assert_eq!(
        upgraded_client_state.inner().chain_id.as_str(),
        UPGRADED_CHAIN_ID
    );

    Ok(())
}

/// IBC rate limit test
/// 1. Test per-epoch throuput
///   - The per-epoch throughput is 1 NAM
///   - Transfer 1 NAM in an epoch will succeed
///   - Transfer 1 NAM in the same epoch will fail
///   - Transfer 1 NAM in the next epoch will succeed
/// 2. Test the mint limit
///   - The mint limit is 1
///   - Receiving 2 samoleans from Gaia will fail
#[test]
fn ibc_rate_limit() -> Result<()> {
    // Mint limit 2 transfer/channel-0/nam, per-epoch throughput limit 1 NAM
    let update_genesis = |mut genesis: templates::All<
        templates::Unvalidated,
    >,
                          base_dir: &_| {
        genesis.parameters.parameters.epochs_per_year =
            epochs_per_year_from_min_duration(50);
        genesis.parameters.ibc_params.default_mint_limit = Amount::from_u64(1);
        genesis
            .parameters
            .ibc_params
            .default_per_epoch_throughput_limit = Amount::from_u64(1_000_000);
        setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
    };
    let (ledger, gaia, test, test_gaia) = run_namada_gaia(update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    setup_hermes(&test, &test_gaia)?;
    let port_id_namada = "transfer".parse().unwrap();
    let port_id_gaia: PortId = "transfer".parse().unwrap();
    let (channel_id_namada, channel_id_gaia) =
        create_channel_with_hermes(&test, &test_gaia)?;

    // Start relaying
    let hermes = run_hermes(&test)?;
    let _bg_hermes = hermes.background();

    // wait for the next epoch
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }

    // Transfer 1 NAM from Namada to Gaia
    let gaia_receiver = find_gaia_address(&test_gaia, GAIA_USER)?;
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;

    // Transfer 1 NAM from Namada to Gaia again will fail
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        // expect an error of the throughput limit
        Some(
            "Transfer exceeding the per-epoch throughput limit is not allowed",
        ),
        false,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }

    // Transfer 1 NAM from Namada to Gaia will succeed in the new epoch
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        false,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }

    // Transfer 2 samoleans from Gaia to Namada will succeed, but Namada can't
    // receive due to the mint limit and the packet will be timed out
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_gaia(
        &test_gaia,
        GAIA_USER,
        namada_receiver,
        GAIA_COIN,
        2,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        Some(Duration::new(10, 0)),
    )?;
    wait_for_packet_relay(&port_id_gaia, &channel_id_gaia, &test)?;

    // Check if Namada hasn't receive it
    let ibc_denom = format!("{port_id_namada}/{channel_id_namada}/{GAIA_COIN}");
    // Need the raw address to check the balance because the token shouldn't be
    // received
    let token_addr = ibc_token(ibc_denom).to_string();
    check_balance(&test, ALBERT, token_addr, 0)?;

    Ok(())
}

fn run_namada_gaia(
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
) -> Result<(NamadaCmd, NamadaCmd, Test, Test)> {
    let test = setup::network(&mut update_genesis, None)?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let ledger = start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;

    // gaia
    let test_gaia = setup_gaia()?;
    let gaia = run_gaia(&test_gaia)?;
    sleep(5);

    Ok((ledger, gaia, test, test_gaia))
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

fn upgrade_client(
    test: &Test,
    host_chain_id: impl AsRef<str>,
    upgrade_height: u64,
) -> Result<()> {
    let args = [
        "upgrade",
        "client",
        "--host-chain",
        host_chain_id.as_ref(),
        "--client",
        "07-tendermint-0",
        "--upgrade-height",
        &upgrade_height.to_string(),
    ];
    let mut hermes = run_hermes_cmd(test, args, Some(120))?;
    hermes.exp_string("upgraded-chain")?;
    hermes.assert_success();

    Ok(())
}

fn get_client_state(
    test: &Test,
    client_id: &ClientId,
) -> Result<TmClientState> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    let key = client_state_key(client_id);

    let result = test
        .async_runtime()
        .block_on(query_storage_value_bytes(&client, &key, None, false));
    let cs = match result {
        (Some(v), _) => Any::decode(&v[..])
            .map_err(|e| eyre!("Decoding the client state failed: {}", e))?,
        _ => {
            return Err(eyre!(
                "The client state doesn't exist: client ID {}",
                client_id
            ));
        }
    };

    let client_state = TmClientState::try_from(cs)
        .expect("the state should be a TmClientState");

    Ok(client_state)
}

fn try_invalid_transfers(
    test: &Test,
    receiver: impl AsRef<str>,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<()> {
    // invalid port
    let nam_addr = find_address(test, NAM)?;
    transfer(
        test,
        ALBERT,
        receiver.as_ref(),
        NAM,
        10,
        Some(ALBERT_KEY),
        &"port".parse().unwrap(),
        channel_id,
        None,
        None,
        // the IBC denom can't be parsed when using an invalid port
        Some(&format!("Invalid IBC denom: {nam_addr}")),
        false,
    )?;

    // invalid channel
    transfer(
        test,
        ALBERT,
        receiver.as_ref(),
        NAM,
        10,
        Some(ALBERT_KEY),
        port_id,
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
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let amount = amount.to_string();
    let tx_args = apply_use_device(vec![
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
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(120))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    signer: Option<&str>,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout_sec: Option<Duration>,
    shielding_data_path: Option<PathBuf>,
    expected_err: Option<&str>,
    wait_reveal_pk: bool,
) -> Result<u32> {
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let channel_id = channel_id.to_string();
    let port_id = port_id.to_string();
    let amount = amount.to_string();
    let mut tx_args = apply_use_device(vec![
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
        "200000",
        "--node",
        &rpc,
    ]);

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

    if sender.as_ref().starts_with("zsk") {
        let mut cmd = run!(
            test,
            Bin::Wallet,
            &[
                "gen",
                "--alias",
                IBC_REFUND_TARGET_ALIAS,
                "--alias-force",
                "--unsafe-dont-encrypt"
            ],
            Some(20),
        )?;
        cmd.assert_success();
        tx_args.push("--refund-target");
        tx_args.push(IBC_REFUND_TARGET_ALIAS);
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
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(())
}

fn propose_funding(
    test: &Test,
    continuous_receiver: impl AsRef<str>,
    retro_receiver: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
) -> Result<Epoch> {
    let pgf_funding = PgfFunding {
        continuous: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(10),
            target: continuous_receiver.as_ref().to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
        retro: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(5),
            target: retro_receiver.as_ref().to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
    };

    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "PGF",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "PGF proposal",
                "motivation": "PGF proposal test",
                "details": "PGF proposal",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 6_u64,
        },
        "data": pgf_funding,
    });
    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_inflation(test: &Test) -> Result<Epoch> {
    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "IBC token inflation",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "IBC token inflation",
                "motivation": "IBC token inflation",
                "details": "IBC token inflation",
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

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "4000000",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(100))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_upgrade_client(
    test_namada: &Test,
    test_gaia: &Test,
    upgrade_height: u64,
) -> Result<()> {
    let client_state =
        get_client_state(test_namada, &IBC_CLINET_ID.parse().unwrap())?;
    let mut client_state = client_state.inner().clone();
    client_state.chain_id = UPGRADED_CHAIN_ID.parse().unwrap();
    client_state.latest_height = Height::new(0, upgrade_height + 1).unwrap();
    client_state.zero_custom_fields();
    let any_client_state = Any::from(client_state.clone());

    let proposer = get_gaia_gov_address(test_gaia)?;

    let proposal_json = serde_json::json!({
          "messages": [
            {
              "@type": "/ibc.core.client.v1.MsgIBCSoftwareUpgrade",
              "plan": {
                "name": "Upgrade",
                "height": upgrade_height,
                "info": ""
              },
              "upgraded_client_state": {
                  "@type": any_client_state.type_url,
                  "chain_id": client_state.chain_id().to_string(),
                  "unbonding_period": format!("{}s", client_state.unbonding_period.as_secs()),
                  "latest_height": client_state.latest_height,
                  "proof_specs": client_state.proof_specs,
                  "upgrade_path": client_state.upgrade_path,
              },
              "signer": proposer
            }
          ],
          "metadata": "ipfs://CID",
          "deposit": "10000000stake",
          "title": "Upgrade",
          "summary": "Upgrade Gaia chain",
          "expedited": false
    });
    let proposal_json_path = test_gaia.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let rpc = format!("tcp://{GAIA_RPC}");
    let submit_proposal_args = vec![
        "tx",
        "gov",
        "submit-proposal",
        proposal_json_path.to_str().unwrap(),
        "--from",
        GAIA_USER,
        "--gas",
        "250000",
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
    let mut gaia = run_gaia_cmd(test_gaia, submit_proposal_args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn wait_for_pass(test: &Test) -> Result<()> {
    let args = ["query", "gov", "proposal", "1"];
    for _ in 0..10 {
        sleep(5);
        let mut gaia = run_gaia_cmd(test, args, Some(40))?;
        let (_, matched) = gaia.exp_regex("status: .*")?;
        if matched.split(' ').last().unwrap() == "PROPOSAL_STATUS_PASSED" {
            break;
        }
    }
    Ok(())
}

fn vote_on_gaia(test: &Test) -> Result<()> {
    let rpc = format!("tcp://{GAIA_RPC}");
    let args = vec![
        "tx",
        "gov",
        "vote",
        "1",
        "yes",
        "--from",
        GAIA_VALIDATOR,
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
    let mut gaia = run_gaia_cmd(test, args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn submit_votes(test: &Test) -> Result<()> {
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
    let submit_proposal_vote_delagator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--node",
        &rpc,
    ]);
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
    timeout_sec: Option<Duration>,
) -> Result<()> {
    let port_id = port_id.to_string();
    let channel_id = channel_id.to_string();
    let amount = format!("{}{}", amount, token.as_ref());
    let rpc = format!("tcp://{GAIA_RPC}");
    // If the receiver is a pyament address we want to mask it to the more
    // general MASP internal address to improve on privacy
    let receiver = match PaymentAddress::from_str(receiver.as_ref()) {
        Ok(_) => MASP.to_string(),
        Err(_) => receiver.as_ref().to_string(),
    };
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

    let timeout_nanosec = timeout_sec
        .as_ref()
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_default();
    if timeout_sec.is_some() {
        args.push("--packet-timeout-timestamp");
        args.push(&timeout_nanosec);
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

fn check_balance(
    test: &Test,
    owner: impl AsRef<str>,
    token: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
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

fn check_inflated_balance(
    test: &Test,
    viewing_key: impl AsRef<str>,
) -> Result<()> {
    shielded_sync(test, viewing_key.as_ref())?;

    let rpc = get_actor_rpc(test, Who::Validator(0));
    let query_args = vec![
        "balance",
        "--owner",
        viewing_key.as_ref(),
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

fn shielded_sync(test: &Test, viewing_key: impl AsRef<str>) -> Result<()> {
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
