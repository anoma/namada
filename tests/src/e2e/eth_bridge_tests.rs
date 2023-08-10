mod helpers;

use std::num::NonZeroU64;
use std::ops::ControlFlow;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use color_eyre::eyre::{eyre, Result};
use expectrl::ControlCode;
use namada::eth_bridge::oracle;
use namada::eth_bridge::storage::vote_tallies;
use namada::ledger::eth_bridge::{
    ContractVersion, Contracts, EthereumBridgeConfig, MinimumConfirmations,
    UpgradeableContract,
};
use namada::types::address::wnam;
use namada::types::control_flow::time::{Constant, Sleep};
use namada::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
use namada::types::ethereum_events::EthAddress;
use namada::types::storage::{self, Epoch};
use namada::types::{address, token};
use namada_apps::config::ethereum_bridge;
use namada_core::ledger::eth_bridge::ADDRESS as BRIDGE_ADDRESS;
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::{
    EthereumEvent, TransferToEthereum, TransferToNamada,
};
use namada_core::types::token::Amount;
use namada_test_utils::tx_data::TxWriteData;
use namada_test_utils::TestWasms;
use tokio::time::{Duration, Instant};

use super::setup::set_ethereum_bridge_mode;
use crate::e2e::eth_bridge_tests::helpers::{
    attempt_wrapped_erc20_transfer, find_wrapped_erc20_balance,
    read_erc20_supply, send_transfer_to_namada_event,
    setup_single_validator_test, EventsEndpointClient,
    DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR,
};
use crate::e2e::helpers::{
    find_address, find_balance, get_actor_rpc, init_established_account,
    rpc_client_do, run_single_node_test_from,
};
use crate::e2e::setup;
use crate::e2e::setup::constants::{
    ALBERT, ALBERT_KEY, BERTHA, BERTHA_KEY, NAM,
};
use crate::e2e::setup::{Bin, Who};
use crate::{run, run_as};

/// Tests that we can start the ledger with an endpoint for submitting Ethereum
/// events. This mode can be used in further end-to-end tests.
#[test]
fn run_ledger_with_ethereum_events_endpoint() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::SelfHostedEndpoint,
        Some(DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR),
    );

    // Start the ledger as a validator
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;
    ledger.exp_string(
        "Starting to listen for Borsh-serialized Ethereum events",
    )?;
    ledger.exp_string("Namada ledger node started")?;

    ledger.send_control(ControlCode::EndOfText)?;
    ledger.exp_string(
        "Stopping listening for Borsh-serialized Ethereum events",
    )?;

    Ok(())
}

/// Test we can transfer some DAI to an implicit address on Namada,
/// then back to Ethereum, burning the assets we minted after the
/// first transfer.
#[tokio::test]
async fn test_roundtrip_eth_transfer() -> Result<()> {
    const CLIENT_COMMAND_TIMEOUT_SECONDS: u64 = 60;
    const QUERY_TIMEOUT_SECONDS: u64 = 40;
    const SOLE_VALIDATOR: Who = Who::Validator(0);
    const RECEIVER: &str = "0x6B175474E89094C55Da98b954EedeAC495271d0F";

    let (test, bg_ledger) = setup_single_validator_test()?;

    // check the initial supply of DAI - should be None
    let ledger_addr = get_actor_rpc(&test, &SOLE_VALIDATOR);
    let rpc_addr = format!("http://{ledger_addr}");
    let dai_supply =
        read_erc20_supply(&rpc_addr, &DAI_ERC20_ETH_ADDRESS).await?;
    assert_eq!(dai_supply, None);

    let transfer_amount = token::Amount::from(10_000_000);
    // [`BERTHA`] is a pre-existing implicit address in our wallet
    let berthas_addr = find_address(&test, BERTHA)?;

    let dai_transfer = TransferToNamada {
        amount: transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: berthas_addr.to_owned(),
    };
    let bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    // at this point Bertha should have some tokens in Namada
    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &SOLE_VALIDATOR,
        &DAI_ERC20_ETH_ADDRESS,
        &berthas_addr,
    )?;
    assert_eq!(bertha_wdai_balance, transfer_amount);

    let dai_supply =
        read_erc20_supply(&rpc_addr, &DAI_ERC20_ETH_ADDRESS).await?;
    assert_eq!(dai_supply, Some(transfer_amount));

    // let's transfer them back to Ethereum
    let amount = token::DenominatedAmount {
        amount: transfer_amount,
        denom: 0u8.into(),
    }
    .to_string();
    let dai_addr = DAI_ERC20_ETH_ADDRESS.to_string();
    let tx_args = vec![
        "add-erc20-transfer",
        "--address",
        BERTHA,
        "--signer",
        BERTHA,
        "--amount",
        &amount,
        "--erc20",
        &dai_addr,
        "--ethereum-address",
        RECEIVER,
        "--fee-amount",
        "10",
        "--fee-payer",
        BERTHA,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &ledger_addr,
    ];

    let mut namadac_tx = run!(
        test,
        Bin::Client,
        tx_args,
        Some(CLIENT_COMMAND_TIMEOUT_SECONDS)
    )?;
    namadac_tx.exp_string("Transaction accepted")?;
    namadac_tx.exp_string("Transaction applied")?;
    namadac_tx.exp_string("Transaction is valid")?;
    drop(namadac_tx);

    let mut namadar = run!(
        test,
        Bin::Relayer,
        [
            "ethereum-bridge-pool",
            "query",
            "--ledger-address",
            &ledger_addr,
        ],
        Some(QUERY_TIMEOUT_SECONDS),
    )?;
    // get the returned hash of the transfer.
    let regex =
        expectrl::Regex(r#""bridge_pool_contents":(?s).*(?-s)"[0-9A-F]+":"#);
    let mut hash = String::from_utf8(
        namadar
            .session
            .expect(regex)?
            .get(0)
            .ok_or_else(|| eyre!("failed to retrieve hash with regex"))?
            .to_vec(),
    )?
    .split_ascii_whitespace()
    .last()
    .ok_or_else(|| eyre!("failed to get last token"))?
    .to_string();
    hash.remove(0);
    hash.truncate(hash.len() - 2);

    let relayer = berthas_addr.to_string();
    let proof_args = vec![
        "ethereum-bridge-pool",
        "construct-proof",
        "--hash-list",
        &hash,
        "--ledger-address",
        &ledger_addr,
        "--relayer",
        &relayer,
    ];
    let mut namadar =
        run!(test, Bin::Relayer, proof_args, Some(QUERY_TIMEOUT_SECONDS))?;
    namadar.exp_string(r#"{"hashes":["#)?;

    let mut client = EventsEndpointClient::default();

    let transfers = EthereumEvent::TransfersToEthereum {
        nonce: 0.into(),
        transfers: vec![TransferToEthereum {
            amount: transfer_amount,
            asset: DAI_ERC20_ETH_ADDRESS,
            receiver: EthAddress::from_str(RECEIVER).expect("Test failed"),
            gas_amount: Amount::native_whole(10),
            sender: berthas_addr.clone(),
            gas_payer: berthas_addr.clone(),
        }],
        valid_transfers_map: vec![true],
        relayer: berthas_addr.clone(),
    };

    client.send(&transfers).await?;
    let mut ledger = bg_ledger.foreground();
    ledger.exp_string(
        "Applying state updates derived from Ethereum events found in \
         protocol transaction",
    )?;
    let _bg_ledger = ledger.background();
    let mut namadar = run!(
        test,
        Bin::Relayer,
        [
            "ethereum-bridge-pool",
            "query",
            "--ledger-address",
            &ledger_addr,
        ],
        Some(QUERY_TIMEOUT_SECONDS),
    )?;
    namadar.exp_string("Bridge pool is empty.")?;

    // bertha's balance should be back at 0
    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &SOLE_VALIDATOR,
        &DAI_ERC20_ETH_ADDRESS,
        &berthas_addr,
    )?;
    assert_eq!(bertha_wdai_balance, 0.into());

    // check the final supply of DAI - should be 0
    let dai_supply =
        read_erc20_supply(&rpc_addr, &DAI_ERC20_ETH_ADDRESS).await?;
    assert_eq!(dai_supply, Some(0.into()));

    Ok(())
}
