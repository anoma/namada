mod helpers;

use std::num::NonZeroU64;
use std::ops::ControlFlow;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use color_eyre::eyre::{eyre, Result};
use expectrl::ControlCode;
use namada_sdk::control_flow::time::{Constant, Sleep};
use namada_sdk::eth_bridge::oracle;
use namada_sdk::eth_bridge::storage::vote_tallies;
use namada_sdk::eth_bridge::{
    ContractVersion, Contracts, EthereumBridgeParams, MinimumConfirmations,
    UpgradeableContract,
};
use namada_apps_lib::config::ethereum_bridge;
use namada_core::address::Address;
use namada_core::ethereum_events::{
    EthereumEvent, TransferToEthereum, TransferToNamada,
};
use namada_core::token::Amount;
use namada_sdk::address::wnam;
use namada_sdk::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
use namada_sdk::ethereum_events::EthAddress;
use namada_sdk::storage::{self, Epoch};
use namada_sdk::{address, token};
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
use crate::strings::{
    LEDGER_STARTED, TX_ACCEPTED, TX_APPLIED_SUCCESS, VALIDATOR_NODE,
};
use crate::{run, run_as, ADDRESS as BRIDGE_ADDRESS};

/// # Examples
///
/// ```
/// let storage_key = storage_key("queue");
/// assert_eq!(
///     storage_key,
///     "#tnam1quqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfgdmms/queue"
/// );
/// ```
fn storage_key(path: &str) -> String {
    format!("#{BRIDGE_ADDRESS}/{path}")
}

/// Tests that we can start the ledger with an endpoint for submitting Ethereum
/// events. This mode can be used in further end-to-end tests.
#[test]
fn run_ledger_with_ethereum_events_endpoint() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::SelfHostedEndpoint,
        Some(DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR),
    );

    // Start the ledger as a validator
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;
    ledger.exp_string(
        "Starting to listen for Borsh-serialized Ethereum events",
    )?;
    ledger.exp_string(LEDGER_STARTED)?;

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
    let amount =
        token::DenominatedAmount::new(transfer_amount, 0u8.into()).to_string();
    let dai_addr = DAI_ERC20_ETH_ADDRESS.to_string();
    let tx_args = vec![
        "add-erc20-transfer",
        "--address",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--amount",
        &amount,
        "--erc20",
        &dai_addr,
        "--ethereum-address",
        RECEIVER,
        "--gas-amount",
        "10",
        "--gas-payer",
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
    namadac_tx.exp_string(TX_ACCEPTED)?;
    namadac_tx.exp_string(TX_APPLIED_SUCCESS)?;
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

/// In this test, we check the following:
/// 1. We can successfully add transfers to the bridge pool.
/// 2. We can query the bridge pool and it is non-empty.
/// 3. We request a proof of inclusion of the transfer into the bridge pool.
/// 4. We submit an Ethereum event indicating that the transfer has been
///    relayed.
/// 5. We check that the event is removed from the bridge pool.
#[tokio::test]
async fn test_bridge_pool_e2e() {
    const LEDGER_STARTUP_TIMEOUT_SECONDS: u64 = 40;
    const CLIENT_COMMAND_TIMEOUT_SECONDS: u64 = 60;
    const QUERY_TIMEOUT_SECONDS: u64 = 40;
    const SOLE_VALIDATOR: Who = Who::Validator(0);
    const RECEIVER: &str = "0x6B175474E89094C55Da98b954EedeAC495271d0F";
    let wnam_address = wnam().to_canonical();
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params = Some(EthereumBridgeParams {
                eth_start_height: Default::default(),
                min_confirmations: Default::default(),
                contracts: Contracts {
                    native_erc20: wnam(),
                    bridge: UpgradeableContract {
                        address: EthAddress([0; 20]),
                        version: Default::default(),
                    },
                    governance: UpgradeableContract {
                        address: EthAddress([1; 20]),
                        version: Default::default(),
                    },
                },
            });
            genesis
        },
        None,
    )
    .unwrap();
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::SelfHostedEndpoint,
        Some(DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR),
    );
    let mut namadan_ledger = run_as!(
        test,
        SOLE_VALIDATOR,
        Bin::Node,
        &["ledger"],
        Some(LEDGER_STARTUP_TIMEOUT_SECONDS)
    )
    .unwrap();
    namadan_ledger.exp_string("Committed block hash").unwrap();
    let bg_ledger = namadan_ledger.background();

    let ledger_addr = get_actor_rpc(&test, &SOLE_VALIDATOR);
    let tx_args = vec![
        "add-erc20-transfer",
        "--address",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--amount",
        "100",
        "--erc20",
        &wnam_address,
        "--ethereum-address",
        RECEIVER,
        "--gas-amount",
        "10",
        "--gas-payer",
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
    )
    .unwrap();
    namadac_tx.exp_string(TX_ACCEPTED).unwrap();
    namadac_tx.exp_string(TX_APPLIED_SUCCESS).unwrap();
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
    )
    .unwrap();
    // get the returned hash of the transfer.
    let regex =
        expectrl::Regex(r#""bridge_pool_contents":(?s).*(?-s)"[0-9A-F]+":"#);
    let mut hash = String::from_utf8(
        namadar
            .session
            .expect(regex)
            .unwrap()
            .get(0)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
    .split_ascii_whitespace()
    .last()
    .unwrap()
    .to_string();
    hash.remove(0);
    hash.truncate(hash.len() - 2);

    // get the randomly generated address for Bertha.
    let regex = expectrl::Regex(r#""sender": "atest[0-9a-z]+","#);
    let mut berthas_addr = String::from_utf8(
        namadar
            .session
            .expect(regex)
            .unwrap()
            .get(0)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
    .split_ascii_whitespace()
    .last()
    .unwrap()
    .trim()
    .to_string();
    berthas_addr.remove(0);
    berthas_addr.pop();
    berthas_addr.pop();
    let berthas_addr = Address::from_str(&berthas_addr).unwrap();

    let relayer_address = berthas_addr.to_string();
    let proof_args = vec![
        "ethereum-bridge-pool",
        "construct-proof",
        "--hash-list",
        &hash,
        "--ledger-address",
        &ledger_addr,
        "--relayer",
        &relayer_address,
    ];
    let mut namadar =
        run!(test, Bin::Relayer, proof_args, Some(QUERY_TIMEOUT_SECONDS),)
            .unwrap();
    namadar.exp_string(r#"{"hashes":["#).unwrap();

    let mut client = EventsEndpointClient::default();

    let transfers = EthereumEvent::TransfersToEthereum {
        nonce: 0.into(),
        transfers: vec![TransferToEthereum {
            amount: Amount::native_whole(100),
            asset: EthAddress::from_str(&wnam_address).expect("Test failed"),
            receiver: EthAddress::from_str(RECEIVER).expect("Test failed"),
            gas_amount: Amount::native_whole(10),
            sender: berthas_addr.clone(),
            gas_payer: berthas_addr.clone(),
        }],
        valid_transfers_map: vec![true],
        relayer: berthas_addr,
    };

    client.send(&transfers).await.unwrap();
    let mut ledger = bg_ledger.foreground();
    ledger
        .exp_string(
            "Applying state updates derived from Ethereum events found in \
             protocol transaction",
        )
        .unwrap();
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
    )
    .unwrap();
    namadar.exp_string("Bridge pool is empty.").unwrap();
}

/// Tests transfers of wNAM ERC20s from Ethereum are treated differently to
/// other ERC20 transfers.
#[tokio::test]
async fn test_wnam_transfer() -> Result<()> {
    let ethereum_bridge_params = EthereumBridgeParams {
        eth_start_height: Default::default(),
        min_confirmations: MinimumConfirmations::from(unsafe {
            // SAFETY: The only way the API contract of `NonZeroU64` can
            // be violated is if we construct values
            // of this type using 0 as argument.
            NonZeroU64::new_unchecked(10)
        }),
        contracts: Contracts {
            native_erc20: wnam(),
            bridge: UpgradeableContract {
                address: EthAddress([2; 20]),
                version: ContractVersion::default(),
            },
            governance: UpgradeableContract {
                address: EthAddress([3; 20]),
                version: ContractVersion::default(),
            },
        },
    };
    // TODO: for a more realistic e2e test, the bridge shouldn't be
    // initialized with a NAM balance - rather we should establish a balance
    // there by making a proper `TransferToEthereum` of NAM
    const BRIDGE_INITIAL_NAM_BALANCE: u64 = 100;

    let mut native_token_address = None;
    // use a network-config.toml with eth bridge parameters in it
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params =
                Some(ethereum_bridge_params.clone());
            let native_token = genesis.token.get_mut("NAM").unwrap();
            native_token_address =
                Some(native_token.address.as_ref().unwrap().clone());
            native_token.balances.as_mut().unwrap().insert(
                BRIDGE_ADDRESS.to_string(),
                BRIDGE_INITIAL_NAM_BALANCE.into(),
            );
            genesis
        },
        None,
    )?;
    let native_token_address = Address::decode(native_token_address.unwrap())?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::SelfHostedEndpoint,
        Some(DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR),
    );
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;

    ledger.exp_string(LEDGER_STARTED)?;
    ledger.exp_string(VALIDATOR_NODE)?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    let bg_ledger = ledger.background();

    const WNAM_TRANSFER_AMOUNT_MICROS: u64 = 10_000_000;
    let wnam_transfer = TransferToNamada {
        amount: token::Amount::from(WNAM_TRANSFER_AMOUNT_MICROS),
        asset: ethereum_bridge_params.contracts.native_erc20,
        receiver: address::testing::established_address_1(),
    };
    let transfers = EthereumEvent::TransfersToNamada {
        nonce: 0.into(),
        transfers: vec![wnam_transfer.clone()],
        valid_transfers_map: vec![true],
    };

    let mut client = EventsEndpointClient::default();
    client.send(&transfers).await?;

    let mut ledger = bg_ledger.foreground();
    ledger.exp_string("Redeemed native token for wrapped ERC20 token")?;
    let _bg_ledger = ledger.background();

    // check NAM balance of receiver and bridge
    let receiver_balance = find_balance(
        &test,
        Who::Validator(0),
        &native_token_address,
        &wnam_transfer.receiver,
    )?;
    assert_eq!(receiver_balance, wnam_transfer.amount);

    let bridge_balance = find_balance(
        &test,
        Who::Validator(0),
        &native_token_address,
        &BRIDGE_ADDRESS,
    )?;
    assert_eq!(
        bridge_balance,
        token::Amount::from(BRIDGE_INITIAL_NAM_BALANCE * 1_000_000)
            - wnam_transfer.amount
    );

    Ok(())
}

/// Tests that the ledger configures its Ethereum oracle with values from
/// storage, if the Ethereum bridge has been bootstrapped for the Namada chain.
#[test]
fn test_configure_oracle_from_storage() -> Result<()> {
    let ethereum_bridge_params = EthereumBridgeParams {
        eth_start_height: Default::default(),
        min_confirmations: MinimumConfirmations::from(unsafe {
            // SAFETY: The only way the API contract of `NonZeroU64` can
            // be violated is if we construct values
            // of this type using 0 as argument.
            NonZeroU64::new_unchecked(10)
        }),
        contracts: Contracts {
            native_erc20: EthAddress([1; 20]),
            bridge: UpgradeableContract {
                address: EthAddress([2; 20]),
                version: ContractVersion::default(),
            },
            governance: UpgradeableContract {
                address: EthAddress([3; 20]),
                version: ContractVersion::default(),
            },
        },
    };

    // use a network-config.toml with eth bridge parameters in it
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params =
                Some(ethereum_bridge_params.clone());
            genesis
        },
        None,
    )?;

    // start the ledger with the real oracle and wait for a block to be
    // committed
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::RemoteEndpoint,
        None,
    );
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;

    ledger.exp_string(LEDGER_STARTED)?;
    ledger.exp_string(VALIDATOR_NODE)?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    // check that the oracle has been configured with the values from storage
    let initial_config = oracle::config::Config {
        min_confirmations: ethereum_bridge_params.min_confirmations.into(),
        bridge_contract: ethereum_bridge_params.contracts.bridge.address,
        governance_contract: ethereum_bridge_params
            .contracts
            .governance
            .address,
        start_block: 0.into(),
    };
    ledger.exp_string(&format!(
        "Oracle received initial configuration - {:?}",
        &initial_config
    ))?;
    Ok(())
}

/// Test we can transfer some DAI to an implicit address on Namada.
#[tokio::test]
async fn test_dai_transfer_implicit() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let transfer_amount = token::Amount::from(10_000_000);
    // [`ALBERT`] is a pre-existing implicit address in our wallet
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, transfer_amount);

    Ok(())
}

/// Test we can transfer some DAI to an established address on Namada.
#[tokio::test]
async fn test_dai_transfer_established() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    // create an established account that Albert controls
    let established_alias = "albert-established";
    let rpc_address = get_actor_rpc(&test, Who::Validator(0));
    init_established_account(
        &test,
        &rpc_address,
        ALBERT,
        ALBERT_KEY,
        established_alias,
    )?;
    let established_addr = find_address(&test, established_alias)?;

    let transfer_amount = token::Amount::from(10_000_000);

    let dai_transfer = TransferToNamada {
        amount: transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: established_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &established_addr,
    )?;
    assert_eq!(established_wdai_balance, transfer_amount);

    Ok(())
}

/// Test attempting to transfer some wDAI from an implicit address on Namada is
/// not authorized if the transaction is not signed by the key that controls the
/// implicit address.
#[tokio::test]
async fn test_wdai_transfer_implicit_unauthorized() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    let bertha_addr = find_address(&test, BERTHA)?;

    // attempt a transfer from Albert to Bertha that should fail, as it's not
    // signed with Albert's key
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr.to_string(),
        &bertha_addr.to_string(),
        &bertha_addr.to_string(),
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into()),
    )?;
    cmd.exp_string(TX_REJECTED)?;
    cmd.assert_success();

    // check balances are unchanged after an unsuccessful transfer
    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    Ok(())
}

/// Test attempting to transfer some wDAI from an implicit address on Namada is
/// not authorized if the transaction is not signed by the key that controls the
/// implicit address.
#[tokio::test]
async fn test_wdai_transfer_established_unauthorized() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    // create an established account that Albert controls
    let albert_established_alias = "albert-established";
    let rpc_address = get_actor_rpc(&test, Who::Validator(0));
    init_established_account(
        &test,
        &rpc_address,
        ALBERT,
        ALBERT_KEY,
        albert_established_alias,
    )?;
    let albert_established_addr =
        find_address(&test, albert_established_alias)?;

    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_established_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    let bertha_addr = find_address(&test, BERTHA)?;

    // attempt a transfer from Albert to Bertha that should fail, as it's not
    // signed with Albert's key
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr.to_string(),
        &bertha_addr.to_string(),
        &bertha_addr.to_string(),
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into()),
    )?;
    cmd.exp_string(TX_REJECTED)?;
    cmd.assert_success();

    // check balances are unchanged after an unsuccessful transfer
    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    Ok(())
}

/// Test transferring some wDAI from an implicit address on Namada to another
/// implicit address of Namada.
#[tokio::test]
async fn test_wdai_transfer_implicit_to_implicit() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    // attempt a transfer from Albert to Bertha that should succeed, as it's
    // signed with Albert's key
    let bertha_addr = find_address(&test, BERTHA)?;
    let second_transfer_amount =
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into());
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr.to_string(),
        &bertha_addr.to_string(),
        &albert_addr.to_string(),
        second_transfer_amount,
    )?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(
        albert_wdai_balance,
        initial_transfer_amount - second_transfer_amount.amount
    );

    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_addr,
    )?;
    assert_eq!(bertha_wdai_balance, second_transfer_amount.amount);

    Ok(())
}

#[tokio::test]
async fn test_wdai_transfer_implicit_to_established() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    // create an established account that Bertha controls
    let bertha_established_alias = "bertha-established";
    let rpc_address = get_actor_rpc(&test, Who::Validator(0));
    init_established_account(
        &test,
        &rpc_address,
        BERTHA,
        BERTHA_KEY,
        bertha_established_alias,
    )?;
    let bertha_established_addr =
        find_address(&test, bertha_established_alias)?;

    // attempt a transfer from Albert to Bertha that should succeed, as it's
    // signed with Albert's key
    let second_transfer_amount =
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into());
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr.to_string(),
        &bertha_established_addr.to_string(),
        &albert_addr.to_string(),
        second_transfer_amount,
    )?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(
        albert_wdai_balance,
        initial_transfer_amount - second_transfer_amount.amount
    );

    let bertha_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_established_addr,
    )?;
    assert_eq!(
        bertha_established_wdai_balance,
        second_transfer_amount.amount
    );

    Ok(())
}

#[tokio::test]
async fn test_wdai_transfer_established_to_implicit() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    // create an established account that Albert controls
    let albert_established_alias = "albert-established";
    let rpc_address = get_actor_rpc(&test, Who::Validator(0));
    init_established_account(
        &test,
        &rpc_address,
        ALBERT,
        ALBERT_KEY,
        albert_established_alias,
    )?;
    let albert_established_addr =
        find_address(&test, albert_established_alias)?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_established_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(albert_established_wdai_balance, initial_transfer_amount);

    let bertha_addr = find_address(&test, BERTHA)?;

    // attempt a transfer from Albert to Bertha that should succeed, as it's
    // signed with Albert's key
    let second_transfer_amount =
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into());
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr.to_string(),
        &bertha_addr.to_string(),
        &albert_established_addr.to_string(),
        second_transfer_amount,
    )?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();

    let albert_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(
        albert_established_wdai_balance,
        initial_transfer_amount - second_transfer_amount.amount
    );

    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_addr,
    )?;
    assert_eq!(bertha_wdai_balance, second_transfer_amount.amount);

    // TODO: invalid transfer

    Ok(())
}

#[tokio::test]
async fn test_wdai_transfer_established_to_established() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    // create an established account that Albert controls
    let albert_established_alias = "albert-established";
    let rpc_address = get_actor_rpc(&test, Who::Validator(0));
    init_established_account(
        &test,
        &rpc_address,
        ALBERT,
        ALBERT_KEY,
        albert_established_alias,
    )?;
    let albert_established_addr =
        find_address(&test, albert_established_alias)?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_established_addr.to_owned(),
    };
    let _bg_ledger =
        send_transfer_to_namada_event(bg_ledger, dai_transfer, 0.into())
            .await?;

    let albert_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(albert_established_wdai_balance, initial_transfer_amount);

    // create an established account that Bertha controls
    let bertha_established_alias = "bertha-established";
    init_established_account(
        &test,
        &rpc_address,
        BERTHA,
        BERTHA_KEY,
        bertha_established_alias,
    )?;
    let bertha_established_addr =
        find_address(&test, bertha_established_alias)?;

    // attempt a transfer from Albert to Bertha that should succeed, as it's
    // signed with Albert's key
    let second_transfer_amount =
        &token::DenominatedAmount::new(token::Amount::from(10_000), 0u8.into());
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr.to_string(),
        &bertha_established_addr.to_string(),
        &albert_established_addr.to_string(),
        second_transfer_amount,
    )?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();

    let albert_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_established_addr,
    )?;
    assert_eq!(
        albert_established_wdai_balance,
        initial_transfer_amount - second_transfer_amount.amount
    );

    let bertha_established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_established_addr,
    )?;
    assert_eq!(
        bertha_established_wdai_balance,
        second_transfer_amount.amount
    );

    // TODO: invalid transfer

    Ok(())
}
