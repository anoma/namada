//! Helper functionality for use in tests to do with the Ethereum bridge.

use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use eyre::{eyre, Context, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request, StatusCode};
use namada_sdk::address::{wnam, Address};
use namada_sdk::ethereum_events::{
    EthAddress, EthereumEvent, TransferToNamada, Uint,
};
use namada_sdk::eth_bridge::{
    wrapped_erc20s, ContractVersion, Contracts, EthereumBridgeParams,
    MinimumConfirmations, UpgradeableContract,
};
use namada_sdk::token;
use namada_apps_lib::config::ethereum_bridge;

use crate::e2e::helpers::{
    get_actor_rpc, rpc_client_do, strip_trailing_newline,
};
use crate::e2e::setup::{
    self, set_ethereum_bridge_mode, Bin, NamadaBgCmd, NamadaCmd, Test, Who,
};
use crate::strings::{LEDGER_STARTED, VALIDATOR_NODE};
use crate::{run, run_as};

/// The default listen address for a self-hosted events endpoint.
pub const DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR: &str = "0.0.0.0:3030";

impl Default for EventsEndpointClient {
    fn default() -> Self {
        let ethereum_events_endpoint =
            format!("http://{DEFAULT_ETHEREUM_EVENTS_LISTEN_ADDR}/eth_events");
        Self::new(ethereum_events_endpoint)
    }
}

/// Simple client for submitting fake Ethereum events to a Namada node.
pub struct EventsEndpointClient {
    // The client used to send HTTP requests to the Namada node.
    http: Client<HttpConnector, Body>,
    // The URL to which Borsh-serialized Ethereum events should be HTTP POSTed. e.g. "http://0.0.0.0:3030/eth_events"
    events_endpoint: String,
}

impl EventsEndpointClient {
    pub fn new(events_endpoint: String) -> Self {
        Self {
            http: Client::new(),
            events_endpoint,
        }
    }

    /// Sends an Ethereum event to the Namada node. Returns `Ok` iff the event
    /// was successfully sent.
    pub async fn send(&mut self, event: &EthereumEvent) -> Result<()> {
        let event = event.serialize_to_vec()?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.events_endpoint)
            .header("content-type", "application/octet-stream")
            .body(Body::from(event))?;

        let resp = self
            .http
            .request(req)
            .await
            .wrap_err_with(|| "sending event")?;

        if resp.status() != StatusCode::OK {
            return Err(eyre!("unexpected response status: {}", resp.status()));
        }
        Ok(())
    }
}

/// Sets up the necessary environment for a test involving a single Namada
/// validator that is exposing an endpoint for submission of fake Ethereum
/// events.
pub fn setup_single_validator_test() -> Result<(Test, NamadaBgCmd)> {
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

    // use a network-config.toml with eth bridge parameters in it
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params =
                Some(ethereum_bridge_params.clone());
            genesis
        },
        None,
    )?;

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

    Ok((test, bg_ledger))
}

/// Sends a fake Ethereum event to a Namada node representing a transfer of
/// wrapped ERC20s.
pub async fn send_transfer_to_namada_event(
    bg_ledger: NamadaBgCmd,
    transfer: TransferToNamada,
    nonce: Uint,
) -> Result<NamadaBgCmd> {
    let transfers = EthereumEvent::TransfersToNamada {
        nonce,
        transfers: vec![transfer.clone()],
        valid_transfers_map: vec![true],
    };

    let mut client = EventsEndpointClient::default();
    client.send(&transfers).await?;

    // wait until the transfer is definitely processed
    let mut ledger = bg_ledger.foreground();
    let TransferToNamada {
        receiver, amount, ..
    } = transfer;
    ledger.exp_string(&format!(
        "Minted wrapped ERC20s - (receiver - {receiver}, amount - {})",
        amount.to_string_native()
    ))?;
    ledger.exp_string("Committed block hash")?;
    Ok(ledger.background())
}

/// Attempt to transfer some wrapped ERC20 from one Namada address to another.
/// This will fail if the keys for `signer` are not in the local wallet.
pub fn attempt_wrapped_erc20_transfer(
    test: &Test,
    node: Who,
    asset: &EthAddress,
    from: &str,
    to: &str,
    signer: &str,
    amount: &token::DenominatedAmount,
) -> Result<NamadaCmd> {
    let ledger_address = get_actor_rpc(test, node);

    let token = wrapped_erc20s::token(asset).to_string();

    let amount = amount.to_string();
    let transfer_args = vec![
        "transfer",
        "--token",
        &token,
        "--source",
        from,
        "--target",
        to,
        "--signing-keys",
        signer,
        "--amount",
        &amount,
        "--ledger-address",
        &ledger_address,
    ];
    run!(test, Bin::Client, transfer_args, Some(40))
}

/// Find the balance of specific wrapped ERC20 for an account. This function
/// will error if an account doesn't have an explicit balance (i.e. has never
/// been involved in a wrapped ERC20 transfer of any kind).
pub fn find_wrapped_erc20_balance(
    test: &Test,
    node: Who,
    asset: &EthAddress,
    owner: &Address,
) -> Result<token::Amount> {
    let ledger_address = get_actor_rpc(test, node);

    let token = wrapped_erc20s::token(asset);
    let balance_key = token::storage_key::balance_key(&token, owner);
    let mut bytes = run!(
        test,
        Bin::Client,
        &[
            "query-bytes",
            "--storage-key",
            &balance_key.to_string(),
            "--ledger-address",
            &ledger_address,
        ],
        Some(10)
    )?;
    let (_, matched) = bytes.exp_regex("Found data: 0x.*")?;
    let data_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1[2..]
        .to_string();
    let amount =
        token::Amount::try_from_slice(&HEXLOWER.decode(data_str.as_bytes())?)?;
    bytes.assert_success();
    Ok(amount)
}

/// Read the total supply of some wrapped ERC20 token in Namada.
pub async fn read_erc20_supply(
    ledger_addr: &str,
    asset: &EthAddress,
) -> Result<Option<token::Amount>> {
    rpc_client_do(ledger_addr, &(), |rpc, client, ()| async move {
        let amount = rpc
            .shell()
            .eth_bridge()
            .read_erc20_supply(&client, asset)
            .await?;
        Ok(amount)
    })
    .await
}
