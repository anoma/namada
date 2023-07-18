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

use core::convert::TryFrom;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashMap;

use color_eyre::eyre::Result;
use eyre::eyre;
use namada::ibc::applications::transfer::VERSION as ICS20_VERSION;
use namada::ibc::clients::ics07_tendermint::client_state::{
    AllowUpdate, ClientState as TmClientState,
};
use namada::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use namada::ibc::clients::ics07_tendermint::header::Header as IbcTmHeader;
use namada::ibc::clients::ics07_tendermint::trust_threshold::TrustThreshold;
use namada::ibc::core::ics02_client::client_state::ClientState;
use namada::ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use namada::ibc::core::ics02_client::msgs::update_client::MsgUpdateClient;
use namada::ibc::core::ics03_connection::connection::Counterparty as ConnCounterparty;
use namada::ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use namada::ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use namada::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use namada::ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use namada::ibc::core::ics03_connection::version::Version as ConnVersion;
use namada::ibc::core::ics04_channel::channel::Order as ChanOrder;
use namada::ibc::core::ics04_channel::msgs::{
    MsgAcknowledgement, MsgChannelOpenAck, MsgChannelOpenConfirm,
    MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket, MsgTimeout,
};
use namada::ibc::core::ics04_channel::packet::Packet;
use namada::ibc::core::ics04_channel::timeout::TimeoutHeight;
use namada::ibc::core::ics04_channel::Version as ChanVersion;
use namada::ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes,
};
use namada::ibc::core::ics23_commitment::merkle::MerkleProof;
use namada::ibc::core::ics24_host::identifier::{
    ChainId, ChannelId, ClientId, ConnectionId, PortId,
};
use namada::ibc::core::Msg;
use namada::ibc::{Height, Signer};
use namada::ibc_proto::google::protobuf::Any;
use namada::ledger::events::EventType;
use namada::ledger::ibc::storage::*;
use namada::ledger::parameters::{storage as param_storage, EpochDuration};
use namada::ledger::pos::{self, PosParams};
use namada::ledger::queries::RPC;
use namada::ledger::storage::ics23_specs::ibc_proof_specs;
use namada::ledger::storage::traits::Sha256Hasher;
use namada::tendermint::abci::Event as AbciEvent;
use namada::tendermint::block::Height as TmHeight;
use namada::types::address::{Address, InternalAddress};
use namada::types::key::PublicKey;
use namada::types::storage::{BlockHeight, Key};
use namada::types::token::Amount;
use namada_apps::client::rpc::{
    query_storage_value, query_storage_value_bytes,
};
use namada_apps::client::utils::id_from_pk;
use namada_apps::config::ethereum_bridge;
use namada_apps::config::genesis::genesis_config::GenesisConfig;
use namada_apps::facade::tendermint::block::Header as TmHeader;
use namada_apps::facade::tendermint::merkle::proof::Proof as TmProof;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_apps::facade::tendermint_rpc::{Client, HttpClient, Url};
use prost::Message;
use setup::constants::*;
use tendermint_light_client::components::io::{Io, ProdIo as TmLightClientIo};

use super::setup::set_ethereum_bridge_mode;
use crate::e2e::helpers::{find_address, get_actor_rpc, get_validator_pk};
use crate::e2e::setup::{self, sleep, Bin, NamadaCmd, Test, Who};
use crate::{run, run_as};

#[test]
fn run_ledger_ibc() -> Result<()> {
    let (test_a, test_b) = setup_two_single_node_nets()?;
    set_ethereum_bridge_mode(
        &test_a,
        &test_a.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test_b,
        &test_b.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // Run Chain A
    let mut ledger_a = run_as!(
        test_a,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run"],
        Some(40)
    )?;
    ledger_a.exp_string("Namada ledger node started")?;
    // Run Chain B
    let mut ledger_b = run_as!(
        test_b,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run"],
        Some(40)
    )?;
    ledger_b.exp_string("Namada ledger node started")?;
    ledger_a.exp_string("This node is a validator")?;
    ledger_b.exp_string("This node is a validator")?;

    // Wait for a first block
    ledger_a.exp_string("Committed block hash")?;
    ledger_b.exp_string("Committed block hash")?;

    let _bg_ledger_a = ledger_a.background();
    let _bg_ledger_b = ledger_b.background();

    sleep(5);

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

    // Transfer 50000 received over IBC on Chain B
    transfer_received_token(&port_id_b, &channel_id_b, &test_b)?;
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

    // Skip tests for closing a channel and timeout_on_close since the transfer
    // channel cannot be closed

    Ok(())
}

fn setup_two_single_node_nets() -> Result<(Test, Test)> {
    // epoch per 100 seconds
    let update_genesis = |mut genesis: GenesisConfig| {
        genesis.parameters.epochs_per_year = 315_360;
        genesis
    };
    let update_genesis_b = |mut genesis: GenesisConfig| {
        genesis.parameters.epochs_per_year = 315_360;
        setup::set_validators(1, genesis, |_| setup::ANOTHER_CHAIN_PORT_OFFSET)
    };
    Ok((
        setup::network(update_genesis, None)?,
        setup::network(update_genesis_b, None)?,
    ))
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
    let height_a = submit_ibc_tx(test_a, message, ALBERT)?;

    let height = query_height(test_a)?;
    let client_state = make_client_state(test_a, height);
    let height = client_state.latest_height();
    let message = MsgCreateClient {
        client_state: client_state.into(),
        consensus_state: make_consensus_state(test_a, height)?.into(),
        signer: signer(),
    };
    let height_b = submit_ibc_tx(test_b, message, ALBERT)?;

    let events = get_events(test_a, height_a)?;
    let client_id_a = get_client_id_from_events(&events)
        .ok_or(eyre!("Transaction failed"))?;
    let events = get_events(test_b, height_b)?;
    let client_id_b = get_client_id_from_events(&events)
        .ok_or(eyre!("Transaction failed"))?;

    // `client_id_a` represents the ID of the B's client on Chain A
    Ok((client_id_a, client_id_b))
}

fn make_client_state(test: &Test, height: Height) -> TmClientState {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();

    let key = pos::params_key();
    let pos_params = test
        .async_runtime()
        .block_on(query_storage_value::<HttpClient, PosParams>(&client, &key))
        .unwrap();
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

    TmClientState::new(
        chain_id,
        TrustThreshold::default(),
        Duration::from_secs(trusting_period),
        Duration::from_secs(unbonding_period),
        max_clock_drift,
        height,
        ibc_proof_specs::<Sha256Hasher>().into(),
        vec![],
        AllowUpdate {
            after_expiry: true,
            after_misbehaviour: true,
        },
    )
    .unwrap()
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
    let key = client_state_key(&target_client_id.as_str().parse().unwrap());
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
        header: header.into(),
        client_id: client_id.clone(),
        signer: signer(),
    };
    submit_ibc_tx(target_test, message, ALBERT)?;

    check_ibc_update_query(
        target_test,
        client_id,
        BlockHeight(target_height.revision_height()),
    )?;
    Ok(())
}

fn make_light_client_io(test: &Test) -> TmLightClientIo {
    let addr = format!("http://{}", get_actor_rpc(test, &Who::Validator(0)));
    let rpc_addr = Url::from_str(&addr).unwrap();
    let rpc_client = HttpClient::new(rpc_addr).unwrap();
    let rpc_timeout = Duration::new(10, 0);

    let pk = get_validator_pk(test, &Who::Validator(0)).unwrap();
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
        version: Some(ConnVersion::default()),
        delay_period: Duration::new(1, 0),
        signer: "test_a".to_string().into(),
    };
    // OpenInitConnection on Chain A
    let height = submit_ibc_tx(test_a, msg, ALBERT)?;
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
    let msg = make_msg_conn_open_try(
        client_id_b.clone(),
        client_state,
        counterparty,
        conn_proof,
        client_state_proof,
        consensus_proof,
        height_a,
    );
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // OpenTryConnection on Chain B
    let height = submit_ibc_tx(test_b, msg, ALBERT)?;
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
        version: ConnVersion::default(),
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // OpenAckConnection on Chain A
    submit_ibc_tx(test_a, msg, ALBERT)?;

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
    submit_ibc_tx(test_b, msg, ALBERT)?;

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
    let key = connection_key(&conn_id.as_str().parse().unwrap());
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
    let height = submit_ibc_tx(test_a, msg, ALBERT)?;

    let events = get_events(test_a, height)?;
    let channel_id_a = get_channel_id_from_events(&events)
        .ok_or(eyre!("Transaction failed"))?;

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
    let height = submit_ibc_tx(test_b, msg, ALBERT)?;

    let events = get_events(test_a, height)?;
    let channel_id_b = get_channel_id_from_events(&events)
        .ok_or(eyre!("Transaction failed"))?;

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
    submit_ibc_tx(test_a, msg, ALBERT)?;

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
    submit_ibc_tx(test_b, msg, ALBERT)?;

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
    let key = client_state_key(&client_id.as_str().parse().unwrap());
    let (value, tm_proof) =
        query_value_with_proof(test, &key, Some(target_height))?;
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
    let key =
        consensus_state_key(&client_id.as_str().parse().unwrap(), ibc_height);
    let (_, tm_proof) =
        query_value_with_proof(test, &key, Some(target_height))?;
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
    let receiver = find_address(test_b, BERTHA)?;
    let height = transfer(
        test_a,
        ALBERT,
        &receiver,
        NAM,
        &Amount::native_whole(100000),
        port_id_a,
        channel_id_a,
        None,
    )?;
    let events = get_events(test_a, height)?;
    let packet =
        get_packet_from_events(&events).ok_or(eyre!("Transaction failed"))?;
    check_ibc_packet_query(test_a, &"send_packet".parse().unwrap(), &packet)?;

    let height_a = query_height(test_a)?;
    let proof_commitment_on_a =
        get_commitment_proof(test_a, &packet, height_a)?;
    let msg = MsgRecvPacket {
        packet,
        proof_commitment_on_a,
        proof_height_on_a: height_a,
        signer: signer(),
    };
    // Update the client state of Chain A on Chain B
    update_client_with_height(test_a, test_b, client_id_b, height_a)?;
    // Receive the token on Chain B
    let height = submit_ibc_tx(test_b, msg, ALBERT)?;
    let events = get_events(test_b, height)?;
    let packet =
        get_packet_from_events(&events).ok_or(eyre!("Transaction failed"))?;
    let ack =
        get_ack_from_events(&events).ok_or(eyre!("Transaction failed"))?;
    check_ibc_packet_query(
        test_b,
        &"write_acknowledgement".parse().unwrap(),
        &packet,
    )?;

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
    submit_ibc_tx(test_a, msg, ALBERT)?;

    Ok(())
}

fn transfer_received_token(
    port_id: &PortId,
    channel_id: &ChannelId,
    test: &Test,
) -> Result<()> {
    let nam = find_address(test, NAM)?;
    // token received via the port and channel
    let denom = format!("{port_id}/{channel_id}/{nam}");
    let ibc_token = ibc_token(denom).to_string();

    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let amount = Amount::native_whole(50000).to_string_native();
    let tx_args = [
        "transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        &ibc_token,
        "--amount",
        &amount,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
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
    let nam = find_address(test_b, NAM)?.to_string();
    let receiver = find_address(test_a, ALBERT)?;

    // Chain A was the source for the sent token
    let denom_raw = format!("{}/{}/{}", port_id_b, channel_id_b, nam);
    let ibc_token = ibc_token(denom_raw).to_string();
    // Send a token from Chain B
    let height = transfer(
        test_b,
        BERTHA,
        &receiver,
        ibc_token,
        &Amount::native_whole(50000),
        port_id_b,
        channel_id_b,
        None,
    )?;
    let events = get_events(test_b, height)?;
    let packet =
        get_packet_from_events(&events).ok_or(eyre!("Transaction failed"))?;

    let height_b = query_height(test_b)?;
    let proof = get_commitment_proof(test_b, &packet, height_b)?;
    let msg = MsgRecvPacket {
        packet,
        proof_commitment_on_a: proof,
        proof_height_on_a: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // Receive the token on Chain A
    let height = submit_ibc_tx(test_a, msg, ALBERT)?;
    let events = get_events(test_a, height)?;
    let packet =
        get_packet_from_events(&events).ok_or(eyre!("Transaction failed"))?;
    let ack =
        get_ack_from_events(&events).ok_or(eyre!("Transaction failed"))?;

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
    submit_ibc_tx(test_b, msg, ALBERT)?;

    Ok(())
}

fn transfer_timeout(
    test_a: &Test,
    test_b: &Test,
    client_id_a: &ClientId,
    port_id_a: &PortId,
    channel_id_a: &ChannelId,
) -> Result<()> {
    let receiver = find_address(test_b, BERTHA)?;

    // Send a token from Chain A
    let height = transfer(
        test_a,
        ALBERT,
        &receiver,
        NAM,
        &Amount::native_whole(100000),
        port_id_a,
        channel_id_a,
        Some(Duration::new(5, 0)),
    )?;
    let events = get_events(test_a, height)?;
    let packet =
        get_packet_from_events(&events).ok_or(eyre!("Transaction failed"))?;

    // wait for the timeout
    sleep(5);

    let height_b = query_height(test_b)?;
    let proof_unreceived_on_b =
        get_receipt_absence_proof(test_b, &packet, height_b)?;
    let msg = MsgTimeout {
        packet,
        next_seq_recv_on_b: 0.into(), // not used
        proof_unreceived_on_b,
        proof_height_on_b: height_b,
        signer: signer(),
    };
    // Update the client state of Chain B on Chain A
    update_client_with_height(test_b, test_a, client_id_a, height_b)?;
    // Timeout on Chain A
    submit_ibc_tx(test_a, msg, ALBERT)?;

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
        &packet.port_id_on_a.as_str().parse().unwrap(),
        &packet.chan_id_on_a.as_str().parse().unwrap(),
        u64::from(packet.seq_on_a).into(),
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
    let key = ack_key(
        &packet.port_id_on_b.as_str().parse().unwrap(),
        &packet.chan_id_on_b.as_str().parse().unwrap(),
        u64::from(packet.seq_on_a).into(),
    );
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
        &packet.port_id_on_b.as_str().parse().unwrap(),
        &packet.chan_id_on_b.as_str().parse().unwrap(),
        u64::from(packet.seq_on_a).into(),
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
    message: impl Msg + std::fmt::Debug,
    signer: &str,
) -> Result<u32> {
    let data_path = test.test_dir.path().join("tx.data");
    let data = make_ibc_data(message);
    std::fs::write(&data_path, data).expect("writing data failed");

    let data_path = data_path.to_string_lossy();
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let mut client = run!(
        test,
        Bin::Client,
        [
            "tx",
            "--code-path",
            TX_IBC_WASM,
            "--data-path",
            &data_path,
            "--signer",
            signer,
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
            "--node",
            &rpc
        ],
        Some(40)
    )?;
    client.exp_string("Transaction applied")?;
    check_tx_height(test, &mut client)
}

#[allow(clippy::too_many_arguments)]
fn transfer(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: &Address,
    token: impl AsRef<str>,
    amount: &Amount,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout_sec: Option<Duration>,
) -> Result<u32> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));

    let receiver = receiver.to_string();
    let amount = amount.to_string_native();
    let channel_id = channel_id.to_string();
    let port_id = port_id.to_string();
    let mut tx_args = vec![
        "ibc-transfer",
        "--source",
        sender.as_ref(),
        "--receiver",
        &receiver,
        "--signer",
        sender.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--channel-id",
        &channel_id,
        "--port-id",
        &port_id,
        "--node",
        &rpc,
    ];

    let timeout = timeout_sec.unwrap_or_default().as_secs().to_string();
    if timeout_sec.is_some() {
        tx_args.push("--timeout-sec-offset");
        tx_args.push(&timeout);
    }

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied")?;
    check_tx_height(test, &mut client)
}

fn check_tx_height(test: &Test, client: &mut NamadaCmd) -> Result<u32> {
    let (unread, matched) = client.exp_regex("\"height\": .*,")?;
    let height_str = matched
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1
        .replace(['"', ','], "");
    let height = height_str.parse().unwrap();

    let (_unread, matched) = client.exp_regex("\"code\": .*,")?;
    let code = matched
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1
        .replace(['"', ','], "");
    if code != "0" {
        return Err(eyre!("The IBC transaction failed: unread {}", unread));
    }

    // wait for the next block to use the app hash
    while height as u64 + 1 > query_height(test)?.revision_height() {
        sleep(1);
    }

    Ok(height)
}

fn make_ibc_data(message: impl Msg) -> Vec<u8> {
    let msg = message.to_any();
    let mut tx_data = vec![];
    prost::Message::encode(&msg, &mut tx_data)
        .expect("encoding IBC message shouldn't fail");
    tx_data
}

fn query_height(test: &Test) -> Result<Height> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();

    let status = test
        .async_runtime()
        .block_on(client.status())
        .map_err(|e| eyre!("Getting the status failed: {}", e))?;

    Ok(Height::new(0, status.sync_info.latest_block_height.into()).unwrap())
}

fn query_header(test: &Test, height: Height) -> Result<TmHeader> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();
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
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();
    match test.async_runtime().block_on(RPC.shell().ibc_client_update(
        &client,
        &client_id.as_str().parse().unwrap(),
        &consensus_height,
    )) {
        Ok(Some(event)) => {
            println!("Found the update event: {:?}", event);
            Ok(())
        }
        Ok(None) => Err(eyre!("No update event for the client {}", client_id)),
        Err(e) => Err(eyre!("IBC update event query failed: {}", e)),
    }
}

fn check_ibc_packet_query(
    test: &Test,
    event_type: &EventType,
    packet: &Packet,
) -> Result<()> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();
    match test.async_runtime().block_on(RPC.shell().ibc_packet(
        &client,
        event_type,
        &packet.port_id_on_a.as_str().parse().unwrap(),
        &packet.chan_id_on_a.as_str().parse().unwrap(),
        &packet.port_id_on_b.as_str().parse().unwrap(),
        &packet.chan_id_on_b.as_str().parse().unwrap(),
        &packet.seq_on_a.to_string().parse().unwrap(),
    )) {
        Ok(Some(event)) => {
            println!("Found the packet event: {:?}", event);
            Ok(())
        }
        Ok(None) => Err(eyre!("No packet event for the packet {}", packet)),
        Err(e) => Err(eyre!("IBC packet event query failed: {}", e)),
    }
}

fn query_value_with_proof(
    test: &Test,
    key: &Key,
    height: Option<Height>,
) -> Result<(Option<Vec<u8>>, TmProof)> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();
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
    use namada::ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
    use namada::ibc_proto::ics23::CommitmentProof;

    let mut proofs = Vec::new();

    for op in &tm_proof.ops {
        let mut parsed = CommitmentProof { proof: None };
        prost::Message::merge(&mut parsed, op.data.as_slice())
            .expect("merging CommitmentProof failed");
        proofs.push(parsed);
    }

    let merkle_proof = MerkleProof::from(RawMerkleProof { proofs });
    CommitmentProofBytes::try_from(merkle_proof).map_err(|e| {
        eyre!("Proof conversion to CommitmentProofBytes failed: {}", e)
    })
}

/// Check balances after IBC transfer
fn check_balances(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_a: &Test,
    test_b: &Test,
) -> Result<()> {
    let token = find_address(test_a, NAM)?;

    // Check the balances on Chain A
    let rpc_a = get_actor_rpc(test_a, &Who::Validator(0));
    let query_args = vec!["balance", "--token", NAM, "--node", &rpc_a];
    let mut client = run!(test_a, Bin::Client, query_args, Some(40))?;
    // Check the escrowed balance
    let expected = format!(
        ": 100000, owned by {}",
        Address::Internal(InternalAddress::Ibc)
    );
    client.exp_string(&expected)?;
    // Check the source balance
    let expected = ": 900000, owned by albert".to_string();
    client.exp_string(&expected)?;
    client.assert_success();

    // Check the balance on Chain B
    let denom = format!("{}/{}/{}", &dest_port_id, &dest_channel_id, &token,);
    let ibc_token = ibc_token(denom).to_string();
    let rpc_b = get_actor_rpc(test_b, &Who::Validator(0));
    let query_args = vec![
        "balance", "--owner", BERTHA, "--token", &ibc_token, "--node", &rpc_b,
    ];
    let expected = format!("{}: 100000", ibc_token);
    let mut client = run!(test_b, Bin::Client, query_args, Some(40))?;
    client.exp_string(&expected)?;
    client.assert_success();
    Ok(())
}

/// Check balances after non IBC transfer
fn check_balances_after_non_ibc(
    port_id: &PortId,
    channel_id: &ChannelId,
    test: &Test,
) -> Result<()> {
    // Check the balance on Chain B
    let token = find_address(test, NAM)?;
    let denom = format!("{}/{}/{}", port_id, channel_id, token);
    let ibc_token = ibc_token(denom).to_string();

    // Check the source
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let query_args = vec![
        "balance", "--owner", BERTHA, "--token", &ibc_token, "--node", &rpc,
    ];
    let expected = format!("{}: 50000", ibc_token);
    let mut client = run!(test, Bin::Client, query_args, Some(40))?;
    client.exp_string(&expected)?;
    client.assert_success();

    // Check the traget
    let query_args = vec![
        "balance", "--owner", ALBERT, "--token", &ibc_token, "--node", &rpc,
    ];
    let expected = format!("{}: 50000", ibc_token);
    let mut client = run!(test, Bin::Client, query_args, Some(40))?;
    client.exp_string(&expected)?;
    client.assert_success();

    Ok(())
}

/// Check balances after IBC transfer back
fn check_balances_after_back(
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
    test_a: &Test,
    test_b: &Test,
) -> Result<()> {
    let token = find_address(test_b, NAM)?;

    // Check the balances on Chain A
    let rpc_a = get_actor_rpc(test_a, &Who::Validator(0));
    let query_args = vec!["balance", "--token", NAM, "--node", &rpc_a];
    let mut client = run!(test_a, Bin::Client, query_args, Some(40))?;
    // Check the escrowed balance
    let expected = format!(
        ": 50000, owned by {}",
        Address::Internal(InternalAddress::Ibc)
    );
    client.exp_string(&expected)?;
    // Check the source balance
    let expected = ": 950000, owned by albert".to_string();
    client.exp_string(&expected)?;
    client.assert_success();

    // Check the balance on Chain B
    let denom = format!("{}/{}/{}", dest_port_id, dest_channel_id, &token,);
    let ibc_token = ibc_token(denom).to_string();
    let rpc_b = get_actor_rpc(test_b, &Who::Validator(0));
    let query_args = vec![
        "balance", "--owner", BERTHA, "--token", &ibc_token, "--node", &rpc_b,
    ];
    let expected = format!("{}: 0", ibc_token);
    let mut client = run!(test_b, Bin::Client, query_args, Some(40))?;
    client.exp_string(&expected)?;
    client.assert_success();
    Ok(())
}

fn signer() -> Signer {
    "signer".to_string().into()
}

/// Helper function to make the MsgConnectionOpenTry because it has a private
/// field
fn make_msg_conn_open_try(
    client_id: ClientId,
    client_state: TmClientState,
    counterparty: ConnCounterparty,
    conn_proof: CommitmentProofBytes,
    client_state_proof: CommitmentProofBytes,
    consensus_proof: CommitmentProofBytes,
    proofs_height: Height,
) -> MsgConnectionOpenTry {
    use namada::ibc_proto::ibc::core::connection::v1::MsgConnectionOpenTry as RawMsgConnectionOpenTry;

    let consensus_height = client_state.latest_height();
    #[allow(deprecated)]
    RawMsgConnectionOpenTry {
        client_id: client_id.as_str().to_string(),
        client_state: Some(client_state.into()),
        counterparty: Some(counterparty.into()),
        delay_period: 0,
        counterparty_versions: vec![ConnVersion::default().into()],
        proof_init: conn_proof.into(),
        proof_height: Some(proofs_height.into()),
        proof_client: client_state_proof.into(),
        proof_consensus: consensus_proof.into(),
        consensus_height: Some(consensus_height.into()),
        signer: "signer".to_string(),
        previous_connection_id: ConnectionId::default().to_string(),
    }
    .try_into()
    .expect("invalid message")
}

fn get_client_id_from_events(events: &Vec<AbciEvent>) -> Option<ClientId> {
    get_attribute_from_events(events, "client_id").map(|v| v.parse().unwrap())
}

fn get_connection_id_from_events(
    events: &Vec<AbciEvent>,
) -> Option<ConnectionId> {
    get_attribute_from_events(events, "connection_id")
        .map(|v| v.parse().unwrap())
}

fn get_channel_id_from_events(events: &Vec<AbciEvent>) -> Option<ChannelId> {
    get_attribute_from_events(events, "channel_id").map(|v| v.parse().unwrap())
}

fn get_ack_from_events(events: &Vec<AbciEvent>) -> Option<Vec<u8>> {
    get_attribute_from_events(events, "packet_ack")
        .map(|v| Vec::from(v.as_bytes()))
}

fn get_attribute_from_events(
    events: &Vec<AbciEvent>,
    key: &str,
) -> Option<String> {
    for event in events {
        let attributes = get_attributes_from_event(&event);
        if let Some(value) = attributes.get(key) {
            return Some(value.clone());
        }
    }
    None
}

fn get_packet_from_events(events: &Vec<AbciEvent>) -> Option<Packet> {
    for event in events {
        let attributes = get_attributes_from_event(event);
        if !attributes.contains_key("packet_src_port") {
            continue;
        }
        let mut packet = Packet::default();
        for (key, val) in attributes {
            match key.as_str() {
                "packet_src_port" => packet.port_id_on_a = val.parse().unwrap(),
                "packet_src_channel" => {
                    packet.chan_id_on_a = val.parse().unwrap()
                }
                "packet_dst_port" => packet.port_id_on_b = val.parse().unwrap(),
                "packet_dst_channel" => {
                    packet.chan_id_on_b = val.parse().unwrap()
                }
                "packet_timeout_height" => {
                    packet.timeout_height_on_b = match Height::from_str(&val) {
                        Ok(height) => TimeoutHeight::At(height),
                        Err(_) => TimeoutHeight::Never,
                    }
                }
                "packet_timeout_timestamp" => {
                    packet.timeout_timestamp_on_b = val.parse().unwrap()
                }
                "packet_sequence" => {
                    packet.seq_on_a = u64::from_str(&val).unwrap().into()
                }
                "packet_data" => packet.data = Vec::from(val.as_bytes()),
                _ => {}
            }
        }
        return Some(packet);
    }
    None
}

fn get_attributes_from_event(event: &AbciEvent) -> HashMap<String, String> {
    event
        .attributes
        .iter()
        .map(|tag| (tag.key.to_string(), tag.value.to_string()))
        .collect()
}

fn get_events(test: &Test, height: u32) -> Result<Vec<AbciEvent>> {
    let rpc = get_actor_rpc(test, &Who::Validator(0));
    let ledger_address = TendermintAddress::from_str(&rpc).unwrap();
    let client = HttpClient::new(ledger_address).unwrap();

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
