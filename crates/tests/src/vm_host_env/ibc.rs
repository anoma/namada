use core::time::Duration;
use std::collections::HashMap;

use ibc_testkit::testapp::ibc::clients::mock::client_state::{
    client_type, MockClientState,
};
use ibc_testkit::testapp::ibc::clients::mock::consensus_state::MockConsensusState;
use ibc_testkit::testapp::ibc::clients::mock::header::MockHeader;
use namada::gas::TxGasMeter;
use namada::governance::parameters::GovernanceParameters;
use namada::ibc::apps::transfer::types::error::TokenTransferError;
use namada::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use namada::ibc::apps::transfer::types::packet::PacketData;
use namada::ibc::apps::transfer::types::{
    ack_success_b64, PrefixedCoin, VERSION,
};
use namada::ibc::core::channel::types::acknowledgement::{
    AcknowledgementStatus, StatusValue,
};
use namada::ibc::core::channel::types::channel::{
    ChannelEnd, Counterparty as ChanCounterparty, Order, State as ChanState,
};
use namada::ibc::core::channel::types::msgs::{
    MsgAcknowledgement, MsgChannelCloseConfirm, MsgChannelCloseInit,
    MsgChannelOpenAck, MsgChannelOpenConfirm, MsgChannelOpenInit,
    MsgChannelOpenTry, MsgRecvPacket, MsgTimeout, MsgTimeoutOnClose,
};
pub use namada::ibc::core::channel::types::packet::Packet;
use namada::ibc::core::channel::types::timeout::TimeoutHeight;
use namada::ibc::core::channel::types::Version as ChanVersion;
use namada::ibc::core::client::types::msgs::{
    MsgCreateClient, MsgUpdateClient, MsgUpgradeClient,
};
use namada::ibc::core::client::types::Height;
use namada::ibc::core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentProofBytes,
};
use namada::ibc::core::connection::types::msgs::{
    MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit,
    MsgConnectionOpenTry,
};
use namada::ibc::core::connection::types::version::Version as ConnVersion;
use namada::ibc::core::connection::types::{
    ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
};
pub use namada::ibc::core::host::types::identifiers::{
    ChannelId, ClientId, ConnectionId, PortId, Sequence,
};
use namada::ibc::primitives::proto::{Any, Protobuf};
use namada::ibc::primitives::Timestamp;
use namada::ledger::gas::VpGasMeter;
pub use namada::ledger::ibc::storage::{
    ack_key, channel_counter_key, channel_key, client_counter_key,
    client_state_key, client_update_height_key, client_update_timestamp_key,
    commitment_key, connection_counter_key, connection_key,
    consensus_state_key, ibc_token, next_sequence_ack_key,
    next_sequence_recv_key, next_sequence_send_key, port_key, receipt_key,
};
use namada::ledger::native_vp::ibc::{
    get_dummy_genesis_validator, get_dummy_header as tm_dummy_header, Ibc,
};
use namada::ledger::native_vp::multitoken::{
    Error as MultitokenVpError, MultitokenVp,
};
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::ledger::parameters::storage::{
    get_epoch_duration_storage_key, get_max_expected_time_per_block_key,
};
use namada::ledger::parameters::EpochDuration;
use namada::ledger::storage::mockdb::MockDB;
use namada::ledger::tx_env::TxEnv;
use namada::ledger::{ibc, pos};
use namada::proof_of_stake::OwnedPosParams;
use namada::state::Sha256Hasher;
use namada::tendermint::time::Time as TmTime;
use namada::token::{self, Amount, DenominatedAmount};
use namada::tx::Tx;
use namada::types::address::{self, Address, InternalAddress};
use namada::types::hash::Hash;
use namada::types::storage::{
    self, BlockHash, BlockHeight, Epoch, Key, TxIndex,
};
use namada::types::time::DurationSecs;
use namada::vm::{wasm, WasmCacheRwAccess};
use namada_test_utils::TestWasms;
use namada_tx_prelude::BorshSerializeExt;

use crate::tx::*;

const ADDRESS: Address = Address::Internal(InternalAddress::Ibc);
pub const ANY_DENOMINATION: u8 = 4;
const COMMITMENT_PREFIX: &[u8] = b"ibc";

pub struct TestIbcVp<'a> {
    pub ibc: Ibc<'a, MockDB, Sha256Hasher, WasmCacheRwAccess>,
}

impl<'a> TestIbcVp<'a> {
    pub fn validate(
        &self,
        tx_data: &Tx,
    ) -> std::result::Result<bool, namada::ledger::native_vp::ibc::Error> {
        self.ibc.validate_tx(
            tx_data,
            self.ibc.ctx.keys_changed,
            self.ibc.ctx.verifiers,
        )
    }
}

pub struct TestMultitokenVp<'a> {
    pub multitoken_vp:
        MultitokenVp<'a, MockDB, Sha256Hasher, WasmCacheRwAccess>,
}

impl<'a> TestMultitokenVp<'a> {
    pub fn validate(
        &self,
        tx: &Tx,
    ) -> std::result::Result<bool, MultitokenVpError> {
        self.multitoken_vp.validate_tx(
            tx,
            self.multitoken_vp.ctx.keys_changed,
            self.multitoken_vp.ctx.verifiers,
        )
    }
}

/// Validate an IBC transaction with IBC VP.
pub fn validate_ibc_vp_from_tx<'a>(
    tx_env: &'a TestTxEnv,
    tx: &'a Tx,
) -> std::result::Result<bool, namada::ledger::native_vp::ibc::Error> {
    let (verifiers, keys_changed) = tx_env
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&tx_env.verifiers);
    let addr = Address::Internal(InternalAddress::Ibc);
    if !verifiers.contains(&addr) {
        panic!(
            "IBC address {} isn't part of the tx verifiers set: {:#?}",
            addr, verifiers
        );
    }
    let (vp_wasm_cache, _vp_cache_dir) =
        wasm::compilation_cache::common::testing::cache();

    let ctx = Ctx::new(
        &ADDRESS,
        &tx_env.wl_storage.storage,
        &tx_env.wl_storage.write_log,
        tx,
        &TxIndex(0),
        VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
            1_000_000.into(),
        )),
        &keys_changed,
        &verifiers,
        vp_wasm_cache,
    );
    let ibc = Ibc { ctx };

    TestIbcVp { ibc }.validate(tx)
}

/// Validate the native token VP for the given address
pub fn validate_multitoken_vp_from_tx<'a>(
    tx_env: &'a TestTxEnv,
    tx: &'a Tx,
    target: &Key,
) -> std::result::Result<bool, MultitokenVpError> {
    let (verifiers, keys_changed) = tx_env
        .wl_storage
        .write_log
        .verifiers_and_changed_keys(&tx_env.verifiers);
    if !keys_changed.contains(target) {
        panic!(
            "The given target address {} isn't part of the tx verifiers set: \
             {:#?}",
            target, keys_changed,
        );
    }
    let (vp_wasm_cache, _vp_cache_dir) =
        wasm::compilation_cache::common::testing::cache();

    let ctx = Ctx::new(
        &ADDRESS,
        &tx_env.wl_storage.storage,
        &tx_env.wl_storage.write_log,
        tx,
        &TxIndex(0),
        VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
            1_000_000.into(),
        )),
        &keys_changed,
        &verifiers,
        vp_wasm_cache,
    );
    let multitoken_vp = MultitokenVp { ctx };

    TestMultitokenVp { multitoken_vp }.validate(tx)
}

/// Initialize the test storage. Requires initialized [`tx_host_env::ENV`].
pub fn init_storage() -> (Address, Address) {
    // wasm for init_account
    let code = TestWasms::VpAlwaysTrue.read_bytes();
    let code_hash = Hash::sha256(&code);

    tx_host_env::with(|env| {
        ibc::init_genesis_storage(&mut env.wl_storage);
        let gov_params = GovernanceParameters::default();
        gov_params.init_storage(&mut env.wl_storage).unwrap();
        pos::test_utils::test_init_genesis(
            &mut env.wl_storage,
            OwnedPosParams::default(),
            vec![get_dummy_genesis_validator()].into_iter(),
            Epoch(1),
        )
        .unwrap();
        // store wasm code
        let key = Key::wasm_code(&code_hash);
        env.wl_storage.storage.write(&key, code.clone()).unwrap();

        // block header to check timeout timestamp
        env.wl_storage
            .storage
            .set_header(tm_dummy_header())
            .unwrap();
        env.wl_storage
            .storage
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();
    });

    // initialize a token
    let token = tx_host_env::ctx().init_account(code_hash, &None).unwrap();
    let denom_key = token::storage_key::denom_key(&token);
    let token_denom = token::Denomination(ANY_DENOMINATION);
    // initialize an account
    let account = tx_host_env::ctx().init_account(code_hash, &None).unwrap();
    let key = token::storage_key::balance_key(&token, &account);
    let init_bal = Amount::from_uint(100, token_denom).unwrap();
    tx_host_env::with(|env| {
        env.wl_storage
            .storage
            .write(&denom_key, &token_denom.serialize_to_vec())
            .unwrap();
        env.wl_storage
            .storage
            .write(&key, &init_bal.serialize_to_vec())
            .unwrap();
    });

    // epoch duration
    let key = get_epoch_duration_storage_key();
    let epoch_duration = EpochDuration {
        min_num_of_blocks: 10,
        min_duration: DurationSecs(100),
    };
    let bytes = epoch_duration.serialize_to_vec();
    tx_host_env::with(|env| {
        env.wl_storage.storage.write(&key, &bytes).unwrap();
    });

    // max_expected_time_per_block
    let time = DurationSecs::from(Duration::new(60, 0));
    let key = get_max_expected_time_per_block_key();
    let bytes = namada::types::encode(&time);
    tx_host_env::with(|env| {
        env.wl_storage.storage.write(&key, &bytes).unwrap();
    });

    // commit the initialized token and account
    tx_host_env::with(|env| {
        env.wl_storage.commit_tx();
        env.wl_storage.commit_block().unwrap();

        // block header to check timeout timestamp
        env.wl_storage
            .storage
            .set_header(tm_dummy_header())
            .unwrap();
        env.wl_storage
            .storage
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();
    });

    (token, account)
}

pub fn client_id() -> ClientId {
    ClientId::new(client_type(), 0).expect("invalid client ID")
}

pub fn prepare_client() -> (ClientId, Any, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    let (client_state, consensus_state) = dummy_client();
    // client state
    let client_id = client_id();
    let key = client_state_key(&client_id);
    let bytes = Protobuf::<Any>::encode_vec(client_state);
    writes.insert(key, bytes);
    // consensus state
    let height = client_state.latest_height();
    let key = consensus_state_key(&client_id, height);
    let bytes = Protobuf::<Any>::encode_vec(consensus_state);
    writes.insert(key, bytes);
    // client update time
    let key = client_update_timestamp_key(&client_id);
    let time = tx_host_env::with(|env| {
        let header = env
            .wl_storage
            .storage
            .get_block_header(None)
            .unwrap()
            .0
            .unwrap();
        header.time
    });
    let bytes = TmTime::try_from(time).unwrap().encode_vec();
    writes.insert(key, bytes);
    // client update height
    let key = client_update_height_key(&client_id);
    let height = tx_host_env::with(|env| {
        let height = env.wl_storage.storage.get_block_height().0;
        Height::new(0, height.0).expect("invalid height")
    });
    let bytes = height.encode_vec();
    writes.insert(key, bytes);
    // client counter
    let key = client_counter_key();
    let bytes = 1_u64.to_be_bytes().to_vec();
    writes.insert(key, bytes);

    (client_id, client_state.into(), writes)
}

fn dummy_client() -> (MockClientState, MockConsensusState) {
    let height = Height::new(0, 1).unwrap();
    let header = MockHeader {
        height,
        // for a past block on the counterparty chain
        timestamp: (Timestamp::now() - Duration::from_secs(10)).unwrap(),
    };
    let client_state = MockClientState::new(header);
    let consensus_state = MockConsensusState::new(header);

    (client_state, consensus_state)
}

pub fn prepare_opened_connection(
    client_id: &ClientId,
) -> (ConnectionId, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    let conn_id = ConnectionId::new(0);
    let key = connection_key(&conn_id);
    let conn = ConnectionEnd::new(
        ConnState::Open,
        client_id.clone(),
        dummy_connection_counterparty(),
        vec![ConnVersion::default()],
        Duration::new(0, 0),
    )
    .expect("invalid connection");
    let bytes = conn.encode_vec();
    writes.insert(key, bytes);
    // connection counter
    let key = connection_counter_key();
    let bytes = 1_u64.to_be_bytes().to_vec();
    writes.insert(key, bytes);

    (conn_id, writes)
}

pub fn prepare_opened_channel(
    conn_id: &ConnectionId,
    is_ordered: bool,
) -> (PortId, ChannelId, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    // port
    let port_id = PortId::transfer();
    let key = port_key(&port_id);
    writes.insert(key, 0_u64.to_be_bytes().to_vec());
    // channel
    let channel_id = ChannelId::new(0);
    let key = channel_key(&port_id, &channel_id);
    let mut channel = ChannelEnd::new(
        ChanState::Open,
        Order::Unordered,
        dummy_channel_counterparty(),
        vec![conn_id.clone()],
        ChanVersion::new(VERSION.to_string()),
    )
    .expect("invalid channel");
    if is_ordered {
        channel.ordering = Order::Ordered;
    }
    let bytes = channel.encode_vec();
    writes.insert(key, bytes);

    (port_id, channel_id, writes)
}

pub fn msg_create_client() -> MsgCreateClient {
    let (client_state, consensus_state) = dummy_client();
    MsgCreateClient {
        client_state: client_state.into(),
        consensus_state: consensus_state.into(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_update_client(client_id: ClientId) -> MsgUpdateClient {
    let height = Height::new(0, 2).unwrap();
    let header = MockHeader {
        height,
        timestamp: Timestamp::now(),
    }
    .into();
    MsgUpdateClient {
        client_id,
        client_message: header,
        signer: "test".to_string().into(),
    }
}

pub fn msg_upgrade_client(client_id: ClientId) -> MsgUpgradeClient {
    let (client_state, consensus_state) = dummy_client();
    MsgUpgradeClient {
        client_id,
        upgraded_client_state: client_state.into(),
        upgraded_consensus_state: consensus_state.into(),
        proof_upgrade_client: dummy_proof(),
        proof_upgrade_consensus_state: dummy_proof(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_connection_open_init(client_id: ClientId) -> MsgConnectionOpenInit {
    let client_type = client_type();
    let counterparty_client_id = ClientId::new(client_type, 42).unwrap();
    let commitment_prefix =
        CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec()).unwrap();
    let counterparty =
        ConnCounterparty::new(counterparty_client_id, None, commitment_prefix);

    MsgConnectionOpenInit {
        client_id_on_a: client_id,
        counterparty,
        version: None,
        delay_period: Duration::new(0, 0),
        signer: "test".to_string().into(),
    }
}

pub fn msg_connection_open_try(
    client_id: ClientId,
    client_state: Any,
) -> MsgConnectionOpenTry {
    let consensus_height = Height::new(0, 1).expect("invalid height");
    #[allow(deprecated)]
    MsgConnectionOpenTry {
        client_id_on_b: client_id,
        client_state_of_b_on_a: client_state,
        counterparty: dummy_connection_counterparty(),
        versions_on_a: vec![ConnVersion::default()],
        proofs_height_on_a: dummy_proof_height(),
        proof_conn_end_on_a: dummy_proof(),
        proof_client_state_of_b_on_a: dummy_proof(),
        proof_consensus_state_of_b_on_a: dummy_proof(),
        consensus_height_of_b_on_a: consensus_height,
        delay_period: Duration::from_secs(0),
        signer: "test".to_string().into(),
        proof_consensus_state_of_b: Some(dummy_proof()),
        previous_connection_id: ConnectionId::default().to_string(),
    }
}

pub fn msg_connection_open_ack(
    connection_id: ConnectionId,
    client_state: Any,
) -> MsgConnectionOpenAck {
    let consensus_height = Height::new(0, 1).expect("invalid height");
    let counterparty = dummy_connection_counterparty();
    MsgConnectionOpenAck {
        conn_id_on_a: connection_id,
        conn_id_on_b: counterparty.connection_id().cloned().unwrap(),
        client_state_of_a_on_b: client_state,
        proof_conn_end_on_b: dummy_proof(),
        proof_client_state_of_a_on_b: dummy_proof(),
        proof_consensus_state_of_a_on_b: dummy_proof(),
        proofs_height_on_b: dummy_proof_height(),
        consensus_height_of_a_on_b: consensus_height,
        version: ConnVersion::default(),
        signer: "test".to_string().into(),
        proof_consensus_state_of_a: None,
    }
}

pub fn msg_connection_open_confirm(
    connection_id: ConnectionId,
) -> MsgConnectionOpenConfirm {
    MsgConnectionOpenConfirm {
        conn_id_on_b: connection_id,
        proof_conn_end_on_a: dummy_proof(),
        proof_height_on_a: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

fn dummy_proof() -> CommitmentProofBytes {
    vec![0].try_into().unwrap()
}

fn dummy_proof_height() -> Height {
    Height::new(0, 1).unwrap()
}

fn dummy_connection_counterparty() -> ConnCounterparty {
    let client_type = client_type();
    let client_id = ClientId::new(client_type, 42).expect("invalid client ID");
    let conn_id = ConnectionId::new(12);
    let commitment_prefix =
        CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
            .expect("the prefix should be parsable");
    ConnCounterparty::new(client_id, Some(conn_id), commitment_prefix)
}

pub fn msg_channel_open_init(
    port_id: PortId,
    conn_id: ConnectionId,
) -> MsgChannelOpenInit {
    MsgChannelOpenInit {
        port_id_on_a: port_id,
        connection_hops_on_a: vec![conn_id],
        port_id_on_b: PortId::transfer(),
        ordering: Order::Unordered,
        signer: "test".to_string().into(),
        version_proposal: ChanVersion::new(VERSION.to_string()),
    }
}

pub fn msg_channel_open_try(
    port_id: PortId,
    conn_id: ConnectionId,
) -> MsgChannelOpenTry {
    let counterparty = dummy_channel_counterparty();
    #[allow(deprecated)]
    MsgChannelOpenTry {
        port_id_on_b: port_id,
        connection_hops_on_b: vec![conn_id],
        port_id_on_a: counterparty.port_id().clone(),
        chan_id_on_a: counterparty.channel_id().cloned().unwrap(),
        version_supported_on_a: ChanVersion::new(VERSION.to_string()),
        proof_chan_end_on_a: dummy_proof(),
        proof_height_on_a: dummy_proof_height(),
        ordering: Order::Unordered,
        signer: "test".to_string().into(),
        version_proposal: ChanVersion::default(),
    }
}

pub fn msg_channel_open_ack(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelOpenAck {
    let counterparty = dummy_channel_counterparty();
    MsgChannelOpenAck {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        chan_id_on_b: counterparty.channel_id().cloned().unwrap(),
        version_on_b: ChanVersion::new(VERSION.to_string()),
        proof_chan_end_on_b: dummy_proof(),
        proof_height_on_b: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_channel_open_confirm(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelOpenConfirm {
    MsgChannelOpenConfirm {
        port_id_on_b: port_id,
        chan_id_on_b: channel_id,
        proof_chan_end_on_a: dummy_proof(),
        proof_height_on_a: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_channel_close_init(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelCloseInit {
    MsgChannelCloseInit {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        signer: "test".to_string().into(),
    }
}

pub fn msg_channel_close_confirm(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelCloseConfirm {
    MsgChannelCloseConfirm {
        port_id_on_b: port_id,
        chan_id_on_b: channel_id,
        proof_chan_end_on_a: dummy_proof(),
        proof_height_on_a: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn dummy_channel_counterparty() -> ChanCounterparty {
    let port_id = PortId::transfer();
    let channel_id = ChannelId::new(42);
    ChanCounterparty::new(port_id, Some(channel_id))
}

pub fn unorder_channel(channel: &mut ChannelEnd) {
    channel.ordering = Order::Unordered;
}

pub fn msg_transfer(
    port_id: PortId,
    channel_id: ChannelId,
    denom: String,
    sender: &Address,
) -> MsgTransfer {
    let amount = DenominatedAmount::native(Amount::native_whole(100));
    let timestamp = (Timestamp::now() + Duration::from_secs(100)).unwrap();
    MsgTransfer {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        packet_data: PacketData {
            token: PrefixedCoin {
                denom: denom.parse().expect("invalid denom"),
                amount: amount.into(),
            },
            sender: sender.to_string().into(),
            receiver: address::testing::gen_established_address()
                .to_string()
                .into(),
            memo: "memo".to_string().into(),
        },
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: timestamp,
    }
}

pub fn set_timeout_timestamp(msg: &mut MsgTransfer) {
    msg.timeout_timestamp_on_b =
        (msg.timeout_timestamp_on_b - Duration::from_secs(201)).unwrap();
}

pub fn msg_packet_recv(packet: Packet) -> MsgRecvPacket {
    MsgRecvPacket {
        packet,
        proof_commitment_on_a: dummy_proof(),
        proof_height_on_a: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_packet_ack(packet: Packet) -> MsgAcknowledgement {
    let packet_ack = AcknowledgementStatus::success(ack_success_b64()).into();
    MsgAcknowledgement {
        packet,
        acknowledgement: packet_ack,
        proof_acked_on_b: dummy_proof(),
        proof_height_on_b: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn received_packet(
    port_id: PortId,
    channel_id: ChannelId,
    sequence: Sequence,
    token: String,
    receiver: &Address,
) -> Packet {
    let amount = DenominatedAmount::native(Amount::native_whole(100));
    let counterparty = dummy_channel_counterparty();
    let timestamp = (Timestamp::now() + Duration::from_secs(100)).unwrap();
    let coin = PrefixedCoin {
        denom: token.parse().expect("invalid denom"),
        amount: amount.into(),
    };
    let sender = address::testing::gen_established_address();
    let data = PacketData {
        token: coin,
        sender: sender.to_string().into(),
        receiver: receiver.to_string().into(),
        memo: "memo".to_string().into(),
    };
    Packet {
        seq_on_a: sequence,
        port_id_on_a: counterparty.port_id().clone(),
        chan_id_on_a: counterparty.channel_id().unwrap().clone(),
        port_id_on_b: port_id,
        chan_id_on_b: channel_id,
        data: serde_json::to_vec(&data).unwrap(),
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: timestamp,
    }
}

pub fn msg_timeout(packet: Packet, next_sequence_recv: Sequence) -> MsgTimeout {
    MsgTimeout {
        packet,
        next_seq_recv_on_b: next_sequence_recv,
        proof_unreceived_on_b: dummy_proof(),
        proof_height_on_b: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn msg_timeout_on_close(
    packet: Packet,
    next_sequence_recv: Sequence,
) -> MsgTimeoutOnClose {
    MsgTimeoutOnClose {
        packet,
        next_seq_recv_on_b: next_sequence_recv,
        proof_unreceived_on_b: dummy_proof(),
        proof_close_on_b: dummy_proof(),
        proof_height_on_b: dummy_proof_height(),
        signer: "test".to_string().into(),
    }
}

pub fn packet_from_message(
    msg: &MsgTransfer,
    sequence: Sequence,
    counterparty: &ChanCounterparty,
) -> Packet {
    let packet_data = PacketData {
        token: msg.packet_data.token.clone(),
        sender: msg.packet_data.sender.clone(),
        receiver: msg.packet_data.receiver.clone(),
        memo: "memo".to_string().into(),
    };
    let data =
        serde_json::to_vec(&packet_data).expect("Encoding PacketData failed");

    Packet {
        seq_on_a: sequence,
        port_id_on_a: msg.port_id_on_a.clone(),
        chan_id_on_a: msg.chan_id_on_a.clone(),
        port_id_on_b: counterparty.port_id.clone(),
        chan_id_on_b: counterparty
            .channel_id()
            .cloned()
            .expect("the counterparty channel should exist"),
        data,
        timeout_height_on_b: msg.timeout_height_on_b,
        timeout_timestamp_on_b: msg.timeout_timestamp_on_b,
    }
}

pub fn balance_key_with_ibc_prefix(denom: String, owner: &Address) -> Key {
    let ibc_token = ibc_token(denom);
    token::storage_key::balance_key(&ibc_token, owner)
}

pub fn transfer_ack_with_error() -> AcknowledgementStatus {
    AcknowledgementStatus::error(
        StatusValue::new(
            TokenTransferError::PacketDataDeserialization.to_string(),
        )
        .expect("Empty message"),
    )
}
