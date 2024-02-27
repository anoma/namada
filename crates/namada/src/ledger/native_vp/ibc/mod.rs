//! IBC integration as a native validity predicate

pub mod context;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;
use std::time::Duration;

use context::{PseudoExecutionContext, VpValidationContext};
use namada_core::address::Address;
use namada_core::storage::Key;
use namada_gas::{IBC_ACTION_EXECUTE_GAS, IBC_ACTION_VALIDATE_GAS};
use namada_ibc::{
    Error as ActionError, IbcActions, TransferModule, ValidationParams,
};
use namada_proof_of_stake::storage::read_pos_params;
use namada_state::write_log::StorageModification;
use namada_state::StateRead;
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use thiserror::Error;

use crate::ibc::core::host::types::identifiers::ChainId as IbcChainId;
use crate::ledger::ibc::storage::{calc_hash, is_ibc_denom_key, is_ibc_key};
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::ledger::parameters::read_epoch_duration_parameter;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
    #[error("Decoding error: {0}")]
    Decoding(std::io::Error),
    #[error("IBC message is required as transaction data")]
    NoTxData,
    #[error("IBC action error: {0}")]
    IbcAction(ActionError),
    #[error("State change error: {0}")]
    StateChange(String),
    #[error("IBC event error: {0}")]
    IbcEvent(String),
}

/// IBC functions result
pub type VpResult<T> = std::result::Result<T, Error>;

/// IBC VP
pub struct Ibc<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> NativeVp for Ibc<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> VpResult<bool> {
        let signed = tx_data;
        let tx_data = signed.data().ok_or(Error::NoTxData)?;

        // Pseudo execution and compare them
        self.validate_state(&tx_data, keys_changed)?;

        // Validate the state according to the given IBC message
        self.validate_with_msg(&tx_data)?;

        // Validate the denom store if a denom key has been changed
        self.validate_denom(keys_changed)?;

        Ok(true)
    }
}

impl<'a, S, CA> Ibc<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    fn validate_state(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
    ) -> VpResult<()> {
        let exec_ctx = PseudoExecutionContext::new(self.ctx.pre());
        let ctx = Rc::new(RefCell::new(exec_ctx));

        let mut actions = IbcActions::new(ctx.clone());
        let module = TransferModule::new(ctx.clone());
        actions.add_transfer_module(module.module_id(), module);
        // Charge gas for the expensive execution
        self.ctx
            .charge_gas(IBC_ACTION_EXECUTE_GAS)
            .map_err(Error::NativeVpError)?;
        actions.execute(tx_data)?;

        let changed_ibc_keys: HashSet<&Key> =
            keys_changed.iter().filter(|k| is_ibc_key(k)).collect();
        if changed_ibc_keys.len() != ctx.borrow().get_changed_keys().len() {
            return Err(Error::StateChange(format!(
                "The changed keys mismatched: Actual {:?}, Expected {:?}",
                changed_ibc_keys,
                ctx.borrow().get_changed_keys(),
            )));
        }

        for key in changed_ibc_keys {
            let actual = self
                .ctx
                .read_bytes_post(key)
                .map_err(Error::NativeVpError)?;
            match_value(key, actual, ctx.borrow().get_changed_value(key))?;
        }

        // check the event
        let actual = self.ctx.state.write_log().get_ibc_events();
        if *actual != ctx.borrow().event {
            return Err(Error::IbcEvent(format!(
                "The IBC event is invalid: Actual {:?}, Expected {:?}",
                actual,
                ctx.borrow().event
            )));
        }

        Ok(())
    }

    fn validate_with_msg(&self, tx_data: &[u8]) -> VpResult<()> {
        let validation_ctx = VpValidationContext::new(self.ctx.pre());
        let ctx = Rc::new(RefCell::new(validation_ctx));

        let mut actions = IbcActions::new(ctx.clone());
        actions.set_validation_params(self.validation_params()?);

        let module = TransferModule::new(ctx);
        actions.add_transfer_module(module.module_id(), module);
        // Charge gas for the expensive validation
        self.ctx
            .charge_gas(IBC_ACTION_VALIDATE_GAS)
            .map_err(Error::NativeVpError)?;
        actions.validate(tx_data).map_err(Error::IbcAction)
    }

    /// Retrieve the validation params
    pub fn validation_params(&self) -> VpResult<ValidationParams> {
        use std::str::FromStr;
        let chain_id = self.ctx.get_chain_id().map_err(Error::NativeVpError)?;
        let proof_specs =
            namada_state::ics23_specs::ibc_proof_specs::<<S as StateRead>::H>();
        let pos_params =
            read_pos_params(&self.ctx.post()).map_err(Error::NativeVpError)?;
        let pipeline_len = pos_params.pipeline_len;
        let epoch_duration = read_epoch_duration_parameter(&self.ctx.post())
            .map_err(Error::NativeVpError)?;
        let unbonding_period_secs =
            pipeline_len * epoch_duration.min_duration.0;
        Ok(ValidationParams {
            chain_id: IbcChainId::from_str(&chain_id)
                .map_err(ActionError::ChainId)?,
            proof_specs: proof_specs.into(),
            unbonding_period: Duration::from_secs(unbonding_period_secs),
            upgrade_path: Vec::new(),
        })
    }

    fn validate_denom(&self, keys_changed: &BTreeSet<Key>) -> VpResult<()> {
        for key in keys_changed {
            if let Some((_, hash)) = is_ibc_denom_key(key) {
                match self.ctx.read_post::<String>(key).map_err(|e| {
                    ActionError::Denom(format!(
                        "Getting the denom failed: Key {}, Error {}",
                        key, e
                    ))
                })? {
                    Some(denom) => {
                        if calc_hash(&denom) != hash {
                            return Err(ActionError::Denom(format!(
                                "The denom is invalid: Key {}, Denom {}",
                                key, denom
                            ))
                            .into());
                        }
                    }
                    None => {
                        return Err(ActionError::Denom(format!(
                            "The corresponding denom wasn't stored: Key {}",
                            key
                        ))
                        .into());
                    }
                }
            }
        }
        Ok(())
    }
}

fn match_value(
    key: &Key,
    actual: Option<Vec<u8>>,
    expected: Option<&StorageModification>,
) -> VpResult<()> {
    match (actual, expected) {
        (Some(v), Some(StorageModification::Write { value })) => {
            if v == *value {
                Ok(())
            } else {
                Err(Error::StateChange(format!(
                    "The value mismatched: Key {} actual {:?}, expected {:?}",
                    key, v, value
                )))
            }
        }
        (Some(_), _) => Err(Error::StateChange(format!(
            "The value was invalid: Key {}",
            key
        ))),
        (None, Some(StorageModification::Delete)) => Ok(()),
        (None, _) => Err(Error::StateChange(format!(
            "The key was deleted unexpectedly: Key {}",
            key
        ))),
    }
}

impl From<ActionError> for Error {
    fn from(err: ActionError) -> Self {
        Self::IbcAction(err)
    }
}

/// A dummy header used for testing
#[cfg(any(test, feature = "testing"))]
pub fn get_dummy_header() -> crate::storage::Header {
    use crate::tendermint::time::Time as TmTime;
    crate::storage::Header {
        hash: crate::hash::Hash([0; 32]),
        time: TmTime::now().try_into().unwrap(),
        next_validators_hash: crate::hash::Hash([0; 32]),
    }
}

/// A dummy validator used for testing
#[cfg(any(test, feature = "testing"))]
pub fn get_dummy_genesis_validator()
-> namada_proof_of_stake::types::GenesisValidator {
    use crate::core::address::testing::established_address_1;
    use crate::core::dec::Dec;
    use crate::core::key::testing::common_sk_from_simple_seed;
    use crate::key;
    use crate::token::Amount;

    let address = established_address_1();
    let tokens = Amount::native_whole(1);
    let consensus_sk = common_sk_from_simple_seed(0);
    let consensus_key = consensus_sk.to_public();

    let protocol_sk = common_sk_from_simple_seed(1);
    let protocol_key = protocol_sk.to_public();

    let commission_rate =
        Dec::new(1, 1).expect("expected 0.1 to be a valid decimal");
    let max_commission_rate_change =
        Dec::new(1, 1).expect("expected 0.1 to be a valid decimal");

    let eth_hot_sk =
        key::common::SecretKey::Secp256k1(key::testing::gen_keypair::<
            key::secp256k1::SigScheme,
        >());
    let eth_hot_key = eth_hot_sk.to_public();

    let eth_cold_sk =
        key::common::SecretKey::Secp256k1(key::testing::gen_keypair::<
            key::secp256k1::SigScheme,
        >());
    let eth_cold_key = eth_cold_sk.to_public();

    namada_proof_of_stake::types::GenesisValidator {
        address,
        tokens,
        consensus_key,
        protocol_key,
        eth_cold_key,
        eth_hot_key,
        commission_rate,
        max_commission_rate_change,
        metadata: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use borsh::BorshDeserialize;
    use borsh_ext::BorshSerializeExt;
    use ibc_testkit::testapp::ibc::clients::mock::client_state::{
        client_type, MockClientState, MOCK_CLIENT_TYPE,
    };
    use ibc_testkit::testapp::ibc::clients::mock::consensus_state::MockConsensusState;
    use ibc_testkit::testapp::ibc::clients::mock::header::MockHeader;
    use namada_core::validity_predicate::VpSentinel;
    use namada_gas::TxGasMeter;
    use namada_governance::parameters::GovernanceParameters;
    use namada_state::testing::TestState;
    use namada_state::StorageRead;
    use namada_tx::data::TxType;
    use namada_tx::{Code, Data, Section, Signature};
    use prost::Message;
    use sha2::Digest;

    use super::*;
    use crate::core::address::testing::{
        established_address_1, established_address_2, nam,
    };
    use crate::core::address::InternalAddress;
    use crate::core::storage::Epoch;
    use crate::ibc::apps::transfer::types::events::{
        AckEvent, DenomTraceEvent, RecvEvent, TimeoutEvent, TransferEvent,
    };
    use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
    use crate::ibc::apps::transfer::types::packet::PacketData;
    use crate::ibc::apps::transfer::types::{
        ack_success_b64, PrefixedCoin, TracePrefix, VERSION,
    };
    use crate::ibc::core::channel::types::acknowledgement::{
        Acknowledgement, AcknowledgementStatus,
    };
    use crate::ibc::core::channel::types::channel::{
        ChannelEnd, Counterparty as ChanCounterparty, Order, State as ChanState,
    };
    use crate::ibc::core::channel::types::commitment::PacketCommitment;
    use crate::ibc::core::channel::types::events::{
        AcknowledgePacket, OpenAck as ChanOpenAck,
        OpenConfirm as ChanOpenConfirm, OpenInit as ChanOpenInit,
        OpenTry as ChanOpenTry, ReceivePacket, SendPacket, TimeoutPacket,
        WriteAcknowledgement,
    };
    use crate::ibc::core::channel::types::msgs::{
        MsgAcknowledgement, MsgChannelOpenAck, MsgChannelOpenConfirm,
        MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket, MsgTimeout,
        MsgTimeoutOnClose,
    };
    use crate::ibc::core::channel::types::packet::Packet;
    use crate::ibc::core::channel::types::timeout::TimeoutHeight;
    use crate::ibc::core::channel::types::Version as ChanVersion;
    use crate::ibc::core::client::types::events::{CreateClient, UpdateClient};
    use crate::ibc::core::client::types::msgs::{
        MsgCreateClient, MsgUpdateClient,
    };
    use crate::ibc::core::client::types::Height;
    use crate::ibc::core::commitment_types::commitment::{
        CommitmentPrefix, CommitmentProofBytes,
    };
    use crate::ibc::core::connection::types::events::{
        OpenAck as ConnOpenAck, OpenConfirm as ConnOpenConfirm,
        OpenInit as ConnOpenInit, OpenTry as ConnOpenTry,
    };
    use crate::ibc::core::connection::types::msgs::{
        MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit,
        MsgConnectionOpenTry,
    };
    use crate::ibc::core::connection::types::version::Version as ConnVersion;
    use crate::ibc::core::connection::types::{
        ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
    };
    use crate::ibc::core::handler::types::events::{
        IbcEvent as RawIbcEvent, MessageEvent,
    };
    use crate::ibc::core::host::types::identifiers::{
        ChannelId, ClientId, ConnectionId, PortId, Sequence,
    };
    use crate::ibc::core::router::types::event::ModuleEvent;
    use crate::ibc::primitives::proto::{Any, Protobuf};
    use crate::ibc::primitives::{Msg, Timestamp};
    use crate::ibc::storage::{
        ack_key, channel_counter_key, channel_key, client_connections_key,
        client_counter_key, client_state_key, client_update_height_key,
        client_update_timestamp_key, commitment_key, connection_counter_key,
        connection_key, consensus_state_key, ibc_denom_key,
        next_sequence_ack_key, next_sequence_recv_key, next_sequence_send_key,
        receipt_key,
    };
    use crate::key::testing::keypair_1;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::parameters::storage::{
        get_epoch_duration_storage_key, get_max_expected_time_per_block_key,
    };
    use crate::ledger::parameters::EpochDuration;
    use crate::ledger::{ibc, pos};
    use crate::storage::{BlockHash, BlockHeight, TxIndex};
    use crate::tendermint::time::Time as TmTime;
    use crate::time::DurationSecs;
    use crate::token::storage_key::balance_key;
    use crate::token::Amount;
    use crate::vm::wasm;

    const ADDRESS: Address = Address::Internal(InternalAddress::Ibc);
    const COMMITMENT_PREFIX: &[u8] = b"ibc";
    const TX_GAS_LIMIT: u64 = 1_000_000;

    fn get_client_id() -> ClientId {
        let id = format!("{}-0", MOCK_CLIENT_TYPE);
        ClientId::from_str(&id).expect("Creating a client ID failed")
    }

    fn init_storage() -> TestState {
        let mut state = TestState::default();

        // initialize the storage
        ibc::init_genesis_storage(&mut state);
        let gov_params = GovernanceParameters::default();
        gov_params.init_storage(&mut state).unwrap();
        pos::test_utils::test_init_genesis(
            &mut state,
            namada_proof_of_stake::OwnedPosParams::default(),
            vec![get_dummy_genesis_validator()].into_iter(),
            Epoch(1),
        )
        .unwrap();
        // epoch duration
        let epoch_duration_key = get_epoch_duration_storage_key();
        let epoch_duration = EpochDuration {
            min_num_of_blocks: 10,
            min_duration: DurationSecs(100),
        };
        state
            .write_log_mut()
            .write(&epoch_duration_key, epoch_duration.serialize_to_vec())
            .expect("write failed");
        // max_expected_time_per_block
        let time = DurationSecs::from(Duration::new(60, 0));
        let time_key = get_max_expected_time_per_block_key();
        state
            .write_log_mut()
            .write(&time_key, namada_core::encode(&time))
            .expect("write failed");
        // set a dummy header
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();

        state
    }

    fn insert_init_client(state: &mut TestState) {
        // insert a mock client type
        let client_id = get_client_id();
        // insert a mock client state
        let client_state_key = client_state_key(&get_client_id());
        let height = Height::new(0, 1).unwrap();
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header);
        let bytes = Protobuf::<Any>::encode_vec(client_state);
        state
            .write_log_mut()
            .write(&client_state_key, bytes)
            .expect("write failed");
        // insert a mock consensus state
        let consensus_key = consensus_state_key(&client_id, height);
        let consensus_state = MockConsensusState::new(header);
        let bytes = Protobuf::<Any>::encode_vec(consensus_state);
        state
            .write_log_mut()
            .write(&consensus_key, bytes)
            .expect("write failed");
        // insert update time and height
        let client_update_time_key = client_update_timestamp_key(&client_id);
        let time = StateRead::get_block_header(state, None)
            .unwrap()
            .0
            .unwrap()
            .time;
        let bytes = TmTime::try_from(time).unwrap().encode_vec();
        state
            .write_log_mut()
            .write(&client_update_time_key, bytes)
            .expect("write failed");
        let client_update_height_key = client_update_height_key(&client_id);
        let host_height = state.in_mem().get_block_height().0;
        let host_height =
            Height::new(0, host_height.0).expect("invalid height");
        state
            .write_log_mut()
            .write(&client_update_height_key, host_height.encode_vec())
            .expect("write failed");
        state.write_log_mut().commit_tx();
    }

    fn get_connection_id() -> ConnectionId {
        ConnectionId::new(0)
    }

    fn get_port_id() -> PortId {
        PortId::transfer()
    }

    fn get_channel_id() -> ChannelId {
        ChannelId::new(0)
    }

    fn get_connection(conn_state: ConnState) -> ConnectionEnd {
        ConnectionEnd::new(
            conn_state,
            get_client_id(),
            get_conn_counterparty(),
            vec![ConnVersion::default()],
            Duration::new(0, 0),
        )
        .unwrap()
    }

    fn get_conn_counterparty() -> ConnCounterparty {
        let counterpart_client_id = ClientId::new(client_type(), 22).unwrap();
        let counterpart_conn_id = ConnectionId::new(32);
        let commitment_prefix =
            CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
                .expect("the prefix should be parsable");
        ConnCounterparty::new(
            counterpart_client_id,
            Some(counterpart_conn_id),
            commitment_prefix,
        )
    }

    fn get_channel(channel_state: ChanState, order: Order) -> ChannelEnd {
        ChannelEnd::new(
            channel_state,
            order,
            get_channel_counterparty(),
            vec![get_connection_id()],
            ChanVersion::new(VERSION.to_string()),
        )
        .unwrap()
    }

    fn get_channel_counterparty() -> ChanCounterparty {
        let counterpart_port_id = PortId::transfer();
        let counterpart_channel_id = ChannelId::new(0);
        ChanCounterparty::new(counterpart_port_id, Some(counterpart_channel_id))
    }

    fn get_next_seq(state: &TestState, key: &Key) -> Sequence {
        let (val, _) = state.db_read(key).expect("read failed");
        match val {
            Some(v) => {
                // IBC related data is encoded without borsh
                let index: [u8; 8] = v.try_into().expect("decoding failed");
                let index = u64::from_be_bytes(index);
                Sequence::from(index)
            }
            // The sequence has not been used yet
            None => Sequence::from(1),
        }
    }

    fn increment_sequence(state: &mut TestState, key: &Key) {
        let count = match state.read_bytes(key).expect("read failed") {
            Some(value) => {
                let count: [u8; 8] =
                    value.try_into().expect("decoding a count failed");
                u64::from_be_bytes(count)
            }
            None => 0,
        };
        state
            .write_log_mut()
            .write(key, (count + 1).to_be_bytes().to_vec())
            .expect("write failed");
    }

    fn increment_counter(state: &mut TestState, key: &Key) {
        let count = match state.read_bytes(key).expect("read failed") {
            Some(value) => {
                u64::try_from_slice(&value).expect("invalid counter value")
            }
            None => unreachable!("The counter should be initialized"),
        };
        state
            .write_log_mut()
            .write(key, (count + 1).serialize_to_vec())
            .expect("write failed");
    }

    fn dummy_proof() -> CommitmentProofBytes {
        CommitmentProofBytes::try_from(vec![0]).unwrap()
    }

    fn packet_from_message(
        msg: &MsgTransfer,
        sequence: Sequence,
        counterparty: &ChanCounterparty,
    ) -> Packet {
        let data = serde_json::to_vec(&msg.packet_data)
            .expect("Encoding PacketData failed");

        Packet {
            seq_on_a: sequence,
            port_id_on_a: msg.port_id_on_a.clone(),
            chan_id_on_a: msg.chan_id_on_a.clone(),
            port_id_on_b: counterparty.port_id.clone(),
            chan_id_on_b: counterparty
                .channel_id()
                .expect("the counterparty channel should exist")
                .clone(),
            data,
            timeout_height_on_b: msg.timeout_height_on_b,
            timeout_timestamp_on_b: msg.timeout_timestamp_on_b,
        }
    }

    fn commitment(packet: &Packet) -> PacketCommitment {
        let timeout = packet.timeout_timestamp_on_b.nanoseconds().to_be_bytes();
        let revision_number = packet
            .timeout_height_on_b
            .commitment_revision_number()
            .to_be_bytes();
        let revision_height = packet
            .timeout_height_on_b
            .commitment_revision_height()
            .to_be_bytes();
        let data = sha2::Sha256::digest(&packet.data);
        let input = [
            &timeout,
            &revision_number,
            &revision_height,
            data.as_slice(),
        ]
        .concat();
        sha2::Sha256::digest(&input).to_vec().into()
    }

    #[test]
    fn test_create_client() {
        let mut state = init_storage();
        let mut keys_changed = BTreeSet::new();

        let height = Height::new(0, 1).unwrap();
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_id = get_client_id();
        // message
        let client_state = MockClientState::new(header);
        let consensus_state = MockConsensusState::new(header);
        let msg = MsgCreateClient {
            client_state: client_state.into(),
            consensus_state: consensus_state.clone().into(),
            signer: "account0".to_string().into(),
        };
        // client state
        let client_state_key = client_state_key(&get_client_id());
        let bytes = Protobuf::<Any>::encode_vec(client_state);
        state
            .write_log_mut()
            .write(&client_state_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_state_key);
        // client consensus
        let consensus_key = consensus_state_key(&client_id, height);
        let bytes = Protobuf::<Any>::encode_vec(consensus_state);
        state
            .write_log_mut()
            .write(&consensus_key, bytes)
            .expect("write failed");
        keys_changed.insert(consensus_key);
        // client counter
        let client_counter_key = client_counter_key();
        increment_counter(&mut state, &client_counter_key);
        keys_changed.insert(client_counter_key);

        let event = RawIbcEvent::CreateClient(CreateClient::new(
            client_id,
            client_type(),
            client_state.latest_height(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Client);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_create_client_fail() {
        let mut state = TestState::default();

        let mut keys_changed = BTreeSet::new();

        // initialize the storage
        ibc::init_genesis_storage(&mut state);
        // set a dummy header
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();

        let height = Height::new(0, 1).unwrap();
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        // insert only client state
        let client_state = MockClientState::new(header);
        let client_state_key = client_state_key(&get_client_id());
        let bytes = Protobuf::<Any>::encode_vec(client_state);
        state
            .write_log_mut()
            .write(&client_state_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_state_key);
        let client_state = MockClientState::new(header);
        let consensus_state = MockConsensusState::new(header);
        // make a correct message
        let msg = MsgCreateClient {
            client_state: client_state.into(),
            consensus_state: consensus_state.into(),
            signer: "account0".to_string().into(),
        };

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        // this should fail because no state is stored
        let result =
            ibc.validate_tx(&tx, &keys_changed, &verifiers).unwrap_err();
        assert_matches!(result, Error::StateChange(_));
    }

    #[test]
    fn test_update_client() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");

        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // update the client
        let client_id = get_client_id();
        let client_state_key = client_state_key(&get_client_id());
        let height = Height::new(0, 11).unwrap();
        // the header should be created before
        let time = (TmTime::now() - std::time::Duration::new(100, 0)).unwrap();
        let header = MockHeader {
            height,
            timestamp: time.into(),
        };
        let msg = MsgUpdateClient {
            client_id: client_id.clone(),
            client_message: header.into(),
            signer: "account0".to_string().into(),
        };
        // client state
        let client_state = MockClientState::new(header);
        let bytes = Protobuf::<Any>::encode_vec(client_state);
        state
            .write_log_mut()
            .write(&client_state_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_state_key);
        // consensus state
        let consensus_key = consensus_state_key(&client_id, height);
        let consensus_state = MockConsensusState::new(header);
        let bytes = Protobuf::<Any>::encode_vec(consensus_state);
        state
            .write_log_mut()
            .write(&consensus_key, bytes)
            .expect("write failed");
        keys_changed.insert(consensus_key);
        // client update time
        let client_update_time_key = client_update_timestamp_key(&client_id);
        let time = StateRead::get_block_header(&state, None)
            .unwrap()
            .0
            .unwrap()
            .time;
        let bytes = TmTime::try_from(time).unwrap().encode_vec();
        state
            .write_log_mut()
            .write(&client_update_time_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_update_time_key);
        // client update height
        let client_update_height_key = client_update_height_key(&client_id);
        let host_height = state.in_mem().get_block_height().0;
        let host_height =
            Height::new(0, host_height.0).expect("invalid height");
        state
            .write_log_mut()
            .write(&client_update_height_key, host_height.encode_vec())
            .expect("write failed");
        keys_changed.insert(client_update_height_key);
        // event
        let consensus_height = client_state.latest_height();
        let event = RawIbcEvent::UpdateClient(UpdateClient::new(
            client_id,
            client_type(),
            consensus_height,
            vec![consensus_height],
            Protobuf::<Any>::encode_vec(header),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Client);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_init_connection() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare a message
        let mut counterparty = get_conn_counterparty();
        counterparty.connection_id = None;
        let msg = MsgConnectionOpenInit {
            client_id_on_a: get_client_id(),
            counterparty,
            version: Some(ConnVersion::default()),
            delay_period: Duration::new(100, 0),
            signer: "account0".to_string().into(),
        };

        // insert an INIT connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = ConnectionEnd::new(
            ConnState::Init,
            msg.client_id_on_a.clone(),
            msg.counterparty.clone(),
            vec![msg.version.clone().unwrap()],
            msg.delay_period,
        )
        .expect("invalid connection");
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(conn_key);
        // client connection list
        let client_conn_key = client_connections_key(&msg.client_id_on_a);
        let conn_list = conn_id.to_string();
        let bytes = conn_list.serialize_to_vec();
        state
            .write_log_mut()
            .write(&client_conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_conn_key);
        // connection counter
        let conn_counter_key = connection_counter_key();
        increment_counter(&mut state, &conn_counter_key);
        keys_changed.insert(conn_counter_key);
        // event
        let event = RawIbcEvent::OpenInitConnection(ConnOpenInit::new(
            conn_id,
            msg.client_id_on_a.clone(),
            msg.counterparty.client_id().clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Connection);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_init_connection_fail() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        // initialize the storage
        ibc::init_genesis_storage(&mut state);
        // set a dummy header
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();

        // prepare data
        let mut counterparty = get_conn_counterparty();
        counterparty.connection_id = None;
        let msg = MsgConnectionOpenInit {
            client_id_on_a: get_client_id(),
            counterparty,
            version: Some(ConnVersion::default()),
            delay_period: Duration::new(100, 0),
            signer: "account0".to_string().into(),
        };

        // insert an Init connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = ConnectionEnd::new(
            ConnState::Init,
            msg.client_id_on_a.clone(),
            msg.counterparty.clone(),
            vec![msg.version.clone().unwrap()],
            msg.delay_period,
        )
        .expect("invalid connection");
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(conn_key);
        // client connection list
        let client_conn_key = client_connections_key(&msg.client_id_on_a);
        let conn_list = conn_id.to_string();
        let bytes = conn_list.serialize_to_vec();
        state
            .write_log_mut()
            .write(&client_conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_conn_key);
        // connection counter
        let conn_counter_key = connection_counter_key();
        increment_counter(&mut state, &conn_counter_key);
        keys_changed.insert(conn_counter_key);
        // No event

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should fail because no event
        let result =
            ibc.validate_tx(&tx, &keys_changed, &verifiers).unwrap_err();
        assert_matches!(result, Error::IbcEvent(_));
    }

    #[test]
    fn test_try_connection() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let height = Height::new(0, 1).unwrap();
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header);
        let proof_height = Height::new(0, 1).unwrap();
        #[allow(deprecated)]
        let msg = MsgConnectionOpenTry {
            client_id_on_b: get_client_id(),
            client_state_of_b_on_a: client_state.into(),
            counterparty: get_conn_counterparty(),
            versions_on_a: vec![ConnVersion::default()],
            proofs_height_on_a: proof_height,
            proof_conn_end_on_a: dummy_proof(),
            proof_client_state_of_b_on_a: dummy_proof(),
            proof_consensus_state_of_b_on_a: dummy_proof(),
            consensus_height_of_b_on_a: client_state.latest_height(),
            delay_period: Duration::from_secs(0),
            signer: "account0".to_string().into(),
            proof_consensus_state_of_b: Some(dummy_proof()),
            previous_connection_id: ConnectionId::default().to_string(),
        };

        // insert a TryOpen connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = ConnectionEnd::new(
            ConnState::TryOpen,
            msg.client_id_on_b.clone(),
            msg.counterparty.clone(),
            msg.versions_on_a.clone(),
            msg.delay_period,
        )
        .expect("invalid connection");
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(conn_key);
        // client connection list
        let client_conn_key = client_connections_key(&msg.client_id_on_b);
        let conn_list = conn_id.to_string();
        let bytes = conn_list.serialize_to_vec();
        state
            .write_log_mut()
            .write(&client_conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(client_conn_key);
        // connection counter
        let conn_counter_key = connection_counter_key();
        increment_counter(&mut state, &conn_counter_key);
        keys_changed.insert(conn_counter_key);
        // event
        let event = RawIbcEvent::OpenTryConnection(ConnOpenTry::new(
            conn_id,
            msg.client_id_on_b.clone(),
            msg.counterparty.connection_id().cloned().unwrap(),
            msg.counterparty.client_id().clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Connection);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_ack_connection() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an Init connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Init);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // update the connection to Open
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(conn_key);

        // prepare data
        let height = Height::new(0, 1).unwrap();
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header);
        let counterparty = get_conn_counterparty();
        let proof_height = Height::new(0, 1).unwrap();

        let msg = MsgConnectionOpenAck {
            conn_id_on_a: get_connection_id(),
            conn_id_on_b: counterparty.connection_id().cloned().unwrap(),
            client_state_of_a_on_b: client_state.into(),
            proof_conn_end_on_b: dummy_proof(),
            proof_client_state_of_a_on_b: dummy_proof(),
            proof_consensus_state_of_a_on_b: dummy_proof(),
            proofs_height_on_b: proof_height,
            consensus_height_of_a_on_b: client_state.latest_height(),
            version: ConnVersion::default(),
            signer: "account0".to_string().into(),
            proof_consensus_state_of_a: None,
        };
        // event
        let event = RawIbcEvent::OpenAckConnection(ConnOpenAck::new(
            msg.conn_id_on_a.clone(),
            get_client_id(),
            msg.conn_id_on_b.clone(),
            counterparty.client_id().clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Connection);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_code = vec![];
        let tx_index = TxIndex::default();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_confirm_connection() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert a TryOpen connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::TryOpen);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // update the connection to Open
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        keys_changed.insert(conn_key);

        // prepare data
        let proof_height = Height::new(0, 1).unwrap();
        let msg = MsgConnectionOpenConfirm {
            conn_id_on_b: get_connection_id(),
            proof_conn_end_on_a: dummy_proof(),
            proof_height_on_a: proof_height,
            signer: "account0".to_string().into(),
        };
        // event
        let counterparty = get_conn_counterparty();
        let event = RawIbcEvent::OpenConfirmConnection(ConnOpenConfirm::new(
            get_connection_id(),
            get_client_id(),
            counterparty.connection_id().cloned().unwrap(),
            counterparty.client_id().clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Connection);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_code = vec![];
        let tx_index = TxIndex::default();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_init_channel() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an opened connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let msg = MsgChannelOpenInit {
            port_id_on_a: get_port_id(),
            connection_hops_on_a: vec![conn_id.clone()],
            port_id_on_b: get_port_id(),
            ordering: Order::Unordered,
            signer: "account0".to_string().into(),
            version_proposal: ChanVersion::new(VERSION.to_string()),
        };

        // insert an Init channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let mut counterparty = get_channel_counterparty();
        counterparty.channel_id = None;
        let channel = ChannelEnd::new(
            ChanState::Init,
            msg.ordering,
            counterparty.clone(),
            msg.connection_hops_on_a.clone(),
            msg.version_proposal.clone(),
        )
        .unwrap();
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        keys_changed.insert(channel_key);
        // channel counter
        let chan_counter_key = channel_counter_key();
        increment_counter(&mut state, &chan_counter_key);
        keys_changed.insert(chan_counter_key);
        // sequences
        let channel_id = get_channel_id();
        let port_id = msg.port_id_on_a.clone();
        let send_key = next_sequence_send_key(&port_id, &channel_id);
        increment_sequence(&mut state, &send_key);
        keys_changed.insert(send_key);
        let recv_key = next_sequence_recv_key(&port_id, &channel_id);
        increment_sequence(&mut state, &recv_key);
        keys_changed.insert(recv_key);
        let ack_key = next_sequence_ack_key(&port_id, &channel_id);
        increment_sequence(&mut state, &ack_key);
        keys_changed.insert(ack_key);
        // event
        let event = RawIbcEvent::OpenInitChannel(ChanOpenInit::new(
            msg.port_id_on_a.clone(),
            get_channel_id(),
            counterparty.port_id().clone(),
            conn_id,
            msg.version_proposal.clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_try_channel() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let proof_height = Height::new(0, 1).unwrap();
        let conn_id = get_connection_id();
        let counterparty = get_channel_counterparty();
        #[allow(deprecated)]
        let msg = MsgChannelOpenTry {
            port_id_on_b: get_port_id(),
            connection_hops_on_b: vec![conn_id.clone()],
            port_id_on_a: counterparty.port_id().clone(),
            chan_id_on_a: counterparty.channel_id().cloned().unwrap(),
            version_supported_on_a: ChanVersion::new(VERSION.to_string()),
            proof_chan_end_on_a: dummy_proof(),
            proof_height_on_a: proof_height,
            ordering: Order::Unordered,
            signer: "account0".to_string().into(),
            version_proposal: ChanVersion::default(),
        };

        // insert a TryOpen channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::TryOpen, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        keys_changed.insert(channel_key);
        // channel counter
        let chan_counter_key = channel_counter_key();
        increment_counter(&mut state, &chan_counter_key);
        keys_changed.insert(chan_counter_key);
        // sequences
        let channel_id = get_channel_id();
        let port_id = msg.port_id_on_a.clone();
        let send_key = next_sequence_send_key(&port_id, &channel_id);
        increment_sequence(&mut state, &send_key);
        keys_changed.insert(send_key);
        let recv_key = next_sequence_recv_key(&port_id, &channel_id);
        increment_sequence(&mut state, &recv_key);
        keys_changed.insert(recv_key);
        let ack_key = next_sequence_ack_key(&port_id, &channel_id);
        increment_sequence(&mut state, &ack_key);
        keys_changed.insert(ack_key);
        // event
        let event = RawIbcEvent::OpenTryChannel(ChanOpenTry::new(
            msg.port_id_on_a.clone(),
            get_channel_id(),
            counterparty.port_id().clone(),
            counterparty.channel_id().cloned().unwrap(),
            conn_id,
            msg.version_supported_on_a.clone(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_ack_channel() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Init channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Init, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let proof_height = Height::new(0, 1).unwrap();
        let counterparty = get_channel_counterparty();
        let msg = MsgChannelOpenAck {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            chan_id_on_b: counterparty.channel_id().cloned().unwrap(),
            version_on_b: ChanVersion::new(VERSION.to_string()),
            proof_chan_end_on_b: dummy_proof(),
            proof_height_on_b: proof_height,
            signer: "account0".to_string().into(),
        };

        // update the channel to Open
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        keys_changed.insert(channel_key);
        // event
        let event = RawIbcEvent::OpenAckChannel(ChanOpenAck::new(
            msg.port_id_on_a.clone(),
            msg.chan_id_on_a.clone(),
            counterparty.port_id().clone(),
            counterparty.channel_id().cloned().unwrap(),
            get_connection_id(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.add_section(Section::Signature(Signature::new(
            vec![outer_tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &outer_tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&outer_tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_confirm_channel() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert a TryOpen channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::TryOpen, Order::Ordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let proof_height = Height::new(0, 1).unwrap();
        let msg = MsgChannelOpenConfirm {
            port_id_on_b: get_port_id(),
            chan_id_on_b: get_channel_id(),
            proof_chan_end_on_a: dummy_proof(),
            proof_height_on_a: proof_height,
            signer: "account0".to_string().into(),
        };

        // update the channel to Open
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        keys_changed.insert(channel_key);
        // event
        let counterparty = get_channel_counterparty();
        let event = RawIbcEvent::OpenConfirmChannel(ChanOpenConfirm::new(
            msg.port_id_on_b.clone(),
            msg.chan_id_on_b.clone(),
            counterparty.port_id().clone(),
            counterparty.channel_id().cloned().unwrap(),
            get_connection_id(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    // skip test_close_init_channel() and test_close_confirm_channel() since it
    // is not allowed to close the transfer channel

    #[test]
    fn test_send_packet() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Open channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        // init balance
        let sender = established_address_1();
        let balance_key = balance_key(&nam(), &sender);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&balance_key, amount.serialize_to_vec())
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let msg = MsgTransfer {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: nam().to_string().parse().unwrap(),
                    amount: 100u64.into(),
                },
                sender: sender.to_string().into(),
                receiver: "receiver".to_string().into(),
                memo: "memo".to_string().into(),
            },
            timeout_height_on_b: TimeoutHeight::At(Height::new(0, 10).unwrap()),
            timeout_timestamp_on_b: Timestamp::none(),
        };

        // the sequence send
        let seq_key = next_sequence_send_key(&get_port_id(), &get_channel_id());
        let sequence = get_next_seq(&state, &seq_key);
        state
            .write_log_mut()
            .write(&seq_key, (u64::from(sequence) + 1).to_be_bytes().to_vec())
            .expect("write failed");
        keys_changed.insert(seq_key);
        // packet commitment
        let packet =
            packet_from_message(&msg, sequence, &get_channel_counterparty());
        let commitment_key =
            commitment_key(&msg.port_id_on_a, &msg.chan_id_on_a, sequence);
        let commitment = commitment(&packet);
        let bytes = commitment.into_vec();
        state
            .write_log_mut()
            .write(&commitment_key, bytes)
            .expect("write failed");
        keys_changed.insert(commitment_key);
        // event
        let transfer_event = TransferEvent {
            sender: msg.packet_data.sender.clone(),
            receiver: msg.packet_data.receiver.clone(),
            amount: msg.packet_data.token.amount,
            denom: msg.packet_data.token.denom.clone(),
            memo: msg.packet_data.memo.clone(),
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(transfer_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event = RawIbcEvent::SendPacket(SendPacket::new(
            packet,
            Order::Unordered,
            get_connection_id(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_recv_packet() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an open channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let sender = established_address_1();
        let receiver = established_address_2();
        let transfer_msg = MsgTransfer {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: nam().to_string().parse().unwrap(),
                    amount: 100u64.into(),
                },
                sender: sender.to_string().into(),
                receiver: receiver.to_string().into(),
                memo: "memo".to_string().into(),
            },
            timeout_height_on_b: TimeoutHeight::At(Height::new(0, 10).unwrap()),
            timeout_timestamp_on_b: Timestamp::none(),
        };
        let counterparty = get_channel_counterparty();
        let mut packet =
            packet_from_message(&transfer_msg, 1.into(), &counterparty);
        packet.port_id_on_a = counterparty.port_id().clone();
        packet.chan_id_on_a = counterparty.channel_id().cloned().unwrap();
        packet.port_id_on_b = get_port_id();
        packet.chan_id_on_b = get_channel_id();
        let msg = MsgRecvPacket {
            packet: packet.clone(),
            proof_commitment_on_a: dummy_proof(),
            proof_height_on_a: Height::new(0, 1).unwrap(),
            signer: "account0".to_string().into(),
        };

        // the sequence send
        let receipt_key = receipt_key(
            &msg.packet.port_id_on_b,
            &msg.packet.chan_id_on_b,
            msg.packet.seq_on_a,
        );
        let bytes = [1_u8].to_vec();
        state
            .write_log_mut()
            .write(&receipt_key, bytes)
            .expect("write failed");
        keys_changed.insert(receipt_key);
        // packet commitment
        let ack_key = ack_key(
            &packet.port_id_on_b,
            &packet.chan_id_on_b,
            msg.packet.seq_on_a,
        );
        let transfer_ack = AcknowledgementStatus::success(ack_success_b64());
        let acknowledgement: Acknowledgement = transfer_ack.into();
        let bytes = sha2::Sha256::digest(acknowledgement.as_bytes()).to_vec();
        state
            .write_log_mut()
            .write(&ack_key, bytes)
            .expect("write failed");
        keys_changed.insert(ack_key);
        // denom
        let mut coin = transfer_msg.packet_data.token;
        coin.denom.add_trace_prefix(TracePrefix::new(
            packet.port_id_on_b.clone(),
            packet.chan_id_on_b.clone(),
        ));
        let trace_hash = calc_hash(coin.denom.to_string());
        let denom_key = ibc_denom_key(receiver.to_string(), &trace_hash);
        let bytes = coin.denom.to_string().serialize_to_vec();
        state
            .write_log_mut()
            .write(&denom_key, bytes)
            .expect("write failed");
        keys_changed.insert(denom_key);
        let denom_key = ibc_denom_key(nam().to_string(), &trace_hash);
        let bytes = coin.denom.to_string().serialize_to_vec();
        state
            .write_log_mut()
            .write(&denom_key, bytes)
            .expect("write failed");
        keys_changed.insert(denom_key);
        // event
        let recv_event = RecvEvent {
            sender: sender.to_string().into(),
            receiver: receiver.to_string().into(),
            denom: nam().to_string().parse().unwrap(),
            amount: 100u64.into(),
            memo: "memo".to_string().into(),
            success: true,
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(recv_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let denom_trace_event = DenomTraceEvent {
            trace_hash: Some(trace_hash),
            denom: coin.denom,
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(denom_trace_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event = RawIbcEvent::ReceivePacket(ReceivePacket::new(
            msg.packet.clone(),
            Order::Unordered,
            get_connection_id(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event =
            RawIbcEvent::WriteAcknowledgement(WriteAcknowledgement::new(
                packet,
                acknowledgement,
                get_connection_id(),
            ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_ack_packet() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Open channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        // commitment
        let sender = established_address_1();
        let transfer_msg = MsgTransfer {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: nam().to_string().parse().unwrap(),
                    amount: 100u64.into(),
                },
                sender: sender.to_string().into(),
                receiver: "receiver".to_string().into(),
                memo: "memo".to_string().into(),
            },
            timeout_height_on_b: TimeoutHeight::At(Height::new(0, 10).unwrap()),
            timeout_timestamp_on_b: Timestamp::none(),
        };
        let sequence = 1.into();
        let packet = packet_from_message(
            &transfer_msg,
            sequence,
            &get_channel_counterparty(),
        );
        let commitment_key = commitment_key(
            &transfer_msg.port_id_on_a,
            &transfer_msg.chan_id_on_a,
            sequence,
        );
        let commitment = commitment(&packet);
        let bytes = commitment.into_vec();
        state
            .write_log_mut()
            .write(&commitment_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let transfer_ack = AcknowledgementStatus::success(ack_success_b64());
        let msg = MsgAcknowledgement {
            packet: packet.clone(),
            acknowledgement: transfer_ack.clone().into(),
            proof_acked_on_b: dummy_proof(),
            proof_height_on_b: Height::new(0, 1).unwrap(),
            signer: "account0".to_string().into(),
        };

        // delete the commitment
        state
            .write_log_mut()
            .delete(&commitment_key)
            .expect("delete failed");
        keys_changed.insert(commitment_key);
        // event
        let data = serde_json::from_slice::<PacketData>(&packet.data)
            .expect("decoding packet data failed");
        let ack_event = AckEvent {
            sender: data.sender,
            receiver: data.receiver,
            denom: data.token.denom,
            amount: data.token.amount,
            memo: data.memo,
            acknowledgement: transfer_ack,
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(ack_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event = RawIbcEvent::AcknowledgePacket(AcknowledgePacket::new(
            packet,
            Order::Unordered,
            get_connection_id(),
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_timeout_packet() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Open channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        // init the escrow balance
        let balance_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::Ibc));
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&balance_key, amount.serialize_to_vec())
            .expect("write failed");
        // commitment
        let transfer_msg = MsgTransfer {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: nam().to_string().parse().unwrap(),
                    amount: 100u64.into(),
                },
                sender: established_address_1().to_string().into(),
                receiver: "receiver".to_string().into(),
                memo: "memo".to_string().into(),
            },
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: (Timestamp::now() - Duration::new(10, 0))
                .unwrap(),
        };
        let sequence = 1.into();
        let packet = packet_from_message(
            &transfer_msg,
            sequence,
            &get_channel_counterparty(),
        );
        let commitment_key = commitment_key(
            &transfer_msg.port_id_on_a,
            &transfer_msg.chan_id_on_a,
            sequence,
        );
        let commitment = commitment(&packet);
        let bytes = commitment.into_vec();
        state
            .write_log_mut()
            .write(&commitment_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let msg = MsgTimeout {
            packet: packet.clone(),
            next_seq_recv_on_b: sequence,
            proof_unreceived_on_b: dummy_proof(),
            proof_height_on_b: Height::new(0, 1).unwrap(),
            signer: "account0".to_string().into(),
        };

        // delete the commitment
        state
            .write_log_mut()
            .delete(&commitment_key)
            .expect("delete failed");
        keys_changed.insert(commitment_key);
        // event
        let data = serde_json::from_slice::<PacketData>(&packet.data)
            .expect("decoding packet data failed");
        let timeout_event = TimeoutEvent {
            refund_receiver: data.sender,
            refund_denom: data.token.denom,
            refund_amount: data.token.amount,
            memo: data.memo,
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(timeout_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event = RawIbcEvent::TimeoutPacket(TimeoutPacket::new(
            packet,
            Order::Unordered,
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_timeout_on_close_packet() {
        let mut keys_changed = BTreeSet::new();
        let mut state = init_storage();
        insert_init_client(&mut state);

        // insert an open connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec();
        state
            .write_log_mut()
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Open channel
        let channel_key = channel_key(&get_port_id(), &get_channel_id());
        let channel = get_channel(ChanState::Open, Order::Unordered);
        let bytes = channel.encode_vec();
        state
            .write_log_mut()
            .write(&channel_key, bytes)
            .expect("write failed");
        // init the escrow balance
        let balance_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::Ibc));
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&balance_key, amount.serialize_to_vec())
            .expect("write failed");
        // commitment
        let sender = established_address_1();
        let transfer_msg = MsgTransfer {
            port_id_on_a: get_port_id(),
            chan_id_on_a: get_channel_id(),
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: nam().to_string().parse().unwrap(),
                    amount: 100u64.into(),
                },
                sender: sender.to_string().into(),
                receiver: "receiver".to_string().into(),
                memo: "memo".to_string().into(),
            },
            timeout_height_on_b: TimeoutHeight::At(Height::new(0, 10).unwrap()),
            timeout_timestamp_on_b: Timestamp::none(),
        };
        let sequence = 1.into();
        let packet = packet_from_message(
            &transfer_msg,
            sequence,
            &get_channel_counterparty(),
        );
        let commitment_key = commitment_key(
            &transfer_msg.port_id_on_a,
            &transfer_msg.chan_id_on_a,
            sequence,
        );
        let commitment = commitment(&packet);
        let bytes = commitment.into_vec();
        state
            .write_log_mut()
            .write(&commitment_key, bytes)
            .expect("write failed");
        state.write_log_mut().commit_tx();
        state.commit_block().expect("commit failed");
        // for next block
        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state
            .in_mem_mut()
            .begin_block(BlockHash::default(), BlockHeight(2))
            .unwrap();

        // prepare data
        let msg = MsgTimeoutOnClose {
            packet: packet.clone(),
            next_seq_recv_on_b: sequence,
            proof_unreceived_on_b: dummy_proof(),
            proof_close_on_b: dummy_proof(),
            proof_height_on_b: Height::new(0, 1).unwrap(),
            signer: "account0".to_string().into(),
        };

        // delete the commitment
        state
            .write_log_mut()
            .delete(&commitment_key)
            .expect("delete failed");
        keys_changed.insert(commitment_key);
        // event
        let data = serde_json::from_slice::<PacketData>(&packet.data)
            .expect("decoding packet data failed");
        let timeout_event = TimeoutEvent {
            refund_receiver: data.sender,
            refund_denom: data.token.denom,
            refund_amount: data.token.amount,
            memo: data.memo,
        };
        let event = RawIbcEvent::Module(ModuleEvent::from(timeout_event));
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());
        let event = RawIbcEvent::TimeoutPacket(TimeoutPacket::new(
            packet,
            Order::Unordered,
        ));
        let message_event = RawIbcEvent::Message(MessageEvent::Channel);
        state
            .write_log_mut()
            .emit_ibc_event(message_event.try_into().unwrap());
        state
            .write_log_mut()
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(keypair_1());

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }
}
