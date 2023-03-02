//! IBC integration as a native validity predicate

mod context;
mod denom;
mod token;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;

use borsh::BorshDeserialize;
use context::{PseudoExecutionContext, VpValidationContext};
use namada_core::ledger::ibc::storage::{is_ibc_denom_key, is_ibc_key};
use namada_core::ledger::ibc::{
    Error as ActionError, IbcActions, TransferModule,
};
use namada_core::ledger::storage::write_log::StorageModification;
use namada_core::ledger::storage::{self as ledger_storage, StorageHasher};
use namada_core::proto::SignedTxData;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;
use thiserror::Error;
pub use token::{Error as IbcTokenError, IbcToken};

use crate::ledger::native_vp::{self, Ctx, NativeVp, VpEnv};
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
    #[error("Denom store error: {0}")]
    Denom(denom::Error),
    #[error("IBC event error: {0}")]
    IbcEvent(String),
}

/// IBC functions result
pub type VpResult<T> = std::result::Result<T, Error>;

/// IBC VP
pub struct Ibc<'a, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Ibc;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> VpResult<bool> {
        let signed =
            SignedTxData::try_from_slice(tx_data).map_err(Error::Decoding)?;
        let tx_data = &signed.data.ok_or(Error::NoTxData)?;

        // Pseudo execution and compare them
        self.validate_state(tx_data, keys_changed)?;

        // Validate the state according to the given IBC message
        self.validate_with_msg(tx_data)?;

        // Validate the denom store if a denom key has been changed
        if keys_changed.iter().any(is_ibc_denom_key) {
            self.validate_denom(tx_data).map_err(Error::Denom)?;
        }

        Ok(true)
    }
}

impl<'a, DB, H, CA> Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
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
        // TODO 'static issue
        // let module = TransferModule::new(ctx.clone());
        // actions.add_route(module.module_id(), module);
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
            match self
                .ctx
                .read_bytes_post(&key)
                .map_err(Error::NativeVpError)?
            {
                Some(v) => match ctx.borrow().get_changed_value(&key) {
                    Some(StorageModification::Write { value }) => {
                        if v != *value {
                            return Err(Error::StateChange(format!(
                                "The value mismatched: Key {}",
                                key,
                            )));
                        }
                    }
                    _ => {
                        return Err(Error::StateChange(format!(
                            "The value was invalid: Key {}",
                            key
                        )));
                    }
                },
                None => {
                    match ctx.borrow().get_changed_value(&key) {
                        Some(StorageModification::Delete) => {
                            // the key was deleted expectedly
                        }
                        _ => {
                            return Err(Error::StateChange(format!(
                                "The key was deleted unexpectedly: Key {}",
                                key
                            )));
                        }
                    }
                }
            }
        }

        // check the event
        let actual = self.ctx.write_log.get_ibc_events();
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
        let validation_ctx = VpValidationContext::new(self.ctx.post());
        let ctx = Rc::new(RefCell::new(validation_ctx));

        let mut actions = IbcActions::new(ctx.clone());
        // TODO 'static issue
        // let module = TransferModule::new(ctx);
        // actions.add_route(module.module_id(), module);
        actions.validate(tx_data).map_err(Error::IbcAction)
    }
}

impl From<ActionError> for Error {
    fn from(err: ActionError) -> Self {
        Self::IbcAction(err)
    }
}

/// A dummy header used for testing
#[cfg(any(feature = "test", feature = "testing"))]
pub fn get_dummy_header() -> crate::types::storage::Header {
    use crate::tendermint::time::Time as TmTime;
    crate::types::storage::Header {
        hash: crate::types::hash::Hash([0; 32]),
        time: TmTime::now().try_into().unwrap(),
        next_validators_hash: crate::types::hash::Hash([0; 32]),
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::convert::TryFrom;
    use std::str::FromStr;

    use crate::ibc::applications::ics20_fungible_token_transfer::msgs::transfer::MsgTransfer;
    use crate::ibc::core::ics02_client::client_consensus::ConsensusState;
    use crate::ibc::core::ics02_client::client_state::ClientState;
    use crate::ibc::core::ics02_client::client_type::ClientType;
    use crate::ibc::core::ics02_client::header::Header;
    use crate::ibc::core::ics02_client::msgs::create_client::MsgCreateAnyClient;
    use crate::ibc::core::ics02_client::msgs::update_client::MsgUpdateAnyClient;
    use crate::ibc::core::ics03_connection::connection::{
        ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
    };
    use crate::ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
    use crate::ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
    use crate::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
    use crate::ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
    use crate::ibc::core::ics03_connection::version::Version as ConnVersion;
    use crate::ibc::core::ics04_channel::channel::{
        ChannelEnd, Counterparty as ChanCounterparty, Order, State as ChanState,
    };
    use crate::ibc::core::ics04_channel::msgs::acknowledgement::MsgAcknowledgement;
    use crate::ibc::core::ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck;
    use crate::ibc::core::ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm;
    use crate::ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
    use crate::ibc::core::ics04_channel::msgs::chan_open_try::MsgChannelOpenTry;
    use crate::ibc::core::ics04_channel::msgs::recv_packet::MsgRecvPacket;
    use crate::ibc::core::ics04_channel::packet::{Packet, Sequence};
    use crate::ibc::core::ics04_channel::Version as ChanVersion;
    use crate::ibc::core::ics23_commitment::commitment::CommitmentProofBytes;
    use crate::ibc::core::ics24_host::identifier::{
        ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
    };
    use crate::ibc::mock::client_state::{MockClientState, MockConsensusState};
    use crate::ibc::mock::header::MockHeader;
    use crate::ibc::proofs::{ConsensusProof, Proofs};
    use crate::ibc::signer::Signer;
    use crate::ibc::timestamp::Timestamp;
    use crate::ibc::tx_msg::Msg;
    use crate::ibc::Height;
    use crate::ibc_proto::cosmos::base::v1beta1::Coin;
    use namada_core::ledger::storage::testing::TestWlStorage;
    use prost::Message;
    use crate::tendermint::time::Time as TmTime;
    use crate::tendermint_proto::Protobuf;

    use super::get_dummy_header;
    use namada_core::ledger::ibc::actions::{
        self, commitment_prefix, init_connection, make_create_client_event,
        make_open_ack_channel_event, make_open_ack_connection_event,
        make_open_confirm_channel_event, make_open_confirm_connection_event,
        make_open_init_channel_event, make_open_init_connection_event,
        make_open_try_channel_event, make_open_try_connection_event,
        make_send_packet_event, make_update_client_event, packet_from_message,
        try_connection,
    };
    use super::super::storage::{
        ack_key, capability_key, channel_key, client_state_key,
        client_type_key, client_update_height_key, client_update_timestamp_key,
        commitment_key, connection_key, consensus_state_key,
        next_sequence_ack_key, next_sequence_recv_key, next_sequence_send_key,
        port_key, receipt_key,
    };
    use super::*;
    use crate::types::key::testing::keypair_1;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::testing::TestStorage;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::proto::Tx;
    use crate::types::ibc::data::{PacketAck, PacketReceipt};
    use crate::vm::wasm;
    use crate::types::storage::TxIndex;
    use crate::types::storage::{BlockHash, BlockHeight};

    const ADDRESS: Address = Address::Internal(InternalAddress::Ibc);

    fn get_client_id() -> ClientId {
        ClientId::from_str("test_client").expect("Creating a client ID failed")
    }

    fn insert_init_states() -> TestWlStorage {
        let mut wl_storage = TestWlStorage::default();

        // initialize the storage
        super::super::init_genesis_storage(&mut wl_storage);
        // set a dummy header
        wl_storage
            .storage
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        wl_storage
            .storage
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();

        // insert a mock client type
        let client_id = get_client_id();
        let client_type_key = client_type_key(&client_id);
        let client_type = ClientType::Mock.as_str().as_bytes().to_vec();
        wl_storage
            .write_log
            .write(&client_type_key, client_type)
            .expect("write failed");
        // insert a mock client state
        let client_state_key = client_state_key(&get_client_id());
        let height = Height::new(0, 1);
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header).wrap_any();
        let bytes = client_state.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&client_state_key, bytes)
            .expect("write failed");
        // insert a mock consensus state
        let consensus_key = consensus_state_key(&client_id, height);
        let consensus_state = MockConsensusState::new(header).wrap_any();
        let bytes = consensus_state.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&consensus_key, bytes)
            .expect("write failed");
        // insert update time and height
        let client_update_time_key = client_update_timestamp_key(&client_id);
        let bytes = TmTime::now().encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&client_update_time_key, bytes)
            .expect("write failed");
        let client_update_height_key = client_update_height_key(&client_id);
        let host_height = Height::new(10, 100);
        wl_storage
            .write_log
            .write(
                &client_update_height_key,
                host_height.encode_vec().expect("encoding failed"),
            )
            .expect("write failed");
        wl_storage.write_log.commit_tx();

        wl_storage
    }

    fn get_connection_id() -> ConnectionId {
        ConnectionId::new(0)
    }

    fn get_port_channel_id() -> PortChannelId {
        PortChannelId {
            port_id: get_port_id(),
            channel_id: get_channel_id(),
        }
    }

    fn get_port_id() -> PortId {
        PortId::from_str("test_port").unwrap()
    }

    fn get_channel_id() -> ChannelId {
        ChannelId::from_str("channel-42").unwrap()
    }

    fn get_connection(conn_state: ConnState) -> ConnectionEnd {
        ConnectionEnd::new(
            conn_state,
            get_client_id(),
            get_conn_counterparty(),
            vec![ConnVersion::default()],
            Duration::new(100, 0),
        )
    }

    fn get_conn_counterparty() -> ConnCounterparty {
        let counterpart_client_id =
            ClientId::from_str("counterpart_test_client")
                .expect("Creating a client ID failed");
        let counterpart_conn_id =
            ConnectionId::from_str("counterpart_test_connection")
                .expect("Creating a connection ID failed");
        ConnCounterparty::new(
            counterpart_client_id,
            Some(counterpart_conn_id),
            commitment_prefix(),
        )
    }

    fn get_channel(channel_state: ChanState, order: Order) -> ChannelEnd {
        ChannelEnd::new(
            channel_state,
            order,
            get_channel_counterparty(),
            vec![get_connection_id()],
            ChanVersion::ics20(),
        )
    }

    fn get_channel_counterparty() -> ChanCounterparty {
        let counterpart_port_id = PortId::from_str("counterpart_test_port")
            .expect("Creating a port ID failed");
        let counterpart_channel_id = ChannelId::from_str("channel-0")
            .expect("Creating a channel ID failed");
        ChanCounterparty::new(counterpart_port_id, Some(counterpart_channel_id))
    }

    fn set_port(write_log: &mut WriteLog, index: u64) {
        let port_key = port_key(&get_port_id());
        write_log
            .write(&port_key, index.to_be_bytes().to_vec())
            .expect("write failed");
        // insert to the reverse map
        let cap_key = capability_key(index);
        let port_id = get_port_id();
        let bytes = port_id.as_str().as_bytes().to_vec();
        write_log.write(&cap_key, bytes).expect("write failed");
    }

    fn get_next_seq(storage: &TestStorage, key: &Key) -> Sequence {
        let (val, _) = storage.read(key).expect("read failed");
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

    fn increment_seq(write_log: &mut WriteLog, key: &Key, seq: Sequence) {
        let seq_num = u64::from(seq.increment());
        write_log
            .write(key, seq_num.to_be_bytes().to_vec())
            .expect("write failed");
    }

    #[test]
    fn test_create_client() {
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();

        let height = Height::new(0, 1);
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_id = get_client_id();
        // insert client type, state, and consensus state
        let client_type_key = client_type_key(&client_id);
        let client_type = ClientType::Mock.as_str().as_bytes().to_vec();
        write_log
            .write(&client_type_key, client_type)
            .expect("write failed");
        let client_state = MockClientState::new(header).wrap_any();
        let consensus_state = MockConsensusState::new(header).wrap_any();
        let msg = MsgCreateAnyClient {
            client_state: client_state.clone(),
            consensus_state: consensus_state.clone(),
            signer: Signer::new("account0"),
        };
        let client_state_key = client_state_key(&get_client_id());
        let bytes = client_state.encode_vec().expect("encoding failed");
        write_log
            .write(&client_state_key, bytes)
            .expect("write failed");
        let consensus_key = consensus_state_key(&client_id, height);
        let bytes = consensus_state.encode_vec().expect("encoding failed");
        write_log
            .write(&consensus_key, bytes)
            .expect("write failed");
        // insert update time and height
        let client_update_time_key = client_update_timestamp_key(&client_id);
        let bytes = TmTime::now().encode_vec().expect("encoding failed");
        write_log
            .write(&client_update_time_key, bytes)
            .expect("write failed");
        let client_update_height_key = client_update_height_key(&client_id);
        let host_height = Height::new(10, 100);
        write_log
            .write(
                &client_update_height_key,
                host_height.encode_vec().expect("encoding failed"),
            )
            .expect("write failed");

        let event = make_create_client_event(&get_client_id(), &msg);
        write_log.emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(client_state_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &storage,
            &write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_create_client_fail() {
        let storage = TestStorage::default();
        let write_log = WriteLog::default();
        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        let client_state_key = client_state_key(&get_client_id());
        keys_changed.insert(client_state_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &storage,
            &write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        // this should fail because no state is stored
        let result = ibc
            .validate_tx(tx.data.as_ref().unwrap(), &keys_changed, &verifiers)
            .unwrap_err();
        assert_matches!(
            result,
            Error::ClientError(client::Error::InvalidStateChange(_))
        );
    }

    #[test]
    fn test_update_client() {
        let mut wl_storage = insert_init_states();
        wl_storage.commit_block().expect("commit failed");

        // update the client
        let client_id = get_client_id();
        let client_state_key = client_state_key(&get_client_id());
        let height = Height::new(1, 11);
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let msg = MsgUpdateAnyClient {
            client_id: client_id.clone(),
            header: header.wrap_any(),
            signer: Signer::new("account0"),
        };
        let client_state = MockClientState::new(header).wrap_any();
        let bytes = client_state.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&client_state_key, bytes)
            .expect("write failed");
        let consensus_key = consensus_state_key(&client_id, height);
        let consensus_state = MockConsensusState::new(header).wrap_any();
        let bytes = consensus_state.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&consensus_key, bytes)
            .expect("write failed");
        let event = make_update_client_event(&client_id, &msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());
        // update time and height for this updating
        let key = client_update_timestamp_key(&client_id);
        wl_storage
            .write_log
            .write(&key, TmTime::now().encode_vec().expect("encoding failed"))
            .expect("write failed");
        let key = client_update_height_key(&client_id);
        wl_storage
            .write_log
            .write(
                &key,
                Height::new(10, 101).encode_vec().expect("encoding failed"),
            )
            .expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(client_state_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_init_connection() {
        let mut wl_storage = insert_init_states();
        wl_storage.commit_block().expect("commit failed");

        // prepare a message
        let msg = MsgConnectionOpenInit {
            client_id: get_client_id(),
            counterparty: get_conn_counterparty(),
            version: None,
            delay_period: Duration::new(100, 0),
            signer: Signer::new("account0"),
        };

        // insert an INIT connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = init_connection(&msg);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        let event = make_open_init_connection_event(&conn_id, &msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(conn_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_init_connection_fail() {
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();

        // prepare data
        let msg = MsgConnectionOpenInit {
            client_id: get_client_id(),
            counterparty: get_conn_counterparty(),
            version: None,
            delay_period: Duration::new(100, 0),
            signer: Signer::new("account0"),
        };

        // insert an Init connection
        let conn_key = connection_key(&get_connection_id());
        let conn = init_connection(&msg);
        let bytes = conn.encode_vec().expect("encoding failed");
        write_log.write(&conn_key, bytes).expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(conn_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &storage,
            &write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should fail because no client exists
        let result = ibc
            .validate_tx(tx.data.as_ref().unwrap(), &keys_changed, &verifiers)
            .unwrap_err();
        assert_matches!(
            result,
            Error::ConnectionError(connection::Error::InvalidClient(_))
        );
    }

    #[test]
    fn test_try_connection() {
        let mut wl_storage = insert_init_states();
        wl_storage
            .write_log
            .commit_block(&mut wl_storage.storage)
            .expect("commit failed");

        // prepare data
        let height = Height::new(0, 1);
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header).wrap_any();
        let proof_conn = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_conn,
            Some(proof_client),
            Some(proof_consensus),
            None,
            Height::new(0, 1),
        )
        .unwrap();
        let msg = MsgConnectionOpenTry {
            previous_connection_id: None,
            client_id: get_client_id(),
            client_state: Some(client_state),
            counterparty: get_conn_counterparty(),
            counterparty_versions: vec![ConnVersion::default()],
            proofs,
            delay_period: Duration::new(100, 0),
            signer: Signer::new("account0"),
        };

        // insert a TryOpen connection
        let conn_id = get_connection_id();
        let conn_key = connection_key(&conn_id);
        let conn = try_connection(&msg);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        let event = make_open_try_connection_event(&conn_id, &msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(conn_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        // this should return true because state has been stored
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_ack_connection() {
        let mut wl_storage = insert_init_states();
        // insert an Init connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Init);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage
            .write_log
            .commit_block(&mut wl_storage.storage)
            .expect("commit failed");
        // update the connection to Open
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");

        // prepare data
        let height = Height::new(0, 1);
        let header = MockHeader {
            height,
            timestamp: Timestamp::now(),
        };
        let client_state = MockClientState::new(header).wrap_any();
        let counterparty = get_conn_counterparty();
        let proof_conn = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_conn,
            Some(proof_client),
            Some(proof_consensus),
            None,
            Height::new(0, 1),
        )
        .unwrap();
        let tx_code = vec![];
        let msg = MsgConnectionOpenAck {
            connection_id: get_connection_id(),
            counterparty_connection_id: counterparty
                .connection_id()
                .unwrap()
                .clone(),
            client_state: Some(client_state),
            proofs,
            version: ConnVersion::default(),
            signer: Signer::new("account0"),
        };
        let event = make_open_ack_connection_event(&msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(conn_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_confirm_connection() {
        let mut wl_storage = insert_init_states();
        // insert a TryOpen connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::TryOpen);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");
        // update the connection to Open
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");

        // prepare data
        let height = Height::new(0, 1);
        let proof_conn = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_conn,
            Some(proof_client),
            Some(proof_consensus),
            None,
            height,
        )
        .unwrap();
        let tx_code = vec![];
        let msg = MsgConnectionOpenConfirm {
            connection_id: get_connection_id(),
            proofs,
            signer: Signer::new("account0"),
        };
        let event = make_open_confirm_connection_event(&msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(conn_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_init_channel() {
        let mut wl_storage = insert_init_states();
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        wl_storage.commit_block().expect("commit failed");

        // prepare data
        let channel = get_channel(ChanState::Init, Order::Ordered);
        let msg = MsgChannelOpenInit {
            port_id: get_port_id(),
            channel: channel.clone(),
            signer: Signer::new("account0"),
        };

        // insert an Init channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        let event = make_open_init_channel_event(&get_channel_id(), &msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(channel_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_try_channel() {
        let mut wl_storage = insert_init_states();
        // insert an opend connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        wl_storage.commit_block().expect("commit failed");

        // prepare data
        let height = Height::new(0, 1);
        let proof_channel = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_channel,
            Some(proof_client),
            Some(proof_consensus),
            None,
            height,
        )
        .unwrap();
        let channel = get_channel(ChanState::TryOpen, Order::Ordered);
        let msg = MsgChannelOpenTry {
            port_id: get_port_id(),
            previous_channel_id: None,
            channel: channel.clone(),
            counterparty_version: ChanVersion::ics20(),
            proofs,
            signer: Signer::new("account0"),
        };

        // insert a TryOpen channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        let event = make_open_try_channel_event(&get_channel_id(), &msg);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(channel_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_ack_channel() {
        let mut wl_storage = insert_init_states();
        // insert an opend connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an Init channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Init, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // prepare data
        let height = Height::new(0, 1);
        let proof_channel = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_channel,
            Some(proof_client),
            Some(proof_consensus),
            None,
            height,
        )
        .unwrap();
        let msg = MsgChannelOpenAck {
            port_id: get_port_id(),
            channel_id: get_channel_id(),
            counterparty_channel_id: *get_channel_counterparty()
                .channel_id()
                .unwrap(),
            counterparty_version: ChanVersion::ics20(),
            proofs,
            signer: Signer::new("account0"),
        };

        // update the channel to Open
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        let event =
            make_open_ack_channel_event(&msg, &channel).expect("no connection");
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(channel_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_confirm_channel() {
        let mut wl_storage = insert_init_states();
        // insert an opend connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert a TryOpen channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::TryOpen, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // prepare data
        let height = Height::new(0, 1);
        let proof_channel = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_client = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proof_consensus = ConsensusProof::new(
            CommitmentProofBytes::try_from(vec![0]).unwrap(),
            height,
        )
        .unwrap();
        let proofs = Proofs::new(
            proof_channel,
            Some(proof_client),
            Some(proof_consensus),
            None,
            height,
        )
        .unwrap();
        let msg = MsgChannelOpenConfirm {
            port_id: get_port_id(),
            channel_id: get_channel_id(),
            proofs,
            signer: Signer::new("account0"),
        };

        // update the channel to Open
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");

        let event = make_open_confirm_channel_event(&msg, &channel)
            .expect("no connection");
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(channel_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_port() {
        let mut wl_storage = insert_init_states();
        // insert a port
        set_port(&mut wl_storage.write_log, 0);

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(port_key(&get_port_id()));

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_capability() {
        let mut wl_storage = insert_init_states();
        // insert a port
        let index = 0;
        set_port(&mut wl_storage.write_log, index);

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        let cap_key = capability_key(index);
        keys_changed.insert(cap_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_seq_send() {
        let mut wl_storage = insert_init_states();
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an opened channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // prepare a message
        let timeout_timestamp =
            (Timestamp::now() + Duration::from_secs(100)).unwrap();
        let msg = MsgTransfer {
            source_port: get_port_id(),
            source_channel: get_channel_id(),
            token: Some(Coin {
                denom: "NAM".to_string(),
                amount: 100u64.to_string(),
            }),
            sender: Signer::new("sender"),
            receiver: Signer::new("receiver"),
            timeout_height: Height::new(0, 100),
            timeout_timestamp,
        };

        // get and increment the nextSequenceSend
        let seq_key = next_sequence_send_key(&get_port_channel_id());
        let sequence = get_next_seq(&wl_storage.storage, &seq_key);
        increment_seq(&mut wl_storage.write_log, &seq_key, sequence);
        // make a packet
        let counterparty = get_channel_counterparty();
        let packet = packet_from_message(&msg, sequence, &counterparty);
        // insert a commitment
        let commitment = actions::commitment(&packet);
        let key = commitment_key(&get_port_id(), &get_channel_id(), sequence);
        wl_storage
            .write_log
            .write(&key, commitment.into_vec())
            .expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(seq_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_seq_recv() {
        let mut wl_storage = insert_init_states();
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an opened channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // get and increment the nextSequenceRecv
        let seq_key = next_sequence_recv_key(&get_port_channel_id());
        let sequence = get_next_seq(&wl_storage.storage, &seq_key);
        increment_seq(&mut wl_storage.write_log, &seq_key, sequence);
        // make a packet and data
        let counterparty = get_channel_counterparty();
        let timeout_timestamp =
            (Timestamp::now() + Duration::from_secs(100)).unwrap();
        let packet = Packet {
            sequence,
            source_port: counterparty.port_id().clone(),
            source_channel: *counterparty.channel_id().unwrap(),
            destination_port: get_port_id(),
            destination_channel: get_channel_id(),
            data: vec![0],
            timeout_height: Height::new(0, 100),
            timeout_timestamp,
        };
        let proof_packet = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proofs =
            Proofs::new(proof_packet, None, None, None, Height::new(0, 1))
                .unwrap();
        let msg = MsgRecvPacket {
            packet,
            proofs,
            signer: Signer::new("account0"),
        };

        // insert a receipt and an ack
        let key = receipt_key(&get_port_id(), &get_channel_id(), sequence);
        wl_storage
            .write_log
            .write(&key, PacketReceipt::default().as_bytes().to_vec())
            .expect("write failed");
        let key = ack_key(&get_port_id(), &get_channel_id(), sequence);
        let ack = PacketAck::result_success().encode_to_vec();
        wl_storage.write_log.write(&key, ack).expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(seq_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_seq_ack() {
        let mut wl_storage = insert_init_states();
        // get the nextSequenceAck
        let seq_key = next_sequence_ack_key(&get_port_channel_id());
        let sequence = get_next_seq(&wl_storage.storage, &seq_key);
        // make a packet
        let counterparty = get_channel_counterparty();
        let timeout_timestamp =
            (Timestamp::now() + core::time::Duration::from_secs(100)).unwrap();
        let packet = Packet {
            sequence,
            source_port: get_port_id(),
            source_channel: get_channel_id(),
            destination_port: counterparty.port_id().clone(),
            destination_channel: *counterparty.channel_id().unwrap(),
            data: vec![0],
            timeout_height: Height::new(0, 100),
            timeout_timestamp,
        };
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an opened channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        // insert a commitment
        let commitment = actions::commitment(&packet);
        let commitment_key =
            commitment_key(&get_port_id(), &get_channel_id(), sequence);
        wl_storage
            .write_log
            .write(&commitment_key, commitment.into_vec())
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // prepare data
        let ack = PacketAck::result_success().encode_to_vec();
        let proof_packet = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proofs =
            Proofs::new(proof_packet, None, None, None, Height::new(0, 1))
                .unwrap();
        let msg = MsgAcknowledgement {
            packet,
            acknowledgement: ack.into(),
            proofs,
            signer: Signer::new("account0"),
        };

        // increment the nextSequenceAck
        increment_seq(&mut wl_storage.write_log, &seq_key, sequence);
        // delete the commitment
        wl_storage
            .write_log
            .delete(&commitment_key)
            .expect("delete failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(seq_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_commitment() {
        let mut wl_storage = insert_init_states();
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an opened channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage.commit_block().expect("commit failed");

        // prepare a message
        let timeout_timestamp =
            (Timestamp::now() + Duration::from_secs(100)).unwrap();
        let msg = MsgTransfer {
            source_port: get_port_id(),
            source_channel: get_channel_id(),
            token: Some(Coin {
                denom: "NAM".to_string(),
                amount: 100u64.to_string(),
            }),
            sender: Signer::new("sender"),
            receiver: Signer::new("receiver"),
            timeout_height: Height::new(0, 100),
            timeout_timestamp,
        };

        // make a packet
        let seq_key = next_sequence_send_key(&get_port_channel_id());
        let sequence = get_next_seq(&wl_storage.storage, &seq_key);
        let counterparty = get_channel_counterparty();
        let packet = packet_from_message(&msg, sequence, &counterparty);
        // insert a commitment
        let commitment = actions::commitment(&packet);
        let commitment_key = commitment_key(
            &packet.source_port,
            &packet.source_channel,
            sequence,
        );
        wl_storage
            .write_log
            .write(&commitment_key, commitment.into_vec())
            .expect("write failed");
        let event = make_send_packet_event(packet);
        wl_storage
            .write_log
            .emit_ibc_event(event.try_into().unwrap());

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(commitment_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );
        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_receipt() {
        let mut wl_storage = insert_init_states();
        // insert an opened connection
        let conn_key = connection_key(&get_connection_id());
        let conn = get_connection(ConnState::Open);
        let bytes = conn.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&conn_key, bytes)
            .expect("write failed");
        // insert an opened channel
        set_port(&mut wl_storage.write_log, 0);
        let channel_key = channel_key(&get_port_channel_id());
        let channel = get_channel(ChanState::Open, Order::Ordered);
        let bytes = channel.encode_vec().expect("encoding failed");
        wl_storage
            .write_log
            .write(&channel_key, bytes)
            .expect("write failed");
        wl_storage.write_log.commit_tx();
        wl_storage
            .write_log
            .commit_block(&mut wl_storage.storage)
            .expect("commit failed");

        // make a packet and data
        let counterparty = get_channel_counterparty();
        let timeout_timestamp =
            (Timestamp::now() + Duration::from_secs(100)).unwrap();
        let packet = Packet {
            sequence: Sequence::from(1),
            source_port: counterparty.port_id().clone(),
            source_channel: *counterparty.channel_id().unwrap(),
            destination_port: get_port_id(),
            destination_channel: get_channel_id(),
            data: vec![0],
            timeout_height: Height::new(0, 100),
            timeout_timestamp,
        };
        let proof_packet = CommitmentProofBytes::try_from(vec![0]).unwrap();
        let proofs =
            Proofs::new(proof_packet, None, None, None, Height::new(0, 1))
                .unwrap();
        let msg = MsgRecvPacket {
            packet,
            proofs,
            signer: Signer::new("account0"),
        };

        // insert a receipt and an ack
        let receipt_key = receipt_key(
            &msg.packet.destination_port,
            &msg.packet.destination_channel,
            msg.packet.sequence,
        );
        wl_storage
            .write_log
            .write(&receipt_key, PacketReceipt::default().as_bytes().to_vec())
            .expect("write failed");
        let ack_key = ack_key(
            &msg.packet.destination_port,
            &msg.packet.destination_channel,
            msg.packet.sequence,
        );
        let ack = PacketAck::result_success().encode_to_vec();
        wl_storage
            .write_log
            .write(&ack_key, ack)
            .expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(receipt_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }

    #[test]
    fn test_validate_ack() {
        let mut wl_storage = insert_init_states();

        // insert a receipt and an ack
        let receipt_key =
            receipt_key(&get_port_id(), &get_channel_id(), Sequence::from(1));
        wl_storage
            .write_log
            .write(&receipt_key, PacketReceipt::default().as_bytes().to_vec())
            .expect("write failed");
        let ack_key =
            ack_key(&get_port_id(), &get_channel_id(), Sequence::from(1));
        let ack = PacketAck::result_success().encode_to_vec();
        wl_storage
            .write_log
            .write(&ack_key, ack)
            .expect("write failed");

        let tx_index = TxIndex::default();
        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data)).sign(&keypair_1());
        let gas_meter = VpGasMeter::new(0);
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let mut keys_changed = BTreeSet::new();
        keys_changed.insert(ack_key);

        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &tx_index,
            gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let ibc = Ibc { ctx };
        assert!(
            ibc.validate_tx(
                tx.data.as_ref().unwrap(),
                &keys_changed,
                &verifiers
            )
            .expect("validation failed")
        );
    }
}
