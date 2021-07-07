//! IBC integration as a native validity predicate

use std::collections::HashSet;
use std::str::FromStr;

use ibc::ics02_client::context::ClientReader;
use ibc::ics24_host::identifier::ClientId;
use ibc::ics24_host::Path;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::ledger::vp_env::{Result, RuntimeError};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{Key, KeySeg};

/// IBC VP
pub struct Ibc;

impl NativeVp for Ibc {
    const ADDR: InternalAddress = InternalAddress::Ibc;

    fn init_genesis_storage<DB, H>(storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
        // the client counter
        let path = "clients/counter".to_owned();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client counter failed");
        let value = crate::ledger::storage::types::encode(&0);
        storage
            .write(&key, value)
            .expect("Unable to write the initial client counter");
    }

    fn validate_tx<DB, H>(
        ctx: &mut Ctx<DB, H>,
        _tx_data: &[u8],
        keys_changed: &HashSet<Key>,
        _verifiers: &HashSet<Address>,
    ) -> Result<bool>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        let mut clients = HashSet::new();

        for key in keys_changed {
            if !key.is_ibc_key() {
                continue;
            }

            let accepted = match get_ibc_prefix(key) {
                IbcPrefix::Client => {
                    let client_id = get_client_id(key)?;
                    if !clients.insert(client_id.clone()) {
                        // this client has been checked
                        continue;
                    }
                    match get_client_state_change(ctx, &client_id)? {
                        StateChange::Created => {
                            validate_created_client(ctx, &client_id)?
                        }
                        StateChange::Updated => {
                            validate_updated_client(ctx, &client_id)?
                        }
                        _ => {
                            tracing::info!(
                                "unexpected state change for an IBC client: \
                                 key {}",
                                key
                            );
                            false
                        }
                    }
                }
                // TODO implement validations for modules
                IbcPrefix::Connection => false,
                IbcPrefix::Channel => false,
                IbcPrefix::Packet => false,
                IbcPrefix::Unknown => false,
            };
            if !accepted {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

enum StateChange {
    Created,
    Updated,
    Deleted,
    NotExists,
}

enum IbcPrefix {
    Client,
    Connection,
    Channel,
    Packet,
    Unknown,
}

fn get_ibc_prefix(key: &Key) -> IbcPrefix {
    match &*key.segments[1].raw() {
        "clients" => IbcPrefix::Client,
        "connections" => IbcPrefix::Connection,
        "channelEnds" => IbcPrefix::Channel,
        "packets" => IbcPrefix::Packet,
        _ => IbcPrefix::Unknown,
    }
}

fn get_client_id(key: &Key) -> Result<ClientId> {
    ClientId::from_str(&key.segments[2].raw())
        .map_err(|e| RuntimeError::IbcKeyError(e.to_string()))
}

fn get_client_state_change<DB, H>(
    ctx: &mut Ctx<DB, H>,
    client_id: &ClientId,
) -> Result<StateChange>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    let path = Path::ClientState(client_id.clone()).to_string();
    let key =
        Key::ibc_key(path).expect("Creating a key for a client type failed");
    if ctx.has_key_pre(&key)? {
        if ctx.has_key_post(&key)? {
            Ok(StateChange::Updated)
        } else {
            Ok(StateChange::Deleted)
        }
    } else if ctx.has_key_post(&key)? {
        Ok(StateChange::Created)
    } else {
        Ok(StateChange::NotExists)
    }
}

fn validate_created_client<DB, H>(
    ctx: &mut Ctx<DB, H>,
    client_id: &ClientId,
) -> Result<bool>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    let client_type = match ctx.client_type(client_id) {
        Some(t) => t,
        None => {
            tracing::info!("the client type of ID {} doesn't exist", client_id);
            return Ok(false);
        }
    };
    let client_state = match ctx.client_state(client_id) {
        Some(s) => s,
        None => {
            tracing::info!(
                "the client state of ID {} doesn't exist",
                client_id
            );
            return Ok(false);
        }
    };
    let height = client_state.latest_height();
    let consensus_state = match ctx.consensus_state(client_id, height) {
        Some(c) => c,
        None => {
            tracing::info!(
                "the consensus state of ID {} doesn't exist",
                client_id
            );
            return Ok(false);
        }
    };
    Ok(client_type == client_state.client_type()
        && client_type == consensus_state.client_type())
}

fn validate_updated_client<DB, H>(
    _ctx: &mut Ctx<DB, H>,
    _id: &ClientId,
) -> Result<bool>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    // TODO: validate UpdateClient and UpgradeClient
    Ok(false)
}

#[cfg(test)]
mod tests {
    use ibc::ics02_client::client_consensus::ConsensusState;
    use ibc::ics02_client::client_state::ClientState;
    use ibc::mock::client_state::{MockClientState, MockConsensusState};
    use ibc::mock::header::MockHeader;
    use ibc::Height;
    use tendermint_proto::Protobuf;

    use super::*;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::testing::TestStorage;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::proto::Tx;

    fn get_client_id() -> ClientId {
        ClientId::from_str("test_client").expect("Creating a client ID failed")
    }

    fn get_client_type_key() -> Key {
        let client_id = get_client_id();
        let path = Path::ClientType(client_id).to_string();
        Key::ibc_key(path).expect("Creating a key for a client type failed")
    }

    fn get_client_state_key() -> Key {
        let client_id = get_client_id();
        let path = Path::ClientState(client_id).to_string();
        Key::ibc_key(path).expect("Creating a key for a client state failed")
    }

    fn get_consensus_state_key(height: Height) -> Key {
        let path = Path::ClientConsensusState {
            client_id: get_client_id(),
            epoch: height.revision_number,
            height: height.revision_height,
        }
        .to_string();
        Key::ibc_key(path)
            .expect("Creating a key for a consensus state shouldn't fail")
    }

    #[test]
    fn test_create_client() {
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();

        // insert a mock client type
        let client_type_key = get_client_type_key();
        // `ClientType::Mock` cannot be decoded in ibc-rs for now
        let client_type = "mock".to_string();
        write_log
            .write(
                &client_type_key,
                crate::ledger::storage::types::encode(&client_type),
            )
            .expect("write failed");
        // insert a mock client state
        let client_state_key = get_client_state_key();
        let height = Height::new(1, 10);
        let header = MockHeader::new(height);
        let client_state = MockClientState(header).wrap_any();
        let bytes = client_state.encode_vec().expect("encoding failed");
        write_log
            .write(&client_state_key, bytes)
            .expect("write failed");
        // insert a mock consensus state
        let consensus_key = get_consensus_state_key(height);
        let consensus_state = MockConsensusState(header).wrap_any();
        let bytes = consensus_state.encode_vec().expect("encoding failed");
        write_log
            .write(&consensus_key, bytes)
            .expect("write failed");
        write_log.commit_tx();

        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data.clone()));
        let gas_meter = VpGasMeter::new(0);
        let mut ctx = Ctx::new(&storage, &write_log, &tx, gas_meter);

        let mut keys_changed = HashSet::new();
        keys_changed.insert(client_state_key);

        let verifiers = HashSet::new();

        // this should return true because state has been stored
        assert!(
            Ibc::validate_tx(&mut ctx, &tx_data, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_create_client_fail() {
        let storage = TestStorage::default();
        let write_log = WriteLog::default();
        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data.clone()));
        let gas_meter = VpGasMeter::new(0);
        let mut ctx = Ctx::new(&storage, &write_log, &tx, gas_meter);

        let mut keys_changed = HashSet::new();
        keys_changed.insert(get_client_state_key());

        let verifiers = HashSet::new();

        // this should return false because no state is stored
        assert!(
            !Ibc::validate_tx(&mut ctx, &tx_data, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }
}
