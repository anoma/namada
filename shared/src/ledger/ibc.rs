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

    fn init_genesis_storage<DB, H>(_storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
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
        for key in keys_changed {
            if !key.is_ibc_key() {
                continue;
            }

            match get_ibc_prefix(key) {
                IbcPrefix::CLIENT => {
                    let client_id = get_client_id(key)?;
                    match get_client_state_change(ctx, &client_id)? {
                        StateChange::Created => {
                            if !validate_created_client(ctx, &client_id)? {
                                return Ok(false);
                            }
                        }
                        StateChange::Updated => {
                            if !validate_updated_client(ctx, &client_id)? {
                                return Ok(false);
                            }
                        }
                        _ => {
                            return Ok(false);
                        }
                    }
                }
                IbcPrefix::CONNECTION => {}
                IbcPrefix::CHANNEL => {}
                IbcPrefix::PACKET => {}
                IbcPrefix::UNKNOWN => {
                    return Ok(false);
                }
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
    CLIENT,
    CONNECTION,
    CHANNEL,
    PACKET,
    UNKNOWN,
}

fn get_ibc_prefix(key: &Key) -> IbcPrefix {
    match &*key.segments[1].raw() {
        "clients" => IbcPrefix::CLIENT,
        "connections" => IbcPrefix::CONNECTION,
        "channelEnds" => IbcPrefix::CHANNEL,
        "packets" => IbcPrefix::PACKET,
        _ => IbcPrefix::UNKNOWN,
    }
}

fn get_client_id(key: &Key) -> Result<ClientId> {
    ClientId::from_str(&key.segments[2].raw())
        .map_err(|e| RuntimeError::IbcDecodingError(e.to_string()))
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
    } else {
        if ctx.has_key_post(&key)? {
            Ok(StateChange::Created)
        } else {
            Ok(StateChange::NotExists)
        }
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
    let client_state = match ctx.client_state(&client_id) {
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
    match ctx.consensus_state(client_id, height) {
        Some(_) => Ok(true),
        None => {
            tracing::info!(
                "the consensus state of ID {} doesn't exist",
                client_id
            );
            return Ok(false);
        }
    }
}

fn validate_updated_client<DB, H>(
    _ctx: &mut Ctx<DB, H>,
    _id: &ClientId,
) -> Result<bool>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::testing::TestStorage;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::proto::Tx;

    #[test]
    fn test_create_client() {
        let storage = TestStorage::default();
        let write_log = WriteLog::default();

        let tx_code = vec![];
        let tx_data = vec![];
        let tx = Tx::new(tx_code, Some(tx_data.clone()));
        let gas_meter = VpGasMeter::new(0);
        let mut ctx = Ctx::new(&storage, &write_log, &tx, gas_meter);

        let client_id = ClientId::from_str("test_client")
            .expect("Creating a client ID failed");
        let path = Path::ClientState(client_id.clone()).to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client state failed");

        let mut keys_changed = HashSet::new();
        keys_changed.insert(key);

        let verifiers = HashSet::new();

        // this should return false because no state is stored
        match Ibc::validate_tx(&mut ctx, &tx_data, &keys_changed, &verifiers) {
            Ok(false) => {}
            _ => panic!("unexpected result"),
        }
    }
}
