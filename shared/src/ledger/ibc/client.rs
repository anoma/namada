//! IBC validity predicate for client module

use std::str::FromStr;

use borsh::BorshDeserialize;
use ibc::ics02_client::client_consensus::AnyConsensusState;
use ibc::ics02_client::client_def::{AnyClient, ClientDef};
use ibc::ics02_client::client_state::AnyClientState;
use ibc::ics02_client::client_type::ClientType;
use ibc::ics02_client::context::ClientReader;
use ibc::ics02_client::height::Height;
use ibc::ics24_host::identifier::ClientId;
use ibc::ics24_host::Path;
use tendermint_proto::Protobuf;

use super::{Error, Ibc, Result, StateChange};
use crate::ledger::storage::{self, StorageHasher};
use crate::types::ibc::{ClientUpdateData, ClientUpgradeData};
use crate::types::storage::{Key, KeySeg};

impl<'a, DB, H> Ibc<'a, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    pub(super) fn validate_client(
        &self,
        client_id: &ClientId,
        tx_data: &[u8],
    ) -> Result<bool> {
        match self.get_client_state_change(client_id)? {
            StateChange::Created => self.validate_created_client(client_id),
            StateChange::Updated => {
                self.validate_updated_client(client_id, tx_data)
            }
            _ => {
                tracing::info!(
                    "unexpected state change for an IBC client: {}",
                    client_id
                );
                Ok(false)
            }
        }
    }

    /// Returns the client ID after #IBC/clients
    pub(super) fn get_client_id(key: &Key) -> Result<ClientId> {
        match key.segments.get(2) {
            Some(id) => ClientId::from_str(&id.raw())
                .map_err(|e| Error::KeyError(e.to_string())),
            None => Err(Error::KeyError(format!(
                "The client key doesn't have a client ID: {}",
                key
            ))),
        }
    }

    fn get_client_state_change(
        &self,
        client_id: &ClientId,
    ) -> Result<StateChange> {
        let path = Path::ClientState(client_id.clone()).to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client type failed");
        self.get_state_change(&key)
    }

    fn validate_created_client(&self, client_id: &ClientId) -> Result<bool> {
        let client_type = match self.client_type(client_id) {
            Some(t) => t,
            None => {
                tracing::info!(
                    "the client type of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };
        let client_state = match ClientReader::client_state(self, client_id) {
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
        let consensus_state = match self.consensus_state(client_id, height) {
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

    fn validate_updated_client(
        &self,
        client_id: &ClientId,
        tx_data: &[u8],
    ) -> Result<bool> {
        // check the type of data in tx_data
        match ClientUpdateData::try_from_slice(tx_data) {
            Ok(data) => {
                // "UpdateClient"
                self.verify_update_client(client_id, data)
            }
            Err(_) => match ClientUpgradeData::try_from_slice(tx_data) {
                Ok(data) => {
                    // "UpgradeClient"
                    self.verify_upgrade_client(client_id, data)
                }
                Err(e) => Err(Error::DecodingTxDataError(e)),
            },
        }
    }

    fn verify_update_client(
        &self,
        client_id: &ClientId,
        data: ClientUpdateData,
    ) -> Result<bool> {
        let id = data.client_id()?;
        if id != *client_id {
            tracing::info!(
                "the client ID is mismatched: {} in the tx data, {} in the key",
                id,
                client_id,
            );
            return Ok(false);
        }

        // check the posterior states
        let client_state = match ClientReader::client_state(self, client_id) {
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
        let consensus_state = match self.consensus_state(client_id, height) {
            Some(s) => s,
            None => {
                tracing::info!(
                    "the consensus state of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };
        // check the prior states
        let prev_client_state = match self.client_state_pre(client_id) {
            Some(s) => s,
            None => {
                tracing::info!(
                    "the prior client state of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };
        let prev_consensus_state = match self
            .consensus_state_pre(client_id, prev_client_state.latest_height())
        {
            Some(s) => s,
            None => {
                tracing::info!(
                    "the prior consensus state of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };

        let client = AnyClient::from_client_type(client_state.client_type());
        let headers = data.headers()?;
        let updated = headers.iter().try_fold(
            (prev_client_state, prev_consensus_state),
            |(new_client_state, _), header| {
                client.check_header_and_update_state(
                    new_client_state,
                    header.clone(),
                )
            },
        );
        match updated {
            Ok((new_client_state, new_consensus_state)) => Ok(new_client_state
                == client_state
                && new_consensus_state == consensus_state),
            Err(e) => {
                tracing::info!(
                    "a header is invalid for the client {}: {}",
                    client_id,
                    e,
                );
                Ok(false)
            }
        }
    }

    fn verify_upgrade_client(
        &self,
        client_id: &ClientId,
        data: ClientUpgradeData,
    ) -> Result<bool> {
        let id = data.client_id()?;
        if id != *client_id {
            tracing::info!(
                "the client ID is mismatched: {} in the tx data, {} in the key",
                id,
                client_id,
            );
            return Ok(false);
        }

        // check the posterior states
        let client_state = match ClientReader::client_state(self, client_id) {
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
        let consensus_state = match self.consensus_state(client_id, height) {
            Some(s) => s,
            None => {
                tracing::info!(
                    "the consensus state of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };
        // check the prior client state
        let pre_client_state = match self.client_state_pre(client_id) {
            Some(s) => s,
            None => {
                tracing::info!(
                    "the prior client state of ID {} doesn't exist",
                    client_id
                );
                return Ok(false);
            }
        };
        // get proofs
        let client_proof = data.proof_client()?;
        let consensus_proof = data.proof_consensus_state()?;

        let client = AnyClient::from_client_type(client_state.client_type());
        match client.verify_upgrade_and_update_state(
            &pre_client_state,
            &consensus_state,
            client_proof,
            consensus_proof,
        ) {
            Ok((new_client_state, new_consensus_state)) => Ok(new_client_state
                == client_state
                && new_consensus_state == consensus_state),
            Err(e) => {
                tracing::info!(
                    "the header is invalid for the client {}: {}",
                    client_id,
                    e
                );
                Ok(false)
            }
        }
    }

    fn client_state_pre(&self, client_id: &ClientId) -> Option<AnyClientState> {
        let path = Path::ClientState(client_id.clone()).to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client state shouldn't fail");
        match self.ctx.read_pre(&key) {
            Ok(Some(value)) => AnyClientState::decode_vec(&value).ok(),
            // returns None even if DB read fails
            _ => None,
        }
    }

    pub(super) fn client_counter_pre(&self) -> u64 {
        let key = Key::ibc_client_counter();
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => match storage::types::decode(&value) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("decoding a client counter failed: {}", e);
                    u64::MAX
                }
            },
            _ => {
                tracing::error!("client counter doesn't exist");
                unreachable!();
            }
        }
    }

    fn consensus_state_pre(
        &self,
        client_id: &ClientId,
        height: Height,
    ) -> Option<AnyConsensusState> {
        let path = Path::ClientConsensusState {
            client_id: client_id.clone(),
            epoch: height.revision_number,
            height: height.revision_height,
        }
        .to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a consensus state shouldn't fail");
        match self.ctx.read_pre(&key) {
            Ok(Some(value)) => AnyConsensusState::decode_vec(&value).ok(),
            // returns None even if DB read fails
            _ => None,
        }
    }
}

/// Load the posterior client state
impl<'a, DB, H> ClientReader for Ibc<'a, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn client_type(&self, client_id: &ClientId) -> Option<ClientType> {
        let path = Path::ClientType(client_id.clone()).to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client type shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => {
                let s: String = storage::types::decode(&value).ok()?;
                Some(ClientType::from_str(&s).ok()?)
            }
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn client_state(&self, client_id: &ClientId) -> Option<AnyClientState> {
        let path = Path::ClientState(client_id.clone()).to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a client state shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => AnyClientState::decode_vec(&value).ok(),
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn consensus_state(
        &self,
        client_id: &ClientId,
        height: Height,
    ) -> Option<AnyConsensusState> {
        let path = Path::ClientConsensusState {
            client_id: client_id.clone(),
            epoch: height.revision_number,
            height: height.revision_height,
        }
        .to_string();
        let key = Key::ibc_key(path)
            .expect("Creating a key for a consensus state shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => AnyConsensusState::decode_vec(&value).ok(),
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn client_counter(&self) -> u64 {
        let key = Key::ibc_client_counter();
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => match storage::types::decode(&value) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("decoding a client counter failed: {}", e);
                    u64::MIN
                }
            },
            _ => {
                tracing::error!("client counter doesn't exist");
                unreachable!();
            }
        }
    }
}
