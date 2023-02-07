//! Shell methods for querying state

use borsh::BorshSerialize;
use ferveo_common::TendermintValidator;
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
use namada::ledger::storage_api::token;
use namada::types::address::Address;
use namada::types::key;
use namada::types::key::dkg_session_keys::DkgPublicKey;

use super::*;
use crate::node::ledger::response;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Uses `path` in the query to forward the request to the
    /// right query method and returns the result (which may be
    /// the default if `path` is not a supported string.
    /// INVARIANT: This method must be stateless.
    pub fn query(&self, query: request::Query) -> response::Query {
        let ctx = RequestCtx {
            wl_storage: &self.wl_storage,
            event_log: self.event_log(),
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: self.storage_read_past_height_limit,
        };

        // Convert request to domain-type
        let request = match namada::ledger::queries::RequestQuery::try_from_tm(
            &self.wl_storage,
            query,
        ) {
            Ok(request) => request,
            Err(err) => {
                return response::Query {
                    code: 1,
                    info: format!("Unexpected query: {}", err),
                    ..Default::default()
                };
            }
        };

        // Invoke the root RPC handler - returns borsh-encoded data on success
        let result = namada::ledger::queries::handle_path(ctx, &request);
        match result {
            Ok(ResponseQuery { data, info, proof }) => response::Query {
                value: data,
                info,
                proof_ops: proof.map(Into::into),
                ..Default::default()
            },
            Err(err) => response::Query {
                code: 1,
                info: format!("RPC error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Simple helper function for the ledger to get balances
    /// of the specified token at the specified address
    pub fn get_balance(
        &self,
        token: &Address,
        owner: &Address,
    ) -> token::Amount {
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        token::read_balance(&self.wl_storage, token, owner)
            .expect("Token balance read in the protocol must not fail")
    }

    /// Lookup data about a validator from their protocol signing key
    #[allow(dead_code)]
    pub fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
    ) -> Option<TendermintValidator<EllipticCurve>> {
        let pk_bytes = pk
            .try_to_vec()
            .expect("Serializing public key should not fail");
        // get the current epoch
        let (current_epoch, _) = self.wl_storage.storage.get_current_epoch();
        // get the PoS params
        let pos_params = self.wl_storage.read_pos_params();
        // get the active validator set
        self.wl_storage
            .read_validator_set()
            .get(current_epoch)
            .expect("Validators for the next epoch should be known")
            .active
            .iter()
            .find(|validator| {
                let pk_key = key::protocol_pk_key(&validator.address);
                match self.wl_storage.read_bytes(&pk_key) {
                    Ok(Some(bytes)) => bytes == pk_bytes,
                    _ => false,
                }
            })
            .map(|validator| {
                let dkg_key =
                    key::dkg_session_keys::dkg_pk_key(&validator.address);
                let dkg_publickey: DkgPublicKey = self
                    .wl_storage
                    .read(&dkg_key)
                    .expect("Validator should have public dkg key")
                    .expect("Validator should have public dkg key");
                TendermintValidator {
                    power: into_tm_voting_power(
                        pos_params.tm_votes_per_token,
                        validator.bonded_stake,
                    ) as u64,
                    address: validator.address.to_string(),
                    public_key: (&dkg_publickey).into(),
                }
            })
    }
}
