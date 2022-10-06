//! Shell methods for querying state

use borsh::{BorshDeserialize, BorshSerialize};
use ferveo_common::TendermintValidator;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
use namada::ledger::storage_api;
use namada::types::address::Address;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::{key, token};

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
            storage: &self.storage,
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
        };

        // Convert request to domain-type
        let request = match namada::ledger::queries::RequestQuery::try_from_tm(
            &self.storage,
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
            Ok(ResponseQuery {
                data,
                info,
                proof_ops,
            }) => response::Query {
                value: data,
                info,
                proof_ops,
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
        let balance = storage_api::StorageRead::read(
            &self.storage,
            &token::balance_key(token, owner),
        );
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        balance
            .expect("Storage read in the protocol must not fail")
            .unwrap_or_default()
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
        let (current_epoch, _) = self.storage.get_current_epoch();
        // get the active validator set
        self.storage
            .read_validator_set()
            .get(current_epoch)
            .expect("Validators for the next epoch should be known")
            .active
            .iter()
            .find(|validator| {
                let pk_key = key::protocol_pk_key(&validator.address);
                match self.storage.read(&pk_key) {
                    Ok((Some(bytes), _)) => bytes == pk_bytes,
                    _ => false,
                }
            })
            .map(|validator| {
                let dkg_key =
                    key::dkg_session_keys::dkg_pk_key(&validator.address);
                let bytes = self
                    .storage
                    .read(&dkg_key)
                    .expect("Validator should have public dkg key")
                    .0
                    .expect("Validator should have public dkg key");
                let dkg_publickey =
                    &<DkgPublicKey as BorshDeserialize>::deserialize(
                        &mut bytes.as_ref(),
                    )
                    .expect(
                        "DKG public key in storage should be deserializable",
                    );
                TendermintValidator {
                    power: validator.voting_power.into(),
                    address: validator.address.to_string(),
                    public_key: dkg_publickey.into(),
                }
            })
    }
}
