//! Shell methods for querying state

use borsh::BorshDeserialize;
use ferveo_common::TendermintValidator;
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
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
            storage: &self.storage,
            event_log: self.event_log(),
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: self.storage_read_past_height_limit,
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

    /// Lookup data about a validator from their protocol signing key
    #[allow(dead_code)]
    pub fn get_validator_from_protocol_pk(
        &self,
        pk: &common::PublicKey,
    ) -> Option<TendermintValidator<EllipticCurve>> {
        let pk_bytes = pk
            .try_to_vec()
            .expect("Serializing public key should not fail");
        // get the current epoch
        let (current_epoch, _) = self.storage.get_current_epoch();
        // get the PoS params
        let pos_params = self.storage.read_pos_params();
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
                    power: into_tm_voting_power(
                        pos_params.tm_votes_per_token,
                        validator.bonded_stake,
                    ) as u64,
                    address: validator.address.to_string(),
                    public_key: dkg_publickey.into(),
                }
            })
    }
}

// NOTE: we are testing `namada::ledger::queries_ext`,
// which is not possible from `namada` since we do not have
// access to the `Shell` there
#[cfg(test)]
#[cfg(not(feature = "abcipp"))]
mod test_queries {
    use namada::ledger::queries_ext::{QueriesExt, SendValsetUpd};
    use namada::types::storage::Epoch;

    use super::*;
    use crate::node::ledger::shell::test_utils;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    macro_rules! test_can_send_validator_set_update {
        (epoch_assertions: $epoch_assertions:expr $(,)?) => {
            /// Test if [`QueriesExt::can_send_validator_set_update`] behaves as
            /// expected.
            #[test]
            fn test_can_send_validator_set_update() {
                let (mut shell, _recv, _) = test_utils::setup_at_height(0u64);

                let epoch_assertions = $epoch_assertions;

                // test `SendValsetUpd::Now`  and `SendValsetUpd::AtPrevHeight`
                for (curr_epoch, curr_block_height, can_send) in
                    epoch_assertions
                {
                    shell.storage.last_height =
                        BlockHeight(curr_block_height - 1);
                    assert_eq!(
                        curr_block_height,
                        shell.storage.get_current_decision_height().0
                    );
                    assert_eq!(
                        shell.storage.get_epoch(curr_block_height.into()),
                        Some(Epoch(curr_epoch))
                    );
                    assert_eq!(
                        shell
                            .storage
                            .can_send_validator_set_update(SendValsetUpd::Now),
                        can_send,
                    );
                    // TODO(feature = "abcipp"): test
                    // `SendValsetUpd::AtPrevHeight`; `idx` is the value
                    // of the current index being iterated over
                    // the array `epoch_assertions`
                    //
                    // ```ignore
                    // if let Some((epoch, height, can_send)) =
                    //     epoch_assertions.get(_idx.wrapping_sub(1)).copied()
                    // {
                    //     assert_eq!(
                    //         shell.storage.get_epoch(height.into()),
                    //         Some(Epoch(epoch))
                    //     );
                    //     assert_eq!(
                    //         shell.storage.can_send_validator_set_update(
                    //             SendValsetUpd::AtPrevHeight
                    //         ),
                    //         can_send,
                    //     );
                    // }
                    // ```
                    let time = namada::types::time::DateTimeUtc::now();
                    let mut req = FinalizeBlock::default();
                    req.header.time = time;
                    shell.finalize_block(req).expect("Test failed");
                    shell.commit();
                    shell.storage.next_epoch_min_start_time = time;
                }
            }
        };
    }

    #[cfg(feature = "abcipp")]
    test_can_send_validator_set_update! {
        // TODO(feature = "abcipp"): add some epoch assertions
        epoch_assertions: []
    }

    #[cfg(not(feature = "abcipp"))]
    test_can_send_validator_set_update! {
        epoch_assertions: [
            // (current epoch, current block height, can send valset upd)
            (0, 1, false),
            (0, 2, true),
            (0, 3, false),
            (0, 4, false),
            (0, 5, false),
            (0, 6, false),
            (0, 7, false),
            (0, 8, false),
            (0, 9, false),
            // we will change epoch here
            (0, 10, false),
            (1, 11, true),
            (1, 12, false),
            (1, 13, false),
            (1, 14, false),
            (1, 15, false),
            (1, 16, false),
            (1, 17, false),
            (1, 18, false),
            (1, 19, false),
            // we will change epoch here
            (1, 20, false),
            (2, 21, true),
            (2, 22, false),
            (2, 23, false),
            (2, 24, false),
            (2, 25, false),
            (2, 26, false),
            (2, 27, false),
            (2, 28, false),
        ],
    }
}
