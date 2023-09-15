//! Shell methods for querying state

use borsh_ext::BorshSerializeExt;
use ferveo_common::TendermintValidator;
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
use namada::ledger::storage_api::token;
use namada::proof_of_stake::{
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
};
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
        pk: &common::PublicKey,
    ) -> Option<TendermintValidator<EllipticCurve>> {
        let pk_bytes = pk.serialize_to_vec();
        // get the current epoch
        let (current_epoch, _) = self.wl_storage.storage.get_current_epoch();

        // TODO: resolve both unwrap() instances better below

        // get the PoS params
        let pos_params = read_pos_params(&self.wl_storage).unwrap();
        // get the consensus validator set
        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &self.wl_storage,
            current_epoch,
        )
        .unwrap();

        consensus_vals
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

// NOTE: we are testing `namada::ledger::queries_ext`,
// which is not possible from `namada` since we do not have
// access to the `Shell` there
#[cfg(test)]
#[cfg(not(feature = "abcipp"))]
mod test_queries {
    use namada::core::ledger::storage::EPOCH_SWITCH_BLOCKS_DELAY;
    use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::types::storage::Epoch;

    use super::*;
    use crate::facade::tendermint_proto::abci::VoteInfo;
    use crate::node::ledger::shell::test_utils;
    use crate::node::ledger::shell::test_utils::get_pkh_from_address;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    macro_rules! test_must_send_valset_upd {
        (epoch_assertions: $epoch_assertions:expr $(,)?) => {
            /// Test if [`EthBridgeQueries::must_send_valset_upd`] behaves as
            /// expected.
            #[test]
            fn test_must_send_valset_upd() {
                const EPOCH_NUM_BLOCKS: u64 =
                    10 - EPOCH_SWITCH_BLOCKS_DELAY as u64;

                let (mut shell, _recv, _, _oracle_control_recv) =
                    test_utils::setup_at_height(0u64);

                let epoch_assertions = $epoch_assertions;

                let mut prev_epoch = None;

                // test `SendValsetUpd::Now`  and `SendValsetUpd::AtPrevHeight`
                for (curr_epoch, curr_block_height, can_send) in
                    epoch_assertions
                {
                    if prev_epoch != Some(curr_epoch) {
                        prev_epoch = Some(curr_epoch);
                        shell.start_new_epoch_in(EPOCH_NUM_BLOCKS);
                    }
                    if let Some(b) =
                        shell.wl_storage.storage.last_block.as_mut()
                    {
                        b.height = BlockHeight(curr_block_height - 1);
                    }
                    assert_eq!(
                        curr_block_height,
                        shell
                            .wl_storage
                            .pos_queries()
                            .get_current_decision_height()
                            .0
                    );
                    assert_eq!(
                        shell
                            .wl_storage
                            .pos_queries()
                            .get_epoch(curr_block_height.into()),
                        Some(Epoch(curr_epoch))
                    );
                    assert_eq!(
                        shell
                            .wl_storage
                            .ethbridge_queries()
                            .must_send_valset_upd(SendValsetUpd::Now),
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
                    //         shell.storage.must_send_valset_upd(
                    //             SendValsetUpd::AtPrevHeight
                    //         ),
                    //         can_send,
                    //     );
                    // }
                    // ```
                    let params =
                        shell.wl_storage.pos_queries().get_pos_params();
                    let consensus_set: Vec<WeightedValidator> =
                        read_consensus_validator_set_addresses_with_stake(
                            &shell.wl_storage,
                            Epoch::default(),
                        )
                        .unwrap()
                        .into_iter()
                        .collect();

                    let val1 = consensus_set[0].clone();
                    let pkh1 = get_pkh_from_address(
                        &shell.wl_storage,
                        &params,
                        val1.address.clone(),
                        Epoch::default(),
                    );
                    let votes = vec![VoteInfo {
                        validator: Some(
                            namada::tendermint_proto::abci::Validator {
                                address: pkh1.clone(),
                                power: u128::try_from(val1.bonded_stake)
                                    .expect("Test failed")
                                    as i64,
                            },
                        ),
                        signed_last_block: true,
                    }];
                    let req = FinalizeBlock {
                        proposer_address: pkh1,
                        votes,
                        ..Default::default()
                    };
                    shell.finalize_and_commit(Some(req));
                }
            }
        };
    }

    #[cfg(feature = "abcipp")]
    test_must_send_valset_upd! {
        // TODO(feature = "abcipp"): add some epoch assertions
        epoch_assertions: []
    }

    #[cfg(not(feature = "abcipp"))]
    test_must_send_valset_upd! {
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
