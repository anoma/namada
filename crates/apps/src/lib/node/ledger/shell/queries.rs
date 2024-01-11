//! Shell methods for querying state

use namada::ledger::dry_run_tx;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
use namada::token;
use namada::types::address::Address;

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

        // Invoke the root RPC handler - returns borsh-encoded data on success
        let result = if query.path == "/shell/dry_run_tx" {
            dry_run_tx(ctx, &query)
        } else {
            namada::ledger::queries::handle_path(ctx, &query)
        };
        match result {
            Ok(ResponseQuery { data, info, proof }) => response::Query {
                value: data.into(),
                info,
                proof: proof.map(Into::into),
                ..Default::default()
            },
            Err(err) => response::Query {
                code: 1.into(),
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
}

// NOTE: we are testing `namada::ledger::queries_ext`,
// which is not possible from `namada` since we do not have
// access to the `Shell` there
#[cfg(test)]
mod test_queries {
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::storage::read_consensus_validator_set_addresses_with_stake;
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::state::EPOCH_SWITCH_BLOCKS_DELAY;
    use namada::tendermint::abci::types::VoteInfo;
    use namada::types::storage::{BlockHash, Epoch};
    use namada_sdk::eth_bridge::{EthBridgeQueries, SendValsetUpd};

    use super::*;
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
                    shell.wl_storage.storage.begin_block(
                        BlockHash::default(), curr_block_height.into()).unwrap();

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
                        validator: namada::tendermint::abci::types::Validator {
                            address: pkh1.clone().into(),
                            power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                        },
                        sig_info: namada::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
                    }];
                    let req = FinalizeBlock {
                        proposer_address: pkh1.to_vec(),
                        votes,
                        ..Default::default()
                    };
                    shell.finalize_and_commit(Some(req));
                }
            }
        };
    }

    test_must_send_valset_upd! {
        epoch_assertions: [
            // (current epoch, current block height, can send valset upd)
            // NOTE: can send valset upd on every 2nd block of an epoch
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
