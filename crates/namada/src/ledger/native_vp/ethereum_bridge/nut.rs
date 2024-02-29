//! Validity predicate for Non Usable Tokens (NUTs).

use std::collections::BTreeSet;

use eyre::WrapErr;
use namada_core::address::{Address, InternalAddress};
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_tx::Tx;
use namada_vp_env::VpEnv;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::token::storage_key::is_any_token_balance_key;
use crate::token::Amount;
use crate::vm::WasmCacheAccess;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] eyre::Report);

/// Validity predicate for non-usable tokens.
///
/// All this VP does is reject NUT transfers whose destination
/// address is not the Bridge pool escrow address.
pub struct NonUsableTokens<'ctx, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA>,
}

impl<'a, S, CA> NativeVp for NonUsableTokens<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        _: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Non usable tokens VP triggered",
        );

        let is_multitoken =
            verifiers.contains(&Address::Internal(InternalAddress::Multitoken));
        if !is_multitoken {
            tracing::debug!("Rejecting non-multitoken transfer tx");
            return Ok(false);
        }

        let nut_owners =
            keys_changed.iter().filter_map(
                |key| match is_any_token_balance_key(key) {
                    Some(
                        [Address::Internal(InternalAddress::Nut(_)), owner],
                    ) => Some((key, owner)),
                    _ => None,
                },
            );

        for (changed_key, token_owner) in nut_owners {
            let pre: Amount = self
                .ctx
                .read_pre(changed_key)
                .context("Reading pre amount failed")
                .map_err(Error)?
                .unwrap_or_default();
            let post: Amount = self
                .ctx
                .read_post(changed_key)
                .context("Reading post amount failed")
                .map_err(Error)?
                .unwrap_or_default();

            match token_owner {
                // the NUT balance of the bridge pool should increase
                Address::Internal(InternalAddress::EthBridgePool) => {
                    if post < pre {
                        tracing::debug!(
                            %changed_key,
                            pre_amount = ?pre,
                            post_amount = ?post,
                            "Bridge pool balance should have increased"
                        );
                        return Ok(false);
                    }
                }
                // arbitrary addresses should have their balance decrease
                _addr => {
                    if post > pre {
                        tracing::debug!(
                            %changed_key,
                            pre_amount = ?pre,
                            post_amount = ?post,
                            "Balance should have decreased"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod test_nuts {
    use std::cell::RefCell;
    use std::env::temp_dir;

    use assert_matches::assert_matches;
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::storage::TxIndex;
    use namada_core::validity_predicate::VpSentinel;
    use namada_ethereum_bridge::storage::wrapped_erc20s;
    use namada_state::testing::TestState;
    use namada_state::StorageWrite;
    use namada_tx::data::TxType;
    use proptest::prelude::*;

    use super::*;
    use crate::ledger::gas::{TxGasMeter, VpGasMeter};
    use crate::token::storage_key::balance_key;
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    /// Run a VP check on a NUT transfer between the two provided addresses.
    fn check_nut_transfer(src: Address, dst: Address) -> Option<bool> {
        let nut = wrapped_erc20s::nut(&DAI_ERC20_ETH_ADDRESS);
        let src_balance_key = balance_key(&nut, &src);
        let dst_balance_key = balance_key(&nut, &dst);

        let state = {
            let mut state = TestState::default();

            // write initial balances
            state
                .write(&src_balance_key, Amount::from(200_u64))
                .expect("Test failed");
            state
                .write(&dst_balance_key, Amount::from(100_u64))
                .expect("Test failed");
            state.commit_block().expect("Test failed");

            // write the updated balances
            state
                .write_log_mut()
                .write(
                    &src_balance_key,
                    Amount::from(100_u64).serialize_to_vec(),
                )
                .expect("Test failed");
            state
                .write_log_mut()
                .write(
                    &dst_balance_key,
                    Amount::from(200_u64).serialize_to_vec(),
                )
                .expect("Test failed");

            state
        };

        let keys_changed = {
            let mut keys = BTreeSet::new();
            keys.insert(src_balance_key);
            keys.insert(dst_balance_key);
            keys
        };
        let verifiers = {
            let mut v = BTreeSet::new();
            v.insert(Address::Internal(InternalAddress::Multitoken));
            v
        };

        let tx = Tx::from_type(TxType::Raw);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::<_, WasmCacheRwAccess>::new(
            &Address::Internal(InternalAddress::Nut(DAI_ERC20_ETH_ADDRESS)),
            &state,
            &tx,
            &TxIndex(0),
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            VpCache::new(temp_dir(), 100usize),
        );
        let vp = NonUsableTokens { ctx };

        // print debug info in case we run into failures
        for key in &keys_changed {
            let pre: Amount = vp
                .ctx
                .read_pre(key)
                .expect("Test failed")
                .unwrap_or_default();
            let post: Amount = vp
                .ctx
                .read_post(key)
                .expect("Test failed")
                .unwrap_or_default();
            println!("{key}: PRE={pre:?} POST={post:?}");
        }

        vp.validate_tx(&tx, &keys_changed, &verifiers).ok()
    }

    proptest! {
        /// Test that transferring NUTs between two arbitrary addresses
        /// will always fail.
        #[test]
        fn test_nut_transfer_rejected(
            (src, dst) in (arb_non_internal_address(), arb_non_internal_address())
        ) {
            let status = check_nut_transfer(src, dst);
            assert_matches!(status, Some(false));
        }

        /// Test that transferring NUTs from an arbitrary address to the
        /// Bridge pool address passes.
        #[test]
        fn test_nut_transfer_passes(src in arb_non_internal_address()) {
            let status = check_nut_transfer(
                src,
                Address::Internal(InternalAddress::EthBridgePool),
            );
            assert_matches!(status, Some(true));
        }
    }
}
