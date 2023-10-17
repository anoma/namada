//! Validity predicate for Non Usable Tokens (NUTs).

use std::collections::BTreeSet;

use eyre::WrapErr;
use namada_core::ledger::storage as ledger_storage;
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;
use namada_core::types::token::Amount;

use crate::ledger::native_vp::{Ctx, NativeVp, VpEnv};
use crate::proto::Tx;
use crate::types::token::is_any_token_balance_key;
use crate::vm::WasmCacheAccess;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] eyre::Report);

/// Validity predicate for non-usable tokens.
///
/// All this VP does is reject NUT transfers whose destination
/// address is not the Bridge pool escrow address.
pub struct NonUsableTokens<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for NonUsableTokens<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
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
    use std::env::temp_dir;

    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage_api::StorageWrite;
    use namada_core::types::address::testing::arb_non_internal_address;
    use namada_core::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::types::storage::TxIndex;
    use namada_core::types::token::balance_key;
    use namada_core::types::transaction::TxType;
    use namada_ethereum_bridge::storage::wrapped_erc20s;
    use proptest::prelude::*;

    use super::*;
    use crate::ledger::gas::{TxGasMeter, VpGasMeter};
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    /// Run a VP check on a NUT transfer between the two provided addresses.
    fn check_nut_transfer(src: Address, dst: Address) -> Option<bool> {
        let nut = wrapped_erc20s::nut(&DAI_ERC20_ETH_ADDRESS);
        let src_balance_key = balance_key(&nut, &src);
        let dst_balance_key = balance_key(&nut, &dst);

        let wl_storage = {
            let mut wl = TestWlStorage::default();

            // write initial balances
            wl.write(&src_balance_key, Amount::from(200_u64))
                .expect("Test failed");
            wl.write(&dst_balance_key, Amount::from(100_u64))
                .expect("Test failed");
            wl.commit_block().expect("Test failed");

            // write the updated balances
            wl.write_log
                .write(
                    &src_balance_key,
                    Amount::from(100_u64).try_to_vec().expect("Test failed"),
                )
                .expect("Test failed");
            wl.write_log
                .write(
                    &dst_balance_key,
                    Amount::from(200_u64).try_to_vec().expect("Test failed"),
                )
                .expect("Test failed");

            wl
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
        let ctx = Ctx::<_, _, WasmCacheRwAccess>::new(
            &Address::Internal(InternalAddress::Nut(DAI_ERC20_ETH_ADDRESS)),
            &wl_storage.storage,
            &wl_storage.write_log,
            &tx,
            &TxIndex(0),
            VpGasMeter::new_from_tx_meter(&TxGasMeter::new_from_sub_limit(
                u64::MAX.into(),
            )),
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
