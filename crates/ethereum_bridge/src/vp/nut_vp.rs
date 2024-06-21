//! Validity predicate for Non Usable Tokens (NUTs).

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::{Address, InternalAddress};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_core::token::{self, Amount};
use namada_state::StateRead;
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{self, Ctx, NativeVp, VpEvaluator};
use namada_vp::VpEnv;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error("Non-usable token VP error: {0}")]
pub struct Error(#[from] native_vp::Error);

/// Validity predicate for non-usable tokens.
///
/// All this VP does is reject NUT transfers whose destination
/// address is not the Bridge pool escrow address.
pub struct NonUsableTokens<'ctx, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Generic types for DI
    pub _marker: PhantomData<TokenKeys>,
}

impl<'view, 'ctx: 'view, S, CA, EVAL, TokenKeys> NativeVp<'view>
    for NonUsableTokens<'ctx, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    CA: 'static + Clone,
    TokenKeys: token::Keys,
{
    type Error = Error;

    fn validate_tx(
        &'view self,
        _: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<(), Self::Error> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Non usable tokens VP triggered",
        );

        verifiers
            .contains(&Address::Internal(InternalAddress::Multitoken))
            .ok_or_else(|| {
                let error = Error(native_vp::Error::new_const(
                    "Rejecting non-multitoken transfer tx",
                ));
                tracing::debug!("{error}");
                error
            })?;

        let nut_owners = keys_changed.iter().filter_map(|key| {
            match TokenKeys::is_any_token_balance_key(key) {
                Some([Address::Internal(InternalAddress::Nut(_)), owner]) => {
                    Some((key, owner))
                }
                _ => None,
            }
        });

        for (changed_key, token_owner) in nut_owners {
            let pre: Amount = self
                .ctx
                .read_pre(changed_key)
                .map_err(Error)?
                .unwrap_or_default();
            let post: Amount = self
                .ctx
                .read_post(changed_key)
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
                        return Err(native_vp::Error::new_alloc(format!(
                            "Bridge pool balance should have increased. The \
                             previous balance was {pre:?}, the post balance \
                             is {post:?}.",
                        ))
                        .into());
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
                        return Err(native_vp::Error::new_alloc(format!(
                            "Balance should have decreased. The previous \
                             balance was {pre:?}, the post balance is \
                             {post:?}."
                        ))
                        .into());
                    }
                }
            }
        }

        Ok(())
    }
}

impl<'ctx, S, CA, EVAL, TokenKeys> NonUsableTokens<'ctx, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    CA: 'static + Clone,
    TokenKeys: token::Keys,
{
    /// Instantiate NUT VP
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self {
            ctx,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test_nuts {
    use std::cell::RefCell;
    use std::env::temp_dir;

    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::storage::TxIndex;
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_state::testing::TestState;
    use namada_state::StorageWrite;
    use namada_trans_token::storage_key::balance_key;
    use namada_tx::data::TxType;
    use namada_tx::Tx;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vm::wasm::VpCache;
    use namada_vm::WasmCacheRwAccess;
    use proptest::prelude::*;

    use super::*;
    use crate::storage::wrapped_erc20s;

    type CA = WasmCacheRwAccess;
    type Eval = VpEvalWasm<
        <TestState as StateRead>::D,
        <TestState as StateRead>::H,
        CA,
    >;
    type TokenKeys = namada_token::Store<()>;
    type NonUsableTokens<'a, S> =
        super::NonUsableTokens<'a, S, VpCache<CA>, Eval, TokenKeys>;

    /// Run a VP check on a NUT transfer between the two provided addresses.
    fn check_nut_transfer(src: Address, dst: Address) -> bool {
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

        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::<_, VpCache<WasmCacheRwAccess>, Eval>::new(
            &Address::Internal(InternalAddress::Nut(DAI_ERC20_ETH_ADDRESS)),
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            VpCache::new(temp_dir(), 100usize),
        );
        let vp = NonUsableTokens::new(ctx);

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

        vp.validate_tx(&batched_tx, &keys_changed, &verifiers)
            .map_or_else(|_| false, |()| true)
    }

    proptest! {
        /// Test that transferring NUTs between two arbitrary addresses
        /// will always fail.
        #[test]
        fn test_nut_transfer_rejected(
            (src, dst) in (arb_non_internal_address(), arb_non_internal_address())
        ) {
            assert!(!check_nut_transfer(src, dst));
        }

        /// Test that transferring NUTs from an arbitrary address to the
        /// Bridge pool address passes.
        #[test]
        fn test_nut_transfer_passes(src in arb_non_internal_address()) {
            assert!(check_nut_transfer(
                src,
                Address::Internal(InternalAddress::EthBridgePool),
            ));
        }
    }
}
