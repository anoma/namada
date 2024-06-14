//! Validity predicate for the Ethereum bridge

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::HashSet;
use namada_core::storage::Key;
use namada_core::token::{self, Amount};
use namada_state::StateRead;
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{self, Ctx, NativeVp, StorageReader, VpEvaluator};

use crate::storage;
use crate::storage::escrow_key;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error("Ethereum Bridge VP error: {0}")]
pub struct Error(#[from] native_vp::Error);

/// Validity predicate for the Ethereum bridge
pub struct EthBridge<'ctx, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Token keys type
    pub token_keys: PhantomData<TokenKeys>,
}

impl<'ctx, S, CA, EVAL, TokenKeys> EthBridge<'ctx, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    TokenKeys: token::Keys,
{
    /// If the Ethereum bridge's escrow key was written to, we check
    /// that the NAM balance increased and that the Bridge pool VP has
    /// been triggered.
    fn check_escrow(&self, verifiers: &BTreeSet<Address>) -> Result<(), Error> {
        let escrow_key = TokenKeys::balance_key(
            &self.ctx.state.in_mem().native_token,
            &crate::ADDRESS,
        );

        let escrow_pre: Amount =
            (&self.ctx).read_pre_value(&escrow_key)?.unwrap_or_default();
        let escrow_post: Amount =
            (&self.ctx).must_read_post_value(&escrow_key)?;

        // The amount escrowed should increase.
        if escrow_pre < escrow_post {
            // NB: normally, we only escrow NAM under the Ethereum bridge
            // address in the context of a Bridge pool transfer
            let bridge_pool_is_verifier =
                verifiers.contains(&storage::bridge_pool::BRIDGE_POOL_ADDRESS);

            bridge_pool_is_verifier.ok_or_else(|| {
                native_vp::Error::new_const(
                    "Bridge pool VP was not marked as a verifier of the \
                     transaction",
                )
                .into()
            })
        } else {
            Err(native_vp::Error::new_const(
                "User tx attempted to decrease the amount of native tokens \
                 escrowed in the Ethereum Bridge's account",
            )
            .into())
        }
    }
}

impl<'a, S, CA, EVAL, TokenKeys> NativeVp<'a>
    for EthBridge<'a, S, CA, EVAL, TokenKeys>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    TokenKeys: token::Keys,
{
    type Error = Error;

    /// Validate that a wasm transaction is permitted to change keys under this
    /// account.
    ///
    /// We only permit increasing the escrowed balance of NAM under the Ethereum
    /// bridge address, when writing to storage from wasm transactions.
    ///
    /// Some other changes to the storage subspace of this account are expected
    /// to happen natively i.e. bypassing this validity predicate. For example,
    /// changes to the `eth_msgs/...` keys. For those cases, we reject here as
    /// no wasm transactions should be able to modify those keys.
    fn validate_tx(
        &self,
        _: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<(), Self::Error> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Ethereum Bridge VP triggered",
        );

        validate_changed_keys::<TokenKeys>(
            &self.ctx.state.in_mem().native_token,
            keys_changed,
        )?;

        self.check_escrow(verifiers)
    }
}

/// Checks if `keys_changed` represents a valid set of changed keys.
///
/// This implies checking if two distinct keys were changed:
///
/// 1. The Ethereum bridge escrow account's NAM balance key.
/// 2. Another account's NAM balance key.
///
/// Any other keys changed under the Ethereum bridge account
/// are rejected.
fn validate_changed_keys<TokenKeys: token::Keys>(
    nam_addr: &Address,
    keys_changed: &BTreeSet<Key>,
) -> Result<(), Error> {
    // acquire all keys that either changed our account, or that touched
    // nam balances
    let keys_changed: HashSet<_> = keys_changed
        .iter()
        .filter(|&key| {
            let changes_eth_storage = storage::has_eth_addr_segment(key);
            let changes_nam_balance =
                TokenKeys::is_balance_key(nam_addr, key).is_some();
            changes_nam_balance || changes_eth_storage
        })
        .collect();
    if keys_changed.is_empty() {
        return Err(native_vp::Error::SimpleMessage(
            "No keys changed under our account so this validity predicate \
             shouldn't have been triggered",
        )
        .into());
    }
    tracing::debug!(
        relevant_keys.len = keys_changed.len(),
        "Found keys changed under our account"
    );
    let nam_escrow_addr_modified = keys_changed.contains(&escrow_key(nam_addr));
    if !nam_escrow_addr_modified {
        let error = native_vp::Error::new_const(
            "The native token's escrow balance should have been modified",
        )
        .into();
        tracing::debug!("{error}");
        return Err(error);
    }
    let all_keys_are_nam_balance = keys_changed
        .iter()
        .all(|key| TokenKeys::is_balance_key(nam_addr, key).is_some());
    if !all_keys_are_nam_balance {
        let error = native_vp::Error::new_const(
            "Some modified keys were not a native token's balance key",
        )
        .into();
        tracing::debug!("{error}");
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::env::temp_dir;

    use namada_core::address::testing::{established_address_1, nam, wnam};
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::ethereum_events::EthAddress;
    use namada_core::{ethereum_events, WasmCacheRwAccess};
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_state::testing::TestState;
    use namada_state::{StorageWrite, TxIndex};
    use namada_trans_token::storage_key::{balance_key, minted_balance_key};
    use namada_tx::data::TxType;
    use namada_tx::{Tx, TxCommitments};
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vm::wasm::VpCache;
    use rand::Rng;

    use super::*;
    use crate::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
    use crate::storage::parameters::{
        Contracts, EthereumBridgeParams, UpgradeableContract,
    };
    use crate::storage::wrapped_erc20s;

    const ARBITRARY_OWNER_A_ADDRESS: &str =
        "tnam1qqwuj7aart6ackjfkk7486jwm2ufr4t7cq4535u4";
    const ARBITRARY_OWNER_A_INITIAL_BALANCE: u64 = 100;
    const ESCROW_AMOUNT: u64 = 100;
    const BRIDGE_POOL_ESCROW_INITIAL_BALANCE: u64 = 0;

    type CA = WasmCacheRwAccess;
    type Eval = VpEvalWasm<
        <TestState as StateRead>::D,
        <TestState as StateRead>::H,
        CA,
    >;
    type TokenKeys = namada_token::Store<()>;

    /// Return some arbitrary random key belonging to this account
    fn arbitrary_key() -> Key {
        let mut rng = rand::thread_rng();
        let rn = rng.gen::<u64>();
        storage::prefix()
            .push(&format!("arbitrary key segment {}", rn))
            .expect("should always be able to construct this key")
    }

    /// Initialize some dummy storage for testing
    fn setup_storage() -> TestState {
        let mut state = TestState::default();

        // setup a user with a balance
        let balance_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        state
            .write(
                &balance_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE),
            )
            .expect("Test failed");

        // a dummy config for testing
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: Default::default(),
            contracts: Contracts {
                native_erc20: wnam(),
                bridge: UpgradeableContract {
                    address: EthAddress([42; 20]),
                    version: Default::default(),
                },
            },
        };
        config.init_storage(&mut state);
        state.commit_block().expect("Test failed");
        state
    }

    /// Setup a ctx for running native vps
    fn setup_ctx<'a>(
        tx: &'a Tx,
        cmt: &'a TxCommitments,
        state: &'a TestState,
        gas_meter: &'a RefCell<VpGasMeter>,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
    ) -> Ctx<'a, TestState, VpCache<WasmCacheRwAccess>, Eval> {
        Ctx::new(
            &crate::ADDRESS,
            state,
            tx,
            cmt,
            &TxIndex(0),
            gas_meter,
            keys_changed,
            verifiers,
            VpCache::new(temp_dir(), 100usize),
        )
    }

    #[test]
    fn test_accepts_expected_keys_changed() {
        let keys_changed = BTreeSet::from([
            balance_key(&nam(), &established_address_1()),
            balance_key(&nam(), &crate::ADDRESS),
        ]);

        let result = validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

        assert!(result.is_ok());
    }

    #[test]
    fn test_error_if_triggered_without_keys_changed() {
        let keys_changed = BTreeSet::new();

        let result = validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_if_not_two_keys_changed() {
        {
            let keys_changed = BTreeSet::from_iter(vec![arbitrary_key(); 3]);

            let result =
                validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

            assert!(result.is_err());
        }
        {
            let keys_changed = BTreeSet::from_iter(vec![
                escrow_key(&nam()),
                arbitrary_key(),
                arbitrary_key(),
            ]);

            let result =
                validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

            assert!(result.is_err());
        }
    }

    #[test]
    fn test_rejects_if_not_two_multitoken_keys_changed() {
        {
            let keys_changed =
                BTreeSet::from_iter(vec![arbitrary_key(), arbitrary_key()]);

            let result =
                validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

            assert!(result.is_err());
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                minted_balance_key(&wrapped_erc20s::token(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )),
            ]);

            let result =
                validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

            assert!(result.is_err());
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                balance_key(
                    &wrapped_erc20s::token(
                        &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                    ),
                    &Address::decode(ARBITRARY_OWNER_A_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result =
                validate_changed_keys::<TokenKeys>(&nam(), &keys_changed);

            assert!(result.is_err());
        }
    }

    /// Test that escrowing Nam is accepted.
    #[test]
    fn test_escrow_nam_accepted() {
        let mut state = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        state
            .write_log_mut()
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .serialize_to_vec(),
            )
            .expect("Test failed");

        // credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &crate::ADDRESS);
        state
            .write_log_mut()
            .write(
                &escrow_key,
                Amount::from(
                    BRIDGE_POOL_ESCROW_INITIAL_BALANCE + ESCROW_AMOUNT,
                )
                .serialize_to_vec(),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([BRIDGE_POOL_ADDRESS]);

        // set up the VP
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let vp = EthBridge {
            ctx: setup_ctx(
                batched_tx.tx,
                batched_tx.cmt,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
            ),
            token_keys: PhantomData::<TokenKeys>,
        };

        let res = vp.validate_tx(&batched_tx, &keys_changed, &verifiers);
        assert!(res.is_ok());
    }

    /// Test that escrowing must increase the balance
    #[test]
    fn test_escrowed_nam_must_increase() {
        let mut state = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        state
            .write_log_mut()
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .serialize_to_vec(),
            )
            .expect("Test failed");

        // do not credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &crate::ADDRESS);
        state
            .write_log_mut()
            .write(
                &escrow_key,
                Amount::from(BRIDGE_POOL_ESCROW_INITIAL_BALANCE)
                    .serialize_to_vec(),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([BRIDGE_POOL_ADDRESS]);

        // set up the VP
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let vp = EthBridge {
            ctx: setup_ctx(
                batched_tx.tx,
                batched_tx.cmt,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
            ),
            token_keys: PhantomData::<TokenKeys>,
        };

        let res = vp.validate_tx(&batched_tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }

    /// Test that the VP checks that the bridge pool vp will
    /// be triggered if escrowing occurs.
    #[test]
    fn test_escrowing_must_trigger_bridge_pool_vp() {
        let mut state = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        state
            .write_log_mut()
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .serialize_to_vec(),
            )
            .expect("Test failed");

        // credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &crate::ADDRESS);
        state
            .write_log_mut()
            .write(
                &escrow_key,
                Amount::from(
                    BRIDGE_POOL_ESCROW_INITIAL_BALANCE + ESCROW_AMOUNT,
                )
                .serialize_to_vec(),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([]);

        // set up the VP
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let vp = EthBridge {
            ctx: setup_ctx(
                batched_tx.tx,
                batched_tx.cmt,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
            ),
            token_keys: PhantomData::<TokenKeys>,
        };

        let res = vp.validate_tx(&batched_tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }
}
