//! Validity predicate for the Ethereum bridge
use std::collections::{BTreeSet, HashSet};

use eyre::{eyre, Result};
use namada_core::address::Address;
use namada_core::storage::Key;
use namada_ethereum_bridge::storage;
use namada_ethereum_bridge::storage::escrow_key;
use namada_tx::Tx;

use crate::ledger::native_vp::{Ctx, NativeVp, StorageReader};
use crate::state::StateRead;
use crate::token::storage_key::{balance_key, is_balance_key};
use crate::token::Amount;
use crate::vm::WasmCacheAccess;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] eyre::Error);

/// Validity predicate for the Ethereum bridge
pub struct EthBridge<'ctx, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA>,
}

impl<'ctx, S, CA> EthBridge<'ctx, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// If the Ethereum bridge's escrow key was written to, we check
    /// that the NAM balance increased and that the Bridge pool VP has
    /// been triggered.
    fn check_escrow(
        &self,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Error> {
        let escrow_key = balance_key(
            &self.ctx.state.in_mem().native_token,
            &crate::ethereum_bridge::ADDRESS,
        );

        let escrow_pre: Amount =
            if let Ok(Some(value)) = (&self.ctx).read_pre_value(&escrow_key) {
                value
            } else {
                tracing::debug!(
                    "Could not retrieve the Ethereum bridge VP's balance from \
                     storage"
                );
                return Ok(false);
            };
        let escrow_post: Amount =
            if let Ok(Some(value)) = (&self.ctx).read_post_value(&escrow_key) {
                value
            } else {
                tracing::debug!(
                    "Could not retrieve the modified Ethereum bridge VP's \
                     balance after applying tx"
                );
                return Ok(false);
            };

        // The amount escrowed should increase.
        if escrow_pre < escrow_post {
            // NB: normally, we only escrow NAM under the Ethereum bridge
            // address in the context of a Bridge pool transfer
            Ok(verifiers.contains(&storage::bridge_pool::BRIDGE_POOL_ADDRESS))
        } else {
            tracing::info!(
                "A normal tx cannot decrease the amount of Nam escrowed in \
                 the Ethereum bridge"
            );
            Ok(false)
        }
    }
}

impl<'a, S, CA> NativeVp for EthBridge<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
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
        _: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Ethereum Bridge VP triggered",
        );

        if !validate_changed_keys(
            &self.ctx.state.in_mem().native_token,
            keys_changed,
        )? {
            return Ok(false);
        }

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
fn validate_changed_keys(
    nam_addr: &Address,
    keys_changed: &BTreeSet<Key>,
) -> Result<bool, Error> {
    // acquire all keys that either changed our account, or that touched
    // nam balances
    let keys_changed: HashSet<_> = keys_changed
        .iter()
        .filter(|&key| {
            let changes_eth_storage = storage::has_eth_addr_segment(key);
            let changes_nam_balance = is_balance_key(nam_addr, key).is_some();
            changes_nam_balance || changes_eth_storage
        })
        .collect();
    if keys_changed.is_empty() {
        return Err(Error(eyre!(
            "No keys changed under our account so this validity predicate \
             shouldn't have been triggered"
        )));
    }
    tracing::debug!(
        relevant_keys.len = keys_changed.len(),
        "Found keys changed under our account"
    );
    Ok(keys_changed.contains(&escrow_key(nam_addr))
        && keys_changed
            .iter()
            .all(|key| is_balance_key(nam_addr, key).is_some()))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::env::temp_dir;

    use namada_core::borsh::BorshSerializeExt;
    use namada_core::validity_predicate::VpSentinel;
    use namada_gas::TxGasMeter;
    use namada_state::testing::TestState;
    use namada_state::StorageWrite;
    use namada_tx::data::TxType;
    use rand::Rng;

    use super::*;
    use crate::address::testing::{established_address_1, nam, wnam};
    use crate::ethereum_bridge::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
    use crate::ethereum_bridge::storage::parameters::{
        Contracts, EthereumBridgeParams, UpgradeableContract,
    };
    use crate::ethereum_bridge::storage::wrapped_erc20s;
    use crate::ethereum_events;
    use crate::ethereum_events::EthAddress;
    use crate::ledger::gas::VpGasMeter;
    use crate::storage::TxIndex;
    use crate::token::storage_key::minted_balance_key;
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    const ARBITRARY_OWNER_A_ADDRESS: &str =
        "tnam1qqwuj7aart6ackjfkk7486jwm2ufr4t7cq4535u4";
    const ARBITRARY_OWNER_A_INITIAL_BALANCE: u64 = 100;
    const ESCROW_AMOUNT: u64 = 100;
    const BRIDGE_POOL_ESCROW_INITIAL_BALANCE: u64 = 0;

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
        state: &'a TestState,
        gas_meter: &'a RefCell<VpGasMeter>,
        sentinel: &'a RefCell<VpSentinel>,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
    ) -> Ctx<'a, TestState, WasmCacheRwAccess> {
        Ctx::new(
            &crate::ethereum_bridge::ADDRESS,
            state,
            tx,
            &TxIndex(0),
            gas_meter,
            sentinel,
            keys_changed,
            verifiers,
            VpCache::new(temp_dir(), 100usize),
        )
    }

    #[test]
    fn test_accepts_expected_keys_changed() {
        let keys_changed = BTreeSet::from([
            balance_key(&nam(), &established_address_1()),
            balance_key(&nam(), &crate::ethereum_bridge::ADDRESS),
        ]);

        let result = validate_changed_keys(&nam(), &keys_changed);

        assert_matches!(result, Ok(true));
    }

    #[test]
    fn test_error_if_triggered_without_keys_changed() {
        let keys_changed = BTreeSet::new();

        let result = validate_changed_keys(&nam(), &keys_changed);

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_if_not_two_keys_changed() {
        {
            let keys_changed = BTreeSet::from_iter(vec![arbitrary_key(); 3]);

            let result = validate_changed_keys(&nam(), &keys_changed);

            assert_matches!(result, Ok(false));
        }
        {
            let keys_changed = BTreeSet::from_iter(vec![
                escrow_key(&nam()),
                arbitrary_key(),
                arbitrary_key(),
            ]);

            let result = validate_changed_keys(&nam(), &keys_changed);

            assert_matches!(result, Ok(false));
        }
    }

    #[test]
    fn test_rejects_if_not_two_multitoken_keys_changed() {
        {
            let keys_changed =
                BTreeSet::from_iter(vec![arbitrary_key(), arbitrary_key()]);

            let result = validate_changed_keys(&nam(), &keys_changed);

            assert_matches!(result, Ok(false));
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                minted_balance_key(&wrapped_erc20s::token(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )),
            ]);

            let result = validate_changed_keys(&nam(), &keys_changed);

            assert_matches!(result, Ok(false));
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

            let result = validate_changed_keys(&nam(), &keys_changed);

            assert_matches!(result, Ok(false));
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
        let escrow_key = balance_key(&nam(), &crate::ethereum_bridge::ADDRESS);
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
        let tx = Tx::from_type(TxType::Raw);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let sentinel = RefCell::new(VpSentinel::default());
        let vp = EthBridge {
            ctx: setup_ctx(
                &tx,
                &state,
                &gas_meter,
                &sentinel,
                &keys_changed,
                &verifiers,
            ),
        };

        let res = vp.validate_tx(&tx, &keys_changed, &verifiers);
        assert!(res.expect("Test failed"));
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
        let escrow_key = balance_key(&nam(), &crate::ethereum_bridge::ADDRESS);
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
        let tx = Tx::from_type(TxType::Raw);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let sentinel = RefCell::new(VpSentinel::default());
        let vp = EthBridge {
            ctx: setup_ctx(
                &tx,
                &state,
                &gas_meter,
                &sentinel,
                &keys_changed,
                &verifiers,
            ),
        };

        let res = vp.validate_tx(&tx, &keys_changed, &verifiers);
        assert!(!res.expect("Test failed"));
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
        let escrow_key = balance_key(&nam(), &crate::ethereum_bridge::ADDRESS);
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
        let tx = Tx::from_type(TxType::Raw);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let sentinel = RefCell::new(VpSentinel::default());
        let vp = EthBridge {
            ctx: setup_ctx(
                &tx,
                &state,
                &gas_meter,
                &sentinel,
                &keys_changed,
                &verifiers,
            ),
        };

        let res = vp.validate_tx(&tx, &keys_changed, &verifiers);
        assert!(!res.expect("Test failed"));
    }
}
