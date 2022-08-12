//! Validity predicate for the Ethereum bridge

mod store;

use std::collections::{BTreeSet, HashSet};

use eyre::{eyre, Result};
use itertools::Itertools;

use self::store::Reader;
use crate::ledger::eth_bridge::storage::{self, wrapped_erc20s};
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage as ledger_storage;
use crate::ledger::storage::StorageHasher;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

/// Validity predicate for the Ethereum bridge
pub struct EthBridge<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, DB, H, CA>,
}

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

impl<'a, DB, H, CA> NativeVp for EthBridge<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = super::INTERNAL_ADDRESS;

    /// Validate that a wasm transaction is permitted to change keys under this
    /// account.
    ///
    /// We permit only the following changes via wasm for the time being:
    /// - a wrapped ERC20's supply key to decrease iff one of its balance keys
    ///   decreased by the same amount
    /// - a wrapped ERC20's balance key to decrease iff another one of its
    ///   balance keys increased by the same amount
    ///
    /// Some other changes to the storage subspace of this account are expected
    /// to happen natively i.e. bypassing this validity predicate. For example,
    /// changes to the `eth_msgs/...` keys. For those cases, we reject here as
    /// no wasm transactions should be able to modify those keys.
    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(
            tx_data_len = tx_data.len(),
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Validity predicate triggered",
        );
        let (key_a, key_b) = match extract_valid_keys_changed(keys_changed)? {
            Some((key_a, key_b)) => (key_a, key_b),
            None => return Ok(false),
        };
        Ok(validate_balance_change(&self.ctx, key_a, key_b)?)
    }
}

/// Pure function not attached to the [`EthBridge`] struct so that it is easier
/// to test
fn extract_valid_keys_changed(
    keys_changed: &BTreeSet<Key>,
) -> Result<
    Option<(wrapped_erc20s::MultitokenKey, wrapped_erc20s::MultitokenKey)>,
    Error,
> {
    // we aren't concerned with keys that changed outside of our account
    let keys_changed: HashSet<_> = keys_changed
        .into_iter()
        .filter(|key| storage::is_eth_bridge_key(key))
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

    if keys_changed.len() != 2 {
        tracing::debug!(
            relevant_keys.len = keys_changed.len(),
            "Rejecting transaction as only two keys should have changed"
        );
        return Ok(None);
    }

    let mut keys = HashSet::<_>::default();
    for key in keys_changed.into_iter() {
        let key = match wrapped_erc20s::MultitokenKey::try_from(key) {
            Ok(key) => key,
            Err(error) => {
                tracing::debug!(
                    %key,
                    ?error,
                    "Rejecting transaction as key is not a wrapped ERC20 key"
                );
                return Ok(None);
            }
        };
        keys.insert(key);
    }

    // We can .unwrap() here as we know for sure that this set has len=2
    let (key_a, key_b) = keys.into_iter().collect_tuple().unwrap();
    if key_a.asset != key_b.asset {
        tracing::debug!(
            ?key_a,
            ?key_b,
            "Rejecting transaction as keys are for different assets"
        );
        return Ok(None);
    }
    Ok(Some((key_a, key_b)))
}

fn validate_balance_change(
    reader: impl Reader,
    key_a: wrapped_erc20s::MultitokenKey,
    key_b: wrapped_erc20s::MultitokenKey,
) -> Result<bool> {
    let (balance_a, balance_b) =
        match (key_a.suffix.clone(), key_b.suffix.clone()) {
            (
                wrapped_erc20s::MultitokenKeyType::Balance { .. },
                wrapped_erc20s::MultitokenKeyType::Balance { .. },
            ) => (Key::from(&key_a), Key::from(&key_b)),
            (
                wrapped_erc20s::MultitokenKeyType::Balance { .. },
                wrapped_erc20s::MultitokenKeyType::Supply,
            )
            | (
                wrapped_erc20s::MultitokenKeyType::Supply,
                wrapped_erc20s::MultitokenKeyType::Balance { .. },
            ) => {
                // TODO: eventually we will permit burns here
                tracing::debug!(
                    ?key_a,
                    ?key_b,
                    "Rejecting transaction that is attempting to change a \
                     supply key"
                );
                return Ok(false);
            }
            (
                wrapped_erc20s::MultitokenKeyType::Supply,
                wrapped_erc20s::MultitokenKeyType::Supply,
            ) => {
                // in theory, this should be unreachable!() as we would have
                // already rejected if both supply keys were for
                // the same asset
                tracing::debug!(
                    ?key_a,
                    ?key_b,
                    "Rejecting transaction that is attempting to change two \
                     supply keys"
                );
                return Ok(false);
            }
        };
    // TODO: check total delta = 0 AND tx_data was signed by decreasing
    // balance's owner
    let balance_a = match reader.read_pre(&balance_a)? {
        Some(value) => value,
        None => {
            tracing::debug!(
                ?balance_a,
                "Rejecting transaction as could not read balance key"
            );
            return Ok(false);
        }
    };
    let balance_b = match reader.read_pre(&balance_b)? {
        Some(value) => value,
        None => {
            tracing::debug!(
                ?balance_b,
                "Rejecting transaction as could not read balance key"
            );
            return Ok(false);
        }
    };
    Ok(true)
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::types::ethereum_events;

    const ARBITRARY_OWNER_A_ADDRESS: &str =
        "atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4";
    const ARBITRARY_OWNER_B_ADDRESS: &str =
        "atest1v4ehgw36xuunwd6989prwdfkxqmnvsfjxs6nvv6xxucrs3f3xcmns3fcxdzrvvz9xverzvzr56le8f";

    /// Return some arbitrary random key belonging to this account
    fn arbitrary_key() -> Key {
        let mut rng = rand::thread_rng();
        let rn = rng.gen::<u64>();
        storage::prefix()
            .push(&format!("arbitrary key segment {}", rn))
            .expect("should always be able to construct this key")
    }

    #[test]
    fn test_error_if_triggered_without_keys_changed() {
        let keys_changed = BTreeSet::new();

        let result = extract_valid_keys_changed(&keys_changed);

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_if_not_two_keys_changed() {
        {
            let keys_changed = BTreeSet::from_iter(vec![arbitrary_key()]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }
        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                arbitrary_key(),
                arbitrary_key(),
            ]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    fn test_rejects_if_not_two_multitoken_keys_changed() {
        {
            let keys_changed =
                BTreeSet::from_iter(vec![arbitrary_key(), arbitrary_key()]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .supply(),
            ]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_A_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    fn test_rejects_if_multitoken_keys_for_different_assets() {
        {
            let keys_changed = BTreeSet::from_iter(vec![
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_A_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::USDC_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_B_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    // TODO: this test will no longer be valid once we allow burning
    fn test_rejects_if_supply_key_changed() {
        let asset = &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
        {
            let keys_changed = BTreeSet::from_iter(vec![
                wrapped_erc20s::Keys::from(asset).supply(),
                wrapped_erc20s::Keys::from(asset).balance(
                    &Address::decode(ARBITRARY_OWNER_B_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = extract_valid_keys_changed(&keys_changed);

            assert!(matches!(result, Ok(None)));
        }
    }
}
