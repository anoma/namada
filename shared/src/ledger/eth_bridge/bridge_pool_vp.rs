//! Validity predicate for the Ethereum bridge
use std::collections::{BTreeSet, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{Report, Result};

use crate::ledger::eth_bridge::storage::bridge_pool::{
    BRIDGE_POOL_ADDRESS, get_pending_key, get_signed_root_key,
}
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage::{DB, DBIter, StorageHasher};
use crate::types::address::{Address, InternalAddress};
use crate::types::eth_bridge_pool::{GasFee, PendingTransfer, TransferToEthereum};
use crate::types::storage::{Key, KeySeg};
use crate::types::token::Amount;
use crate::vm::WasmCacheAccess;

/// A positive or negative amount
enum SignedAmount {
    Positive(Amount),
    Negative(Amount),
}

/// Validity predicate for the Ethereum bridge
pub struct BridgePoolVp<'ctx, DB, H, CA>
where
    DB: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, DB, H, CA>,
}

impl<'a, DB, H, CA> BridgePoolVp<'a, DB, H, CA>
where
    DB: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Helper function for reading values from storage
    fn read_post_value<T>(&self, key: &Key) -> Option<T>
    where
        T: BorshDeserialize,
    {
        if let Ok(Some(bytes)) = self.ctx.read_post(key) {
            <T as BorshDeserialize>::try_from_slice(bytes.as_slice()).ok()
        } else {
            None
        }
    }

    /// Helper function for reading values from storage
    fn read_pre_value<T>(&self, key: &Key) -> Option<T>
    where
        T: BorshDeserialize,
    {
        if let Ok(Some(bytes)) = self.ctx.read_pre(key) {
            <T as BorshDeserialize>::try_from_slice(bytes.as_slice()).ok()
        } else {
            None
        }
    }

    /// Get the change in the balance of an account
    /// associated with an address
    fn account_balance_delta(&self, address: &Address) -> Option<SignedAmount> {
        let account_key = Key::from(address.to_db_key());
        let before: Amount = self.read_pre_value(&account_key)?;
        let after: Amount = self.read_post_value(&account_key)?
        if before > after {
            Some(SignedAmount::Negative(before - after)
        } else {
            Some(SignedAmount::Positive(after - before)
        }
    }
}

impl<'a, DB, H, CA> NativeVp for BridgePoolVp<'a, DB, H, CA>
where
    DB: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    const ADDR: InternalAddress = InternalAddress::EthBridgePool;

    type Error = Report;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        tracing::debug!(
            tx_data_len = _tx_data.len(),
            keys_changed_len = _keys_changed.len(),
            verifiers_len = _verifiers.len(),
            "Validity predicate triggered",
        );
        let transfer: PendingTransfer = BorshDeserialize::try_from_slice(tx_data)?;
        // check that the signed root is not modified
        let signed_root_key = get_signed_root_key();
        if keys_changed.contains(&signed_root_key) {
            return Ok(false)
        }
        // check that the pending transfer (and only that) was added to the pool
        let pending_key = get_pending_key();
        let pending_pre: HashSet<PendingTransfer> = self.read_pre_value(&get_pending_key())
            .ok_or(eyre!("The bridge pool transfers are missing from storage"))?;
        let pending_post: HashSet<PendingTransfer> = self.read_post_value(&get_pending_key())
            .ok_or(eyre!("The bridge pool transfers are missing from storage"))?;
        for item in pending_pre.symmetric_difference(&pending_post){
            if item != &transfer  {
                return Ok(false);
            }
        }

        // check that gas fees were put into escrow
        if let Some(SignedAmount::Negative(amount)) = self.account_balance_delta(&transfer.gas_fee.payer) {
            if amount != transfer.gas_fee.amount {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
        // TODO: Check that correct amount was received in escrow
        // TODO: Verify nonce

        Ok(true)
    }
}
