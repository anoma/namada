//! Native VP for multitokens

use std::collections::{BTreeSet, HashMap};

use namada_governance::is_proposal_accepted;
use namada_state::StateRead;
use namada_token::storage_key::is_any_token_parameter_key;
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use thiserror::Error;

use crate::address::{Address, InternalAddress};
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::storage::{Key, KeySeg};
use crate::token::storage_key::{
    is_any_minted_balance_key, is_any_minter_key, is_any_token_balance_key,
    minter_key,
};
use crate::token::Amount;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Multitoken functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Multitoken VP
pub struct MultitokenVp<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> NativeVp for MultitokenVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let mut inc_changes: HashMap<Address, Amount> = HashMap::new();
        let mut dec_changes: HashMap<Address, Amount> = HashMap::new();
        let mut inc_mints: HashMap<Address, Amount> = HashMap::new();
        let mut dec_mints: HashMap<Address, Amount> = HashMap::new();
        for key in keys_changed {
            if let Some([token, _]) = is_any_token_balance_key(key) {
                let pre: Amount = self.ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = self.ctx.read_post(key)?.unwrap_or_default();
                match post.checked_sub(pre) {
                    Some(diff) => {
                        let change =
                            inc_changes.entry(token.clone()).or_default();
                        *change =
                            change.checked_add(diff).ok_or_else(|| {
                                Error::NativeVpError(
                                    native_vp::Error::SimpleMessage(
                                        "Overflowed in balance check",
                                    ),
                                )
                            })?;
                    }
                    None => {
                        let diff = pre
                            .checked_sub(post)
                            .expect("Underflow shouldn't happen here");
                        let change =
                            dec_changes.entry(token.clone()).or_default();
                        *change =
                            change.checked_add(diff).ok_or_else(|| {
                                Error::NativeVpError(
                                    native_vp::Error::SimpleMessage(
                                        "Overflowed in balance check",
                                    ),
                                )
                            })?;
                    }
                }
            } else if let Some(token) = is_any_minted_balance_key(key) {
                let pre: Amount = self.ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = self.ctx.read_post(key)?.unwrap_or_default();
                match post.checked_sub(pre) {
                    Some(diff) => {
                        let mint = inc_mints.entry(token.clone()).or_default();
                        *mint = mint.checked_add(diff).ok_or_else(|| {
                            Error::NativeVpError(
                                native_vp::Error::SimpleMessage(
                                    "Overflowed in balance check",
                                ),
                            )
                        })?;
                    }
                    None => {
                        let diff = pre
                            .checked_sub(post)
                            .expect("Underflow shouldn't happen here");
                        let mint = dec_mints.entry(token.clone()).or_default();
                        *mint = mint.checked_add(diff).ok_or_else(|| {
                            Error::NativeVpError(
                                native_vp::Error::SimpleMessage(
                                    "Overflowed in balance check",
                                ),
                            )
                        })?;
                    }
                }
                // Check if the minter is set
                if !self.is_valid_minter(token, verifiers)? {
                    return Ok(false);
                }
            } else if let Some(token) = is_any_minter_key(key) {
                if !self.is_valid_minter(token, verifiers)? {
                    return Ok(false);
                }
            } else if is_any_token_parameter_key(key).is_some() {
                return self.is_valid_parameter(tx_data);
            } else if key.segments.first()
                == Some(
                    &Address::Internal(InternalAddress::Multitoken).to_db_key(),
                )
            {
                // Reject when trying to update an unexpected key under
                // `#Multitoken/...`
                return Ok(false);
            }
        }

        let mut all_tokens = BTreeSet::new();
        all_tokens.extend(inc_changes.keys().cloned());
        all_tokens.extend(dec_changes.keys().cloned());
        all_tokens.extend(inc_mints.keys().cloned());
        all_tokens.extend(dec_mints.keys().cloned());

        Ok(all_tokens.iter().all(|token| {
            let inc_change =
                inc_changes.get(token).cloned().unwrap_or_default();
            let dec_change =
                dec_changes.get(token).cloned().unwrap_or_default();
            let inc_mint = inc_mints.get(token).cloned().unwrap_or_default();
            let dec_mint = dec_mints.get(token).cloned().unwrap_or_default();

            if inc_change >= dec_change && inc_mint >= dec_mint {
                inc_change.checked_sub(dec_change)
                    == inc_mint.checked_sub(dec_mint)
            } else if (inc_change < dec_change && inc_mint >= dec_mint)
                || (inc_change >= dec_change && inc_mint < dec_mint)
            {
                false
            } else {
                dec_change.checked_sub(inc_change)
                    == dec_mint.checked_sub(inc_mint)
            }
        }))
    }
}

impl<'a, S, CA> MultitokenVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Return the minter if the minter is valid and the minter VP exists
    pub fn is_valid_minter(
        &self,
        token: &Address,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        match token {
            Address::Internal(InternalAddress::IbcToken(_)) => {
                // Check if the minter is set
                let minter_key = minter_key(token);
                match self.ctx.read_post::<Address>(&minter_key)? {
                    Some(minter)
                        if minter
                            == Address::Internal(InternalAddress::Ibc) =>
                    {
                        Ok(verifiers.contains(&minter))
                    }
                    _ => Ok(false),
                }
            }
            _ => {
                // ERC20 and other tokens should not be minted by a wasm
                // transaction
                Ok(false)
            }
        }
    }

    /// Return if the parameter change was done via a governance proposal
    pub fn is_valid_parameter(&self, tx: &Tx) -> Result<bool> {
        match tx.data() {
            Some(data) => is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                .map_err(Error::NativeVpError),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use borsh_ext::BorshSerializeExt;
    use namada_core::validity_predicate::VpSentinel;
    use namada_gas::TxGasMeter;
    use namada_state::testing::TestState;
    use namada_tx::data::TxType;
    use namada_tx::{Code, Data, Section, Signature};

    use super::*;
    use crate::core::address::testing::{
        established_address_1, established_address_2, nam,
    };
    use crate::key::testing::keypair_1;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::ibc::storage::ibc_token;
    use crate::storage::TxIndex;
    use crate::token::storage_key::{balance_key, minted_balance_key};
    use crate::vm::wasm::compilation_cache::common::testing::cache as wasm_cache;

    const ADDRESS: Address = Address::Internal(InternalAddress::Multitoken);

    fn dummy_tx(state: &TestState) -> Tx {
        let tx_code = vec![];
        let tx_data = vec![];
        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Signature(Signature::new(
            tx.sechashes(),
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        tx
    }

    #[test]
    fn test_valid_transfer() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        let sender = established_address_1();
        let sender_key = balance_key(&nam(), &sender);
        let amount = Amount::native_whole(100);
        state
            .db_write(&sender_key, amount.serialize_to_vec())
            .expect("write failed");

        // transfer 10
        let amount = Amount::native_whole(90);
        state
            .write_log_mut()
            .write(&sender_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(sender_key);
        let receiver = established_address_2();
        let receiver_key = balance_key(&nam(), &receiver);
        let amount = Amount::native_whole(10);
        state
            .write_log_mut()
            .write(&receiver_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(receiver_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(sender);
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_invalid_transfer() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        let sender = established_address_1();
        let sender_key = balance_key(&nam(), &sender);
        let amount = Amount::native_whole(100);
        state
            .db_write(&sender_key, amount.serialize_to_vec())
            .expect("write failed");

        // transfer 10
        let amount = Amount::native_whole(90);
        state
            .write_log_mut()
            .write(&sender_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(sender_key);
        let receiver = established_address_2();
        let receiver_key = balance_key(&nam(), &receiver);
        // receive more than 10
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&receiver_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(receiver_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_valid_mint() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // minter
        let minter = Address::Internal(InternalAddress::Ibc);
        let minter_key = minter_key(&token);
        state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_invalid_mint() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&nam(), &target);
        // mint more than 100
        let amount = Amount::native_whole(1000);
        state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&nam());
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // minter
        let minter = nam();
        let minter_key = minter_key(&nam());
        state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_no_minter() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // no minter is set

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_invalid_minter() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // invalid minter
        let minter = established_address_1();
        let minter_key = minter_key(&token);
        state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_invalid_minter_update() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        let minter_key = minter_key(&nam());
        let minter = established_address_1();
        state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");

        keys_changed.insert(minter_key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }

    #[test]
    fn test_invalid_key_update() {
        let mut state = TestState::default();
        let mut keys_changed = BTreeSet::new();

        let key = Key::from(
            Address::Internal(InternalAddress::Multitoken).to_db_key(),
        )
        .push(&"invalid_segment".to_string())
        .unwrap();
        state
            .write_log_mut()
            .write(&key, 0.serialize_to_vec())
            .expect("write failed");

        keys_changed.insert(key);

        let tx_index = TxIndex::default();
        let tx = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let sentinel = RefCell::new(VpSentinel::default());
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &tx_index,
            &gas_meter,
            &sentinel,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            !vp.validate_tx(&tx, &keys_changed, &verifiers)
                .expect("validation failed")
        );
    }
}
