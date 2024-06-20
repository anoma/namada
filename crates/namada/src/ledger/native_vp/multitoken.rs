//! Native VP for multitokens

use std::collections::BTreeSet;

use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::HashMap;
use namada_governance::is_proposal_accepted;
use namada_parameters::storage::is_native_token_transferable;
use namada_state::StateRead;
use namada_token::storage_key::is_any_token_parameter_key;
use namada_tx::action::{
    Action, Bond, ClaimRewards, GovAction, PosAction, Read, Withdraw,
};
use namada_tx::BatchedTxRef;
use namada_vp_env::VpEnv;
use thiserror::Error;

use crate::address::{Address, InternalAddress, GOV, POS};
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::storage::{Key, KeySeg};
use crate::token::storage_key::{
    is_any_minted_balance_key, is_any_minter_key, is_any_token_balance_key,
    minter_key,
};
use crate::token::Amount;
use crate::vm::WasmCacheAccess;

/// The owner of some balance change.
#[derive(Copy, Clone, Eq, PartialEq)]
enum Owner<'a> {
    Account(&'a Address),
    Protocol,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Multitoken VP error: governance proposal change is invalid")]
    InvalidGovernanceChange,
    #[error("Multitoken VP error: Native VP error: {0}")]
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
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Is VP triggered by a governance proposal?
        if is_proposal_accepted(
            &self.ctx.pre(),
            tx_data.tx.data(tx_data.cmt).unwrap_or_default().as_ref(),
        )
        .unwrap_or_default()
        {
            return Ok(());
        }

        let native_token = self.ctx.pre().ctx.get_native_token()?;
        let is_native_token_transferable =
            is_native_token_transferable(&self.ctx.pre())?;
        let actions = self.ctx.read_actions()?;
        // The native token can be transferred to and out of the `PoS` and `Gov`
        // accounts, even if `is_native_token_transferable` is false
        let is_allowed_inc = |token: &Address, bal_owner: &Address| -> bool {
            *token != native_token
                || is_native_token_transferable
                || (!actions.is_empty()
                    && actions.iter().all(|action| {
                        has_bal_inc_protocol_action(
                            action,
                            if *bal_owner == POS || *bal_owner == GOV {
                                Owner::Protocol
                            } else {
                                Owner::Account(bal_owner)
                            },
                        )
                    }))
        };
        let is_allowed_dec = |token: &Address, bal_owner: &Address| -> bool {
            *token != native_token
                || is_native_token_transferable
                || (!actions.is_empty()
                    && actions.iter().all(|action| {
                        has_bal_dec_protocol_action(
                            action,
                            if *bal_owner == POS || *bal_owner == GOV {
                                Owner::Protocol
                            } else {
                                Owner::Account(bal_owner)
                            },
                        )
                    }))
        };

        let mut inc_changes: HashMap<Address, Amount> = HashMap::new();
        let mut dec_changes: HashMap<Address, Amount> = HashMap::new();
        let mut inc_mints: HashMap<Address, Amount> = HashMap::new();
        let mut dec_mints: HashMap<Address, Amount> = HashMap::new();
        for key in keys_changed {
            if let Some([token, owner]) = is_any_token_balance_key(key) {
                let pre: Amount = self.ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = self.ctx.read_post(key)?.unwrap_or_default();
                match post.checked_sub(pre) {
                    Some(diff) => {
                        if !is_allowed_inc(token, owner) {
                            tracing::debug!(
                                "Native token deposit isn't allowed"
                            );
                            return Err(Error::NativeVpError(
                                native_vp::Error::SimpleMessage(
                                    "Native token deposit isn't allowed",
                                ),
                            ));
                        }
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
                        if !is_allowed_dec(token, owner) {
                            tracing::debug!(
                                "Native token withdraw isn't allowed"
                            );
                            return Err(Error::NativeVpError(
                                native_vp::Error::SimpleMessage(
                                    "Native token deposit isn't allowed",
                                ),
                            ));
                        }
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
                if *token == native_token && !is_native_token_transferable {
                    tracing::debug!(
                        "Minting/Burning native token isn't allowed"
                    );
                    return Err(Error::NativeVpError(
                        native_vp::Error::SimpleMessage(
                            "Minting/Burning native token isn't allowed",
                        ),
                    ));
                }

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
                self.is_valid_minter(token, verifiers)?;
            } else if let Some(token) = is_any_minter_key(key) {
                self.is_valid_minter(token, verifiers)?;
            } else if is_any_token_parameter_key(key).is_some() {
                return self.is_valid_parameter(tx_data);
            } else if key.segments.first()
                == Some(
                    &Address::Internal(InternalAddress::Multitoken).to_db_key(),
                )
            {
                // Reject when trying to update an unexpected key under
                // `#Multitoken/...`
                return Err(native_vp::Error::new_alloc(format!(
                    "Unexpected change to the multitoken account: {key}"
                ))
                .into());
            }
        }

        let mut all_tokens = BTreeSet::new();
        all_tokens.extend(inc_changes.keys().cloned());
        all_tokens.extend(dec_changes.keys().cloned());
        all_tokens.extend(inc_mints.keys().cloned());
        all_tokens.extend(dec_mints.keys().cloned());

        all_tokens.iter().try_for_each(|token| {
            if token.is_internal()
                && matches!(token, Address::Internal(InternalAddress::Nut(_)))
                && !verifiers.contains(token)
            {
                // Established address tokens, IbcToken and Erc20 do not have
                // VPs themselves, their validation is handled
                // by the `Multitoken` internal address,
                // but internal token Nut addresses have to verify the transfer
                return Err(native_vp::Error::new_alloc(format!(
                    "Token {token} must verify the tx"
                ))
                .into());
            }

            let inc_change =
                inc_changes.get(token).cloned().unwrap_or_default();
            let dec_change =
                dec_changes.get(token).cloned().unwrap_or_default();
            let inc_mint = inc_mints.get(token).cloned().unwrap_or_default();
            let dec_mint = dec_mints.get(token).cloned().unwrap_or_default();

            let token_changes_are_balanced =
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
                };

            token_changes_are_balanced.ok_or_else(|| {
                native_vp::Error::new_const(
                    "The transaction's token changes are unbalanced",
                )
                .into()
            })
        })
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
    ) -> Result<()> {
        match token {
            Address::Internal(InternalAddress::IbcToken(_)) => {
                // Check if the minter is set
                let minter_key = minter_key(token);
                match self.ctx.read_post::<Address>(&minter_key)? {
                    Some(minter)
                        if minter
                            == Address::Internal(InternalAddress::Ibc) =>
                    {
                        verifiers.contains(&minter).ok_or_else(|| {
                            native_vp::Error::new_const(
                                "The IBC VP was not triggered",
                            )
                            .into()
                        })
                    }
                    _ => Err(native_vp::Error::new_const(
                        "Only the IBC account is able to mint IBC tokens",
                    )
                    .into()),
                }
            }
            _ => Err(native_vp::Error::new_alloc(format!(
                "Attempted to mint non-IBC token {token}"
            ))
            .into()),
        }
    }

    /// Return if the parameter change was done via a governance proposal
    pub fn is_valid_parameter(
        &self,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        batched_tx.tx.data(batched_tx.cmt).map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "Token parameter changes require tx data to be present",
                )
                .into())
            },
            |data| {
                is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "Token parameter changes can only be performed by \
                             a governance proposal that has been accepted",
                        )
                        .into()
                    })
            },
        )
    }
}

fn has_bal_inc_protocol_action(action: &Action, owner: Owner<'_>) -> bool {
    match action {
        Action::Pos(
            PosAction::ClaimRewards(ClaimRewards { validator, source })
            | PosAction::Withdraw(Withdraw { validator, source }),
        ) => match owner {
            Owner::Account(owner) => {
                source.as_ref().unwrap_or(validator) == owner
            }
            // NB: pos or gov's balance can increase
            Owner::Protocol => true,
        },
        // NB: only pos or gov balances can decrease with these actions
        Action::Pos(PosAction::Bond(Bond { .. }))
        | Action::Gov(GovAction::InitProposal { .. }) => {
            owner == Owner::Protocol
        }
        // NB: every other case is invalid
        _ => false,
    }
}

fn has_bal_dec_protocol_action(action: &Action, owner: Owner<'_>) -> bool {
    match action {
        Action::Pos(PosAction::Bond(Bond {
            validator, source, ..
        })) => match owner {
            Owner::Account(owner) => {
                source.as_ref().unwrap_or(validator) == owner
            }
            // NB: pos or gov's balance can decrease
            Owner::Protocol => true,
        },
        Action::Gov(GovAction::InitProposal { author: source }) => {
            match owner {
                Owner::Account(owner) => source == owner,
                // NB: pos or gov's balance can decrease
                Owner::Protocol => true,
            }
        }
        // NB: only pos or gov balances can decrease with these actions
        Action::Pos(
            PosAction::ClaimRewards(ClaimRewards { .. })
            | PosAction::Withdraw(Withdraw { .. }),
        ) => owner == Owner::Protocol,
        // NB: every other case is invalid
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use assert_matches::assert_matches;
    use borsh_ext::BorshSerializeExt;
    use namada_gas::TxGasMeter;
    use namada_parameters::storage::get_native_token_transferable_key;
    use namada_state::testing::TestState;
    use namada_state::StorageWrite;
    use namada_tx::action::Write;
    use namada_tx::data::TxType;
    use namada_tx::{Authorization, BatchedTx, Code, Data, Section, Tx};

    use super::*;
    use crate::core::address::testing::{
        established_address_1, established_address_2, nam,
    };
    use crate::key::testing::keypair_1;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::ibc::trace::ibc_token;
    use crate::storage::TxIndex;
    use crate::token::storage_key::{balance_key, minted_balance_key};
    use crate::vm::wasm::compilation_cache::common::testing::cache as wasm_cache;

    const ADDRESS: Address = Address::Internal(InternalAddress::Multitoken);

    fn init_state() -> TestState {
        let mut state = TestState::default();
        namada_parameters::init_test_storage(&mut state).unwrap();
        state
    }

    fn dummy_tx(state: &TestState) -> BatchedTx {
        let tx_code = vec![];
        let tx_data = vec![];
        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            tx.sechashes(),
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        tx.batch_first_tx()
    }

    fn transfer(
        state: &mut TestState,
        src: &Address,
        dest: &Address,
    ) -> BTreeSet<Key> {
        let mut keys_changed = BTreeSet::new();

        let src_key = balance_key(&nam(), src);
        let amount = Amount::native_whole(100);
        state
            .db_write(&src_key, amount.serialize_to_vec())
            .expect("write failed");

        // transfer 10
        let amount = Amount::native_whole(90);
        state
            .write_log_mut()
            .write(&src_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(src_key);

        let dest_key = balance_key(&nam(), dest);
        let amount = Amount::native_whole(10);
        state
            .write_log_mut()
            .write(&dest_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(dest_key);

        keys_changed
    }

    #[test]
    fn test_valid_transfer() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_transfer() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        // receive more than 10
        let dest_key = balance_key(&nam(), &dest);
        let amount = Amount::native_whole(100);
        state
            .write_log_mut()
            .write(&dest_key, amount.serialize_to_vec())
            .expect("write failed");

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_valid_mint() {
        let mut state = init_state();
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
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        // The token must be part of the verifier set (checked by MultitokenVp)
        verifiers.insert(token);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_mint() {
        let mut state = init_state();
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
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_no_minter() {
        let mut state = init_state();
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
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_invalid_minter() {
        let mut state = init_state();
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
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_invalid_minter_update() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        let minter_key = minter_key(&nam());
        let minter = established_address_1();
        state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");

        keys_changed.insert(minter_key);

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_invalid_key_update() {
        let mut state = init_state();
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
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers)
                .is_err()
        );
    }

    #[test]
    fn test_native_token_not_transferable() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert_matches!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_native_token_transferable_to_pos() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = POS;
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Pos(PosAction::Bond(Bond {
                validator: established_address_1(),
                source: None,
                amount: Amount::native_whole(90),
            })))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert_matches!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers),
            Ok(_)
        );
    }

    #[test]
    fn test_native_token_transferable_from_gov() {
        let mut state = init_state();
        let src = GOV;
        let dest = established_address_1();
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Gov(GovAction::InitProposal {
                author: established_address_1(),
            }))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert_matches!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_native_token_transferable_to_gov() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = GOV;
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Gov(GovAction::InitProposal {
                author: established_address_1(),
            }))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert_matches!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers),
            Ok(_)
        );
    }

    /// Check that even if native token transfers are disabled, we can
    /// still claim PoS rewards.
    #[test]
    fn test_native_token_transferable_from_pos() {
        let mut state = init_state();

        // simulate claiming PoS rewards
        let src = POS;
        let dest = established_address_1();
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Pos(PosAction::ClaimRewards(ClaimRewards {
                validator: established_address_1(),
                source: None,
            })))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let tx_index = TxIndex::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        ));
        let (vp_wasm_cache, _vp_cache_dir) = wasm_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let vp = MultitokenVp { ctx };
        assert_matches!(
            vp.validate_tx(&tx.batch_ref_tx(&cmt), &keys_changed, &verifiers),
            Ok(_)
        );
    }
}
