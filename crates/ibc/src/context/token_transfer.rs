//! IBC token transfer context

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use ibc::apps::transfer::context::{
    TokenTransferExecutionContext, TokenTransferValidationContext,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::{Memo, PrefixedCoin, PrefixedDenom};
use ibc::core::channel::types::error::ChannelError;
use ibc::core::handler::types::error::ContextError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::address::{Address, InternalAddress};
use namada_core::token::Amount;
use namada_core::uint::Uint;

use super::common::IbcCommonContext;
use crate::{trace, IBC_ESCROW_ADDRESS};

/// Token transfer context to handle tokens
#[derive(Debug)]
pub struct TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
}

impl<C> TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    /// Make new token transfer context
    pub fn new(
        inner: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self { inner, verifiers }
    }

    /// Insert a verifier address whose VP will verify the tx.
    fn insert_verifier(&mut self, addr: &Address) {
        self.verifiers.borrow_mut().insert(addr.clone());
    }

    /// Get the token address and the amount from PrefixedCoin. If the base
    /// denom is not an address, it returns `IbcToken`
    fn get_token_amount(
        &self,
        coin: &PrefixedCoin,
    ) -> Result<(Address, Amount), TokenTransferError> {
        let token = match Address::decode(coin.denom.base_denom.as_str()) {
            Ok(token_addr) if coin.denom.trace_path.is_empty() => token_addr,
            _ => trace::ibc_token(coin.denom.to_string()),
        };

        // Convert IBC amount to Namada amount for the token
        let uint_amount = Uint(primitive_types::U256::from(coin.amount).0);
        let amount = Amount::from_uint(uint_amount, 0).map_err(|e| {
            TokenTransferError::ContextError(
                ChannelError::Other {
                    description: format!(
                        "The IBC amount is invalid: Coin {coin}, Error {e}",
                    ),
                }
                .into(),
            )
        })?;

        Ok((token, amount))
    }

    /// Update the mint amount of the token
    fn update_mint_amount(
        &self,
        token: &Address,
        amount: Amount,
        is_minted: bool,
    ) -> Result<(), TokenTransferError> {
        let mint = self.inner.borrow().mint_amount(token)?;
        let updated_mint = if is_minted {
            mint.checked_add(amount).ok_or_else(|| {
                TokenTransferError::Other(
                    "The mint amount overflowed".to_string(),
                )
            })?
        } else {
            mint.checked_sub(amount).ok_or_else(|| {
                TokenTransferError::Other(
                    "The mint amount underflowed".to_string(),
                )
            })?
        };
        self.inner
            .borrow_mut()
            .store_mint_amount(token, updated_mint)
            .map_err(TokenTransferError::from)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn add_deposit(
        &self,
        token: &Address,
        amount: Amount,
    ) -> Result<(), TokenTransferError> {
        let deposit = self.inner.borrow().deposit(token)?;
        let added_deposit = deposit.checked_add(amount).ok_or_else(|| {
            TokenTransferError::Other(
                "The per-epoch deposit overflowed".to_string(),
            )
        })?;
        self.inner
            .borrow_mut()
            .store_deposit(token, added_deposit)
            .map_err(TokenTransferError::from)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn add_withdraw(
        &self,
        token: &Address,
        amount: Amount,
    ) -> Result<(), TokenTransferError> {
        let withdraw = self.inner.borrow().withdraw(token)?;
        let added_withdraw = withdraw.checked_add(amount).ok_or_else(|| {
            TokenTransferError::Other(
                "The per-epoch withdraw overflowed".to_string(),
            )
        })?;
        self.inner
            .borrow_mut()
            .store_withdraw(token, added_withdraw)
            .map_err(TokenTransferError::from)
    }

    fn maybe_store_ibc_denom(
        &self,
        owner: &Address,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        if coin.denom.trace_path.is_empty() {
            // It isn't an IBC denom
            return Ok(());
        }
        let ibc_denom = coin.denom.to_string();
        let trace_hash = trace::calc_hash(&ibc_denom);

        self.inner
            .borrow_mut()
            .store_ibc_trace(owner.to_string(), &trace_hash, &ibc_denom)
            .map_err(TokenTransferError::from)?;

        let base_token = Address::decode(coin.denom.base_denom.as_str())
            .map(|a| a.to_string())
            .unwrap_or(coin.denom.base_denom.to_string());
        self.inner
            .borrow_mut()
            .store_ibc_trace(base_token, &trace_hash, &ibc_denom)
            .map_err(TokenTransferError::from)
    }
}

impl<C> TokenTransferValidationContext for TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    type AccountId = Address;

    fn get_port(&self) -> Result<PortId, TokenTransferError> {
        Ok(PortId::transfer())
    }

    fn can_send_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn can_receive_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn escrow_coins_validate(
        &self,
        _from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn unescrow_coins_validate(
        &self,
        _to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn mint_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn burn_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(trace::calc_hash(denom.to_string()))
    }
}

impl<C> TokenTransferExecutionContext for TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    fn escrow_coins_execute(
        &mut self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.add_withdraw(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        self.inner
            .borrow_mut()
            .transfer_token(
                from_account,
                &IBC_ESCROW_ADDRESS,
                &ibc_token,
                amount,
            )
            .map_err(|e| ContextError::from(e).into())
    }

    fn unescrow_coins_execute(
        &mut self,
        to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.add_deposit(&ibc_token, amount)?;

        self.inner
            .borrow_mut()
            .transfer_token(&IBC_ESCROW_ADDRESS, to_account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // The trace path of the denom is already updated if receiving the token
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.update_mint_amount(&ibc_token, amount, true)?;
        self.add_deposit(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        // Store the IBC denom with the token hash to be able to retrieve it
        // later
        self.maybe_store_ibc_denom(account, coin)?;

        self.inner
            .borrow_mut()
            .mint_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.update_mint_amount(&ibc_token, amount, false)?;
        self.add_withdraw(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        // The burn is "unminting" from the minted balance
        self.inner
            .borrow_mut()
            .burn_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }
}
