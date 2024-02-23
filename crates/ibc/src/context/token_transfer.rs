//! IBC token transfer context

use std::cell::RefCell;
use std::rc::Rc;

use namada_core::address::{Address, InternalAddress};
use namada_core::ibc::apps::transfer::context::{
    TokenTransferExecutionContext, TokenTransferValidationContext,
};
use namada_core::ibc::apps::transfer::types::error::TokenTransferError;
use namada_core::ibc::apps::transfer::types::{PrefixedCoin, PrefixedDenom};
use namada_core::ibc::core::channel::types::error::ChannelError;
use namada_core::ibc::core::handler::types::error::ContextError;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::token;
use namada_core::uint::Uint;
use namada_token::read_denom;

use super::common::IbcCommonContext;
use crate::storage;

/// Token transfer context to handle tokens
#[derive(Debug)]
pub struct TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
}

impl<C> TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    /// Make new token transfer context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self { inner }
    }

    /// Get the token address and the amount from PrefixedCoin. If the base
    /// denom is not an address, it returns `IbcToken`
    fn get_token_amount(
        &self,
        coin: &PrefixedCoin,
    ) -> Result<(Address, token::DenominatedAmount), TokenTransferError> {
        let token = match Address::decode(coin.denom.base_denom.as_str()) {
            Ok(token_addr) if coin.denom.trace_path.is_empty() => token_addr,
            _ => storage::ibc_token(coin.denom.to_string()),
        };

        // Convert IBC amount to Namada amount for the token
        let denom = read_denom(&*self.inner.borrow(), &token)
            .map_err(ContextError::from)?
            .unwrap_or(token::Denomination(0));
        let uint_amount = Uint(primitive_types::U256::from(coin.amount).0);
        let amount =
            token::Amount::from_uint(uint_amount, denom).map_err(|e| {
                TokenTransferError::ContextError(
                    ChannelError::Other {
                        description: format!(
                            "The IBC amount is invalid: Coin {coin}, Error {e}",
                        ),
                    }
                    .into(),
                )
            })?;
        let amount = token::DenominatedAmount::new(amount, denom);

        Ok((token, amount))
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

    fn get_escrow_account(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
    ) -> Result<Self::AccountId, TokenTransferError> {
        Ok(Address::Internal(InternalAddress::Ibc))
    }

    fn can_send_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn can_receive_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn send_coins_validate(
        &self,
        _from: &Self::AccountId,
        _to: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn mint_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn burn_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(storage::calc_hash(denom.to_string()))
    }
}

impl<C> TokenTransferExecutionContext for TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    fn send_coins_execute(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // Assumes that the coin denom is prefixed with "port-id/channel-id" or
        // has no prefix
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.inner
            .borrow_mut()
            .transfer_token(from, to, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // The trace path of the denom is already updated if receiving the token
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.inner
            .borrow_mut()
            .mint_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        // The burn is "unminting" from the minted balance
        self.inner
            .borrow_mut()
            .burn_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }
}
