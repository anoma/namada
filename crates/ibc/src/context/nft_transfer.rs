//! IBC Non-Fungible token transfer context

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use ibc::apps::nft_transfer::context::{
    NftTransferExecutionContext, NftTransferValidationContext,
};
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::apps::nft_transfer::types::{
    ClassData, ClassUri, Memo, PrefixedClassId, TokenData, TokenId, TokenUri,
    PORT_ID_STR,
};
use ibc::core::handler::types::error::ContextError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::address::Address;
use namada_core::token::Amount;
use namada_systems::trans_token;

use super::common::IbcCommonContext;
use crate::{trace, NftClass, NftMetadata, IBC_ESCROW_ADDRESS};

/// NFT transfer context to handle tokens
#[derive(Debug)]
pub struct NftTransferContext<C, Token>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
    _marker: PhantomData<Token>,
}

impl<C, Token> NftTransferContext<C, Token>
where
    C: IbcCommonContext,
    Token: trans_token::Keys,
{
    /// Make new NFT transfer context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    /// Update the mint amount of the token
    fn update_mint_amount(
        &self,
        token: &Address,
        is_minted: bool,
    ) -> Result<(), NftTransferError> {
        let mint = self.inner.borrow().mint_amount(token)?;
        let updated_mint = if is_minted && mint.is_zero() {
            Amount::from_u64(1)
        } else if !is_minted && mint == Amount::from_u64(1) {
            Amount::zero()
        } else {
            return Err(NftTransferError::Other(
                "The mint amount was invalid".to_string(),
            ));
        };
        self.inner
            .borrow_mut()
            .store_mint_amount(token, updated_mint)
            .map_err(NftTransferError::from)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn add_deposit(&self, token: &Address) -> Result<(), NftTransferError> {
        let deposit = self.inner.borrow().deposit(token)?;
        let added_deposit =
            deposit.checked_add(Amount::from_u64(1)).ok_or_else(|| {
                NftTransferError::Other(
                    "The per-epoch deposit overflowed".to_string(),
                )
            })?;
        self.inner
            .borrow_mut()
            .store_deposit(token, added_deposit)
            .map_err(NftTransferError::from)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn add_withdraw(&self, token: &Address) -> Result<(), NftTransferError> {
        let withdraw = self.inner.borrow().withdraw(token)?;
        let added_withdraw =
            withdraw.checked_add(Amount::from_u64(1)).ok_or_else(|| {
                NftTransferError::Other(
                    "The per-epoch withdraw overflowed".to_string(),
                )
            })?;
        self.inner
            .borrow_mut()
            .store_withdraw(token, added_withdraw)
            .map_err(NftTransferError::from)
    }

    fn store_ibc_trace(
        &self,
        owner: &Address,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError> {
        let ibc_trace = trace::ibc_trace_for_nft(class_id, token_id);
        let trace_hash = trace::calc_hash(&ibc_trace);

        self.inner
            .borrow_mut()
            .store_ibc_trace(owner.to_string(), &trace_hash, &ibc_trace)
            .map_err(NftTransferError::from)?;

        self.inner
            .borrow_mut()
            .store_ibc_trace(token_id, &trace_hash, &ibc_trace)
            .map_err(NftTransferError::from)
    }
}

impl<C, Token> NftTransferValidationContext for NftTransferContext<C, Token>
where
    C: IbcCommonContext,
    Token: trans_token::Keys,
{
    type AccountId = Address;
    type Nft = NftMetadata;
    type NftClass = NftClass;

    fn get_port(&self) -> Result<PortId, NftTransferError> {
        Ok(PORT_ID_STR.parse().expect("the ID should be parsable"))
    }

    fn can_send_nft(&self) -> Result<(), NftTransferError> {
        Ok(())
    }

    fn can_receive_nft(&self) -> Result<(), NftTransferError> {
        Ok(())
    }

    /// Validates that the NFT can be created or updated successfully.
    fn create_or_update_class_validate(
        &self,
        class_id: &PrefixedClassId,
        _class_uri: Option<&ClassUri>,
        _class_data: Option<&ClassData>,
    ) -> Result<(), NftTransferError> {
        match self.get_nft_class(class_id) {
            Ok(_) | Err(NftTransferError::NftClassNotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn escrow_nft_validate(
        &self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        // The metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the account owns the NFT
        if self.inner.borrow().is_nft_owned::<Token>(
            class_id,
            token_id,
            from_account,
        )? {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The sender balance is invalid: sender {from_account}, \
                 class_id {class_id}, token_id {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn unescrow_nft_validate(
        &self,
        _to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError> {
        // The metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the NFT is escrowed
        if self.inner.borrow().is_nft_owned::<Token>(
            class_id,
            token_id,
            &IBC_ESCROW_ADDRESS,
        )? {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The escrow balance is invalid: class_id {class_id}, token_id \
                 {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn mint_nft_validate(
        &self,
        _account: &Self::AccountId,
        _class_id: &PrefixedClassId,
        _token_id: &TokenId,
        _token_uri: Option<&TokenUri>,
        _token_data: Option<&TokenData>,
    ) -> Result<(), NftTransferError> {
        // Balance changes will be validated by Multitoken VP
        Ok(())
    }

    fn burn_nft_validate(
        &self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        // Metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the account owns the NFT
        if self
            .inner
            .borrow()
            .is_nft_owned::<Token>(class_id, token_id, account)?
        {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The sender balance is invalid: sender {account}, class_id \
                 {class_id}, token_id {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn token_hash_string(
        &self,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Option<String> {
        Some(trace::calc_hash(format!("{class_id}/{token_id}")))
    }

    /// Returns the NFT
    fn get_nft(
        &self,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<Self::Nft, NftTransferError> {
        match self.inner.borrow().nft_metadata(class_id, token_id) {
            Ok(Some(nft)) => Ok(nft),
            Ok(None) => Err(NftTransferError::NftNotFound),
            Err(e) => Err(NftTransferError::ContextError(e)),
        }
    }

    /// Returns the NFT class
    fn get_nft_class(
        &self,
        class_id: &PrefixedClassId,
    ) -> Result<Self::NftClass, NftTransferError> {
        match self.inner.borrow().nft_class(class_id) {
            Ok(Some(class)) => Ok(class),
            Ok(None) => Err(NftTransferError::NftClassNotFound),
            Err(e) => Err(NftTransferError::ContextError(e)),
        }
    }
}

impl<C, Token> NftTransferExecutionContext for NftTransferContext<C, Token>
where
    C: IbcCommonContext,
    Token: trans_token::Keys,
{
    fn create_or_update_class_execute(
        &self,
        class_id: &PrefixedClassId,
        class_uri: Option<&ClassUri>,
        class_data: Option<&ClassData>,
    ) -> Result<(), NftTransferError> {
        let class = NftClass {
            class_id: class_id.clone(),
            class_uri: class_uri.cloned(),
            class_data: class_data.cloned(),
        };
        self.inner
            .borrow_mut()
            .store_nft_class(class)
            .map_err(|e| e.into())
    }

    fn escrow_nft_execute(
        &mut self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        let ibc_token = trace::ibc_token_for_nft(class_id, token_id);

        self.add_withdraw(&ibc_token)?;

        self.inner
            .borrow_mut()
            .transfer_token(
                from_account,
                &IBC_ESCROW_ADDRESS,
                &ibc_token,
                Amount::from_u64(1),
            )
            .map_err(|e| ContextError::from(e).into())
    }

    /// Executes the unescrow of the NFT in a user account.
    fn unescrow_nft_execute(
        &mut self,
        to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError> {
        let ibc_token = trace::ibc_token_for_nft(class_id, token_id);

        self.add_deposit(&ibc_token)?;

        self.inner
            .borrow_mut()
            .transfer_token(
                &IBC_ESCROW_ADDRESS,
                to_account,
                &ibc_token,
                Amount::from_u64(1),
            )
            .map_err(|e| ContextError::from(e).into())
    }

    fn mint_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        token_uri: Option<&TokenUri>,
        token_data: Option<&TokenData>,
    ) -> Result<(), NftTransferError> {
        let ibc_token = trace::ibc_token_for_nft(class_id, token_id);

        // create or update the metadata
        let metadata = NftMetadata {
            class_id: class_id.clone(),
            token_id: token_id.clone(),
            token_uri: token_uri.cloned(),
            token_data: token_data.cloned(),
        };
        self.inner.borrow_mut().store_nft_metadata(metadata)?;

        self.update_mint_amount(&ibc_token, true)?;
        self.add_deposit(&ibc_token)?;

        // Store the IBC trace with the token hash to be able to retrieve it
        // later
        self.store_ibc_trace(account, class_id, token_id)?;

        self.inner
            .borrow_mut()
            .mint_token(account, &ibc_token, Amount::from_u64(1))
            .map_err(|e| ContextError::from(e).into())
    }

    fn burn_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        let ibc_token = trace::ibc_token_for_nft(class_id, token_id);

        self.update_mint_amount(&ibc_token, false)?;
        self.add_withdraw(&ibc_token)?;

        self.inner
            .borrow_mut()
            .burn_token(account, &ibc_token, Amount::from_u64(1))
            .map_err(|e| ContextError::from(e).into())
    }
}
