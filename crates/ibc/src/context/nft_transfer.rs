//! IBC Non-Fungible token transfer context

use std::cell::RefCell;
use std::rc::Rc;

use namada_core::ibc::apps::nft_transfer::context::{
    NftClassContext, NftContext, NftTransferExecutionContext,
    NftTransferValidationContext,
};
use namada_core::ibc::apps::nft_transfer::types::error::NftTransferError;
use namada_core::ibc::apps::nft_transfer::types::{
    ClassData, ClassUri, Memo, PrefixedClassId, TokenData, TokenId, TokenUri,
    PORT_ID_STR,
};
use namada_core::ibc::core::channel::types::error::ChannelError;
use namada_core::ibc::core::handler::types::error::ContextError;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::types::address::Address;
use namada_core::types::ibc::{NftClass, NftMetadata, IBC_ESCROW_ADDRESS};

use super::common::IbcCommonContext;
use crate::storage;

/// NFT transfer context to handle tokens
#[derive(Debug)]
pub struct NftTransferContext<C>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
}

impl<C> NftTransferContext<C>
where
    C: IbcCommonContext,
{
    /// Make new NFT transfer context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self { inner }
    }
}

impl<C> NftTransferValidationContext for NftTransferContext<C>
where
    C: IbcCommonContext,
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
        class_uri: &ClassUri,
        class_data: &ClassData,
    ) -> Result<(), NftTransferError> {
        match self.get_nft_class(class_id) {
            Err(NftTransferError::NftClassNotFound) => Ok(()),
            Err(e) => Err(e),
            Ok(class) if class.class_id != *class_id => {
                Err(NftTransferError::Other(format!(
                    "The existing Class ID mismatched: class_id {class_id}"
                )))
            }
            _ => Ok(()),
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
        // Assumes that the class ID is prefixed with "port-id/channel-id" or
        // has no prefix
        if self.inner.borrow().is_valid_nft_balance(
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
        // Assumes that the class ID is prefixed with "port-id/channel-id" or
        // has no prefix
        if self.inner.borrow().is_valid_nft_balance(
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
        _token_uri: &TokenUri,
        _token_data: &TokenData,
    ) -> Result<(), NftTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn burn_nft_validate(
        &self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        if self
            .inner
            .borrow()
            .is_valid_nft_balance(class_id, token_id, account)?
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

    fn class_hash_string(&self, class_id: &PrefixedClassId) -> Option<String> {
        Some(storage::calc_hash(class_id.to_string()))
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

impl<C> NftTransferExecutionContext for NftTransferContext<C>
where
    C: IbcCommonContext,
{
    fn create_or_update_class_execute(
        &self,
        class_id: &PrefixedClassId,
        class_uri: &ClassUri,
        class_data: &ClassData,
    ) -> Result<(), NftTransferError> {
        let class = NftClass {
            class_id: class_id.clone(),
            class_uri: class_uri.clone(),
            class_data: class_data.clone(),
        };
        self.inner
            .borrow_mut()
            .store_nft_class(class_id, class)
            .map_err(|e| ContextError::from(e).into())
    }

    /// Executes the escrow of the NFT in a user account.
    ///
    /// `memo` field allows to incorporate additional contextual details in the
    /// escrow execution.
    fn escrow_nft_execute(
        &mut self,
        from_account: &Self::AccountId,
        port_id: &PortId,
        channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        memo: &Memo,
    ) -> Result<(), NftTransferError>;

    /// Executes the unescrow of the NFT in a user account.
    fn unescrow_nft_execute(
        &mut self,
        to_account: &Self::AccountId,
        port_id: &PortId,
        channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError>;

    /// Executes minting of the NFT in a user account.
    fn mint_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        token_uri: &TokenUri,
        token_data: &TokenData,
    ) -> Result<(), NftTransferError>;

    /// Executes burning of the NFT in a user account.
    ///
    /// `memo` field allows to incorporate additional contextual details in the
    /// burn execution.
    fn burn_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        memo: &Memo,
    ) -> Result<(), NftTransferError>;
}
