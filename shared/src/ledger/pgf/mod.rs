//! Pgf VP

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use namada_core::ledger::governance::storage::keys as gov_storage;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::ledger::governance::utils::is_valid_validator_voting_period;
use namada_core::ledger::storage;
use namada_core::ledger::storage_api::governance::is_proposal_accepted;
use namada_core::ledger::vp_env::VpEnv;
use namada_proof_of_stake::is_validator;
use thiserror::Error;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage_api::StorageRead;
use crate::ledger::{native_vp, pos};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{Epoch, Key};
use crate::types::token;
use crate::vm::WasmCacheAccess;

/// for handling Pgf NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

/// The pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Pgf VP
pub struct PgfVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for PgfVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Pgf;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let native_token = self.ctx.pre().get_native_token()?;

        let result = keys_changed.iter().all(|key| {
            true
        });
        Ok(result)
    }
}

impl<'a, DB, H, CA> PgfVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{

}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType {
    #[allow(non_camel_case_types)]
    COUNTER,
    #[allow(non_camel_case_types)]
    VOTE,
    #[allow(non_camel_case_types)]
    CONTENT,
    #[allow(non_camel_case_types)]
    PROPOSAL_CODE,
    #[allow(non_camel_case_types)]
    TYPE,
    #[allow(non_camel_case_types)]
    PROPOSAL_COMMIT,
    #[allow(non_camel_case_types)]
    GRACE_EPOCH,
    #[allow(non_camel_case_types)]
    START_EPOCH,
    #[allow(non_camel_case_types)]
    END_EPOCH,
    #[allow(non_camel_case_types)]
    FUNDS,
    #[allow(non_camel_case_types)]
    BALANCE,
    #[allow(non_camel_case_types)]
    AUTHOR,
    #[allow(non_camel_case_types)]
    PARAMETER,
    #[allow(non_camel_case_types)]
    UNKNOWN_GOVERNANCE,
    #[allow(non_camel_case_types)]
    UNKNOWN,
}

impl KeyType {
    fn from_key(key: &Key, native_token: &Address) -> Self {
        if gov_storage::is_vote_key(key) {
            Self::VOTE
        } else if gov_storage::is_content_key(key) {
            KeyType::CONTENT
        } else if gov_storage::is_proposal_type_key(key) {
            Self::TYPE
        } else if gov_storage::is_proposal_code_key(key) {
            Self::PROPOSAL_CODE
        } else if gov_storage::is_grace_epoch_key(key) {
            KeyType::GRACE_EPOCH
        } else if gov_storage::is_start_epoch_key(key) {
            KeyType::START_EPOCH
        } else if gov_storage::is_commit_proposal_key(key) {
            KeyType::PROPOSAL_COMMIT
        } else if gov_storage::is_end_epoch_key(key) {
            KeyType::END_EPOCH
        } else if gov_storage::is_balance_key(key) {
            KeyType::FUNDS
        } else if gov_storage::is_author_key(key) {
            KeyType::AUTHOR
        } else if gov_storage::is_counter_key(key) {
            KeyType::COUNTER
        } else if gov_storage::is_parameter_key(key) {
            KeyType::PARAMETER
        } else if token::is_balance_key(native_token, key).is_some() {
            KeyType::BALANCE
        } else if gov_storage::is_governance_key(key) {
            KeyType::UNKNOWN_GOVERNANCE
        } else {
            KeyType::UNKNOWN
        }
    }
}
