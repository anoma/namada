//! Governance VP

pub mod utils;

use std::collections::BTreeSet;

use namada_core::ledger::governance::storage as gov_storage;
use namada_core::ledger::storage;
use namada_core::ledger::vp_env::VpEnv;
use namada_core::types::governance::{ProposalVote, Stewards, VoteType};
use namada_core::types::transaction::governance::ProposalType;
use thiserror::Error;
use utils::is_valid_validator_voting_period;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage_api::StorageRead;
use crate::ledger::{native_vp, pos};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{Epoch, Key};
use crate::types::token;
use crate::vm::WasmCacheAccess;

/// for handling Governance NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Governance VP
pub struct GovernanceVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for GovernanceVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Governance;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let (is_valid_keys_set, set_count) =
            self.is_valid_key_set(keys_changed)?;
        if !is_valid_keys_set {
            return Ok(false);
        };
        let native_token = self.ctx.pre().get_native_token()?;

        let result = keys_changed.iter().all(|key| {
            let proposal_id = gov_storage::get_proposal_id(key);
            let key_type = KeyType::from_key(key, &native_token);

            let result = match (key_type, proposal_id) {
                (KeyType::VOTE, Some(proposal_id)) => {
                    self.is_valid_vote_key(proposal_id, key, verifiers)
                }
                (KeyType::CONTENT, Some(proposal_id)) => {
                    self.is_valid_content_key(proposal_id)
                }
                (KeyType::TYPE, Some(proposal_id)) => {
                    self.is_valid_proposal_type(proposal_id)
                }
                (KeyType::PROPOSAL_CODE, Some(proposal_id)) => {
                    self.is_valid_proposal_code(proposal_id)
                }
                (KeyType::GRACE_EPOCH, Some(proposal_id)) => {
                    self.is_valid_grace_epoch(proposal_id)
                }
                (KeyType::START_EPOCH, Some(proposal_id)) => {
                    self.is_valid_start_epoch(proposal_id)
                }
                (KeyType::END_EPOCH, Some(proposal_id)) => {
                    self.is_valid_end_epoch(proposal_id)
                }
                (KeyType::FUNDS, Some(proposal_id)) => {
                    self.is_valid_funds(proposal_id, &native_token)
                }
                (KeyType::AUTHOR, Some(proposal_id)) => {
                    self.is_valid_author(proposal_id, verifiers)
                }
                (KeyType::COUNTER, _) => self.is_valid_counter(set_count),
                (KeyType::PROPOSAL_COMMIT, _) => {
                    self.is_valid_proposal_commit()
                }
                (KeyType::PARAMETER, _) => self.is_valid_parameter(tx_data),
                (KeyType::BALANCE, _) => self.is_valid_balance(&native_token),
                (KeyType::UNKNOWN_GOVERNANCE, _) => Ok(false),
                (KeyType::UNKNOWN, _) => Ok(true),
                _ => Ok(false),
            };

            result.unwrap_or(false)
        });
        Ok(result)
    }
}

impl<'a, DB, H, CA> GovernanceVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    fn is_valid_key_set(&self, keys: &BTreeSet<Key>) -> Result<(bool, u64)> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: u64 =
            self.ctx.pre().read(&counter_key)?.unwrap_or_default();
        let post_counter: u64 =
            self.ctx.post().read(&counter_key)?.unwrap_or_default();

        if post_counter < pre_counter {
            return Ok((false, 0));
        }

        for counter in pre_counter..post_counter {
            // Construct the set of expected keys
            // NOTE: we don't check the existance of committing_epoch because
            // it's going to be checked later into the VP
            let mandatory_keys = BTreeSet::from([
                counter_key.clone(),
                gov_storage::get_content_key(counter),
                gov_storage::get_author_key(counter),
                gov_storage::get_proposal_type_key(counter),
                gov_storage::get_funds_key(counter),
                gov_storage::get_voting_start_epoch_key(counter),
                gov_storage::get_voting_end_epoch_key(counter),
                gov_storage::get_grace_epoch_key(counter),
            ]);

            // Check that expected set is a subset the actual one
            if !keys.is_superset(&mandatory_keys) {
                return Ok((false, 0));
            }
        }

        Ok((true, post_counter - pre_counter))
    }

    fn is_valid_vote_key(
        &self,
        proposal_id: u64,
        key: &Key,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let counter_key = gov_storage::get_counter_key();
        let voting_start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let voting_end_epoch_key =
            gov_storage::get_voting_end_epoch_key(proposal_id);

        let current_epoch = self.ctx.get_block_epoch().ok();

        let pre_counter: Option<u64> = self.ctx.pre().read(&counter_key)?;
        let pre_voting_start_epoch: Option<Epoch> =
            self.ctx.pre().read(&voting_start_epoch_key)?;
        let pre_voting_end_epoch: Option<Epoch> =
            self.ctx.pre().read(&voting_end_epoch_key)?;

        let voter = gov_storage::get_voter_address(key);
        let delegation_address = gov_storage::get_vote_delegation_address(key);
        let vote: Option<ProposalVote> = self.ctx.read_post(key)?;

        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: Option<ProposalType> =
            self.ctx.read_pre(&proposal_type_key)?;

        match (
            pre_counter,
            proposal_type,
            vote,
            voter,
            delegation_address,
            current_epoch,
            pre_voting_start_epoch,
            pre_voting_end_epoch,
        ) {
            (
                Some(pre_counter),
                Some(proposal_type),
                Some(vote),
                Some(voter_address),
                Some(delegation_address),
                Some(current_epoch),
                Some(pre_voting_start_epoch),
                Some(pre_voting_end_epoch),
            ) => {
                if pre_counter <= proposal_id {
                    // Invalid proposal id
                    return Ok(false);
                }
                if current_epoch < pre_voting_start_epoch
                    || current_epoch > pre_voting_end_epoch
                {
                    // Voted outside of voting window
                    return Ok(false);
                }

                if let ProposalVote::Yay(vote_type) = vote {
                    if proposal_type != vote_type {
                        return Ok(false);
                    }

                    if let VoteType::ETHBridge(_sig) = vote_type {
                        // TODO: Check the validity of the signature with the
                        // governance ETH key in storage for the given validator
                        // <https://github.com/anoma/namada/issues/1166>
                    }
                }

                match proposal_type {
                    ProposalType::Default(_)
                    | ProposalType::PGFSteward(_)
                    | ProposalType::PGFPayment(_) => {
                        if self
                            .is_validator(
                                pre_voting_start_epoch,
                                verifiers,
                                voter_address,
                                delegation_address,
                            )
                            .unwrap_or(false)
                        {
                            Ok(is_valid_validator_voting_period(
                                current_epoch,
                                pre_voting_start_epoch,
                                pre_voting_end_epoch,
                            ))
                        } else {
                            Ok(self
                                .is_delegator(
                                    pre_voting_start_epoch,
                                    verifiers,
                                    voter_address,
                                    delegation_address,
                                )
                                .unwrap_or(false))
                        }
                    }
                    ProposalType::ETHBridge => Ok(self
                        .is_validator(
                            pre_voting_start_epoch,
                            verifiers,
                            voter_address,
                            delegation_address,
                        )
                        .unwrap_or(false)),
                }
            }
            _ => Ok(false),
        }
    }

    /// Validate a content key
    pub fn is_valid_content_key(&self, proposal_id: u64) -> Result<bool> {
        let content_key: Key = gov_storage::get_content_key(proposal_id);
        let max_content_length_parameter_key =
            gov_storage::get_max_proposal_content_key();

        let has_pre_content: bool = self.ctx.has_key_pre(&content_key)?;
        if has_pre_content {
            return Ok(false);
        }

        let max_content_length: Option<usize> =
            self.ctx.pre().read(&max_content_length_parameter_key)?;
        let post_content: Option<Vec<u8>> =
            self.ctx.read_bytes_post(&content_key)?;

        match (post_content, max_content_length) {
            (Some(post_content), Some(max_content_length)) => {
                Ok(post_content.len() < max_content_length)
            }
            _ => Ok(false),
        }
    }

    /// Validate the proposal type
    pub fn is_valid_proposal_type(&self, proposal_id: u64) -> Result<bool> {
        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type =
            match self.ctx.read_post::<ProposalType>(&proposal_type_key)? {
                Some(proposal_type) => proposal_type,
                None => return Ok(false),
            };

        match proposal_type {
            ProposalType::Default(_) => Ok(true),
            ProposalType::PGFSteward(ref changes) => {
                self.validate_pgf_steward_proposal(changes)
            }
            ProposalType::PGFPayment(_) => Ok(true),
            ProposalType::ETHBridge => Ok(true),
        }
    }

    /// Check that a PGF steward proposal is valid:
    ///
    /// - All the addresses proposed are of type [`Address::Established`]
    /// - The addresses to add are not already part of the PGF Steward set
    /// - The addresses to remove are already part of the PGF Steward set
    fn validate_pgf_steward_proposal(
        &self,
        changes: &Stewards,
    ) -> Result<bool> {
        // Check that all the addresses are established
        for address in changes.add.iter().chain(changes.remove.iter()) {
            match address {
                Address::Established(_) => {
                    // Check that established address exists in
                    // storage
                    let vp_key = Key::validity_predicate(&address);
                    if !self.ctx.has_key_pre(&vp_key)? {
                        return Ok(false);
                    }
                }
                _ => return Ok(false),
            }
        }

        // TODO:
        // Check that the added addresses are not already part of the Stewards' set

        // TODO:
        // Check that the removed addresses are part of the Stewards' set

        Ok(true)
    }

    /// Validate a proposal code
    pub fn is_valid_proposal_code(&self, proposal_id: u64) -> Result<bool> {
        let proposal_type_key: Key =
            gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: Option<ProposalType> =
            self.ctx.read_post(&proposal_type_key)?;

        // Check that the proposal type admits wasm code
        match proposal_type {
            Some(ProposalType::Default(_)) => (),
            _ => return Ok(false),
        }

        let code_key = gov_storage::get_proposal_code_key(proposal_id);
        let max_code_size_parameter_key =
            gov_storage::get_max_proposal_code_size_key();

        let has_pre_code: bool = self.ctx.has_key_pre(&code_key)?;
        if has_pre_code {
            return Ok(false);
        }

        let max_proposal_length: Option<usize> =
            self.ctx.pre().read(&max_code_size_parameter_key)?;
        let post_code: Option<Vec<u8>> = self.ctx.read_bytes_post(&code_key)?;

        match (post_code, max_proposal_length) {
            (Some(post_code), Some(max_content_length)) => {
                Ok(post_code.len() < max_content_length)
            }
            _ => Ok(false),
        }
    }

    /// Validate a grace_epoch key
    pub fn is_valid_grace_epoch(&self, proposal_id: u64) -> Result<bool> {
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let grace_epoch_key = gov_storage::get_grace_epoch_key(proposal_id);
        let min_grace_epoch_key =
            gov_storage::get_min_proposal_grace_epoch_key();

        let has_pre_grace_epoch = self.ctx.has_key_pre(&grace_epoch_key)?;
        if has_pre_grace_epoch {
            return Ok(false);
        }

        let end_epoch: Option<u64> = self.ctx.post().read(&end_epoch_key)?;
        let grace_epoch: Option<u64> =
            self.ctx.post().read(&grace_epoch_key)?;
        let min_grace_epoch: Option<u64> =
            self.ctx.pre().read(&min_grace_epoch_key)?;
        match (min_grace_epoch, grace_epoch, end_epoch) {
            (Some(min_grace_epoch), Some(grace_epoch), Some(end_epoch)) => {
                let committing_epoch_key =
                    gov_storage::get_committing_proposals_key(
                        proposal_id,
                        grace_epoch,
                    );
                let has_post_committing_epoch =
                    self.ctx.has_key_post(&committing_epoch_key)?;

                Ok(has_post_committing_epoch
                    && end_epoch < grace_epoch
                    && grace_epoch - end_epoch >= min_grace_epoch)
            }
            _ => Ok(false),
        }
    }

    /// Validate a start_epoch key
    pub fn is_valid_start_epoch(&self, proposal_id: u64) -> Result<bool> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let min_period_parameter_key =
            gov_storage::get_min_proposal_period_key();

        let current_epoch = self.ctx.get_block_epoch().ok();

        let has_pre_start_epoch = self.ctx.has_key_pre(&start_epoch_key)?;
        let has_pre_end_epoch = self.ctx.has_key_pre(&end_epoch_key)?;

        if has_pre_start_epoch || has_pre_end_epoch {
            return Ok(false);
        }

        let start_epoch: Option<Epoch> =
            self.ctx.post().read(&start_epoch_key)?;
        let end_epoch: Option<Epoch> = self.ctx.post().read(&end_epoch_key)?;
        let min_period: Option<u64> =
            self.ctx.pre().read(&min_period_parameter_key)?;

        match (min_period, start_epoch, end_epoch, current_epoch) {
            (
                Some(min_period),
                Some(start_epoch),
                Some(end_epoch),
                Some(current_epoch),
            ) => {
                if end_epoch <= start_epoch || start_epoch <= current_epoch {
                    return Ok(false);
                }
                Ok((end_epoch - start_epoch) % min_period == 0
                    && (end_epoch - start_epoch).0 >= min_period)
            }
            _ => Ok(false),
        }
    }

    /// Validate a end_epoch key
    fn is_valid_end_epoch(&self, proposal_id: u64) -> Result<bool> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let min_period_parameter_key =
            gov_storage::get_min_proposal_period_key();
        let max_period_parameter_key =
            gov_storage::get_max_proposal_period_key();

        let current_epoch = self.ctx.get_block_epoch().ok();

        let has_pre_start_epoch = self.ctx.has_key_pre(&start_epoch_key)?;
        let has_pre_end_epoch = self.ctx.has_key_pre(&end_epoch_key)?;

        if has_pre_start_epoch || has_pre_end_epoch {
            return Ok(false);
        }

        let start_epoch: Option<Epoch> =
            self.ctx.post().read(&start_epoch_key)?;
        let end_epoch: Option<Epoch> = self.ctx.post().read(&end_epoch_key)?;
        let min_period: Option<u64> =
            self.ctx.pre().read(&min_period_parameter_key)?;
        let max_period: Option<u64> =
            self.ctx.pre().read(&max_period_parameter_key)?;
        match (
            min_period,
            max_period,
            start_epoch,
            end_epoch,
            current_epoch,
        ) {
            (
                Some(min_period),
                Some(max_period),
                Some(start_epoch),
                Some(end_epoch),
                Some(current_epoch),
            ) => {
                if end_epoch <= start_epoch || start_epoch <= current_epoch {
                    return Ok(false);
                }
                Ok((end_epoch - start_epoch) % min_period == 0
                    && (end_epoch - start_epoch).0 >= min_period
                    && (end_epoch - start_epoch).0 <= max_period)
            }
            _ => Ok(false),
        }
    }

    /// Validate a funds key
    pub fn is_valid_funds(
        &self,
        proposal_id: u64,
        native_token_address: &Address,
    ) -> Result<bool> {
        let funds_key = gov_storage::get_funds_key(proposal_id);
        let balance_key =
            token::balance_key(native_token_address, self.ctx.address);
        let min_funds_parameter_key = gov_storage::get_min_proposal_fund_key();

        let min_funds_parameter: Option<token::Amount> =
            self.ctx.pre().read(&min_funds_parameter_key)?;
        let pre_balance: Option<token::Amount> =
            self.ctx.pre().read(&balance_key)?;
        let post_balance: Option<token::Amount> =
            self.ctx.post().read(&balance_key)?;
        let post_funds: Option<token::Amount> =
            self.ctx.post().read(&funds_key)?;

        match (min_funds_parameter, pre_balance, post_balance, post_funds) {
            (
                Some(min_funds_parameter),
                Some(pre_balance),
                Some(post_balance),
                Some(post_funds),
            ) => Ok(post_funds >= min_funds_parameter
                && post_balance - pre_balance == post_funds),
            (
                Some(min_funds_parameter),
                None,
                Some(post_balance),
                Some(post_funds),
            ) => {
                Ok(post_funds >= min_funds_parameter
                    && post_balance == post_funds)
            }
            _ => Ok(false),
        }
    }

    /// Validate a balance key
    fn is_valid_balance(&self, native_token_address: &Address) -> Result<bool> {
        let balance_key =
            token::balance_key(native_token_address, self.ctx.address);
        let min_funds_parameter_key = gov_storage::get_min_proposal_fund_key();

        let min_funds_parameter: Option<token::Amount> =
            self.ctx.pre().read(&min_funds_parameter_key)?;
        let pre_balance: Option<token::Amount> =
            self.ctx.pre().read(&balance_key)?;
        let post_balance: Option<token::Amount> =
            self.ctx.post().read(&balance_key)?;

        match (min_funds_parameter, pre_balance, post_balance) {
            (
                Some(min_funds_parameter),
                Some(pre_balance),
                Some(post_balance),
            ) => Ok(post_balance > pre_balance
                && post_balance - pre_balance >= min_funds_parameter),
            (Some(min_funds_parameter), None, Some(post_balance)) => {
                Ok(post_balance >= min_funds_parameter)
            }
            _ => Ok(false),
        }
    }

    /// Validate a author key
    pub fn is_valid_author(
        &self,
        proposal_id: u64,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let author_key = gov_storage::get_author_key(proposal_id);

        let has_pre_author = self.ctx.has_key_pre(&author_key)?;

        if has_pre_author {
            return Ok(false);
        }

        let author = self.ctx.post().read(&author_key)?;

        match author {
            Some(author) => match author {
                Address::Established(_) => {
                    let address_exist_key = Key::validity_predicate(&author);
                    let address_exist =
                        self.ctx.has_key_post(&address_exist_key)?;

                    Ok(address_exist && verifiers.contains(&author))
                }
                Address::Implicit(_) => Ok(verifiers.contains(&author)),
                Address::Internal(_) => Ok(false),
            },
            _ => Ok(false),
        }
    }

    /// Validate a counter key
    pub fn is_valid_counter(&self, set_count: u64) -> Result<bool> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: Option<u64> = self.ctx.pre().read(&counter_key)?;
        let post_counter: Option<u64> = self.ctx.post().read(&counter_key)?;

        match (pre_counter, post_counter) {
            (Some(pre_counter), Some(post_counter)) => {
                Ok(pre_counter + set_count == post_counter)
            }
            _ => Ok(false),
        }
    }

    /// Validate a commit key
    pub fn is_valid_proposal_commit(&self) -> Result<bool> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: Option<u64> = self.ctx.pre().read(&counter_key)?;
        let post_counter: Option<u64> = self.ctx.post().read(&counter_key)?;

        match (pre_counter, post_counter) {
            (Some(pre_counter), Some(post_counter)) => {
                // NOTE: can't do pre_counter + set_count == post_counter here
                // because someone may update an empty proposal that just
                // register a committing key causing a bug
                Ok(pre_counter < post_counter)
            }
            _ => Ok(false),
        }
    }

    /// Validate a governance parameter
    pub fn is_valid_parameter(&self, tx_data: &[u8]) -> Result<bool> {
        utils::is_proposal_accepted(&self.ctx.pre(), tx_data)
            .map_err(Error::NativeVpError)
    }

    /// Check if a vote is from a validator
    pub fn is_validator(
        &self,
        epoch: Epoch,
        verifiers: &BTreeSet<Address>,
        address: &Address,
        delegation_address: &Address,
    ) -> Result<bool>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + storage::StorageHasher,
        CA: 'static + WasmCacheAccess,
    {
        let all_validators =
            pos::namada_proof_of_stake::read_all_validator_addresses(
                &self.ctx.pre(),
                epoch,
            )?;
        if !all_validators.is_empty() {
            let is_voter_validator = all_validators
                .into_iter()
                .any(|validator| validator.eq(address));
            let is_signer_validator = verifiers.contains(address);
            let is_delegation_address = delegation_address.eq(address);

            Ok(is_voter_validator
                && is_signer_validator
                && is_delegation_address)
        } else {
            Ok(false)
        }
    }

    /// Check if a vote is from a delegator
    pub fn is_delegator(
        &self,
        epoch: Epoch,
        verifiers: &BTreeSet<Address>,
        address: &Address,
        delegation_address: &Address,
    ) -> Result<bool> {
        // let bond_key = pos::bond_key(&BondId {
        //     source: address.clone(),
        //     validator: delegation_address.clone(),
        // });
        let bond_handle = pos::namada_proof_of_stake::bond_handle(
            address,
            delegation_address,
        );
        let params =
            pos::namada_proof_of_stake::read_pos_params(&self.ctx.pre())?;
        let bond = bond_handle.get_sum(&self.ctx.pre(), epoch, &params)?;
        // let bonds: Option<Bonds> = self.ctx.pre().read(&bond_key)?;

        if bond.is_some() && verifiers.contains(address) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
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
