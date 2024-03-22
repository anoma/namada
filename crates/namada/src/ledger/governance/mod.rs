//! Governance VP

pub mod utils;

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use namada_core::booleans::{BoolResultUnitExt, ResultBoolExt};
use namada_governance::storage::proposal::{
    AddRemove, PGFAction, ProposalType,
};
use namada_governance::storage::{is_proposal_accepted, keys as gov_storage};
use namada_governance::utils::is_valid_validator_voting_period;
use namada_governance::ProposalVote;
use namada_proof_of_stake::is_validator;
use namada_proof_of_stake::queries::find_delegations;
use namada_state::{StateRead, StorageRead};
use namada_tx::action::{Action, GovAction, Read};
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use thiserror::Error;

use self::utils::ReadType;
use crate::address::{Address, InternalAddress};
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::{native_vp, pos};
use crate::storage::{Epoch, Key};
use crate::token;
use crate::vm::WasmCacheAccess;

/// for handling Governance NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

/// The governance internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Governance);

/// The maximum number of item in a pgf proposal
pub const MAX_PGF_ACTIONS: usize = 20;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Governance VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
    #[error(
        "Action {0} not authorized by {1} which is not part of verifier set"
    )]
    Unauthorized(&'static str, Address),
}

/// Governance VP
pub struct GovernanceVp<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> NativeVp for GovernanceVp<'a, S, CA>
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
    ) -> Result<()> {
        let (is_valid_keys_set, set_count) =
            self.is_valid_init_proposal_key_set(keys_changed)?;
        if !is_valid_keys_set {
            tracing::info!("Invalid changed governance key set");
            return Err(native_vp::Error::new_const(
                "Invalid changed governance key set",
            )
            .into());
        };

        let native_token = self.ctx.pre().get_native_token()?;

        // Find the actions applied in the tx
        let actions = self.ctx.read_actions()?;

        // There must be at least one action if any of the keys belong to gov
        if actions.is_empty()
            && keys_changed.iter().any(gov_storage::is_governance_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(native_vp::Error::new_const(
                "Rejecting tx without any action written to temp storage",
            )
            .into());
        }

        // Check action authorization
        for action in actions {
            match action {
                Action::Gov(gov_action) => match gov_action {
                    GovAction::InitProposal { id: _, author } => {
                        if !verifiers.contains(&author) {
                            tracing::info!(
                                "Unauthorized GovAction::InitProposal"
                            );
                            return Err(Error::Unauthorized(
                                "InitProposal",
                                author,
                            ));
                        }
                    }
                    GovAction::VoteProposal { id: _, voter } => {
                        if !verifiers.contains(&voter) {
                            tracing::info!(
                                "Unauthorized GovAction::VoteProposal"
                            );
                            return Err(Error::Unauthorized(
                                "VoteProposal",
                                voter,
                            ));
                        }
                    }
                },
                _ => {
                    // Other actions are not relevant to PoS VP
                    continue;
                }
            }
        }

        keys_changed.iter().try_for_each(|key| {
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
                (KeyType::UNKNOWN_GOVERNANCE, _) => {
                    Err(native_vp::Error::new_alloc(format!(
                        "Unkown governance key change: {key}"
                    ))
                    .into())
                }
                (KeyType::UNKNOWN, _) => Ok(()),
                _ => Err(native_vp::Error::new_alloc(format!(
                    "Unkown governance key change: {key}"
                ))
                .into()),
            };

            result.inspect_err(|err| {
                tracing::info!(
                    "Key {key_type:?} rejected with error: {err:#?}."
                )
            })?;

            Ok(())
        })
    }
}

impl<'a, S, CA> GovernanceVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    fn is_valid_init_proposal_key_set(
        &self,
        keys: &BTreeSet<Key>,
    ) -> Result<(bool, u64)> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: u64 = self.force_read(&counter_key, ReadType::Pre)?;
        let post_counter: u64 =
            self.force_read(&counter_key, ReadType::Post)?;

        if post_counter < pre_counter {
            return Ok((false, 0));
        }

        for counter in pre_counter..post_counter {
            // Construct the set of expected keys
            // NOTE: we don't check the existence of committing_epoch because
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

            // Check that expected set is a subset of the actual one
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
    ) -> Result<()> {
        let counter_key = gov_storage::get_counter_key();
        let voting_start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let voting_end_epoch_key =
            gov_storage::get_voting_end_epoch_key(proposal_id);

        let current_epoch = self.ctx.get_block_epoch()?;

        let pre_counter: u64 = self.force_read(&counter_key, ReadType::Pre)?;
        let pre_voting_start_epoch: Epoch =
            self.force_read(&voting_start_epoch_key, ReadType::Pre)?;
        let pre_voting_end_epoch: Epoch =
            self.force_read(&voting_end_epoch_key, ReadType::Pre)?;

        let voter = gov_storage::get_voter_address(key);
        let delegation_address = gov_storage::get_vote_delegation_address(key);

        let (voter_address, delegation_address) =
            match (voter, delegation_address) {
                (Some(voter_address), Some(delegator_address)) => {
                    (voter_address, delegator_address)
                }
                _ => {
                    return Err(native_vp::Error::new_alloc(format!(
                        "Vote key is not valid: {key}"
                    ))
                    .into());
                }
            };

        // Invalid proposal id
        if pre_counter <= proposal_id {
            let error = native_vp::Error::new_alloc(format!(
                "Invalid proposal ID. Expected {pre_counter} or lower, got \
                 {proposal_id}"
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let vote_key = gov_storage::get_vote_proposal_key(
            proposal_id,
            voter_address.clone(),
            delegation_address.clone(),
        );

        if self
            .force_read::<ProposalVote>(&vote_key, ReadType::Post)
            .is_err()
        {
            return Err(native_vp::Error::new_alloc(format!(
                "Vote key is not valid: {key}"
            ))
            .into());
        }

        // TODO: We should refactor this by modifying the vote proposal tx
        let all_delegations_are_valid = if let Ok(delegations) =
            find_delegations(&self.ctx.pre(), voter_address, &current_epoch)
        {
            if delegations.is_empty() {
                return Err(native_vp::Error::new_alloc(format!(
                    "No delegations found for {voter_address}"
                ))
                .into());
            } else {
                delegations.iter().all(|(address, _)| {
                    let vote_key = gov_storage::get_vote_proposal_key(
                        proposal_id,
                        voter_address.clone(),
                        address.clone(),
                    );
                    self.ctx.post().has_key(&vote_key).unwrap_or(false)
                })
            }
        } else {
            return Err(native_vp::Error::new_alloc(format!(
                "Failed to query delegations for {voter_address}"
            ))
            .into());
        };
        if !all_delegations_are_valid {
            return Err(native_vp::Error::new_alloc(format!(
                "Not all delegations of {voter_address} were deemed valid"
            ))
            .into());
        }

        // Voted outside of voting window. We dont check for validator because
        // if the proposal type is validator, we need to let
        // them vote for the entire voting window.
        if !self.is_valid_voting_window(
            current_epoch,
            pre_voting_start_epoch,
            pre_voting_end_epoch,
            false,
        ) {
            let error = native_vp::Error::new_alloc(format!(
                "Voted outside voting window. Current epoch: {current_epoch}, \
                 start: {pre_voting_start_epoch}, end: {pre_voting_end_epoch}."
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        // first check if validator, then check if delegator
        let is_validator =
            self.is_validator(verifiers, voter_address, delegation_address)?;

        if is_validator {
            return is_valid_validator_voting_period(
                current_epoch,
                pre_voting_start_epoch,
                pre_voting_end_epoch,
            )
            .ok_or_else(|| {
                native_vp::Error::new_alloc(format!(
                    "Validator {voter_address} voted outside of the voting \
                     period. Current epoch: {current_epoch}, pre voting start \
                     epoch: {pre_voting_start_epoch}, pre voting end epoch: \
                     {pre_voting_end_epoch}."
                ))
                .into()
            });
        }

        let is_delegator = self.is_delegator(
            pre_voting_start_epoch,
            verifiers,
            voter_address,
            delegation_address,
        )?;

        if !is_delegator {
            return Err(native_vp::Error::new_alloc(format!(
                "Address {voter_address} is neither a validator nor a \
                 delegator."
            ))
            .into());
        }

        Ok(())
    }

    /// Validate a content key
    pub fn is_valid_content_key(&self, proposal_id: u64) -> Result<()> {
        let content_key: Key = gov_storage::get_content_key(proposal_id);
        let max_content_length_parameter_key =
            gov_storage::get_max_proposal_content_key();

        let has_pre_content: bool = self.ctx.has_key_pre(&content_key)?;
        if has_pre_content {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} already had content written \
                 to storage."
            ))
            .into());
        }

        let max_content_length: usize =
            self.force_read(&max_content_length_parameter_key, ReadType::Pre)?;
        let post_content =
            self.ctx.read_bytes_post(&content_key)?.unwrap_or_default();

        let is_valid = post_content.len() <= max_content_length;
        if !is_valid {
            let error = native_vp::Error::new_alloc(format!(
                "Max content length {max_content_length}, got {}.",
                post_content.len()
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }
        Ok(())
    }

    /// Validate the proposal type
    pub fn is_valid_proposal_type(&self, proposal_id: u64) -> Result<()> {
        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: ProposalType =
            self.force_read(&proposal_type_key, ReadType::Post)?;

        match proposal_type {
            ProposalType::PGFSteward(stewards) => {
                let stewards_added = stewards
                    .iter()
                    .filter_map(|pgf_action| match pgf_action {
                        AddRemove::Add(address) => Some(address.clone()),
                        _ => None,
                    })
                    .collect::<Vec<Address>>();
                let total_stewards_added = stewards_added.len() as u64;

                let all_pgf_action_addresses = stewards
                    .iter()
                    .map(|steward| match steward {
                        AddRemove::Add(address) => address,
                        AddRemove::Remove(address) => address,
                    })
                    .collect::<BTreeSet<&Address>>()
                    .len();

                // we allow only a single steward to be added
                if total_stewards_added > 1 {
                    Err(native_vp::Error::new_const(
                        "Only one steward is allowed to be added per proposal",
                    )
                    .into())
                } else if total_stewards_added == 0 {
                    let is_valid_total_pgf_actions =
                        stewards.len() < MAX_PGF_ACTIONS;

                    return if is_valid_total_pgf_actions {
                        Ok(())
                    } else {
                        return Err(native_vp::Error::new_alloc(format!(
                            "Maximum number of steward actions \
                             ({MAX_PGF_ACTIONS}) exceeded ({})",
                            stewards.len()
                        ))
                        .into());
                    };
                } else if let Some(address) = stewards_added.first() {
                    let author_key = gov_storage::get_author_key(proposal_id);
                    let author = self
                        .force_read::<Address>(&author_key, ReadType::Post)?;
                    let is_valid_author = address.eq(&author);

                    if !is_valid_author {
                        return Err(native_vp::Error::new_alloc(format!(
                            "Author {author} does not match added steward \
                             address {address}",
                        ))
                        .into());
                    }

                    let stewards_addresses_are_unique =
                        stewards.len() == all_pgf_action_addresses;

                    if !stewards_addresses_are_unique {
                        return Err(native_vp::Error::new_const(
                            "Non-unique modified steward addresses",
                        )
                        .into());
                    }

                    let is_valid_total_pgf_actions =
                        all_pgf_action_addresses < MAX_PGF_ACTIONS;

                    if !is_valid_total_pgf_actions {
                        return Err(native_vp::Error::new_alloc(format!(
                            "Maximum number of steward actions \
                             ({MAX_PGF_ACTIONS}) exceeded \
                             ({all_pgf_action_addresses})",
                        ))
                        .into());
                    }

                    return Ok(());
                } else {
                    return Err(native_vp::Error::new_const(
                        "Invalid PGF proposal",
                    )
                    .into());
                }
            }
            ProposalType::PGFPayment(fundings) => {
                // collect all the funding target that we have to add and are
                // unique
                let are_continuous_add_targets_unique = fundings
                    .iter()
                    .filter_map(|funding| match funding {
                        PGFAction::Continuous(AddRemove::Add(target)) => {
                            Some(target.target().to_lowercase())
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<String>>();

                // collect all the funding target that we have to remove and are
                // unique
                let are_continuous_remove_targets_unique = fundings
                    .iter()
                    .filter_map(|funding| match funding {
                        PGFAction::Continuous(AddRemove::Remove(target)) => {
                            Some(target.target().to_lowercase())
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<String>>();

                let total_retro_targets = fundings
                    .iter()
                    .filter(|funding| matches!(funding, PGFAction::Retro(_)))
                    .count();

                let is_total_fundings_valid = fundings.len() < MAX_PGF_ACTIONS;

                if !is_total_fundings_valid {
                    return Err(native_vp::Error::new_alloc(format!(
                        "Maximum number of funding actions \
                         ({MAX_PGF_ACTIONS}) exceeded ({})",
                        fundings.len()
                    ))
                    .into());
                }

                // check that they are unique by checking that the set of add
                // plus the set of remove plus the set of retro is equal to the
                // total fundings
                let are_continuous_fundings_unique =
                    are_continuous_add_targets_unique.len()
                        + are_continuous_remove_targets_unique.len()
                        + total_retro_targets
                        == fundings.len();

                if !are_continuous_fundings_unique {
                    return Err(native_vp::Error::new_const(
                        "Non-unique modified fundings",
                    )
                    .into());
                }

                // can't remove and add the same target in the same proposal
                let are_targets_unique = are_continuous_add_targets_unique
                    .intersection(&are_continuous_remove_targets_unique)
                    .count() as u64
                    == 0;

                are_targets_unique.ok_or_else(|| {
                    native_vp::Error::new_const(
                        "One or more payment targets were added and removed \
                         in the same proposal",
                    )
                    .into()
                })
            }
            _ => Ok(()), // default proposal
        }
    }

    /// Validate a proposal code
    pub fn is_valid_proposal_code(&self, proposal_id: u64) -> Result<()> {
        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: ProposalType =
            self.force_read(&proposal_type_key, ReadType::Post)?;

        if !proposal_type.is_default() {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} modified a proposal code key, \
                 but its type is not default.",
            ))
            .into());
        }

        let code_key = gov_storage::get_proposal_code_key(proposal_id);
        let max_code_size_parameter_key =
            gov_storage::get_max_proposal_code_size_key();

        let has_pre_code: bool = self.ctx.has_key_pre(&code_key)?;
        if has_pre_code {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} already had wasm code written \
                 to storage in its slot.",
            ))
            .into());
        }

        let max_proposal_length: usize =
            self.force_read(&max_code_size_parameter_key, ReadType::Pre)?;
        let post_code: Vec<u8> =
            self.ctx.read_bytes_post(&code_key)?.unwrap_or_default();

        let wasm_code_below_max_len = post_code.len() <= max_proposal_length;

        if !wasm_code_below_max_len {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} wrote wasm code with length \
                 {} to storage, but the max allowed length is \
                 {max_proposal_length}.",
                post_code.len(),
            ))
            .into());
        }

        Ok(())
    }

    /// Validate a grace_epoch key
    pub fn is_valid_grace_epoch(&self, proposal_id: u64) -> Result<()> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let grace_epoch_key = gov_storage::get_grace_epoch_key(proposal_id);
        let max_proposal_period = gov_storage::get_max_proposal_period_key();
        let min_grace_epoch_key =
            gov_storage::get_min_proposal_grace_epoch_key();

        let has_pre_grace_epoch = self.ctx.has_key_pre(&grace_epoch_key)?;
        if has_pre_grace_epoch {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} already had a grace epoch \
                 written to storage in its slot.",
            ))
            .into());
        }

        let start_epoch: Epoch =
            self.force_read(&start_epoch_key, ReadType::Post)?;
        let end_epoch: Epoch =
            self.force_read(&end_epoch_key, ReadType::Post)?;
        let grace_epoch: Epoch =
            self.force_read(&grace_epoch_key, ReadType::Post)?;
        let min_grace_epoch: u64 =
            self.force_read(&min_grace_epoch_key, ReadType::Pre)?;
        let max_proposal_period: u64 =
            self.force_read(&max_proposal_period, ReadType::Pre)?;

        let committing_epoch_key = gov_storage::get_committing_proposals_key(
            proposal_id,
            grace_epoch.into(),
        );
        let has_post_committing_epoch =
            self.ctx.has_key_post(&committing_epoch_key)?;
        if !has_post_committing_epoch {
            let error = native_vp::Error::new_const(
                "Committing proposal key is missing present",
            )
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let is_valid_grace_epoch = end_epoch < grace_epoch
            && (grace_epoch - end_epoch).0 >= min_grace_epoch;
        if !is_valid_grace_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Expected min duration between the end and grace epoch \
                 {min_grace_epoch}, but got grace = {grace_epoch}, end = \
                 {end_epoch}",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }
        let is_valid_max_proposal_period = start_epoch < grace_epoch
            && grace_epoch.0 - start_epoch.0 <= max_proposal_period;
        if !is_valid_max_proposal_period {
            let error = native_vp::Error::new_alloc(format!(
                "Expected max duration between the start and grace epoch \
                 {max_proposal_period}, but got grace = {grace_epoch}, start \
                 = {start_epoch}",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        Ok(())
    }

    /// Validate a start_epoch key
    pub fn is_valid_start_epoch(&self, proposal_id: u64) -> Result<()> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let min_period_parameter_key =
            gov_storage::get_min_proposal_voting_period_key();

        let current_epoch = self.ctx.get_block_epoch()?;

        let has_pre_start_epoch = self.ctx.has_key_pre(&start_epoch_key)?;
        if has_pre_start_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Failed to validate start epoch. Proposal with id \
                 {proposal_id} already had a pre_start epoch written to \
                 storage in its slot.",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let has_pre_end_epoch = self.ctx.has_key_pre(&end_epoch_key)?;
        if has_pre_end_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Failed to validate start epoch. Proposal with id \
                 {proposal_id} already had a pre_end epoch written to storage \
                 in its slot.",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let start_epoch: Epoch =
            self.force_read(&start_epoch_key, ReadType::Post)?;
        let end_epoch: Epoch =
            self.force_read(&end_epoch_key, ReadType::Post)?;
        let min_period: u64 =
            self.force_read(&min_period_parameter_key, ReadType::Pre)?;

        if end_epoch <= start_epoch {
            return Err(native_vp::Error::new_alloc(format!(
                "Ending epoch {end_epoch} cannot be lower than or equal to \
                 the starting epoch {start_epoch} of the proposal with id \
                 {proposal_id}.",
            ))
            .into());
        }

        if start_epoch <= current_epoch {
            return Err(native_vp::Error::new_alloc(format!(
                "Starting epoch {start_epoch} cannot be lower than or equal \
                 to the current epoch {current_epoch} of the proposal with id \
                 {proposal_id}.",
            ))
            .into());
        }

        // TODO: HACK THAT NEEDS TO BE PROPERLY FIXED WITH PARAM
        let latency = 30u64;
        if start_epoch.0 - current_epoch.0 > latency {
            return Err(native_vp::Error::new_alloc(format!(
                "Starting epoch {start_epoch} of the proposal with id \
                 {proposal_id} is too far in the future (more than {latency} \
                 epochs away from the current epoch {current_epoch}).",
            ))
            .into());
        }

        let proposal_period_multiple_of_min_period =
            (end_epoch - start_epoch) % min_period == 0;
        if !proposal_period_multiple_of_min_period {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} does not have a voting period \
                 that is a multiple of the minimum voting period \
                 {min_period}. Starting epoch is {start_epoch}, and ending \
                 epoch is {end_epoch}.",
            ))
            .into());
        }

        let proposal_meets_min_period =
            (end_epoch - start_epoch).0 >= min_period;
        if !proposal_meets_min_period {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} does not meet the required \
                 minimum period of {min_period} epochs. Starting epoch is \
                 {start_epoch}, and ending epoch is {end_epoch}.",
            ))
            .into());
        }

        Ok(())
    }

    /// Validate a end_epoch key
    fn is_valid_end_epoch(&self, proposal_id: u64) -> Result<()> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let min_period_parameter_key =
            gov_storage::get_min_proposal_voting_period_key();
        let max_period_parameter_key =
            gov_storage::get_max_proposal_period_key();

        let current_epoch = self.ctx.get_block_epoch()?;

        let has_pre_start_epoch = self.ctx.has_key_pre(&start_epoch_key)?;
        if has_pre_start_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Failed to validate end epoch. Proposal with id {proposal_id} \
                 already had a pre_start epoch written to storage in its slot.",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let has_pre_end_epoch = self.ctx.has_key_pre(&end_epoch_key)?;
        if has_pre_end_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Failed to validate end epoch. Proposal with id {proposal_id} \
                 already had a pre_end epoch written to storage in its slot.",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let start_epoch: Epoch =
            self.force_read(&start_epoch_key, ReadType::Post)?;
        let end_epoch: Epoch =
            self.force_read(&end_epoch_key, ReadType::Post)?;
        let min_period: u64 =
            self.force_read(&min_period_parameter_key, ReadType::Pre)?;
        let max_period: u64 =
            self.force_read(&max_period_parameter_key, ReadType::Pre)?;

        if end_epoch <= start_epoch || start_epoch <= current_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id}'s end epoch ({end_epoch}) \
                 must be after the start epoch ({start_epoch}), and the start \
                 epoch must be after the current epoch ({current_epoch})."
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }

        let proposal_period_multiple_of_min_period =
            (end_epoch - start_epoch) % min_period == 0;
        if !proposal_period_multiple_of_min_period {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} does not have a voting period \
                 that is a multiple of the minimum voting period \
                 {min_period}. Starting epoch is {start_epoch}, and ending \
                 epoch is {end_epoch}.",
            ))
            .into());
        }

        let valid_voting_period = (end_epoch - start_epoch).0 >= min_period
            && (end_epoch - start_epoch).0 <= max_period;

        valid_voting_period.ok_or_else(|| {
            native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} must have a voting period \
                 with a minimum of {min_period} epochs, and a maximum of \
                 {max_period} epochs. The starting epoch is {start_epoch}, \
                 and the ending epoch is {end_epoch}.",
            ))
            .into()
        })
    }

    /// Validate a funds key
    pub fn is_valid_funds(
        &self,
        proposal_id: u64,
        native_token_address: &Address,
    ) -> Result<()> {
        let funds_key = gov_storage::get_funds_key(proposal_id);
        let balance_key = token::storage_key::balance_key(
            native_token_address,
            self.ctx.address,
        );
        let min_funds_parameter_key = gov_storage::get_min_proposal_fund_key();

        let min_funds_parameter: token::Amount =
            self.force_read(&min_funds_parameter_key, ReadType::Pre)?;
        let pre_balance: Option<token::Amount> =
            self.ctx.pre().read(&balance_key)?;
        let post_balance: token::Amount =
            self.force_read(&balance_key, ReadType::Post)?;
        let post_funds: token::Amount =
            self.force_read(&funds_key, ReadType::Post)?;

        pre_balance.map_or_else(
            // null pre balance
            || {
                let is_post_funds_greater_than_minimum =
                    post_funds >= min_funds_parameter;
                is_post_funds_greater_than_minimum.ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::new_alloc(format!(
                        "Funds must be greater than the minimum funds of {}",
                        min_funds_parameter.native_denominated()
                    )))
                })?;

                let post_balance_is_same = post_balance == post_funds;
                post_balance_is_same.ok_or_else(|| {
                    native_vp::Error::new_alloc(format!(
                        "Funds and the balance of the governance account have \
                         diverged: funds {} != balance {}",
                        post_funds.native_denominated(),
                        post_balance.native_denominated()
                    ))
                    .into()
                })
            },
            // there was some non-zero balance in the governance account
            |pre_balance| {
                let is_post_funds_greater_than_minimum =
                    post_funds >= min_funds_parameter;
                is_post_funds_greater_than_minimum.ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::new_alloc(format!(
                        "Funds {} must be greater than the minimum funds of {}",
                        post_funds.native_denominated(),
                        min_funds_parameter.native_denominated()
                    )))
                })?;

                let is_valid_funds = post_balance >= pre_balance
                    && post_balance - pre_balance == post_funds;
                is_valid_funds.ok_or_else(|| {
                    native_vp::Error::new_alloc(format!(
                        "Invalid funds {} have been written to storage",
                        post_funds.native_denominated()
                    ))
                    .into()
                })
            },
        )
    }

    /// Validate a balance key
    fn is_valid_balance(&self, native_token_address: &Address) -> Result<()> {
        let balance_key = token::storage_key::balance_key(
            native_token_address,
            self.ctx.address,
        );
        let min_funds_parameter_key = gov_storage::get_min_proposal_fund_key();

        let pre_balance: Option<token::Amount> =
            self.ctx.pre().read(&balance_key)?;

        let min_funds_parameter: token::Amount =
            self.force_read(&min_funds_parameter_key, ReadType::Pre)?;
        let post_balance: token::Amount =
            self.force_read(&balance_key, ReadType::Post)?;

        let balance_is_valid = if let Some(pre_balance) = pre_balance {
            post_balance > pre_balance
                && post_balance - pre_balance >= min_funds_parameter
        } else {
            post_balance >= min_funds_parameter
        };

        balance_is_valid.ok_or_else(|| {
            native_vp::Error::new_alloc(format!(
                "Invalid balance {} has been written to storage",
                post_balance.native_denominated()
            ))
            .into()
        })
    }

    /// Validate a author key
    pub fn is_valid_author(
        &self,
        proposal_id: u64,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let author_key = gov_storage::get_author_key(proposal_id);

        let has_pre_author = self.ctx.has_key_pre(&author_key)?;
        if has_pre_author {
            return Err(native_vp::Error::new_alloc(format!(
                "Proposal with id {proposal_id} already had an author written \
                 to storage"
            ))
            .into());
        }

        let author = self.force_read(&author_key, ReadType::Post)?;
        namada_account::exists(&self.ctx.pre(), &author)
            .map_err(Error::NativeVpError)
            .true_or_else(|| {
                native_vp::Error::new_alloc(format!(
                    "No author account {author} could be found for the \
                     proposal with id {proposal_id}"
                ))
                .into()
            })?;

        verifiers.contains(&author).ok_or_else(|| {
            native_vp::Error::new_alloc(format!(
                "The VP of the proposal with id {proposal_id}'s author \
                 {author} should have been triggered"
            ))
            .into()
        })
    }

    /// Validate a counter key
    pub fn is_valid_counter(&self, set_count: u64) -> Result<()> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: u64 = self.force_read(&counter_key, ReadType::Pre)?;
        let post_counter: u64 =
            self.force_read(&counter_key, ReadType::Post)?;

        let expected_counter = pre_counter + set_count;
        let valid_counter = expected_counter == post_counter;

        valid_counter.ok_or_else(|| {
            native_vp::Error::new_alloc(format!(
                "Invalid proposal counter. Expected {expected_counter}, but \
                 got {post_counter} instead."
            ))
            .into()
        })
    }

    /// Validate a commit key
    pub fn is_valid_proposal_commit(&self) -> Result<()> {
        let counter_key = gov_storage::get_counter_key();
        let pre_counter: u64 = self.force_read(&counter_key, ReadType::Pre)?;
        let post_counter: u64 =
            self.force_read(&counter_key, ReadType::Post)?;

        // NOTE: can't do pre_counter + set_count == post_counter here
        // because someone may update an empty proposal that just
        // register a committing key causing a bug
        let pre_counter_is_lower = pre_counter < post_counter;

        pre_counter_is_lower.ok_or_else(|| {
            native_vp::Error::new_alloc(format!(
                "The value of the previous counter {pre_counter} must be \
                 lower than the value of the new counter {post_counter}."
            ))
            .into()
        })
    }

    /// Validate a governance parameter
    pub fn is_valid_parameter(&self, tx: &Tx) -> Result<()> {
        tx.data().map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "Governance parameter changes require tx data to be \
                     present",
                )
                .into())
            },
            |data| {
                is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "Governance parameter changes can only be \
                             performed by a governance proposal that has been \
                             accepted",
                        )
                        .into()
                    })
            },
        )
    }

    /// Check if a vote is from a validator
    pub fn is_validator(
        &self,
        verifiers: &BTreeSet<Address>,
        address: &Address,
        delegation_address: &Address,
    ) -> Result<bool>
    where
        S: StateRead,
        CA: 'static + WasmCacheAccess,
    {
        if !address.eq(delegation_address) {
            return Ok(false);
        }

        let is_validator = is_validator(&self.ctx.pre(), address)?;

        Ok(is_validator && verifiers.contains(address))
    }

    /// Private method to read from storage data that are 100% in storage.
    fn force_read<T>(&self, key: &Key, read_type: ReadType) -> Result<T>
    where
        T: BorshDeserialize,
    {
        let res = match read_type {
            ReadType::Pre => self.ctx.pre().read::<T>(key),
            ReadType::Post => self.ctx.post().read::<T>(key),
        }?;

        if let Some(data) = res {
            Ok(data)
        } else {
            Err(native_vp::Error::new_alloc(format!(
                "Proposal field should not be empty: {key}"
            ))
            .into())
        }
    }

    fn is_valid_voting_window(
        &self,
        current_epoch: Epoch,
        start_epoch: Epoch,
        end_epoch: Epoch,
        is_validator: bool,
    ) -> bool {
        if is_validator {
            is_valid_validator_voting_period(
                current_epoch,
                start_epoch,
                end_epoch,
            )
        } else {
            current_epoch >= start_epoch && current_epoch <= end_epoch
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
        Ok(address != delegation_address
            && verifiers.contains(address)
            && pos::namada_proof_of_stake::is_delegator(
                &self.ctx.pre(),
                address,
                Some(epoch),
            )?)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug)]
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
        } else if token::storage_key::is_balance_key(native_token, key)
            .is_some()
        {
            KeyType::BALANCE
        } else if gov_storage::is_governance_key(key) {
            KeyType::UNKNOWN_GOVERNANCE
        } else {
            KeyType::UNKNOWN
        }
    }
}
