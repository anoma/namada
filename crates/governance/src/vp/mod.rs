//! Governance VP

pub mod pgf;
pub mod utils;

use std::collections::BTreeSet;
use std::marker::PhantomData;

use borsh::BorshDeserialize;
use namada_core::arith::{self, checked};
use namada_core::booleans::{BoolResultUnitExt, ResultBoolExt};
use namada_core::storage::Epoch;
use namada_core::{proof_of_stake, storage, token};
use namada_state::{StateRead, StorageRead};
use namada_tx::action::{Action, GovAction, Read};
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{Ctx, CtxPreStorageRead, NativeVp, VpEvaluator};
use namada_vp::{native_vp, VpEnv};
use thiserror::Error;

use self::utils::ReadType;
use crate::address::{Address, InternalAddress};
use crate::storage::proposal::{AddRemove, PGFAction, ProposalType};
use crate::storage::{is_proposal_accepted, keys as gov_storage};
use crate::utils::is_valid_validator_voting_period;
use crate::ProposalVote;

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
    #[error("Arithmetic {0}")]
    Arith(#[from] arith::Error),
}

/// Governance VP
pub struct GovernanceVp<'ctx, S, CA, EVAL, PoS, TokenKeys>
where
    S: StateRead,
    EVAL: VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Generic types for DI
    pub _marker: PhantomData<(PoS, TokenKeys)>,
}

impl<'view, 'ctx: 'view, S, CA, EVAL, PoS, TokenKeys> NativeVp<'view>
    for GovernanceVp<'ctx, S, CA, EVAL, PoS, TokenKeys>
where
    S: StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    PoS: proof_of_stake::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = namada_state::StorageError,
        >,
    TokenKeys: token::Keys,
{
    type Error = Error;

    fn validate_tx(
        &'view self,
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<storage::Key>,
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

        // Is VP triggered by a governance proposal?
        if is_proposal_accepted(
            &self.ctx.pre(),
            tx_data.tx.data(tx_data.cmt).unwrap_or_default().as_ref(),
        )
        .unwrap_or_default()
        {
            return Ok(());
        }

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
                    GovAction::InitProposal { author } => {
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
                    // Other actions are not relevant to Governance VP
                    continue;
                }
            }
        }

        // keys_changed.iter().try_for_each(|key| {
        for key in keys_changed.iter() {
            let proposal_id = gov_storage::get_proposal_id(key);
            let key_type = KeyType::from_key::<TokenKeys>(key, &native_token);

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
                (KeyType::ACTIVATION_EPOCH, Some(proposal_id)) => {
                    self.is_valid_activation_epoch(proposal_id)
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
        }
        Ok(())
    }
}

impl<'view, 'ctx: 'view, S, CA, EVAL, PoS, TokenKeys>
    GovernanceVp<'ctx, S, CA, EVAL, PoS, TokenKeys>
where
    S: StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    PoS: proof_of_stake::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = namada_state::StorageError,
        >,
    TokenKeys: token::Keys,
{
    /// Instantiate a Governance VP
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self {
            ctx,
            _marker: PhantomData,
        }
    }

    fn is_valid_init_proposal_key_set(
        &self,
        keys: &BTreeSet<storage::Key>,
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
                gov_storage::get_activation_epoch_key(counter),
            ]);

            // Check that expected set is a subset of the actual one
            if !keys.is_superset(&mandatory_keys) {
                return Ok((false, 0));
            }
        }

        Ok((true, checked!(post_counter - pre_counter)?))
    }

    fn is_valid_vote_key(
        &'view self,
        proposal_id: u64,
        key: &storage::Key,
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

        let voter = gov_storage::get_voter_address(key).ok_or(
            native_vp::Error::new_alloc(format!(
                "Failed to parse a voter from the vote key {key}",
            )),
        )?;
        let validator = gov_storage::get_vote_delegation_address(key).ok_or(
            native_vp::Error::new_alloc(format!(
                "Failed to parse a validator from the vote key {key}",
            )),
        )?;

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
            voter.clone(),
            validator.clone(),
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

        // No checks for the target validators, since ultimately whether the
        // vote counts or not is determined by the validator state at the end
        // epoch

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
        let is_validator = self.is_validator(verifiers, voter, validator)?;

        if is_validator {
            return is_valid_validator_voting_period(
                current_epoch,
                pre_voting_start_epoch,
                pre_voting_end_epoch,
            )
            .ok_or_else(|| {
                native_vp::Error::new_alloc(format!(
                    "Validator {voter} voted outside of the voting period. \
                     Current epoch: {current_epoch}, pre voting start epoch: \
                     {pre_voting_start_epoch}, pre voting end epoch: \
                     {pre_voting_end_epoch}."
                ))
                .into()
            });
        }

        let is_delegator = self.is_delegator(
            pre_voting_start_epoch,
            verifiers,
            voter,
            validator,
        )?;

        if !is_delegator {
            return Err(native_vp::Error::new_alloc(format!(
                "Address {voter} is neither a validator nor a delegator."
            ))
            .into());
        }

        Ok(())
    }

    /// Validate a content key
    pub fn is_valid_content_key(&self, proposal_id: u64) -> Result<()> {
        let content_key: storage::Key =
            gov_storage::get_content_key(proposal_id);
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
        // Check the byte length
        let post_content_bytes =
            self.ctx.read_bytes_post(&content_key)?.unwrap_or_default();

        let is_valid = post_content_bytes.len() <= max_content_length;
        if !is_valid {
            let error = native_vp::Error::new_alloc(format!(
                "Max content length {max_content_length}, got {}.",
                post_content_bytes.len()
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
                let are_continuous_fundings_unique = checked!(
                    are_continuous_add_targets_unique.len()
                        + are_continuous_remove_targets_unique.len()
                        + total_retro_targets
                )? == fundings.len();

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
            // Default proposal condition are checked already for all other
            // proposals.
            // default_with_wasm proposal needs to check only for valid code
            _ => Ok(()),
        }
    }

    /// Validate a proposal code
    pub fn is_valid_proposal_code(&self, proposal_id: u64) -> Result<()> {
        let proposal_type_key = gov_storage::get_proposal_type_key(proposal_id);
        let proposal_type: ProposalType =
            self.force_read(&proposal_type_key, ReadType::Post)?;

        if !proposal_type.is_default_with_wasm() {
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
            self.ctx.read_post(&code_key)?.unwrap_or_default();

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

    /// Validate an activation_epoch key
    pub fn is_valid_activation_epoch(&self, proposal_id: u64) -> Result<()> {
        let start_epoch_key =
            gov_storage::get_voting_start_epoch_key(proposal_id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(proposal_id);
        let activation_epoch_key =
            gov_storage::get_activation_epoch_key(proposal_id);
        let max_proposal_period = gov_storage::get_max_proposal_period_key();
        let min_grace_epochs_key =
            gov_storage::get_min_proposal_grace_epochs_key();

        let has_pre_activation_epoch =
            self.ctx.has_key_pre(&activation_epoch_key)?;
        if has_pre_activation_epoch {
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
        let activation_epoch: Epoch =
            self.force_read(&activation_epoch_key, ReadType::Post)?;
        let min_grace_epochs: u64 =
            self.force_read(&min_grace_epochs_key, ReadType::Pre)?;
        let max_proposal_period: u64 =
            self.force_read(&max_proposal_period, ReadType::Pre)?;

        let committing_epoch_key = gov_storage::get_committing_proposals_key(
            proposal_id,
            activation_epoch.into(),
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

        let is_valid_activation_epoch = end_epoch < activation_epoch
            && checked!(activation_epoch - end_epoch)
                .map_err(|e| Error::NativeVpError(e.into()))?
                .0
                >= min_grace_epochs;
        if !is_valid_activation_epoch {
            let error = native_vp::Error::new_alloc(format!(
                "Expected min duration between the end and grace epoch \
                 {min_grace_epochs}, but got activation = {activation_epoch}, \
                 end = {end_epoch}",
            ))
            .into();
            tracing::info!("{error}");
            return Err(error);
        }
        let is_valid_max_proposal_period = start_epoch < activation_epoch
            && checked!(activation_epoch.0 - start_epoch.0)?
                <= max_proposal_period;
        if !is_valid_max_proposal_period {
            let error = native_vp::Error::new_alloc(format!(
                "Expected max duration between the start and grace epoch \
                 {max_proposal_period}, but got activation = \
                 {activation_epoch}, start = {start_epoch}",
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
        let max_latency_paramater_key =
            gov_storage::get_max_proposal_latency_key();

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

        let latency: u64 =
            self.force_read(&max_latency_paramater_key, ReadType::Pre)?;
        if checked!(start_epoch.0 - current_epoch.0)? > latency {
            return Err(native_vp::Error::new_alloc(format!(
                "Starting epoch {start_epoch} of the proposal with id \
                 {proposal_id} is too far in the future (more than {latency} \
                 epochs away from the current epoch {current_epoch}).",
            ))
            .into());
        }

        let proposal_meets_min_period = checked!(end_epoch - start_epoch)
            .map_err(|e| Error::NativeVpError(e.into()))?
            .0
            >= min_period;
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

        let diff = checked!(end_epoch - start_epoch)
            .map_err(|e| Error::NativeVpError(e.into()))?;
        let valid_voting_period = diff.0 >= min_period && diff.0 <= max_period;

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
        let balance_key =
            TokenKeys::balance_key(native_token_address, self.ctx.address);
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
                    && checked!(post_balance - pre_balance)
                        .map_err(|e| Error::NativeVpError(e.into()))?
                        == post_funds;
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
        let balance_key =
            TokenKeys::balance_key(native_token_address, self.ctx.address);
        let min_funds_parameter_key = gov_storage::get_min_proposal_fund_key();

        let pre_balance: Option<token::Amount> =
            self.ctx.pre().read(&balance_key)?;

        let min_funds_parameter: token::Amount =
            self.force_read(&min_funds_parameter_key, ReadType::Pre)?;
        let post_balance: token::Amount =
            self.force_read(&balance_key, ReadType::Post)?;

        let balance_is_valid = if let Some(pre_balance) = pre_balance {
            post_balance > pre_balance
                && checked!(post_balance - pre_balance)
                    .map_err(|e| Error::NativeVpError(e.into()))?
                    >= min_funds_parameter
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

        let expected_counter = checked!(pre_counter + set_count)?;
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
    pub fn is_valid_parameter(
        &self,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        let BatchedTxRef { tx, cmt } = batched_tx;
        tx.data(cmt).map_or_else(
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
        &'view self,
        verifiers: &BTreeSet<Address>,
        voter: &Address,
        validator: &Address,
    ) -> Result<bool> {
        if !voter.eq(validator) {
            return Ok(false);
        }

        let is_validator = PoS::is_validator(&self.ctx.pre(), voter)?;

        Ok(is_validator && verifiers.contains(voter))
    }

    /// Private method to read from storage data that are 100% in storage.
    fn force_read<T>(
        &self,
        key: &storage::Key,
        read_type: ReadType,
    ) -> Result<T>
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
        &'view self,
        epoch: Epoch,
        verifiers: &BTreeSet<Address>,
        address: &Address,
        delegation_address: &Address,
    ) -> Result<bool> {
        Ok(address != delegation_address
            && verifiers.contains(address)
            && PoS::is_delegator(&self.ctx.pre(), address, Some(epoch))?)
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
    ACTIVATION_EPOCH,
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
    fn from_key<TokenKeys>(key: &storage::Key, native_token: &Address) -> Self
    where
        TokenKeys: token::Keys,
    {
        if gov_storage::is_vote_key(key) {
            Self::VOTE
        } else if gov_storage::is_content_key(key) {
            KeyType::CONTENT
        } else if gov_storage::is_proposal_type_key(key) {
            Self::TYPE
        } else if gov_storage::is_proposal_code_key(key) {
            Self::PROPOSAL_CODE
        } else if gov_storage::is_activation_epoch_key(key) {
            KeyType::ACTIVATION_EPOCH
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
        } else if TokenKeys::is_balance_key(native_token, key).is_some() {
            KeyType::BALANCE
        } else if gov_storage::is_governance_key(key) {
            KeyType::UNKNOWN_GOVERNANCE
        } else {
            KeyType::UNKNOWN
        }
    }
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use assert_matches::assert_matches;
    use namada_core::address::testing::{
        established_address_1, established_address_3, nam,
    };
    use namada_core::address::Address;
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::key::testing::keypair_1;
    use namada_core::key::RefTo;
    use namada_core::storage::testing::get_dummy_header;
    use namada_core::time::DateTimeUtc;
    use namada_core::token;
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_parameters::Parameters;
    use namada_proof_of_stake::bond_tokens;
    use namada_proof_of_stake::test_utils::get_dummy_genesis_validator;
    use namada_state::mockdb::MockDB;
    use namada_state::testing::TestState;
    use namada_state::{
        BlockHeight, Epoch, FullAccessState, Key, Sha256Hasher, State,
        StateRead, StorageRead, TxIndex,
    };
    use namada_token::storage_key::balance_key;
    use namada_tx::action::{Action, GovAction, Write};
    use namada_tx::data::TxType;
    use namada_tx::{Authorization, Code, Data, Section, Tx};
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vm::wasm::VpCache;
    use namada_vm::{wasm, WasmCacheRwAccess};
    use namada_vp::native_vp::{Ctx, CtxPreStorageRead, NativeVp};

    use crate::storage::keys::{
        get_activation_epoch_key, get_author_key, get_committing_proposals_key,
        get_content_key, get_counter_key, get_funds_key, get_proposal_type_key,
        get_vote_proposal_key, get_voting_end_epoch_key,
        get_voting_start_epoch_key,
    };
    use crate::{ProposalType, ProposalVote, ADDRESS};

    type CA = WasmCacheRwAccess;
    type Eval<S> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;
    type GovernanceVp<'ctx, S> = super::GovernanceVp<
        'ctx,
        S,
        VpCache<CA>,
        Eval<S>,
        namada_proof_of_stake::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        namada_token::Store<()>,
    >;

    fn init_storage() -> TestState {
        let mut state = TestState::default();

        namada_proof_of_stake::test_utils::test_init_genesis(
            &mut state,
            namada_proof_of_stake::OwnedPosParams::default(),
            vec![get_dummy_genesis_validator()].into_iter(),
            Epoch(1),
        )
        .unwrap();

        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state.in_mem_mut().begin_block(BlockHeight(1)).unwrap();

        state
    }

    #[test]
    fn test_noop() {
        let state = init_storage();
        let keys_changed = BTreeSet::new();

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address]);

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        let batched_tx = tx.batch_ref_first_tx().unwrap();

        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );
    }

    fn initialize_account_balance<S>(
        state: &mut S,
        address: &Address,
        amount: token::Amount,
    ) where
        S: State,
    {
        let balance_key = balance_key(&nam(), address);
        state
            .write_log_mut()
            .write(&balance_key, amount.serialize_to_vec())
            .expect("write failed");
        state.write_log_mut().commit_batch();
    }

    #[cfg(test)]
    fn update_epoch_to(
        state: &mut FullAccessState<MockDB, Sha256Hasher>,
        total_epochs: u64,
        height: BlockHeight,
    ) {
        state.in_mem_mut().update_epoch_blocks_delay = Some(1);
        let parameters = Parameters::default();
        for _ in 0..total_epochs {
            state.in_mem_mut().update_epoch_blocks_delay = Some(1);
            state
                .update_epoch(
                    height,
                    #[allow(clippy::disallowed_methods)]
                    DateTimeUtc::now()
                        .next_second()
                        .next_second()
                        .next_second()
                        .next_second()
                        .next_second(),
                    &parameters,
                )
                .unwrap();
        }
    }

    fn get_proposal_keys(
        proposal_id: u64,
        activation_epoch: u64,
    ) -> BTreeSet<Key> {
        let counter_key = get_counter_key();
        let voting_end_epoch_key = get_voting_end_epoch_key(proposal_id);
        let voting_start_epoch_key = get_voting_start_epoch_key(proposal_id);
        let activation_epoch_key = get_activation_epoch_key(proposal_id);
        let content_key = get_content_key(proposal_id);
        let author_key = get_author_key(proposal_id);
        let proposal_type_key = get_proposal_type_key(proposal_id);
        let funds_key = get_funds_key(proposal_id);
        let commiting_key =
            get_committing_proposals_key(proposal_id, activation_epoch);

        BTreeSet::from([
            counter_key.clone(),
            funds_key.clone(),
            content_key.clone(),
            author_key.clone(),
            proposal_type_key.clone(),
            voting_start_epoch_key.clone(),
            voting_end_epoch_key.clone(),
            activation_epoch_key.clone(),
            commiting_key.clone(),
        ])
    }

    fn transfer<S>(
        state: &mut S,
        source: &Address,
        target: &Address,
        amount: u64,
    ) where
        S: State,
    {
        let source_balance_key = balance_key(&nam(), source);
        let target_balance_key = balance_key(&nam(), target);
        let amount = token::Amount::native_whole(amount);

        let mut current_source: token::Amount =
            state.read(&source_balance_key).unwrap().unwrap();
        let mut current_target: token::Amount =
            state.read(&target_balance_key).unwrap().unwrap();

        current_source.spend(&amount).unwrap();
        current_target.receive(&amount).unwrap();

        state
            .write_log_mut()
            .write(&source_balance_key, current_source.serialize_to_vec())
            .expect("write failed");

        state
            .write_log_mut()
            .write(&target_balance_key, current_target.serialize_to_vec())
            .expect("write failed");
    }

    #[allow(clippy::too_many_arguments)]
    fn init_proposal<S>(
        state: &mut S,
        proposal_id: u64,
        funds: u64,
        start_epoch: u64,
        end_epoch: u64,
        activation_epoch: u64,
        signer_address: &Address,
        no_commiting_key: bool,
    ) where
        S: State + namada_tx::action::Write,
    {
        let counter_key = get_counter_key();
        let voting_end_epoch_key = get_voting_end_epoch_key(proposal_id);
        let voting_start_epoch_key = get_voting_start_epoch_key(proposal_id);
        let activation_epoch_key = get_activation_epoch_key(proposal_id);
        let content_key = get_content_key(proposal_id);
        let author_key = get_author_key(proposal_id);
        let proposal_type_key = get_proposal_type_key(proposal_id);
        let funds_key = get_funds_key(proposal_id);
        let commiting_key =
            get_committing_proposals_key(proposal_id, activation_epoch);

        transfer(state, signer_address, &ADDRESS, funds);

        state
            .push_action(Action::Gov(GovAction::InitProposal {
                author: signer_address.clone(),
            }))
            .unwrap();

        state
            .write_log_mut()
            .write(&counter_key, (proposal_id + 1).serialize_to_vec())
            .unwrap();
        state
            .write_log_mut()
            .write(&voting_end_epoch_key, Epoch(end_epoch).serialize_to_vec())
            .unwrap();
        state
            .write_log_mut()
            .write(
                &voting_start_epoch_key,
                Epoch(start_epoch).serialize_to_vec(),
            )
            .unwrap();
        state
            .write_log_mut()
            .write(
                &activation_epoch_key,
                Epoch(activation_epoch).serialize_to_vec(),
            )
            .unwrap();
        state
            .write_log_mut()
            .write(&content_key, vec![1, 2, 3, 4])
            .unwrap();
        state
            .write_log_mut()
            .write(&author_key, signer_address.serialize_to_vec())
            .unwrap();
        state
            .write_log_mut()
            .write(&proposal_type_key, ProposalType::Default.serialize_to_vec())
            .unwrap();
        state
            .write_log_mut()
            .write(
                &funds_key,
                token::Amount::native_whole(funds).serialize_to_vec(),
            )
            .unwrap();
        if !no_commiting_key {
            state
                .write_log_mut()
                .write(&commiting_key, ().serialize_to_vec())
                .unwrap();
        }
    }

    #[test]
    fn test_goverance_proposal_accepted() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let governance_balance_key = balance_key(&nam(), &ADDRESS);
        let amount: token::Amount =
            state.read(&governance_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(500));

        let author_balance_key = balance_key(&nam(), &signer_address);
        let amount: token::Amount =
            state.read(&author_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(10));

        let governance_counter_key = get_counter_key();
        let counter: u64 =
            state.read(&governance_counter_key).unwrap().unwrap();
        assert_eq!(counter, 1);
    }

    #[test]
    fn test_governance_proposal_not_enough_funds_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(500),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            499,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        let result =
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers); // this should fail
        assert_matches!(&result, Err(_));

        if result.is_err() {
            state.drop_tx_batch();
        } else {
            state.commit_tx_batch();
        }
        state.commit_block().unwrap();

        let governance_balance_key = balance_key(&nam(), &ADDRESS);
        let amount: token::Amount =
            state.read(&governance_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(0));

        let author_balance_key = balance_key(&nam(), &signer_address);
        let amount: token::Amount =
            state.read(&author_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(500));

        let governance_counter_key = get_counter_key();
        let counter: u64 =
            state.read(&governance_counter_key).unwrap().unwrap();
        assert_eq!(counter, 0);
    }

    #[test]
    fn test_governance_proposal_more_funds_accepted() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            509,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        let result =
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers);
        assert_matches!(&result, Ok(_));

        if result.is_err() {
            state.drop_tx_batch();
        } else {
            state.commit_tx_batch();
        }
        state.commit_block().unwrap();

        let governance_balance_key = balance_key(&nam(), &ADDRESS);
        let amount: token::Amount =
            state.read(&governance_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(509));

        let author_balance_key = balance_key(&nam(), &signer_address);
        let amount: token::Amount =
            state.read(&author_balance_key).unwrap().unwrap();
        assert_eq!(amount, token::Amount::native_whole(1));

        let governance_counter_key = get_counter_key();
        let counter: u64 =
            state.read(&governance_counter_key).unwrap().unwrap();
        assert_eq!(counter, 1);
    }

    #[test]
    fn test_governance_too_small_voting_period_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            509,
            3,
            4,
            activation_epoch,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_governance_too_small_grace_period_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 12;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            509,
            3,
            9,
            activation_epoch,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_governance_too_big_voting_window_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 40;

        let keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            509,
            3,
            9,
            activation_epoch,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_governance_no_committing_key_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let counter_key = get_counter_key();
        let voting_end_epoch_key = get_voting_end_epoch_key(proposal_id);
        let voting_start_epoch_key = get_voting_start_epoch_key(proposal_id);
        let activation_epoch_key = get_activation_epoch_key(proposal_id);
        let content_key = get_content_key(proposal_id);
        let author_key = get_author_key(proposal_id);
        let proposal_type_key = get_proposal_type_key(proposal_id);
        let funds_key = get_funds_key(proposal_id);

        let keys_changed = BTreeSet::from([
            counter_key.clone(),
            funds_key.clone(),
            content_key.clone(),
            author_key.clone(),
            proposal_type_key.clone(),
            voting_start_epoch_key.clone(),
            voting_end_epoch_key.clone(),
            activation_epoch_key.clone(),
        ]);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            509,
            3,
            9,
            activation_epoch,
            &signer_address,
            true,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_governance_invalid_start_epoch_failed() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let counter_key = get_counter_key();
        let voting_end_epoch_key = get_voting_end_epoch_key(proposal_id);
        let voting_start_epoch_key = get_voting_start_epoch_key(proposal_id);
        let activation_epoch_key = get_activation_epoch_key(proposal_id);
        let content_key = get_content_key(proposal_id);
        let author_key = get_author_key(proposal_id);
        let proposal_type_key = get_proposal_type_key(proposal_id);
        let funds_key = get_funds_key(proposal_id);

        let keys_changed = BTreeSet::from([
            counter_key.clone(),
            funds_key.clone(),
            content_key.clone(),
            author_key.clone(),
            proposal_type_key.clone(),
            voting_start_epoch_key.clone(),
            voting_end_epoch_key.clone(),
            activation_epoch_key.clone(),
        ]);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            0,
            9,
            activation_epoch,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_goverance_vote_validator_success() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (7 * 2);

        update_epoch_to(&mut state, 7, height);

        let validator_address = established_address_1();

        let vote_key = get_vote_proposal_key(
            0,
            validator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: validator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(validator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );
    }

    #[test]
    fn test_goverance_vote_validator_out_of_voting_window_fail() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (7 * 2);

        update_epoch_to(&mut state, 10, height);

        let validator_address = established_address_1();

        let vote_key = get_vote_proposal_key(
            0,
            validator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: validator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(validator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_goverance_vote_validator_fail() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);
        // this should return true because state has been stored
        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (7 * 2);

        update_epoch_to(&mut state, 8, height);

        let validator_address = established_address_1();

        let vote_key = get_vote_proposal_key(
            0,
            validator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: validator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(validator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_goverance_vote_delegator_success() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (9 * 2);

        let validator_address = established_address_1();
        let delegator_address = established_address_3();

        initialize_account_balance(
            &mut state,
            &delegator_address,
            token::Amount::native_whole(1000000),
        );

        bond_tokens(
            &mut state,
            Some(&delegator_address),
            &validator_address,
            token::Amount::from_u64(10000),
            Epoch(1),
            None,
        )
        .unwrap();

        update_epoch_to(&mut state, 9, height);

        let vote_key = get_vote_proposal_key(
            0,
            delegator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: delegator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(delegator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );
    }

    #[test]
    fn test_goverance_vote_delegator_fail() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (10 * 2);

        let validator_address = established_address_1();
        let delegator_address = established_address_3();

        initialize_account_balance(
            &mut state,
            &delegator_address,
            token::Amount::native_whole(1000000),
        );

        bond_tokens(
            &mut state,
            Some(&delegator_address),
            &validator_address,
            token::Amount::from_u64(10000),
            Epoch(1),
            None,
        )
        .unwrap();

        update_epoch_to(&mut state, 10, height);

        let vote_key = get_vote_proposal_key(
            0,
            delegator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: delegator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(delegator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }

    #[test]
    fn test_goverance_vote_invalid_verifier_fail() {
        let mut state = init_storage();

        let proposal_id = 0;
        let activation_epoch = 19;

        let mut keys_changed = get_proposal_keys(proposal_id, activation_epoch);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX),
        ));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let mut verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(0),
        );
        state.commit_block().unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        init_proposal(
            &mut state,
            proposal_id,
            500,
            3,
            9,
            19,
            &signer_address,
            false,
        );

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Ok(_)
        );

        state.write_log_mut().commit_batch();
        state.commit_block().unwrap();

        let height = state.in_mem().get_block_height().0 + (10 * 2);

        let validator_address = established_address_1();
        let delegator_address = established_address_3();

        initialize_account_balance(
            &mut state,
            &delegator_address,
            token::Amount::native_whole(1000000),
        );

        bond_tokens(
            &mut state,
            Some(&delegator_address),
            &validator_address,
            token::Amount::from_u64(10000),
            Epoch(1),
            None,
        )
        .unwrap();

        update_epoch_to(&mut state, 10, height);

        let vote_key = get_vote_proposal_key(
            0,
            delegator_address.clone(),
            validator_address.clone(),
        );
        state
            .push_action(Action::Gov(GovAction::VoteProposal {
                id: 0,
                voter: delegator_address.clone(),
            }))
            .unwrap();
        state
            .write_log_mut()
            .write(&vote_key, ProposalVote::Yay.serialize_to_vec())
            .unwrap();

        keys_changed.clear();
        keys_changed.insert(vote_key);

        verifiers.clear();
        verifiers.insert(validator_address);

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache,
        );

        let governance_vp = GovernanceVp::new(ctx);

        assert_matches!(
            governance_vp.validate_tx(&batched_tx, &keys_changed, &verifiers),
            Err(_)
        );
    }
}
