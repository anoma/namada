//! Proof of Stake system integration with functions for transactions

use namada_account::Address;
use namada_core::dec::Dec;
use namada_core::key;
pub use namada_proof_of_stake::parameters::PosParams;
pub use namada_proof_of_stake::queries::find_delegation_validators;
use namada_proof_of_stake::storage::read_pos_params;
use namada_proof_of_stake::types::{ResultSlashing, ValidatorMetaData};
use namada_proof_of_stake::{
    become_validator, bond_tokens, change_consensus_key,
    change_validator_commission_rate, change_validator_metadata,
    claim_reward_tokens, deactivate_validator, reactivate_validator,
    redelegate_tokens, unbond_tokens, unjail_validator, withdraw_tokens,
};
pub use namada_proof_of_stake::{parameters, storage, storage_key, types};
pub use namada_state::StorageRead;
use namada_tx::action::{
    Action, ClaimRewards, PosAction, Redelegation, Unbond, Withdraw, Write,
};
use namada_tx::data::pos::{BecomeValidator, Bond};
use namada_tx_env::ctx::{common, Ctx, TxResult};
use namada_tx_env::{Result, TxEnv};

use crate::{governance, token};

/// Extension trait to add PoS methods to `Ctx`.
pub trait PosCtxExt {
    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult;

    /// Unbond self-bonded tokens from a validator when `source` is `None`
    /// or equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> Result<ResultSlashing>;

    /// Withdraw unbonded tokens from a self-bond to a validator when
    /// `source` is `None` or equal to the `validator` address, or withdraw
    /// unbonded tokens delegated to the `validator` to the `source`.
    fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> Result<token::Amount>;

    /// Change validator consensus key.
    fn change_validator_consensus_key(
        &mut self,
        validator: &Address,
        consensus_key: &common::PublicKey,
    ) -> TxResult;

    /// Change validator commission rate.
    fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        rate: &Dec,
    ) -> TxResult;

    /// Unjail a jailed validator and re-enter the validator sets.
    fn unjail_validator(&mut self, validator: &Address) -> TxResult;

    /// Redelegate bonded tokens from one validator to another one.
    fn redelegate_tokens(
        &mut self,
        owner: &Address,
        src_validator: &Address,
        dest_validator: &Address,
        amount: token::Amount,
    ) -> TxResult;

    /// Claim available reward tokens
    fn claim_reward_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> Result<token::Amount>;

    /// Attempt to initialize a validator account. On success, returns the
    /// initialized validator account's address.
    fn become_validator(
        &mut self,
        become_validator: BecomeValidator,
    ) -> Result<Address>;

    /// Deactivate validator
    fn deactivate_validator(&mut self, validator: &Address) -> TxResult;

    /// Reactivate validator
    fn reactivate_validator(&mut self, validator: &Address) -> TxResult;

    /// Change validator metadata.
    #[allow(clippy::too_many_arguments)]
    fn change_validator_metadata(
        &mut self,
        validator: &Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        avatar: Option<String>,
        name: Option<String>,
        commission_rate: Option<Dec>,
    ) -> TxResult;
}

impl PosCtxExt for Ctx {
    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        // The tx must be authorized by the source address
        let verifier = source.as_ref().unwrap_or(&validator);
        self.insert_verifier(verifier)?;

        self.push_action(Action::Pos(PosAction::Bond(Bond {
            validator: validator.clone(),
            amount,
            source: source.cloned(),
        })))?;

        let current_epoch = self.get_block_epoch()?;
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            self,
            source,
            validator,
            amount,
            current_epoch,
            None,
        )
    }

    /// Unbond self-bonded tokens from a validator when `source` is `None`
    /// or equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> Result<ResultSlashing> {
        // The tx must be authorized by the source address
        let verifier = source.as_ref().unwrap_or(&validator);
        self.insert_verifier(verifier)?;

        self.push_action(Action::Pos(PosAction::Unbond(Unbond {
            validator: validator.clone(),
            amount,
            source: source.cloned(),
        })))?;

        let current_epoch = self.get_block_epoch()?;
        unbond_tokens::<_, governance::Store<_>>(
            self,
            source,
            validator,
            amount,
            current_epoch,
            false,
        )
    }

    /// Withdraw unbonded tokens from a self-bond to a validator when
    /// `source` is `None` or equal to the `validator` address, or withdraw
    /// unbonded tokens delegated to the `validator` to the `source`.
    fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> Result<token::Amount> {
        // The tx must be authorized by the source address
        let verifier = source.as_ref().unwrap_or(&validator);
        self.insert_verifier(verifier)?;

        self.push_action(Action::Pos(PosAction::Withdraw(Withdraw {
            validator: validator.clone(),
            source: source.cloned(),
        })))?;

        let current_epoch = self.get_block_epoch()?;
        withdraw_tokens::<_, governance::Store<_>, token::Store<_>>(
            self,
            source,
            validator,
            current_epoch,
        )
    }

    /// Change validator consensus key.
    fn change_validator_consensus_key(
        &mut self,
        validator: &Address,
        consensus_key: &common::PublicKey,
    ) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::ConsensusKeyChange(
            validator.clone(),
        )))?;

        let current_epoch = self.get_block_epoch()?;
        change_consensus_key::<_, governance::Store<_>>(
            self,
            validator,
            consensus_key,
            current_epoch,
        )
    }

    /// Change validator commission rate.
    fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        rate: &Dec,
    ) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::CommissionChange(
            validator.clone(),
        )))?;

        let current_epoch = self.get_block_epoch()?;
        change_validator_commission_rate::<_, governance::Store<_>>(
            self,
            validator,
            *rate,
            current_epoch,
        )
    }

    /// Unjail a jailed validator and re-enter the validator sets.
    fn unjail_validator(&mut self, validator: &Address) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::Unjail(validator.clone())))?;

        let current_epoch = self.get_block_epoch()?;
        unjail_validator::<_, governance::Store<_>>(
            self,
            validator,
            current_epoch,
        )
    }

    /// Redelegate bonded tokens from one validator to another one.
    fn redelegate_tokens(
        &mut self,
        owner: &Address,
        src_validator: &Address,
        dest_validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(owner)?;

        self.push_action(Action::Pos(PosAction::Redelegation(Redelegation {
            src_validator: src_validator.clone(),
            dest_validator: dest_validator.clone(),
            owner: owner.clone(),
            amount,
        })))?;

        let current_epoch = self.get_block_epoch()?;
        redelegate_tokens::<_, governance::Store<_>>(
            self,
            owner,
            src_validator,
            dest_validator,
            current_epoch,
            amount,
        )
    }

    /// Claim available reward tokens
    fn claim_reward_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> Result<token::Amount> {
        // The tx must be authorized by the source address
        let verifier = source.as_ref().unwrap_or(&validator);
        self.insert_verifier(verifier)?;

        self.push_action(Action::Pos(PosAction::ClaimRewards(ClaimRewards {
            validator: validator.clone(),
            source: source.cloned(),
        })))?;

        let current_epoch = self.get_block_epoch()?;
        claim_reward_tokens::<_, governance::Store<_>, token::Store<_>>(
            self,
            source,
            validator,
            current_epoch,
        )
    }

    /// Attempt to initialize a validator account. On success, returns the
    /// initialized validator account's address.
    fn become_validator(
        &mut self,
        BecomeValidator {
            address,
            consensus_key,
            eth_cold_key,
            eth_hot_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
        }: BecomeValidator,
    ) -> Result<Address> {
        let current_epoch = self.get_block_epoch()?;
        let eth_cold_key = key::common::PublicKey::Secp256k1(eth_cold_key);
        let eth_hot_key = key::common::PublicKey::Secp256k1(eth_hot_key);
        let params = read_pos_params::<_, governance::Store<_>>(self)?;

        // The tx must be authorized by the source address
        self.insert_verifier(&address)?;

        self.push_action(Action::Pos(PosAction::BecomeValidator(
            address.clone(),
        )))?;

        become_validator::<_, governance::Store<_>>(
            self,
            namada_proof_of_stake::BecomeValidator {
                params: &params,
                address: &address,
                consensus_key: &consensus_key,
                protocol_key: &protocol_key,
                eth_cold_key: &eth_cold_key,
                eth_hot_key: &eth_hot_key,
                current_epoch,
                commission_rate,
                max_commission_rate_change,
                metadata: ValidatorMetaData {
                    email,
                    description,
                    website,
                    discord_handle,
                    avatar,
                    name,
                },
                offset_opt: None,
            },
        )?;

        Ok(address)
    }

    /// Deactivate validator
    fn deactivate_validator(&mut self, validator: &Address) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::DeactivateValidator(
            validator.clone(),
        )))?;

        let current_epoch = self.get_block_epoch()?;
        deactivate_validator::<_, governance::Store<_>>(
            self,
            validator,
            current_epoch,
        )
    }

    /// Reactivate validator
    fn reactivate_validator(&mut self, validator: &Address) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::ReactivateValidator(
            validator.clone(),
        )))?;

        let current_epoch = self.get_block_epoch()?;
        reactivate_validator::<_, governance::Store<_>>(
            self,
            validator,
            current_epoch,
        )
    }

    /// Change validator metadata.
    #[allow(clippy::too_many_arguments)]
    fn change_validator_metadata(
        &mut self,
        validator: &Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        avatar: Option<String>,
        name: Option<String>,
        commission_rate: Option<Dec>,
    ) -> TxResult {
        // The tx must be authorized by the source address
        self.insert_verifier(validator)?;

        self.push_action(Action::Pos(PosAction::MetadataChange(
            validator.clone(),
        )))?;

        let current_epoch = self.get_block_epoch()?;
        change_validator_metadata::<_, governance::Store<_>>(
            self,
            validator,
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
            commission_rate,
            current_epoch,
        )
    }
}
