//! Proof of Stake system integration with functions for transactions

use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::transaction::InitValidator;
use namada_core::types::{key, token};
pub use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::{
    become_validator, bond_tokens, change_validator_commission_rate,
    read_pos_params, redelegate_tokens, unbond_tokens, unjail_validator,
    withdraw_tokens, BecomeValidator,
};
pub use namada_proof_of_stake::{parameters, types, ResultSlashing};

use super::*;

impl Ctx {
    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    pub fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        bond_tokens(self, source, validator, amount, current_epoch)
    }

    /// Unbond self-bonded tokens from a validator when `source` is `None`
    /// or equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    pub fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> EnvResult<ResultSlashing> {
        let current_epoch = self.get_block_epoch()?;
        unbond_tokens(self, source, validator, amount, current_epoch, false)
    }

    /// Withdraw unbonded tokens from a self-bond to a validator when
    /// `source` is `None` or equal to the `validator` address, or withdraw
    /// unbonded tokens delegated to the `validator` to the `source`.
    pub fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
    ) -> EnvResult<token::Amount> {
        let current_epoch = self.get_block_epoch()?;
        withdraw_tokens(self, source, validator, current_epoch)
    }

    /// Change validator commission rate.
    pub fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        rate: &Dec,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        change_validator_commission_rate(self, validator, *rate, current_epoch)
    }

    /// Unjail a jailed validator and re-enter the validator sets.
    pub fn unjail_validator(&mut self, validator: &Address) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        unjail_validator(self, validator, current_epoch)
    }

    /// Redelegate bonded tokens from one validator to another one.
    pub fn redelegate_tokens(
        &mut self,
        owner: &Address,
        src_validator: &Address,
        dest_validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        redelegate_tokens(
            self,
            owner,
            src_validator,
            dest_validator,
            current_epoch,
            amount,
        )
    }

    /// Attempt to initialize a validator account. On success, returns the
    /// initialized validator account's address.
    pub fn init_validator(
        &mut self,
        InitValidator {
            account_key,
            consensus_key,
            eth_cold_key,
            eth_hot_key,
            protocol_key,
            dkg_key,
            commission_rate,
            max_commission_rate_change,
            validator_vp_code_hash: _,
        }: InitValidator,
        validator_vp_code_hash: Hash,
    ) -> EnvResult<Address> {
        let current_epoch = self.get_block_epoch()?;
        // Init validator account
        let validator_address = self.init_account(validator_vp_code_hash)?;
        let pk_key = key::pk_key(&validator_address);
        self.write(&pk_key, &account_key)?;
        let protocol_pk_key = key::protocol_pk_key(&validator_address);
        self.write(&protocol_pk_key, &protocol_key)?;
        let dkg_pk_key = key::dkg_session_keys::dkg_pk_key(&validator_address);
        self.write(&dkg_pk_key, &dkg_key)?;
        let eth_cold_key = key::common::PublicKey::Secp256k1(eth_cold_key);
        let eth_hot_key = key::common::PublicKey::Secp256k1(eth_hot_key);

        let params = read_pos_params(self)?;
        become_validator(BecomeValidator {
            storage: self,
            params: &params,
            address: &validator_address,
            consensus_key: &consensus_key,
            eth_cold_key: &eth_cold_key,
            eth_hot_key: &eth_hot_key,
            current_epoch,
            commission_rate,
            max_commission_rate_change,
        })?;

        Ok(validator_address)
    }
}
