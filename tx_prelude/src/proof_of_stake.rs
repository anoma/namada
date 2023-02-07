//! Proof of Stake system integration with functions for transactions

use namada_core::types::key::common;
use namada_core::types::transaction::{InitAccount, InitValidator};
use namada_core::types::{key, token};
pub use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::{
    become_validator, bond_tokens, change_validator_commission_rate,
    read_pos_params, unbond_tokens, withdraw_tokens,
};
pub use namada_proof_of_stake::{parameters, types};
use rust_decimal::Decimal;

use super::*;

impl Ctx {
    /// NEW: Self-bond tokens to a validator when `source` is `None` or equal to
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

    /// NEW: Unbond self-bonded tokens from a validator when `source` is `None`
    /// or equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    pub fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        unbond_tokens(self, source, validator, amount, current_epoch)
    }

    /// NEW: Withdraw unbonded tokens from a self-bond to a validator when
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

    /// NEW: Change validator commission rate.
    pub fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        rate: &Decimal,
    ) -> TxResult {
        let current_epoch = self.get_block_epoch()?;
        change_validator_commission_rate(self, validator, *rate, current_epoch)
    }

    /// NEW: Attempt to initialize a validator account. On success, returns the
    /// initialized validator account's address.
    pub fn init_validator(
        &mut self,
        InitValidator {
            account_keys,
            consensus_key,
            protocol_key,
            dkg_key,
            commission_rate,
            max_commission_rate_change,
            threshold,
            validator_vp_code,
        }: InitValidator,
    ) -> EnvResult<Address> {
        let current_epoch = self.get_block_epoch()?;
        let account_data = InitAccount {
            public_keys: account_keys,
            threshold,
            vp_code: validator_vp_code,
        };
        let validator_address = account::init_account(self, account_data)?;
        let protocol_pk_key = key::protocol_pk_key(&validator_address);
        self.write(&protocol_pk_key, &protocol_key)?;
        let dkg_pk_key = key::dkg_session_keys::dkg_pk_key(&validator_address);
        self.write(&dkg_pk_key, &dkg_key)?;

        let params = read_pos_params(self)?;
        become_validator(
            self,
            &params,
            &validator_address,
            &consensus_key,
            current_epoch,
            commission_rate,
            max_commission_rate_change,
        )?;

        Ok(validator_address)
    }
}
