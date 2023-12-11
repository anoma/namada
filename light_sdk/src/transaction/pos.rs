use crate::transaction;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::proto::Section;
use namada_core::proto::SignatureIndex;
use namada_core::proto::Signer;
use namada_core::proto::TxError;
use namada_core::proto::{Signature, Tx};
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::pos::Redelegation;
use namada_core::types::transaction::Fee;
use namada_core::types::transaction::GasLimit;
use std::collections::BTreeMap;
use std::str::FromStr;

use super::GlobalArgs;

const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
const TX_UNJAIL_VALIDATOR_WASM: &str = "tx_unjail_validator.wasm";
const TX_DEACTIVATE_VALIDATOR_WASM: &str = "tx_deactivate_validator.wasm";
const TX_REACTIVATE_VALIDATOR_WASM: &str = "tx_reactivate_validator.wasm";
const TX_CLAIM_REWARDS_WASM: &str = "tx_claim_rewards.wasm";
const TX_REDELEGATE_WASM: &str = "tx_redelegate.wasm";
const TX_CHANGE_METADATA_WASM: &str = "tx_change_validator_metadata.wasm";
const TX_CHANGE_CONSENSUS_KEY_WASM: &str = "tx_change_consensus_key.wasm";
const TX_CHANGE_COMMISSION_WASM: &str = "tx_change_validator_commission.wasm";
const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";

/// A bond transaction
pub struct Bond(Tx);

impl Bond {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        amount: token::Amount,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let unbond = namada_core::types::transaction::pos::Bond {
            validator,
            amount,
            source,
        };

        Self(transaction::build_tx(
            args,
            unbond,
            TX_BOND_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

/// An unbond transaction
pub struct Unbond(Tx);

impl Unbond {
    /// Build a raw Unbond transaction from the given parameters
    pub fn new(
        validator: Address,
        amount: token::Amount,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let unbond = namada_core::types::transaction::pos::Unbond {
            validator,
            amount,
            source,
        };

        Self(transaction::build_tx(
            args,
            unbond,
            TX_UNBOND_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct InitValidator(Tx);

impl InitValidator {
    /// Build a raw Init validator transaction from the given parameters
    pub fn new(
        account_keys: Vec<common::PublicKey>,
        threshold: u8,
        consensus_key: common::PublicKey,
        eth_cold_key: secp256k1::PublicKey,
        eth_hot_key: secp256k1::PublicKey,
        protocol_key: common::PublicKey,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        email: String,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        validator_vp_code_hash: Hash,
        args: GlobalArgs,
    ) -> Self {
        let update_account =
            namada_core::types::transaction::pos::InitValidator {
                account_keys,
                threshold,
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
                validator_vp_code_hash,
            };

        Self(transaction::build_tx(
            args,
            update_account,
            TX_INIT_VALIDATOR_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct UnjailValidator(Tx);

impl UnjailValidator {
    /// Build a raw Unjail validator transaction from the given parameters
    pub fn new(address: Address, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            address,
            TX_UNJAIL_VALIDATOR_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct DeactivateValidator(Tx);

impl DeactivateValidator {
    /// Build a raw DeactivateValidator transaction from the given parameters
    pub fn new(address: Address, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            address,
            TX_DEACTIVATE_VALIDATOR_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct ReactivateValidator(Tx);

impl ReactivateValidator {
    /// Build a raw ReactivateValidator transaction from the given parameters
    pub fn new(address: Address, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            address,
            TX_REACTIVATE_VALIDATOR_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct ClaimRewards(Tx);

impl ClaimRewards {
    /// Build a raw ClaimRewards transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal = namada_core::types::transaction::pos::Withdraw {
            validator,
            source,
        };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CLAIM_REWARDS_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct ChangeMetaData(Tx);

impl ChangeMetaData {
    /// Build a raw ChangeMetadata transaction from the given parameters
    pub fn new(
        validator: Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        commission_rate: Option<Dec>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal =
            namada_core::types::transaction::pos::MetaDataChange {
                validator,
                email,
                description,
                website,
                discord_handle,
                commission_rate,
            };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CHANGE_METADATA_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct ChangeConsensusKey(Tx);

impl ChangeConsensusKey {
    /// Build a raw ChangeConsensusKey transaction from the given parameters
    pub fn new(
        validator: Address,
        consensus_key: common::PublicKey,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal =
            namada_core::types::transaction::pos::ConsensusKeyChange {
                validator,
                consensus_key,
            };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CHANGE_CONSENSUS_KEY_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct ChangeCommission(Tx);

impl ChangeCommission {
    /// Build a raw ChangeCommission transaction from the given parameters
    pub fn new(validator: Address, new_rate: Dec, args: GlobalArgs) -> Self {
        let init_proposal =
            namada_core::types::transaction::pos::CommissionChange {
                validator,
                new_rate,
            };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CHANGE_COMMISSION_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct Withdraw(Tx);

impl Withdraw {
    /// Build a raw Withdraw transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        //FIXME: request the correct type directly in the args instead of rebuilding it
        let init_proposal = namada_core::types::transaction::pos::Withdraw {
            validator,
            source,
        };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_WITHDRAW_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct Redelegate(Tx);

impl Redelegate {
    /// Build a raw Redelegate transaction from the given parameters
    pub fn new(
        src_validator: Address,
        dest_validator: Address,
        owner: Address,
        amount: Amount,
        args: GlobalArgs,
    ) -> Self {
        let redelegation = Redelegation {
            src_validator,
            dest_validator,
            owner,
            amount,
        };

        Self(transaction::build_tx(
            args,
            redelegation,
            TX_REDELEGATE_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}
