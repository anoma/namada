use namada_sdk::address::Address;
use namada_sdk::dec::Dec;
use namada_sdk::hash::Hash;
use namada_sdk::key::{common, secp256k1};
use namada_sdk::token;
use namada_sdk::token::{Amount, DenominatedAmount};
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::data::pos::Redelegation;
use namada_sdk::tx::{Authorization, Tx, TxError};

use super::{GlobalArgs, attach_fee, attach_fee_signature};
use crate::transaction;

const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_BECOME_VALIDATOR_WASM: &str = "tx_become_validator.wasm";
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
#[derive(Debug, Clone)]
pub struct Bond(Tx);

impl Bond {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        amount: token::Amount,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let unbond = namada_sdk::tx::data::pos::Bond {
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
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
        let unbond = namada_sdk::tx::data::pos::Unbond {
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to initialize a new PoS validator
pub struct BecomeValidator(Tx);

impl BecomeValidator {
    /// Build a raw Init validator transaction from the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
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
        avatar: Option<String>,
        name: Option<String>,
        args: GlobalArgs,
    ) -> Self {
        let update_account = namada_sdk::tx::data::pos::BecomeValidator {
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
        };

        Self(transaction::build_tx(
            args,
            update_account,
            TX_BECOME_VALIDATOR_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to unjail a PoS validator
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to deactivate a validator
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to reactivate a previously deactivated validator
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to claim PoS rewards
pub struct ClaimRewards(Tx);

impl ClaimRewards {
    /// Build a raw ClaimRewards transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal =
            namada_sdk::tx::data::pos::Withdraw { validator, source };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CLAIM_REWARDS_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to change the validator's metadata
pub struct ChangeMetaData(Tx);

impl ChangeMetaData {
    /// Build a raw ChangeMetadata transaction from the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        avatar: Option<String>,
        name: Option<String>,
        commission_rate: Option<Dec>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal = namada_sdk::tx::data::pos::MetaDataChange {
            validator,
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
            commission_rate,
        };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_CHANGE_METADATA_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to modify the validator's consensus key
pub struct ChangeConsensusKey(Tx);

impl ChangeConsensusKey {
    /// Build a raw ChangeConsensusKey transaction from the given parameters
    pub fn new(
        validator: Address,
        consensus_key: common::PublicKey,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal = namada_sdk::tx::data::pos::ConsensusKeyChange {
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to modify the validator's commission rate
pub struct ChangeCommission(Tx);

impl ChangeCommission {
    /// Build a raw ChangeCommission transaction from the given parameters
    pub fn new(validator: Address, new_rate: Dec, args: GlobalArgs) -> Self {
        let init_proposal = namada_sdk::tx::data::pos::CommissionChange {
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to withdraw previously unstaked funds
pub struct Withdraw(Tx);

impl Withdraw {
    /// Build a raw Withdraw transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal =
            namada_sdk::tx::data::pos::Withdraw { validator, source };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_WITHDRAW_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to redelegate
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}
