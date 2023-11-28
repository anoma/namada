

/*
    SDK for building transactions without having to pass in an entire Namada chain

    Requirements:
        * Don't try to refactor the existing sdk - this shouldn't cause any merge conflicts with anything
        * Minimal dependencies - no filesystem, no multi-threading, no IO, no wasm decoding
            * core with default features turned off seems fine
        * No lifetimes or abstract types
            * it should be dump-ass simple to use this from other languages or contexts
        * Callers should never have to worry about TxType::Raw or TxType::Wrapper - this should be hidden in the implementation
        * No usage of async
            * None of this signing code requires any async behavior - it's crazy to force all callers into async

    Proposed Flow:
        * the crate should expose 1 struct and an implementation for that struct for every transaction type
            * every struct (ie Bond) should have these functions
                * new() - to create a new type of Bond - it takes all parameters, like chain_id (this will lead to duplication, which is desired for a simple API (if desired the caller can build their own TxFactory))
                * sign_bytes() - the bytes that need to be signed by the signer
        * the crate should expose 1 struct and an implementation for a wrapper transaction
            * new()
                * should take a correctly signed inner tx (this is not enforced but rather documented, you can use this API to create garbage)
                * takes the inner tx & the inner signature
                * should take all the fields that are required by the wrapper
            * sign_bytes() - the bytes that need to be signed by the signer

     Future Development:
        * !!! AVOID ABSTRACT TYPES (that a caller needs to pass in) or LIFETIMES (in the caller api) LIKE THE PLAGUE !!!
        * around this core light_sdk we can build more complex features
            * get data via helper functions from a connected node
                * can have an query endpoint that just takes a Tendermint RPC node and allows me to query it
            * verify signatures
            * support multi-sig signers
            * dry-run these transactions
                * ALWAYS EXPOSE SYNC AND ASYNC FUNCTIONALITY
                    * never force callers into using async - we must always support an API that synchronous
        * none of this extra stuff should leak into the core
            * need to be able to import the core to iOS or other languages without complex dependencies
        * key backends
            * file based key backends that callers can use
            * libudev based key backends that call out to HSMs

     Questions:
        * Can a single wrapper contain more than 1 inner transaction?
        * Can the signer of the inner tx be different than of the wrapper transaction?
        * Is the signature of the outer transaction dependent on the signature of the inner one?
        * How do the tags work again? Can I only sign over the tags and not the wasm_hash?
            * If we need wasm_hashes, those should be saved as constants in the binary and a caller can decide to pass in their own wasm hashes or load the constants.

            MAINNET_BOND_WASM_HASH: &str = "mainnet_wasm_hash";
            Bond::new("wasm_hash");
            Bond::new(MAINNET_BOND_WASM_HASH)
 */

/*
    * need a function sign_bytes() that just returns me the bytes to sign
    * need a function that takes a transaction and some sign_bytes and forms a submittable tx from them
    * this is roughly the API that we want
    ```rust
        let keypair = gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
    ```
 */

use namada_core::proto::{Tx, Signature};
use namada_core::types::chain::ChainId;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::time::DateTimeUtc;
use namada_core::types::hash::Hash;
use namada_core::types::transaction::GasLimit;
use namada_core::types::storage::Epoch;
use namada_core::types::transaction::Fee;
use namada_core::proto::Signer;
use std::collections::BTreeMap;
use namada_core::proto::Section;
use std::str::FromStr;
use namada_core::proto::TxError;
use namada_core::types::address::Address;
use namada_core::types::token;
use borsh_ext::BorshSerializeExt;
use namada_core::types::dec::Dec;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};

/// Initialize account transaction WASM
pub const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
/// Initialize validator transaction WASM path
pub const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
/// Unjail validator transaction WASM path
pub const TX_UNJAIL_VALIDATOR_WASM: &str = "tx_unjail_validator.wasm";
/// Deactivate validator transaction WASM path
pub const TX_DEACTIVATE_VALIDATOR_WASM: &str = "tx_deactivate_validator.wasm";
/// Reactivate validator transaction WASM path
pub const TX_REACTIVATE_VALIDATOR_WASM: &str = "tx_reactivate_validator.wasm";
/// Initialize proposal transaction WASM path
pub const TX_INIT_PROPOSAL_WASM: &str = "tx_init_proposal.wasm";
/// Vote transaction WASM path
pub const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";
/// Reveal public key transaction WASM path
pub const TX_REVEAL_PK_WASM: &str = "tx_reveal_pk.wasm";
/// Update validity predicate WASM path
pub const TX_UPDATE_ACCOUNT_WASM: &str = "tx_update_account.wasm";
/// Transfer transaction WASM path
pub const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
/// IBC transaction WASM path
pub const TX_IBC_WASM: &str = "tx_ibc.wasm";
/// User validity predicate WASM path
pub const VP_USER_WASM: &str = "vp_user.wasm";
/// Validator validity predicate WASM path
pub const VP_VALIDATOR_WASM: &str = "vp_validator.wasm";
/// Bond WASM path
pub const TX_BOND_WASM: &str = "tx_bond.wasm";
/// Unbond WASM path
pub const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
/// Withdraw WASM path
pub const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
/// Claim-rewards WASM path
pub const TX_CLAIM_REWARDS_WASM: &str = "tx_claim_rewards.wasm";
/// Bridge pool WASM path
pub const TX_BRIDGE_POOL_WASM: &str = "tx_bridge_pool.wasm";
/// Change commission WASM path
pub const TX_CHANGE_COMMISSION_WASM: &str =
    "tx_change_validator_commission.wasm";
/// Change consensus key WASM path
pub const TX_CHANGE_CONSENSUS_KEY_WASM: &str = "tx_change_consensus_key.wasm";
/// Change validator metadata WASM path
pub const TX_CHANGE_METADATA_WASM: &str = "tx_change_validator_metadata.wasm";
/// Resign steward WASM path
pub const TX_RESIGN_STEWARD: &str = "tx_resign_steward.wasm";
/// Update steward commission WASM path
pub const TX_UPDATE_STEWARD_COMMISSION: &str =
    "tx_update_steward_commission.wasm";
/// Redelegate transaction WASM path
pub const TX_REDELEGATE_WASM: &str = "tx_redelegate.wasm";
/// Target chain ID
pub const CHAIN_ID: &str = "localnet.3e837878d84b54a40f-0";
/// Reveal public key transaction code hash
pub const TX_REVEAL_PK_HASH: &str = "924d926119e24a16d2eb50752acedd9ffc506f5131bbfc866cdc1c0c20d2de77";

#[derive(Debug)]
pub enum Error { ParseWasmHashErr, ParseChainIdErr }

fn build_tx(
    data: Vec<u8>,
    timestamp: DateTimeUtc,
    expiration: Option<DateTimeUtc>,
    code_hash: &str,
    code_tag: &str,
    chain_id: &str,
) -> Result<Tx, Error> {
    // Provide default values for chain ID and code hash
    let chain_id = ChainId(chain_id.to_owned());
    let code_hash = Hash::from_str(code_hash).map_err(|_| Error::ParseWasmHashErr)?;
    // Construct a raw transaction
    let mut inner_tx = Tx::new(chain_id, expiration);
    inner_tx.header.timestamp = timestamp;
    inner_tx.add_code_from_hash(code_hash, Some(code_tag.to_owned()));
    inner_tx.add_serialized_data(data); // takes the borsh encoded data
    Ok(inner_tx)
}

fn sign_bytes(tx: &Tx) -> Hash {
    let mut tx = tx.clone();
    tx.protocol_filter();
    Signature {
        targets: vec![tx.raw_header_hash()],
        signer: Signer::PubKeys(vec![]),
        signatures: BTreeMap::new(),
    }.get_raw_hash()
}

fn attach_inner_signatures(
    tx: &Tx,
    signer: Signer,
    signatures: BTreeMap<u8, common::Signature>,
) -> Tx {
    let mut tx = tx.clone();
    tx.add_section(Section::Signature(Signature {
        targets: vec![tx.raw_header_hash()],
        signer,
        signatures,
    }));
    tx
}

pub struct RevealPk(Tx);

impl RevealPk {
    /// Build a raw Reveal Public Key transaction from the given parameters
    pub fn new(
        public_key: common::PublicKey,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        build_tx(public_key.serialize_to_vec(), timestamp, expiration, code_hash, TX_REVEAL_PK_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Bond(Tx);

impl Bond {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        amount: token::Amount,
        source: Option<Address>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let bond = namada_core::types::transaction::pos::Bond {
            validator,
            amount,
            source,
        };

        build_tx(bond.serialize_to_vec(), timestamp, expiration, code_hash, TX_BOND_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Unbond(Tx);

impl Unbond {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        amount: token::Amount,
        source: Option<Address>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let bond = namada_core::types::transaction::pos::Unbond {
            validator,
            amount,
            source,
        };

        build_tx(bond.serialize_to_vec(), timestamp, expiration, code_hash, TX_UNBOND_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct InitAccount(Tx);

impl InitAccount {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        public_keys: Vec<common::PublicKey>,
        vp_code_hash: Hash,
        threshold: u8,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_account = namada_core::types::transaction::account::InitAccount {
            public_keys,
            vp_code_hash,
            threshold,
        };

        build_tx(init_account.serialize_to_vec(), timestamp, expiration, code_hash, TX_INIT_ACCOUNT_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct UpdateAccount(Tx);

impl UpdateAccount {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        addr: Address,
        vp_code_hash: Option<Hash>,
        public_keys: Vec<common::PublicKey>,
        threshold: Option<u8>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let update_account = namada_core::types::transaction::account::UpdateAccount {
            addr,
            vp_code_hash,
            public_keys,
            threshold,
        };

        build_tx(update_account.serialize_to_vec(), timestamp, expiration, code_hash, TX_UPDATE_ACCOUNT_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct InitValidator(Tx);

impl InitValidator {
    /// Build a raw Bond transaction from the given parameters
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
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let update_account = namada_core::types::transaction::pos::InitValidator {
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

        build_tx(update_account.serialize_to_vec(), timestamp, expiration, code_hash, TX_INIT_VALIDATOR_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct InitProposal(Tx);

impl InitProposal {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        id: Option<u64>,
        content: Hash,
        author: Address,
        r#type: ProposalType,
        voting_start_epoch: Epoch,
        voting_end_epoch: Epoch,
        grace_epoch: Epoch,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::governance::InitProposalData {
            id,
            content,
            author,
            r#type,
            voting_start_epoch,
            voting_end_epoch,
            grace_epoch,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_INIT_PROPOSAL_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Transfer(Tx);

impl Transfer {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        source: Address,
        target: Address,
        token: Address,
        amount: DenominatedAmount,
        key: Option<String>,
        shielded: Option<Hash>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::token::Transfer {
            source,
            target,
            token,
            amount,
            key,
            shielded,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_TRANSFER_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Withdraw(Tx);

impl Withdraw {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::pos::Withdraw {
            validator,
            source,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_WITHDRAW_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct ClaimRewards(Tx);

impl ClaimRewards {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        source: Option<Address>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::pos::Withdraw {
            validator,
            source,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_CLAIM_REWARDS_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct ChangeCommission(Tx);

impl ChangeCommission {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        new_rate: Dec,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::pos::CommissionChange {
            validator,
            new_rate,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_CHANGE_COMMISSION_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct ChangeMetaData(Tx);

impl ChangeMetaData {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        commission_rate: Option<Dec>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::pos::MetaDataChange {
            validator,
            email,
            description,
            website,
            discord_handle,
            commission_rate,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_CHANGE_METADATA_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct ChangeConsensusKey(Tx);

impl ChangeConsensusKey {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        validator: Address,
        consensus_key: common::PublicKey,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::transaction::pos::ConsensusKeyChange {
            validator,
            consensus_key,
        };

        build_tx(init_proposal.serialize_to_vec(), timestamp, expiration, code_hash, TX_CHANGE_CONSENSUS_KEY_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct UnjailValidator(Tx);

impl UnjailValidator {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        address: Address,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        build_tx(address.serialize_to_vec(), timestamp, expiration, code_hash, TX_UNJAIL_VALIDATOR_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct DeactivateValidator(Tx);

impl DeactivateValidator {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        address: Address,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        build_tx(address.serialize_to_vec(), timestamp, expiration, code_hash, TX_DEACTIVATE_VALIDATOR_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct ReactivateValidator(Tx);

impl ReactivateValidator {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        address: Address,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        build_tx(address.serialize_to_vec(), timestamp, expiration, code_hash, TX_REACTIVATE_VALIDATOR_WASM, chain_id)
            .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Wrapper(Tx);

impl Wrapper {
    /// Takes a transaction and some signatures and wraps them in a wrapper
    /// transaction
    pub fn new(
        tx: &Tx,
        fee: Fee,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
        unshield_hash: Option<Hash>,
    ) -> Self {
        let mut tx = tx.clone();
        tx.add_wrapper(fee, fee_payer, epoch, gas_limit, unshield_hash);
        Self(tx)
    }

    /// Takes any kind of outer tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        let mut tx = self.0.clone();
        tx.protocol_filter();
        Signature {
            targets: tx.sechashes(),
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::new(),
        }.get_raw_hash()
    }

    /// Attach the given outer signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        let mut tx = self.0.clone();
        tx.add_section(Section::Signature(Signature {
            targets: tx.sechashes(),
            signer: Signer::PubKeys(vec![signer]),
            signatures: [(0, signature)].into_iter().collect(),
        }));
        Self(tx)
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> std::result::Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use namada_core::types::key::RefTo;
    use namada_core::types::key::SigScheme;
    use namada_core::types::token::Amount;
    use namada_core::types::address::Address;
    use std::str::FromStr;

    #[test]
    fn it_works() {
        // Setup the keys and addresses necessary for this test
        let nam = Address::from_str("tnam1q8vyjrk5n30vfphaa26v7prkh8mjv4rfd5fkxh80")
            .expect("unable to construct address");
        let sk = common::SecretKey::from_str("0083318ccceac6c08a0177667840b4b93f0e455e45d4c38c28b73b8f8462fbf548")
            .expect("unable to construct secret key");
        let pk = sk.ref_to();
        let now = DateTimeUtc::now();
        // Make the raw reveal PK transaction
        let reveal_pk = RevealPk::new(pk.clone(), now, None, TX_REVEAL_PK_HASH, CHAIN_ID)
            .unwrap();
        // Sign the raw reveal PK transaction
        let inner_hash = reveal_pk.sign_bytes();
        let sig = common::SigScheme::sign(&sk, inner_hash);
        let signatures = [(0, sig)].into_iter().collect();
        // Attach the inner signature to the transaction
        let reveal_pk = reveal_pk.attach_signatures(Signer::PubKeys(vec![pk.clone()]), signatures);
        let fee = Fee {
            amount_per_gas_unit: Amount::from(10),
            token: nam,
        };
        // Wrap the inner transaction
        let wrapper_tx = Wrapper::new(
            &reveal_pk.0,
            fee,
            pk.clone(),
            Epoch::from(10),
            GasLimit::from(20_000),
            None,
        );
        // Sign the wrapper transaction
        let outer_hash = wrapper_tx.sign_bytes();
        let sig = common::SigScheme::sign(&sk, outer_hash);
        // Attach the wrapper signature to the transaction
        let wrapper_tx = wrapper_tx.attach_signatures(pk.clone(), sig);
        // Validate the outcome
        wrapper_tx.0.validate_tx().expect("failed to validate transaction");
    }
}
