//! The necessary type definitions for the contents of the
//! Ethereum bridge pool
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::token::Token;
use serde::{Deserialize, Serialize};

use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolProof;
use crate::types::address::Address;
use crate::types::eth_abi::Encode;
use crate::types::ethereum_events::{EthAddress, Uint};
use crate::types::keccak::KeccakHash;
use crate::types::storage::{BlockHeight, DbKeySeg, Key};
use crate::types::token::Amount;
use crate::types::vote_extensions::validator_set_update::ValidatorSetArgs;

/// A namespace used in our Ethereuem smart contracts
const NAMESPACE: &str = "transfer";

/// A transfer message to be submitted to Ethereum
/// to move assets from Namada across the bridge.
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct TransferToEthereum {
    /// The type of token
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The sender of the transfer
    pub sender: Address,
    /// The amount to be transferred
    pub amount: Amount,
}

/// A transfer message to Ethereum sitting in the
/// bridge pool, waiting to be relayed
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct PendingTransfer {
    /// The message to send to Ethereum to
    pub transfer: TransferToEthereum,
    /// The amount of gas fees (in NAM)
    /// paid by the user sending this transfer
    pub gas_fee: GasFee,
}

impl Encode<7> for PendingTransfer {
    fn tokenize(&self) -> [Token; 7] {
        // TODO: This version should be looked up from storage
        let version = Token::Uint(1.into());
        let namespace = Token::String(NAMESPACE.into());
        let from = Token::Address(self.transfer.asset.0.into());
        let fee = Token::Uint(u64::from(self.gas_fee.amount).into());
        let to = Token::Address(self.transfer.recipient.0.into());
        let amount = Token::Uint(u64::from(self.transfer.amount).into());
        let fee_from = Token::String(self.gas_fee.payer.to_string());
        [version, namespace, from, to, amount, fee, fee_from]
    }
}

impl From<&PendingTransfer> for Key {
    fn from(transfer: &PendingTransfer) -> Self {
        Key {
            segments: vec![DbKeySeg::StringSeg(
                transfer.keccak256().to_string(),
            )],
        }
    }
}

/// The amount of NAM to be payed to the relayer of
/// a transfer across the Ethereum Bridge to compensate
/// for Ethereum gas fees.
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct GasFee {
    /// The amount of fees (in NAM)
    pub amount: Amount,
    /// The account of fee payer.
    pub payer: Address,
}

/// A Merkle root (Keccak hash) of the Ethereum
/// bridge pool that has been signed by validators'
/// Ethereum keys.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct MultiSignedMerkleRoot {
    /// The signatures from validators
    pub sigs: BTreeSet<crate::types::key::secp256k1::Signature>,
    /// The Merkle root being signed
    pub root: KeccakHash,
    /// The block height at which this root was valid
    pub height: BlockHeight,
    /// A nonce for the next transfer batch for replay protection
    pub nonce: Uint,
}

impl Encode<3> for MultiSignedMerkleRoot {
    fn tokenize(&self) -> [Token; 3] {
        let MultiSignedMerkleRoot {
            sigs, root, nonce, ..
        } = self;
        // TODO: check the tokenization of the signatures
        let sigs = Token::Array(
            sigs.iter().map(|sig| sig.tokenize()[0].clone()).collect(),
        );
        let root = Token::FixedBytes(root.0.to_vec());
        [sigs, root, Token::Uint(nonce.clone().into())]
    }
}

/// All the information to relay to Ethereum
/// that a set of transfers exist in the Ethereum
/// bridge pool.
pub struct RelayProof {
    /// Information about the signing validators
    pub validator_args: ValidatorSetArgs,
    /// A merkle root signed by a quorum of validators
    pub root: MultiSignedMerkleRoot,
    /// A membership proof
    pub proof: BridgePoolProof,
}

impl Encode<7> for RelayProof {
    fn tokenize(&self) -> [Token; 7] {
        let [val_set_args] = self.validator_args.tokenize();
        let [sigs, root, nonce] = self.root.tokenize();
        let [proof, transfers, flags] = self.proof.tokenize();
        [val_set_args, sigs, transfers, root, proof, flags, nonce]
    }
}
