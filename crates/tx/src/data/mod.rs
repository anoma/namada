//! Data-Types that are used in transactions.

/// txs that contain decrypted payloads or assertions of
/// non-decryptability
pub mod decrypted;
pub mod eval_vp;
/// txs to manage pgf
pub mod pgf;
/// txs to manage pos
pub mod pos;
/// transaction protocols made by validators
pub mod protocol;
/// wrapper txs with encrypted payloads
pub mod wrapper;

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::str::FromStr;

pub use decrypted::*;
use namada_core::address::Address;
use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::ethereum_structs::EthBridgeEvent;
use namada_core::hash::Hash;
use namada_core::ibc::IbcEvent;
use namada_core::storage;
use namada_gas::{Gas, VpsGas};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use wrapper::*;

use crate::data::protocol::ProtocolTx;

/// The different result codes that the ledger may send back to a client
/// indicating the status of their submitted tx.
/// The codes must not change with versions, only need ones may be added.
#[derive(
    Debug,
    Copy,
    Clone,
    FromPrimitive,
    ToPrimitive,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
pub enum ResultCode {
    // WARN: These codes shouldn't be changed between version!
    // =========================================================================
    /// Success
    Ok = 0,
    /// Error in WASM tx execution
    WasmRuntimeError = 1,
    /// Invalid tx
    InvalidTx = 2,
    /// Invalid signature
    InvalidSig = 3,
    /// Tx is in invalid order
    InvalidOrder = 4,
    /// Tx wasn't expected
    ExtraTxs = 5,
    /// Undecryptable
    Undecryptable = 6,
    /// The block is full
    AllocationError = 7,
    /// Replayed tx
    ReplayTx = 8,
    /// Invalid chain ID
    InvalidChainId = 9,
    /// Expired tx
    ExpiredTx = 10,
    /// Exceeded gas limit
    TxGasLimit = 11,
    /// Error in paying tx fee
    FeeError = 12,
    /// Invalid vote extension
    InvalidVoteExtension = 13,
    /// Tx is too large
    TooLarge = 14,
    /// Decrypted tx is expired
    ExpiredDecryptedTx = 15,
    // =========================================================================
    // WARN: These codes shouldn't be changed between version!
}

impl ResultCode {
    /// Checks if the given [`ResultCode`] value is a protocol level error,
    /// that can be recovered from at the finalize block stage.
    pub const fn is_recoverable(&self) -> bool {
        use ResultCode::*;
        // NOTE: pattern match on all `ResultCode` variants, in order
        // to catch potential bugs when adding new codes
        match self {
            Ok | WasmRuntimeError | ExpiredDecryptedTx => true,
            InvalidTx | InvalidSig | InvalidOrder | ExtraTxs
            | Undecryptable | AllocationError | ReplayTx | InvalidChainId
            | ExpiredTx | TxGasLimit | FeeError | InvalidVoteExtension
            | TooLarge => false,
        }
    }

    /// Convert to `u32`.
    pub fn to_u32(&self) -> u32 {
        ToPrimitive::to_u32(self).unwrap()
    }

    /// Convert from `u32`.
    pub fn from_u32(raw: u32) -> Option<Self> {
        FromPrimitive::from_u32(raw)
    }
}

impl From<ResultCode> for String {
    fn from(code: ResultCode) -> String {
        code.to_string()
    }
}

impl From<ResultCode> for u32 {
    fn from(code: ResultCode) -> u32 {
        code.to_u32()
    }
}

impl Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u32())
    }
}

impl FromStr for ResultCode {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = u32::from_str(s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        Self::from_u32(raw).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected error code",
            )
        })
    }
}

impl From<ResultCode> for namada_core::tendermint::abci::Code {
    fn from(value: ResultCode) -> Self {
        Self::from(value.to_u32())
    }
}

/// Get the hash of a transaction
pub fn hash_tx(tx_bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(tx_bytes);
    Hash(*digest.as_ref())
}

/// Transaction application result
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct TxResult {
    /// Total gas used by the transaction (includes the gas used by VPs)
    pub gas_used: Gas,
    /// Storage keys touched by the transaction
    pub changed_keys: BTreeSet<storage::Key>,
    /// The results of all the triggered validity predicates by the transaction
    pub vps_result: VpsResult,
    /// New established addresses created by the transaction
    pub initialized_accounts: Vec<Address>,
    /// IBC events emitted by the transaction
    pub ibc_events: BTreeSet<IbcEvent>,
    /// Ethereum bridge events emitted by the transaction
    pub eth_bridge_events: BTreeSet<EthBridgeEvent>,
}

impl TxResult {
    /// Check if the tx has been accepted by all the VPs
    pub fn is_accepted(&self) -> bool {
        self.vps_result.rejected_vps.is_empty()
    }
}

/// Result of checking a transaction with validity predicates
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct VpsResult {
    /// The addresses whose VPs accepted the transaction
    pub accepted_vps: BTreeSet<Address>,
    /// The addresses whose VPs rejected the transaction
    pub rejected_vps: BTreeSet<Address>,
    /// The total gas used by all the VPs
    pub gas_used: VpsGas,
    /// Errors occurred in any of the VPs, if any
    pub errors: Vec<(Address, String)>,
    /// Sentinel to signal an invalid transaction signature
    pub invalid_sig: bool,
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "Transaction is {}. Gas used: {};{} VPs result: {}",
                if self.is_accepted() {
                    "valid"
                } else {
                    "invalid"
                },
                self.gas_used,
                iterable_to_string("Changed keys", self.changed_keys.iter()),
                self.vps_result,
            )
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

impl FromStr for TxResult {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl fmt::Display for VpsResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            iterable_to_string("Accepted", self.accepted_vps.iter()),
            iterable_to_string("Rejected", self.rejected_vps.iter()),
            iterable_to_string(
                "Errors",
                self.errors
                    .iter()
                    .map(|(addr, err)| format!("{} in {}", err, addr))
            ),
        )
    }
}

/// Format all the values of the given iterator into a string
fn iterable_to_string<T: fmt::Display>(
    label: &str,
    iter: impl Iterator<Item = T>,
) -> String {
    let mut iter = iter.peekable();
    if iter.peek().is_none() {
        "".into()
    } else {
        format!(
            " {}: {};",
            label,
            iter.map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

/// Struct that classifies that kind of Tx
/// based on the contents of its data.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum TxType {
    /// An ordinary tx
    Raw,
    /// A Tx that contains an encrypted raw tx
    Wrapper(Box<WrapperTx>),
    /// An attempted decryption of a wrapper tx
    Decrypted(DecryptedTx),
    /// Txs issued by validators as part of internal protocols
    Protocol(Box<ProtocolTx>),
}

impl TxType {
    /// Produce a SHA-256 hash of this header  
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

/// Sentinel used in transactions to signal events that require special
/// replay protection handling back to the protocol.
#[derive(Debug, Default)]
pub enum TxSentinel {
    /// No action required
    #[default]
    None,
    /// Exceeded gas limit
    OutOfGas,
    /// Found invalid commtiment to one of the transaction's sections
    InvalidCommitment,
}

impl TxSentinel {
    /// Set the sentinel for an out of gas error
    pub fn set_out_of_gas(&mut self) {
        *self = Self::OutOfGas
    }

    /// Set the sentinel for an invalid section commitment error
    pub fn set_invalid_commitment(&mut self) {
        *self = Self::InvalidCommitment
    }
}

#[cfg(test)]
mod test_process_tx {
    use assert_matches::assert_matches;
    use namada_core::address::testing::nam;
    use namada_core::key::*;
    use namada_core::storage::Epoch;
    use namada_core::token::{Amount, DenominatedAmount};

    use super::*;
    use crate::{Code, Data, Section, Signature, Tx, TxError};

    fn gen_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
    }

    /// Test that process_tx correctly identifies a raw tx with no
    /// data and returns an identical copy
    #[test]
    fn test_process_tx_raw_tx_no_data() {
        let mut outer_tx = Tx::from_type(TxType::Raw);
        let code_sec = outer_tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        outer_tx.validate_tx().expect("Test failed");
        match outer_tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(code_sec.get_hash(), outer_tx.header.code_hash,)
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies tx containing
    /// a raw tx with some data and returns an identical copy
    /// of the inner data
    #[test]
    fn test_process_tx_raw_tx_some_data() {
        let mut tx = Tx::from_type(TxType::Raw);
        let code_sec = tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        let data_sec = tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()))
            .clone();

        tx.validate_tx().expect("Test failed");
        match tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(code_sec.get_hash(), tx.header().code_hash,);
                assert_eq!(data_sec.get_hash(), tx.header().data_hash,);
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies a raw tx with some
    /// signed data and returns an identical copy of the inner data
    #[test]
    fn test_process_tx_raw_tx_some_signed_data() {
        let mut tx = Tx::from_type(TxType::Raw);
        let code_sec = tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        let data_sec = tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()))
            .clone();
        tx.add_section(Section::Signature(Signature::new(
            vec![tx.raw_header_hash()],
            [(0, gen_keypair())].into_iter().collect(),
            None,
        )));

        tx.validate_tx().expect("Test failed");
        match tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(code_sec.get_hash(), tx.header().code_hash,);
                assert_eq!(data_sec.get_hash(), tx.header().data_hash,);
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies a wrapper tx with some
    /// data and extracts the signed data.
    #[test]
    fn test_process_tx_wrapper_tx() {
        let keypair = gen_keypair();
        // the signed tx
        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    Amount::from_uint(10, 0).expect("Test failed"),
                ),
                token: nam(),
            },
            keypair.ref_to(),
            Epoch(0),
            Default::default(),
            None,
        ))));
        tx.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.add_section(Section::Signature(Signature::new(
            tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        tx.validate_tx().expect("Test failed");
    }

    /// Test that process_tx correctly returns an error on a wrapper tx
    /// with some unsigned data
    #[test]
    fn test_process_tx_wrapper_tx_unsigned() {
        let keypair = gen_keypair();
        // the signed tx
        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    Amount::from_uint(10, 0).expect("Test failed"),
                ),
                token: nam(),
            },
            keypair.ref_to(),
            Epoch(0),
            Default::default(),
            None,
        ))));
        tx.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let result = tx.validate_tx().expect_err("Test failed");
        assert_matches!(result, TxError::SigError(_));
    }
}

/// Test that process_tx correctly identifies a DecryptedTx
/// with some unsigned data and returns an identical copy
#[test]
fn test_process_tx_decrypted_unsigned() {
    use crate::{Code, Data, Tx};
    let mut tx = Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
    let code_sec = tx
        .set_code(Code::new("transaction data".as_bytes().to_owned(), None))
        .clone();
    let data_sec = tx
        .set_data(Data::new("transaction data".as_bytes().to_owned()))
        .clone();
    tx.validate_tx().expect("Test failed");
    match tx.header().tx_type {
        TxType::Decrypted(DecryptedTx::Decrypted) => {
            assert_eq!(tx.header().code_hash, code_sec.get_hash(),);
            assert_eq!(tx.header().data_hash, data_sec.get_hash(),);
        }
        _ => panic!("Test failed"),
    }
}

/// Test that process_tx correctly identifies a DecryptedTx
/// with some signed data and extracts it without checking
/// signature
#[test]
fn test_process_tx_decrypted_signed() {
    use namada_core::key::*;

    use crate::{Code, Data, Section, Signature, Tx};

    fn gen_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
    }

    use namada_core::key::Signature as S;
    let mut decrypted =
        Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
    // Invalid signed data
    let ed_sig =
        ed25519::Signature::try_from_slice([0u8; 64].as_ref()).unwrap();
    let mut sig_sec = Signature::new(
        vec![decrypted.header_hash()],
        [(0, gen_keypair())].into_iter().collect(),
        None,
    );
    sig_sec
        .signatures
        .insert(0, common::Signature::try_from_sig(&ed_sig).unwrap());
    decrypted.add_section(Section::Signature(sig_sec));
    // create the tx with signed decrypted data
    let code_sec = decrypted
        .set_code(Code::new("transaction data".as_bytes().to_owned(), None))
        .clone();
    let data_sec = decrypted
        .set_data(Data::new("transaction data".as_bytes().to_owned()))
        .clone();
    decrypted.validate_tx().expect("Test failed");
    match decrypted.header().tx_type {
        TxType::Decrypted(DecryptedTx::Decrypted) => {
            assert_eq!(decrypted.header.code_hash, code_sec.get_hash());
            assert_eq!(decrypted.header.data_hash, data_sec.get_hash());
        }
        _ => panic!("Test failed"),
    }
}
