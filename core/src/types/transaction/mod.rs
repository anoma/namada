//! Types that are used in transactions.

/// txs that contain decrypted payloads or assertions of
/// non-decryptability
pub mod decrypted;
/// tools for encrypted data
pub mod encrypted;
/// txs to manage governance
pub mod governance;
pub mod pos;
/// transaction protocols made by validators
pub mod protocol;
/// wrapper txs with encrypted payloads
pub mod wrapper;

use std::collections::BTreeSet;
use std::fmt;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
pub use decrypted::*;
#[cfg(feature = "ferveo-tpke")]
pub use encrypted::EncryptionKey;
pub use protocol::UpdateDkgSessionKey;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use wrapper::*;

use crate::ledger::gas::VpsGas;
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::ibc::IbcEvent;
use crate::types::key::*;
use crate::types::storage;

/// Get the hash of a transaction
pub fn hash_tx(tx_bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(tx_bytes);
    Hash(*digest.as_ref())
}

/// Transaction application result
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct TxResult {
    /// Total gas used by the transaction (includes the gas used by VPs)
    pub gas_used: u64,
    /// Storage keys touched by the transaction
    pub changed_keys: BTreeSet<storage::Key>,
    /// The results of all the triggered validity predicates by the transaction
    pub vps_result: VpsResult,
    /// New established addresses created by the transaction
    pub initialized_accounts: Vec<Address>,
    /// Optional IBC event emitted by the transaction
    pub ibc_event: Option<IbcEvent>,
}

impl TxResult {
    /// Check if the tx has been accepted by all the VPs
    pub fn is_accepted(&self) -> bool {
        self.vps_result.rejected_vps.is_empty()
    }
}

/// Result of checking a transaction with validity predicates
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct VpsResult {
    /// The addresses whose VPs accepted the transaction
    pub accepted_vps: BTreeSet<Address>,
    /// The addresses whose VPs rejected the transaction
    pub rejected_vps: BTreeSet<Address>,
    /// The total gas used by all the VPs
    pub gas_used: VpsGas,
    /// Errors occurred in any of the VPs, if any
    pub errors: Vec<(Address, String)>,
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

/// A tx data type to update an account's validity predicate
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct UpdateVp {
    /// An address of the account
    pub addr: Address,
    /// The new VP code
    pub vp_code: Hash,
}

/// A tx data type to initialize a new established account
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct InitAccount {
    /// Public key to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_key: common::PublicKey,
    /// The VP code
    pub vp_code: Hash,
}

/// A tx data type to initialize a new validator account.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct InitValidator {
    /// Public key to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub account_key: common::PublicKey,
    /// A key to be used for signing blocks and votes on blocks.
    pub consensus_key: common::PublicKey,
    /// Public key used to sign protocol transactions
    pub protocol_key: common::PublicKey,
    /// Serialization of the public session key used in the DKG
    pub dkg_key: crate::types::key::dkg_session_keys::DkgPublicKey,
    /// The initial commission rate charged for delegation rewards
    pub commission_rate: Decimal,
    /// The maximum change allowed per epoch to the commission rate. This is
    /// immutable once set here.
    pub max_commission_rate_change: Decimal,
    /// The VP code for validator account
    pub validator_vp_code: Hash,
}

/// Module that includes helper functions for classifying
/// different types of transactions that the ledger
/// must support as well as conversion functions
/// between them.
pub mod tx_types {
    use std::convert::TryFrom;

    use thiserror;

    use super::*;
    use sha2::{Sha256, Digest};
    use crate::proto::{Tx, Code, Data, Section, Signature};
    #[cfg(feature = "ferveo-tpke")]
    use crate::types::transaction::protocol::ProtocolTx;

    /// Errors relating to decrypting a wrapper tx and its
    /// encrypted payload from a Tx type
    #[allow(missing_docs)]
    #[derive(thiserror::Error, Debug, PartialEq)]
    pub enum TxError {
        #[error("{0}")]
        Unsigned(String),
        #[error("{0}")]
        SigError(String),
        #[error("Failed to deserialize Tx: {0}")]
        Deserialization(String),
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Deserialize, Default)]
    pub struct RawHeader {
        pub code_hash: Hash,
        pub data_hash: Hash,
    }

    /// Struct that classifies that kind of Tx
    /// based on the contents of its data.
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Deserialize)]
    pub enum TxType {
        /// An ordinary tx
        Raw(RawHeader),
        /// A Tx that contains an encrypted raw tx
        Wrapper(WrapperTx),
        /// An attempted decryption of a wrapper tx
        Decrypted(DecryptedTx),
        /// Txs issued by validators as part of internal protocols
        #[cfg(feature = "ferveo-tpke")]
        Protocol(ProtocolTx),
    }

    impl TxType {
        pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
            hasher.update(self.try_to_vec().expect("unable to serialize header"));
            hasher
        }

        pub fn wrapper(&self) -> Option<WrapperTx> {
            if let Self::Wrapper(wrapper) = self {
                Some(wrapper.clone())
            } else {
                None
            }
        }
    }

    /// Determines the type of the input Tx
    ///
    /// If it is a raw Tx, signed or not, the Tx is
    /// returned unchanged inside an enum variant stating its type.
    ///
    /// If it is a decrypted tx, signing it adds no security so we
    /// extract the signed data without checking the signature (if it
    /// is signed) or return as is. Either way, it is returned in
    /// an enum variant stating its type.
    ///
    /// If it is a WrapperTx, we extract the signed data of
    /// the Tx and verify it is of the appropriate form. This means
    /// 1. The signed Tx data deserializes to a WrapperTx type
    /// 2. The wrapper tx is indeed signed
    /// 3. The signature is valid
    ///
    /// We modify the data of the WrapperTx to contain only the signed
    /// data if valid and return it wrapped in a enum variant
    /// indicating it is a wrapper. Otherwise, an error is
    /// returned indicating the signature was not valid
    pub fn process_tx(tx: &Tx) -> Result<&Tx, TxError> {
        match tx.header()
        {
            // verify signature and extract signed data
            TxType::Wrapper(wrapper) => {
                tx.verify_signature(&wrapper.pk, &tx.header_hash())
                    .map_err(|err| {
                        TxError::SigError(format!(
                            "WrapperTx signature verification failed: {}",
                            err
                        ))
                    })?;
                Ok(tx)
            }
            // verify signature and extract signed data
            #[cfg(feature = "ferveo-tpke")]
            TxType::Protocol(protocol) => {
                tx.verify_signature(&protocol.pk, &tx.header_hash())
                    .map_err(|err| {
                        TxError::SigError(format!(
                            "ProtocolTx signature verification failed: {}",
                            err
                        ))
                    })?;
                Ok(tx)
            }
            // we extract the signed data, but don't check the signature
            decrypted @ TxType::Decrypted(_) => Ok(tx),
            // return as is
            raw @ TxType::Raw(_) => Ok(tx),
        }
    }

    #[cfg(test)]
    mod test_process_tx {
        use super::*;
        use crate::types::address::nam;
        use crate::types::storage::Epoch;
        use crate::proto::{Code, Data};

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
            let mut outer_tx = Tx::new(TxType::Raw(RawHeader::default()));
            let code_sec = outer_tx.set_code(Code::new("wasm code".as_bytes().to_owned())).clone();
            match process_tx(&outer_tx).expect("Test failed").header() {
                TxType::Raw(raw) => assert_eq!(
                    Hash(code_sec.hash(&mut Sha256::new()).finalize_reset().into()),
                    raw.code_hash,
                ),
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies tx containing
        /// a raw tx with some data and returns an identical copy
        /// of the inner data
        #[test]
        fn test_process_tx_raw_tx_some_data() {
            let mut tx = Tx::new(TxType::Raw(RawHeader::default()));
            let code_sec = tx.set_code(Code::new("wasm code".as_bytes().to_owned())).clone();
            let data_sec = tx.set_data(Data::new("transaction data".as_bytes().to_owned())).clone();

            match process_tx(&tx).expect("Test failed").header() {
                TxType::Raw(raw) => {
                    assert_eq!(
                        Hash(code_sec.hash(&mut Sha256::new()).finalize_reset().into()),
                        raw.code_hash,
                    );
                    assert_eq!(
                        Hash(data_sec.hash(&mut Sha256::new()).finalize_reset().into()),
                        raw.data_hash,
                    );
                },
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies a raw tx with some
        /// signed data and returns an identical copy of the inner data
        #[test]
        fn test_process_tx_raw_tx_some_signed_data() {
            let mut tx = Tx::new(TxType::Raw(RawHeader::default()));
            let code_sec = tx.set_code(Code::new("wasm code".as_bytes().to_owned())).clone();
            let data_sec = tx.set_data(Data::new("transaction data".as_bytes().to_owned())).clone();
            tx.add_section(Section::Signature(Signature::new(tx.code_hash(), &gen_keypair())));
            tx.add_section(Section::Signature(Signature::new(tx.data_hash(), &gen_keypair())));

            match process_tx(&tx).expect("Test failed").header() {
                TxType::Raw(raw) => {
                    assert_eq!(
                        Hash(code_sec.hash(&mut Sha256::new()).finalize_reset().into()),
                        raw.code_hash,
                    );
                    assert_eq!(
                        Hash(data_sec.hash(&mut Sha256::new()).finalize_reset().into()),
                        raw.data_hash,
                    );
                },
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies a wrapper tx with some
        /// data and extracts the signed data.
        #[test]
        fn test_process_tx_wrapper_tx() {
            let keypair = gen_keypair();
            // the signed tx
            let mut tx = Tx::new(TxType::Wrapper(WrapperTx::new(
                Fee {
                    amount: 10.into(),
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                #[cfg(not(feature = "mainnet"))]
                None,
            )));
            tx.set_code(Code::new("wasm code".as_bytes().to_owned()));
            tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
            tx.add_section(Section::Signature(Signature::new(&tx.header_hash(), &keypair)));
            tx.encrypt(&Default::default());

            match process_tx(&tx.clone()).expect("Test failed").header() {
                TxType::Wrapper(wrapper) => {
                    tx.decrypt(<EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator())
                            .expect("Test failed");
                    //assert_eq!(tx, decrypted);
                }
                _ => panic!("Test failed: Expected Wrapper Tx"),
            }
        }

        /// Test that process_tx correctly returns an error on a wrapper tx
        /// with some unsigned data
        #[test]
        fn test_process_tx_wrapper_tx_unsigned() {
            let keypair = gen_keypair();
            // the signed tx
            let mut tx = Tx::new(TxType::Wrapper(
                WrapperTx::new(
                Fee {
                    amount: 10.into(),
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                #[cfg(not(feature = "mainnet"))]
                None,
            )
            ));
            tx.set_code(Code::new("wasm code".as_bytes().to_owned()));
            tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
            tx.encrypt(&Default::default());
            let result = process_tx(&tx).expect_err("Test failed");
            assert_matches!(result, TxError::SigError(_));
        }
    }

    /// Test that process_tx correctly identifies a DecryptedTx
    /// with some unsigned data and returns an identical copy
    #[test]
    fn test_process_tx_decrypted_unsigned() {
        let mut tx = Tx::new(TxType::Decrypted(DecryptedTx::Decrypted {
            code_hash: Hash::default(),
            data_hash: Hash::default(),
            header_hash: Hash::default(),
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
        let code_sec = tx.set_code(Code::new("transaction data".as_bytes().to_owned())).clone();
        let data_sec = tx.set_data(Data::new("transaction data".as_bytes().to_owned())).clone();
        match process_tx(&tx).expect("Test failed").header() {
            TxType::Decrypted(DecryptedTx::Decrypted {
                code_hash,
                data_hash,
                header_hash,
                #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: _,
            }) => {
                assert_eq!(code_hash, Hash(code_sec.hash(&mut Sha256::new()).finalize_reset().into()));
                assert_eq!(data_hash, Hash(data_sec.hash(&mut Sha256::new()).finalize_reset().into()));
            }
            _ => panic!("Test failed"),
        }
    }

    /// Test that process_tx correctly identifies a DecryptedTx
    /// with some signed data and extracts it without checking
    /// signature
    #[test]
    fn test_process_tx_decrypted_signed() {
        fn gen_keypair() -> common::SecretKey {
            use rand::prelude::ThreadRng;
            use rand::thread_rng;

            let mut rng: ThreadRng = thread_rng();
            ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
        }
        
        use crate::types::key::Signature as S;
        let mut decrypted = Tx::new(TxType::Decrypted(DecryptedTx::Decrypted {
            code_hash: Hash::default(),
            data_hash: Hash::default(),
            header_hash: Hash::default(),
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
        // Invalid signed data
        let ed_sig =
            ed25519::Signature::try_from_slice([0u8; 64].as_ref()).unwrap();
        let mut sig_sec = Signature::new(&decrypted.header_hash(), &gen_keypair());
        sig_sec.signature = common::Signature::try_from_sig(&ed_sig).unwrap();
        decrypted.add_section(Section::Signature(sig_sec));
        // create the tx with signed decrypted data
        let code_sec = decrypted.set_code(Code::new("transaction data".as_bytes().to_owned())).clone();
        let data_sec = decrypted.set_data(Data::new("transaction data".as_bytes().to_owned())).clone();
        match process_tx(&decrypted).expect("Test failed").header() {
            TxType::Decrypted(DecryptedTx::Decrypted {
                header_hash,
                code_hash,
                data_hash,
                #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: _,
            }) => {
                assert_eq!(code_hash, Hash(code_sec.hash(&mut Sha256::new()).finalize_reset().into()));
                assert_eq!(data_hash, Hash(data_sec.hash(&mut Sha256::new()).finalize_reset().into()));
            }
            _ => panic!("Test failed"),
        }
    }
}

pub use tx_types::*;
