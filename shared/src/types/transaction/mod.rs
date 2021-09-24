//! Types that are used in transactions.
pub mod wrapper;
pub mod decrypted;
mod encrypted;
pub mod pos;

use std::convert::TryFrom;
use std::fmt::{self, Display};

use borsh::{BorshDeserialize, BorshSerialize};
pub use decrypted::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use wrapper::*;

use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::key::ed25519::{PublicKey, SignedTxData, verify_tx_sig};


#[derive(
  Clone,
  Debug,
  Hash,
  PartialEq,
  BorshSerialize,
  BorshDeserialize,
  Serialize,
  Deserialize,
)]
pub struct Hash([u8; 32]);

impl Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

/// Get the hash of a transaction
pub fn hash_tx(tx_bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(tx_bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&digest);
    Hash(hash_bytes)
}

/// A tx data type to update an account's validity predicate
#[derive(
  Debug,
  Clone,
  PartialEq,
  BorshSerialize,
  BorshDeserialize,
  Serialize,
  Deserialize,
)]
pub struct UpdateVp {
    /// An address of the account
    pub addr: Address,
    /// The new VP code
    pub vp_code: Vec<u8>,
}

/// A tx data type to initialize a new established account
#[derive(
  Debug,
  Clone,
  PartialEq,
  BorshSerialize,
  BorshDeserialize,
  Serialize,
  Deserialize,
)]
pub struct InitAccount {
    /// Public key to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_key: PublicKey,
    /// The VP code
    pub vp_code: Vec<u8>,
}



#[cfg(feature = "ferveo-tpke")]
pub mod tx_types {
    use super::*;

    /// Struct that classifies that kind of Tx
    /// based on the contents of its data.
    #[derive(Clone, Debug, PartialEq)]
    pub enum TxType {
        /// An ordinary tx
        Raw(Tx),
        /// A Tx that contains an encrypted raw tx
        Wrapper(WrapperTx),
        /// An attempted decryption of a wrapper tx
        Decrypted(DecryptedTx),
    }

    impl From<TxType> for Tx {
        fn from(ty: TxType) -> Self {
            match ty {
                TxType::Raw(tx) => tx,
                TxType::Wrapper(tx) => Tx::new(vec![], tx.try_to_vec().ok()),
                TxType::Decrypted(tx) => Tx::new(vec![], tx.try_to_vec().ok()),
            }
        }
    }


    /// Used to determine the type of a Tx
    impl From<Tx> for TxType {
        fn from(tx: Tx) -> Self {
            if let Some(ref data) = tx.data {
                if let Ok(wrapper) =  <WrapperTx as BorshDeserialize>::deserialize(&mut data.as_ref()) {
                    TxType::Wrapper(wrapper)
                } else if let Ok(decrypted) = <DecryptedTx as BorshDeserialize>::deserialize(&mut data.as_ref()) {
                    TxType::Decrypted(decrypted)
                } else {
                    TxType::Raw(tx)
                }
            } else {
                TxType::Raw(tx)
            }
        }
    }

    impl<'a> TryFrom<&'a [u8]> for TxType {
        type Error = <Tx as TryFrom<&'a [u8]>>::Error;
        fn try_from(tx_bytes: &[u8]) -> Result<Self, Self::Error> {
            Ok(TxType::from(Tx::try_from(tx_bytes)?))
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
    pub fn process_tx(mut tx: Tx) -> Result<TxType, WrapperTxErr> {
        if let Some(Ok(SignedTxData {
                           data: Some(data),
                           ref sig,
                       })) = tx
            .data
            .as_ref()
            .map(|data| SignedTxData::try_from_slice(&data[..]))
        {
            match TxType::from(Tx{ code: vec![], data: Some(data), timestamp: tx.timestamp }) {
                // verify signature and extract signed data
                TxType::Wrapper(wrapper) => {
                    verify_tx_sig(&wrapper.pk, &tx, sig)
                        .map_err(|err| WrapperTxErr::SigError(err.to_string()))?;
                    Ok(TxType::Wrapper(wrapper))
                }
                // we extract the signed data, but don't check the signature
                decrypted @ TxType::Decrypted(_) => Ok(decrypted),
                // return as is
                TxType::Raw(_) => Ok(TxType::Raw(tx))
            }
        } else {
            match TxType::from(tx) {
                // we only accept signed wrappers
                TxType::Wrapper(_) => Err(WrapperTxErr::Unsigned),
                // return as is
                val @ _ => Ok(val),
            }
        }
    }

    #[cfg(test)]
    mod test_process_tx {
        use super::*;
        use crate::types::address::xan;
        use crate::types::storage::Epoch;

        /// Test that process_tx correctly identifies a raw tx with no
        /// data and returns an identical copy
        #[test]
        fn test_process_tx_raw_tx_no_data() {
            let tx = Tx::new("wasm code".as_bytes().to_owned(), None);

            match process_tx(tx.clone()).expect("Test failed") {
                TxType::Raw(raw) => assert_eq!(tx, raw),
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies a raw tx with some
        /// data and returns an identical copy
        #[test]
        fn test_process_tx_raw_tx_some_data() {
            let tx = Tx::new(
                "wasm code".as_bytes().to_owned(),
                Some("transaction data".as_bytes().to_owned()),
            );

            match process_tx(tx.clone()).expect("Test failed") {
                TxType::Raw(raw) => assert_eq!(tx, raw),
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies a raw tx with some
        /// signed data and returns an identical copy
        #[test]
        fn test_process_tx_raw_tx_some_signed_data() {
            let tx = Tx::new(
                "wasm code".as_bytes().to_owned(),
                Some("transaction data".as_bytes().to_owned()),
            )
                .sign(&gen_keypair());

            match process_tx(tx.clone()).expect("Test failed") {
                TxType::Raw(raw) => assert_eq!(tx, raw),
                _ => panic!("Test failed: Expected Raw Tx"),
            }
        }

        /// Test that process_tx correctly identifies a wrapper tx with some
        /// data and extracts the signed data.
        #[test]
        fn test_process_tx_wrapper_tx() {
            let keypair = gen_keypair();
            let tx = Tx::new(
                "wasm code".as_bytes().to_owned(),
                Some("transaction data".as_bytes().to_owned()),
            );
            // the signed tx
            let wrapper = WrapperTx::new(
                Fee {
                    amount: 10.into(),
                    token: xan(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx.clone(),
            )
            .sign(&keypair)
            .expect("Test failed");

            match process_tx(wrapper).expect("Test failed") {
                TxType::Wrapper(wrapper) => {
                    let decrypted =
                        wrapper.decrypt(<EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator())
                            .expect("Test failed");
                    assert_eq!(tx, decrypted);
                }
                _ => panic!("Test failed: Expected Wrapper Tx"),
            }
        }

        /// Test that process_tx correctly returns an error on a wrapper tx
        /// with some unsigned data
        #[test]
        fn test_process_tx_wrapper_tx_unsigned() {
            let keypair = gen_keypair();
            let tx = Tx::new(
                "wasm code".as_bytes().to_owned(),
                Some("transaction data".as_bytes().to_owned()),
            );
            // the signed tx
            let wrapper = WrapperTx::new(
                Fee {
                    amount: 10.into(),
                    token: xan(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx,
            );

            let tx = Tx::new(
                vec![],
                Some(wrapper.try_to_vec().expect("Test failed")),
            );
            let result = process_tx(tx).expect_err("Test failed");
            assert_eq!(result, WrapperTxErr::Unsigned);
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
pub use tx_types::*;