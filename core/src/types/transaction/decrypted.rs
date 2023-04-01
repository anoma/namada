pub use ark_bls12_381::Bls12_381 as EllipticCurve;

/// Integration of Ferveo cryptographic primitives
/// to enable decrypting txs.
/// *Not wasm compatible*
pub mod decrypted_tx {
    #[cfg(feature = "ferveo-tpke")]
    use ark_ec::PairingEngine;
    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

    use super::EllipticCurve;
    use crate::proto::Tx;
    #[cfg(feature = "ferveo-tpke")]
    use crate::types::transaction::encrypted::EncryptedTx;
    use crate::types::transaction::{Hash, TxType, WrapperTx};
    use crate::proto::InnerTx;
    use crate::proto::{SignedTxData, SignedOuterTxData};

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, serde::Serialize, serde::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    /// Holds the result of attempting to decrypt
    /// a transaction and the data necessary for
    /// other validators to verify
    pub enum DecryptedTx {
        /// The decrypted payload
        Decrypted {
            /// Inner tx.
            // For some reason, we get `warning: fields `tx` and
            // `has_valid_pow` are never read` even though they are being used!
            #[allow(dead_code)]
            tx: InnerTx,
            #[cfg(not(feature = "mainnet"))]
            /// A PoW solution can be used to allow zero-fee testnet
            /// transactions.
            /// This is true when the wrapper of this tx contains a valid
            /// `testnet_pow::Solution`.
            // For some reason, we get `warning: fields `tx` and
            // `has_valid_pow` are never read` even though they are being used!
            #[allow(dead_code)]
            has_valid_pow: bool,
        },
        /// The wrapper whose payload could not be decrypted
        Undecryptable(WrapperTx),
    }

    impl DecryptedTx {
        /// Convert the inner tx value to bytes
        pub fn to_bytes(&self) -> Vec<u8> {
            match self {
                DecryptedTx::Decrypted {
                    tx,
                    #[cfg(not(feature = "mainnet"))]
                        has_valid_pow: _,
                } => tx.to_bytes(),
                DecryptedTx::Undecryptable(wrapper) => {
                    wrapper.try_to_vec().unwrap()
                }
            }
        }

        /// Return the hash used as a commitment to the tx's contents in the
        /// wrapper tx that includes this tx as an encrypted payload.
        pub fn hash_commitment(&self) -> Hash {
            match self {
                DecryptedTx::Decrypted {
                    tx,
                    #[cfg(not(feature = "mainnet"))]
                        has_valid_pow: _,
                } => Hash(tx.partial_hash()),
                DecryptedTx::Undecryptable(wrapper) => wrapper.tx_hash.clone(),
            }
        }
    }

    /// Verify that if the encrypted payload was marked
    /// "undecryptable", we should not be able to decrypt
    /// it
    #[cfg(feature = "ferveo-tpke")]
    pub fn verify_decrypted_correctly(
        decrypted: &DecryptedTx,
        privkey: <EllipticCurve as PairingEngine>::G2Affine,
        inner_tx: Option<InnerTx>,
    ) -> bool {
        match decrypted {
            // A tx is decryptable if it contains the literal code inside it
            DecryptedTx::Decrypted { .. } => true,
            // A tx is undecryptable if its inner_tx decrypts incorrectly
            DecryptedTx::Undecryptable(tx) if inner_tx.is_some() => {
                tx.decrypt(privkey, inner_tx.unwrap()).is_err()
            }
            // A tx is undecryptable if the inner_tx is not present
            DecryptedTx::Undecryptable(_) => true,
        }
    }

    impl From<DecryptedTx> for Tx {
        fn from(decrypted: DecryptedTx) -> Self {
            Tx::new(
                vec![],
                Some(
                    SignedOuterTxData {
                        data: Some(
                            TxType::Decrypted(decrypted)
                        ),
                        sig: None,
                    }
                ),
            )
        }
    }
}

pub use decrypted_tx::*;
