/// Integration of Ferveo cryptographic primitives
/// to enable decrypting txs.
/// *Not wasm compatible*
#[cfg(feature = "ferveo-tpke")]
pub mod decrypted_tx {
    use std::convert::TryFrom;

    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ec::PairingEngine;
    use borsh::{BorshDeserialize, BorshSerialize};

    use crate::proto::Tx;
    use crate::types::transaction::WrapperTx;

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    #[allow(clippy::large_enum_variant)]
    /// Holds the result of attempting to decrypt
    /// a transaction and the data necessary for
    /// other validators to verify
    pub enum DecryptedTx {
        /// The decrypted payload
        Decrypted(Tx),
        /// The wrapper whose payload could not be decrypted
        Undecryptable(WrapperTx),
    }

    impl DecryptedTx {
        /// Convert the inner tx value to bytes
        pub fn to_bytes(&self) -> Vec<u8> {
            match self {
                DecryptedTx::Decrypted(tx) => tx.to_bytes(),
                DecryptedTx::Undecryptable(wrapper) => {
                    wrapper.try_to_vec().unwrap()
                }
            }
        }
    }

    /// Verify that if the encrypted payload was marked
    /// "undecryptable", we should not be able to decrypt
    /// it
    pub fn verify_not_decryptable(
        decrypted: &DecryptedTx,
        privkey: <EllipticCurve as PairingEngine>::G2Affine,
    ) -> bool {
        match decrypted {
            DecryptedTx::Decrypted(_) => false,
            DecryptedTx::Undecryptable(tx) => tx.decrypt(privkey).is_err(),
        }
    }

    impl From<DecryptedTx> for Tx {
        fn from(decrypted: DecryptedTx) -> Self {
            Tx::new(
                vec![],
                Some(
                    decrypted
                        .try_to_vec()
                        .expect("Encrypting transaction should not fail"),
                ),
            )
        }
    }

    impl TryFrom<&Tx> for DecryptedTx {
        type Error = crate::types::transaction::WrapperTxErr;

        fn try_from(tx: &Tx) -> Result<Self, Self::Error> {
            if let Some(data) = tx.data.as_ref() {
                <Self as BorshDeserialize>::deserialize(&mut data.as_ref())
                    .map_err(|_| {
                        crate::types::transaction::WrapperTxErr::InvalidTx
                    })
            } else {
                Err(crate::types::transaction::WrapperTxErr::InvalidTx)
            }
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
pub use decrypted_tx::*;
