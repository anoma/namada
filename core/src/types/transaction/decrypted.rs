pub use ark_bls12_381::Bls12_381 as EllipticCurve;

/// Integration of Ferveo cryptographic primitives
/// to enable decrypting txs.
/// *Not wasm compatible*
pub mod decrypted_tx {
    #[cfg(feature = "ferveo-tpke")]
    use ark_ec::PairingEngine;
    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use sha2::{Digest, Sha256};

    #[derive(
        Clone,
        Debug,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        serde::Serialize,
        serde::Deserialize,
    )]
    #[allow(clippy::large_enum_variant)]
    /// Holds the result of attempting to decrypt
    /// a transaction and the data necessary for
    /// other validators to verify
    pub enum DecryptedTx {
        /// The decrypted payload
        Decrypted,
        /// The wrapper whose payload could not be decrypted
        Undecryptable,
    }

    impl DecryptedTx {
        /// Produce a SHA-256 hash of this header
        pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
            hasher.update(
                self.try_to_vec().expect("unable to serialize decrypted tx"),
            );
            hasher
        }
    }

    /// Verify that if the encrypted payload was marked
    /// "undecryptable", we should not be able to decrypt
    /// it
    #[cfg(feature = "ferveo-tpke")]
    pub fn verify_decrypted_correctly(
        decrypted: &DecryptedTx,
        mut otx: crate::proto::Tx,
        privkey: <super::EllipticCurve as PairingEngine>::G2Affine,
    ) -> bool {
        match decrypted {
            DecryptedTx::Decrypted { .. } => true,
            DecryptedTx::Undecryptable => otx.decrypt(privkey).is_err(),
        }
    }
}

pub use decrypted_tx::*;
