pub use ark_bls12_381::Bls12_381 as EllipticCurve;

/// Integration of Ferveo cryptographic primitives to enable decrypting txs.
/// *Not wasm compatible*
pub mod decrypted_tx {
    use namada_core::borsh::{
        BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
    };
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
            hasher.update(self.serialize_to_vec());
            hasher
        }
    }
}

pub use decrypted_tx::*;
