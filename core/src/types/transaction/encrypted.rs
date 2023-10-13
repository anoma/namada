/// Integration of Ferveo cryptographic primitives
/// to enable encrypted txs.
/// *Not wasm compatible*
#[cfg(feature = "ferveo-tpke")]
pub mod encrypted_tx {
    use std::io::{Error, ErrorKind, Read, Write};

    use ark_ec::PairingEngine;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use borsh::{BorshDeserialize, BorshSerialize};

    use crate::types::transaction::{AffineCurve, EllipticCurve};
    /// The first group in our elliptic curve bilinear pairing
    pub type G1 = <EllipticCurve as PairingEngine>::G1Affine;
    /// An encryption key for txs
    #[derive(Debug, Clone, PartialEq)]
    pub struct EncryptionKey(pub G1);

    impl Default for EncryptionKey {
        fn default() -> Self {
            Self(G1::prime_subgroup_generator())
        }
    }

    impl borsh::ser::BorshSerialize for EncryptionKey {
        fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let mut buf = Vec::<u8>::new();
            CanonicalSerialize::serialize(&self.0, &mut buf)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            BorshSerialize::serialize(&buf, writer)
        }
    }

    impl borsh::de::BorshDeserialize for EncryptionKey {
        fn deserialize_reader<R: Read>(
            reader: &mut R,
        ) -> std::io::Result<Self> {
            let key: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            Ok(EncryptionKey(
                CanonicalDeserialize::deserialize(&*key)
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?,
            ))
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
pub use encrypted_tx::*;
