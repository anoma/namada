//! Fuzzy message detection MASP primitives.

use std::collections::BTreeMap;
use std::io;

use borsh::schema::Definition;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use masp_primitives::sapling::SaplingIvk;
use polyfuzzy::fmd2_compact::{
    CompactSecretKey as PolyfuzzyCompactSecretKey,
    FlagCiphertexts as PolyfuzzyFlagCiphertext,
};
#[cfg(feature = "rand")]
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, IntoXof, KangarooTwelve, Xof};

#[allow(dead_code)]
pub mod parameters {
    //! Fuzzy message detection parameters used by Namada.

    /// Gamma parameter.
    ///
    /// This parameter defines the minimum false positive rate,
    /// which is given by `2^-GAMMA`.
    pub const GAMMA: usize = 20;

    /// Threshold parameter.
    ///
    /// This parameter affects the length of payment addresses.
    /// The raw data of payment addresses will contain `THRESHOLD + 1`
    /// extra compressed curve points (32 bytes each), to allow
    /// flagging note ownership to their respective owner.
    pub const THRESHOLD: usize = 1;

    /// Evaluate whether the given compressed bit ciphertext is valid.
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn valid_compressed_bit_ciphertext(bits: &[u8]) -> bool {
        // Number of bytes required to represent a polyfuzzy bit ciphertext
        // with a `GAMMA` parameter.
        const COMPRESSED_BIT_CIPHERTEXT_LEN: usize =
            GAMMA / 8 + (GAMMA % 8 != 0) as usize;

        // Mask with the padding bits that should be set to 0 (or,
        // in other words, unset) in the bit ciphertext produced
        // by polyfuzzy. Since the library doesn't set any of the
        // upper bits, if they have been set it means someone has
        // tampered with the flag ciphertext.
        const UNSET_BITS_MASK: u8 = 0xff << (GAMMA % 8);

        bits.len() == COMPRESSED_BIT_CIPHERTEXT_LEN
            && bits[COMPRESSED_BIT_CIPHERTEXT_LEN - 1] & UNSET_BITS_MASK == 0
    }
}

/// FMD secret key.
//#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SecretKey {
    inner: PolyfuzzyCompactSecretKey,
}

impl SecretKey {
    /// Hash personalization string used when deriving a [`SecretKey`]
    /// from a [`SaplingIvk`].
    const KDF_PERSONALIZATION: &str = "Namada FMD Secret Key";
}

impl From<&SaplingIvk> for SecretKey {
    fn from(ivk: &SaplingIvk) -> Self {
        let mut xof_stream = {
            let mut hasher = KangarooTwelve::new(Self::KDF_PERSONALIZATION);

            // derive key material from input viewing key
            hasher.update(&ivk.to_repr());

            hasher.into_xof()
        };

        Self {
            inner: PolyfuzzyCompactSecretKey::derive_from_xof_stream(
                parameters::THRESHOLD,
                |buf| {
                    xof_stream.squeeze(buf);
                },
            ),
        }
    }
}

impl From<SaplingIvk> for SecretKey {
    #[inline]
    fn from(ivk: SaplingIvk) -> Self {
        (&ivk).into()
    }
}

/// FMD flag ciphertexts.
//#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct FlagCiphertext {
    inner: PolyfuzzyFlagCiphertext,
}

impl FlagCiphertext {
    /// Check if the flag ciphertext is valid, according to Namada's consensus
    /// rules.
    #[inline]
    pub fn is_valid(&self) -> bool {
        parameters::valid_compressed_bit_ciphertext(self.inner.bits())
    }

    /// Generate a random [`FlagCiphertext`].
    #[cfg(feature = "rand")]
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self {
            inner: PolyfuzzyFlagCiphertext::random(rng, parameters::GAMMA),
        }
    }
}

impl From<PolyfuzzyFlagCiphertext> for FlagCiphertext {
    fn from(flag_ciphertext: PolyfuzzyFlagCiphertext) -> Self {
        Self {
            inner: flag_ciphertext,
        }
    }
}

impl From<FlagCiphertext> for PolyfuzzyFlagCiphertext {
    fn from(flag_ciphertext: FlagCiphertext) -> Self {
        flag_ciphertext.inner
    }
}

impl AsRef<PolyfuzzyFlagCiphertext> for FlagCiphertext {
    fn as_ref(&self) -> &PolyfuzzyFlagCiphertext {
        &self.inner
    }
}

#[cfg(feature = "default-flag-ciphertext")]
impl Default for FlagCiphertext {
    #[inline]
    fn default() -> Self {
        Self::random(&mut rand_core::OsRng)
    }
}

mod borsh_impls {
    use super::*;

    macro_rules! borsh_derive_from_bincode {
        ($($type:ty),+) => {
            $(
                impl BorshSerialize for $type {
                    #[inline]
                    fn serialize<W: io::Write>(
                        &self,
                        writer: &mut W,
                    ) -> io::Result<()> {
                        bincode_as_borsh_serialize(writer, self)
                    }
                }

                impl BorshDeserialize for $type {
                    #[inline]
                    fn deserialize_reader<R: io::Read>(
                        reader: &mut R,
                    ) -> io::Result<Self> {
                        bincode_as_borsh_deserialize(reader)
                    }
                }

                impl BorshSchema for $type {
                    fn add_definitions_recursively(
                        definitions: &mut BTreeMap<String, Definition>,
                    ) {
                        let def = {
                            <Vec<u8>>::add_definitions_recursively(definitions);
                            definitions.get(&<Vec<u8>>::declaration()).unwrap().clone()
                        };

                        definitions.insert(Self::declaration(), def);
                    }

                    fn declaration() -> String {
                        std::any::type_name::<Self>().into()
                    }
                }
            )+
        };
    }

    fn bincode_as_borsh_serialize<W: io::Write, T: Serialize>(
        writer: &mut W,
        data: &T,
    ) -> io::Result<()> {
        // NOTE: serialize the size. borsh will only see an
        // opaque vector of bytes
        let size: u32 = bincode::serialized_size(data)
            .map_err(from_bincode_err)?
            .try_into()
            .map_err(io::Error::other)?;
        writer.write_all(&size.to_le_bytes())?;

        bincode::serialize_into(writer, data).map_err(from_bincode_err)
    }

    fn bincode_as_borsh_deserialize<
        R: io::Read,
        T: for<'de> Deserialize<'de>,
    >(
        reader: &mut R,
    ) -> io::Result<T> {
        // NOTE: skip the length of the fake vector of bytes
        reader.read_exact(&mut [0u8; 4])?;

        bincode::deserialize_from(reader).map_err(from_bincode_err)
    }

    #[allow(clippy::boxed_local)]
    fn from_bincode_err(err: bincode::Error) -> io::Error {
        match *err {
            bincode::ErrorKind::Io(err) => err,
            other => io::Error::other(other),
        }
    }

    borsh_derive_from_bincode!(FlagCiphertext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "default-flag-ciphertext")]
    fn test_flag_ciphertext_borsh_roundtrip() {
        use crate::borsh::BorshSerializeExt;

        // run this test a couple of times
        for _ in 0..5 {
            let random_flag_ciphertext = FlagCiphertext::default();

            let serialized = random_flag_ciphertext.serialize_to_vec();
            let deserialized =
                FlagCiphertext::try_from_slice(&serialized).unwrap();

            assert_eq!(random_flag_ciphertext, deserialized);
        }
    }

    #[test]
    #[cfg(feature = "default-flag-ciphertext")]
    fn test_random_flag_ciphertext_is_valid() {
        // run this test a couple of times
        for _ in 0..5 {
            let random_flag_ciphertext = FlagCiphertext::default();
            assert!(random_flag_ciphertext.is_valid());
        }
    }

    #[test]
    fn test_flag_ciphertext_bits_validation() {
        let mut bits: Vec<u8> = {
            let mut bits = [false; parameters::GAMMA];

            // set some random bits
            bits[0] = true;
            bits[5] = true;
            bits[10] = true;
            bits[parameters::GAMMA - 1] = true;
            bits[parameters::GAMMA - 2] = true;
            bits[parameters::GAMMA - 3] = true;

            // compress the bits
            bits.chunks(8)
                .map(|bits| {
                    bits.iter().copied().enumerate().fold(
                        0u8,
                        |accum_byte, (i, bit)| {
                            #[allow(clippy::cast_lossless)]
                            {
                                accum_byte ^ ((bit as u8) << i)
                            }
                        },
                    )
                })
                .collect()
        };

        // check validation of a proper flag ciphertext
        assert!(parameters::valid_compressed_bit_ciphertext(&bits));

        let all_bits_unset = (0..8 - (parameters::GAMMA % 8))
            .map(|i| bits[bits.len() - 1] & (0b1000_0000_u8 >> i))
            .all(|bit| bit == 0);

        assert!(all_bits_unset, "Invalid bit ciphertext");

        if parameters::GAMMA % 8 != 0 {
            let n = bits.len();
            bits[n - 1] |= 0b1000_0000_u8;

            // check validation of a flag ciphertext with padding bits
            // that has been tampered with
            assert!(!parameters::valid_compressed_bit_ciphertext(&bits));

            let some_bit_unset = (0..8 - (parameters::GAMMA % 8))
                .map(|i| bits[bits.len() - 1] & (0b1000_0000_u8 >> i))
                .any(|bit| bit != 0);

            assert!(some_bit_unset, "Valid bit ciphertext");
        }
    }
}
