//! Fuzzy message detection scheme related functionality.

// TODO: we shouldn't use edwards points, we have to use ristretto points

use std::num::NonZeroUsize;

use generic_ec::traits::Reduce;
use hd_wallet::curves::ed25519::{Point, Scalar, SecretScalar};
use hd_wallet::curves::Ed25519;
use hd_wallet::NonHardenedIndex;
use masp_primitives::sapling::{Diversifier, ViewingKey};
use zeroize::{Zeroize, Zeroizing};

use crate::DerivationPath;

const FMD_SCHEME_SEED_PREFIX: &str = "Namada_FMDScheme";

const FMD_SCHEME_CHAIN_CODE: [u8; 32] = *b"Namada_FMDSchemeNamada_FMDScheme";

/// Derive a fuzzy message detection seed child key.
trait DeriveFmdSeedChildKey: Sized {
    /// Derive a new child key with the given index.
    fn derive_child_key_with_index(
        &self,
        child_index: NonHardenedIndex,
    ) -> Self;

    /// Derive a new child key.
    fn derive_seed_child_key(&self) -> Self {
        // The derivation path index used to derive new seed child keys (0)
        const CHILD_INDEX: NonHardenedIndex = NonHardenedIndex::MIN;

        self.derive_child_key_with_index(CHILD_INDEX)
    }
}

/// The seed key pair used when deriving [`fmd::SecretKey`] instances.
#[derive(Debug)]
#[repr(transparent)]
pub struct ExtendedSeedKeyPair(hd_wallet::ExtendedKeyPair<Ed25519>);

impl DeriveFmdSeedChildKey for hd_wallet::ExtendedKeyPair<Ed25519> {
    fn derive_child_key_with_index(&self, index: NonHardenedIndex) -> Self {
        hd_wallet::edwards::derive_child_key_pair(self, *index)
    }
}

impl ExtendedSeedKeyPair {
    /// Derive a seed key pair from the given inputs.
    pub fn derive(
        viewing_key: &ViewingKey,
        diversifier: &Diversifier,
        spending_key_derivation_path: &DerivationPath,
    ) -> Self {
        use sha2::Digest;

        let hash = Zeroizing::new({
            let mut hasher = sha2::Sha256::default();
            hasher.update(FMD_SCHEME_SEED_PREFIX);
            hasher.update(viewing_key.to_bytes());
            hasher.update(diversifier.0);
            hasher.finalize().into()
        });

        let seed_key = hd_wallet::ExtendedSecretKey::<Ed25519> {
            secret_key: generic_ec_scalar_from_bytes(hash),
            chain_code: FMD_SCHEME_CHAIN_CODE,
        }
        .into();

        Self(
            spending_key_derivation_path
                .path()
                .iter()
                .copied()
                .map(|child| {
                    NonHardenedIndex::try_from(child.to_u32())
                        .expect("Child index should be non-hardened")
                })
                .fold(seed_key, |seed_key, child_index| {
                    seed_key.derive_child_key_with_index(child_index)
                }),
        )
    }

    /// Derive an [`fmd::SecretKey`] with `gamma` sub-keys from the seed.
    pub fn into_fmd_secret_key(self, gamma: NonZeroUsize) -> fmd::SecretKey {
        let mut seed = self.0;

        fmd::SecretKey::from_bytes_mod_order((0..gamma.get()).map(|_| {
            seed = seed.derive_seed_child_key();
            *generic_ec_scalar_to_bytes(&seed.secret_key().secret_key)
        }))
    }

    /// Get the public counterpart of the seed.
    pub fn to_public(&self) -> ExtendedSeedPublicKey {
        ExtendedSeedPublicKey(*self.0.public_key())
    }
}

/// The seed public key used when deriving [`fmd::PublicKey`] instances.
#[derive(Debug)]
#[repr(transparent)]
pub struct ExtendedSeedPublicKey(hd_wallet::ExtendedPublicKey<Ed25519>);

impl DeriveFmdSeedChildKey for hd_wallet::ExtendedPublicKey<Ed25519> {
    fn derive_child_key_with_index(&self, index: NonHardenedIndex) -> Self {
        hd_wallet::edwards::derive_child_public_key(self, index)
    }
}

impl From<SeedPublicKey> for ExtendedSeedPublicKey {
    fn from(seed: SeedPublicKey) -> ExtendedSeedPublicKey {
        seed.extend()
    }
}

impl ExtendedSeedPublicKey {
    /// Return a trimmed down representatio of this [`ExtendedSeedPublicKey`].
    pub fn trim(&self) -> SeedPublicKey {
        SeedPublicKey(self.0.public_key)
    }

    /// Derive an [`fmd::PublicKey`] with `gamma` sub-keys from the seed.
    pub fn into_fmd_public_key(self, gamma: NonZeroUsize) -> fmd::PublicKey {
        let mut seed = self.0;

        fmd::PublicKey::from_bytes((0..gamma.get()).map(|_| {
            seed = seed.derive_seed_child_key();
            generic_ec_point_to_bytes(&seed.public_key)
        }))
        .expect("Public key conversion should be infallible at this stage")
    }
}

/// Trimmed down [`ExtendedSeedPublicKey`].
#[derive(Debug)]
#[repr(transparent)]
pub struct SeedPublicKey(Point);

impl SeedPublicKey {
    /// Parse a [`SeedPublicKey`] from the given data.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let point = generic_ec_point_from_bytes(bytes)?;
        Some(Self(point))
    }

    /// Return a byte representation of this [`SeedPublicKey`].
    pub fn to_bytes(&self) -> [u8; 32] {
        generic_ec_point_to_bytes(&self.0)
    }

    /// Extend this [`SeedPublicKey`].
    pub fn extend(self) -> ExtendedSeedPublicKey {
        ExtendedSeedPublicKey(hd_wallet::ExtendedPublicKey {
            public_key: self.0,
            chain_code: FMD_SCHEME_CHAIN_CODE,
        })
    }
}

fn generic_ec_point_from_bytes(bytes: [u8; 32]) -> Option<Point> {
    Point::from_bytes(bytes).ok()
}

fn generic_ec_point_to_bytes(point: &Point) -> [u8; 32] {
    let mut raw_bytes = [0u8; 32];
    let encoded = point.to_bytes(true);
    raw_bytes.copy_from_slice(encoded.as_bytes());
    raw_bytes
}

fn generic_ec_scalar_from_bytes(bytes: Zeroizing<[u8; 32]>) -> SecretScalar {
    SecretScalar::new(&mut Scalar::from_le_array_mod_order(&bytes))
}

fn generic_ec_scalar_to_bytes(
    secret_scalar: &SecretScalar,
) -> Zeroizing<[u8; 32]> {
    let mut raw_bytes = Zeroizing::new([0u8; 32]);
    let mut encoded_generic_ec = secret_scalar.as_ref().to_le_bytes();
    raw_bytes.copy_from_slice(encoded_generic_ec.as_bytes());
    encoded_generic_ec.as_mut().zeroize();
    raw_bytes
}

#[cfg(test)]
mod fmd_scheme_tests {
    use curve25519_dalek::scalar::Scalar as DalekScalar;

    use super::*;

    #[test]
    fn test_raw_scalar_compatible_with_dalek() {
        let scalar =
            generic_ec_scalar_from_bytes(Zeroizing::new([0xef_u8; 32]));
        let encoded = generic_ec_scalar_to_bytes(&scalar);
        let decoded = DalekScalar::from_bytes_mod_order(*encoded);
        let re_encoded = Zeroizing::new(decoded.to_bytes());
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_raw_point_compatible_with_dalek() {
        // TODO
    }
}
