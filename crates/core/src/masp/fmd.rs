//! Fuzzy message detection MASP primitives.

use std::collections::BTreeMap;
use std::io;

use borsh::schema::Definition;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use polyfuzzy::fmd2_compact::FlagCiphertexts as PolyfuzzyFlagCiphertext;
use serde::{Deserialize, Serialize};

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
}

/// FMD flag ciphertexts.
//#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FlagCiphertext {
    inner: PolyfuzzyFlagCiphertext,
}

impl AsRef<PolyfuzzyFlagCiphertext> for FlagCiphertext {
    fn as_ref(&self) -> &PolyfuzzyFlagCiphertext {
        &self.inner
    }
}

// TODO: use polyfuzzy PartialEq impl once available,
// and simply derive it in FlagCiphertext
impl PartialEq for FlagCiphertext {
    fn eq(&self, other: &Self) -> bool {
        let this = bincode::serialize(&self.inner).unwrap();
        let other = bincode::serialize(&other.inner).unwrap();

        this == other
    }
}

#[cfg(feature = "rand")]
impl Default for FlagCiphertext {
    // TODO: improve this default impl
    fn default() -> Self {
        use polyfuzzy::fmd2_compact::MultiFmd2CompactScheme;
        use polyfuzzy::{FmdKeyGen, MultiFmdScheme};
        use rand_core::OsRng;

        let mut scheme = MultiFmd2CompactScheme::new(
            parameters::GAMMA,
            parameters::THRESHOLD,
        );
        let (_sk, pk) = scheme.generate_keys(&mut OsRng);

        Self {
            inner: scheme.flag(&pk, &mut OsRng),
        }
    }
}

impl BorshSerialize for FlagCiphertext {
    #[inline]
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        // NOTE: serialize the size. borsh will only see an
        // opaque vector of bytes
        let size: u32 = bincode::serialized_size(&self.inner)
            .map_err(from_bincode_err)?
            .try_into()
            .map_err(io::Error::other)?;
        writer.write_all(&size.to_le_bytes())?;

        bincode::serialize_into(writer, &self.inner).map_err(from_bincode_err)
    }
}

impl BorshDeserialize for FlagCiphertext {
    #[inline]
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        // NOTE: skip the length of the fake vector of bytes
        reader.read_exact(&mut [0u8; 4])?;

        bincode::deserialize_from(reader).map_err(from_bincode_err)
    }
}

impl BorshSchema for FlagCiphertext {
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

#[allow(clippy::boxed_local)]
fn from_bincode_err(err: bincode::Error) -> io::Error {
    match *err {
        bincode::ErrorKind::Io(err) => err,
        other => io::Error::other(other),
    }
}
