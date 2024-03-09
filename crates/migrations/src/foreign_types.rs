use borsh::BorshDeserialize;
use namada_macros::derive_typehash;

use crate::REGISTER_DESERIALIZERS;

const HASHU8: [u8; 32] = derive_typehash!(Vec::<u8>);
pub const HASHVECSTR: [u8; 32] = derive_typehash!(Vec::<String>);

impl crate::TypeHash for Vec<u8> {
    const HASH: [u8; 32] = HASHU8;
}

impl crate::TypeHash for Vec<String> {
    const HASH: [u8; 32] = HASHVECSTR;
}

#[linkme::distributed_slice(REGISTER_DESERIALIZERS)]
static BYTES: fn() = || {
    crate::register_deserializer(HASHU8, |bytes| {
        Vec::<u8>::try_from_slice(&bytes)
            .map(|val| format!("{:?}", val))
            .ok()
    });
};

#[linkme::distributed_slice(REGISTER_DESERIALIZERS)]
static STRINGS: fn() = || {
    crate::register_deserializer(HASHVECSTR, |bytes| {
        Vec::<u8>::try_from_slice(&bytes)
            .map(|val| format!("{:?}", val))
            .ok()
    });
};
