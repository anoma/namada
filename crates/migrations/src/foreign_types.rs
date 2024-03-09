use borsh::BorshDeserialize;
use namada_macros::derive_typehash;

use crate::REGISTER_DESERIALIZERS;

// TODO: change naming bc HASHu8 and HASHBYTE conflicts

const HASHU8: [u8; 32] = derive_typehash!(Vec::<u8>);
pub const HASHVECSTR: [u8; 32] = derive_typehash!(Vec::<String>);
pub const HASHBYTE: [u8; 32] = derive_typehash!(u64);

impl crate::TypeHash for Vec<u8> {
    const HASH: [u8; 32] = HASHU8;
}

impl crate::TypeHash for Vec<String> {
    const HASH: [u8; 32] = HASHVECSTR;
}

impl crate::TypeHash for u64 {
    const HASH: [u8; 32] = HASHBYTE;
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
        Vec::<String>::try_from_slice(&bytes)
            .map(|val| format!("{:?}", val))
            .ok()
    });
};

#[linkme::distributed_slice(REGISTER_DESERIALIZERS)]
static BYTE: fn() = || {
    crate::register_deserializer(HASHBYTE, |bytes| {
        u64::try_from_slice(&bytes)
            .map(|val| format!("{:?}", val))
            .ok()
    });
};
