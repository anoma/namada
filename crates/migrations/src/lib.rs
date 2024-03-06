#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
#[cfg(feature = "migrations")]
pub use linkme::distributed_slice;
/// Predicate that checks if an arbitrary byte array deserializes as some type `T`
/// erased inside of the callback. If the serialization is correct, the full path of `T`
/// is returned as a string (via [`std::any::type_name`]).
type CbFromByteArrayToTypeName = fn(Vec<u8>) -> Option<String>;

lazy_static! {
    pub static ref TYPE_DESERIALIZERS: Mutex<HashMap<[u8; 32], CbFromByteArrayToTypeName>> =
        Mutex::new(HashMap::new());
}

#[cfg(feature = "migrations")]
#[distributed_slice]
pub static REGISTER_DESERIALIZERS: [fn()];

pub trait TypeHash {
    const HASH: [u8; 32];
}

/// Calls all of the regeistered callbacks which place type
/// deserializes into [`TYPE_DESERIALIZERS`].
#[cfg(feature = "migrations")]
pub fn initialize_deserializers() {
    for func in REGISTER_DESERIALIZERS {
        func();
    }
}
