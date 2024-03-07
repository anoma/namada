use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
pub use linkme::distributed_slice;

/// Predicate that checks if an arbitrary byte array deserializes as some type
/// `T` erased inside of the callback. If the serialization is correct, the full
/// path of `T` is returned as a string (via [`std::any::type_name`]).
type CbFromByteArrayToTypeName = fn(Vec<u8>) -> Option<String>;

lazy_static! {
    pub static ref TYPE_DESERIALIZERS: Mutex<HashMap<[u8; 32], CbFromByteArrayToTypeName>> =
        Mutex::new(HashMap::new());
}

#[distributed_slice]
pub static REGISTER_DESERIALIZERS: [fn()];

pub trait TypeHash {
    const HASH: [u8; 32];
}

/// Calls all of the registered callbacks which place type
/// deserializers into [`TYPE_DESERIALIZERS`].
pub fn initialize_deserializers() {
    for func in REGISTER_DESERIALIZERS {
        func();
    }
}
