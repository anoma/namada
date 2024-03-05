#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
#[cfg(feature = "migrations")]
pub use linkme::distributed_slice;

lazy_static! {
    pub static ref TYPE_DESERIALIZERS: Mutex<HashMap<[u8; 32], fn(Vec<u8>) -> Option<String>>> =
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