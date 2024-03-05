#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
pub use linkme::distributed_slice;

lazy_static! {
    pub static ref TYPE_DESERIALIZERS: Mutex<HashMap<[u8; 32], fn(Vec<u8>) -> bool>> =
        Mutex::new(HashMap::new());
}

#[distributed_slice]
pub static REGISTER_DESERIALIZERS: [fn()];

pub trait TypeHash {
    const HASH: [u8; 32];
}
