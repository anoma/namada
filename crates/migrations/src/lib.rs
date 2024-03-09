use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use lazy_static::lazy_static;
pub use linkme::distributed_slice;

/// Predicate that checks if an arbitrary byte array deserializes as some type
/// `T` erased inside of the callback. If the serialization is correct, the full
/// path of `T` is returned as a string (via [`std::any::type_name`]).
pub type CbFromByteArrayToTypeName = fn(Vec<u8>) -> Option<String>;

lazy_static! {
    static ref TYPE_DESERIALIZERS: Mutex<HashMap<[u8; 32], CbFromByteArrayToTypeName>> =
        Mutex::new(HashMap::new());
}

#[distributed_slice]
pub static REGISTER_DESERIALIZERS: [fn()];

pub trait TypeHash {
    const HASH: [u8; 32];
}

/// Calls all of the registered callbacks which place type
/// deserializers into [`TYPE_DESERIALIZERS`].
fn initialize_deserializers() {
    static INIT_GUARD: OnceLock<()> = OnceLock::new();
    INIT_GUARD.get_or_init(|| {
        for func in REGISTER_DESERIALIZERS {
            func();
        }
    });
}

/// Register a serializer to the global list.
pub fn register_deserializer(
    type_hash: [u8; 32],
    func: CbFromByteArrayToTypeName,
) {
    let mut locked = TYPE_DESERIALIZERS.lock().unwrap();
    locked.insert(type_hash, func);
}

/// Retrieve a deserializer for the provided type.
pub fn get_deserializer(
    type_hash: &[u8; 32],
) -> Option<CbFromByteArrayToTypeName> {
    initialize_deserializers();
    let locked = TYPE_DESERIALIZERS.lock().unwrap();
    locked.get(type_hash).cloned()
}
