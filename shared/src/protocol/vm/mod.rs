use std::ffi::c_void;
use std::marker::PhantomData;

use wasmparser::{Validator, WasmFeatures};

pub mod host_env;
pub mod memory;
pub mod prefix_iter;
pub mod write_log;

/// This is used to attach the Ledger's host structures to wasm environment,
/// which is used for implementing some host calls. It wraps an immutable
/// reference, so the access is thread-safe, but because of the unsafe
/// reference conversion, care must be taken that while this reference is
/// borrowed, no other process can modify it.
pub struct EnvHostWrapper<T>(*const c_void, PhantomData<T>);
unsafe impl<T> Send for EnvHostWrapper<T> {}
unsafe impl<T> Sync for EnvHostWrapper<T> {}

// Have to manually implement [`Clone`], because the derived [`Clone`] for
// [`PhantomData<T>`] puts the bound on [`T: Clone`]. Relevant issue: <https://github.com/rust-lang/rust/issues/26925>
impl<T> Clone for EnvHostWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T> EnvHostWrapper<T> {
    /// Wrap a reference for VM environment.
    ///
    /// # Safety
    ///
    /// Because this is unsafe, care must be taken that while this reference
    /// is borrowed, no other process can modify it.
    pub unsafe fn new(host_structure: *const c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// Get a reference from VM environment.
    ///
    /// # Safety
    ///
    /// Because this is unsafe, care must be taken that while this reference
    /// is borrowed, no other process can modify it.
    #[allow(dead_code)]
    pub unsafe fn get(&self) -> *const T {
        self.0 as *const T
    }
}

/// This is used to attach the Ledger's host structures to wasm environment,
/// which is used for implementing some host calls. Because it's mutable, it's
/// not thread-safe. Also, care must be taken that while this reference is
/// borrowed, no other process can read or modify it.
pub struct MutEnvHostWrapper<T>(*mut c_void, PhantomData<T>);
unsafe impl<T> Send for MutEnvHostWrapper<T> {}
unsafe impl<T> Sync for MutEnvHostWrapper<T> {}

// Same as for [`EnvHostWrapper`], we have to manually implement [`Clone`],
// because the derived [`Clone`] for [`PhantomData<T>`] puts the bound on [`T:
// Clone`].
impl<T> Clone for MutEnvHostWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T> MutEnvHostWrapper<T> {
    /// Wrap a mutable reference for VM environment.
    ///
    /// # Safety
    ///
    /// This is not thread-safe. Also, because this is unsafe, care must be
    /// taken that while this reference is borrowed, no other process can read
    /// or modify it.
    pub unsafe fn new(host_structure: *mut c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// Get a mutable reference from VM environment.
    ///
    /// # Safety
    ///
    /// This is not thread-safe. Also, because this is unsafe, care must be
    /// taken that while this reference is borrowed, no other process can read
    /// or modify it.
    pub unsafe fn get(&self) -> *mut T {
        self.0 as *mut T
    }
}

/// Validate an untrusted wasm code with restrictions that we place such code
/// (e.g. transaction and validity predicates)
pub fn validate_untrusted_wasm(
    wasm_code: impl AsRef<[u8]>,
) -> Result<(), wasmparser::BinaryReaderError> {
    let mut validator = Validator::new();

    let features = WasmFeatures {
        reference_types: false,
        multi_value: false,
        bulk_memory: false,
        module_linking: false,
        simd: false,
        threads: false,
        tail_call: false,
        deterministic_only: true,
        multi_memory: false,
        exceptions: false,
        memory64: false,
    };
    validator.wasm_features(features);

    validator.validate_all(wasm_code.as_ref())
}
