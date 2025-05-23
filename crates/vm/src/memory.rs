//! Virtual machine's memory.

use std::cell::RefCell;
use std::error::Error;
use std::rc;

use namada_gas::Gas;

/// Abstract representation of virtual machine's memory.
pub trait VmMemory: Clone + Send + Sync {
    /// Error type for the methods' results.
    type Error: Error + Sync + Send + 'static + Into<namada_state::Error>;

    /// Returns bytes read from memory together with the associated gas cost.
    fn read_bytes(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, Gas), Self::Error>;

    /// Write bytes to memory. Returns the gas cost.
    fn write_bytes(
        &mut self,
        offset: u64,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Gas, Self::Error>;

    /// Returns string read from memory together with the associated gas cost.
    fn read_string(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(String, Gas), Self::Error>;

    /// Write string to memory. Returns the gas cost.
    fn write_string(
        &mut self,
        offset: u64,
        string: String,
    ) -> Result<Gas, Self::Error>;

    /// Return a wasmer store associated with this memory.
    fn store(&self) -> rc::Weak<RefCell<wasmer::Store>>;
}

/// Helper module for VM testing
#[cfg(feature = "testing")]
pub mod testing {
    pub use core::slice;
    use std::convert::Infallible;

    use super::*;

    /// Native memory implementation may be used for testing VM host environment
    /// natively, without compiling to wasm.
    #[derive(Clone, Default)]
    pub struct NativeMemory;

    type Result<T> = std::result::Result<T, Infallible>;

    impl VmMemory for NativeMemory {
        type Error = Infallible;

        fn read_bytes(
            &mut self,
            offset: u64,
            len: usize,
        ) -> Result<(Vec<u8>, Gas)> {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            Ok((slice.to_vec(), Gas::default()))
        }

        fn write_bytes(
            &mut self,
            offset: u64,
            bytes: impl AsRef<[u8]>,
        ) -> Result<Gas> {
            let bytes = bytes.as_ref();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            Ok(Gas::default())
        }

        fn read_string(
            &mut self,
            offset: u64,
            len: usize,
        ) -> Result<(String, Gas)> {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            let string = std::str::from_utf8(slice)
                .expect("unable to decode string from memory")
                .to_string();
            Ok((string, Gas::default()))
        }

        fn write_string(&mut self, offset: u64, string: String) -> Result<Gas> {
            let bytes = string.as_bytes();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            Ok(Gas::default())
        }

        fn store(&self) -> rc::Weak<RefCell<wasmer::Store>> {
            unimplemented!()
        }
    }
}
