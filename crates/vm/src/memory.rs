//! Virtual machine's memory.

use std::error::Error;

/// Abstract representation of virtual machine's memory.
pub trait VmMemory: Clone + Send + Sync {
    /// Error type for the methods' results.
    type Error: Error + Sync + Send + 'static;

    /// Returns bytes read from memory together with the associated gas cost.
    fn read_bytes(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, u64), Self::Error>;

    /// Write bytes to memory. Returns the gas cost.
    fn write_bytes(
        &mut self,
        offset: u64,
        bytes: impl AsRef<[u8]>,
    ) -> Result<u64, Self::Error>;

    /// Returns string read from memory together with the associated gas cost.
    fn read_string(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(String, u64), Self::Error>;

    /// Write string to memory. Returns the gas cost.
    fn write_string(
        &mut self,
        offset: u64,
        string: String,
    ) -> Result<u64, Self::Error>;
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
        ) -> Result<(Vec<u8>, u64)> {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            Ok((slice.to_vec(), 0))
        }

        fn write_bytes(
            &mut self,
            offset: u64,
            bytes: impl AsRef<[u8]>,
        ) -> Result<u64> {
            let bytes = bytes.as_ref();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            Ok(0)
        }

        fn read_string(
            &mut self,
            offset: u64,
            len: usize,
        ) -> Result<(String, u64)> {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            let string = std::str::from_utf8(slice)
                .expect("unable to decode string from memory")
                .to_string();
            Ok((string, 0))
        }

        fn write_string(&mut self, offset: u64, string: String) -> Result<u64> {
            let bytes = string.as_bytes();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            Ok(0)
        }
    }
}
