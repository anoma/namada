//! Virtual machine's memory.

/// Abstract representation of virtual machine's memory.
pub trait VmMemory: Clone + Send + Sync {
    /// Returns bytes read from memory together with the associated gas cost.
    fn read_bytes(&self, offset: u64, len: usize) -> (Vec<u8>, u64);

    /// Write bytes to memory. Returns the gas cost.
    fn write_bytes(&self, offset: u64, bytes: impl AsRef<[u8]>) -> u64;

    /// Returns string read from memory together with the associated gas cost.
    fn read_string(&self, offset: u64, len: usize) -> (String, u64);

    /// Write string to memory. Returns the gas cost.
    fn write_string(&self, offset: u64, string: String) -> u64;
}

/// Helper module for VM testing
#[cfg(feature = "testing")]
pub mod testing {
    pub use core::slice;

    use super::*;

    /// Native memory implementation may be used for testing VM host environment
    /// natively, without compiling to wasm.
    #[derive(Clone)]
    pub struct NativeMemory;

    impl VmMemory for NativeMemory {
        fn read_bytes(&self, offset: u64, len: usize) -> (Vec<u8>, u64) {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            (slice.to_vec(), 0)
        }

        fn write_bytes(&self, offset: u64, bytes: impl AsRef<[u8]>) -> u64 {
            let bytes = bytes.as_ref();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            0
        }

        fn read_string(&self, offset: u64, len: usize) -> (String, u64) {
            let slice = unsafe { slice::from_raw_parts(offset as _, len as _) };
            let string = std::str::from_utf8(slice)
                .expect("unable to decode string from memory")
                .to_string();
            (string, 0)
        }

        fn write_string(&self, offset: u64, string: String) -> u64 {
            let bytes = string.as_bytes();
            let len = bytes.len();
            let target =
                unsafe { slice::from_raw_parts_mut(offset as _, len as _) };
            target.clone_from_slice(bytes);
            0
        }
    }
}
