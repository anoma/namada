//! Shared internal types between the host env and guest (wasm).

/// A result of a wasm call to host functions that may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnvResult {
    Success = 1,
    Fail = -1,
}

impl HostEnvResult {
    pub fn to_i64(self) -> i64 {
        self as _
    }

    pub fn is_success(int: i64) -> bool {
        int == Self::Success.to_i64()
    }

    pub fn is_fail(int: i64) -> bool {
        int == Self::Fail.to_i64()
    }
}

impl From<bool> for HostEnvResult {
    fn from(success: bool) -> Self {
        if success { Self::Success } else { Self::Fail }
    }
}
