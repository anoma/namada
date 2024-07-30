//! Parameters abstract interfaces

pub use namada_core::parameters::*;
use namada_core::storage;
pub use namada_storage::Result;

/// Abstract parameters storage keys interface
pub trait Keys {
    /// Key for implicit VP
    fn implicit_vp_key() -> storage::Key;
}

/// Abstract parameters storage read interface
pub trait Read<S> {
    /// Read all parameters
    fn read(storage: &S) -> Result<Parameters>;

    /// Read MASP epoch multiplier parameter
    fn masp_epoch_multiplier(storage: &S) -> Result<u64>;

    /// Read the the epoch duration parameter
    fn epoch_duration_parameter(storage: &S) -> Result<EpochDuration>;

    /// Read the `is_native_token_transferable` parameter
    fn is_native_token_transferable(storage: &S) -> Result<bool>;

    /// Read the number of epochs per year parameter
    fn epochs_per_year(storage: &S) -> Result<u64>;
}

/// Abstract parameters storage write interface
pub trait Write<S>: Read<S> {
    /// Write all parameters
    fn write(storage: &mut S, parameters: &Parameters) -> Result<()>;
}
