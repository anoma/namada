//! This crate contains code that is shared between the VM host (the ledger) and
//! the guest (wasm code).

mod imports;
pub mod memory;

pub mod tx_prelude {
    pub use super::imports::tx::*;
    pub use super::memory;
}

pub mod vp_prelude {
    pub use super::imports::vp::*;
    pub use super::memory;
}

pub mod matchmaker_prelude {
    pub use super::imports::matchmaker::*;
    pub use super::memory;
}

pub mod filter_prelude {
    pub use super::imports::filter::*;
    pub use super::memory;
}
