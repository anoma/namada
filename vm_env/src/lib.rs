//! This crate contains code that is shared between the VM host (the ledger) and
//! the guest (wasm code).

mod imports;

pub mod tx_prelude {
    pub use super::imports::tx::*;
    pub use anoma_shared::types::Address;
    pub use anoma_shared::vm_memory;
}

pub mod vp_prelude {
    pub use super::imports::vp::*;
    pub use anoma_shared::types::Address;
    pub use anoma_shared::vm_memory;
}

pub mod matchmaker_prelude {
    pub use super::imports::matchmaker::*;
    pub use anoma_shared::types::Address;
    pub use anoma_shared::vm_memory;
}
