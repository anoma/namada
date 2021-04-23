//! This crate contains code that is shared between the VM host (the ledger) and
//! the guest (wasm code).

mod imports;

pub mod tx_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::{vm_memory, *};

    pub use super::imports::tx::*;
}

pub mod vp_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::{vm_memory, *};

    pub use super::imports::vp::*;
}

pub mod matchmaker_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::{vm_memory, *};

    pub use super::imports::matchmaker::*;
}
