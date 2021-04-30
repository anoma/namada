//! This crate contains library code for wasm. Some of the code is re-exported
//! from the `shared` crate.

mod imports;
pub mod key;
mod token;

pub mod tx_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::vm_memory;

    pub use super::imports::tx::*;

    pub mod token {
        pub use anoma_shared::types::token::*;

        pub use crate::token::transfer;
    }
}

pub mod vp_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::vm_memory;

    pub use crate::imports::vp::*;

    pub mod key {
        pub mod ed25519 {
            pub use anoma_shared::types::key::ed25519::*;

            pub use crate::key::ed25519::*;
        }
    }

    pub mod token {
        pub use anoma_shared::types::token::*;

        pub use crate::token::vp;
    }
}

pub mod matchmaker_prelude {
    pub use anoma_shared::types::*;
    pub use anoma_shared::*;

    pub use crate::imports::matchmaker::*;
}

pub mod filter_prelude {
    pub use anoma_shared::vm_memory;

    pub use super::imports::filter::*;
}
