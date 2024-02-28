//! Configuration for an oracle.
use std::num::NonZeroU64;

use namada_core::ethereum_events::EthAddress;
use namada_core::ethereum_structs;

/// Configuration for an oracle.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Config {
    /// The minimum number of block confirmations an Ethereum block must have
    /// before it will be checked for bridge events.
    pub min_confirmations: NonZeroU64,
    /// The Ethereum address of the current bridge contract.
    pub bridge_contract: EthAddress,
    /// The earliest Ethereum block from which events may be processed.
    pub start_block: ethereum_structs::BlockHeight,
    /// The status of the Ethereum bridge (active / inactive)
    pub active: bool,
}

// TODO: this production Default implementation is temporary, there should be no
//  default config - initialization should always be from storage.
impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            // SAFETY: we must always call NonZeroU64::new_unchecked here with a
            // value that is >= 1
            min_confirmations: unsafe { NonZeroU64::new_unchecked(100) },
            bridge_contract: EthAddress([0; 20]),
            start_block: 0.into(),
            active: true,
        }
    }
}
