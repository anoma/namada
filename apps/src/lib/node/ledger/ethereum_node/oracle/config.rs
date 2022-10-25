//! Configuration for an oracle.
use namada::types::ethereum_events::EthAddress;

/// Configuration for an [`Oracle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Config {
    pub min_confirmations: u64,
    pub mint_contract: EthAddress,
    pub governance_contract: EthAddress,
}

// TODO: this production Default implementation is temporary, there should be no
//  default config - initialization should always be from storage
impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            min_confirmations: 100,
            mint_contract: EthAddress([0; 20]),
            governance_contract: EthAddress([1; 20]),
        }
    }
}
