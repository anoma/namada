use namada_core::types::ethereum_events::Uint;
use namada_core::types::keccak::KeccakHash;

pub trait EthBridgeQueries {
    /// Get the latest nonce for the Ethereum bridge
    /// pool.
    fn get_bride_pool_nonce(&self) -> Uint;

    /// Get the latest root of the Ethereum bridge
    /// pool Merkle tree.
    fn get_bridge_pool_root(&self) -> KeccakHash;
}