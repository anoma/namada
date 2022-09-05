//! Functionality for accessing the storage subspace
pub mod bridge_pool;
pub mod eth_msgs;
pub mod wrapped_erc20s;

use super::ADDRESS;
use crate::types::storage::{Key, KeySeg};

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}
