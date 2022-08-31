//! Functionality for accessing the storage subspace
use super::ADDRESS;
use crate::types::storage::{Key, KeySeg};

pub mod eth_msgs;
pub mod wrapped_erc20s;

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}
