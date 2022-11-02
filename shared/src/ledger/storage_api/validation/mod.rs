//! Storage change validation helpers

use std::fmt::Debug;

use borsh::BorshDeserialize;

use crate::ledger::storage_api;
use crate::ledger::vp_env::VpEnv;
use crate::types::storage;

/// Data update with prior and posterior state.
#[derive(Clone, Debug)]
pub enum Data<T> {
    /// Newly added value
    Add {
        /// Posterior state
        post: T,
    },
    /// Updated value prior and posterior state
    Update {
        /// Prior state
        pre: T,
        /// Posterior state
        post: T,
    },
    /// Deleted value
    Delete {
        /// Prior state
        pre: T,
    },
}

/// Read the prior and posterior state for the given key.
pub fn read_data<ENV, T>(
    env: &ENV,
    key: &storage::Key,
) -> Result<Option<Data<T>>, storage_api::Error>
where
    T: BorshDeserialize,
    ENV: for<'a> VpEnv<'a>,
{
    let pre = env.read_pre(key)?;
    let post = env.read_post(key)?;
    Ok(match (pre, post) {
        (None, None) => {
            // If the key was inserted and then deleted in the same tx, we don't
            // need to validate it as it's not visible to any VPs
            None
        }
        (None, Some(post)) => Some(Data::Add { post }),
        (Some(pre), None) => Some(Data::Delete { pre }),
        (Some(pre), Some(post)) => Some(Data::Update { pre, post }),
    })
}
