//! Pfg

use crate::ledger::pgf::{storage as pgf_storage, CounsilData};
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::transaction::pgf::InitCounsil;

/// A proposal creation transaction.
pub fn init_counsil<S>(
    storage: &mut S,
    data: InitCounsil,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let counsil_key = pgf_storage::get_candidate_key(&data.address, data.spending_cap);
    let counsil_data = CounsilData {
        epoch: data.epoch,
        data: data.data,
    };
    storage.write(&counsil_key, counsil_data);
    Ok(())
}