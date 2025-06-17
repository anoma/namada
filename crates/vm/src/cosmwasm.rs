use std::{any::Any, str::FromStr};

pub use cosmwasm_vm::{Backend, BackendResult};
use cosmwasm_vm::{BackendError, GasInfo};

use cosmwasm_std::{Binary, ContractResult, Order, Record, SystemResult};
use namada_core::address::Address;
use namada_core::storage;
use namada_state::{StorageRead, StorageWrite};

pub fn backend<'a, S>(
    storage: &'a mut S,
    owner: Address,
) -> Backend<BackendApi, Storage<'a, S>, Querier>
where
    S: StorageRead + StorageWrite,
{
    Backend {
        api: BackendApi,
        storage: Storage { storage, owner },
        querier: Querier,
    }
}

#[derive(Debug, Clone)]
pub struct BackendApi;

#[derive(Debug)]
pub struct Storage<'a, S> {
    pub storage: &'a mut S,
    pub owner: Address,
}

#[derive(Debug)]
pub struct Querier;

impl cosmwasm_vm::BackendApi for BackendApi {
    fn addr_validate(&self, input: &str) -> BackendResult<()> {
        todo!()
    }

    fn addr_canonicalize(&self, human: &str) -> BackendResult<Vec<u8>> {
        todo!()
    }

    fn addr_humanize(&self, canonical: &[u8]) -> BackendResult<String> {
        todo!()
    }
}

impl<S> cosmwasm_vm::Storage for Storage<'_, S>
where
    S: StorageRead + StorageWrite,
{
    fn get(&self, key: &[u8]) -> BackendResult<Option<Vec<u8>>> {
        let key = storage::Key::from(storage::DbKeySeg::AddressSeg(
            self.owner.clone(),
        ))
        .with_segment(storage::DbKeySeg::StringSeg(
            std::str::from_utf8(key).unwrap().to_string(),
        ));
        dbg!(key.to_string());
        let result = self.storage.read_bytes(&key);
        dbg!(&result);
        (
            result.map_err(|e| BackendError::user_err(e.to_string())),
            // TODO gas
            GasInfo::with_cost(0),
        )
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> BackendResult<()> {
        let key = storage::Key::from(storage::DbKeySeg::AddressSeg(
            self.owner.clone(),
        ))
        .with_segment(storage::DbKeySeg::StringSeg(
            std::str::from_utf8(key).unwrap().to_string(),
        ));
        let result = self.storage.write_bytes(&key, value);
        dbg!(&result);
        (
            result.map_err(|e| BackendError::user_err(e.to_string())),
            // TODO gas
            GasInfo::with_cost(0),
        )
    }

    fn remove(&mut self, key: &[u8]) -> BackendResult<()> {
        todo!()
    }

    fn scan(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        order: Order,
    ) -> BackendResult<u32> {
        todo!()
    }

    fn next(&mut self, iterator_id: u32) -> BackendResult<Option<Record>> {
        todo!()
    }
}

impl cosmwasm_vm::Querier for Querier {
    fn query_raw(
        &self,
        request: &[u8],
        gas_limit: u64,
    ) -> BackendResult<SystemResult<ContractResult<Binary>>> {
        todo!()
    }
}
