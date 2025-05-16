pub use cosmwasm_vm::{Backend, BackendResult};

use cosmwasm_std::{Binary, ContractResult, Order, Record, SystemResult};

pub fn backend() -> Backend<BackendApi, Storage, Querier> {
    Backend {
        api: BackendApi,
        storage: Storage,
        querier: Querier,
    }
}

#[derive(Debug, Clone)]
pub struct BackendApi;

#[derive(Debug)]
pub struct Storage;

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

impl cosmwasm_vm::Storage for Storage {
    fn get(&self, key: &[u8]) -> BackendResult<Option<Vec<u8>>> {
        todo!()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> BackendResult<()> {
        todo!()
    }

    fn remove(&mut self, key: &[u8]) -> BackendResult<()> {
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
