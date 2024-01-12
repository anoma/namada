pub mod eth_bridge_pool;
pub mod pos;

use std::cell::RefCell;
use std::collections::BTreeSet;

use namada::ledger::gas::VpGasMeter;
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::state::mockdb::MockDB;
use namada::state::Sha256Hasher;
use namada::types::address::Address;
use namada::types::storage;
use namada::vm::WasmCacheRwAccess;

use crate::tx::TestTxEnv;

type NativeVpCtx<'a> = Ctx<'a, MockDB, Sha256Hasher, WasmCacheRwAccess>;

#[derive(Debug)]
pub struct TestNativeVpEnv {
    pub tx_env: TestTxEnv,
    pub address: Address,
    pub verifiers: BTreeSet<Address>,
    pub keys_changed: BTreeSet<storage::Key>,
}

impl TestNativeVpEnv {
    pub fn from_tx_env(tx_env: TestTxEnv, address: Address) -> Self {
        // Find the tx verifiers and keys_changes the same way as protocol would
        let verifiers = tx_env.get_verifiers();

        let keys_changed = tx_env.all_touched_storage_keys();

        Self {
            address,
            tx_env,
            verifiers,
            keys_changed,
        }
    }
}

impl TestNativeVpEnv {
    /// Run some transaction code `apply_tx` and validate it with a native VP
    pub fn validate_tx<'a, T>(
        &'a self,
        init_native_vp: impl Fn(NativeVpCtx<'a>) -> T,
    ) -> Result<bool, <T as NativeVp>::Error>
    where
        T: NativeVp,
    {
        let ctx = Ctx {
            iterators: Default::default(),
            gas_meter: RefCell::new(VpGasMeter::new_from_tx_meter(
                &self.tx_env.gas_meter,
            )),
            sentinel: Default::default(),
            storage: &self.tx_env.wl_storage.storage,
            write_log: &self.tx_env.wl_storage.write_log,
            tx: &self.tx_env.tx,
            tx_index: &self.tx_env.tx_index,
            vp_wasm_cache: self.tx_env.vp_wasm_cache.clone(),
            address: &self.address,
            keys_changed: &self.keys_changed,
            verifiers: &self.verifiers,
        };
        let native_vp = init_native_vp(ctx);

        native_vp.validate_tx(
            &self.tx_env.tx,
            &self.keys_changed,
            &self.verifiers,
        )
    }
}
