pub mod eth_bridge_pool;
pub mod pos;

use std::cell::RefCell;
use std::collections::BTreeSet;

use namada::core::address::Address;
use namada::core::storage;
use namada::ledger::gas::VpGasMeter;
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::state::testing::TestState;
use namada::vm::WasmCacheRwAccess;
use namada_core::validity_predicate::VpSentinel;

use crate::tx::TestTxEnv;

type NativeVpCtx<'a> = Ctx<'a, TestState, WasmCacheRwAccess>;

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
        gas_meter: &'a RefCell<VpGasMeter>,
        sentinel: &'a RefCell<VpSentinel>,
        init_native_vp: impl Fn(NativeVpCtx<'a>) -> T,
    ) -> Result<bool, <T as NativeVp>::Error>
    where
        T: NativeVp,
    {
        let ctx = Ctx::new(
            &self.address,
            &self.tx_env.state,
            &self.tx_env.tx,
            &self.tx_env.tx_index,
            gas_meter,
            sentinel,
            &self.keys_changed,
            &self.verifiers,
            self.tx_env.vp_wasm_cache.clone(),
        );
        let native_vp = init_native_vp(ctx);

        native_vp.validate_tx(
            &self.tx_env.tx,
            &self.keys_changed,
            &self.verifiers,
        )
    }
}
