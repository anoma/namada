//! This module combines the native host function implementations from
//! `native_tx_env` with the functions exposed to the tx wasm
//! that will call to the native functions, instead of interfacing via a
//! wasm runtime. It can be used for WASM and host environment integration
//! tests.

use namada_core::time::DurationSecs;
pub use namada_tx_env::ctx::{Ctx, *};
pub use namada_tx_env::testing::native_tx_env::*;
pub use namada_tx_env::testing::{ctx, TestTxEnv};
pub use namada_tx_prelude::*;
use parameters::EpochDuration;

use crate::vp::TestVpEnv;

/// Set the [`TestTxEnv`] back from a [`TestVpEnv`]. This is useful when
/// testing validation with multiple transactions that accumulate some state
/// changes.
pub fn set_from_vp_env(vp_env: TestVpEnv) {
    let TestVpEnv {
        state,
        batched_tx,
        vp_wasm_cache,
        vp_cache_dir,
        ..
    } = vp_env;
    let tx_env = TestTxEnv {
        state,
        vp_wasm_cache,
        vp_cache_dir,
        batched_tx,
        ..Default::default()
    };
    set(tx_env);
}

pub trait TestTxEnvExt {
    fn init_parameters(
        &mut self,
        epoch_duration: Option<EpochDuration>,
        vp_allowlist: Option<Vec<String>>,
        tx_allowlist: Option<Vec<String>>,
    );

    /// Credit tokens to the target account.
    fn credit_tokens(
        &mut self,
        target: &Address,
        token: &Address,
        amount: token::Amount,
    );

    fn init_account_storage(
        &mut self,
        owner: &Address,
        public_keys: Vec<common::PublicKey>,
        threshold: u8,
    );

    /// Set public key for the address.
    fn write_account_threshold(&mut self, address: &Address, threshold: u8);
}

impl TestTxEnvExt for TestTxEnv {
    fn init_parameters(
        &mut self,
        epoch_duration: Option<EpochDuration>,
        vp_allowlist: Option<Vec<String>>,
        tx_allowlist: Option<Vec<String>>,
    ) {
        parameters::update_epoch_parameter(
            &mut self.state,
            &epoch_duration.unwrap_or(EpochDuration {
                min_num_of_blocks: 1,
                min_duration: DurationSecs(5),
            }),
        )
        .unwrap();
        parameters::update_tx_allowlist_parameter(
            &mut self.state,
            tx_allowlist.unwrap_or_default(),
        )
        .unwrap();
        parameters::update_vp_allowlist_parameter(
            &mut self.state,
            vp_allowlist.unwrap_or_default(),
        )
        .unwrap();
    }

    fn credit_tokens(
        &mut self,
        target: &Address,
        token: &Address,
        amount: token::Amount,
    ) {
        let storage_key = token::storage_key::balance_key(token, target);
        self.state.write(&storage_key, amount).unwrap();
    }

    fn init_account_storage(
        &mut self,
        owner: &Address,
        public_keys: Vec<common::PublicKey>,
        threshold: u8,
    ) {
        account::init_account_storage(
            &mut self.state,
            owner,
            &public_keys,
            threshold,
        )
        .expect("Unable to write Account substorage.");
    }

    fn write_account_threshold(&mut self, address: &Address, threshold: u8) {
        let storage_key = account::threshold_key(address);
        self.state.write(&storage_key, threshold).unwrap();
    }
}
