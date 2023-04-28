//! Tests for [`namada_core::ledger::testnet_pow`].

use namada_core::ledger::storage_api;
use namada_core::ledger::testnet_pow::*;
use namada_core::types::{address, token};

use crate::tx::{self, TestTxEnv};
use crate::vp;

#[test]
fn test_challenge_and_solution() -> storage_api::Result<()> {
    let faucet_address = address::testing::established_address_1();
    let difficulty = Difficulty::try_new(1).unwrap();
    let withdrawal_limit = token::Amount::whole(1_000);

    let mut tx_env = TestTxEnv::default();

    // Source address that's using PoW (this would be derived from the tx
    // wrapper pk)
    let source = address::testing::established_address_2();

    // Ensure that the addresses exists, so we can use them in a tx
    tx_env.spawn_accounts([&faucet_address, &source]);

    init_faucet_storage(
        &mut tx_env.wl_storage,
        &faucet_address,
        difficulty,
        withdrawal_limit,
    )?;
    tx_env.commit_genesis();

    let challenge = Challenge::new(
        &mut tx_env.wl_storage,
        &faucet_address,
        source.clone(),
    )?;

    let solution = challenge.solve();

    // The solution must be valid
    assert!(solution.verify_solution(source.clone()));

    // Changing the solution to `0` invalidates it
    {
        let mut solution = solution.clone();
        solution.value = 0;
        // If you're unlucky and this fails, try changing the solution to
        // a different literal.
        assert!(!solution.verify_solution(source.clone()));
    }
    // Changing the counter invalidates it
    {
        let mut solution = solution.clone();
        solution.params.counter = 10;
        // If you're unlucky and this fails, try changing the counter to
        // a different literal.
        assert!(!solution.verify_solution(source.clone()));
    }

    // Apply the solution from a tx
    vp::vp_host_env::init_from_tx(faucet_address.clone(), tx_env, |_addr| {
        solution
            .apply_from_tx(tx::ctx(), &faucet_address, &source)
            .unwrap();
    });

    // Check that it's valid
    let is_valid =
        solution.validate(&vp::ctx().pre(), &faucet_address, source.clone())?;
    assert!(is_valid);

    // Commit the tx
    let vp_env = vp::vp_host_env::take();
    tx::tx_host_env::set_from_vp_env(vp_env);
    tx::tx_host_env::commit_tx_and_block();
    let tx_env = tx::tx_host_env::take();

    // Re-apply the same solution from a tx
    vp::vp_host_env::init_from_tx(faucet_address.clone(), tx_env, |_addr| {
        solution
            .apply_from_tx(tx::ctx(), &faucet_address, &source)
            .unwrap();
    });

    // Check that it's not longer valid
    let is_valid =
        solution.validate(&vp::ctx().pre(), &faucet_address, source)?;
    assert!(!is_valid);

    Ok(())
}
