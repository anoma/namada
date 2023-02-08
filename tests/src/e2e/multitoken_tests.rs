//! Tests for multitoken functionality
use color_eyre::eyre::Result;
use namada_core::types::token;

use super::helpers::get_actor_rpc;
use super::setup::constants::{ALBERT, BERTHA, CHRISTEL};
use super::setup::{self, Who};
use crate::e2e;
use crate::e2e::setup::constants::{ALBERT_KEY, BERTHA_KEY};

mod helpers;

#[test]
fn test_multitoken_transfer_implicit_to_implicit() -> Result<()> {
    let (test, _ledger) = e2e::helpers::setup_single_node_test()?;

    let rpc_addr = get_actor_rpc(&test, &Who::Validator(0));
    let multitoken_alias = helpers::init_multitoken_vp(&test, &rpc_addr)?;

    // establish a multitoken VP with the following balances
    // - #atest5blah/tokens/red/balance/$albert_established = 100
    // - #atest5blah/tokens/red/balance/$bertha = 0

    let multitoken_vp_addr =
        e2e::helpers::find_address(&test, &multitoken_alias)?;
    println!("Fake multitoken VP established at {}", multitoken_vp_addr);

    let albert_addr = e2e::helpers::find_address(&test, ALBERT)?;
    let albert_starting_red_balance = token::Amount::from(100_000_000);
    helpers::mint_red_tokens(
        &test,
        &rpc_addr,
        &multitoken_vp_addr,
        &albert_addr,
        &albert_starting_red_balance,
    )?;

    let transfer_amount = token::Amount::from(10_000_000);

    // make a transfer from Albert to Bertha, signed by Christel - this should
    // be rejected
    let mut unauthorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
        BERTHA,
        CHRISTEL,
        &transfer_amount,
    )?;
    unauthorized_transfer.exp_string("Transaction applied with result")?;
    unauthorized_transfer.exp_string("Transaction is invalid")?;
    unauthorized_transfer.exp_string(&format!("Rejected: {albert_addr}"))?;
    unauthorized_transfer.assert_success();

    let albert_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
    )?;
    assert_eq!(albert_balance, albert_starting_red_balance);

    // make a transfer from Albert to Bertha, signed by Albert - this should
    // be accepted
    let mut authorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
        BERTHA,
        ALBERT,
        &token::Amount::from(10_000_000),
    )?;
    authorized_transfer.exp_string("Transaction applied with result")?;
    authorized_transfer.exp_string("Transaction is valid")?;
    authorized_transfer.assert_success();

    let albert_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
    )?;
    assert_eq!(
        albert_balance,
        albert_starting_red_balance - transfer_amount
    );
    Ok(())
}

#[test]
fn test_multitoken_transfer_established_to_implicit() -> Result<()> {
    let (test, _ledger) = e2e::helpers::setup_single_node_test()?;

    let rpc_addr = get_actor_rpc(&test, &Who::Validator(0));
    let multitoken_alias = helpers::init_multitoken_vp(&test, &rpc_addr)?;

    let multitoken_vp_addr =
        e2e::helpers::find_address(&test, &multitoken_alias)?;
    println!("Fake multitoken VP established at {}", multitoken_vp_addr);

    // create an established account that Albert controls
    let established_alias = "established";
    e2e::helpers::init_established_account(
        &test,
        &rpc_addr,
        ALBERT,
        ALBERT_KEY,
        established_alias,
    )?;

    let established_starting_red_balance = token::Amount::from(100_000_000);
    // mint some red tokens for the established account
    let established_addr =
        e2e::helpers::find_address(&test, established_alias)?;
    helpers::mint_red_tokens(
        &test,
        &rpc_addr,
        &multitoken_vp_addr,
        &established_addr,
        &established_starting_red_balance,
    )?;

    let transfer_amount = token::Amount::from(10_000_000);
    // attempt an unauthorized transfer to Albert from the established account
    let mut unauthorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
        BERTHA,
        CHRISTEL,
        &transfer_amount,
    )?;
    unauthorized_transfer.exp_string("Transaction applied with result")?;
    unauthorized_transfer.exp_string("Transaction is invalid")?;
    unauthorized_transfer
        .exp_string(&format!("Rejected: {established_addr}"))?;
    unauthorized_transfer.assert_success();

    let established_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
    )?;
    assert_eq!(established_balance, established_starting_red_balance);

    // attempt an authorized transfer to Albert from the established account
    let mut authorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
        BERTHA,
        ALBERT,
        &transfer_amount,
    )?;
    authorized_transfer.exp_string("Transaction applied with result")?;
    authorized_transfer.exp_string("Transaction is valid")?;
    authorized_transfer.assert_success();

    let established_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
    )?;
    assert_eq!(
        established_balance,
        established_starting_red_balance - transfer_amount
    );

    Ok(())
}

#[test]
fn test_multitoken_transfer_implicit_to_established() -> Result<()> {
    let (test, _ledger) = e2e::helpers::setup_single_node_test()?;

    let rpc_addr = get_actor_rpc(&test, &Who::Validator(0));
    let multitoken_alias = helpers::init_multitoken_vp(&test, &rpc_addr)?;

    let multitoken_vp_addr =
        e2e::helpers::find_address(&test, &multitoken_alias)?;
    println!("Fake multitoken VP established at {}", multitoken_vp_addr);

    // create an established account controlled by Bertha
    let established_alias = "established";
    e2e::helpers::init_established_account(
        &test,
        &rpc_addr,
        BERTHA,
        BERTHA_KEY,
        established_alias,
    )?;

    let albert_addr = e2e::helpers::find_address(&test, ALBERT)?;
    let albert_starting_red_balance = token::Amount::from(100_000_000);
    helpers::mint_red_tokens(
        &test,
        &rpc_addr,
        &multitoken_vp_addr,
        &albert_addr,
        &albert_starting_red_balance,
    )?;

    let transfer_amount = token::Amount::from(10_000_000);

    // attempt an unauthorized transfer from Albert to the established account
    let mut unauthorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
        established_alias,
        CHRISTEL,
        &transfer_amount,
    )?;
    unauthorized_transfer.exp_string("Transaction applied with result")?;
    unauthorized_transfer.exp_string("Transaction is invalid")?;
    unauthorized_transfer.exp_string(&format!("Rejected: {albert_addr}"))?;
    unauthorized_transfer.assert_success();

    let albert_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
    )?;
    assert_eq!(albert_balance, albert_starting_red_balance);

    // attempt an authorized transfer to Albert from the established account
    let mut authorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
        established_alias,
        ALBERT,
        &transfer_amount,
    )?;
    authorized_transfer.exp_string("Transaction applied with result")?;
    authorized_transfer.exp_string("Transaction is valid")?;
    authorized_transfer.assert_success();

    let albert_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        ALBERT,
    )?;
    assert_eq!(
        albert_balance,
        albert_starting_red_balance - transfer_amount
    );

    Ok(())
}

#[test]
fn test_multitoken_transfer_established_to_established() -> Result<()> {
    let (test, _ledger) = e2e::helpers::setup_single_node_test()?;

    let rpc_addr = get_actor_rpc(&test, &Who::Validator(0));
    let multitoken_alias = helpers::init_multitoken_vp(&test, &rpc_addr)?;

    let multitoken_vp_addr =
        e2e::helpers::find_address(&test, &multitoken_alias)?;
    println!("Fake multitoken VP established at {}", multitoken_vp_addr);

    // create an established account that Albert controls
    let established_alias = "established";
    e2e::helpers::init_established_account(
        &test,
        &rpc_addr,
        ALBERT,
        ALBERT_KEY,
        established_alias,
    )?;

    let established_starting_red_balance = token::Amount::from(100_000_000);
    // mint some red tokens for the established account
    let established_addr =
        e2e::helpers::find_address(&test, established_alias)?;
    helpers::mint_red_tokens(
        &test,
        &rpc_addr,
        &multitoken_vp_addr,
        &established_addr,
        &established_starting_red_balance,
    )?;

    // create another established account to receive transfers
    let receiver_alias = "receiver";
    e2e::helpers::init_established_account(
        &test,
        &rpc_addr,
        BERTHA,
        BERTHA_KEY,
        receiver_alias,
    )?;

    let established_starting_red_balance = token::Amount::from(100_000_000);
    // mint some red tokens for the established account
    let established_addr =
        e2e::helpers::find_address(&test, established_alias)?;
    helpers::mint_red_tokens(
        &test,
        &rpc_addr,
        &multitoken_vp_addr,
        &established_addr,
        &established_starting_red_balance,
    )?;

    let transfer_amount = token::Amount::from(10_000_000);

    // attempt an unauthorized transfer
    let mut unauthorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
        receiver_alias,
        CHRISTEL,
        &transfer_amount,
    )?;
    unauthorized_transfer.exp_string("Transaction applied with result")?;
    unauthorized_transfer.exp_string("Transaction is invalid")?;
    unauthorized_transfer
        .exp_string(&format!("Rejected: {established_addr}"))?;
    unauthorized_transfer.assert_success();

    let established_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
    )?;
    assert_eq!(established_balance, established_starting_red_balance);

    // attempt an authorized transfer which should succeed
    let mut authorized_transfer = helpers::attempt_red_tokens_transfer(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
        receiver_alias,
        ALBERT,
        &transfer_amount,
    )?;
    authorized_transfer.exp_string("Transaction applied with result")?;
    authorized_transfer.exp_string("Transaction is valid")?;
    authorized_transfer.assert_success();

    let established_balance = helpers::fetch_red_token_balance(
        &test,
        &rpc_addr,
        &multitoken_alias,
        established_alias,
    )?;
    assert_eq!(
        established_balance,
        established_starting_red_balance - transfer_amount
    );

    Ok(())
}
