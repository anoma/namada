use std::path::PathBuf;
use std::str::FromStr;

use borsh_ext::BorshSerializeExt;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use namada_apps_lib::wallet::defaults::{albert_keypair, christel_keypair};
use namada_core::dec::Dec;
use namada_core::masp::TokenMap;
use namada_node::shell::testing::client::run;
use namada_node::shell::testing::node::{MockNode, NodeResults};
use namada_node::shell::testing::utils::{Bin, CapturedOutput};
use namada_sdk::account::AccountPublicKeysMap;
use namada_sdk::address::InternalAddress;
use namada_sdk::chain::testing::get_dummy_header;
use namada_sdk::chain::ChainId;
use namada_sdk::io::Client;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::masp_primitives::sapling::PaymentAddress;
use namada_sdk::signing::SigningTxData;
use namada_sdk::state::{StorageRead, StorageWrite};
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::storage_key::masp_token_map_key;
use namada_sdk::token::{self, Amount, DenominatedAmount};
use namada_sdk::tx::Data;
use namada_sdk::{tendermint, DEFAULT_GAS_LIMIT};
use namada_tx_prelude::transaction::{Fee, TxType, WrapperTx};
use namada_vp::state::{FullAccessState, KeySeg};
use test_log::test;

use super::setup;
use crate::e2e::setup::constants::{
    AA_PAYMENT_ADDRESS, AA_VIEWING_KEY, AB_PAYMENT_ADDRESS, AB_VIEWING_KEY,
    AC_PAYMENT_ADDRESS, AC_VIEWING_KEY, ALBERT, ALBERT_KEY, A_SPENDING_KEY,
    BB_PAYMENT_ADDRESS, BERTHA, BERTHA_KEY, BTC, B_SPENDING_KEY, CHRISTEL,
    CHRISTEL_KEY, ETH, MASP, NAM,
};
use crate::strings::TX_APPLIED_SUCCESS;

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.
#[test]
fn masp_incentives() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "1",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a non-zero number (rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });

    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a number greater than the last epoch's balance
    // (more rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18887"));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18963"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Send 0.001 ETH from Albert to PA(B)
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            ETH,
            "--amount",
            "0.001",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert ETH balance at VK(B) is 0.001
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0.001"));

    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert ETH balance at VK(B) is still 0.001
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0.001"));

    // Assert NAM balance at VK(B) is non-zero (rewards have been
    // dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.725514"));

    // Assert NAM balance at MASP pool is an accumulation of
    // rewards from both the shielded BTC and shielded ETH
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.358764"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 0.001 ETH from SK(B) to Christel
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            B_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            ETH,
            "--amount",
            "0.001",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert ETH balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0"));

    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert VK(B) retains the NAM rewards dispensed in the correct
    // amount.
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.451732"));

    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.219616"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Send 1 BTC from SK(A) to Christel
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            A_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            BTC,
            "--amount",
            "1",
            "--signing-keys",
            ALBERT_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    // Assert VK(A) retained the NAM rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2.268662"));

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.723616"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert NAM balance at VK(A) is the rewards dispensed earlier
    // (since VK(A) has no shielded assets, no further rewards should
    //  be dispensed to that account)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2.268662"));

    // Assert NAM balance at VK(B) is the rewards dispensed earlier
    // (since VK(A) has no shielded assets, no further rewards should
    //  be dispensed to that account)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.451732"));

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.723616"));

    // Wait till epoch boundary to prevent conversion expiry during transaction
    // construction
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Send all NAM rewards from SK(B) to Christel
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            B_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            NAM,
            "--gas-limit",
            "300000",
            "--amount",
            "1.451732",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Send all NAM rewards from SK(A) to Bertha
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            A_SPENDING_KEY,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            "2.268662",
            "--signing-keys",
            ALBERT_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert NAM balance at MASP pool is nearly 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.003222"));

    Ok(())
}

/// In this test we ensure that a non-converted asset type (i.e. from an older
/// epoch) can be correctly spent
///
/// 1. Shield some tokens to trigger rewards
/// 2. Shield the minimum amount 10^-6 native tokens
/// 3. Sleep for a few epochs
/// 4. Check the minimum amount is still in the shielded balance
/// 5. Spend this minimum amount succesfully
#[test]
fn spend_unconverted_asset_type() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    let _ep0 = node.next_epoch();

    // 1. Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "20",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // 2. Shield the minimum amount
    node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "0.000001",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // 3. Sleep for a few epochs
    for _ in 0..5 {
        node.next_epoch();
    }
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // 4. Check the shielded balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000001"));

    // 5. Spend the shielded balance
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            B_SPENDING_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "0.000001",
            "--gas-payer",
            CHRISTEL_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Attempt to spend 10 BTC at SK(A) to PA(B)
/// 3. Attempt to spend 15 BTC at SK(A) to Bertha
/// 4. Send 20 BTC from Albert to PA(A)
/// 5. Attempt to spend 10 ETH at SK(A) to PA(B)
/// 6. Spend 7 BTC at SK(A) to PA(B)
/// 7. Spend 7 BTC at SK(A) to PA(B)
/// 8. Attempt to spend 7 BTC at SK(A) to PA(B)
/// 9. Spend 6 BTC at SK(A) to PA(B)
/// 10. Assert BTC balance at VK(A) is 0
/// 11. Assert ETH balance at VK(A) is 0
/// 12. Assert balance at VK(B) is 10 BTC
/// 13. Send 10 BTC from SK(B) to Bertha
#[test]
fn masp_txs_and_queries() -> Result<()> {
    // Uncomment for better debugging
    // let _log_guard = namada_apps_lib::logging::init_from_env_or(
    //     tracing::level_filters::LevelFilter::INFO,
    // )?;
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    enum Response {
        Ok(&'static str),
        Err(&'static str),
    }

    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // add necessary viewing keys to shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    let txs_args = vec![
        // 0. Attempt to spend 10 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Err(""),
        ),
        // 1. Attempt to spend 15 BTC at SK(A) to Bertha
        (
            vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "15",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Err(""),
        ),
        // 2. Send 20 BTC from Albert to PA(A)
        (
            vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "20",
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 3. Attempt to spend 10 ETH at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                ETH,
                "--amount",
                "10",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Err(""),
        ),
        // 4. Spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 5. Spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 6. Attempt to spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Err(""),
        ),
        // 7. Spend 6 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "6",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 8. Assert BTC balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("btc: 0"),
        ),
        // 9. Assert ETH balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("eth: 0"),
        ),
        // 10. Assert balance at VK(B) is 20 BTC
        (
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("btc: 20"),
        ),
        // 11. Send 20 BTC from SK(B) to Bertha
        (
            vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "20",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
    ];

    for (tx_args, tx_result) in &txs_args {
        node.assert_success();
        // there is no need to dry run balance queries
        let dry_run_args = if tx_args[0] == "transfer"
            || tx_args[0] == "shield"
            || tx_args[0] == "unshield"
        {
            // We ensure transfers don't cross epoch boundaries.
            node.next_epoch();
            vec![true, false]
        } else {
            vec![false]
        };
        for &dry_run in &dry_run_args {
            // sync shielded context
            run(
                &node,
                Bin::Client,
                vec!["shielded-sync", "--node", validator_one_rpc],
            )?;
            let tx_args = if dry_run {
                [tx_args.clone(), vec!["--dry-run"]].concat()
            } else {
                tx_args.clone()
            };
            println!(
                "{}: {:?}\n\n",
                "Running".green().underline(),
                tx_args.join(" ").yellow().underline()
            );
            let captured =
                CapturedOutput::of(|| run(&node, Bin::Client, tx_args.clone()));
            match tx_result {
                Response::Ok(TX_APPLIED_SUCCESS) => {
                    assert!(
                        captured.result.is_ok(),
                        "{:?} failed with result {:?}.\n Unread output: {}",
                        tx_args,
                        captured.result,
                        captured.output,
                    );
                    if !dry_run {
                        node.assert_success();
                    } else {
                        assert!(
                            captured.contains(TX_APPLIED_SUCCESS),
                            "{:?} failed to contain needle 'Transaction is \
                             valid',\nGot output '{}'",
                            tx_args,
                            captured.output
                        );
                    }
                }
                Response::Ok(out) => {
                    assert!(
                        captured.result.is_ok(),
                        "{:?} failed with result {:?}.\n Unread output: {}",
                        tx_args,
                        captured.result,
                        captured.output,
                    );
                    assert!(
                        captured.contains(out),
                        "{:?} failed to contain needle '{}',\nGot output '{}'",
                        tx_args,
                        out,
                        captured.output
                    );
                }
                Response::Err(msg) => {
                    assert!(
                        captured.result.is_err(),
                        "{:?} unexpectedly succeeded",
                        tx_args
                    );
                    assert!(
                        captured.contains(msg),
                        "{:?} failed to contain needle {},\nGot output {}",
                        tx_args,
                        msg,
                        captured.output
                    );
                }
            }
        }
    }

    Ok(())
}

/// Tests that multiple transactions can be constructed (without fetching) from
/// the shielded context and executed in the same block
#[test]
fn multiple_unfetched_txs_same_block() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // 1. Shield tokens
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "200",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operations without fetching. Dump the txs to then reload and
    // submit in the same block
    let tempdir = tempfile::tempdir().unwrap();
    let mut txs_bytes = vec![];

    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "50",
            "--gas-payer",
            ALBERT_KEY,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    txs_bytes.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "50",
            "--gas-payer",
            CHRISTEL_KEY,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    txs_bytes.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            B_SPENDING_KEY,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "50",
            "--gas-payer",
            CHRISTEL_KEY,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    txs_bytes.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    let sk = christel_keypair();
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let mut txs = vec![];
    for bytes in txs_bytes {
        let mut tx = namada_sdk::tx::Tx::deserialize(&bytes).unwrap();
        tx.add_wrapper(
            namada_sdk::tx::data::wrapper::Fee {
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token: native_token.clone(),
            },
            pk.clone(),
            DEFAULT_GAS_LIMIT.into(),
        );
        tx.sign_wrapper(sk.clone());

        txs.push(tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);
    // If empty than failed in process proposal
    assert!(!node.tx_result_codes.lock().unwrap().is_empty());
    node.assert_success();

    Ok(())
}

/// Tests that an expired masp tx is rejected by the vp
#[test]
fn expired_masp_tx() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // 1. Shield tokens
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operation to avoid the need of a signature on the inner tx.
    //    Dump the tx to then reload and submit
    let tempdir = tempfile::tempdir().unwrap();

    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "50",
            "--gas-payer",
            CHRISTEL_KEY,
            // We want to create an expired masp tx. Doing so will also set the
            // expiration field of the header which can be a problem because
            // this would lead to the transaction being rejected by the
            // protocol check while we want to test expiration in the masp vp.
            // However, this is not a real issue: to avoid the failure in
            // protocol we are going to overwrite the header with one having no
            // expiration
            "--expiration",
            #[allow(clippy::disallowed_methods)]
            &DateTimeUtc::now().to_string(),
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    let sk = christel_keypair();
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let mut tx = namada_sdk::tx::Tx::deserialize(&tx_bytes).unwrap();
    // Remove the expiration field to avoid a failure because of it, we only
    // want to check the expiration in the masp vp
    tx.header.expiration = None;
    tx.add_wrapper(
        namada_sdk::tx::data::wrapper::Fee {
            amount_per_gas_unit: DenominatedAmount::native(1.into()),
            token: native_token.clone(),
        },
        pk.clone(),
        DEFAULT_GAS_LIMIT.into(),
    );
    tx.sign_wrapper(sk.clone());
    let wrapper_hash = tx.wrapper_hash();
    let inner_cmt = tx.first_commitments().unwrap();

    // Skip at least 20 blocks to ensure expiration (this is because of the
    // default masp expiration)
    for _ in 0..=20 {
        node.finalize_and_commit(None);
    }
    node.clear_results();
    node.submit_txs(vec![tx.to_bytes()]);
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty than failed in process proposal
        assert!(!codes.is_empty());

        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok));
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted a single batch
        assert_eq!(results.len(), 1);

        for result in results.iter() {
            // The batch should contain a single inner tx
            assert_eq!(result.0.len(), 1);

            let inner_tx_result = result
                .get_inner_tx_result(
                    wrapper_hash.as_ref(),
                    itertools::Either::Right(inner_cmt),
                )
                .expect("Missing expected tx result")
                .as_ref()
                .expect("Result is supposed to be Ok");

            assert!(inner_tx_result
                .vps_result
                .rejected_vps
                .contains(&namada_sdk::address::MASP));
            assert!(inner_tx_result.vps_result.errors.contains(&(
                namada_sdk::address::MASP,
                "Native VP error: MASP transaction is expired".to_string()
            )));
        }
    }

    Ok(())
}

// Test that a masp unshield transaction can be succesfully executed even across
// an epoch boundary.
#[test]
fn cross_epoch_unshield() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // 1. Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "1000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // 2. Generate the tx in the current epoch
    let tempdir = tempfile::tempdir().unwrap();
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            A_SPENDING_KEY,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            "100",
            "--gas-payer",
            ALBERT_KEY,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Look for the only file in the temp dir
    let tx_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();

    // 3. Submit the unshielding in the following epoch
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        vec![
            "tx",
            "--owner",
            ALBERT_KEY,
            "--tx-path",
            tx_path.to_str().unwrap(),
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    Ok(())
}

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.
#[test]
fn dynamic_assets() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let (mut node, _services) = setup::setup()?;
    let btc = BTC.to_lowercase();
    let nam = NAM.to_lowercase();

    let token_map_key = masp_token_map_key();
    let test_tokens = {
        // Only distribute rewards for NAM tokens
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        let test_tokens = tokens.clone();
        tokens.retain(|k, _v| *k == nam);
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens.clone())
            .unwrap();
        test_tokens
    };
    // add necessary viewing keys to shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "1",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    {
        // Start decoding and distributing shielded rewards for BTC in next
        // epoch
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        tokens.insert(btc.clone(), test_tokens[&btc].clone());
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens)
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is still 0 since rewards were still not being
    // distributed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "1",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is now 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert NAM balance at VK(A) is still 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert that VK(A) has now received a NAM rewward for second deposit
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.06262"));

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    {
        // Stop distributing shielded rewards for NAM in next epoch
        let storage = &mut node.shell.lock().unwrap().state;
        storage
            .write(
                &token::storage_key::masp_max_reward_rate_key(
                    &test_tokens[&nam],
                ),
                Dec::zero(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that VK(A) has now received a NAM rewward for second deposit
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.15655"));

    {
        // Stop decoding and distributing shielded rewards for BTC in next epoch
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        tokens.remove(&btc);
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens)
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is still the same
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.15655"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is still the same
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.15655"));

    {
        // Start distributing shielded rewards for NAM in next epoch
        let storage = &mut node.shell.lock().unwrap().state;
        storage
            .write(
                &token::storage_key::masp_max_reward_rate_key(
                    &test_tokens[&nam],
                ),
                Dec::from_str("0.1").unwrap(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is now increasing
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.156705"));

    Ok(())
}

// Test fee payment in masp:
//
// 1. Masp fee payment runs out of gas
// 2. Attempt fee payment with a non-MASP transaction
// 3. Valid fee payment (also check that the first tx in the batch is executed
//    only once)
#[test]
fn masp_fee_payment() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "500000",
            "--gas-payer",
            CHRISTEL_KEY,
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    _ = node.next_masp_epoch();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 500000"));

    // 1. Out of gas for masp fee payment
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "20000",
                "--gas-price",
                "1",
                "--disposable-gas-payer",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_err());
    _ = node.next_masp_epoch();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 500000"));

    // 2. Attempt fee payment with non-MASP transfer
    // Drain balance of Albert implicit
    run(
        &node,
        Bin::Client,
        vec![
            "transparent-transfer",
            "--source",
            ALBERT_KEY,
            "--target",
            BERTHA_KEY,
            "--token",
            NAM,
            "--amount",
            "1500000",
            "--gas-payer",
            CHRISTEL_KEY,
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Gas payer is Albert implicit, whose balance is 0. Let's try to
    // transparently send some tokens (enough to pay fees) to him and check that
    // this is not allowed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transparent-transfer",
                "--source",
                BERTHA_KEY,
                "--target",
                ALBERT_KEY,
                "--token",
                NAM,
                "--amount",
                "200000",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
                // Force to skip check in client
                "--force",
            ],
        )
    });
    assert!(captured.result.is_err());

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // 3. Valid masp fee payment
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "10000",
            "--gas-price",
            "1",
            "--disposable-gas-payer",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();
    // Check the exact balance of the tx source to ensure that the masp fee
    // payment transaction was executed only once
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 240000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 10000"));

    Ok(())
}

// Test that when paying gas via masp we select the gas limit as the minimum
// between the transaction's gas limit and the protocol parameter.
#[test]
fn masp_fee_payment_gas_limit() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Set an insufficient gas limit for masp fee payment to force all
        // transactions to fail
        genesis.parameters.parameters.masp_fee_payment_gas_limit = 10_000;
        genesis
    })?;
    _ = node.next_masp_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "1000000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Check that the balance hasn't changed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000000"));

    // Masp fee payment with huge gas, check that the tx still fails because of
    // the protocol param
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "500000",
                "--gas-price",
                "1",
                "--disposable-gas-payer",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_err());
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Check that the balance hasn't changed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000000"));

    Ok(())
}

// Test masp fee payement with an unshield to a non-disposable address with
// already some funds on it.
#[test]
fn masp_fee_payment_with_non_disposable() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            // Decrease payer's balance to 1
            "1999999",
            // Pay gas transparently
            "--gas-payer",
            BERTHA_KEY,
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1999999"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    // Masp fee payment to non-disposable address
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "300000",
                "--gas-price",
                "1",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1699999"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    Ok(())
}

// Test masp fee payement with a custom provided spending key. Check that fees
// are split between the actual source of the payment and this gas spending
// key
#[test]
fn masp_fee_payment_with_custom_spending_key() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_c",
            "--value",
            AC_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "10000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "300000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 10000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 300000"));

    // Masp fee payment with custom gas payer
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "9000",
                "--gas-limit",
                "300000",
                "--gas-price",
                "1",
                "--gas-spending-key",
                B_SPENDING_KEY,
                "--disposable-gas-payer",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 9000"));

    Ok(())
}

// Test masp fee payement with a different token from the one used in the
// transaction itself and with the support of a different key for gas payment
#[test]
fn masp_fee_payment_with_different_token() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Whitelist BTC for gas payment
        genesis.parameters.parameters.minimum_gas_price.insert(
            "btc".into(),
            DenominatedAmount::new(1.into(), token::Denomination(6)),
        );
        genesis
    })?;
    _ = node.next_masp_epoch();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_b",
            "--value",
            AB_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "1",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "1000",
            "--gas-payer",
            ALBERT_KEY,
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "300000",
            "--gas-payer",
            ALBERT_KEY,
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 300000"));

    // Masp fee payment with custom token and gas payer
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-token",
                BTC,
                "--gas-limit",
                "300000",
                "--gas-price",
                "1",
                "--gas-spending-key",
                B_SPENDING_KEY,
                "--disposable-gas-payer",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    node.assert_success();

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1000"));

    Ok(())
}

// An ouput description of the masp can be replayed (pushed to the commitment
// tree more than once). The nullifiers and merkle paths will be unique. Test
// that a batch containing two identical shielding txs can be executed correctly
// and the two identical notes can be spent with no issues.
#[test]
fn identical_output_descriptions() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Add the relevant viewing keys to the wallet otherwise the shielded
    // context won't precache the masp data
    run(
        &node,
        Bin::Wallet,
        vec![
            "add",
            "--alias",
            "alias_a",
            "--value",
            AA_VIEWING_KEY,
            "--unsafe-dont-encrypt",
        ],
    )?;
    node.assert_success();

    // Generate a tx to shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "1000",
            "--gas-limit",
            "300000",
            "--gas-payer",
            ALBERT_KEY,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    // Create a batch that contains the same shielding tx twice
    let tx: namada_sdk::tx::Tx = serde_json::from_slice(&tx_bytes).unwrap();
    // Inject some randomness in the cloned tx to change the hash
    let mut tx_clone = tx.clone();
    let mut cmt = tx_clone.header.batch.first().unwrap().to_owned();
    let random_hash: Vec<_> = (0..namada_sdk::hash::HASH_LENGTH)
        .map(|_| rand::random::<u8>())
        .collect();
    cmt.memo_hash = namada_sdk::hash::Hash(random_hash.try_into().unwrap());
    tx_clone.header.batch.clear();
    tx_clone.header.batch.insert(cmt);

    let signing_data = SigningTxData {
        owner: None,
        public_keys: vec![albert_keypair().to_public()],
        threshold: 1,
        account_public_keys_map: None,
        fee_payer: albert_keypair().to_public(),
    };

    let (mut batched_tx, _signing_data) = namada_sdk::tx::build_batch(vec![
        (tx, signing_data.clone()),
        (tx_clone, signing_data),
    ])
    .unwrap();

    batched_tx.sign_raw(
        vec![albert_keypair()],
        AccountPublicKeysMap::from_iter(
            vec![(albert_keypair().to_public())].into_iter(),
        ),
        None,
    );
    batched_tx.sign_wrapper(albert_keypair());

    let wrapper_hash = batched_tx.wrapper_hash();
    let inner_cmts = batched_tx.commitments();

    let txs = vec![batched_tx.to_bytes()];

    node.clear_results();
    node.submit_txs(txs);

    // Check that the batch was successful
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty than failed in process proposal
        assert!(!codes.is_empty());

        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok));
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted a single batch
        assert_eq!(results.len(), 1);

        for result in results.iter() {
            // The batch should contain a two inner tx
            assert_eq!(result.0.len(), 2);

            for inner_cmt in inner_cmts {
                let inner_tx_result = result
                    .get_inner_tx_result(
                        wrapper_hash.as_ref(),
                        itertools::Either::Right(inner_cmt),
                    )
                    .expect("Missing expected tx result")
                    .as_ref()
                    .expect("Result is supposed to be Ok");

                assert!(inner_tx_result.is_accepted());
            }
        }
    }

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Assert NAM balance at VK(A) is 2000
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                CHRISTEL,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2000000"));

    // Spend both notes successfully
    run(
        &node,
        Bin::Client,
        vec![
            "unshield",
            "--source",
            A_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            NAM,
            // Spend the entire shielded amount
            "--amount",
            "2000",
            "--gas-payer",
            BERTHA_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                CHRISTEL,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2002000"));

    Ok(())
}

//FIXME: describe the test
#[test]
fn shielded_actions() -> Result<()> {
    //FIXME: describe the content
    //FIXME: maybe base64?
    //FIXME: remove?
    // const ENCODED_IBC_PACKET: &str = "0A222F6962632E636F72652E6368616E6E656C2E76312E4D7367526563765061636B657412A0190A9414080112087472616E736665721A096368616E6E656C2D3022087472616E736665722A096368616E6E656C2D3032D6137B22616D6F756E74223A22313030222C2264656E6F6D223A2273616D6F6C65616E73222C226D656D6F223A2230323030303030303041323741373236413637354646453930303030303030304142304530303030303132333341364634464641413446353146313337393637353245353032364136333245333139444542423435454642304134343444423632453046363041323446363430303030303030303030303030303942443136324643373443324239334437333035433945353034414142314436393846364439333430303030303030313446373235393437353937374535433144393434333632443935384643373346303941383942374535353032394143394534433944363938313044374243324632433537443331363730324346373537363539443235433434464538423139363731323743424431334546394542434134393030413139343238464546313330313735344231374245443545323830434234464145443234434341344546383337303943444238423743384337354432433833313846383246464137343335444142423236434339323642394134354637343931443845364543343530453246314537373242373132393444313637434531384334393535413731413332444635444641324437414146373332383834433042343445363030424334383643383237444234423132313132423031393331414338423831393434453143353436424137413541374235383435464645304346334130354444374139424346413735443443383037363943303033383045383945394438443531413043373031414537423943323445353933374631464645414639453134363431304445463141443531303733433937453545393146354445384231383941363342353338423142343230433742413345314341454145333635323031323839343235433139363132363144313746434632443442353741323034343537433538363531433242324333383038384646354633414531383245344146313142414143433236413032353234444245463431463330374244383232304646394535364232343630333845394233363638383144323845313331433533424242454334434344433337443341323334324446304532324232353844443737463343413546303937363545453637464446453239424335384346394643453538383344464142343941373645383746393635313938423136424646443930434535433439444631354531364233454138354230414545423042374331453138323135413231353034313031383638434533443842453933373632453335433435423537314535394333443543463541423438323338313433383442413730393630443632374132363345394241383745323030394443454145433942313433343530323845303444343537334337454334433237353839354436454244313343454346313232334231323633424537303639313638444131453436324546443930413934423436374633463842374346304144343746393846423736434638364630323644373130313538444543414336313546423837454439454532384537433736304441453038373241323137443744383532333930323939373431383838323243303142423035414532443136323033304537393038393343303437344334324138323836433032384237304344394537463438393134343042433035383645453639383239304145383744443044433736323346333039383930353444383535453034373335343943323337353642443143453135413933334144414536443034453433443833464337304530333146313543343033393035443939424434444533353633453330313836434434463032334641303637354536454331373042334146344538303338463242304342383442324639383643464430334434374643344631303135453244384537414637423942393741363039353439463330433839383041393236334138414336424144323736443132393743423435433434313634434341353146464233373642314432383138394245363645463945343336353234353644333145463233393537343035363531384332433632303938363345464644303546384530424446333043373032384437323342464532373330433732313633463645313343444336453133423330394446343644353833314137324438313735334138463244443245323236424443333837324437453436323136394634463437353937354233434546343546433244333045383534304244443439454246384233334244454432424646314531373844454642333034364530354245304338334238333243393335413644393439304544323043303846323137414536334432344432464544463446373541423943433645334136424333463035334336443244453130303930313233334136463446464141344635314631333739363735324535303236413633324533313944454242343545464230413434344442363245304636304132344639434646464646464646464646464646464646464646464646464646464646463937463144334137333139374437393432363935363338433446413941433046433336383843344639373734423930354131344533413346313731424143353836433535453833464639374131414546464233414630304144423232433642423933453032423630353237313946363037444143443341303838323734463635353936424430443039393230423631414235444136314242444337463530343933333443463131323133393435443537453541433744303535443034324237453032344141324232463038463041393132363038303532373244433531303531433645343741443446413430334230324234353130423634374145334431373730424143303332364138303542424546443438303536433843313231424442383937463144334137333139374437393432363935363338433446413941433046433336383843344639373734423930354131344533413346313731424143353836433535453833464639374131414546464233414630304144423232433642423838393139443134453841463936314336464443424330373635314232364337413136413334313041454141453937323335323842343136443730334333323639364136463835373933434633343841344339314543383832354446374531414541414437373937424144343041324142463130374335343442413434323042222C227265636569766572223A22746E616D31706371717171717171717171717171717171717171717171717171717171717171717A6D65666168222C2273656E646572223A22636F736D6F7331387A346374653075757A6E6A76356839366B737A726435336E6D6E64727671736E7436656E34227D3A0310E10840F8BB87CDA89FC4FC1712D2040ACE020ACB020A39636F6D6D69746D656E74732F706F7274732F7472616E736665722F6368616E6E656C732F6368616E6E656C2D302F73657175656E6365732F3112207A9E6740AC57A3EB808FD292922FD5AC22113888DE3B9A9DA3262E184FEC75E41A0C0801180120012A040002FE01222A080112260204FE01206C0D328F60E2160A50E5978563B8DD5E8FBE17AE5CB24A208044B9B90623023520222C080112050408FE01201A212000D0AB6C4D5D4F30E80315A3FD90B6FAC55AA11E313CC8E0E5BE8068B625BD3E222C080112050816FE01201A212080EB59589EB5AB7F250B49376C72D3E59BFC9078F52105F811BFACDDFC8CEE70222A080112260A32FE0120F2B700D4AC8276D1E9435186A44FDA8EF8D81B3CBB0D0217D83D0353699AC4C220222A080112260C50FE01205C138BB1FBBD423692CC5C75B51EBCA54A39772699E5F3E6888E2B419DE885D0200AFE010AFB010A0369626312203EA8E34C98426043BAFEF279FAE5F27671E42AEF8D2BDC76840DD2583AA6B9341A090801180120012A0100222708011201011A202CD8B50700950546180AD979135A8708C2EA2098FFF6ADE31B7E40EB5DCF7C05222708011201011A203508165648223BC45E2BD6B7A57C1B4B8EA1C5BDA2D075F8CAE9BB3A197705E72225080112210100EC3C35CC9F02B4B9911DDFF5896ECE038C21B3A2D2F43F77168A90A6AD1BB022250801122101404AFFF7EB48C1A7862879130A05B1B1BE8BFB7388C6356667B56B65AE22144B222708011201011A20D3B8269EC4AA0913FB18124E9F949E284DA29C53C36C9A4744235BC41BD5C3BD1A03108001222D746E616D31717A306E7665633638366539706B7338796E686D35646471386B65376A3265657935307561677472";

    // const ENCODED_IBC_PACKET: &str = "CiIvaWJjLmNvcmUuY2hhbm5lbC52MS5Nc2dSZWN2UGFja2V0EqAZCpQUCAESCHRyYW5zZmVyGgljaGFubmVsLTAiCHRyYW5zZmVyKgljaGFubmVsLTAy1hN7ImFtb3VudCI6IjEwMCIsImRlbm9tIjoic2Ftb2xlYW5zIiwibWVtbyI6IjAyMDAwMDAwMEEyN0E3MjZBNjc1RkZFOTAwMDAwMDAwQUIwRTAwMDAwMTIzM0E2RjRGRkFBNEY1MUYxMzc5Njc1MkU1MDI2QTYzMkUzMTlERUJCNDVFRkIwQTQ0NERCNjJFMEY2MEEyNEY2NDAwMDAwMDAwMDAwMDAwOUJEMTYyRkM3NEMyQjkzRDczMDVDOUU1MDRBQUIxRDY5OEY2RDkzNDAwMDAwMDAxNEY3MjU5NDc1OTc3RTVDMUQ5NDQzNjJEOTU4RkM3M0YwOUE4OUI3RTU1MDI5QUM5RTRDOUQ2OTgxMEQ3QkMyRjJDNTdEMzE2NzAyQ0Y3NTc2NTlEMjVDNDRGRThCMTk2NzEyN0NCRDEzRUY5RUJDQTQ5MDBBMTk0MjhGRUYxMzAxNzU0QjE3QkVENUUyODBDQjRGQUVEMjRDQ0E0RUY4MzcwOUNEQjhCN0M4Qzc1RDJDODMxOEY4MkZGQTc0MzVEQUJCMjZDQzkyNkI5QTQ1Rjc0OTFEOEU2RUM0NTBFMkYxRTc3MkI3MTI5NEQxNjdDRTE4QzQ5NTVBNzFBMzJERjVERkEyRDdBQUY3MzI4ODRDMEI0NEU2MDBCQzQ4NkM4MjdEQjRCMTIxMTJCMDE5MzFBQzhCODE5NDRFMUM1NDZCQTdBNUE3QjU4NDVGRkUwQ0YzQTA1REQ3QTlCQ0ZBNzVENEM4MDc2OUMwMDM4MEU4OUU5RDhENTFBMEM3MDFBRTdCOUMyNEU1OTM3RjFGRkVBRjlFMTQ2NDEwREVGMUFENTEwNzNDOTdFNUU5MUY1REU4QjE4OUE2M0I1MzhCMUI0MjBDN0JBM0UxQ0FFQUUzNjUyMDEyODk0MjVDMTk2MTI2MUQxN0ZDRjJENEI1N0EyMDQ0NTdDNTg2NTFDMkIyQzM4MDg4RkY1RjNBRTE4MkU0QUYxMUJBQUNDMjZBMDI1MjREQkVGNDFGMzA3QkQ4MjIwRkY5RTU2QjI0NjAzOEU5QjM2Njg4MUQyOEUxMzFDNTNCQkJFQzRDQ0RDMzdEM0EyMzQyREYwRTIyQjI1OERENzdGM0NBNUYwOTc2NUVFNjdGREZFMjlCQzU4Q0Y5RkNFNTg4M0RGQUI0OUE3NkU4N0Y5NjUxOThCMTZCRkZEOTBDRTVDNDlERjE1RTE2QjNFQTg1QjBBRUVCMEI3QzFFMTgyMTVBMjE1MDQxMDE4NjhDRTNEOEJFOTM3NjJFMzVDNDVCNTcxRTU5QzNENUNGNUFCNDgyMzgxNDM4NEJBNzA5NjBENjI3QTI2M0U5QkE4N0UyMDA5RENFQUVDOUIxNDM0NTAyOEUwNEQ0NTczQzdFQzRDMjc1ODk1RDZFQkQxM0NFQ0YxMjIzQjEyNjNCRTcwNjkxNjhEQTFFNDYyRUZEOTBBOTRCNDY3RjNGOEI3Q0YwQUQ0N0Y5OEZCNzZDRjg2RjAyNkQ3MTAxNThERUNBQzYxNUZCODdFRDlFRTI4RTdDNzYwREFFMDg3MkEyMTdEN0Q4NTIzOTAyOTk3NDE4ODgyMkMwMUJCMDVBRTJEMTYyMDMwRTc5MDg5M0MwNDc0QzQyQTgyODZDMDI4QjcwQ0Q5RTdGNDg5MTQ0MEJDMDU4NkVFNjk4MjkwQUU4N0REMERDNzYyM0YzMDk4OTA1NEQ4NTVFMDQ3MzU0OUMyMzc1NkJEMUNFMTVBOTMzQURBRTZEMDRFNDNEODNGQzcwRTAzMUYxNUM0MDM5MDVEOTlCRDRERTM1NjNFMzAxODZDRDRGMDIzRkEwNjc1RTZFQzE3MEIzQUY0RTgwMzhGMkIwQ0I4NEIyRjk4NkNGRDAzRDQ3RkM0RjEwMTVFMkQ4RTdBRjdCOUI5N0E2MDk1NDlGMzBDODk4MEE5MjYzQThBQzZCQUQyNzZEMTI5N0NCNDVDNDQxNjRDQ0E1MUZGQjM3NkIxRDI4MTg5QkU2NkVGOUU0MzY1MjQ1NkQzMUVGMjM5NTc0MDU2NTE4QzJDNjIwOTg2M0VGRkQwNUY4RTBCREYzMEM3MDI4RDcyM0JGRTI3MzBDNzIxNjNGNkUxM0NEQzZFMTNCMzA5REY0NkQ1ODMxQTcyRDgxNzUzQThGMkREMkUyMjZCREMzODcyRDdFNDYyMTY5RjRGNDc1OTc1QjNDRUY0NUZDMkQzMEU4NTQwQkRENDlFQkY4QjMzQkRFRDJCRkYxRTE3OERFRkIzMDQ2RTA1QkUwQzgzQjgzMkM5MzVBNkQ5NDkwRUQyMEMwOEYyMTdBRTYzRDI0RDJGRURGNEY3NUFCOUNDNkUzQTZCQzNGMDUzQzZEMkRFMTAwOTAxMjMzQTZGNEZGQUE0RjUxRjEzNzk2NzUyRTUwMjZBNjMyRTMxOURFQkI0NUVGQjBBNDQ0REI2MkUwRjYwQTI0RjlDRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGOTdGMUQzQTczMTk3RDc5NDI2OTU2MzhDNEZBOUFDMEZDMzY4OEM0Rjk3NzRCOTA1QTE0RTNBM0YxNzFCQUM1ODZDNTVFODNGRjk3QTFBRUZGQjNBRjAwQURCMjJDNkJCOTNFMDJCNjA1MjcxOUY2MDdEQUNEM0EwODgyNzRGNjU1OTZCRDBEMDk5MjBCNjFBQjVEQTYxQkJEQzdGNTA0OTMzNENGMTEyMTM5NDVENTdFNUFDN0QwNTVEMDQyQjdFMDI0QUEyQjJGMDhGMEE5MTI2MDgwNTI3MkRDNTEwNTFDNkU0N0FENEZBNDAzQjAyQjQ1MTBCNjQ3QUUzRDE3NzBCQUMwMzI2QTgwNUJCRUZENDgwNTZDOEMxMjFCREI4OTdGMUQzQTczMTk3RDc5NDI2OTU2MzhDNEZBOUFDMEZDMzY4OEM0Rjk3NzRCOTA1QTE0RTNBM0YxNzFCQUM1ODZDNTVFODNGRjk3QTFBRUZGQjNBRjAwQURCMjJDNkJCODg5MTlEMTRFOEFGOTYxQzZGRENCQzA3NjUxQjI2QzdBMTZBMzQxMEFFQUFFOTcyMzUyOEI0MTZENzAzQzMyNjk2QTZGODU3OTNDRjM0OEE0QzkxRUM4ODI1REY3RTFBRUFBRDc3OTdCQUQ0MEEyQUJGMTA3QzU0NEJBNDQyMEIiLCJyZWNlaXZlciI6InRuYW0xcGNxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXptZWZhaCIsInNlbmRlciI6ImNvc21vczE4ejRjdGUwdXV6bmp2NWg5NmtzenJkNTNubW5kcnZxc250NmVuNCJ9OgMQ4QhA+LuHzaifxPwXEtIECs4CCssCCjljb21taXRtZW50cy9wb3J0cy90cmFuc2Zlci9jaGFubmVscy9jaGFubmVsLTAvc2VxdWVuY2VzLzESIHqeZ0CsV6PrgI/SkpIv1awiETiI3juanaMmLhhP7HXkGgwIARgBIAEqBAAC/gEiKggBEiYCBP4BIGwNMo9g4hYKUOWXhWO43V6PvheuXLJKIIBEubkGIwI1ICIsCAESBQQI/gEgGiEgANCrbE1dTzDoAxWj/ZC2+sVaoR4xPMjg5b6AaLYlvT4iLAgBEgUIFv4BIBohIIDrWVietat/JQtJN2xy0+Wb/JB49SEF+BG/rN38jO5wIioIARImCjL+ASDytwDUrIJ20elDUYakT9qO+NgbPLsNAhfYPQNTaZrEwiAiKggBEiYMUP4BIFwTi7H7vUI2ksxcdbUevKVKOXcmmeXz5oiOK0Gd6IXQIAr+AQr7AQoDaWJjEiA+qONMmEJgQ7r+8nn65fJ2ceQq740r3HaEDdJYOqa5NBoJCAEYASABKgEAIicIARIBARogLNi1BwCVBUYYCtl5E1qHCMLqIJj/9q3jG35A613PfAUiJwgBEgEBGiA1CBZWSCI7xF4r1relfBtLjqHFvaLQdfjK6bs6GXcF5yIlCAESIQEA7Dw1zJ8CtLmRHd/1iW7OA4whs6LS9D93FoqQpq0bsCIlCAESIQFASv/360jBp4YoeRMKBbGxvov7c4jGNWZntWtlriIUSyInCAESAQEaINO4Jp7EqgkT+xgSTp+UnihNopxTw2yaR0QjW8Qb1cO9GgMQgAEiLXRuYW0xcXowbnZlYzY4NmU5cGtzOHluaG01ZGRxOGtlN2oyZWV5NTB1YWd0cg==";

    //FIXME: describe
    const ENCODED_IBC_PACKET: &str = "CiIvaWJjLmNvcmUuY2hhbm5lbC52MS5Nc2dSZWN2UGFja2V0Ep8ZCpQUCAESCHRyYW5zZmVyGgljaGFubmVsLTAiCHRyYW5zZmVyKgljaGFubmVsLTAy1hN7ImFtb3VudCI6IjEwMCIsImRlbm9tIjoic2Ftb2xlYW5zIiwibWVtbyI6IjAyMDAwMDAwMEEyN0E3MjZBNjc1RkZFOTAwMDAwMDAwOTcwRTAwMDAwMTIzM0E2RjRGRkFBNEY1MUYxMzc5Njc1MkU1MDI2QTYzMkUzMTlERUJCNDVFRkIwQTQ0NERCNjJFMEY2MEEyNEY2NDAwMDAwMDAwMDAwMDAwOUJEMTYyRkM3NEMyQjkzRDczMDVDOUU1MDRBQUIxRDY5OEY2RDkzNDAwMDAwMDAxQUREQzQzREEwQjRGQUEwMTAwRUM3QTlEQzQ1RTBEMTM4NTgxNjVEMUM4RjFCQjhGNzc0NUE3QkJGQjc1QzM0MEVGMUFCNUMzNzM0OTVCNjA4NDI5RURBNDA5RkJCOTk4NUMxMUI3REI2QjdGMEZGRDAyRkQ2N0U1QkJENEQ2MkM2NTZGMjZCMzY2QUFCNTk4NTY2NTg2OUI5MTdFNzM3REZGMDFEMzY2RjZDRUNCNDlFMUVCRUQ5OEUxMjRFRkJEOTM1MUUwNDI1N0U2RDY5QjIwNUQxMjE3MUQ4RkY0NjFGNjRBNjcwQ0Y0QTQ4RjNFNjVDRjE4RTJGQTcyN0VGNjA4NDE1MDIxMTA3QUEwREZFQzc5NTE0NDY1RkZEQjREMUM4OUZENjIxNzFEQ0Y1QzgxQzYzOEQ3ODQ5QzlGOTNERTcyQjdBNDQwNzE4RUE4NUNBODVDMzA5N0UxQzc2REQwQUExREE4QjI5ODQ5NUE1QTJEQ0VGMkNBMUQ2NjQzRTlGQUJFMjdDQ0U0MUQ1RDlFNUI0MzZFQUY3QTc4RTNENDg3RTgwMTg5MTZCODVCMEJCNzFBNkIwQzlCOUJFNDA0NUI5OEJERDg1NzIxMjBEMzdGRDE3RURGRUMxMTY2MTZCQjQwNTNCRjIzMjgwODgxQjM2MTRBREUzMTk2ODJDRUU1QkE4MkNBNzBGNzVGOEE0RThDNTdCMEJERkQ2N0I5MjczQjBDOUU1OUE1QkExNEE4RUU2QThDRTdENTRCNzQ4M0NDRThDMDc4NEUzMkVFNDMzMkFGMUE2OTc4QjNFRjZCQTIzRjBDMDAwQjgwNkQxOTQyMTkxRkY1Rjg4RTIwNjJFM0ZGQ0IxQTQ2MzYyOEI5QzBFQTY0Rjg5NDkyMjk5RjNGRUM5MUQ2NTBBMkU1MURFNjAyQzA2QjhFOEI4RjNFMjdGQzg4MjAzRDdDMkU0OEYzNjAxRDBGRDAwMTk5NUE1M0Q5Q0RGM0MyNkRCNEQ4Q0YxNjdDQzVGRDE1NDA0RTQ5QjEyNzcxQzc1QTdBQURBNDMwODUxMTc2MzJBOUM0RDIwMjZGRTg1NEUxMkM2RURGMkRFREM3QkRDOURFQ0VDQ0YxRjZCNjU5N0Q3ODhFMjg1NkJBNDA1OEZFQjUxNzAzMDc4MzI1MTZFOTI0RjFFODM2MUI5N0U2RDM0MkFCQTdFQkQxNDI3RkUxMDY3Njc2NUI5QTBDQThEOEY1RkIyODM2OEEzQUFEMzNENEZGMUE5QzNDRjJBNUM5REI2ODhCNzBGRjdGNkJGNEJGODRCQUQ0Rjc5OUQ2QUM3QzBFN0M2NzhBRkQxODZBNjZFMUM5NEE1NkFCNjg1QjY1OTRFQzYxREJEREJFMjdDM0RGMzVGMjJEQjEyNkUzRUJCMDYxQkE2OTdGQzAxQkIyQkYzRENCNDAzRDQxRjVEODk1MjY2MzMyRDI4RUUxRTYwMkYwN0Q4NTM5OEEzNDNFRThDRDNDOEQxQUVFQTZBRDRGMkYyRThFMjI5NEQzN0IzNkJDQkIxNkFCMUNDNTVCRjMxRTdGMkRENTA4NDVGQjI1NjQxRDBBNzA2N0UwRkQ3MEExRjA4RDVDQzhGRERGNjUyNzE0RTExRTI4RkRGNkQ0QUEwMDQzRjY3MzI1RjM3MjhBRTlERDQxQkM2REUyNzM0RDBFMUM5RDVEOTdCM0I0MjU2NDgxRUMyMkY0MDlGRkY2QzEzNjlFRDQ0MTM0MzhFMDRDOTZBMjIwMEZBQjkxRUI3ODIyOEM2NDEyODY2MURCMDQyOERFQUYyQ0ZBOTgwQ0E5MDAyODFENjZCOURCN0UwMTlDRkRERDc2NEI1NzQ0MTZDMDM0MkZEQzVFRUQ4QjVDRUIxRTI0MzVFQzNDNzJDQTE2NUVBQjVBNDIwQ0VGQzY4MkJFN0VBMERDNUVFRTkzODQyRTBCOEZBMDZEREQ1QTQ0Q0IzQzUwQUMyNTRDRkZBNURBRDZBN0NCMTNGQzkwQkQwQzI1OUMwNDAyMTEwMjZFNkY2Rjk3NjdGOTE5MEFCM0M1ODcyOTlDNkE4NTJCNEVDOEEyNzI4Q0IzQTlDMTAxMjMzQTZGNEZGQUE0RjUxRjEzNzk2NzUyRTUwMjZBNjMyRTMxOURFQkI0NUVGQjBBNDQ0REI2MkUwRjYwQTI0RjlDRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGOTdGMUQzQTczMTk3RDc5NDI2OTU2MzhDNEZBOUFDMEZDMzY4OEM0Rjk3NzRCOTA1QTE0RTNBM0YxNzFCQUM1ODZDNTVFODNGRjk3QTFBRUZGQjNBRjAwQURCMjJDNkJCOTNFMDJCNjA1MjcxOUY2MDdEQUNEM0EwODgyNzRGNjU1OTZCRDBEMDk5MjBCNjFBQjVEQTYxQkJEQzdGNTA0OTMzNENGMTEyMTM5NDVENTdFNUFDN0QwNTVEMDQyQjdFMDI0QUEyQjJGMDhGMEE5MTI2MDgwNTI3MkRDNTEwNTFDNkU0N0FENEZBNDAzQjAyQjQ1MTBCNjQ3QUUzRDE3NzBCQUMwMzI2QTgwNUJCRUZENDgwNTZDOEMxMjFCREI4OTdGMUQzQTczMTk3RDc5NDI2OTU2MzhDNEZBOUFDMEZDMzY4OEM0Rjk3NzRCOTA1QTE0RTNBM0YxNzFCQUM1ODZDNTVFODNGRjk3QTFBRUZGQjNBRjAwQURCMjJDNkJCMjhBNjQ1NEVCNjA5RUVGMDIwMkM2M0U4NDgzNDZBQjhCQUYwRDNFOTNENDVENzFBOUUyODBBNDc4QkZEMjMxRDNEQjVFMTkxNkVERjA2OTQzMDU4QjkwNzBFMjdCRTVEQzhFRTM4RDU2MEYwN0Y2NDg2RTJGRkIwQUMxQzVDMDAiLCJyZWNlaXZlciI6InRuYW0xcGNxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXptZWZhaCIsInNlbmRlciI6ImNvc21vczF4MmZ4dWtmOXMwY3lhdHZoaGd3dmNxbHV5NG1hdXFsenlmNmRmeiJ9OgMQzQhAwOfSruvo05QaEtIECs4CCssCCjljb21taXRtZW50cy9wb3J0cy90cmFuc2Zlci9jaGFubmVscy9jaGFubmVsLTAvc2VxdWVuY2VzLzESIBERtD2C3Vn0hptBbhGZ/A/MYKsjOhHibR7y8rLwOVnhGgwIARgBIAEqBAAC2AEiKggBEiYCBNgBID1ximd4CoC/GwHsQKvK5Bi2gqz77S0SLwCujm3lmdfOICIsCAESBQQI2AEgGiEg2Cbb2yBIXXEbC7wqBwIhPyaYZ4Ay+AzEgPDraZqCLnEiLAgBEgUIFtgBIBohINI3DtgYYkCoQ2Il4TSMFmBhVqEpOP83MksbkPACkVndIioIARImCjLYASDXPnQCORCC3CMgwymnZdbYQPa2Iy+Ba/AVlOqQ3I86kiAiKggBEiYMUNgBIA8Q378ys1zqIHaVZrOZLyM0oM4Hah05m1v6tNVBhbAaIAr+AQr7AQoDaWJjEiADsEmAPnkqWsIG2J4BxN+aarD458lluj/dXsPJkVW9kxoJCAEYASABKgEAIicIARIBARogLNi1BwCVBUYYCtl5E1qHCMLqIJj/9q3jG35A613PfAUiJwgBEgEBGiBa7g6HQMUcDsPjkK5u6r2/ZVbnbowRi6y/0J5lpScVeiIlCAESIQHqddd/lk2DoZRj0UJpVAcoeW8dr4ZO7haNKPxEInYrjiIlCAESIQFKd2oJ7PivSso/bHuIKqSozuUyvtVhAAyajcGBVCvEQCInCAESAQEaIGGznmhqo1Rf+vdfD2Pw5uEgukTIONwDBAZ+B88XPJlzGgIQbSItdG5hbTFxejBudmVjNjg2ZTlwa3M4eW5obTVkZHE4a2U3ajJlZXk1MHVhZ3Ry";

    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    setup_ibc(&node);

    node.shell
        .lock()
        .unwrap()
        .state
        .in_mem_mut()
        .last_block
        .as_mut()
        .map(|last_block| last_block.time = DateTimeUtc::unix_epoch());

    //FIXME: reduce code redundancy
    // FIXME: Initialize IBC state
    // let ibc_code_hash = node
    //     .shell
    //     .lock()
    //     .unwrap()
    //     .read_storage_key(&namada_core::storage::Key::wasm_hash("tx_ibc.wasm"))
    //     .unwrap();
    // let mut tx = namada_sdk::tx::Tx::new(
    //     node.shell.lock().unwrap().chain_id.clone(),
    //     None,
    // );
    // tx.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
    //     Fee {
    //         amount_per_gas_unit: DenominatedAmount::native(1.into()),
    //         token: node.shell.lock().unwrap().state.get_native_token().unwrap(),
    //     },
    //     albert_keypair().to_public(),
    //     300_000.into(),
    // ))));
    // tx.add_serialized_data(
    //     data_encoding::BASE64
    //         .decode(ENCODED_OPEN_CHANNEL.as_bytes())
    //         .unwrap(),
    // )
    // .add_code_from_hash(ibc_code_hash, None)
    // .sign_wrapper(albert_keypair());

    // let txs = vec![tx.to_bytes()];
    // node.clear_results();
    // node.submit_txs(txs);
    // node.assert_success();

    // Construct and submit the shielded action
    let ibc_code_hash = node
        .shell
        .lock()
        .unwrap()
        .read_storage_key(&namada_core::storage::Key::wasm_hash("tx_ibc.wasm"))
        .unwrap();
    let mut tx = namada_sdk::tx::Tx::new(
        node.shell.lock().unwrap().chain_id.clone(),
        None,
    );
    tx.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
        Fee {
            amount_per_gas_unit: DenominatedAmount::native(1.into()),
            token: node.shell.lock().unwrap().state.get_native_token().unwrap(),
        },
        albert_keypair().to_public(),
        300_000.into(),
    ))));
    tx.add_serialized_data(
        data_encoding::BASE64
            .decode(ENCODED_IBC_PACKET.as_bytes())
            .unwrap(),
    )
    .add_code_from_hash(ibc_code_hash, None)
    .sign_wrapper(albert_keypair());

    let txs = vec![tx.to_bytes()];
    node.clear_results();
    node.submit_txs(txs);
    node.assert_success();

    Ok(())
}

use namada_core::address::Address;
use namada_core::storage::Key;
use namada_sdk::ibc::apps::transfer::types::packet::PacketData;
use namada_sdk::ibc::apps::transfer::types::PrefixedCoin;
use namada_sdk::ibc::clients::tendermint::client_state::ClientState;
use namada_sdk::ibc::clients::tendermint::consensus_state::ConsensusState;
use namada_sdk::ibc::clients::tendermint::types::{
    AllowUpdate, ClientState as ClientStateType,
    ConsensusState as ConsensusStateType, TrustThreshold,
};
use namada_sdk::ibc::core::channel::types::channel::{
    ChannelEnd, Counterparty as ChannelCounterparty, Order, State,
};
use namada_sdk::ibc::core::channel::types::timeout::{
    TimeoutHeight, TimeoutTimestamp,
};
use namada_sdk::ibc::core::channel::types::Version as ChannelVersion;
use namada_sdk::ibc::core::client::types::Height as IbcHeight;
use namada_sdk::ibc::core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentRoot,
};
use namada_sdk::ibc::core::commitment_types::specs::ProofSpecs;
use namada_sdk::ibc::core::connection::types::version::Version;
use namada_sdk::ibc::core::connection::types::{
    ConnectionEnd, Counterparty, State as ConnectionState,
};
use namada_sdk::ibc::core::host::types::identifiers::{
    ChainId as IbcChainId, ChannelId as NamadaChannelId, ChannelId, ClientId,
    ConnectionId, ConnectionId as NamadaConnectionId, PortId as NamadaPortId,
    PortId,
};
use namada_sdk::ibc::core::host::types::path::{
    ClientConsensusStatePath, ClientStatePath, Path as IbcPath,
};
use namada_sdk::ibc::primitives::proto::{Any, Protobuf};
use namada_sdk::ibc::primitives::Timestamp as IbcTimestamp;
use namada_sdk::ibc::storage::{
    channel_key, client_counter_key, client_update_height_key,
    client_update_timestamp_key, connection_key, mint_limit_key, port_key,
    throughput_limit_key,
};

fn setup_ibc(node: &MockNode) {
    // Set a dummy header
    node.shell
        .lock()
        .unwrap()
        .state
        .in_mem_mut()
        .set_header(get_dummy_header())
        .unwrap();
    // Set client state
    let addr_key =
        Key::from(Address::Internal(InternalAddress::Ibc).to_db_key());
    let client_id = ClientId::new("07-tendermint", 1).unwrap();
    let client_state_key = addr_key.join(&namada_core::storage::Key::from(
        IbcPath::ClientState(ClientStatePath(client_id.clone()))
            .to_string()
            .to_db_key(),
    ));
    let client_state = ClientStateType::new(
        IbcChainId::from_str(&ChainId::default().to_string()).unwrap(),
        TrustThreshold::ONE_THIRD,
        std::time::Duration::new(10_000, 0),
        std::time::Duration::new(20_000, 0),
        std::time::Duration::new(1, 0),
        IbcHeight::new(0, 1).unwrap(),
        ProofSpecs::cosmos(),
        vec![],
        AllowUpdate {
            after_expiry: true,
            after_misbehaviour: true,
        },
    )
    .unwrap()
    .into();
    let bytes = <ClientState as Protobuf<Any>>::encode_vec(client_state);
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&client_state_key, bytes)
        .expect("write failed");

    // Set consensus state
    let now: namada_sdk::tendermint::Time =
        DateTimeUtc::from_unix_timestamp(1727438700)
            .unwrap()
            .try_into()
            .unwrap();
    let consensus_key = addr_key.join(&Key::from(
        IbcPath::ClientConsensusState(ClientConsensusStatePath {
            client_id: client_id.clone(),
            revision_number: 0,
            revision_height: 1,
        })
        .to_string()
        .to_db_key(),
    ));

    let consensus_state = ConsensusStateType {
        timestamp: now,
        root: CommitmentRoot::from_bytes(&[]),
        next_validators_hash: tendermint::Hash::Sha256([0u8; 32]),
    }
    .into();

    let bytes = <ConsensusState as Protobuf<Any>>::encode_vec(consensus_state);
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&consensus_key, bytes)
        .unwrap();

    // client update time
    let key = client_update_timestamp_key(&client_id);
    let bytes = namada_sdk::tendermint::time::Time::try_from(now)
        .unwrap()
        .encode_vec();
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&key, bytes)
        .unwrap();
    // client update height
    let key = client_update_height_key(&client_id);
    let height = namada_sdk::ibc::core::client::types::Height::new(0, 109)
        .expect("invalid height");
    let bytes = height.encode_vec();
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&key, bytes)
        .unwrap();
    // client counter
    let key = client_counter_key();
    let bytes = 1_u64.to_be_bytes().to_vec();
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&key, bytes)
        .unwrap();

    // Set connection open
    let connection = ConnectionEnd::new(
        ConnectionState::Open,
        client_id.clone(),
        Counterparty::new(
            client_id.clone(),
            Some(ConnectionId::new(1)),
            CommitmentPrefix::from("ibc".as_bytes().to_vec()),
        ),
        Version::compatibles(),
        std::time::Duration::new(0, 0),
    )
    .unwrap();

    let connection_key = connection_key(&NamadaConnectionId::new(1));
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&connection_key, connection.encode_vec())
        .unwrap();

    // Set port
    let port_key = port_key(&NamadaPortId::transfer());

    let index_key =
        addr_key.join(&Key::from("capabilities/index".to_string().to_db_key()));
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&index_key, 1u64.to_be_bytes())
        .unwrap();
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&port_key, 1u64.to_be_bytes())
        .unwrap();
    let cap_key =
        addr_key.join(&Key::from("capabilities/1".to_string().to_db_key()));
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&cap_key, PortId::transfer().as_bytes())
        .unwrap();

    // Set Channel open
    let counterparty =
        ChannelCounterparty::new(PortId::transfer(), Some(ChannelId::new(0)));
    let channel = ChannelEnd::new(
        State::Open,
        Order::Unordered,
        counterparty,
        vec![ConnectionId::new(1)],
        ChannelVersion::new("ics20-1".to_string()),
    )
    .unwrap();
    let channel_key =
        channel_key(&NamadaPortId::transfer(), &NamadaChannelId::new(0));
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&channel_key, channel.encode_vec())
        .unwrap();

    let token = node.native_token();
    let mint_limit_key = mint_limit_key(&token);
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(&mint_limit_key, Amount::max_signed().serialize_to_vec())
        .unwrap();
    let throughput_limit_key = throughput_limit_key(&token);
    node.shell
        .lock()
        .unwrap()
        .state
        .db_write(
            &throughput_limit_key,
            Amount::max_signed().serialize_to_vec(),
        )
        .unwrap();
}
