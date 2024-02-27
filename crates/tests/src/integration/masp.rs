use std::path::PathBuf;
use std::str::FromStr;

use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use namada::state::StorageWrite;
use namada::token::{self, DenominatedAmount};
use namada_apps::node::ledger::shell::testing::client::run;
use namada_apps::node::ledger::shell::testing::node::NodeResults;
use namada_apps::node::ledger::shell::testing::utils::{Bin, CapturedOutput};
use namada_apps::wallet::defaults::christel_keypair;
use namada_core::dec::Dec;
use namada_sdk::masp::fs::FsShieldedUtils;
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
    node.next_epoch();
    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded nam balance found"));

    // Wait till epoch boundary
    node.next_epoch();

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
    assert!(captured.contains("nam: 0.031"));

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
    assert!(captured.contains("nam: 0.031"));

    // Wait till epoch boundary
    node.next_epoch();

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
    assert!(captured.contains("nam: 0.09292"));

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
    assert!(captured.contains("nam: 0.09331"));

    // Wait till epoch boundary
    node.next_epoch();

    // Send 0.001 ETH from Albert to PA(B)
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded nam balance found"));

    // Wait till epoch boundary
    node.next_epoch();

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
    assert!(captured.contains("nam: 0.359578"));

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
    assert!(captured.contains("nam: 0.671183"));

    // Wait till epoch boundary
    node.next_epoch();
    // Send 0.001 ETH from SK(B) to Christel
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded eth balance found"));

    node.next_epoch();
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
    assert!(captured.contains("nam: 0.719514"));

    node.next_epoch();
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
    assert!(captured.contains("nam: 1.58943"));

    // Wait till epoch boundary
    node.next_epoch();

    // Send 1 BTC from SK(A) to Christel
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded btc balance found"));

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
    assert!(captured.contains("nam: 1.113911"));

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
    assert!(captured.contains("nam: 1.83743"));

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 1.113911"));

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
    assert!(captured.contains("nam: 0.719514"));

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
    assert!(captured.contains("nam: 1.83743"));

    // Wait till epoch boundary to prevent conversion expiry during transaction
    // construction
    node.next_epoch();
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
            "transfer",
            "--source",
            B_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            NAM,
            "--amount",
            "0.719514",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Wait till epoch boundary
    node.next_epoch();
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
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            "1.113911",
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
    assert!(captured.contains("No shielded nam balance found"));

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
    assert!(captured.contains("No shielded nam balance found"));

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
    assert!(captured.contains("nam: 0.004005"));

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
            "transfer",
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
            "transfer",
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
/// 2. Assert PPA(C) cannot be recognized by incorrect viewing key
/// 3. Assert PPA(C) has not transaction pinned to it
/// 4. Send 20 BTC from Albert to PPA(C)
/// 5. Assert PPA(C) has the 20 BTC transaction pinned to it
#[test]
fn masp_pinned_txs() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    let _ep0 = node.next_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Assert PPA(C) cannot be recognized by incorrect viewing key
    let captured =
        CapturedOutput::with_input(AB_VIEWING_KEY.into()).run(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    AC_PAYMENT_ADDRESS,
                    "--token",
                    BTC,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains("Supplied viewing key cannot decode transactions to")
    );

    // Assert PPA(C) has no transaction pinned to it
    let captured =
        CapturedOutput::with_input(AC_VIEWING_KEY.into()).run(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    AC_PAYMENT_ADDRESS,
                    "--token",
                    BTC,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
    assert!(captured.result.is_ok());
    assert!(captured.contains("has not yet been consumed"));

    // Wait till epoch boundary
    let _ep1 = node.next_epoch();

    // Send 20 BTC from Albert to PPA(C)
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "20",
            "--node",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    // Wait till epoch boundary
    // This makes it more consistent for some reason?
    let _ep2 = node.next_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert PPA(C) has the 20 BTC transaction pinned to it
    let captured =
        CapturedOutput::with_input(AC_VIEWING_KEY.into()).run(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    AC_PAYMENT_ADDRESS,
                    "--token",
                    BTC,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
    assert!(captured.result.is_ok());
    assert!(captured.contains("Received 20 btc"));

    // Assert PPA(C) has no NAM pinned to it
    let captured =
        CapturedOutput::with_input(AC_VIEWING_KEY.into()).run(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    AC_PAYMENT_ADDRESS,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
    assert!(captured.result.is_ok());
    assert!(captured.contains("Received no shielded nam"));

    // Wait till epoch boundary
    let _ep1 = node.next_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    node.assert_success();

    // Assert PPA(C) does not NAM pinned to it on epoch boundary
    let captured =
        CapturedOutput::with_input(AC_VIEWING_KEY.into()).run(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    AC_PAYMENT_ADDRESS,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
    assert!(captured.result.is_ok());
    assert!(captured.contains("Received no shielded nam"));
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
    // let _log_guard = namada_apps::logging::init_from_env_or(
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
                "transfer",
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
                "transfer",
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
            Response::Ok("No shielded btc balance found"),
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
            Response::Ok("No shielded eth balance found"),
        ),
        // 10. Assert balance at VK(B) is 20 BTC
        (
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("btc : 20"),
        ),
        // 11. Send 20 BTC from SK(B) to Bertha
        (
            vec![
                "transfer",
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
        let dry_run_args = if tx_args[0] == "transfer" {
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
            let tx_args = if dry_run && tx_args[0] == "transfer" {
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

/// Test the unshielding tx attached to a wrapper:
///
/// 1. Shield some tokens to reduce the unshielded balance
/// 2. Submit a new wrapper with a valid unshielding tx and assert
/// success
/// 3. Submit another transaction with valid fee unshielding and an inner
/// shielded transfer with the same source
/// 4. Submit a new wrapper with an invalid unshielding tx and assert the
/// failure
#[test]
fn wrapper_fee_unshielding() -> Result<()> {
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

    // 1. Shield some tokens
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "1919999", // Reduce the balance of the fee payer artificially
            "--gas-price",
            "1",
            "--gas-limit",
            "20000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_epoch();

    // 2. Shield more tokens to produce another output description
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "40000", // Reduce the balance of the fee payer artificially
            "--gas-price",
            "1",
            "--gas-limit",
            "20000",
            "--ledger-address",
            validator_one_rpc,
        ],
    )?;
    node.assert_success();

    _ = node.next_epoch();

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
    assert!(captured.contains("nam: 1959999"));

    _ = node.next_epoch();
    // 2. Valid unshielding
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT_KEY,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            "1",
            "--gas-price",
            "1",
            "--gas-limit",
            "20000",
            "--gas-spending-key",
            A_SPENDING_KEY,
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
    assert!(captured.contains("nam: 1939999"));

    _ = node.next_epoch();
    // 3. Try another valid fee unshielding and masp transaction in the same tx,
    // with the same source. This tests that the client can properly construct
    // two valid masp transactions at the same time
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
            "--gas-price",
            "1",
            "--gas-limit",
            "20000",
            "--gas-payer",
            ALBERT_KEY,
            "--gas-spending-key",
            A_SPENDING_KEY,
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
    assert!(captured.contains("nam: 1919998"));

    _ = node.next_epoch();
    // 4. Invalid unshielding
    let tx_args = vec![
        "transfer",
        "--source",
        ALBERT_KEY,
        "--target",
        BERTHA,
        "--token",
        NAM,
        "--amount",
        "1",
        "--gas-price",
        "1000",
        "--gas-spending-key",
        B_SPENDING_KEY,
        "--ledger-address",
        validator_one_rpc,
        // NOTE: Forcing the transaction will make the client produce a
        // transfer without a masp object attached to it, so don't expect a
        // failure from the masp vp here but from the check_fees function
        "--force",
    ];

    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, tx_args.clone()));
    assert!(
        captured.result.is_err(),
        "{:?} unexpectedly succeeded",
        tx_args
    );

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
            "transfer",
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
            "transfer",
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
            "transfer",
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

    // 2. Shielded operations without fetching. Dump the txs to than reload and
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
        let mut tx = namada::tx::Tx::deserialize(&bytes).unwrap();
        tx.add_wrapper(
            namada::tx::data::wrapper_tx::Fee {
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token: native_token.clone(),
            },
            pk.clone(),
            Default::default(),
            20000.into(),
            None,
        );
        tx.sign_wrapper(sk.clone());

        txs.push(tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);
    {
        let results = node.results.lock().unwrap();
        // If empty than failed in process proposal
        assert!(!results.is_empty());

        for result in results.iter() {
            assert!(matches!(result, NodeResults::Ok));
        }
    }
    // Finalize the next block to actually execute the decrypted txs
    node.clear_results();
    node.finalize_and_commit();
    {
        let results = node.results.lock().unwrap();
        for result in results.iter() {
            assert!(matches!(result, NodeResults::Ok));
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
            "transfer",
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
            "transfer",
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

    let tokens = {
        // Only distribute rewards for NAM tokens
        let state = &mut node.shell.lock().unwrap().state;
        let tokens = state.in_mem().conversion_state.tokens.clone();
        state
            .in_mem_mut()
            .conversion_state
            .tokens
            .insert(btc.clone(), tokens[&btc].clone());
        state
            .in_mem_mut()
            .conversion_state
            .tokens
            .retain(|k, _v| *k == nam);
        tokens
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
    node.next_epoch();
    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded nam balance found for given key"));

    {
        // Start decoding and distributing shielded rewards for BTC in next
        // epoch
        let state = &mut node.shell.lock().unwrap().state;
        state
            .in_mem_mut()
            .conversion_state
            .tokens
            .insert(btc.clone(), tokens[&btc].clone());
    }

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("No shielded nam balance found for given key"));

    // Send 1 BTC from Albert to PA
    run(
        &node,
        Bin::Client,
        vec![
            "transfer",
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
    assert!(captured.contains("No shielded nam balance found for given key"));

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 0.0303"));

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
                &token::storage_key::masp_max_reward_rate_key(&tokens[&nam]),
                Dec::zero(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 0.07575"));

    {
        // Stop decoding and distributing shielded rewards for BTC in next epoch
        let state = &mut node.shell.lock().unwrap().state;
        state.in_mem_mut().conversion_state.tokens.remove(&btc);
    }

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 0.07575"));

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 0.07575"));

    {
        // Start distributing shielded rewards for NAM in next epoch
        let storage = &mut node.shell.lock().unwrap().state;
        storage
            .write(
                &token::storage_key::masp_max_reward_rate_key(&tokens[&nam]),
                Dec::from_str("0.1").unwrap(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_epoch();
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
    assert!(captured.contains("nam: 0.075825"));

    Ok(())
}
