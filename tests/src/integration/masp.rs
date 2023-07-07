use std::path::PathBuf;

use color_eyre::eyre::Result;
use namada_apps::client::tx::CLIShieldedUtils;
use namada_core::types::address::{btc, masp_rewards};
use namada_core::types::token;
use namada_core::types::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};

use super::client::run;
use super::setup;
use crate::e2e::setup::constants::{AA_PAYMENT_ADDRESS, AA_VIEWING_KEY, AB_PAYMENT_ADDRESS, AB_VIEWING_KEY, ALBERT, BTC, ETH, MASP, NAM};
use crate::e2e::setup::Bin;
use crate::integration::client::CapturedOutput;

#[test]
fn masp_incentives() -> Result<()> {
    // The number of decimal places used by BTC amounts.
    const BTC_DENOMINATION: u8 = 8;
    // The number of decimal places used by ETH amounts.
    const ETH_DENOMINATION: u8 = 18;
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc= "127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let mut node = setup::setup()?;
    // Wait till epoch boundary
    let ep0 = node.next_epoch();
    // Send 20 BTC from Albert to PA
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
    assert!(node.success());
    node.clear_results();

    // Assert BTC balance at VK(A) is 20
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
    assert!(captured.contains("btc: 20"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(
        || run(
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
            ])
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded nam balance found"));

    let masp_rewards = masp_rewards();

    // Wait till epoch boundary
    let ep1 = node.next_epoch();

    // Assert BTC balance at VK(A) is 20
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 20"));

    let amt20 = token::Amount::from_uint(20, BTC_DENOMINATION).unwrap();
    let amt10 = token::Amount::from_uint(10, ETH_DENOMINATION).unwrap();

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_1-epoch_0)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc
            ],
    ));

    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep1.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Assert NAM balance at MASP pool is 20*BTC_reward*(epoch_1-epoch_0)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc
            ],
        )
    );
    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep1.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Wait till epoch boundary
    let ep2 = node.next_epoch();

    // Assert BTC balance at VK(A) is 20
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 20"));

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_2-epoch_0)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc
            ],
        )
    );
    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep2.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Assert NAM balance at MASP pool is 20*BTC_reward*(epoch_2-epoch_0)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc
            ],
        )
    );
    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep2.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Wait till epoch boundary
    let ep3 = node.next_epoch();

    // Send 10 ETH from Albert to PA(B)
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
            "10",
            "--node",
            validator_one_rpc
        ],
    )?;
    assert!(node.success());
    node.clear_results();

    // Assert ETH balance at VK(B) is 10
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 10"));

    Ok(())
}
