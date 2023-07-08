use std::path::PathBuf;

use color_eyre::eyre::Result;
use namada_apps::client::tx::CLIShieldedUtils;
use namada_core::types::address::{btc, eth, masp_rewards};
use namada_core::types::token;
use namada_core::types::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};

use super::client::run;
use super::setup;
use crate::e2e::setup::constants::{A_SPENDING_KEY, AA_PAYMENT_ADDRESS, AA_VIEWING_KEY, AB_PAYMENT_ADDRESS, AB_VIEWING_KEY, ALBERT, B_SPENDING_KEY, BERTHA, BTC, CHRISTEL, ETH, MASP, NAM};
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

    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded nam balance found"));

    // Wait till epoch boundary
    let ep4 = node.next_epoch();

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
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 10"));

    // Assert NAM balance at VK(B) is 10*ETH_reward*(epoch_4-epoch_3)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc
            ],)
    );
    let amt = (amt10 * masp_rewards[&(eth(), None)]).0 * (ep4.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_4-epoch_0)+10*ETH_reward*(epoch_4-epoch_3)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = ((amt20 * masp_rewards[&(btc(), None)]).0 * (ep4.0 - ep0.0))
        + ((amt10 * masp_rewards[&(eth(), None)]).0 * (ep4.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Wait till epoch boundary
    let ep5 = node.next_epoch();

    // Send 10 ETH from SK(B) to Christel
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
            "10",
            "--signer",
            BERTHA,
            "--node",
            &validator_one_rpc
        ],
    )?;
    assert!(node.success());
    node.clear_results();

    // Assert ETH balance at VK(B) is 0
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
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded eth balance found"));

    let mut ep = node.next_epoch();

    // Assert NAM balance at VK(B) is 10*ETH_reward*(ep-epoch_3)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc
            ],
        )
    );
    let amt = (amt10 * masp_rewards[&(eth(), None)]).0 * (ep.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    ep = node.next_epoch();
    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_5-epoch_0)+10*ETH_reward*(epoch_5-epoch_3)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = ((amt20 * masp_rewards[&(btc(), None)]).0 * (ep.0 - ep0.0))
        + ((amt10 * masp_rewards[&(eth(), None)]).0 * (ep.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Wait till epoch boundary
    let ep6 = node.next_epoch();

    // Send 20 BTC from SK(A) to Christel
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
            "20",
            "--signer",
            ALBERT,
            "--node",
            &validator_one_rpc
        ],
    )?;
    assert!(node.success());
    node.clear_results();

    // Assert BTC balance at VK(A) is 0
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
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded btc balance found"));

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_6-epoch_0)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep6.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated,)));

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_6-epoch_0)+20*ETH_reward*(epoch_5-epoch_3)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = ((amt20 * masp_rewards[&(btc(), None)]).0 * (ep6.0 - ep0.0))
        + ((amt10 * masp_rewards[&(eth(), None)]).0 * (ep5.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated,)));

    // Wait till epoch boundary
    let _ep7 = node.next_epoch();

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_6-epoch_0)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = (amt20 * masp_rewards[&(btc(), None)]).0 * (ep6.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated)));

    // Assert NAM balance at VK(B) is 10*ETH_reward*(epoch_5-epoch_3)
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc
            ],
        )
    );
    let amt = (amt10 * masp_rewards[&(eth(), None)]).0 * (ep5.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated,)));

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_6-epoch_0)+10*ETH_reward*(epoch_5-epoch_3)
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
                &validator_one_rpc
            ],
        )
    );
    let amt = ((amt20 * masp_rewards[&(btc(), None)]).0 * (ep6.0 - ep0.0))
        + ((amt10 * masp_rewards[&(eth(), None)]).0 * (ep5.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    assert!(captured.result.is_ok());
    assert!(captured.contains(&format!("nam: {}", denominated,)));

    // Wait till epoch boundary to prevent conversion expiry during transaction
    // construction
    let _ep8 = node.next_epoch();

    // Send 10*ETH_reward*(epoch_5-epoch_3) NAM from SK(B) to Christel
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
            &((amt10 * masp_rewards[&(eth(), None)]).0 * (ep5.0 - ep3.0))
                .to_string_native(),
            "--signer",
            BERTHA,
            "--node",
            &validator_one_rpc
        ],
    )?;
    assert!(node.success());
    node.clear_results();

    // Wait till epoch boundary
    let _ep9 = node.next_epoch();

    // Send 20*BTC_reward*(epoch_6-epoch_0) NAM from SK(A) to Bertha
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
            &((amt20 * masp_rewards[&(btc(), None)]).0 * (ep6.0 - ep0.0))
                .to_string_native(),
            "--signer",
            ALBERT,
            "--node",
            &validator_one_rpc
        ],
    )?;
    assert!(node.success());
    node.clear_results();

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
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded nam balance found"));

    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(
        || run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("No shielded nam balance found"));

    // Assert NAM balance at MASP pool is 0
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
                &validator_one_rpc
            ],
        )
    );
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    Ok(())
}
