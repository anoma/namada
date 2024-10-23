use std::path::PathBuf;
use std::str::FromStr;

use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use namada_apps_lib::wallet::defaults::{albert_keypair, christel_keypair};
use namada_core::dec::Dec;
use namada_core::masp::TokenMap;
use namada_node::shell::testing::client::run;
use namada_node::shell::testing::node::NodeResults;
use namada_node::shell::testing::utils::{Bin, CapturedOutput};
use namada_sdk::account::AccountPublicKeysMap;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::signing::SigningTxData;
use namada_sdk::state::{StorageRead, StorageWrite};
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::storage_key::masp_token_map_key;
use namada_sdk::token::{self, DenominatedAmount};
use namada_sdk::tx::Tx;
use namada_sdk::{tx, DEFAULT_GAS_LIMIT};
use test_log::test;

use super::setup;
use super::helpers;
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
    const BTC: &str = "tnam1qx46h2at4w46h2at4w46h2at4w46h2at4vdmum77";

    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let (mut node, _services) = setup::setup()?;
    {
        let albert_addr: namada_sdk::address::Address = helpers::find_address(&node, ALBERT).unwrap();

        token::credit_tokens(
            &mut node.shell.lock().unwrap().state,
            &BTC.parse().unwrap(),
            &albert_addr,
            token::Amount::from_uint(namada_sdk::uint::Uint::from_u64(1_000_000_000u64), 0).unwrap(),
        )
        .unwrap();
    }
    //{
    //    for _ in 0..10 {
    //        node.next_masp_epoch();
    //    }

    //    run(
    //        &node,
    //        Bin::Client,
    //        vec![
    //            "shielded-sync",
    //            "--viewing-keys",
    //            AA_VIEWING_KEY,
    //            AB_VIEWING_KEY,
    //            "--node",
    //            validator_one_rpc,
    //        ],
    //    )?;

    //    run(
    //        &node,
    //        Bin::Client,
    //        vec![
    //            "balance",
    //            "--owner",
    //            AA_VIEWING_KEY,
    //            "--token",
    //            NAM,
    //            "--node",
    //            validator_one_rpc,
    //        ],
    //    )?;

    //    panic!();
    //}
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
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
                "1000000",
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:#?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    assert!(captured.contains(&format!("{BTC}: 1000000")));

    //{
    //    for _ in 0..10 {
    //        node.next_masp_epoch();
    //    }

    //    run(
    //        &node,
    //        Bin::Client,
    //        vec![
    //            "shielded-sync",
    //            "--viewing-keys",
    //            AA_VIEWING_KEY,
    //            AB_VIEWING_KEY,
    //            "--node",
    //            validator_one_rpc,
    //        ],
    //    )?;

    //    run(
    //        &node,
    //        Bin::Client,
    //        vec![
    //            "balance",
    //            "--owner",
    //            AA_VIEWING_KEY,
    //            "--token",
    //            NAM,
    //            "--node",
    //            validator_one_rpc,
    //        ],
    //    )?;

    //    panic!();
    //}

    node.next_masp_epoch();

    {
        use std::str::FromStr;

        use namada_sdk::address::InternalAddress;
        use namada_sdk::address::Address;
        use namada_core::masp;
        use namada_sdk::dec::Dec;
        use token::storage_key::balance_key;

        pub type Denomination = u8;
        pub type TokenAddress = Address;

        pub type TokenMaxReward = &'static str;
        pub type TokenTargetLockedAmount = u64;
        pub type KpGain = &'static str;
        pub type KdGain = &'static str;

        let tokens = [(
            6,
            BTC.parse().unwrap(),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        )];

        fn apply_tx<Ctx>(ctx: &mut Ctx, tokens: [(
            Denomination,
            TokenAddress,
            TokenMaxReward,
            TokenTargetLockedAmount,
            KpGain,
            KdGain,
        ); 1]) -> namada_sdk::storage::Result<()>
        where
            Ctx: StorageRead + StorageWrite,
        {
            // Read the current MASP token map
            let mut token_map = masp::TokenMap::default();
            let token_map_key = token::storage_key::masp_token_map_key();
            //let mut token_map = ctx
            //    .read::<masp::TokenMap>(&token_map_key)?
            //    .unwrap_or_default();

            // Enable shielded set rewards for ibc tokens
            for (denomination, token_address, max_reward, target_locked_amount, kp, kd) in
                tokens
            {
                let tok_alias = "dinheirinho";

                let shielded_token_last_inflation_key =
                    token::storage_key::masp_last_inflation_key(&token_address);
                let shielded_token_last_locked_amount_key =
                    token::storage_key::masp_last_locked_amount_key(&token_address);
                let shielded_token_max_rewards_key =
                    token::storage_key::masp_max_reward_rate_key(&token_address);
                let shielded_token_target_locked_amount_key =
                    token::storage_key::masp_locked_amount_target_key(&token_address);
                let shielded_token_kp_gain_key = token::storage_key::masp_kp_gain_key(&token_address);
                let shielded_token_kd_gain_key = token::storage_key::masp_kd_gain_key(&token_address);

                // Add the ibc token to the masp token map
                token_map.insert(tok_alias.to_string(), token_address.clone());

                // Read the current balance of the IBC token in MASP and set that as initial locked amount
                let btc_balance_key = balance_key(
                    &token_address,
                    &Address::Internal(InternalAddress::Masp),
                );
                let current_btc_amount = ctx.read::<token::Amount>(&btc_balance_key)?.unwrap_or_default();
                //assert!(current_btc_amount == token::Amount::from_uint(namada_sdk::uint::Uint::from_u64(1), denomination).unwrap(), "current_btc_amount = {current_btc_amount:?}");
                //ctx.write(&shielded_token_last_locked_amount_key, current_btc_amount)?;

                // Initialize the remaining MASP inflation keys
                //ctx.write(&shielded_token_last_inflation_key, token::Amount::zero())?;

                //ctx.write(
                //    &shielded_token_max_rewards_key,
                //    Dec::from_str(max_reward).unwrap(),
                //)?;
                //ctx.write(
                //    &shielded_token_target_locked_amount_key,
                //    token::Amount::from_uint(target_locked_amount, denomination).unwrap(),
                //)?;
                //ctx.write(&shielded_token_kp_gain_key, Dec::from_str(kp).unwrap())?;
                //ctx.write(&shielded_token_kd_gain_key, Dec::from_str(kd).unwrap())?;


                token::write_params(
                    &Some(token::ShieldedParams {
                        max_reward_rate: Dec::from_str("120000").unwrap(),
                        kp_gain_nom: Dec::from_str("120000").unwrap(),
                        kd_gain_nom: Dec::from_str("120000").unwrap(),
                        locked_amount_target: 1_000_000_000u64,
                    }),
                    ctx,
                    &token_address,
                    &0.into(),
                )?;
            }

            ctx.write(&token_map_key, token_map)?;

            Ok(())
        }

        apply_tx(&mut node.shell.lock().unwrap().state, tokens).unwrap();
        node.finalize_and_commit(None);

        {
            // Send 1 BTC from Albert to PA
            let captured = CapturedOutput::of(|| {
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
                        "1000000",
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok(), "{:#?}", captured.result);
            assert!(captured.contains(TX_APPLIED_SUCCESS));

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
            assert!(captured.contains(&format!("{BTC}: 2000000")));
        }

        for _ in 0..10 {
            node.next_masp_epoch();
        }

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
        )?;

        panic!();
    }

    // Assert BTC balance at MASP is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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
    // Send all NAM rewards from SK(B) to Christel
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Send all NAM rewards from SK(A) to Bertha
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
                "2.268662",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 2. Shield the minimum amount
    node.next_epoch();
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
                "--gas-limit",
                "300000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
    ];

    for (tx_args, tx_result) in &txs_args {
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
                    assert!(
                        captured.contains(TX_APPLIED_SUCCESS),
                        "{:?} failed to contain needle 'Transaction is \
                         valid',\nGot output '{}'",
                        tx_args,
                        captured.output
                    );
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

    // 1. Shield tokens
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
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
                "50",
                "--gas-payer",
                ALBERT_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
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
                "50",
                "--gas-payer",
                CHRISTEL_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
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

    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
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
        let mut tx = Tx::try_from_json_bytes(&bytes).unwrap();
        tx.add_wrapper(
            tx::data::wrapper::Fee {
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
                "50",
                "--gas-payer",
                CHRISTEL_KEY,
                // We want to create an expired masp tx. Doing so will also set
                // the expiration field of the header which can
                // be a problem because this would lead to the
                // transaction being rejected by the
                // protocol check while we want to test expiration in the masp
                // vp. However, this is not a real issue: to
                // avoid the failure in protocol we are going
                // to overwrite the header with one having no
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
        )
    });
    assert!(captured.result.is_ok());

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
    let mut tx = Tx::try_from_json_bytes(&tx_bytes).unwrap();
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

            assert!(
                inner_tx_result
                    .vps_result
                    .rejected_vps
                    .contains(&namada_sdk::address::MASP)
            );
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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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

    // 2. Generate the tx in the current epoch
    let tempdir = tempfile::tempdir().unwrap();
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
                "100",
                "--gas-payer",
                ALBERT_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
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
                "10000",
                "--gas-price",
                "1",
                "--disposable-gas-payer",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
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

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

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

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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

    // Generate a tx to shield some tokens
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
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
    // Inject some randomness in the cloned tx to chagne the hash
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
    let captured = CapturedOutput::of(|| {
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
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

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
