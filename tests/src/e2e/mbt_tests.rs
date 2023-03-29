//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::mbt_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.
#![allow(clippy::type_complexity)]

use std::str::FromStr;

use std::time::{Duration, Instant};

use color_eyre::eyre::Result;

use namada::types::storage::Epoch;

use namada_apps::config::genesis::genesis_config::{
    GenesisConfig, ParametersConfig, PosParamsConfig,
};

use crate::e2e::setup::constants::*;

use crate::e2e::helpers::{find_bonded_stake, get_actor_rpc, get_epoch};
use crate::e2e::setup::NamadaBgCmd;
use crate::e2e::setup::{self, default_port_offset, Bin, Who};
use crate::{run, run_as};

use std::net::SocketAddr;

use namada::types::key::{self, ed25519, SigScheme};
use namada::types::token;
use namada_apps::client;
use namada_apps::config::Config;

use crate::e2e::mbt::Reactor;

use std::collections::{BTreeMap, HashMap, HashSet};

struct NamadaBlockchain {
    test: crate::e2e::setup::Test,
    validators: Vec<Option<NamadaBgCmd>>,
    tla_validators: HashSet<String>,
    tla_accounts: HashMap<String, String>,
}

const PIPELINE_LEN: u64 = 1;
const UNBONDING_LEN: u64 = 2;

impl NamadaBlockchain {
    fn get_reactor() -> Result<Reactor<'static, Self>> {
        let mut mbt_reactor = Reactor::new("lastTx.tag", |state| {
            let num_of_validators: u8 = 2;

            let secs_per_epoch = std::option_env!("NAMADA_E2E_EPOCH_DURATION")
                .map(|x| {
                    x.parse()
                        .expect("NAMADA_E2E_EPOCH_DURATION is not a number")
                })
                .unwrap_or(20);

            let test = setup::network(
                |mut genesis| {
                    let parameters = ParametersConfig {
                        // min num of blocks per epoch
                        min_num_of_blocks: 2,
                        // epochs per year = secs per year / secs per epoch
                        epochs_per_year: 60 * 60 * 24 * 365 / secs_per_epoch,
                        max_expected_time_per_block: 1,
                        ..genesis.parameters
                    };

                    let pos_params = PosParamsConfig {
                        pipeline_len: PIPELINE_LEN,
                        unbonding_len: UNBONDING_LEN,
                        ..genesis.pos_params
                    };

                    let tla_init_bond = state
                        .get(&format!("totalDelegated.\\#map.#(0=\"val\").1"))
                        .i64() as u64;

                    let validator_0 =
                        genesis.validator.get_mut("validator-0").unwrap();
                    validator_0.tokens = Some(tla_init_bond);

                    setup::set_validators(
                        num_of_validators,
                        GenesisConfig {
                            parameters,
                            pos_params,
                            ..genesis
                        },
                        default_port_offset,
                    )
                },
                None,
            )?;

            let validators = (0..(num_of_validators as u64))
                .map(|validator_id| {
                    let args = ["ledger"];
                    let mut validator = run_as!(
                        test,
                        Who::Validator(validator_id),
                        Bin::Node,
                        args,
                        Some(40)
                    )?;
                    validator.exp_string("Namada ledger node started")?;
                    validator.exp_string("This node is a validator")?;
                    Ok(Some(validator.background()))
                })
                .collect::<Result<Vec<_>>>()?;

            let tla_validators =
                ["val"].into_iter().map(|x| x.into()).collect();

            let tla_accounts = [("val", "validator-0"), ("user2", BERTHA)]
                .into_iter()
                .map(|(x, y)| (x.into(), y.into()))
                .collect();

            let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(1));

            let epoch = get_epoch(&test, &validator_one_rpc)?;

            let delegation_withdrawable_epoch = Epoch(epoch.0 + 1);

            let secs_per_epoch = std::option_env!("NAMADA_E2E_EPOCH_DURATION")
                .map(|x| {
                    x.parse()
                        .expect("NAMADA_E2E_EPOCH_DURATION is not a number")
                })
                .unwrap_or(20);

            let start = Instant::now();
            let loop_timeout = Duration::new(secs_per_epoch + 20, 0);
            loop {
                if Instant::now().duration_since(start) > loop_timeout {
                    panic!(
                        "Timed out waiting for epoch: {}",
                        delegation_withdrawable_epoch
                    );
                }
                let epoch = get_epoch(&test, &validator_one_rpc)?;
                if epoch >= delegation_withdrawable_epoch {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            Ok(Self {
                test,
                validators,
                tla_validators,
                tla_accounts,
            })
        });

        mbt_reactor.register("selfDelegate", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(0));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, "validator-0");
            let amount = state.get("lastTx.value").i64();
            let amount_str = amount.to_string();

            let tx_args = vec![
                "bond",
                "--validator",
                real_sender,
                "--amount",
                &amount_str,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run_as!(
                system.test,
                Who::Validator(0),
                Bin::Client,
                tx_args,
                Some(40)
            )?;
            client.exp_string("Transaction is valid.")?;
            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("delegate", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, BERTHA);
            let amount = state.get("lastTx.value").i64();
            let amount_str = amount.to_string();

            let tx_args = vec![
                "bond",
                "--validator",
                "validator-0",
                "--source",
                real_sender,
                "--amount",
                &amount_str,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run!(system.test, Bin::Client, tx_args, Some(40))?;
            client.exp_string("Transaction is valid.")?;
            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("selfUnbond", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(0));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, "validator-0");
            let amount = state.get("lastTx.value").i64();
            let amount_str = amount.to_string();

            let tx_args = vec![
                "unbond",
                "--validator",
                real_sender,
                "--amount",
                &amount_str,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run_as!(
                system.test,
                Who::Validator(0),
                Bin::Client,
                tx_args,
                Some(40)
            )?;

            let expected =
                r#"(Amount \d+ withdrawable starting from epoch \d+\.\s*)+"#;
            let (_unread, matched) = client.exp_regex(expected)?;

            let re = regex::Regex::new(
                r"Amount (\d+) withdrawable starting from epoch (\d+)",
            )
            .unwrap();

            let mut map: BTreeMap<i64, i64> = BTreeMap::new();
            for cap in re.captures_iter(&matched) {
                let amount = cap[1].parse::<i64>().unwrap();
                let epoch = cap[2].parse::<i64>().unwrap();
                *map.entry(epoch).or_default() += amount;
            }

            assert_eq!(map.iter().next_back().unwrap().1, &amount);

            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("unbond", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, BERTHA);
            let amount = state.get("lastTx.value").i64();
            let amount_str = amount.to_string();

            let tx_args = vec![
                "unbond",
                "--validator",
                "validator-0",
                "--source",
                real_sender,
                "--amount",
                &amount_str,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run!(system.test, Bin::Client, tx_args, Some(40))?;

            let expected =
                r#"(Amount \d+ withdrawable starting from epoch \d+\.\s*)+"#;
            let (_unread, matched) = client.exp_regex(expected)?;

            println!(">>>>>>>>>>>>> {matched}");

            let re = regex::Regex::new(
                r"Amount (\d+) withdrawable starting from epoch (\d+)",
            )
            .unwrap();

            let mut map: BTreeMap<i64, i64> = BTreeMap::new();
            for cap in re.captures_iter(&matched) {
                let amount = cap[1].parse::<i64>().unwrap();
                let epoch = cap[2].parse::<i64>().unwrap();
                *map.entry(epoch).or_default() += amount;
            }

            assert_eq!(map.iter().next_back().unwrap().1, &amount);

            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("selfWithdraw", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(0));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, "validator-0");

            let tx_args = vec![
                "withdraw",
                "--validator",
                real_sender,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run_as!(
                system.test,
                Who::Validator(0),
                Bin::Client,
                tx_args,
                Some(40)
            )?;
            client.exp_string("Transaction is valid.")?;
            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("withdraw", |system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));

            let sender = state.get("lastTx.sender");
            let real_sender = system
                .tla_accounts
                .get(sender.str())
                .map(|x| x.as_str())
                .expect("account is not present");
            assert_eq!(real_sender, BERTHA);

            // Submit a withdrawal of the delegation
            let tx_args = vec![
                "withdraw",
                "--validator",
                "validator-0",
                "--source",
                real_sender,
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run!(system.test, Bin::Client, tx_args, Some(40))?;
            client.exp_string("Transaction is valid.")?;
            client.assert_success();

            Ok(())
        });

        mbt_reactor.register("endOfEpoch", |system, _state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));
            let epoch = get_epoch(&system.test, &validator_one_rpc)?;

            let next_epoch = Epoch(epoch.0 + 1);

            println!("Current epoch: {}, waiting till: {}", epoch, next_epoch);

            let secs_per_epoch = std::option_env!("NAMADA_E2E_EPOCH_DURATION")
                .map(|x| {
                    x.parse()
                        .expect("NAMADA_E2E_EPOCH_DURATION is not a number")
                })
                .unwrap_or(20);

            let start = Instant::now();
            let loop_timeout = Duration::new(secs_per_epoch + 20, 0);
            loop {
                if Instant::now().duration_since(start) > loop_timeout {
                    panic!("Timed out waiting for epoch: {}", next_epoch);
                }
                let epoch = get_epoch(&system.test, &validator_one_rpc)?;
                if epoch >= next_epoch {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            Ok(())
        });

        mbt_reactor.register("evidence", |system, _state| {
            // Copy the first genesis validator base-dir
            let validator_0_base_dir =
                system.test.get_base_dir(&Who::Validator(0));
            let validator_0_base_dir_copy =
                system.test.test_dir.path().join("validator-0-copy");
            fs_extra::dir::copy(
                validator_0_base_dir,
                &validator_0_base_dir_copy,
                &fs_extra::dir::CopyOptions {
                    copy_inside: true,
                    ..Default::default()
                },
            )
            .unwrap();

            // Increment its ports and generate new node ID to avoid conflict

            // Same as in `genesis/e2e-tests-single-node.toml` for `validator-0`
            let net_address_0 =
                SocketAddr::from_str("127.0.0.1:27656").unwrap();
            let net_address_port_0 = net_address_0.port();

            let update_config = |ix: u8, mut config: Config| {
                let first_port = net_address_port_0 + 6 * (ix as u16 + 1);
                config.ledger.tendermint.p2p_address.set_port(first_port);
                config
                    .ledger
                    .tendermint
                    .rpc_address
                    .set_port(first_port + 1);
                config.ledger.shell.ledger_address.set_port(first_port + 2);
                config
            };

            let validator_0_copy_config = update_config(
                2,
                Config::load(
                    &validator_0_base_dir_copy,
                    &system.test.net.chain_id,
                    None,
                ),
            );
            validator_0_copy_config
                .write(
                    &validator_0_base_dir_copy,
                    &system.test.net.chain_id,
                    true,
                )
                .unwrap();

            // Generate a new node key
            use rand::prelude::ThreadRng;
            use rand::thread_rng;

            let mut rng: ThreadRng = thread_rng();
            let node_sk = ed25519::SigScheme::generate(&mut rng);
            let node_sk = key::common::SecretKey::Ed25519(node_sk);
            let tm_home_dir = validator_0_base_dir_copy
                .join(system.test.net.chain_id.as_str())
                .join("tendermint");
            let _node_pk =
                client::utils::write_tendermint_node_key(&tm_home_dir, node_sk);

            let args = ["ledger"];

            // Run it to get it to double vote and sign block
            let loc = format!("{}:{}", std::file!(), std::line!());
            // This node will only connect to `validator_1`, so that nodes
            // `validator_0` and `validator_0_copy` should start double signing
            let mut validator_0_copy = setup::run_cmd(
                Bin::Node,
                args,
                Some(40),
                &system.test.working_dir,
                validator_0_base_dir_copy,
                "validator",
                loc,
            )?;
            validator_0_copy.exp_string("Namada ledger node started")?;
            validator_0_copy.exp_string("This node is a validator")?;
            let _bg_validator_0_copy = validator_0_copy.background();

            println!("clone validator started");

            // Submit a valid token transfer tx to validator 0
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));
            let tx_args = [
                "transfer",
                "--source",
                ALBERT,
                "--target",
                CHRISTEL,
                "--token",
                NAM,
                "--amount",
                "10.1",
                "--gas-amount",
                "0",
                "--gas-limit",
                "0",
                "--gas-token",
                NAM,
                "--ledger-address",
                &validator_one_rpc,
            ];
            let mut client = run!(system.test, Bin::Client, tx_args, Some(40))?;
            client.exp_string("Transaction is valid.")?;
            client.assert_success();

            println!("tx send success");

            // Wait for double signing evidence
            let mut validator_1 = system.validators[1]
                .take()
                .expect("validator background command is not present")
                .foreground();

            println!("checking for validator slash");

            validator_1.exp_string("Processing evidence")?;
            validator_1.exp_string("Slashing")?;

            println!("validator slashed");

            system.validators[1] = Some(validator_1.background());

            Ok(())
        });

        mbt_reactor.register_invariant_state(|system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));
            let balance_offset = system
                .tla_accounts
                .iter()
                .map(|(tla_acc, blk_acc)| {
                    let tx_args = [
                        "balance",
                        "--owner",
                        blk_acc,
                        "--token",
                        NAM,
                        "--ledger-address",
                        &validator_one_rpc,
                    ];
                    let mut client =
                        run!(system.test, Bin::Client, tx_args, Some(40))?;
                    let (_unread, matched) =
                        client.exp_regex(&format!("{NAM}:\\s+\\d+\r?\n"))?;
                    let blk_balance: i64 =
                        matched.trim().rsplit_once(" ").unwrap().1.parse()?;
                    client.assert_success();

                    let tla_balance = state
                        .get(&format!("balanceOf.\\#map.#(0=\"{tla_acc}\").1"))
                        .i64();

                    assert!(blk_balance > tla_balance);

                    std::thread::sleep(std::time::Duration::from_secs(1));

                    Ok((tla_acc, blk_balance - tla_balance))
                })
                .collect::<Result<HashMap<_, _>>>()?;

            Ok(serde_json::json!({ "balance_offset": balance_offset }))
        });

        mbt_reactor.register_invariant_state(|system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));

            let bonded_stake_offset = system
                .tla_validators
                .iter()
                .map(|val| {
                    let blk_val =
                        system.tla_accounts.get(val).ok_or_else(|| {
                            eyre::eyre!("validator account doesn't exist.")
                        })?;

                    let blk_bonded_stake =
                        (find_bonded_stake(
                            &system.test,
                            blk_val,
                            &validator_one_rpc,
                        )?
                        .change() as u64
                            / token::SCALE) as i64;

                    // offset with (PIPELINE_LEN + 1)
                    // as cli returns the staked-bond from last commited epoch, not current one
                    let prev_id = state.get("totalDeltas.\\#map.#").i64()
                        - 1
                        - (PIPELINE_LEN as i64);

                    let tla_bonded_stake = state
                        .get(&format!("totalDeltas.\\#map.#(0={prev_id}).1"))
                        .i64();

                    Ok((val, blk_bonded_stake - tla_bonded_stake))
                })
                .collect::<Result<HashMap<_, _>>>()?;

            Ok(serde_json::json!({
                "bonded_stake_offset": bonded_stake_offset
            }))
        });

        mbt_reactor.register_invariant_state(|system, state| {
            let validator_one_rpc =
                get_actor_rpc(&system.test, &Who::Validator(1));

            let blk_epoch =
                get_epoch(&system.test, &validator_one_rpc)?.0 as i64;
            let tla_epoch = state.get("epoch").i64();

            Ok(serde_json::json!({ "epoch_offset": blk_epoch - tla_epoch }))
        });

        Ok(mbt_reactor)
    }
}

// #[test_case::test_case("src/e2e/data/traces/example-20-p1-u2.itf.json")]
// #[test_case::test_case("src/e2e/data/traces/example-300-p1-u2.itf.json")]
// #[test_case::test_case("src/e2e/data/traces/example-slash-50-p2-u4.itf.json")]
// #[test_case::test_case("src/e2e/data/traces/example-slash-50-p2-u6.itf.json")]
#[test_case::test_case("src/e2e/data/traces/example-slash-30-p1-u2.itf.json")]
fn mbt_pos(path: &str) -> Result<()> {
    let json_string = std::fs::read_to_string(path)?;
    let json_value = gjson::parse(&json_string);
    NamadaBlockchain::get_reactor()?.test(&json_value.get("states").array())?;
    Ok(())
}
