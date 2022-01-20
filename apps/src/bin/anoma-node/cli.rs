//! Anoma node CLI.

use anoma_apps::cli::{self, args, cmds};
use anoma_apps::config;
use anoma_apps::node::{gossip, ledger, matchmaker};
use eyre::{Context, Result};

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::anoma_node_cli();
    match cmd {
        cmds::AnomaNode::Ledger(sub) => match sub {
            cmds::Ledger::Run(_) => {
                ledger::run(ctx.config.ledger, ctx.config.wasm_dir);
            }
            cmds::Ledger::Reset(_) => {
                ledger::reset(ctx.config.ledger)
                    .wrap_err("Failed to reset Anoma node")?;
            }
        },
        cmds::AnomaNode::Gossip(sub) => match sub {
            cmds::Gossip::Run(cmds::GossipRun(args)) => {
                let tx_source_address = ctx.get_opt(&args.tx_source_address);
                let tx_signing_key = ctx.get_opt_cached(&args.tx_signing_key);
                let config = ctx.config;
                let mut gossip_cfg = config.intent_gossiper;
                gossip_cfg.update(
                    args.addr,
                    args.rpc,
                    args.matchmaker_path,
                    args.tx_code_path,
                    args.ledger_addr,
                    args.filter_path,
                );
                gossip::run(
                    gossip_cfg,
                    &config
                        .ledger
                        .shell
                        .base_dir
                        .join(ctx.global_config.default_chain_id.as_str()),
                    &config.wasm_dir,
                    tx_source_address,
                    tx_signing_key,
                )
                .wrap_err("Failed to run gossip service")?;
            }
        },
        cmds::AnomaNode::Matchmaker(cmds::Matchmaker(args::Matchmaker {
            intent_gossiper_addr,
            matchmaker_path,
            tx_code_path,
            ledger_addr,
            tx_signing_key,
            tx_source_address,
        })) => {
            let tx_signing_key = ctx.get_cached(&tx_signing_key);
            let tx_source_address = ctx.get(&tx_source_address);

            let mut config = ctx.config;
            let wasm_dir = config.wasm_dir;
            let mm_config = match config.matchmaker.take() {
                Some(mut mm_config) => {
                    if let Some(matchmaker_path) = matchmaker_path.as_ref() {
                        mm_config.matchmaker_path = matchmaker_path.clone();
                    }
                    if let Some(tx_code_path) = tx_code_path.as_ref() {
                        mm_config.tx_code_path = tx_code_path.clone();
                    }
                    mm_config
                }
                None => config::Matchmaker {
                    matchmaker_path: matchmaker_path.unwrap(),
                    tx_code_path: tx_code_path.unwrap(),
                },
            };

            matchmaker::run(
                mm_config,
                intent_gossiper_addr,
                ledger_addr,
                tx_signing_key,
                tx_source_address,
                wasm_dir,
            );
        }
        cmds::AnomaNode::Config(sub) => match sub {
            cmds::Config::Gen(cmds::ConfigGen) => {
                // If the config doesn't exit, it gets generated in the context.
                // In here, we just need to overwrite the default chain ID, in
                // case it's been already set to a different value
                if let Some(chain_id) = ctx.global_args.chain_id.as_ref() {
                    ctx.global_config.default_chain_id = chain_id.clone();
                    ctx.global_config
                        .write(&ctx.global_args.base_dir)
                        .unwrap_or_else(|err| {
                            eprintln!("Error writing global config: {}", err);
                            cli::safe_exit(1)
                        });
                }
                tracing::debug!(
                    "Generated config and set default chain ID to {}",
                    &ctx.global_config.default_chain_id
                );
            }
        },
    }
    Ok(())
}
