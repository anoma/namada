//! Anoma node CLI.

use std::path::Path;

use anoma_apps::config::Config;
use anoma_apps::node::{gossip, ledger};
use anoma_apps::{cli, config};
use eyre::{Context, Result};

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::anoma_node_cli();
    let base_dir = &ctx.global_args.base_dir;
    match cmd {
        cli::cmds::AnomaNode::Ledger(sub) => match sub {
            cli::cmds::Ledger::Run(_) => {
                let config = load_config(base_dir);
                let ledger_cfg = config.ledger.unwrap_or_default();
                ledger::run(ledger_cfg);
            }
            cli::cmds::Ledger::Reset(_) => {
                let config = load_config(base_dir);
                let ledger_cfg = config.ledger.unwrap_or_default();
                ledger::reset(ledger_cfg)
                    .wrap_err("Failed to reset Anoma node")?;
            }
        },
        cli::cmds::AnomaNode::Gossip(sub) => match sub {
            cli::cmds::Gossip::Run(cli::cmds::GossipRun(args)) => {
                let config = load_config(base_dir);
                let mut gossip_cfg = config.intent_gossiper.unwrap_or_default();
                let tx_source_address = ctx.get_opt(args.tx_source_address);
                let tx_signing_key = ctx.get_opt_cached(args.tx_signing_key);
                gossip_cfg.update(
                    args.addr,
                    args.rpc,
                    args.matchmaker_path,
                    args.tx_code_path,
                    args.ledger_addr,
                    args.filter_path,
                );
                gossip::run(gossip_cfg, tx_source_address, tx_signing_key)
                    .wrap_err(
                        "Failed to run gossip
            service",
                    )?;
            }
        },
        cli::cmds::AnomaNode::Config(sub) => match sub {
            cli::cmds::Config::Gen(_) => {
                let gen_config = config::Config::generate(base_dir, false)
                    .wrap_err("Failed to generate the default config")?;
                tracing::debug!("Generated config {:?}", gen_config);
            }
        },
    }
    Ok(())
}

/// Load config from expected path in the `base_dir` or generate a new one if it
/// doesn't exist.
fn load_config(base_dir: &Path) -> Config {
    match Config::read(base_dir) {
        Ok(config) => config,
        Err(err) => {
            eprintln!(
                "Tried to read config in {} but failed with: {}",
                base_dir.display(),
                err
            );
            cli::safe_exit(1)
        }
    }
}
