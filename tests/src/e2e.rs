//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, process::Command};

    use anoma::config::{Config, IntentGossiper};
    use assert_cmd::cargo::CommandCargoExt;
    use color_eyre::eyre::Result;
    use eyre::eyre;
    use rexpect::session::spawn_command;
    use tempfile::tempdir;

    /// A helper that should be ran on start of every e2e test case.
    fn setup() {
        std::env::set_current_dir("..").unwrap();
        Command::new("cargo").arg("build").output().unwrap();
    }

    /// Test that when we "run-ledger" from fresh state, the node starts-up
    /// successfully. When we shut it down and run again, it should load its
    /// previous state.
    #[test]
    fn run_ledger() -> Result<()> {
        setup();

        let base_dir = tempdir().unwrap();

        // Start the ledger
        let mut cmd = Command::cargo_bin("anoman")?;
        cmd.args(&[
            "--base-dir",
            &base_dir.path().to_string_lossy(),
            "run-ledger",
        ]);
        let mut session = spawn_command(cmd, Some(30_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("Anoma ledger node started")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // There should be no previous state
        session
            .exp_string("No state could be found")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // Wait to commit a block and shut down the ledger
        session
            .exp_string("Committed block hash")
            .map_err(|e| eyre!(format!("{}", e)))?;
        drop(session);

        // Start the ledger again, in the same directory
        let mut cmd = Command::cargo_bin("anoman")?;
        cmd.args(&[
            "--base-dir",
            &base_dir.path().to_string_lossy(),
            "run-ledger",
        ]);
        let mut session = spawn_command(cmd, Some(30_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("Anoma ledger node started")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // There should be previous state now
        session
            .exp_string("Last state root hash:")
            .map_err(|e| eyre!(format!("{}", e)))?;

        Ok(())
    }

    /// Test that when we "run-gossip" a peer with no seeds should fail bootstrapping kademlia.
    /// A peer with a seed should be able to bootstrap kademia and connect to the other peer.
    #[test]
    fn run_gossip() -> Result<()> {
        setup();

        let base_dir = tempdir().unwrap();
        let node_dirs = generate_network_of(base_dir.path().to_path_buf(), 2);

        let mut cmd = Command::cargo_bin("anoman")?;
        cmd.args(&["--base-dir", node_dirs[0].to_str().unwrap(), "run-gossip"]);

        let mut session = spawn_command(cmd, Some(30_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("failed to bootstrap kad : NoKnownPeers")
            .map_err(|e| eyre!(format!("{}", e)))?;

        drop(session);

        Ok(())
    }

    pub fn generate_network_of(path: PathBuf, n_of_peers: u32) -> Vec<PathBuf> {
        let mut index = 0;

        let mut node_dirs: Vec<PathBuf> = Vec::new();
        while index < n_of_peers {
            let node_path = path.join(format!("anoma-{}", index));
            node_dirs.push(node_path.clone());
            let mut config = Config::default();
            let gossiper_config = IntentGossiper::default_with_address(
                "0.0.0.0".to_string(),
                20201 + index,
            );
            config.intent_gossiper = Some(gossiper_config);
            config.write(node_path.clone(), true).unwrap();
            index += 1;
        }
        node_dirs
    }
}
