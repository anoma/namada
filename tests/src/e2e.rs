//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
<<<<<<< HEAD
    use std::{path::PathBuf, process::Command};

    use anoma::config::{Config, IntentGossiper};
    use rexpect::session::spawn_command;
    use tempfile::tempdir;

    // timeout for commands
    const TIMEOUT_MS: u64 = 10_000;

    /// Test that when we "run-ledger" from fresh state, the node starts-up
    /// successfully.
    #[test]
    fn run_ledger() {
=======
    use std::process::Command;

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
>>>>>>> 51c66911cc2ad82a32a6b4a4ea3b34ba7ad493c2
        setup();

        let base_dir = tempdir().unwrap();

<<<<<<< HEAD
        let mut cmd = Command::new("cargo");
        cmd.env("ANOMA_LOG_COLOR", "false").args(&[
            "run",
            "--bin",
            "anoman",
            "--",
=======
        // Start the ledger
        let mut cmd = Command::cargo_bin("anoman")?;
        cmd.args(&[
>>>>>>> 51c66911cc2ad82a32a6b4a4ea3b34ba7ad493c2
            "--base-dir",
            &base_dir.path().to_string_lossy(),
            "run-ledger",
        ]);
<<<<<<< HEAD
        let mut p = spawn_command(cmd, Some(TIMEOUT_MS)).unwrap();
        p.exp_string("anoma::node::ledger: No state could be found")
            .unwrap();
    }

    #[test]
    fn gossip() {
        let base_dir = tempdir().unwrap();

        generate_network_of(base_dir.into_path(), 4);
    }

    fn setup() {
        std::env::set_current_dir("..").unwrap();
        Command::new("cargo").arg("build").output().unwrap();
    }

    pub fn generate_network_of(path: PathBuf, n_of_peers: u32) {
        let mut index = 0;
        while index < n_of_peers {
            let node_path = path.join(format!("anoma-{}", index));
            let mut config = Config::default();
            let mut gossiper_config = IntentGossiper::default();
            gossiper_config.set_address("0.0.0.0".to_string(), 20201 + index);
            config.intent_gossiper = Some(gossiper_config);
            config.write(node_path.clone(), true);
            index += 1;
        }
=======
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
>>>>>>> 51c66911cc2ad82a32a6b4a4ea3b34ba7ad493c2
    }
}
