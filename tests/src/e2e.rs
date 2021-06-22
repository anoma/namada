//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
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
        setup();

        let base_dir = tempdir().unwrap();

        let mut cmd = Command::new("cargo");
        cmd.env("ANOMA_LOG_COLOR", "false").args(&[
            "run",
            "--bin",
            "anoman",
            "--",
            "--base-dir",
            &base_dir.path().to_string_lossy(),
            "run-ledger",
        ]);
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
    }
}
