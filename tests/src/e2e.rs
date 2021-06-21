//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
    use std::process::Command;

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

    fn setup() {
        std::env::set_current_dir("..").unwrap();
        Command::new("cargo").arg("build").output().unwrap();
    }
}
