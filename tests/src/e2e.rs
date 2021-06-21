//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
    use std::process::Command;

    use rexpect::session::spawn_command;
    use tempfile::tempdir;

    // timeout for commands (may include Cargo build when ran via Cargo)
    const TIMEOUT_MS: u64 = 100_000;

    #[test]
    fn run_ledger() {
        let base_dir = tempdir().unwrap();

        std::env::set_current_dir("..").unwrap();
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
}
