//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use assert_cmd::cargo::CommandCargoExt;
    use color_eyre::eyre::Result;
    use eyre::eyre;
    use rexpect::session::spawn_command;
    use tempfile::tempdir;

    /// A helper that should be ran on start of every e2e test case.
    fn setup() -> PathBuf {
        let working_dir = fs::canonicalize("..").unwrap();
        Command::new("cargo")
            .arg("build")
            .current_dir(&working_dir)
            .output()
            .unwrap();
        working_dir
    }

    /// Test that when we "run-ledger" from fresh state, the node starts-up
    /// successfully. When we shut it down and run again, it should load its
    /// previous state.
    #[test]
    fn run_ledger() -> Result<()> {
        let dir = setup();

        let base_dir = tempdir().unwrap();

        // Start the ledger
        let mut cmd = Command::cargo_bin("anoman")?;
        cmd.current_dir(&dir).args(&[
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
        cmd.current_dir(&dir).args(&[
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
}
