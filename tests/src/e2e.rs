//! End-to-end tests for Anoma binaries

#[cfg(test)]
mod tests {
    use core::time;
    use std::path::PathBuf;
    use std::process::Command;
    use std::{fs, thread};

    use anoma::config::{Config, IntentGossiper};
    use assert_cmd::assert::OutputAssertExt;
    use assert_cmd::cargo::CommandCargoExt;
    use color_eyre::eyre::Result;
    use eyre::eyre;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    use rexpect::session::spawn_command;
    use tempfile::tempdir;

    /// A helper that should be ran on start of every e2e test case.
    fn setup() -> PathBuf {
        let working_dir = fs::canonicalize("..").unwrap();
        // Build the workspace
        Command::new("cargo")
            .arg("build")
            .current_dir(&working_dir)
            .output()
            .unwrap();
        // Check that tendermint is on $PATH
        Command::new("which").arg("tendermint").assert().success();
        working_dir
    }

    /// Test that when we "run-ledger" with all the possible command
    /// combinations from fresh state, the node starts-up successfully.
    #[test]
    fn run_ledger() -> Result<()> {
        let dir = setup();

        let base_dir = tempdir().unwrap();

        let cmd_combinations = vec![
            ("anoma", vec![]),
            ("anoma", vec!["node"]),
            ("anoman", vec![]),
        ];

        // Start the ledger
        for (cmd_name, args) in cmd_combinations {
            let mut cmd = Command::cargo_bin(cmd_name)?;

            cmd.current_dir(&dir)
                .env("ANOMA_LOG", "debug")
                .args(&["--base-dir", &base_dir.path().to_string_lossy()])
                .args(args)
                .arg("run-ledger");

            let cmd_str = format!("{:?}", cmd);

            let mut session =
                spawn_command(cmd, Some(30_000)).map_err(|e| {
                    eyre!(format!("in command: {}\n\nReason: {}", cmd_str, e))
                })?;

            session
                .exp_string("Anoma ledger node started")
                .map_err(|e| {
                    eyre!(format!("in command: {}\n\nReason: {}", cmd_str, e))
                })?;
        }

        Ok(())
    }

    /// In this test we:
    /// 1. Run the ledger node
    /// 2. Shut it down
    /// 3. Run the ledger again, it should load its previous state
    /// 4. Shut it down
    /// 5. Reset the ledger's state
    /// 6. Run the ledger again, it should start from fresh state
    #[test]
    fn run_ledger_load_state_and_reset() -> Result<()> {
        let dir = setup();

        let base_dir = tempdir().unwrap();
        let base_dir_arg = &base_dir.path().to_string_lossy();

        // 1. Run the ledger node
        let mut cmd = Command::cargo_bin("anoma")?;
        cmd.current_dir(&dir).env("ANOMA_LOG", "debug").args(&[
            "--base-dir",
            base_dir_arg,
            "run-ledger",
        ]);
        println!("Running {:?}", cmd);
        let mut session = spawn_command(cmd, Some(30_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("Anoma ledger node started")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // There should be no previous state
        session
            .exp_string("No state could be found")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // Wait to commit a block
        session
            .exp_regex(r"Committed block hash.*, height: 2")
            .map_err(|e| eyre!(format!("{}", e)))?;
        // 2. Shut it down
        session
            .send_control('c')
            .map_err(|e| eyre!(format!("{}", e)))?;
        drop(session);

        // 3. Run the ledger again, it should load its previous state
        let mut cmd = Command::cargo_bin("anoma")?;
        cmd.current_dir(&dir).env("ANOMA_LOG", "debug").args(&[
            "--base-dir",
            base_dir_arg,
            "run-ledger",
        ]);
        println!("Running {:?}", cmd);
        let mut session = spawn_command(cmd, Some(30_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("Anoma ledger node started")
            .map_err(|e| eyre!(format!("{}", e)))?;

        // There should be previous state now
        session
            .exp_string("Last state root hash:")
            .map_err(|e| eyre!(format!("{}", e)))?;
        // 4. Shut it down
        session
            .send_control('c')
            .map_err(|e| eyre!(format!("{}", e)))?;
        drop(session);

        // 5. Reset the ledger's state
        let mut cmd = Command::cargo_bin("anoma")?;
        cmd.current_dir(&dir).env("ANOMA_LOG", "debug").args(&[
            "--base-dir",
            base_dir_arg,
            "reset-ledger",
        ]);
        cmd.assert().success();

        // 6. Run the ledger again, it should start from fresh state
        let mut cmd = Command::cargo_bin("anoma")?;
        cmd.current_dir(&dir).env("ANOMA_LOG", "debug").args(&[
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

        Ok(())
    }

    /// Test that when we "run-gossip" a peer with no seeds should fail
    /// bootstrapping kademlia. A peer with a seed should be able to
    /// bootstrap kademia and connect to the other peer.
    #[test]
    fn run_gossip() -> Result<()> {
        setup();

        let base_dir = tempdir().unwrap();
        let node_dirs =
            generate_network_of(base_dir.path().to_path_buf(), 2, false, true);

        let first_node_dir = node_dirs[0].0.to_str().unwrap();
        let first_node_peer_id = node_dirs[0].1.to_string();

        let second_node_dir = node_dirs[1].0.to_str().unwrap();
        let second_node_peer_id = node_dirs[1].1.to_string();

        let mut base_node = Command::cargo_bin("anoman")?;
        base_node.env("ANOMA_LOG", "debug");
        base_node.args(&["--base-dir", first_node_dir, "run-gossip"]);

        //  Node without peers
        let mut session = spawn_command(base_node, Some(20_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string(&format!("Peer id: PeerId(\"{}\")", first_node_peer_id))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("failed to bootstrap kad : NoKnownPeers")
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string("listening on 127.0.0.1:20201")
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string(
                "HEARTBEAT: Mesh low. Topic: asset_v0 Contains: 0 needs: 2",
            )
            .map_err(|e| eyre!(format!("{}", e)))?;

        drop(session);

        let mut base_node = Command::cargo_bin("anoman")?;
        base_node.args(&["--base-dir", first_node_dir, "run-gossip"]);

        let mut peer_node = Command::cargo_bin("anoman")?;
        peer_node.args(&["--base-dir", second_node_dir, "run-gossip"]);

        let mut session = spawn_command(base_node, Some(20_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_string(&format!("Peer id: PeerId(\"{}\")", first_node_peer_id))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session
            .exp_regex(&format!(
                ".*(PeerConnected(PeerId(\"{}\")))*",
                second_node_peer_id
            ))
            .map_err(|e| eyre!(format!("{}", e)))?;

        sleep(2);

        let mut session_two = spawn_command(peer_node, Some(20_000))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session_two
            .exp_string(&format!("Peer id: PeerId(\"{}\"", second_node_peer_id))
            .map_err(|e| eyre!(format!("{}", e)))?;

        session_two
            .exp_regex(&format!(
                ".*(PeerConnected(PeerId(\"{}\")))*",
                first_node_peer_id
            ))
            .map_err(|e| eyre!(format!("{}", e)))?;

        drop(session);

        drop(session_two);

        Ok(())
    }

    pub fn generate_network_of(
        path: PathBuf,
        n_of_peers: u32,
        with_mdns: bool,
        with_kademlia: bool,
    ) -> Vec<(PathBuf, PeerId)> {
        let mut index = 0;

        let mut node_dirs: Vec<(PathBuf, PeerId)> = Vec::new();

        while index < n_of_peers {
            let node_path = path.join(format!("anoma-{}", index));

            let mut config = Config::default();
            let info = build_peers(index, node_dirs.clone());

            let gossiper_config = IntentGossiper::default_with_address(
                "127.0.0.1".to_string(),
                20201 + index,
                info,
                with_mdns,
                with_kademlia,
            );
            let peer_key =
                Keypair::Ed25519(gossiper_config.gossiper.key.clone());
            let peer_id = PeerId::from(peer_key.public());

            node_dirs.push((node_path.clone(), peer_id));

            config.intent_gossiper = Some(gossiper_config);

            config.write(node_path.clone(), false).unwrap();
            index += 1;
        }
        node_dirs
    }

    fn sleep(seconds: u64) {
        thread::sleep(time::Duration::from_secs(seconds));
    }

    fn build_peers(
        index: u32,
        network: Vec<(PathBuf, PeerId)>,
    ) -> Vec<(String, u32, PeerId)> {
        if index > 0 {
            return vec![(
                "127.0.0.1".to_string(),
                20201 + index - 1,
                network[index as usize - 1].1,
            )];
        }
        return vec![];
    }
}
