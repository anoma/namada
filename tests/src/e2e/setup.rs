use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, thread, time};

use anoma::types::chain::ChainId;
use anoma_apps::config::{Config, IntentGossiper, Ledger};
use assert_cmd::assert::OutputAssertExt;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use escargot::CargoBuild;
use eyre::eyre;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use rexpect::process::wait::WaitStatus;
use rexpect::session::{spawn_command, PtySession};
use tempfile::{tempdir, TempDir};

const APPS_PACKAGE: &str = "anoma_apps";

/// Env. var for running e2e tests in debug mode
const ENV_VAR_DEBUG: &str = "ANOMA_E2E_DEBUG";

/// Anoma binaries
#[derive(Debug)]
pub enum Bin {
    Node,
    Client,
    Wallet,
}

#[derive(Debug)]
pub struct Test {
    pub working_dir: PathBuf,
    pub base_dir: TempDir,
}

/// Get an [`AnomaCmd`] to run an Anoma binary. By default, these will run in
/// release mode. This can be disabled by setting environment variable
/// `ANOMA_E2E_DEBUG=true`.
/// On [`AnomaCmd`], you can then call e.g. `exp_string` or `exp_regex` to look
/// for an expected output from the command.
///
/// This is a helper macro that adds file and line location to the [`run_cmd`]
/// function call.
#[macro_export]
macro_rules! run {
    ($test:expr, $bin:expr, $args:expr, $timeout_sec:expr) => {{
        // The file and line will expand to the location that invoked `run_cmd!`
        let loc = format!("{}:{}", std::file!(), std::line!());
        $test.run_cmd($bin, $args, $timeout_sec, loc)
    }};
}

impl Test {
    /// Start a new E2E test
    pub fn new() -> Self {
        let working_dir = working_dir();
        let base_dir = tempdir().unwrap();
        Self {
            working_dir,
            base_dir,
        }
    }

    /// Use the `run!` macro instead of calling this method directly to get
    /// automatic source location reporting.
    ///
    /// Get an [`AnomaCmd`] to run an Anoma binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `ANOMA_E2E_DEBUG=true`.
    pub fn run_cmd<I, S>(
        &self,
        bin: Bin,
        args: I,
        timeout_sec: Option<u64>,
        loc: String,
    ) -> Result<AnomaCmd>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        run_cmd(
            bin,
            args,
            timeout_sec,
            &self.working_dir,
            &self.base_dir,
            loc,
        )
    }
}

/// A helper that should be ran on start of every e2e test case.
pub fn working_dir() -> PathBuf {
    let working_dir = fs::canonicalize("..").unwrap();
    // Check that tendermint is on $PATH
    Command::new("which").arg("tendermint").assert().success();
    working_dir
}

/// A command under test
pub struct AnomaCmd {
    pub session: PtySession,
    /// The command that ran this session, used in error reporting
    cmd_str: String,
}

impl AnomaCmd {
    /// Assert that the process exited with success
    pub fn assert_success(&self) {
        let status = self.session.process.wait().unwrap();
        assert_eq!(
            WaitStatus::Exited(self.session.process.child_pid, 0),
            status
        );
    }

    /// Wait until provided string is seen on stdout of child process.
    /// Return the yet unread output (without the matched string)
    ///
    /// Wrapper over the inner `PtySession`'s functions with custom error
    /// reporting.
    pub fn exp_string(&mut self, needle: &str) -> Result<String> {
        self.session.exp_string(needle).map_err(|e| {
            eyre!(format!("\n\nIn command: {}\n\nReason: {}", self.cmd_str, e))
        })
    }

    /// Wait until provided regex is seen on stdout of child process.
    /// Return a tuple:
    /// 1. the yet unread output
    /// 2. the matched regex
    ///
    /// Wrapper over the inner `PtySession`'s functions with custom error
    /// reporting.
    pub fn exp_regex(&mut self, regex: &str) -> Result<(String, String)> {
        self.session.exp_regex(regex).map_err(|e| {
            eyre!(format!("\n\nIn command: {}\n\nReason: {}", self.cmd_str, e))
        })
    }

    /// Send a control code to the running process and consume resulting output
    /// line (which is empty because echo is off)
    ///
    /// E.g. `send_control('c')` sends ctrl-c. Upper/smaller case does not
    /// matter.
    ///
    /// Wrapper over the inner `PtySession`'s functions with custom error
    /// reporting.
    pub fn send_control(&mut self, c: char) -> Result<()> {
        self.session.send_control(c).map_err(|e| {
            eyre!(format!("\n\nIn command: {}\n\nReason: {}", self.cmd_str, e))
        })
    }
}

impl Drop for AnomaCmd {
    fn drop(&mut self) {
        // Clean up the process, if its still running
        let _ = self.session.process.exit();
    }
}

/// Get a [`Command`] to run an Anoma binary. By default, these will run in
/// release mode. This can be disabled by setting environment variable
/// `ANOMA_E2E_DEBUG=true`.
pub fn run_cmd<I, S>(
    bin: Bin,
    args: I,
    timeout_sec: Option<u64>,
    working_dir: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
    loc: String,
) -> Result<AnomaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Root cargo workspace manifest path
    let manifest_path = working_dir.as_ref().join("Cargo.toml");
    let bin_name = match bin {
        Bin::Node => "anoman",
        Bin::Client => "anomac",
        Bin::Wallet => "anomaw",
    };
    // Allow to run in debug
    let run_debug = match env::var(ENV_VAR_DEBUG) {
        Ok(val) => val.to_ascii_lowercase() != "false",
        _ => false,
    };
    let cmd = CargoBuild::new()
        .package(APPS_PACKAGE)
        .manifest_path(manifest_path)
        .bin(bin_name);
    let cmd = if run_debug {
        cmd
    } else {
        // Use the same build settings as `make build-release`
        cmd.release().no_default_features().features("std")
    };
    let mut cmd = cmd.run().unwrap().command();
    cmd.env("ANOMA_LOG", "anoma=debug")
        .current_dir(working_dir)
        .args(&["--base-dir", &base_dir.as_ref().to_string_lossy()])
        .args(args);

    let cmd_str = format!("{:?}", cmd);

    let timeout_ms = timeout_sec.map(|sec| sec * 1_000);
    println!("Starting cmd {}", cmd_str);
    let mut session = spawn_command(cmd, timeout_ms).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}\n{}: {}",
            "Failed to run".underline().red(),
            cmd_str,
            "Location".underline().red(),
            loc,
            "Error".underline().red(),
            e
        )
    })?;

    if let Bin::Node = &bin {
        // When running a node command, we need to wait a bit before checking
        // status
        sleep(1);

        // If the command failed, try print out its output
        if let Some(rexpect::process::wait::WaitStatus::Exited(_, result)) =
            session.process.status()
        {
            if result != 0 {
                return Err(eyre!(
                    "\n\n{}: {}\n{}: {} \n\n{}: {}",
                    "Failed to run".underline().red(),
                    cmd_str,
                    "Location".underline().red(),
                    loc,
                    "Output".underline().red(),
                    session.exp_eof().unwrap_or_else(|err| format!(
                        "No output found, error: {}",
                        err
                    ))
                ));
            }
        }
    }
    Ok(AnomaCmd { session, cmd_str })
}

/// Returns directories with generated config files that should be used as
/// the `--base-dir` for Anoma commands. The first intent gossiper node is
/// setup to also open RPC for receiving intents and run a matchmaker.
pub fn generate_network_of(
    path: PathBuf,
    n_of_peers: u32,
    with_mdns: bool,
    with_kademlia: bool,
    with_matchmaker: bool,
) -> Vec<(PathBuf, PeerId)> {
    let mut index = 0;

    let mut node_dirs: Vec<(PathBuf, PeerId)> = Vec::new();

    let chain_id = ChainId::default();

    while index < n_of_peers {
        let node_path = path.join(format!("anoma-{}", index));

        let info = build_peers(index, node_dirs.clone());

        let gossiper_config = IntentGossiper::default_with_address(
            "127.0.0.1".to_string(),
            20201 + index,
            info,
            with_mdns,
            with_kademlia,
            index == 0 && with_matchmaker,
            index == 0 && with_matchmaker,
        );
        let peer_key = Keypair::Ed25519(gossiper_config.gossiper.key.clone());
        let peer_id = PeerId::from(peer_key.public());

        node_dirs.push((node_path.clone(), peer_id));

        let config = Config {
            ledger: Ledger::new(&node_path, chain_id.clone()),
            intent_gossiper: gossiper_config,
            wasm_dir: "wasm".into(),
        };

        config.write(&node_path, &chain_id, false).unwrap();
        index += 1;
    }
    node_dirs
}

pub fn sleep(seconds: u64) {
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

#[allow(dead_code)]
pub mod constants {
    use std::fs;
    use std::path::PathBuf;

    // User addresses
    pub const ALBERT: &str = "atest1v4ehgw368ycryv2z8qcnxv3cxgmrgvjpxs6yg333gym5vv2zxepnj334g4rryvj9xucrgve4x3xvr4";
    pub const BERTHA: &str = "atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw";
    pub const CHRISTEL: &str = "atest1v4ehgw36x3qng3jzggu5yvpsxgcngv2xgguy2dpkgvu5x33kx3pr2w2zgep5xwfkxscrxs2pj8075p";
    pub const DAEWON: &str = "atest1d9khqw36xprrzdpk89rrws69g4z5vd6pgv65gvjrgeqnv3pcg4zns335xymry335gcerqs3etd0xfa";

    // Fungible token addresses
    pub const XAN: &str = "atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5";
    pub const BTC: &str = "atest1v4ehgw36xdzryve5gsc52veeg5cnsv2yx5eygvp38qcrvd29xy6rys6p8yc5xvp4xfpy2v694wgwcp";
    pub const ETH: &str = "atest1v4ehgw36xqmr2d3nx3ryvd2xxgmrq33j8qcns33sxezrgv6zxdzrydjrxveygd2yxumrsdpsf9jc2p";
    pub const DOT: &str = "atest1v4ehgw36gg6nvs2zgfpyxsfjgc65yv6pxy6nwwfsxgungdzrggeyzv35gveyxsjyxymyz335hur2jn";

    // Bite-sized tokens
    pub const SCHNITZEL: &str = "atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt";
    pub const APFEL: &str = "atest1v4ehgw36gfryydj9g3p5zv3kg9znyd358ycnzsfcggc5gvecgc6ygs2rxv6ry3zpg4zrwdfeumqcz9";
    pub const KARTOFFEL: &str = "atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90";

    // Paths to the WASMs used for tests
    pub const TX_TRANSFER_WASM: &str = "wasm/tx_transfer.wasm";
    pub const VP_USER_WASM: &str = "wasm/vp_user.wasm";
    pub const TX_NO_OP_WASM: &str = "wasm_for_tests/tx_no_op.wasm";
    pub const VP_ALWAYS_TRUE_WASM: &str = "wasm_for_tests/vp_always_true.wasm";
    pub const VP_ALWAYS_FALSE_WASM: &str =
        "wasm_for_tests/vp_always_false.wasm";
    pub const TX_MINT_TOKENS_WASM: &str = "wasm_for_tests/tx_mint_tokens.wasm";

    /// Find the absolute path to one of the WASM files above
    pub fn wasm_abs_path(file_name: &str) -> PathBuf {
        let working_dir = fs::canonicalize("..").unwrap();
        working_dir.join(file_name)
    }
}
