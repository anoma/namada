//! Test that the Quint model corresponds to the Rust implementation by invoking
//! a Quint REPL from PoS state machine test and comparing the state of the
//! system against the state of the model.
//!
//! Run with e.g.:
//! ```bash
//! PROPTEST_CASES=1 \
//!   PROPTEST_MAX_SHRINK_ITERS=0 \
//!   QUINT_DIR=/path/to/PoS-quint \
//!   QUINT_MAIN_FILE=namada.qnt \
//!   cargo test pos_state_machine_test \
//!   --features test_quint \
//!   -- --nocapture
//! ```

use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use std::{env, fs};

use expectrl::process::unix::{PtyStream, UnixProcess};
use expectrl::session::Session;
use expectrl::stream::log::LogStream;
use expectrl::Regex;
use itertools::Itertools;
use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::types::address::Address;
use namada_core::types::storage::Epoch;

use super::{AbstractPosState, Transition};

/// Directory with the quint model - required
const ENV_QUINT_DIR: &str = "QUINT_DIR";
/// Quint model main file - optional, defaults to "namada.qnt"
const ENV_QUINT_MAIN_FILE: &str = "QUINT_MAIN_FILE";
/// Some operations in Quint take a while so keeping a generous timeout
const TIMEOUT: Duration = Duration::from_secs(300);
/// Quint REPL session log file contains the input and output
const REPL_LOG_FILE: &str = "quint_repl.log";
/// Quint input log file
const INPUT_LOG_FILE: &str = "quint_input.log";

#[derive(Debug)]
pub struct State {
    pub session: Session<UnixProcess, LogStream<PtyStream, File>>,
    pub input_log: File,
}

impl State {
    pub fn new(init_state: &AbstractPosState, storage: &TestWlStorage) -> Self {
        let quint_dir = env::var(ENV_QUINT_DIR).unwrap();
        let quint_main_file = env::var(ENV_QUINT_MAIN_FILE)
            .unwrap_or_else(|_| "namada.qnt".to_owned());
        let require_arg = format!("{quint_dir}/{quint_main_file}::namada");

        let mut cmd = Command::new("quint");
        cmd.arg("--quiet");
        cmd.args(["--require", &require_arg]);
        // Turn off colors (chalk npm package)
        cmd.env("FORCE_COLOR", "0");
        cmd.current_dir(quint_dir);

        let session = Session::spawn(cmd).unwrap();

        // Setup logging of the REPL session to a file
        println!(
            "Quint REPL session is logged to {REPL_LOG_FILE}, input to \
             {INPUT_LOG_FILE}."
        );
        let repl_log = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(REPL_LOG_FILE)
            .unwrap();
        let input_log = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(INPUT_LOG_FILE)
            .unwrap();
        let mut session = expectrl::session::log(session, repl_log).unwrap();

        session.set_expect_timeout(Some(TIMEOUT));

        // Wait for REPL start-up
        session.expect("true").unwrap();
        let mut state = Self { session, input_log };

        // Format args for init call
        let pipeline_offset = init_state.params.pipeline_len;
        let unbonding_offset = init_state.params.unbonding_len;
        let cubic_offset = init_state.params.cubic_slashing_window_length;
        let init_balance = init_state
            .genesis_validators
            .iter()
            .fold(0_u64, |acc, validator| acc + u64::from(validator.tokens));
        let genesis_validators_str = init_state
            .genesis_validators
            .iter()
            .map(|validator| {
                format!("\"{}\"", addr_for_quint(&validator.address))
            })
            .join(", ");
        let users = format!("Set({genesis_validators_str})");
        let validators = format!("Set({genesis_validators_str})");
        let quint_init_call = format!(
            "initWithParams({pipeline_offset}, {unbonding_offset}, \
             {cubic_offset}, {init_balance}, {users}, {validators})",
        );

        // Call init and wait for success
        state.send_input(&quint_init_call);
        state.session.expect(Regex(r"true\r\n")).unwrap();

        state.check(init_state, storage);

        state
    }

    /// Apply a transition and check that the Quint's state corresponds to Rust
    /// state
    pub fn apply_and_check(
        &mut self,
        transition: Transition,
        state: &AbstractPosState,
        storage: &TestWlStorage,
    ) {
        self.apply(&transition);
        self.check(state, storage);
    }

    /// Log and send input to Quint
    fn send_input(&mut self, input: &str) {
        println!();
        println!("Quint call: {input}");
        self.input_log
            .write_all(format!("{}\n", input).as_bytes())
            .unwrap();
        self.session.send_line(input.as_bytes()).unwrap();
    }

    /// Apply a transition in Quint
    fn apply(&mut self, transition: &Transition) {
        match transition {
            Transition::NextEpoch => todo!(),
            Transition::InitValidator {
                address,
                consensus_key,
                commission_rate,
                max_commission_rate_change,
            } => todo!(),
            Transition::Bond { id, amount } => todo!(),
            Transition::Unbond { id, amount } => todo!(),
            Transition::Withdraw { id } => todo!(),
            Transition::Misbehavior {
                address,
                slash_type,
                infraction_epoch,
                height,
            } => todo!(),
            Transition::UnjailValidator { address } => todo!(),
        }
    }

    /// Check that the Quint's state corresponds to this state
    fn check(&mut self, state: &AbstractPosState, storage: &TestWlStorage) {
        let current_epoch = storage.storage.block.epoch;
        self.check_validator_stakes(state, current_epoch)
    }

    fn check_validator_stakes(
        &mut self,
        state: &AbstractPosState,
        epoch: Epoch,
    ) {
        for (addr, stake) in state.validator_stakes.get(&epoch).unwrap() {
            let query = format!(
                "validators.get(\"{}\").stake.get({epoch})",
                addr_for_quint(addr)
            );
            self.send_input(&query);
            println!("WAITING");
            let captures = self.session.expect(Regex(r"\d+\r\n")).unwrap();
            let value_bytes = captures.get(0).unwrap();
            let value_str = std::str::from_utf8(value_bytes).unwrap();
            assert!(captures.get(1).is_none());
            let value: u64 = FromStr::from_str(value_str).unwrap();
            assert_eq!(value, 0);
            // TODO: check against the reals stake once we initialize the
            // genesis validators with the proper stake:
            // assert_eq!(value, u64::try_from(*stake).unwrap());
        }
    }
}

fn addr_for_quint(addr: &Address) -> String {
    // Use only the last 8 chars of the 83 chars to make it lighter for Quint
    addr.to_string().get(76..).unwrap().to_owned()
}
