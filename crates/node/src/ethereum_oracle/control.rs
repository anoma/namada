//! The oracle is controlled by sending commands over a channel.

use namada_sdk::eth_bridge::oracle::config::Config;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// Used by an oracle to receive commands.
pub type Receiver = mpsc::Receiver<Command>;

/// Used to send commands to an oracle.
#[derive(Debug)]
pub struct Sender {
    last_command: Option<Command>,
    inner_sender: mpsc::Sender<Command>,
}

impl Sender {
    /// Send a [`Command`] if the last one is not repeated.
    pub fn try_send(
        &mut self,
        cmd: Command,
    ) -> Result<(), TrySendError<Command>> {
        // NOTE: this code may be buggy if we happen to need to
        // send repeated commands
        if self.last_command.as_ref() != Some(&cmd) {
            self.last_command = Some(cmd.clone());
            self.inner_sender.try_send(cmd)
        } else {
            Ok(())
        }
    }
}

/// Returns two sides of a [`mpsc`] channel that can be used for controlling an
/// oracle.
pub fn channel() -> (Sender, Receiver) {
    let (inner_sender, receiver) = mpsc::channel(5);
    let sender = Sender {
        last_command: None,
        inner_sender,
    };
    (sender, receiver)
}

/// Commands used to configure and control an `Oracle`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Command {
    /// Update the config if it changes in storage.
    /// Also used to send an initial configuration to the oracle for it to use.
    /// The oracle will not do anything until this command has been sent.
    UpdateConfig(Config),
}
