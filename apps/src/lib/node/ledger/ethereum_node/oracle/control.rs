//! The oracle is controlled by sending commands over a channel.

use super::config::Config;

/// Commands used to configure and control an `Oracle`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Command {
    /// Initializes the oracle with the given configuration and immediately
    /// starts it.
    Initialize { config: Config },
}
