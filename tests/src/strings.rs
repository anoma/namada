//! Expected strings for integration and e2e tests.

/// Inner tx applied and accepted by VPs.
pub const TX_APPLIED_SUCCESS: &str = "Transaction was successfully applied";

/// Inner transaction rejected by VP(s).
pub const TX_REJECTED: &str = "Transaction was rejected by VPs";

/// Inner transaction failed in execution (no VPs ran).
pub const TX_FAILED: &str = "Transaction failed";

/// Wrapper transaction accepted.
pub const TX_ACCEPTED: &str = "Wrapper transaction accepted";
