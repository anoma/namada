#![allow(clippy::arithmetic_side_effects)]

use std::fmt::Display;

use namada_sdk::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct InternalStats {
    successful_tx: u64,
    rejected_txs: u64,
    errored_txs: u64,
    // Txs not run because of a previous error in the batch
    unrun_txs: u64,
    // Valid transactions discarded because of a failing atomic batch
    successful_tx_in_failed_batch: u64,
    vp_cache_size: (usize, usize),
    tx_cache_size: (usize, usize),
    tx_executed: HashMap<String, u64>,
    wrapper_txs: u64,
}

impl InternalStats {
    pub fn increment_successful_txs(&mut self) {
        self.successful_tx += 1;
    }

    pub fn increment_rejected_txs(&mut self) {
        self.rejected_txs += 1;
    }

    pub fn increment_errored_txs(&mut self) {
        self.errored_txs += 1;
    }

    /// Set the current stats to a failing batch by invalidating the valid
    /// transactions and increasing the number of txs not run.
    pub fn set_failing_atomic_batch(&mut self, unrun_txs: u64) {
        let valid_txs = std::mem::take(&mut self.successful_tx);
        self.successful_tx_in_failed_batch = valid_txs;
        self.unrun_txs = unrun_txs;
    }

    /// Set the current stats to a failing batch by increasing the number of txs
    /// not run.
    pub fn set_failing_batch(&mut self, unrun_txs: u64) {
        self.unrun_txs = unrun_txs;
    }

    pub fn increment_tx_type(&mut self, tx_hash: String) {
        match self.tx_executed.get(&tx_hash) {
            Some(value) => self.tx_executed.insert(tx_hash, value + 1),
            None => self.tx_executed.insert(tx_hash, 1),
        };
    }

    pub fn set_vp_cache_size(&mut self, keys: usize, weight: usize) {
        self.vp_cache_size = (keys, weight);
    }

    pub fn set_tx_cache_size(&mut self, keys: usize, weight: usize) {
        self.tx_cache_size = (keys, weight);
    }

    pub fn format_tx_executed(&self) -> String {
        let mut info = "txs executed: ".to_string();
        for (key, value) in self.tx_executed.clone() {
            info += format!("{} - {}, ", key.to_lowercase(), value).as_ref();
        }
        if self.tx_executed.is_empty() {
            "txs executed: 0".to_string()
        } else {
            info.strip_suffix(", ").unwrap().to_string()
        }
    }

    pub fn increment_wrapper_txs(&mut self) {
        self.wrapper_txs += 1;
    }

    /// Merges two intances of [`InternalStats`]. The caches stats are left
    /// untouched.
    pub fn merge(&mut self, other: Self) {
        self.successful_tx += other.successful_tx;
        self.rejected_txs += other.rejected_txs;
        self.errored_txs += other.errored_txs;
        self.unrun_txs += other.unrun_txs;
        self.successful_tx_in_failed_batch +=
            other.successful_tx_in_failed_batch;
        for (tx, cnt) in other.tx_executed {
            self.tx_executed
                .entry(tx)
                .and_modify(|e| *e += cnt)
                .or_insert(cnt);
        }
        self.wrapper_txs += other.wrapper_txs;
    }
}

impl Display for InternalStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Applied {} transactions. Wrappers: {}, successful inner txs: {}, \
             rejected inner txs: {}, errored inner txs: {}, unrun txs: {}, \
             valid txs discarded by failing atomic batch: {}, vp cache size: \
             {} - {}, tx cache size {} - {}",
            self.successful_tx + self.rejected_txs + self.errored_txs,
            self.wrapper_txs,
            self.successful_tx,
            self.rejected_txs,
            self.errored_txs,
            self.unrun_txs,
            self.successful_tx_in_failed_batch,
            self.vp_cache_size.0,
            self.vp_cache_size.1,
            self.tx_cache_size.0,
            self.tx_cache_size.1
        )
    }
}
