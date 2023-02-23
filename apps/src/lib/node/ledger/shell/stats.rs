use std::fmt::Display;

#[derive(Debug, Default)]
pub struct InternalStats {
    successful_tx: u64,
    rejected_txs: u64,
    errored_txs: u64,
    vp_cache_size: (usize, usize),
    tx_cache_size: (usize, usize),
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

    pub fn set_vp_cache_size(&mut self, keys: usize, weight: usize) {
        self.vp_cache_size = (keys, weight);
    }

    pub fn set_tx_cache_size(&mut self, keys: usize, weight: usize) {
        self.tx_cache_size = (keys, weight);
    }
}

impl Display for InternalStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Applied {} transactions, successful txs: {}, rejected txs: {}, \
             errored txs: {}: vp cache size: {} - {}, tx cache size {} - {}",
            self.successful_tx + self.rejected_txs + self.errored_txs,
            self.successful_tx,
            self.rejected_txs,
            self.errored_txs,
            self.vp_cache_size.0,
            self.vp_cache_size.1,
            self.tx_cache_size.0,
            self.tx_cache_size.1
        )
    }
}
