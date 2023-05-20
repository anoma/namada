use std::collections::HashMap;
use std::fmt::Display;

#[derive(Debug, Default)]
pub struct InternalStats {
    successful_tx: u64,
    rejected_txs: u64,
    errored_txs: u64,
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
}

impl Display for InternalStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Applied {} transactions. Wrappers: {}, successful inner txs: {}, \
             rejected inner txs: {}, errored inner txs: {}, vp cache size: {} \
             - {}, tx cache size {} - {}",
            self.successful_tx + self.rejected_txs + self.errored_txs,
            self.wrapper_txs,
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
