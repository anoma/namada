use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Transaction gas limit exceeded")]
    TransactionGasExceedededError,
    #[error("Block gas limit exceeded")]
    BlockGasExceeded,
    #[error("Overflow during gas operations")]
    GasOverflow,
}

const TX_GAS_PER_BYTE: u64 = 2;
const COMPILE_GAS_PER_BYTE: u64 = 1;
const BASE_TRANSACTION_FEE: u64 = 2;
const PARALLEL_GAS_MULTIPLER: f64 = 0.1;

/// The maximum value should be less or equal to i64::MAX
/// to avoid the gas overflow when sending this to ABCI
const BLOCK_GAS_LIMIT: u64 = 10_000_000_000_000;
const TRANSACTION_GAS_LIMIT: u64 = 10_000_000_000;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct BlockGasMeter {
    block_gas: u64,
    transaction_gas: u64,
}
#[derive(Debug, Clone)]
pub struct VpGasMeter {
    pub vp_gas: u64,
}

impl VpGasMeter {
    pub fn add(&mut self, gas: u64) -> Result<()> {
        self.vp_gas = self.vp_gas.checked_add(gas).ok_or(Error::GasOverflow)?;

        if self.vp_gas > TRANSACTION_GAS_LIMIT {
            return Err(Error::TransactionGasExceedededError);
        }
        Ok(())
    }
}

impl VpGasMeter {
    pub fn new(vp_gas: u64) -> Self {
        Self { vp_gas }
    }
}

impl BlockGasMeter {
    /// Add gas cost for the current transaction.
    pub fn add(&mut self, gas: u64) -> Result<()> {
        self.transaction_gas = self
            .transaction_gas
            .checked_add(gas)
            .ok_or(Error::GasOverflow)?;

        if self.transaction_gas > TRANSACTION_GAS_LIMIT {
            return Err(Error::TransactionGasExceedededError);
        }
        Ok(())
    }

    /// Add the base transaction fee and the fee per transaction byte that's
    /// charged the moment we try to apply the transaction.
    pub fn add_base_transaction_fee(&mut self, bytes_len: usize) -> Result<()> {
        log::info!("add_base_transaction_fee {}", bytes_len);
        self.add(BASE_TRANSACTION_FEE)?;
        self.add(bytes_len as u64 * TX_GAS_PER_BYTE)
    }

    // Add the compiling cost proportionate to the code length
    pub fn add_compiling_fee(&mut self, bytes_len: usize) -> Result<()> {
        self.add(bytes_len as u64 * COMPILE_GAS_PER_BYTE)
    }

    /// Add the transaction gas to the block's total gas. Returns the
    /// transaction's gas cost and resets the transaction meter.
    pub fn finalize_transaction(&mut self) -> Result<u64> {
        self.block_gas = self
            .block_gas
            .checked_add(self.transaction_gas)
            .ok_or(Error::GasOverflow)?;

        if self.block_gas > BLOCK_GAS_LIMIT {
            return Err(Error::BlockGasExceeded);
        }
        let transaction_gas = self.transaction_gas;
        self.transaction_gas = 0;
        Ok(transaction_gas)
    }

    /// Reset the gas meter
    pub fn reset(&mut self) {
        self.transaction_gas = 0;
        self.block_gas = 0;
    }

    pub fn add_parallel_fee(&mut self, vps_gases: &mut Vec<u64>) -> Result<()> {
        let gas_used =
            vps_gases.iter().sum::<u64>() as f64 * PARALLEL_GAS_MULTIPLER;
        self.add(gas_used as u64)
    }

    pub fn get_current_transaction_gas(&mut self) -> u64 {
        self.transaction_gas
    }
}

impl Default for BlockGasMeter {
    fn default() -> Self {
        BlockGasMeter {
            block_gas: 0,
            transaction_gas: 0,
        }
    }
}
