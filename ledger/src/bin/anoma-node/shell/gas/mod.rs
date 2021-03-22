use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Transaction gas limit exceeded")]
    TransactionGasExceedededError(),
    #[error("Block gas limit exceeded")]
    BlockGasExceeded(),
}

const BASE_TRANSACTION_FEE: i64 = 2;
const BLOCK_GAS_LIMIT: i64 = 1000;
const TRANSACTION_GAS_LIMIT: i64 = 100;

pub type Result<T> = std::result::Result<T, Error>;

pub trait GasCounter {
    fn add(&mut self, gas: i64) -> Result<()>;
    fn finalize_transaction(&mut self) -> Result<i64>;
}

#[derive(Debug)]
pub struct BlockGasMeter {
    block_gas: i64,
    transaction_gas: i64,
}

impl GasCounter for BlockGasMeter {
    fn add(&mut self, gas: i64) -> Result<()> {
        self.transaction_gas += gas;
        if self.transaction_gas > TRANSACTION_GAS_LIMIT {
            self.transaction_gas -= gas;
            return Err(Error::TransactionGasExceedededError());
        }
        return Ok(());
    }

    fn finalize_transaction(&mut self) -> Result<i64> {
        self.block_gas += self.transaction_gas;
        if self.block_gas > BLOCK_GAS_LIMIT {
            self.block_gas -= self.transaction_gas;
            return Err(Error::TransactionGasExceedededError());
        }
        return Ok(self.block_gas);
    }
}

impl BlockGasMeter {
    pub fn add_with_base_fee(&mut self, gas: i64) -> Result<()> {
        return self.add(gas + BASE_TRANSACTION_FEE);
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
