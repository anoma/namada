use color_eyre::owo_colors::OwoColorize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Transaction gas limit exceeded")]
    TransactionGasExceedededError(),
    #[error("Block gas limit exceeded")]
    BlockGasExceeded(),
    #[error("Underflow/Overflow during gas operations")]
    MathOperation(),
}

pub const TX_GAS_PER_BYTE: i64 = 2;
const BASE_TRANSACTION_FEE: i64 = 2;
const BLOCK_GAS_LIMIT: i64 = 1000;
const TRANSACTION_GAS_LIMIT: i64 = 100;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct BlockGasMeter {
    block_gas: i64,
    transaction_gas: i64,
}

impl BlockGasMeter {
    pub fn add(&mut self, gas: i64) -> Result<()> {
        let abs_gas = gas.checked_abs().ok_or(Error::MathOperation())?;
        match self.transaction_gas.checked_add(abs_gas) {
            Some(result) => {
                if result > TRANSACTION_GAS_LIMIT {
                    return Err(Error::TransactionGasExceedededError());
                }
                Ok(())
            }
            None => Err(Error::MathOperation()),
        }
    }

    pub fn reset(&mut self) {
        self.transaction_gas = 0;
        self.block_gas = 0;
    }

    pub fn finalize_transaction(&mut self) -> Result<i64> {
        match self.block_gas.checked_add(self.transaction_gas) {
            Some(result) => {
                if result > BLOCK_GAS_LIMIT {
                    return Err(Error::BlockGasExceeded());
                }
                self.transaction_gas = 0;
                Ok(result)
            }
            None => Err(Error::MathOperation()),
        }
    }

    pub fn add_base_transaction_fee(&mut self, gas: i64) -> Result<()> {
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
