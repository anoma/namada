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

pub const TX_GAS_PER_BYTE: u64 = 2;
const BASE_TRANSACTION_FEE: u64 = 2;

/// The maximum value should be less or equal to i64::MAX
/// to avoid the gas overflow when sending this to ABCI
const BLOCK_GAS_LIMIT: u64 = 1000;
const TRANSACTION_GAS_LIMIT: u64 = 100;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct BlockGasMeter {
    block_gas: u64,
    transaction_gas: u64,
}

impl BlockGasMeter {
    pub fn add(&mut self, gas: u64) -> Result<()> {
        // u64::try_from(
        match self.transaction_gas.checked_add(gas) {
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

    pub fn finalize_transaction(&mut self) -> Result<u64> {
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

    pub fn add_base_transaction_fee(&mut self, gas: u64) -> Result<()> {
        match BASE_TRANSACTION_FEE.checked_add(gas) {
            Some(sum) => self.add(sum),
            None => Err(Error::MathOperation()),
        }
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
