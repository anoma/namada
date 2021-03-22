#[derive(Error, Debug)]
pub enum Error {
    #[error("Transaction gas limit exceeded")]
    TransactionGasExceedededError(),
    #[error("Block gas limit exceeded")]
    BlockGasExceeded(),
}

const BLOCK_GAS_LIMIT: usize = 1000;
const TRANSACTION_GAS_LIMIT: usize = 100;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct BlockGasMeter {
    block_gas: i32,
    transaction_gas: i32,
}

impl BlockGasMeter {
    pub fn add(&mut self, gas: i32) -> Result<()> {
        self.transaction_gas += gas;
        if (self.transaction_gas > TRANSACTION_GAS_LIMIT) {
            self.transaction_gas -= gas;
            return TransactionGasExceedededError();
        }
        return Ok();
    }

    pub fn finalize_transaction(&mut self, gas: i32) -> Result<()> {
        self.block_gas += self.transaction_gas;
        if (self.block_gas > BLOCK_GAS_LIMIT) {
            self.block_gas -= self.transaction_gas;
            return BlockGasExceeded();
        }
        return Ok();
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        BlockGasMeter(0, 0);
    }
}
