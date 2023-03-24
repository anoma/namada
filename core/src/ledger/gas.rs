//! Gas accounting module to track the gas usage in a block for transactions and
//! validity predicates triggered by transactions.

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Transaction gas limit exceeded")]
    TransactionGasExceededError,
    #[error("Block gas limit exceeded")]
    BlockGasExceeded,
    #[error("Overflow during gas operations")]
    GasOverflow,
}

const TX_SIZE_GAS_PER_BYTE: u64 = 1;
const COMPILE_GAS_PER_BYTE: u64 = 1;
const PARALLEL_GAS_DIVIDER: u64 = 10;

/// The minimum gas cost for accessing the storage
pub const MIN_STORAGE_GAS: u64 = 1;
/// The gas cost for verifying the signature of a transaction
pub const VERIFY_TX_SIG_GAS_COST: u64 = 1_000;
/// The gas cost for validating wasm vp code
pub const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;
/// The cost for writing a byte to storage
pub const STORAGE_WRITE_GAS_PER_BYTE: u64 = 100;

/// Gas module result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Gas metering in a block. The amount of gas consumed in a block is based on the
/// tx_gas_limit declared by each [`TxGasMeter`]
#[derive(Debug, Clone)]
pub struct BlockGasMeter {
    /// The max amount of gas allowed per block, defined by the protocol parameter
    pub block_gas_limit: u64,
    block_gas: u64,
}

/// Gas metering in a transaction
#[derive(Debug)]
pub struct TxGasMeter {
    /// The gas limit for a transaction
    pub tx_gas_limit: u64,
    transaction_gas: u64,
}

/// Gas metering in a validity predicate
#[derive(Debug, Clone)]
pub struct VpGasMeter {
    /// The transaction gas limit
    tx_gas_limit: u64,
    /// The gas used in the transaction before the VP run
    initial_gas: u64,
    /// The current gas usage in the VP
    pub current_gas: u64,
}

/// Gas meter for VPs parallel runs
#[derive(
    Clone, Debug, Default, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct VpsGas {
    max: Option<u64>,
    rest: Vec<u64>,
}

impl BlockGasMeter {
    /// Build a new instance. Requires the block_gas_limit protocol parameter.
    pub fn new(block_gas_limit: u64) -> Self {
        Self {
            block_gas_limit,
            block_gas: 0,
        }
    }

    /// Add the transaction gas limit to the block's total gas. It will return
    /// error when the consumed gas exceeds the block gas limit, but the state
    /// will still be updated. This function consumes the [`TxGasMeter`] which shouldn't be updated after this point.
    pub fn finalize_transaction(
        &mut self,
        tx_gas_meter: TxGasMeter,
    ) -> Result<()> {
        self.block_gas = self
            .block_gas
            .checked_add(tx_gas_meter.tx_gas_limit)
            .ok_or(Error::GasOverflow)?;

        if self.block_gas > self.block_gas_limit {
            return Err(Error::BlockGasExceeded);
        }
        Ok(())
    }

    /// Tries to add the transaction gas limit to the block's total gas.
    /// If the operation returns an error, propagates this errors without updating the state. This function consumes the [`TxGasMeter`] which shouldn't be updated after this point.
    pub fn try_finalize_transaction(
        &mut self,
        tx_gas_meter: TxGasMeter,
    ) -> Result<()> {
        let updated_gas = self
            .block_gas
            .checked_add(tx_gas_meter.tx_gas_limit)
            .ok_or(Error::GasOverflow)?;

        if updated_gas > self.block_gas_limit {
            return Err(Error::BlockGasExceeded);
        }

        self.block_gas = updated_gas;

        Ok(())
    }
}

impl TxGasMeter {
    /// Initialize a new Tx gas meter. Requires the gas limit for the specific transaction
    pub fn new(tx_gas_limit: u64) -> Self {
        Self {
            tx_gas_limit,
            transaction_gas: 0,
        }
    }

    /// Add gas cost for the current transaction. It will return error when the
    /// consumed gas exceeds the provided transaction gas limit, but the state will still
    /// be updated.
    pub fn add(&mut self, gas: u64) -> Result<()> {
        self.transaction_gas = self
            .transaction_gas
            .checked_add(gas)
            .ok_or(Error::GasOverflow)?;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }

    /// Add the compiling cost proportionate to the code length
    pub fn add_compiling_gas(&mut self, bytes_len: usize) -> Result<()> {
        self.add(bytes_len as u64 * COMPILE_GAS_PER_BYTE)
    }

    /// Add the gas for the space that the transaction requires in the block
    pub fn add_tx_size_gas(&mut self, bytes_len: usize) -> Result<()> {
        self.add(bytes_len as u64 * TX_SIZE_GAS_PER_BYTE)
    }

    /// Add the gas cost used in validity predicates to the current transaction.
    pub fn add_vps_gas(&mut self, vps_gas: &VpsGas) -> Result<()> {
        self.add(vps_gas.get_current_gas()?)
    }

    /// Get the total gas used in the current transaction.
    pub fn get_current_transaction_gas(&self) -> u64 {
        self.transaction_gas
    }
}

impl VpGasMeter {
    /// Initialize a new VP gas meter, starting with the gas consumed in the
    /// transaction so far. Also requires the transaction gas limit.
    pub fn new(tx_gas_limit: u64, initial_gas: u64) -> Self {
        Self {
            tx_gas_limit,
            initial_gas,
            current_gas: 0,
        }
    }

    /// Consume gas in a validity predicate. It will return error when the
    /// consumed gas exceeds the transaction gas limit, but the state will still
    /// be updated.
    pub fn add(&mut self, gas: u64) -> Result<()> {
        let gas = self
            .current_gas
            .checked_add(gas)
            .ok_or(Error::GasOverflow)?;

        self.current_gas = gas;

        let current_total = self
            .initial_gas
            .checked_add(self.current_gas)
            .ok_or(Error::GasOverflow)?;

        if current_total > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }

    /// Add the compiling cost proportionate to the code length
    pub fn add_compiling_gas(&mut self, bytes_len: usize) -> Result<()> {
        self.add(bytes_len as u64 * COMPILE_GAS_PER_BYTE)
    }
}

impl VpsGas {
    /// Set the gas cost from a single VP run. It consumes the [`VpGasMeter`] instance which shouldn't be accessed passed this point.
    pub fn set(&mut self, vp_gas_meter: VpGasMeter) -> Result<()> {
        debug_assert_eq!(self.max, None);
        debug_assert!(self.rest.is_empty());
        self.max = Some(vp_gas_meter.current_gas);
        self.check_limit(vp_gas_meter.tx_gas_limit, vp_gas_meter.initial_gas)
    }

    /// Merge validity predicates gas meters from parallelized runs.
    pub fn merge(
        &mut self,
        other: &mut VpsGas,
        tx_gas_limit: u64,
        initial_gas: u64,
    ) -> Result<()> {
        match (self.max, other.max) {
            (None, Some(_)) => {
                self.max = other.max;
            }
            (Some(this_max), Some(other_max)) => {
                if this_max < other_max {
                    self.rest.push(this_max);
                    self.max = other.max;
                } else {
                    self.rest.push(other_max);
                }
            }
            _ => {}
        }
        self.rest.append(&mut other.rest);

        self.check_limit(tx_gas_limit, initial_gas)
    }

    fn check_limit(&self, tx_gas_limit: u64, initial_gas: u64) -> Result<()> {
        let total = initial_gas
            .checked_add(self.get_current_gas()?)
            .ok_or(Error::GasOverflow)?;
        if total > tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }
        Ok(())
    }

    /// Get the gas consumed by the parallelized VPs
    fn get_current_gas(&self) -> Result<u64> {
        let parallel_gas = self.rest.iter().sum::<u64>() / PARALLEL_GAS_DIVIDER;
        self.max
            .unwrap_or_default()
            .checked_add(parallel_gas)
            .ok_or(Error::GasOverflow)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    const BLOCK_GAS_LIMIT: u64 = 10_000_000_000;
    const TX_GAS_LIMIT: u64 = 1_000_000;

    proptest! {
        #[test]
        fn test_vp_gas_meter_add(gas in 0..BLOCK_GAS_LIMIT) {
            let mut meter = VpGasMeter::new(BLOCK_GAS_LIMIT, 0);
            meter.add(gas).expect("cannot add the gas");
        }

        #[test]
        fn test_block_gas_meter_add(gas in 0..BLOCK_GAS_LIMIT) {
            let mut meter = BlockGasMeter::new(BLOCK_GAS_LIMIT);
            let mut tx_gas_meter = TxGasMeter::new(BLOCK_GAS_LIMIT );
            tx_gas_meter.add(gas).expect("cannot add the gas");
            meter.finalize_transaction(tx_gas_meter).expect("cannot finalize the tx");
            assert_eq!(meter.block_gas, BLOCK_GAS_LIMIT);
        }
    }

    #[test]
    fn test_vp_gas_overflow() {
        let mut meter = VpGasMeter::new(BLOCK_GAS_LIMIT, 1);
        assert_matches!(
            meter.add(u64::MAX).expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_vp_gas_limit() {
        let mut meter = VpGasMeter::new(TX_GAS_LIMIT, 1);
        assert_matches!(
            meter.add(TX_GAS_LIMIT).expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError
        );
    }

    #[test]
    fn test_tx_gas_overflow() {
        let mut meter = TxGasMeter::new(BLOCK_GAS_LIMIT);
        meter.add(1).expect("cannot add the gas");
        assert_matches!(
            meter.add(u64::MAX).expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_tx_gas_limit() {
        let mut meter = TxGasMeter::new(TX_GAS_LIMIT);
        assert_matches!(
            meter
                .add(TX_GAS_LIMIT + 1)
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError
        );
    }

    #[test]
    fn test_block_gas_limit() {
        let mut meter = BlockGasMeter::new(BLOCK_GAS_LIMIT);
        let transaction_gas = 10_000_u64;

        // add the maximum tx gas
        for _ in 0..(BLOCK_GAS_LIMIT / transaction_gas) {
            let tx_gas_meter = TxGasMeter::new(transaction_gas);
            meter
                .finalize_transaction(tx_gas_meter)
                .expect("over the block gas limit");
        }

        let tx_gas_meter = TxGasMeter::new(transaction_gas);
        match meter
            .finalize_transaction(tx_gas_meter)
            .expect_err("unexpectedly succeeded")
        {
            Error::BlockGasExceeded => {}
            _ => panic!("unexpected error happened"),
        }
    }
}
