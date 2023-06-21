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
    #[error("Error converting to u64")]
    ConversionError,
}

const TX_SIZE_GAS_PER_BYTE: u64 = 10;
const COMPILE_GAS_PER_BYTE: u64 = 1;
const PARALLEL_GAS_DIVIDER: u64 = 10;

/// The minimum gas cost for accessing the storage
pub const MIN_STORAGE_GAS: u64 = 1;
/// The gas cost for verifying the signature of a transaction
pub const VERIFY_TX_SIG_GAS_COST: u64 = 10;
/// The gas cost for validating wasm vp code
pub const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;
/// The cost for writing a byte to storage
pub const STORAGE_WRITE_GAS_PER_BYTE: u64 = 100;

/// Gas module result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

//FIXME: shoul we use a type alias Gas for u64?

/// Trait to share gas operations for transactions and validity predicates
pub trait TxVpGasMetering {
    //FIXME: rename this trait, but it should not mention Wasm because this is also used for native vps
    /// Add gas cost. It will return error when the
    /// consumed gas exceeds the provided transaction gas limit, but the state
    /// will still be updated
    fn add(&mut self, gas: u64) -> Result<()>;

    /// Add the compiling cost proportionate to the code length
    fn add_compiling_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.add(
            bytes_len
                .checked_mul(COMPILE_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?,
        )
    }

    /// Add the gas for loading the wasm code from storage
    fn add_wasm_load_from_storage_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.add(
            bytes_len
                .checked_mul(MIN_STORAGE_GAS)
                .ok_or(Error::GasOverflow)?,
        )
    }
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
    //FIXME: should rework this a bit?
    max: Option<u64>,
    rest: Vec<u64>,
}

impl TxVpGasMetering for TxGasMeter {
    fn add(&mut self, gas: u64) -> Result<()> {
        self.transaction_gas = self
            .transaction_gas
            .checked_add(gas)
            .ok_or(Error::GasOverflow)?;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }
}

impl TxGasMeter {
    /// Initialize a new Tx gas meter. Requires the gas limit for the specific
    /// transaction
    pub fn new(tx_gas_limit: u64) -> Self {
        Self {
            tx_gas_limit,
            transaction_gas: 0,
        }
    }

    /// Add the gas for the space that the transaction requires in the block
    pub fn add_tx_size_gas(&mut self, tx_bytes: &[u8]) -> Result<()> {
        let bytes_len: u64 = tx_bytes
            .len()
            .try_into()
            .map_err(|_| Error::ConversionError)?;
        self.add(
            bytes_len
                .checked_mul(TX_SIZE_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?,
        )
    }

    /// Add the gas cost used in validity predicates to the current transaction.
    //FIXME: should this consume VpsGas?
    pub fn add_vps_gas(&mut self, vps_gas: &VpsGas) -> Result<()> {
        self.add(vps_gas.get_current_gas()?)
    }

    /// Get the total gas used in the current transaction.
    pub fn get_current_transaction_gas(&self) -> u64 {
        self.transaction_gas
    }
}

impl TxVpGasMetering for VpGasMeter {
    fn add(&mut self, gas: u64) -> Result<()> {
        self.current_gas = self
            .current_gas
            .checked_add(gas)
            .ok_or(Error::GasOverflow)?;

        let current_total = self
            .initial_gas
            .checked_add(self.current_gas)
            .ok_or(Error::GasOverflow)?;

        if current_total > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }
}

impl VpGasMeter {
    /// Initialize a new VP gas meter, starting with the gas consumed in the
    /// transaction so far. Also requires the transaction gas limit.
    //FIXME: should pass reference to the TxGasMeter here?
    pub fn new(tx_gas_limit: u64, initial_gas: u64) -> Self {
        Self {
            tx_gas_limit,
            initial_gas,
            current_gas: 0,
        }
    }
}

impl VpsGas {
    /// Set the gas cost from a single VP run. It consumes the [`VpGasMeter`]
    /// instance which shouldn't be accessed passed this point.
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
}
