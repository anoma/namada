//! Gas accounting module to track the gas usage in a block for transactions and
//! validity predicates triggered by transactions.

use std::fmt::Display;
use std::ops::Div;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use thiserror::Error;

use super::parameters;
use super::storage_api::{self, StorageRead};
use crate::types::transaction::wrapper::GasLimit;

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

/// The cost of accessing the storage, per byte
pub const STORAGE_ACCESS_GAS_PER_BYTE: u64 = 1;
/// The cost of writing to storage, per byte
pub const STORAGE_WRITE_GAS_PER_BYTE: u64 = 100;
/// The cost of verifying a signle signature of a transaction
pub const VERIFY_TX_SIG_GAS_COST: u64 = 10;
/// The cost of accessing the WASM memory, per byte
pub const VM_MEMORY_ACCESS_GAS_PER_BYTE: u64 = 1;
/// The cost for requesting one more page in wasm (64KB)
pub const WASM_MEMORY_PAGE_GAS_COST: u32 = 100;

/// Gas module result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Decimal scale of Gas units
const SCALE: u64 = 1_000;

/// Helper function to retrieve the `max_block_gas` protocol parameter from
/// storage
pub fn get_max_block_gas(
    storage: &impl StorageRead,
) -> std::result::Result<u64, storage_api::Error> {
    storage
        .read(&parameters::storage::get_max_block_gas_key())?
        .ok_or(storage_api::Error::SimpleMessage(
            "Missing max_block_gas parameter from storage",
        ))
}

/// Representation of gas in sub-units. This effectively decouples gas metering
/// from fee payment, allowing higher resolution when accounting for gas while,
/// at the same time, providing a contained gas value when paying fees.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    PartialOrd,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
)]
pub struct Gas {
    sub: u64,
}

impl Gas {
    /// Checked add of `Gas`. Returns `None` on overflow
    pub fn checked_add(&self, rhs: Self) -> Option<Self> {
        self.sub.checked_add(rhs.sub).map(|sub| Self { sub })
    }

    /// Checked sub of `Gas`. Returns `None` on underflow
    pub fn checked_sub(&self, rhs: Self) -> Option<Self> {
        self.sub.checked_sub(rhs.sub).map(|sub| Self { sub })
    }

    /// Converts the sub gas units to whole ones. If the sub units are not a
    /// multiple of the `SCALE` than ceil the quotient
    fn get_whole_gas_units(&self) -> u64 {
        let quotient = self.sub / SCALE;
        if self.sub % SCALE == 0 {
            quotient
        } else {
            quotient + 1
        }
    }

    /// Generates a `Gas` instance from a whole amount
    pub fn from_whole_units(whole: u64) -> Self {
        Self { sub: whole * SCALE }
    }
}

impl Div<u64> for Gas {
    type Output = Gas;

    fn div(self, rhs: u64) -> Self::Output {
        Self {
            sub: self.sub / rhs,
        }
    }
}

impl From<u64> for Gas {
    fn from(sub: u64) -> Self {
        Self { sub }
    }
}

impl From<Gas> for u64 {
    fn from(gas: Gas) -> Self {
        gas.sub
    }
}

impl Display for Gas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display the gas in whole amounts
        write!(f, "{}", self.get_whole_gas_units())
    }
}

impl From<GasLimit> for Gas {
    // Derive a Gas instance with a sub amount which is exaclty a whole amount
    // since the limit represents gas in whole units
    fn from(value: GasLimit) -> Self {
        Self {
            sub: u64::from(value) * SCALE,
        }
    }
}

/// Trait to share gas operations for transactions and validity predicates
pub trait GasMetering {
    /// Add gas cost. It will return error when the
    /// consumed gas exceeds the provided transaction gas limit, but the state
    /// will still be updated
    fn consume(&mut self, gas: u64) -> Result<()>;

    /// Add the compiling cost proportionate to the code length
    fn add_compiling_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(COMPILE_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?,
        )
    }

    /// Add the gas for loading the wasm code from storage
    fn add_wasm_load_from_storage_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(STORAGE_ACCESS_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?,
        )
    }

    /// Get the gas consumed by the tx alone
    fn get_tx_consumed_gas(&self) -> Gas;

    /// Get the gas limit
    fn get_gas_limit(&self) -> Gas;
}

/// Gas metering in a transaction
#[derive(Debug)]
pub struct TxGasMeter {
    /// The gas limit for a transaction
    pub tx_gas_limit: Gas,
    transaction_gas: Gas,
}

/// Gas metering in a validity predicate
#[derive(Debug, Clone)]
pub struct VpGasMeter {
    /// The transaction gas limit
    tx_gas_limit: Gas,
    /// The gas consumed by the transaction before the Vp
    initial_gas: Gas,
    /// The current gas usage in the VP
    current_gas: Gas,
}

/// Gas meter for VPs parallel runs
#[derive(
    Clone, Debug, Default, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct VpsGas {
    max: Gas,
    rest: Vec<Gas>,
}

impl GasMetering for TxGasMeter {
    fn consume(&mut self, gas: u64) -> Result<()> {
        self.transaction_gas = self
            .transaction_gas
            .checked_add(gas.into())
            .ok_or(Error::GasOverflow)?;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }

    fn get_tx_consumed_gas(&self) -> Gas {
        self.transaction_gas
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit
    }
}

impl TxGasMeter {
    /// Initialize a new Tx gas meter. Requires the `GasLimit` for the specific
    /// wrapper transaction
    pub fn new(tx_gas_limit: GasLimit) -> Self {
        Self {
            tx_gas_limit: tx_gas_limit.into(),
            transaction_gas: Gas::default(),
        }
    }

    /// Initialize a new gas meter. Requires the gas limit expressed in sub
    /// units
    pub fn new_from_sub_limit(tx_gas_limit: Gas) -> Self {
        Self {
            tx_gas_limit,
            transaction_gas: Gas::default(),
        }
    }

    /// Add the gas for the space that the transaction requires in the block
    pub fn add_tx_size_gas(&mut self, tx_bytes: &[u8]) -> Result<()> {
        let bytes_len: u64 = tx_bytes
            .len()
            .try_into()
            .map_err(|_| Error::ConversionError)?;
        self.consume(
            bytes_len
                .checked_mul(TX_SIZE_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?,
        )
    }

    /// Add the gas cost used in validity predicates to the current transaction.
    pub fn add_vps_gas(&mut self, vps_gas: &VpsGas) -> Result<()> {
        self.consume(vps_gas.get_current_gas()?.into())
    }

    /// Get the amount of gas still available to the transaction
    pub fn get_available_gas(&self) -> Gas {
        self.tx_gas_limit
            .checked_sub(self.transaction_gas)
            .unwrap_or_default()
    }
}

impl GasMetering for VpGasMeter {
    fn consume(&mut self, gas: u64) -> Result<()> {
        self.current_gas = self
            .current_gas
            .checked_add(gas.into())
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

    fn get_tx_consumed_gas(&self) -> Gas {
        self.initial_gas
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit
    }
}

impl VpGasMeter {
    /// Initialize a new VP gas meter from the `TxGasMeter`
    pub fn new_from_tx_meter(tx_gas_meter: &TxGasMeter) -> Self {
        Self {
            tx_gas_limit: tx_gas_meter.tx_gas_limit,
            initial_gas: tx_gas_meter.transaction_gas,
            current_gas: Gas::default(),
        }
    }
}

impl VpsGas {
    /// Set the gas cost from a VP run. It consumes the [`VpGasMeter`]
    /// instance which shouldn't be accessed passed this point.
    pub fn set(&mut self, vp_gas_meter: VpGasMeter) -> Result<()> {
        if vp_gas_meter.current_gas > self.max {
            self.rest.push(self.max);
            self.max = vp_gas_meter.current_gas;
        } else {
            self.rest.push(vp_gas_meter.current_gas);
        }

        self.check_limit(&vp_gas_meter)
    }

    /// Merge validity predicates gas meters from parallelized runs. Consumes
    /// the other `VpsGas` instance which shouldn't be used passed this point.
    pub fn merge(
        &mut self,
        mut other: VpsGas,
        tx_gas_meter: &TxGasMeter,
    ) -> Result<()> {
        if self.max < other.max {
            self.rest.push(self.max);
            self.max = other.max;
        } else {
            self.rest.push(other.max);
        }
        self.rest.append(&mut other.rest);

        self.check_limit(tx_gas_meter)
    }

    /// Check if the vp went out of gas. Starts from the gas consumed by the
    /// transaction.
    fn check_limit(&self, gas_meter: &impl GasMetering) -> Result<()> {
        let total = gas_meter
            .get_tx_consumed_gas()
            .checked_add(self.get_current_gas()?)
            .ok_or(Error::GasOverflow)?;
        if total > gas_meter.get_gas_limit() {
            return Err(Error::TransactionGasExceededError);
        }
        Ok(())
    }

    /// Get the gas consumed by the parallelized VPs
    fn get_current_gas(&self) -> Result<Gas> {
        let parallel_gas =
            self.rest.iter().try_fold(Gas::default(), |acc, gas| {
                acc.checked_add(*gas).ok_or(Error::GasOverflow)
            })? / PARALLEL_GAS_DIVIDER;
        self.max.checked_add(parallel_gas).ok_or(Error::GasOverflow)
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
        let tx_gas_meter = TxGasMeter {
            tx_gas_limit: BLOCK_GAS_LIMIT.into(),
            transaction_gas: Gas::default(),
        };
            let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
            meter.consume(gas).expect("cannot add the gas");
        }

    }

    #[test]
    fn test_vp_gas_overflow() {
        let tx_gas_meter = TxGasMeter {
            tx_gas_limit: BLOCK_GAS_LIMIT.into(),
            transaction_gas: (TX_GAS_LIMIT - 1).into(),
        };
        let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
        assert_matches!(
            meter.consume(u64::MAX).expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_vp_gas_limit() {
        let tx_gas_meter = TxGasMeter {
            tx_gas_limit: TX_GAS_LIMIT.into(),
            transaction_gas: (TX_GAS_LIMIT - 1).into(),
        };
        let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
        assert_matches!(
            meter
                .consume(TX_GAS_LIMIT)
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError
        );
    }

    #[test]
    fn test_tx_gas_overflow() {
        let mut meter = TxGasMeter::new_from_sub_limit(BLOCK_GAS_LIMIT.into());
        meter.consume(1).expect("cannot add the gas");
        assert_matches!(
            meter.consume(u64::MAX).expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_tx_gas_limit() {
        let mut meter = TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into());
        assert_matches!(
            meter
                .consume(TX_GAS_LIMIT + 1)
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError
        );
    }
}
