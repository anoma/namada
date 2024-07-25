//! Gas accounting module to track the gas usage in a block for transactions and
//! validity predicates triggered by transactions.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects
)]

pub mod event;
pub mod storage;

use std::fmt::Display;
use std::num::ParseIntError;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::hints;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
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

#[allow(missing_docs)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GasParseError {
    #[error("Failed to parse gas: {0}")]
    Parse(ParseIntError),
    #[error("Gas overflowed")]
    Overflow,
}

const COMPILE_GAS_PER_BYTE: u64 = 1_664;
const PARALLEL_GAS_DIVIDER: u64 = 10;
const WASM_CODE_VALIDATION_GAS_PER_BYTE: u64 = 59;
const WRAPPER_TX_VALIDATION_GAS: u64 = 1_526_700;
// There's no benchmark to calculate the cost of storage occupation, so we
// define it as the cost of storage latency (which is needed for any storage
// operation and it's based on actual execution time), plus the same cost
// multiplied by an arbitrary factor that represents the higher cost of storage
// space as a resource. This way, the storage occupation cost is not completely
// free-floating but it's tied to the other costs
const STORAGE_OCCUPATION_GAS_PER_BYTE: u64 =
    PHYSICAL_STORAGE_LATENCY_PER_BYTE * (1 + 10);
// NOTE: this accounts for the latency of a physical drive access. For read
// accesses we have no way to tell if data was in cache or in storage. Moreover,
// the latency shouldn't really be accounted per single byte but rather per
// storage blob but this would make it more tedious to compute gas in the
// codebase. For these two reasons we just set an arbitrary value (based on
// actual SSDs latency) per byte here
const PHYSICAL_STORAGE_LATENCY_PER_BYTE: u64 = 1_000_000;
// This is based on the global average bandwidth
const NETWORK_TRANSMISSION_GAS_PER_BYTE: u64 = 848;

/// The cost of accessing data from memory (both read and write mode), per byte
pub const MEMORY_ACCESS_GAS_PER_BYTE: u64 = 39;
/// The cost of accessing data from storage, per byte
pub const STORAGE_ACCESS_GAS_PER_BYTE: u64 =
    93 + PHYSICAL_STORAGE_LATENCY_PER_BYTE;
/// The cost of writing data to storage, per byte
pub const STORAGE_WRITE_GAS_PER_BYTE: u64 =
    MEMORY_ACCESS_GAS_PER_BYTE + 17_583 + STORAGE_OCCUPATION_GAS_PER_BYTE;
/// The cost of removing data from storage, per byte
pub const STORAGE_DELETE_GAS_PER_BYTE: u64 =
    MEMORY_ACCESS_GAS_PER_BYTE + 17_583 + PHYSICAL_STORAGE_LATENCY_PER_BYTE;
/// The cost of verifying a single signature of a transaction
pub const VERIFY_TX_SIG_GAS: u64 = 435_190;
/// The cost for requesting one more page in wasm (64KiB)
#[allow(clippy::cast_possible_truncation)] // const in u32 range
pub const WASM_MEMORY_PAGE_GAS: u32 =
    MEMORY_ACCESS_GAS_PER_BYTE as u32 * 64 * 1_024;
/// The cost to validate an Ibc action
pub const IBC_ACTION_VALIDATE_GAS: u64 = 290_935;
/// The cost to execute an Ibc action
pub const IBC_ACTION_EXECUTE_GAS: u64 = 1_685_733;
/// The cost of masp sig verification
pub const MASP_VERIFY_SIG_GAS: u64 = 3_817_500;
/// The fixed cost of spend note verification
pub const MASP_FIXED_SPEND_GAS: u64 = 59_521_000;
/// The variable cost of spend note verification
pub const MASP_VARIABLE_SPEND_GAS: u64 = 9_849_000;
/// The fixed cost of convert note verification
pub const MASP_FIXED_CONVERT_GAS: u64 = 46_197_000;
/// The variable cost of convert note verification
pub const MASP_VARIABLE_CONVERT_GAS: u64 = 10_245_000;
/// The fixed cost of output note verification
pub const MASP_FIXED_OUTPUT_GAS: u64 = 53_439_000;
/// The variable cost of output note verification
pub const MASP_VARIABLE_OUTPUT_GAS: u64 = 9_710_000;
/// The cost to process a masp spend note in the bundle
pub const MASP_SPEND_CHECK_GAS: u64 = 405_070;
/// The cost to process a masp convert note in the bundle
pub const MASP_CONVERT_CHECK_GAS: u64 = 188_590;
/// The cost to process a masp output note in the bundle
pub const MASP_OUTPUT_CHECK_GAS: u64 = 204_430;
/// The cost to run the final masp check in the bundle
pub const MASP_FINAL_CHECK_GAS: u64 = 43;
/// Gas divider specific for the masp vp. Only allocates half of the cores to
/// the masp vp since we can expect the other half to be busy with other vps
pub const MASP_PARALLEL_GAS_DIVIDER: u64 = PARALLEL_GAS_DIVIDER / 2;

/// Gas module result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Representation of tracking gas in sub-units. This effectively decouples gas
/// metering from fee payment, allowing higher resolution when accounting for
/// gas while, at the same time, providing a contained gas value when paying
/// fees.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    PartialOrd,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    BorshSchema,
    Serialize,
    Deserialize,
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

    /// Checked div of `Gas`. Returns `None` if `rhs` is zero.
    pub fn checked_div(&self, rhs: u64) -> Option<Self> {
        self.sub.checked_div(rhs).map(|sub| Self { sub })
    }

    /// Converts the sub gas units to whole ones. If the sub units are not a
    /// multiple of the scale than ceil the quotient
    pub fn get_whole_gas_units(&self, scale: u64) -> WholeGas {
        let quotient = self
            .sub
            .checked_div(scale)
            .expect("Gas quotient should not overflow on checked division");
        if self
            .sub
            .checked_rem(scale)
            .expect("Gas quotient remainder should not overflow")
            == 0
        {
            quotient.into()
        } else {
            quotient
                .checked_add(1)
                .expect("Cannot overflow as the quotient is scaled down u64")
                .into()
        }
    }

    /// Generates a `Gas` instance from a `WholeGas` amount
    pub fn from_whole_units(whole: WholeGas, scale: u64) -> Option<Self> {
        scale.checked_mul(whole.into()).map(|sub| Self { sub })
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

/// Gas represented in whole units. Used for fee payment and to display
/// information to the user.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
)]
pub struct WholeGas(u64);

impl From<u64> for WholeGas {
    fn from(amount: u64) -> WholeGas {
        Self(amount)
    }
}

impl From<WholeGas> for u64 {
    fn from(whole: WholeGas) -> u64 {
        whole.0
    }
}

impl FromStr for WholeGas {
    type Err = GasParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse().map_err(GasParseError::Parse)?))
    }
}

impl Display for WholeGas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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

    /// Add the gas for validating untrusted wasm code
    fn add_wasm_validation_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(WASM_CODE_VALIDATION_GAS_PER_BYTE)
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
    /// Track gas overflow
    gas_overflow: bool,
    /// The gas limit for a transaction
    pub tx_gas_limit: Gas,
    transaction_gas: Gas,
}

/// Gas metering in a validity predicate
#[derive(Debug, Clone)]
pub struct VpGasMeter {
    /// Track gas overflow
    gas_overflow: bool,
    /// The transaction gas limit
    tx_gas_limit: Gas,
    /// The gas consumed by the transaction before the Vp
    initial_gas: Gas,
    /// The current gas usage in the VP
    current_gas: Gas,
}

/// Gas meter for VPs parallel runs
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct VpsGas {
    max: Gas,
    rest: Vec<Gas>,
}

impl GasMetering for TxGasMeter {
    fn consume(&mut self, gas: u64) -> Result<()> {
        if self.gas_overflow {
            hints::cold();
            return Err(Error::GasOverflow);
        }

        self.transaction_gas = self
            .transaction_gas
            .checked_add(gas.into())
            .ok_or_else(|| {
                hints::cold();
                self.gas_overflow = true;
                Error::GasOverflow
            })?;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }

        Ok(())
    }

    fn get_tx_consumed_gas(&self) -> Gas {
        if !self.gas_overflow {
            self.transaction_gas
        } else {
            hints::cold();
            u64::MAX.into()
        }
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit
    }
}

impl TxGasMeter {
    /// Initialize a new Tx gas meter. Requires a gas limit for the specific
    /// wrapper transaction
    pub fn new(tx_gas_limit: impl Into<Gas>) -> Self {
        Self {
            gas_overflow: false,
            tx_gas_limit: tx_gas_limit.into(),
            transaction_gas: Gas::default(),
        }
    }

    /// Add the gas required by a wrapper transaction which is comprised of:
    ///  - cost of validating the wrapper tx
    ///  - space that the transaction requires in the block
    ///  - cost of downloading (as part of the block) the transaction bytes over
    ///    the network
    pub fn add_wrapper_gas(&mut self, tx_bytes: &[u8]) -> Result<()> {
        self.consume(WRAPPER_TX_VALIDATION_GAS)?;

        let bytes_len = tx_bytes.len() as u64;
        self.consume(
            bytes_len
                .checked_mul(
                    STORAGE_OCCUPATION_GAS_PER_BYTE
                        + NETWORK_TRANSMISSION_GAS_PER_BYTE,
                )
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

    /// Copy the consumed gas from the other instance. Fails if this value
    /// exceeds the gas limit of this gas meter or if overflow happened
    pub fn copy_consumed_gas_from(&mut self, other: &Self) -> Result<()> {
        self.transaction_gas = other.transaction_gas;
        self.gas_overflow = other.gas_overflow;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError);
        }
        if self.gas_overflow {
            return Err(Error::GasOverflow);
        }

        Ok(())
    }
}

impl GasMetering for VpGasMeter {
    fn consume(&mut self, gas: u64) -> Result<()> {
        if self.gas_overflow {
            hints::cold();
            return Err(Error::GasOverflow);
        }

        self.current_gas =
            self.current_gas.checked_add(gas.into()).ok_or_else(|| {
                hints::cold();
                self.gas_overflow = true;
                Error::GasOverflow
            })?;

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
        if !self.gas_overflow {
            self.initial_gas
        } else {
            hints::cold();
            u64::MAX.into()
        }
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit
    }
}

impl VpGasMeter {
    /// Initialize a new VP gas meter from the `TxGasMeter`
    pub fn new_from_tx_meter(tx_gas_meter: &TxGasMeter) -> Self {
        Self {
            gas_overflow: false,
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
        let parallel_gas = self
            .rest
            .iter()
            .try_fold(Gas::default(), |acc, gas| {
                acc.checked_add(*gas).ok_or(Error::GasOverflow)
            })?
            .checked_div(PARALLEL_GAS_DIVIDER)
            .expect("Div by non-zero int cannot fail");
        self.max.checked_add(parallel_gas).ok_or(Error::GasOverflow)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use super::*;
    const BLOCK_GAS_LIMIT: u64 = 10_000_000_000;
    const TX_GAS_LIMIT: u64 = 1_000_000;

    proptest! {
        #[test]
        fn test_vp_gas_meter_add(gas in 0..BLOCK_GAS_LIMIT) {
            let tx_gas_meter = TxGasMeter {
                gas_overflow: false,
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
            gas_overflow: false,
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
            gas_overflow: false,
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
        let mut meter = TxGasMeter::new(BLOCK_GAS_LIMIT);
        meter.consume(1).expect("cannot add the gas");
        assert_matches!(
            meter.consume(u64::MAX).expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_tx_gas_limit() {
        let mut meter = TxGasMeter::new(TX_GAS_LIMIT);
        assert_matches!(
            meter
                .consume(TX_GAS_LIMIT + 1)
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError
        );
    }
}
