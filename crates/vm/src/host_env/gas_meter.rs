//! Gas meter used in the vm.

use namada_gas::{
    Gas, GasMeterKind, GasMetering, NativeGasMetering, TxGasMeter,
};

#[cfg(feature = "wasm-runtime")]
use crate::wasm::host_env::WasmGasMeter;

/// Gas meter that stores used gas in native or wasm memory
#[derive(Debug)]
pub enum GasMeter<N> {
    /// Gas is stored in native memory
    Native(N),
    /// Gas is stored in wasm memory
    #[cfg(feature = "wasm-runtime")]
    Wasm(WasmGasMeter),
}

#[cfg(feature = "wasm-runtime")]
impl<N> From<WasmGasMeter> for GasMeter<N> {
    #[inline]
    fn from(meter: WasmGasMeter) -> Self {
        Self::Wasm(meter)
    }
}

impl From<TxGasMeter> for GasMeter<TxGasMeter> {
    #[inline]
    fn from(meter: TxGasMeter) -> Self {
        Self::Native(meter)
    }
}

impl<N> GasMeter<N> {
    /// Return the [`GasMeterKind`] of this meter.
    #[inline]
    pub fn kind(&self) -> GasMeterKind {
        match self {
            Self::Native(_) => GasMeterKind::HostFn,
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(_) => GasMeterKind::MutGlobal,
        }
    }

    /// Returns the initiallly available gas in wasm.
    #[cfg(feature = "wasm-runtime")]
    pub fn wasm_initial_avail_gas(&self) -> Option<Gas> {
        if let Self::Wasm(meter) = self {
            Some(meter.initial_gas())
        } else {
            None
        }
    }
}

impl<N: NativeGasMetering> GasMetering for GasMeter<N> {
    fn consume(&mut self, gas: Gas) -> namada_gas::Result<()> {
        match self {
            Self::Native(meter) => meter.consume(gas),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.consume(gas),
        }
    }

    fn get_tx_consumed_gas(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_tx_consumed_gas(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_tx_consumed_gas(),
        }
    }

    fn get_gas_limit(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_gas_limit(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_gas_limit(),
        }
    }

    fn get_gas_scale(&self) -> u64 {
        match self {
            Self::Native(meter) => meter.get_gas_scale(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_gas_scale(),
        }
    }
}
