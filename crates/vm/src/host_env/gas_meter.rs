//! Gas meter used in the vm.

use std::cell::RefCell;

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
}

#[cfg(feature = "wasm-runtime")]
impl<N> GasMeter<N> {
    /// Create a new gas meter.
    pub fn new<InitNative, InitWasm>(
        kind: GasMeterKind,
        native: InitNative,
        wasm: InitWasm,
    ) -> Self
    where
        InitNative: FnOnce() -> N,
        InitWasm: FnOnce() -> WasmGasMeter,
    {
        match kind {
            GasMeterKind::HostFn => Self::Native(native()),
            GasMeterKind::MutGlobal => Self::Wasm(wasm()),
        }
    }

    /// Initialize the gas meter.
    pub fn init_from<G, E>(
        &mut self,
        native_meter: &N,
        global: G,
    ) -> Result<(), E>
    where
        N: NativeGasMetering + Clone,
        G: FnOnce() -> Result<wasmer::Global, E>,
    {
        match self {
            Self::Native(meter) => {
                meter.clone_from(native_meter);
                Ok(())
            }
            Self::Wasm(meter) => {
                let global = global()?;
                meter.init_from(native_meter, global);
                Ok(())
            }
        }
    }

    /// Flush the consumed gas to the provided meter.
    #[inline]
    pub fn flush_to_meter(
        self,
        native_meter: &RefCell<N>,
    ) -> namada_gas::Result<()>
    where
        N: NativeGasMetering + Clone,
    {
        match self {
            Self::Native(meter) => {
                *native_meter.borrow_mut() = meter;
                Ok(())
            }
            Self::Wasm(meter) => {
                meter.flush_to_meter(&mut *native_meter.borrow_mut())
            }
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

    fn get_initial_gas(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_initial_gas(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_initial_gas(),
        }
    }

    fn get_consumed_gas(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_consumed_gas(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_consumed_gas(),
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
