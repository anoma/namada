use std::sync::{mpsc, Arc, Mutex};

use wasmer::{internals::WithEnv, HostFunction, Memory, WasmTypeList};

#[derive(wasmer::WasmerEnv, Clone)]
pub struct TxEnv {
    // TODO Mutex is not great, we only ever read, but it's what WasmerEnv
    // currently implements. There must be a better way...
    pub sender: Arc<Mutex<mpsc::Sender<TxMsg>>>,
    #[wasmer(export)]
    pub memory: wasmer::LazyInit<Memory>,
}

pub struct TxMsg {
    pub src: String,
    pub dest: String,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct TxRunner {
    memory: Memory,
    wasm_store: wasmer::Store,
}

impl TxRunner {
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        // TODO Could we pass the modified accounts sub-spaces via WASM store directly
        // to VPs' wasm scripts to avoid passing it through the host?
        let wasm_store = wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        let memory = Memory::new(&wasm_store, wasmer::MemoryType::new(1, None, false)).unwrap();
        Self { memory, wasm_store }
    }

    pub fn run<F, Args, Rets>(
        &self,
        tx_code: Vec<u8>,
        tx_data: Vec<u8>,
        tx_sender: mpsc::Sender<TxMsg>,
        func: F,
    ) -> Result<(), String>
    where
        // TODO these types don't need to be generic, specialize the func to avoid leaking these types
        F: HostFunction<Args, Rets, WithEnv, TxEnv>,
        Args: WasmTypeList,
        Rets: WasmTypeList,
    {
        let tx_env = TxEnv {
            sender: Arc::new(Mutex::new(tx_sender)),
            memory: wasmer::LazyInit::default(),
        };
        let tx_module =
            wasmer::Module::new(&self.wasm_store, &tx_code).map_err(|e| e.to_string())?;
        let tx_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => self.memory.clone(),
                "transfer" => wasmer::Function::new_native_with_env(&self.wasm_store, tx_env, func),
            },
        };
        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports).map_err(|e| e.to_string())?;
        let apply_tx = tx_code
            .exports
            .get_function("apply_tx")
            .map_err(|e| e.to_string())?
            .native::<(i32, i32), ()>()
            .map_err(|e| e.to_string())?;
        apply_tx
            .call(tx_data.as_ptr() as i32, tx_data.len() as i32)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub struct VpRunner;

impl VpRunner {
    pub fn run(&self) {
        // TODO run in parallel for all accounts whose sub-space has changed by
        // `apply_tx`:
        //   - all must return `true`
        //   - cancel all workers and fail if any returns `false`
        // let vp_module = wasmer::Module::new(&wasm_store, TODO_vp_code)
        //     .map_err(|e| e.to_string())?;
        // let vp_imports = wasmer::imports! {
        //     // default namespace
        //     "env" => {
        //         // TODO bind host functions:
        //         //"something" => wasmer::func!(something),
        //     },
        // };
        // // run the transaction wasm code
        // let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
        //     .map_err(|e| e.to_string())?;
        // // TODO update Transaction and pass in the vp.data
        // let validate_tx = vp_code
        //     .exports
        //     .get_function("validate_tx")
        //     .map_err(|e| e.to_string())?
        //     .native::<(i32, i32, i32, i32, i32, i32), i32>()
        //     .map_err(|e| e.to_string())?;
        // let accept = validate_tx
        //     .call(0, 0, 1, 1, 2, 2)
        //     .map_err(|e| e.to_string())?;
        // log::debug!("validate_tx result {:#?}", accept);
    }
}
