use borsh::{BorshDeserialize, BorshSerialize};
use std::{
    io::Write,
    sync::{mpsc, Arc, Mutex},
};

use wasmer::{internals::WithEnv, HostFunction, Memory};

#[derive(wasmer::WasmerEnv, Clone)]
pub struct TxEnv {
    // TODO Mutex is not great, we only ever read, but it's what WasmerEnv
    // currently implements. There must be a better way...
    pub sender: Arc<Mutex<mpsc::Sender<TxMsg>>>,
    #[wasmer(export)]
    pub memory: wasmer::LazyInit<Memory>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TxMsg {
    pub src: String,
    pub dest: String,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct TxRunner {
    wasm_store: wasmer::Store,
}

impl TxRunner {
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        // TODO Could we pass the modified accounts sub-spaces via WASM store
        // directly to VPs' wasm scripts to avoid passing it through the
        // host?
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run<F>(
        &self,
        tx_code: Vec<u8>,
        tx_data: Vec<u8>,
        tx_sender: mpsc::Sender<TxMsg>,
        transfer: F,
    ) -> Result<(), String>
    where
        F: HostFunction<(i32, i32, i32, i32, u64), (), WithEnv, TxEnv>,
    {
        let tx_env = TxEnv {
            sender: Arc::new(Mutex::new(tx_sender)),
            memory: wasmer::LazyInit::default(),
        };
        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(|e| e.to_string())?;
        let memory = Memory::new(
            &self.wasm_store,
            wasmer::MemoryType::new(1, None, false),
        )
        .unwrap();
        let tx_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
                "transfer" => wasmer::Function::new_native_with_env(&self.wasm_store, tx_env, transfer),
            },
        };
        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(|e| e.to_string())?;
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

// does the validity predicate accept the state changes?
pub type VpMsg = bool;

#[derive(Clone, Debug)]
pub struct VpRunner {
    wasm_store: wasmer::Store,
}

impl VpRunner {
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        // TODO Could we pass the modified accounts sub-spaces via WASM store
        // directly to VPs' wasm scripts to avoid passing it through the
        // host?
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run(
        &self,
        vp_code: impl AsRef<[u8]>,
        tx_msg: &TxMsg,
        vp_sender: mpsc::Sender<VpMsg>,
    ) -> Result<(), String> {
        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(|e| e.to_string())?;
        let mut tx_bytes = Vec::with_capacity(1024);
        tx_msg.serialize(&mut tx_bytes).unwrap();

        let memory = Memory::new(
            &self.wasm_store,
            wasmer::MemoryType::new(1, None, false),
        )
        .unwrap();
        let vp_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
            },
        };
        // compile and run the transaction wasm code
        let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(|e| e.to_string())?;
        let memory = vp_code
            .exports
            .get_memory("memory")
            .map_err(|e| e.to_string())?;

        {
            // TODO: do this safely in a customized memory implementation
            let mut data = unsafe { memory.data_unchecked_mut() };
            // NOTE: the memory is initialized with 1 page (64kb in
            // `wasmer::Pages`), so this data fits in
            data.write(&tx_bytes).unwrap();
        }

        let validate_tx = vp_code
            .exports
            .get_function("validate_tx")
            .map_err(|e| e.to_string())?
            .native::<(i32, i32), i32>()
            .map_err(|e| e.to_string())?;
        let is_valid = validate_tx
            // TODO: we use 0 for the tx_bytes pointer, because we wrote the
            // `tx_bytes` in the front of `memory`, this should be handled in
            // the memory implementation
            .call(0 as i32, tx_bytes.len() as i32)
            .map_err(|e| e.to_string())?
            == 1;
        vp_sender.send(is_valid).unwrap();
        Ok(())
    }
}
