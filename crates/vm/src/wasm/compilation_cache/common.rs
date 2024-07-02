//! WASM compilation cache.
//!
//! The cache is backed by in-memory LRU cache with configurable size
//! limit and a file system cache of serialized modules.

use std::collections::hash_map::RandomState;
use std::fs;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

use clru::{CLruCache, CLruCacheConfig, WeightScale};
use namada_core::collections::HashMap;
use namada_core::control_flow::time::{ExponentialBackoff, SleepStrategy};
use namada_core::hash::Hash;
use wasmer::{Module, Store};
use wasmer_cache::{FileSystemCache, Hash as CacheHash};

use crate::wasm::run::untrusted_wasm_store;
use crate::wasm::{self, memory};
use crate::{WasmCacheAccess, WasmCacheRoAccess};

/// Cache handle. Thread-safe.
#[derive(Debug, Clone)]
pub struct Cache<N: CacheName, A: WasmCacheAccess> {
    /// Cached files directory
    dir: PathBuf,
    /// Compilation progress
    progress: Arc<RwLock<HashMap<Hash, Compilation>>>,
    /// In-memory LRU cache of compiled modules
    in_memory: Arc<RwLock<MemoryCache>>,
    /// The cache's name
    name: PhantomData<N>,
    /// Cache access level
    access: PhantomData<A>,
}

/// This trait is used to give names to different caches
pub trait CacheName: Clone + std::fmt::Debug {
    /// Get the name of the cache
    fn name() -> &'static str;
}

/// In-memory LRU cache of compiled modules
type MemoryCache = CLruCache<Hash, Module, RandomState, ModuleCacheScale>;

/// Compilation progress
#[derive(Debug)]
enum Compilation {
    Compiling,
    Done,
}

/// Configures the cache scale of modules that limits the maximum capacity
/// of the cache (CLruCache::len + CLruCache::weight <= CLruCache::capacity).
#[derive(Debug)]
struct ModuleCacheScale;

impl WeightScale<Hash, Module> for ModuleCacheScale {
    fn weight(&self, _key: &Hash, _value: &Module) -> usize {
        1
    }
}

impl<N: CacheName, A: WasmCacheAccess> Cache<N, A> {
    /// Create a wasm in-memory cache with a given size limit and a file
    /// system cache.
    ///
    /// # Panics
    /// The `max_bytes` must be non-zero.
    pub fn new(dir: impl Into<PathBuf>, max_bytes: usize) -> Self {
        let cache = CLruCache::with_config(
            CLruCacheConfig::new(NonZeroUsize::new(max_bytes).unwrap())
                .with_scale(ModuleCacheScale),
        );
        let in_memory = Arc::new(RwLock::new(cache));

        let target_hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::hash::DefaultHasher::new();
            wasmer::Target::default().hash(&mut hasher);
            hasher.finish()
        };
        let version = format!(
            "{}_{:x}",
            concat!(env!("CARGO_PKG_VERSION"), "_", env!("RUSTUP_TOOLCHAIN")),
            target_hash,
        );
        let dir = dir.into().join(version);

        fs::create_dir_all(&dir)
            .expect("Couldn't create the wasm cache directory");

        Self {
            dir,
            progress: Default::default(),
            in_memory,
            name: Default::default(),
            access: Default::default(),
        }
    }

    /// Get a WASM module from LRU cache, from a file or compile it and cache
    /// it. If the cache access is set to [`crate::WasmCacheRwAccess`], it
    /// updates the position in the LRU cache. Otherwise, the compiled
    /// module will not be be cached, if it's not already.
    pub fn fetch(
        &mut self,
        code_hash: &Hash,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        if A::is_read_write() {
            self.get(code_hash)
        } else {
            self.peek(code_hash)
        }
    }

    /// Get the current number of items in the cache
    pub fn get_size(&self) -> usize {
        self.in_memory.read().unwrap().len()
    }

    /// Get the current weight of the cache
    pub fn get_cache_size(&self) -> usize {
        self.in_memory.read().unwrap().weight()
    }

    /// Get a WASM module from LRU cache, from a file or compile it and cache
    /// it. Updates the position in the LRU cache.
    fn get(
        &mut self,
        hash: &Hash,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        let mut in_memory = self.in_memory.write().unwrap();
        if let Some(module) = in_memory.get(hash) {
            tracing::trace!(
                "{} found {} in cache.",
                N::name(),
                hash.to_string()
            );
            return Ok(Some((module.clone(), store())));
        }
        drop(in_memory);

        let mut iter = 0;
        let exponential_backoff = ExponentialBackoff {
            base: 2,
            as_duration: |backoff: u64| {
                Duration::from_millis(backoff.saturating_mul(10))
            },
        };
        loop {
            let progress = self.progress.read().unwrap();
            match progress.get(hash) {
                Some(Compilation::Done) => {
                    drop(progress);
                    let mut in_memory = self.in_memory.write().unwrap();
                    if let Some(module) = in_memory.get(hash) {
                        tracing::info!(
                            "{} found {} in memory cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some((module.clone(), store())));
                    }

                    if let Ok((module, store)) =
                        file_load_module(&self.dir, hash)
                    {
                        tracing::info!(
                            "{} found {} in file cache.",
                            N::name(),
                            hash.to_string()
                        );
                        // Put into cache, ignore result if it's full
                        let _ =
                            in_memory.put_with_weight(*hash, module.clone());

                        return Ok(Some((module, store)));
                    } else {
                        return Ok(None);
                    }
                }
                Some(Compilation::Compiling) => {
                    drop(progress);
                    tracing::info!(
                        "Waiting for {} {} ...",
                        N::name(),
                        hash.to_string()
                    );
                    sleep(exponential_backoff.backoff(&iter));
                    // Cannot overflow
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        iter += 1;
                    }
                    continue;
                }
                None => {
                    drop(progress);
                    let (module, store) = if module_file_exists(&self.dir, hash)
                    {
                        tracing::info!(
                            "Trying to load {} {} from file.",
                            N::name(),
                            hash.to_string()
                        );
                        if let Ok(res) = file_load_module(&self.dir, hash) {
                            res
                        } else {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    };

                    // Update progress
                    let mut progress = self.progress.write().unwrap();
                    progress.insert(*hash, Compilation::Done);

                    // Put into cache, ignore the result (fails if the module
                    // cannot fit into the cache)
                    let mut in_memory = self.in_memory.write().unwrap();
                    let _ = in_memory.put_with_weight(*hash, module.clone());

                    return Ok(Some((module, store)));
                }
            }
        }
    }

    /// Peak-only is used for dry-ran txs (and VPs that the tx triggers).
    /// It doesn't update the in-memory cache.
    fn peek(
        &self,
        hash: &Hash,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        let in_memory = self.in_memory.read().unwrap();
        if let Some(module) = in_memory.peek(hash) {
            tracing::info!(
                "{} found {} in cache.",
                N::name(),
                hash.to_string()
            );
            return Ok(Some((module.clone(), store())));
        }
        drop(in_memory);

        let mut iter = 0;
        let exponential_backoff = ExponentialBackoff {
            base: 2,
            as_duration: |backoff: u64| {
                Duration::from_millis(backoff.saturating_mul(10))
            },
        };
        loop {
            let progress = self.progress.read().unwrap();
            match progress.get(hash) {
                Some(Compilation::Done) => {
                    drop(progress);
                    let in_memory = self.in_memory.read().unwrap();
                    if let Some(module) = in_memory.peek(hash) {
                        tracing::info!(
                            "{} found {} in memory cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some((module.clone(), store())));
                    }

                    if let Ok((module, store)) =
                        file_load_module(&self.dir, hash)
                    {
                        tracing::info!(
                            "{} found {} in file cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some((module, store)));
                    } else {
                        return Ok(None);
                    }
                }
                Some(Compilation::Compiling) => {
                    drop(progress);
                    tracing::info!(
                        "Waiting for {} {} ...",
                        N::name(),
                        hash.to_string()
                    );
                    sleep(exponential_backoff.backoff(&iter));
                    // Cannot overflow
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        iter += 1;
                    }
                    continue;
                }
                None => {
                    drop(progress);

                    return if module_file_exists(&self.dir, hash) {
                        tracing::info!(
                            "Trying to load {} {} from file.",
                            N::name(),
                            hash.to_string()
                        );
                        if let Ok(res) = file_load_module(&self.dir, hash) {
                            return Ok(Some(res));
                        } else {
                            return Ok(None);
                        }
                    } else {
                        Ok(None)
                    };
                }
            }
        }
    }

    /// Compile a WASM module and persist the compiled modules to files.
    pub fn compile_or_fetch(
        &mut self,
        code: impl AsRef<[u8]>,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        let hash = hash_of_code(&code);

        if !A::is_read_write() {
            // It doesn't update the cache and files
            let progress = self.progress.read().unwrap();
            match progress.get(&hash) {
                Some(_) => return self.peek(&hash),
                None => {
                    let code = wasm::run::prepare_wasm_code(code)?;
                    return Ok(Some(compile(code)?));
                }
            }
        }

        let mut progress = self.progress.write().unwrap();
        if progress.get(&hash).is_some() {
            drop(progress);
            return self.fetch(&hash);
        }
        progress.insert(hash, Compilation::Compiling);
        drop(progress);

        tracing::info!("Compiling {} {}.", N::name(), hash.to_string());

        match wasm::run::prepare_wasm_code(code) {
            Ok(code) => match compile(code) {
                Ok((module, store)) => {
                    // Write the file
                    file_write_module(&self.dir, &module, &hash);

                    // Update progress
                    let mut progress = self.progress.write().unwrap();
                    progress.insert(hash, Compilation::Done);

                    // Put into cache, ignore result if it's full
                    let mut in_memory = self.in_memory.write().unwrap();
                    let _ = in_memory.put_with_weight(hash, module.clone());

                    Ok(Some((module, store)))
                }
                Err(err) => {
                    tracing::info!(
                        "Failed to compile WASM {} with {}",
                        hash.to_string(),
                        err
                    );
                    let mut progress = self.progress.write().unwrap();
                    progress.swap_remove(&hash);
                    Err(err)
                }
            },
            Err(err) => {
                tracing::info!(
                    "Failed to prepare WASM {} with {}",
                    hash.to_string(),
                    err
                );
                let mut progress = self.progress.write().unwrap();
                progress.swap_remove(&hash);
                Err(err)
            }
        }
    }

    /// Pre-compile a WASM module to a file. The compilation runs in a new OS
    /// thread and the function returns immediately.
    pub fn pre_compile(&mut self, code: impl AsRef<[u8]>) {
        if A::is_read_write() {
            let hash = hash_of_code(&code);
            let mut progress = self.progress.write().unwrap();
            match progress.get(&hash) {
                Some(_) => {
                    // Already known, do nothing
                }
                None => {
                    if module_file_exists(&self.dir, &hash) {
                        progress.insert(hash, Compilation::Done);
                        return;
                    }
                    progress.insert(hash, Compilation::Compiling);
                    drop(progress);
                    let progress = self.progress.clone();
                    let code = code.as_ref().to_vec();
                    let dir = self.dir.clone();
                    std::thread::spawn(move || {
                        tracing::info!("Compiling WASM {}.", hash.to_string());

                        let (_module, _store) =
                            match wasm::run::prepare_wasm_code(code) {
                                Ok(code) => match compile(code) {
                                    Ok((module, store)) => {
                                        // Write the file
                                        file_write_module(&dir, &module, &hash);

                                        // Update progress
                                        let mut progress =
                                            progress.write().unwrap();
                                        progress
                                            .insert(hash, Compilation::Done);
                                        tracing::info!(
                                            "Finished compiling WASM {hash}."
                                        );
                                        if progress.values().all(
                                            |compilation| {
                                                matches!(
                                                    compilation,
                                                    Compilation::Done
                                                )
                                            },
                                        ) {
                                            tracing::info!(
                                                "Finished compiling all {}.",
                                                N::name()
                                            )
                                        }
                                        (module, store)
                                    }
                                    Err(err) => {
                                        let mut progress =
                                            progress.write().unwrap();
                                        tracing::info!(
                                            "Failed to compile WASM {} with {}",
                                            hash.to_string(),
                                            err
                                        );
                                        progress.swap_remove(&hash);
                                        return Err(err);
                                    }
                                },
                                Err(err) => {
                                    let mut progress =
                                        progress.write().unwrap();
                                    tracing::info!(
                                        "Failed to prepare WASM {} with {}",
                                        hash.to_string(),
                                        err
                                    );
                                    progress.swap_remove(&hash);
                                    return Err(err);
                                }
                            };

                        let res: Result<(), wasm::run::Error> = Ok(());
                        res
                    });
                }
            }
        }
    }

    /// Get a read-only cache handle.
    pub fn read_only(&self) -> Cache<N, WasmCacheRoAccess> {
        Cache {
            dir: self.dir.clone(),
            progress: self.progress.clone(),
            in_memory: self.in_memory.clone(),
            name: Default::default(),
            access: Default::default(),
        }
    }
}

fn hash_of_code(code: impl AsRef<[u8]>) -> Hash {
    Hash::sha256(code.as_ref())
}

fn compile(
    code: impl AsRef<[u8]>,
) -> Result<(Module, Store), wasm::run::Error> {
    universal::compile(code).map_err(wasm::run::Error::CompileError)
}

fn file_ext() -> &'static str {
    // This has to be using the file_ext matching the compilation method in the
    // `fn compile`
    universal::FILE_EXT
}

pub(crate) fn store() -> Store {
    // This has to be using the store matching the compilation method in the
    // `fn compile`
    universal::store()
}

fn file_write_module(dir: impl AsRef<Path>, module: &Module, hash: &Hash) {
    use wasmer_cache::Cache;
    let mut fs_cache = fs_cache(dir, hash);
    fs_cache.store(CacheHash::new(hash.0), module).unwrap();
}

fn file_load_module(
    dir: impl AsRef<Path>,
    hash: &Hash,
) -> Result<(Module, Store), wasmer::DeserializeError> {
    use wasmer_cache::Cache;
    let fs_cache = fs_cache(dir, hash);
    let store = store();
    let hash = CacheHash::new(hash.0);
    let module = unsafe { fs_cache.load(&store, hash) };
    if let Err(err) = module.as_ref() {
        tracing::error!(
            "Error loading cached wasm {}: {err}.",
            hash.to_string()
        );
    }
    Ok((module?, store))
}

fn fs_cache(dir: impl AsRef<Path>, hash: &Hash) -> FileSystemCache {
    let path = dir.as_ref().join(hash.to_string().to_lowercase());
    let mut fs_cache = FileSystemCache::new(path).unwrap();
    fs_cache.set_cache_extension(Some(file_ext()));
    fs_cache
}

fn module_file_exists(dir: impl AsRef<Path>, hash: &Hash) -> bool {
    let file =
        dir.as_ref()
            .join(hash.to_string().to_lowercase())
            .join(format!(
                "{}.{}",
                hash.to_string().to_lowercase(),
                file_ext()
            ));
    file.exists()
}

/// A universal engine compilation. The module can be serialized to/from bytes.
mod universal {
    use super::*;

    #[allow(dead_code)]
    pub const FILE_EXT: &str = "bin";

    /// Compile wasm with a universal engine.
    #[allow(dead_code)]
    pub fn compile(
        code: impl AsRef<[u8]>,
    ) -> Result<(Module, Store), wasmer::CompileError> {
        let store = store();
        let module = Module::new(&store, code.as_ref())?;
        Ok((module, store))
    }

    /// Universal WASM store
    #[allow(dead_code)]
    pub fn store() -> Store {
        untrusted_wasm_store(memory::vp_limit())
    }
}

/// Testing helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use tempfile::{tempdir, TempDir};

    use super::*;
    use crate::wasm::{TxCache, VpCache};
    use crate::WasmCacheRwAccess;

    /// VP Cache with a temp dir for testing
    pub fn vp_cache() -> (VpCache<WasmCacheRwAccess>, TempDir) {
        cache::<super::super::vp::Name>()
    }

    /// Tx Cache with a temp dir for testing
    pub fn tx_cache() -> (TxCache<WasmCacheRwAccess>, TempDir) {
        cache::<super::super::tx::Name>()
    }

    /// Generic Cache with a temp dir for testing
    pub fn cache<N: CacheName>() -> (Cache<N, WasmCacheRwAccess>, TempDir) {
        let dir = tempdir().unwrap();
        let cache = Cache::new(
            dir.path(),
            50 * 1024 * 1024, // 50 MiB
        );
        (cache, dir)
    }
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod test {
    use std::cmp::max;

    use assert_matches::assert_matches;
    use byte_unit::Byte;
    use namada_test_utils::TestWasms;
    use tempfile::{tempdir, TempDir};
    use test_log::test;

    use super::*;
    use crate::WasmCacheRwAccess;

    #[test]
    fn test_fetch_or_compile_valid_wasm() {
        // Load some WASMs and find their hashes and in-memory size
        let tx_read_storage_key = load_wasm(TestWasms::TxReadStorageKey.path());
        let tx_no_op = load_wasm(TestWasms::TxNoOp.path());

        // Create a new cache with the limit set to
        // `max(tx_read_storage_key.size, tx_no_op.size) + 1`
        {
            let max_bytes = max(tx_read_storage_key.size, tx_no_op.size) + 1;
            println!(
                "Using cache with max_bytes {} ({})",
                Byte::from_bytes(max_bytes as u128).get_appropriate_unit(true),
                max_bytes
            );
            let (mut cache, _tmp_dir) = cache(max_bytes);

            // Fetch `tx_read_storage_key`
            {
                let fetched = cache.fetch(&tx_read_storage_key.hash).unwrap();
                assert_matches!(
                    fetched,
                    None,
                    "The module should not be in cache"
                );

                let fetched =
                    cache.compile_or_fetch(&tx_read_storage_key.code).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The code should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_read_storage_key.hash),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&tx_read_storage_key.hash),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(&cache.dir, &tx_read_storage_key.hash),
                    "The file must be written"
                );
            }

            // Fetch `tx_no_op`. Fetching another module should get us over the
            // limit, so the previous one should be popped from the cache
            {
                let fetched = cache.fetch(&tx_no_op.hash).unwrap();
                assert_matches!(
                    fetched,
                    None,
                    "The module must not be in cache"
                );

                let fetched = cache.compile_or_fetch(&tx_no_op.code).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The code should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_no_op.hash),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&tx_no_op.hash),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(&cache.dir, &tx_no_op.hash),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(&cache.dir, &tx_read_storage_key.hash),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&tx_read_storage_key.hash),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Reset the in-memory cache and progress and fetch
            // `tx_read_storage_key` again, this time it should get loaded
            // from file
            let in_memory_cache = CLruCache::with_config(
                CLruCacheConfig::new(NonZeroUsize::new(max_bytes).unwrap())
                    .with_scale(ModuleCacheScale),
            );
            let in_memory = Arc::new(RwLock::new(in_memory_cache));
            cache.in_memory = in_memory;
            cache.progress = Default::default();
            {
                let fetched = cache.fetch(&tx_read_storage_key.hash).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in file cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_read_storage_key.hash),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&tx_read_storage_key.hash),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(&cache.dir, &tx_read_storage_key.hash),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(&cache.dir, &tx_no_op.hash),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&tx_no_op.hash),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Fetch `tx_read_storage_key` again, now it should be in-memory
            {
                let fetched = cache.fetch(&tx_read_storage_key.hash).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in memory"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_read_storage_key.hash),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&tx_read_storage_key.hash),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(&cache.dir, &tx_read_storage_key.hash),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(&cache.dir, &tx_no_op.hash),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&tx_no_op.hash),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Fetch `tx_no_op` with read/only access
            {
                let mut cache = cache.read_only();

                let fetched = cache.fetch(&tx_no_op.hash).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                // Fetching with read-only should not modify the in-memory cache
                let fetched = cache.compile_or_fetch(&tx_no_op.code).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_no_op.hash),
                    None,
                    "The module should not be added back to in-memory cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&tx_read_storage_key.hash),
                    Some(_),
                    "The previous module must still be in memory"
                );
            }
        }
    }

    #[test]
    fn test_fetch_or_compile_invalid_wasm() {
        // Some random bytes
        let invalid_wasm = vec![1_u8, 0, 8, 10, 6, 1];
        let hash = hash_of_code(&invalid_wasm);
        let (mut cache, _) = testing::cache::<TestCache>();

        // Try to compile it
        let error = cache
            .compile_or_fetch(&invalid_wasm)
            .expect_err("Compilation should fail");
        println!("Error: {}", error);

        let in_memory = cache.in_memory.read().unwrap();
        assert_matches!(
            in_memory.peek(&hash),
            None,
            "There should be no entry for this hash in memory"
        );

        let progress = cache.progress.read().unwrap();
        assert_matches!(progress.get(&hash), None, "Any progress is removed");

        assert!(
            !module_file_exists(&cache.dir, &hash),
            "The file must not be written"
        );
    }

    #[test]
    fn test_pre_compile_valid_wasm() {
        // Load some WASMs and find their hashes and in-memory size
        let vp_always_true = load_wasm(TestWasms::VpAlwaysTrue.path());
        let vp_eval = load_wasm(TestWasms::VpEval.path());

        // Create a new cache with the limit set to
        // `max(vp_always_true.size, vp_eval.size) + 1 + extra_bytes`
        {
            let max_bytes = max(vp_always_true.size, vp_eval.size) + 1;
            println!(
                "Using cache with max_bytes {} ({})",
                Byte::from_bytes(max_bytes as u128).get_appropriate_unit(true),
                max_bytes
            );
            let (mut cache, _tmp_dir) = cache(max_bytes);

            // Pre-compile `vp_always_true`
            {
                cache.pre_compile(&vp_always_true.code);

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&vp_always_true.hash),
                    Some(Compilation::Done | Compilation::Compiling),
                    "The progress must be updated"
                );
            }

            // Now fetch it to wait for it finish compilation
            {
                let fetched = cache.fetch(&vp_always_true.hash).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&vp_always_true.hash),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&vp_always_true.hash),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(&cache.dir, &vp_always_true.hash),
                    "The file must be written"
                );
            }

            // Pre-compile `vp_eval`. Pre-compiling another module should get us
            // over the limit, so the previous one should be popped
            // from the cache
            {
                cache.pre_compile(&vp_eval.code);

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&vp_eval.hash),
                    Some(Compilation::Done | Compilation::Compiling),
                    "The progress must be updated"
                );
            }

            // Now fetch it to wait for it finish compilation
            {
                let fetched = cache.fetch(&vp_eval.hash).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&vp_eval.hash),
                    Some(_),
                    "The module must be in memory"
                );

                assert!(
                    module_file_exists(&cache.dir, &vp_eval.hash),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(&cache.dir, &vp_always_true.hash),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&vp_always_true.hash),
                    None,
                    "The module should have been popped from memory"
                );
            }
        }
    }

    #[test]
    fn test_pre_compile_invalid_wasm() {
        // Some random bytes
        let invalid_wasm = vec![1_u8];
        let hash = hash_of_code(&invalid_wasm);
        let (mut cache, _) = testing::cache::<TestCache>();

        // Try to pre-compile it
        {
            cache.pre_compile(&invalid_wasm);
            let progress = cache.progress.read().unwrap();
            assert_matches!(
                progress.get(&hash),
                Some(Compilation::Done | Compilation::Compiling) | None,
                "The progress must be updated"
            );
        }

        // Now fetch it to wait for it finish compilation
        {
            let fetched = cache.fetch(&hash).unwrap();
            assert_matches!(
                fetched,
                None,
                "There should be no entry for this hash in cache"
            );

            let in_memory = cache.in_memory.read().unwrap();
            assert_matches!(
                in_memory.peek(&hash),
                None,
                "There should be no entry for this hash in memory"
            );

            let progress = cache.progress.read().unwrap();
            assert_matches!(
                progress.get(&hash),
                None,
                "Any progress is removed"
            );

            assert!(
                !module_file_exists(&cache.dir, &hash),
                "The file must not be written"
            );
        }
    }

    /// Get the WASM code bytes, its hash and find the compiled module's size
    fn load_wasm(file: impl AsRef<Path>) -> WasmWithMeta {
        let file = file.as_ref();
        let code = fs::read(file).unwrap();
        let hash = hash_of_code(&code);
        // Find the size of the compiled module
        let size = {
            let (mut cache, _tmp_dir) = cache(
                // No in-memory cache needed, but must be non-zero
                1,
            );
            let (_module, _store) =
                cache.compile_or_fetch(&code).unwrap().unwrap();
            1
        };
        println!(
            "Compiled module {} size including the hash: {} ({})",
            file.to_string_lossy(),
            Byte::from_bytes(size as u128).get_appropriate_unit(true),
            size,
        );
        WasmWithMeta { code, hash, size }
    }

    /// A test helper for loading WASM and finding its hash and size
    #[derive(Clone, Debug)]
    struct WasmWithMeta {
        code: Vec<u8>,
        hash: Hash,
        /// Compiled module's in-memory size
        size: usize,
    }

    /// A `CacheName` implementation for unit tests
    #[derive(Clone, Debug)]
    struct TestCache;
    impl CacheName for TestCache {
        fn name() -> &'static str {
            "test"
        }
    }

    /// A cache with a temp dir for unit tests
    fn cache(
        max_bytes: usize,
    ) -> (Cache<TestCache, WasmCacheRwAccess>, TempDir) {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path(), max_bytes);
        (cache, dir)
    }
}
