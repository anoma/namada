//! CLI input types can be used for command arguments

use std::env;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use color_eyre::eyre::Result;
use namada::ledger::ibc::storage::ibc_token;
use namada::types::address::{Address, InternalAddress};
use namada::types::chain::ChainId;
use namada::types::ethereum_events::EthAddress;
use namada::types::ibc::is_ibc_denom;
use namada::types::io::Io;
use namada::types::key::*;
use namada::types::masp::*;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::masp::ShieldedContext;
use namada_sdk::wallet::Wallet;
use namada_sdk::{Namada, NamadaImpl};

use super::args;
use crate::cli::utils;
use crate::config::global::GlobalConfig;
use crate::config::{genesis, Config};
use crate::wallet::CliWalletUtils;
use crate::{wallet, wasm_loader};

/// Env. var to set wasm directory
pub const ENV_VAR_WASM_DIR: &str = "NAMADA_WASM_DIR";

/// Env. var to read the Namada chain id from
pub const ENV_VAR_CHAIN_ID: &str = "NAMADA_CHAIN_ID";

/// A raw address (bech32m encoding) or an alias of an address that may be found
/// in the wallet
pub type WalletAddress = FromContext<Address>;

/// A raw extended spending key (bech32m encoding) or an alias of an extended
/// spending key in the wallet
pub type WalletSpendingKey = FromContext<ExtendedSpendingKey>;

/// A raw payment address (bech32m encoding) or an alias of a payment address
/// in the wallet
pub type WalletPaymentAddr = FromContext<PaymentAddress>;

/// A raw full viewing key (bech32m encoding) or an alias of a full viewing key
/// in the wallet
pub type WalletViewingKey = FromContext<ExtendedViewingKey>;

/// A raw address or a raw extended spending key (bech32m encoding) or an alias
/// of either in the wallet
pub type WalletTransferSource = FromContext<TransferSource>;

/// A raw address or a raw payment address (bech32m encoding) or an alias of
/// either in the wallet
pub type WalletTransferTarget = FromContext<TransferTarget>;

/// A raw keypair (hex encoding), an alias, a public key or a public key hash of
/// a keypair that may be found in the wallet
pub type WalletKeypair = FromContext<common::SecretKey>;

/// A raw public key (hex encoding), a public key hash (also hex encoding) or an
/// alias of an public key that may be found in the wallet
pub type WalletPublicKey = FromContext<common::PublicKey>;

/// A raw address or a raw full viewing key (bech32m encoding) or an alias of
/// either in the wallet
pub type WalletBalanceOwner = FromContext<BalanceOwner>;

/// Command execution context
#[derive(Debug)]
pub struct Context {
    /// Global arguments
    pub global_args: args::Global,
    /// The global configuration
    pub global_config: GlobalConfig,
    /// Chain-specific context, if any chain is configured in `global_config`
    pub chain: Option<ChainContext>,
}

/// Command execution context with chain-specific data
#[derive(Debug)]
pub struct ChainContext {
    /// The wallet
    pub wallet: Wallet<CliWalletUtils>,
    /// The ledger configuration for a specific chain ID
    pub config: Config,
    /// The context fr shielded operations
    pub shielded: ShieldedContext<FsShieldedUtils>,
    /// Native token's address
    pub native_token: Address,
}

impl Context {
    pub fn new<IO: Io>(global_args: args::Global) -> Result<Self> {
        let global_config = read_or_try_new_global_config(&global_args);

        let env_var_chain_id = std::env::var(ENV_VAR_CHAIN_ID)
            .ok()
            .and_then(|chain_id| ChainId::from_str(&chain_id).ok());
        let chain_id = env_var_chain_id
            .as_ref()
            .or(global_args.chain_id.as_ref())
            .or(global_config.default_chain_id.as_ref());

        let chain = match chain_id {
            Some(chain_id) if !global_args.is_pre_genesis => {
                let mut config =
                    Config::load(&global_args.base_dir, chain_id, None);
                let chain_dir = global_args.base_dir.join(chain_id.as_str());
                let genesis =
                    genesis::chain::Finalized::read_toml_files(&chain_dir)
                        .expect("Missing genesis files");
                let native_token = genesis.get_native_token().clone();
                let wallet = if wallet::exists(&chain_dir) {
                    wallet::load(&chain_dir).unwrap()
                } else {
                    panic!(
                        "Could not find wallet at {}.",
                        chain_dir.to_string_lossy()
                    );
                };

                // If the WASM dir specified, put it in the config
                match global_args.wasm_dir.as_ref() {
                    Some(wasm_dir) => {
                        config.wasm_dir = wasm_dir.clone();
                    }
                    None => {
                        if let Ok(wasm_dir) = env::var(ENV_VAR_WASM_DIR) {
                            let wasm_dir: PathBuf = wasm_dir.into();
                            config.wasm_dir = wasm_dir;
                        }
                    }
                }
                Some(ChainContext {
                    wallet,
                    config,
                    shielded: FsShieldedUtils::new(chain_dir),
                    native_token,
                })
            }
            _ => None,
        };

        Ok(Self {
            global_args,
            global_config,
            chain,
        })
    }

    /// Try to take the chain context, or exit the process with an error if no
    /// chain is configured.
    pub fn take_chain_or_exit(self) -> ChainContext {
        self.chain
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Try to borrow chain context, or exit the process with an error if no
    /// chain is configured.
    pub fn borrow_chain_or_exit(&self) -> &ChainContext {
        self.chain
            .as_ref()
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Try to borrow mutably chain context, or exit the process with an error
    /// if no chain is configured.
    pub fn borrow_mut_chain_or_exit(&mut self) -> &mut ChainContext {
        self.chain
            .as_mut()
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Make an implementation of Namada from this object and parameters.
    pub fn to_sdk<C, IO>(self, client: C, io: IO) -> impl Namada
    where
        C: namada::ledger::queries::Client + Sync,
        IO: Io,
    {
        let chain_ctx = self.take_chain_or_exit();
        NamadaImpl::native_new(
            client,
            chain_ctx.wallet,
            chain_ctx.shielded,
            io,
            chain_ctx.native_token,
        )
    }
}

fn safe_exit_on_missing_chain_context() -> ! {
    eprintln!(
        "Failed to construct Namada chain context. If no chain is configured, \
         you may need to run `namada client utils join-network`. If the chain \
         is configured, you may need to set the chain id with `--chain-id \
         <chainid>`, via the env var `{ENV_VAR_CHAIN_ID}`, or configure the \
         default chain id in the `global-config.toml` file. If you do intend \
         to run pre-genesis operations, pass the `--pre-genesis` flag as the \
         first argument to the command."
    );
    utils::safe_exit(1)
}

impl ChainContext {
    /// Parse and/or look-up the value from the context.
    pub fn get<T>(&self, from_context: &FromContext<T>) -> T
    where
        T: ArgFromContext,
    {
        from_context.arg_from_ctx(self).unwrap()
    }

    /// Try to parse and/or look-up an optional value from the context.
    pub fn get_opt<T>(&self, from_context: &Option<FromContext<T>>) -> Option<T>
    where
        T: ArgFromContext,
    {
        from_context
            .as_ref()
            .map(|from_context| from_context.arg_from_ctx(self).unwrap())
    }

    /// Parse and/or look-up the value from the context with cache.
    pub fn get_cached<T>(&mut self, from_context: &FromContext<T>) -> T
    where
        T: ArgFromMutContext,
    {
        from_context.arg_from_mut_ctx(self).unwrap()
    }

    /// Try to parse and/or look-up an optional value from the context with
    /// cache.
    pub fn get_opt_cached<T>(
        &mut self,
        from_context: &Option<FromContext<T>>,
    ) -> Option<T>
    where
        T: ArgFromMutContext,
    {
        from_context
            .as_ref()
            .map(|from_context| from_context.arg_from_mut_ctx(self).unwrap())
    }

    /// Get the wasm directory configured for the chain.
    ///
    /// Note that in "dev" build, this may be the root `wasm` dir.
    pub fn wasm_dir(&self) -> PathBuf {
        self.config.ledger.chain_dir().join(&self.config.wasm_dir)
    }

    /// Read the given WASM file from the WASM directory or an absolute path.
    pub fn read_wasm(&self, file_name: impl AsRef<Path>) -> Vec<u8> {
        wasm_loader::read_wasm_or_exit(self.wasm_dir(), file_name)
    }
}

/// Load global config from expected path in the `base_dir` or try to generate a
/// new one without a chain if it doesn't exist.
pub fn read_or_try_new_global_config(
    global_args: &args::Global,
) -> GlobalConfig {
    GlobalConfig::read(&global_args.base_dir).unwrap_or_else(|err| {
        eprintln!("Error reading global config: {}", err);
        super::safe_exit(1)
    })
}

/// Argument that can be given raw or found in the [`Context`].
#[derive(Debug, Clone)]
pub struct FromContext<T> {
    pub(crate) raw: String,
    phantom: PhantomData<T>,
}

impl<T> FromContext<T> {
    pub fn new(raw: String) -> FromContext<T> {
        Self {
            raw,
            phantom: PhantomData,
        }
    }
}

impl FromContext<TransferSource> {
    /// Converts this TransferSource argument to an Address. Call this function
    /// only when certain that raw represents an Address.
    pub fn to_address(&self) -> FromContext<Address> {
        FromContext::<Address> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }

    /// Converts this TransferSource argument to an ExtendedSpendingKey. Call
    /// this function only when certain that raw represents an
    /// ExtendedSpendingKey.
    pub fn to_spending_key(&self) -> FromContext<ExtendedSpendingKey> {
        FromContext::<ExtendedSpendingKey> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }
}

impl FromContext<TransferTarget> {
    /// Converts this TransferTarget argument to an Address. Call this function
    /// only when certain that raw represents an Address.
    pub fn to_address(&self) -> FromContext<Address> {
        FromContext::<Address> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }

    /// Converts this TransferTarget argument to a PaymentAddress. Call this
    /// function only when certain that raw represents a PaymentAddress.
    pub fn to_payment_address(&self) -> FromContext<PaymentAddress> {
        FromContext::<PaymentAddress> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }
}

impl<T> FromContext<T>
where
    T: ArgFromContext,
{
    /// Parse and/or look-up the value from the chain context.
    fn arg_from_ctx(&self, ctx: &ChainContext) -> Result<T, String> {
        T::arg_from_ctx(ctx, &self.raw)
    }
}

impl<T> FromContext<T>
where
    T: ArgFromMutContext,
{
    /// Parse and/or look-up the value from the mutable chain context.
    fn arg_from_mut_ctx(&self, ctx: &mut ChainContext) -> Result<T, String> {
        T::arg_from_mut_ctx(ctx, &self.raw)
    }
}

/// CLI argument that found via the [`ChainContext`].
pub trait ArgFromContext: Sized {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String>;
}

/// CLI argument that found via the [`ChainContext`] and cached (as in case of
/// an encrypted keypair that has been decrypted), hence using mutable context.
pub trait ArgFromMutContext: Sized {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String>;
}

impl ArgFromContext for Address {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        struct Skip;
        let raw = raw.as_ref();
        // An address can be either raw (bech32m encoding)
        FromStr::from_str(raw)
            // An Ethereum address
            .or_else(|_| {
                (raw.len() == 42 && raw.starts_with("0x"))
                    .then(|| {
                        raw.parse::<EthAddress>()
                            .map(|addr| {
                                Address::Internal(InternalAddress::Erc20(addr))
                            })
                            .map_err(|_| Skip)
                    })
                    .unwrap_or(Err(Skip))
            })
            // An IBC token
            .or_else(|_| {
                is_ibc_denom(raw)
                    .map(|(trace_path, base_denom)| {
                        let base_token = ctx
                            .wallet
                            .find_address(&base_denom)
                            .map(|addr| addr.to_string())
                            .unwrap_or(base_denom);
                        let ibc_denom = format!("{trace_path}/{base_token}");
                        ibc_token(ibc_denom)
                    })
                    .ok_or(Skip)
            })
            // Or it can be an alias that may be found in the wallet
            .or_else(|_| {
                ctx.wallet
                    .find_address(raw)
                    .map(|x| x.into_owned())
                    .ok_or(Skip)
            })
            .map_err(|_| format!("Unknown address {raw}"))
    }
}

impl ArgFromMutContext for common::SecretKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // A keypair can be either a raw keypair in hex string
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it can be an alias
            ctx.wallet
                .find_secret_key(raw, None)
                .map_err(|_find_err| format!("Unknown key {}", raw))
        })
    }
}

impl ArgFromContext for common::PublicKey {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // A public key can be either a raw public key in hex string
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it can be a public key hash in hex string
            FromStr::from_str(raw)
                .map(|pkh: PublicKeyHash| {
                    ctx.wallet.find_public_key_by_pkh(&pkh).unwrap()
                })
                // Or it can be an alias that may be found in the wallet
                .or_else(|_parse_err| {
                    ctx.wallet.find_public_key(raw).map_err(|x| x.to_string())
                })
        })
    }
}

impl ArgFromMutContext for ExtendedSpendingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw extended spending key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_spending_key(raw, None)
                .map_err(|_find_err| format!("Unknown spending key {}", raw))
        })
    }
}

impl ArgFromMutContext for ExtendedViewingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw full viewing key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_viewing_key(raw)
                .map(Clone::clone)
                .map_err(|_find_err| format!("Unknown viewing key {}", raw))
        })
    }
}

impl ArgFromContext for PaymentAddress {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a payment address
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_payment_addr(raw)
                .cloned()
                .ok_or_else(|| format!("Unknown payment address {}", raw))
        })
    }
}

impl ArgFromMutContext for TransferSource {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a spending key
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                ExtendedSpendingKey::arg_from_mut_ctx(ctx, raw)
                    .map(Self::ExtendedSpendingKey)
            })
    }
}

impl ArgFromContext for TransferTarget {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a payment address
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                PaymentAddress::arg_from_ctx(ctx, raw).map(Self::PaymentAddress)
            })
    }
}

impl ArgFromMutContext for BalanceOwner {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a viewing key
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                ExtendedViewingKey::arg_from_mut_ctx(ctx, raw)
                    .map(Self::FullViewingKey)
            })
            .or_else(|_| {
                PaymentAddress::arg_from_ctx(ctx, raw).map(Self::PaymentAddress)
            })
    }
}
