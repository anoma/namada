//! Validity predictates dependency injection soup. In here, we're assigning
//! concrete types for generic type params of native VPs.

use namada_vm::wasm::run::VpEvalWasm;
use namada_vm::wasm::VpCache;
use namada_vp::native_vp::{self, CtxPostStorageRead, CtxPreStorageRead};

use crate::state::StateRead;
use crate::{eth_bridge, governance, ibc, parameters, proof_of_stake, token};

/// Native VP context
pub type NativeVpCtx<'a, S, CA> =
    native_vp::Ctx<'a, S, VpCache<CA>, Eval<S, CA>>;

/// VP WASM evaluator
type Eval<S, CA> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;

/// Native PoS VP
pub type PosVp<'a, S, CA> = proof_of_stake::vp::PosVp<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    GovPreStore<'a, S, CA>,
>;

/// Native IBC VP
pub type IbcVp<'a, S, CA> = ibc::vp::Ibc<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    ParamsPreStore<'a, S, CA>,
    GovPreStore<'a, S, CA>,
    TokenStoreForIbcExec<'a, S, CA>,
    PosPreStore<'a, S, CA>,
>;

/// IBC VP pseudo-execution context
pub type IbcVpContext<'view, 'a, S, CA, EVAL> =
    ibc::vp::context::PseudoExecutionContext<
        'view,
        'a,
        S,
        VpCache<CA>,
        EVAL,
        TokenStoreForIbcExec<'a, S, CA>,
    >;

/// Native parameters VP
pub type ParametersVp<'a, S, CA> = parameters::vp::ParametersVp<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    GovPreStore<'a, S, CA>,
>;

/// Native governance VP
pub type GovernanceVp<'a, S, CA> = governance::vp::GovernanceVp<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    PosPreStore<'a, S, CA>,
    TokenKeys,
>;

/// Native PGF VP
pub type PgfVp<'a, S, CA> =
    governance::vp::pgf::PgfVp<'a, S, VpCache<CA>, Eval<S, CA>>;

/// Native multitoken VP
pub type MultitokenVp<'a, S, CA> = token::vp::MultitokenVp<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    ParamsPreStore<'a, S, CA>,
    GovPreStore<'a, S, CA>,
>;

/// Native MASP VP
pub type MaspVp<'a, S, CA> = token::vp::MaspVp<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    ParamsPreStore<'a, S, CA>,
    GovPreStore<'a, S, CA>,
    IbcPostStore<'a, S, CA>,
    TokenKeys,
>;

/// Native ETH bridge VP
pub type EthBridgeVp<'a, S, CA> =
    eth_bridge::vp::EthBridge<'a, S, VpCache<CA>, Eval<S, CA>, TokenKeys>;

/// Native ETH bridge pool VP
pub type EthBridgePoolVp<'a, S, CA> =
    eth_bridge::vp::BridgePool<'a, S, VpCache<CA>, Eval<S, CA>, TokenKeys>;

/// Native ETH bridge NUT VP
pub type EthBridgeNutVp<'a, S, CA> =
    eth_bridge::vp::NonUsableTokens<'a, S, VpCache<CA>, Eval<S, CA>, TokenKeys>;

/// Governance store implementation over the native prior context
pub type GovPreStore<'a, S, CA> =
    governance::Store<CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// Parameters store implementation over the native prior context
pub type ParamsPreStore<'a, S, CA> =
    parameters::Store<CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// PoS store implementation over the native prior context
pub type PosPreStore<'a, S, CA> = proof_of_stake::Store<
    CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>,
>;

/// Ibc store implementation over the native posterior context
pub type IbcPostStore<'a, S, CA> =
    ibc::Store<CtxPostStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// Token store impl over IBC pseudo-execution storage
pub type TokenStoreForIbcExec<'a, S, CA> = token::Store<
    ibc::vp::context::PseudoExecutionStorage<
        'a,
        'a,
        S,
        VpCache<CA>,
        Eval<S, CA>,
    >,
>;

/// Token storage keys implementation
pub type TokenKeys = token::Store<()>;

/// Parameters storage keys implementation
pub type ParamKeys = parameters::Store<()>;
