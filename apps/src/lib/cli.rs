//! The CLI commands that are re-used between the executables `namada`,
//! `namada-node` and `namada-client`.
//!
//! The `namada` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `namada node ...` or `namada client ...`,
//! respectively.

pub mod api;
pub mod client;
pub mod context;
pub mod relayer;
mod utils;
pub mod wallet;

use clap::{ArgGroup, ArgMatches, ColorChoice};
use color_eyre::eyre::Result;
use namada::types::io::StdIo;
use utils::*;
pub use utils::{safe_exit, Cmd};

pub use self::context::Context;
use crate::cli::api::CliIo;

include!("../../version.rs");

const APP_NAME: &str = "Namada";

// Main Namada sub-commands
const NODE_CMD: &str = "node";
const CLIENT_CMD: &str = "client";
const WALLET_CMD: &str = "wallet";
const RELAYER_CMD: &str = "relayer";

pub mod cmds {

    use super::utils::*;
    use super::{
        args, ArgMatches, CLIENT_CMD, NODE_CMD, RELAYER_CMD, WALLET_CMD,
    };

    /// Commands for `namada` binary.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    pub enum Namada {
        // Sub-binary-commands
        Node(NamadaNode),
        Relayer(NamadaRelayer),
        Client(NamadaClient),
        Wallet(NamadaWallet),

        // Inlined commands from the node.
        Ledger(Ledger),

        // Inlined commands from the relayer.
        EthBridgePool(EthBridgePool),

        // Inlined commands from the client.
        TxCustom(TxCustom),
        TxTransfer(TxTransfer),
        TxIbcTransfer(TxIbcTransfer),
        TxUpdateAccount(TxUpdateAccount),
        TxInitProposal(TxInitProposal),
        TxVoteProposal(TxVoteProposal),
        TxRevealPk(TxRevealPk),
    }

    impl Cmd for Namada {
        fn add_sub(app: App) -> App {
            app.subcommand(NamadaNode::def())
                .subcommand(NamadaRelayer::def())
                .subcommand(NamadaClient::def())
                .subcommand(NamadaWallet::def())
                .subcommand(EthBridgePool::def())
                .subcommand(Ledger::def())
                .subcommand(TxCustom::def())
                .subcommand(TxTransfer::def())
                .subcommand(TxIbcTransfer::def())
                .subcommand(TxUpdateAccount::def())
                .subcommand(TxInitProposal::def())
                .subcommand(TxVoteProposal::def())
                .subcommand(TxRevealPk::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let node = SubCmd::parse(matches).map(Self::Node);
            let client = SubCmd::parse(matches).map(Self::Client);
            let relayer = SubCmd::parse(matches).map(Self::Relayer);
            let eth_bridge_pool =
                SubCmd::parse(matches).map(Self::EthBridgePool);
            let wallet = SubCmd::parse(matches).map(Self::Wallet);
            let ledger = SubCmd::parse(matches).map(Self::Ledger);
            let tx_custom = SubCmd::parse(matches).map(Self::TxCustom);
            let tx_transfer = SubCmd::parse(matches).map(Self::TxTransfer);
            let tx_ibc_transfer =
                SubCmd::parse(matches).map(Self::TxIbcTransfer);
            let tx_update_account =
                SubCmd::parse(matches).map(Self::TxUpdateAccount);
            let tx_init_proposal =
                SubCmd::parse(matches).map(Self::TxInitProposal);
            let tx_vote_proposal =
                SubCmd::parse(matches).map(Self::TxVoteProposal);
            let tx_reveal_pk = SubCmd::parse(matches).map(Self::TxRevealPk);
            node.or(client)
                .or(relayer)
                .or(eth_bridge_pool)
                .or(wallet)
                .or(ledger)
                .or(tx_custom)
                .or(tx_transfer)
                .or(tx_ibc_transfer)
                .or(tx_update_account)
                .or(tx_init_proposal)
                .or(tx_vote_proposal)
                .or(tx_reveal_pk)
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadan` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaNode {
        Ledger(Ledger),
        Config(Config),
    }

    impl Cmd for NamadaNode {
        fn add_sub(app: App) -> App {
            app.subcommand(Ledger::def()).subcommand(Config::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let ledger = SubCmd::parse(matches).map(Self::Ledger);
            let config = SubCmd::parse(matches).map(Self::Config);
            ledger.or(config)
        }
    }
    impl SubCmd for NamadaNode {
        const CMD: &'static str = NODE_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about("Node sub-commands.")
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadar` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaRelayer {
        EthBridgePool(EthBridgePool),
        ValidatorSet(ValidatorSet),
    }

    impl Cmd for NamadaRelayer {
        fn add_sub(app: App) -> App {
            app.subcommand(EthBridgePool::def())
                .subcommand(ValidatorSet::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let eth_bridge_pool =
                SubCmd::parse(matches).map(Self::EthBridgePool);
            let validator_set = SubCmd::parse(matches).map(Self::ValidatorSet);
            eth_bridge_pool.or(validator_set)
        }
    }

    impl SubCmd for NamadaRelayer {
        const CMD: &'static str = RELAYER_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about("Relayer sub-commands.")
                    .subcommand_required(true),
            )
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadac` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaClient {
        /// The [`super::Context`] provides access to the wallet and the
        /// config. It will generate a new wallet and config, if they
        /// don't exist.
        WithContext(NamadaClientWithContext),
        /// Utils don't have [`super::Context`], only the global arguments.
        WithoutContext(Utils),
    }

    impl Cmd for NamadaClient {
        fn add_sub(app: App) -> App {
            app
                // Simple transactions
                .subcommand(TxCustom::def().display_order(1))
                .subcommand(TxTransfer::def().display_order(1))
                .subcommand(TxIbcTransfer::def().display_order(1))
                .subcommand(TxUpdateAccount::def().display_order(1))
                .subcommand(TxInitAccount::def().display_order(1))
                .subcommand(TxRevealPk::def().display_order(1))
                // Governance transactions
                .subcommand(TxInitProposal::def().display_order(1))
                .subcommand(TxVoteProposal::def().display_order(1))
                // PoS transactions
                .subcommand(TxBecomeValidator::def().display_order(2))
                .subcommand(TxInitValidator::def().display_order(2))
                .subcommand(TxUnjailValidator::def().display_order(2))
                .subcommand(TxDeactivateValidator::def().display_order(2))
                .subcommand(TxReactivateValidator::def().display_order(2))
                .subcommand(Bond::def().display_order(2))
                .subcommand(Unbond::def().display_order(2))
                .subcommand(Withdraw::def().display_order(2))
                .subcommand(Redelegate::def().display_order(2))
                .subcommand(ClaimRewards::def().display_order(2))
                .subcommand(TxCommissionRateChange::def().display_order(2))
                .subcommand(TxChangeConsensusKey::def().display_order(2))
                .subcommand(TxMetadataChange::def().display_order(2))
                // Ethereum bridge transactions
                .subcommand(AddToEthBridgePool::def().display_order(3))
                // PGF transactions
                .subcommand(TxUpdateStewardCommission::def().display_order(4))
                .subcommand(TxResignSteward::def().display_order(4))
                // Queries
                .subcommand(QueryEpoch::def().display_order(5))
                .subcommand(QueryAccount::def().display_order(5))
                .subcommand(QueryTransfers::def().display_order(5))
                .subcommand(QueryConversions::def().display_order(5))
                .subcommand(QueryMaspRewardTokens::def().display_order(5))
                .subcommand(QueryBlock::def().display_order(5))
                .subcommand(QueryBalance::def().display_order(5))
                .subcommand(QueryBonds::def().display_order(5))
                .subcommand(QueryBondedStake::def().display_order(5))
                .subcommand(QuerySlashes::def().display_order(5))
                .subcommand(QueryDelegations::def().display_order(5))
                .subcommand(QueryFindValidator::def().display_order(5))
                .subcommand(QueryResult::def().display_order(5))
                .subcommand(QueryRawBytes::def().display_order(5))
                .subcommand(QueryProposal::def().display_order(5))
                .subcommand(QueryProposalResult::def().display_order(5))
                .subcommand(QueryProtocolParameters::def().display_order(5))
                .subcommand(QueryPgf::def().display_order(5))
                .subcommand(QueryValidatorState::def().display_order(5))
                .subcommand(QueryCommissionRate::def().display_order(5))
                .subcommand(QueryRewards::def().display_order(5))
                .subcommand(QueryMetaData::def().display_order(5))
                // Actions
                .subcommand(SignTx::def().display_order(6))
                .subcommand(GenIbcShieldedTransafer::def().display_order(6))
                // Utils
                .subcommand(Utils::def().display_order(7))
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            use NamadaClientWithContext::*;
            let tx_custom = Self::parse_with_ctx(matches, TxCustom);
            let tx_transfer = Self::parse_with_ctx(matches, TxTransfer);
            let tx_ibc_transfer = Self::parse_with_ctx(matches, TxIbcTransfer);
            let tx_update_account =
                Self::parse_with_ctx(matches, TxUpdateAccount);
            let tx_init_account = Self::parse_with_ctx(matches, TxInitAccount);
            let tx_become_validator =
                Self::parse_with_ctx(matches, TxBecomeValidator);
            let tx_init_validator =
                Self::parse_with_ctx(matches, TxInitValidator);
            let tx_unjail_validator =
                Self::parse_with_ctx(matches, TxUnjailValidator);
            let tx_deactivate_validator =
                Self::parse_with_ctx(matches, TxDeactivateValidator);
            let tx_reactivate_validator =
                Self::parse_with_ctx(matches, TxReactivateValidator);
            let tx_reveal_pk = Self::parse_with_ctx(matches, TxRevealPk);
            let tx_init_proposal =
                Self::parse_with_ctx(matches, TxInitProposal);
            let tx_vote_proposal =
                Self::parse_with_ctx(matches, TxVoteProposal);
            let tx_update_steward_commission =
                Self::parse_with_ctx(matches, TxUpdateStewardCommission);
            let tx_resign_steward =
                Self::parse_with_ctx(matches, TxResignSteward);
            let tx_commission_rate_change =
                Self::parse_with_ctx(matches, TxCommissionRateChange);
            let tx_change_consensus_key =
                Self::parse_with_ctx(matches, TxChangeConsensusKey);
            let tx_change_metadata =
                Self::parse_with_ctx(matches, TxMetadataChange);
            let bond = Self::parse_with_ctx(matches, Bond);
            let unbond = Self::parse_with_ctx(matches, Unbond);
            let withdraw = Self::parse_with_ctx(matches, Withdraw);
            let redelegate = Self::parse_with_ctx(matches, Redelegate);
            let claim_rewards = Self::parse_with_ctx(matches, ClaimRewards);
            let query_epoch = Self::parse_with_ctx(matches, QueryEpoch);
            let query_account = Self::parse_with_ctx(matches, QueryAccount);
            let query_transfers = Self::parse_with_ctx(matches, QueryTransfers);
            let query_conversions =
                Self::parse_with_ctx(matches, QueryConversions);
            let query_masp_reward_tokens =
                Self::parse_with_ctx(matches, QueryMaspRewardTokens);
            let query_block = Self::parse_with_ctx(matches, QueryBlock);
            let query_balance = Self::parse_with_ctx(matches, QueryBalance);
            let query_bonds = Self::parse_with_ctx(matches, QueryBonds);
            let query_bonded_stake =
                Self::parse_with_ctx(matches, QueryBondedStake);
            let query_slashes = Self::parse_with_ctx(matches, QuerySlashes);
            let query_rewards = Self::parse_with_ctx(matches, QueryRewards);
            let query_delegations =
                Self::parse_with_ctx(matches, QueryDelegations);
            let query_find_validator =
                Self::parse_with_ctx(matches, QueryFindValidator);
            let query_result = Self::parse_with_ctx(matches, QueryResult);
            let query_raw_bytes = Self::parse_with_ctx(matches, QueryRawBytes);
            let query_proposal = Self::parse_with_ctx(matches, QueryProposal);
            let query_proposal_result =
                Self::parse_with_ctx(matches, QueryProposalResult);
            let query_protocol_parameters =
                Self::parse_with_ctx(matches, QueryProtocolParameters);
            let query_pgf = Self::parse_with_ctx(matches, QueryPgf);
            let query_validator_state =
                Self::parse_with_ctx(matches, QueryValidatorState);
            let query_commission =
                Self::parse_with_ctx(matches, QueryCommissionRate);
            let query_metadata = Self::parse_with_ctx(matches, QueryMetaData);
            let add_to_eth_bridge_pool =
                Self::parse_with_ctx(matches, AddToEthBridgePool);
            let sign_tx = Self::parse_with_ctx(matches, SignTx);
            let gen_ibc_shielded =
                Self::parse_with_ctx(matches, GenIbcShieldedTransafer);
            let utils = SubCmd::parse(matches).map(Self::WithoutContext);
            tx_custom
                .or(tx_transfer)
                .or(tx_ibc_transfer)
                .or(tx_update_account)
                .or(tx_init_account)
                .or(tx_reveal_pk)
                .or(tx_init_proposal)
                .or(tx_vote_proposal)
                .or(tx_become_validator)
                .or(tx_init_validator)
                .or(tx_commission_rate_change)
                .or(tx_change_consensus_key)
                .or(tx_change_metadata)
                .or(tx_unjail_validator)
                .or(tx_deactivate_validator)
                .or(tx_reactivate_validator)
                .or(bond)
                .or(unbond)
                .or(withdraw)
                .or(redelegate)
                .or(claim_rewards)
                .or(add_to_eth_bridge_pool)
                .or(tx_update_steward_commission)
                .or(tx_resign_steward)
                .or(query_epoch)
                .or(query_transfers)
                .or(query_conversions)
                .or(query_masp_reward_tokens)
                .or(query_block)
                .or(query_balance)
                .or(query_bonds)
                .or(query_bonded_stake)
                .or(query_slashes)
                .or(query_rewards)
                .or(query_delegations)
                .or(query_find_validator)
                .or(query_result)
                .or(query_raw_bytes)
                .or(query_proposal)
                .or(query_proposal_result)
                .or(query_protocol_parameters)
                .or(query_pgf)
                .or(query_validator_state)
                .or(query_commission)
                .or(query_metadata)
                .or(query_account)
                .or(sign_tx)
                .or(gen_ibc_shielded)
                .or(utils)
        }
    }

    impl NamadaClient {
        /// A helper method to parse sub cmds with context
        fn parse_with_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> NamadaClientWithContext,
        ) -> Option<Self> {
            SubCmd::parse(matches)
                .map(|sub| Self::WithContext(sub_to_self(sub)))
        }
    }

    impl SubCmd for NamadaClient {
        const CMD: &'static str = CLIENT_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about("Client sub-commands.")
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub enum NamadaClientWithContext {
        // Ledger cmds
        TxCustom(TxCustom),
        TxTransfer(TxTransfer),
        TxIbcTransfer(TxIbcTransfer),
        QueryResult(QueryResult),
        TxUpdateAccount(TxUpdateAccount),
        TxInitAccount(TxInitAccount),
        TxBecomeValidator(TxBecomeValidator),
        TxInitValidator(TxInitValidator),
        TxCommissionRateChange(TxCommissionRateChange),
        TxChangeConsensusKey(TxChangeConsensusKey),
        TxMetadataChange(TxMetadataChange),
        TxUnjailValidator(TxUnjailValidator),
        TxDeactivateValidator(TxDeactivateValidator),
        TxReactivateValidator(TxReactivateValidator),
        TxInitProposal(TxInitProposal),
        TxVoteProposal(TxVoteProposal),
        TxRevealPk(TxRevealPk),
        Bond(Bond),
        Unbond(Unbond),
        Withdraw(Withdraw),
        ClaimRewards(ClaimRewards),
        Redelegate(Redelegate),
        AddToEthBridgePool(AddToEthBridgePool),
        TxUpdateStewardCommission(TxUpdateStewardCommission),
        TxResignSteward(TxResignSteward),
        QueryEpoch(QueryEpoch),
        QueryAccount(QueryAccount),
        QueryTransfers(QueryTransfers),
        QueryConversions(QueryConversions),
        QueryMaspRewardTokens(QueryMaspRewardTokens),
        QueryBlock(QueryBlock),
        QueryBalance(QueryBalance),
        QueryBonds(QueryBonds),
        QueryBondedStake(QueryBondedStake),
        QueryCommissionRate(QueryCommissionRate),
        QueryMetaData(QueryMetaData),
        QuerySlashes(QuerySlashes),
        QueryDelegations(QueryDelegations),
        QueryFindValidator(QueryFindValidator),
        QueryRawBytes(QueryRawBytes),
        QueryProposal(QueryProposal),
        QueryProposalResult(QueryProposalResult),
        QueryProtocolParameters(QueryProtocolParameters),
        QueryPgf(QueryPgf),
        QueryValidatorState(QueryValidatorState),
        QueryRewards(QueryRewards),
        SignTx(SignTx),
        GenIbcShieldedTransafer(GenIbcShieldedTransafer),
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    pub enum NamadaWallet {
        /// Key generation
        KeyGen(WalletGen),
        /// Key derivation
        KeyDerive(WalletDerive),
        /// Payment address generation
        PayAddrGen(WalletGenPaymentAddress),
        /// Key / address list
        KeyAddrList(WalletListKeysAddresses),
        /// Key / address search
        KeyAddrFind(WalletFindKeysAddresses),
        /// Key export
        KeyExport(WalletExportKey),
        /// Key import
        KeyImport(WalletImportKey),
        /// Key / address add
        KeyAddrAdd(WalletAddKeyAddress),
        /// Key / address remove
        KeyAddrRemove(WalletRemoveKeyAddress),
    }

    impl Cmd for NamadaWallet {
        fn add_sub(app: App) -> App {
            app.subcommand(WalletGen::def())
                .subcommand(WalletDerive::def())
                .subcommand(WalletGenPaymentAddress::def())
                .subcommand(WalletListKeysAddresses::def())
                .subcommand(WalletFindKeysAddresses::def())
                .subcommand(WalletExportKey::def())
                .subcommand(WalletImportKey::def())
                .subcommand(WalletAddKeyAddress::def())
                .subcommand(WalletRemoveKeyAddress::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let gen = SubCmd::parse(matches).map(Self::KeyGen);
            let derive = SubCmd::parse(matches).map(Self::KeyDerive);
            let pay_addr_gen = SubCmd::parse(matches).map(Self::PayAddrGen);
            let key_addr_list = SubCmd::parse(matches).map(Self::KeyAddrList);
            let key_addr_find = SubCmd::parse(matches).map(Self::KeyAddrFind);
            let export = SubCmd::parse(matches).map(Self::KeyExport);
            let import = SubCmd::parse(matches).map(Self::KeyImport);
            let key_addr_add = SubCmd::parse(matches).map(Self::KeyAddrAdd);
            let key_addr_remove =
                SubCmd::parse(matches).map(Self::KeyAddrRemove);
            gen.or(derive)
                .or(pay_addr_gen)
                .or(key_addr_list)
                .or(key_addr_find)
                .or(export)
                .or(import)
                .or(key_addr_add)
                .or(key_addr_remove)
        }
    }

    impl SubCmd for NamadaWallet {
        const CMD: &'static str = WALLET_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about("Wallet sub-commands.")
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    /// In the transparent setting, generate a new keypair and an implicit
    /// address derived from it. In the shielded setting, generate a new
    /// spending key.
    #[derive(Clone, Debug)]
    pub struct WalletGen(pub args::KeyGen);

    impl SubCmd for WalletGen {
        const CMD: &'static str = "gen";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyGen::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Generates a new transparent / shielded secret key.")
                .long_about(
                    "In the transparent setting, generates a keypair with a \
                     given alias and derives the implicit address from its \
                     public key. The address will be stored with the same \
                     alias.\nIn the shielded setting, generates a new \
                     spending key with a given alias.\nIn both settings, by \
                     default, an HD-key with a default derivation path is \
                     generated, with a random mnemonic code.",
                )
                .add_args::<args::KeyGen>()
        }
    }

    /// In the transparent setting, derive a keypair and implicit address from
    /// the mnemonic code.
    /// In the shielded setting, derive a spending key from the mnemonic code.
    #[derive(Clone, Debug)]
    pub struct WalletDerive(pub args::KeyDerive);

    impl SubCmd for WalletDerive {
        const CMD: &'static str = "derive";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyDerive::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Derive transparent / shielded key from the mnemonic code \
                     or a seed stored on the hardware wallet device.",
                )
                .long_about(
                    "In the transparent setting, derives a keypair from the \
                     given mnemonic code and HD derivation path and derives \
                     the implicit address from its public key. Stores the \
                     keypair and the address with the given alias.\nIn the \
                     shielded setting, derives a spending key.\nA hardware \
                     wallet can be used, in which case the private key is not \
                     derivable.",
                )
                .add_args::<args::KeyDerive>()
        }
    }

    /// List known keys and addresses
    #[derive(Clone, Debug)]
    pub struct WalletListKeysAddresses(pub args::KeyAddressList);

    impl SubCmd for WalletListKeysAddresses {
        const CMD: &'static str = "list";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyAddressList::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("List known keys and addresses in the wallet.")
                .long_about(
                    "In the transparent setting, list known keypairs and \
                     addresses.\nIn the shielded setting, list known spending \
                     / viewing keys and payment addresses.",
                )
                .add_args::<args::KeyAddressList>()
        }
    }

    /// Find known keys and addresses
    #[derive(Clone, Debug)]
    pub struct WalletFindKeysAddresses(pub args::KeyAddressFind);

    impl SubCmd for WalletFindKeysAddresses {
        const CMD: &'static str = "find";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyAddressFind::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Find known keys and addresses in the wallet.")
                .long_about(
                    "In the transparent setting, searches for a keypair / \
                     address by a given alias, public key, or a public key \
                     hash. Looks up an alias of the given address.\nIn the \
                     shielded setting, searches for a spending / viewing key \
                     and payment address by a given alias. Looks up an alias \
                     of the given payment address.",
                )
                .add_args::<args::KeyAddressFind>()
        }
    }

    /// Export key to a file
    #[derive(Clone, Debug)]
    pub struct WalletExportKey(pub args::KeyExport);

    impl SubCmd for WalletExportKey {
        const CMD: &'static str = "export";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyExport::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Exports a transparent keypair / shielded spending key to \
                     a file.",
                )
                .add_args::<args::KeyExport>()
        }
    }

    /// Import key from a file
    #[derive(Clone, Debug)]
    pub struct WalletImportKey(pub args::KeyImport);

    impl SubCmd for WalletImportKey {
        const CMD: &'static str = "import";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyImport::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Imports a transparent keypair / shielded spending key \
                     from a file.",
                )
                .add_args::<args::KeyImport>()
        }
    }

    /// Add public / payment address to the wallet
    #[derive(Clone, Debug)]
    pub struct WalletAddKeyAddress(pub args::KeyAddressAdd);

    impl SubCmd for WalletAddKeyAddress {
        const CMD: &'static str = "add";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyAddressAdd::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Adds the given key or address to the wallet.")
                .add_args::<args::KeyAddressAdd>()
        }
    }

    /// Remove key / address
    #[derive(Clone, Debug)]
    pub struct WalletRemoveKeyAddress(pub args::KeyAddressRemove);

    impl SubCmd for WalletRemoveKeyAddress {
        const CMD: &'static str = "remove";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyAddressRemove::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Remove the given alias and all associated keys / \
                     addresses from the wallet.",
                )
                .add_args::<args::KeyAddressRemove>()
        }
    }

    /// Generate a payment address from a viewing key or payment address
    #[derive(Clone, Debug)]
    pub struct WalletGenPaymentAddress(pub args::PayAddressGen<args::CliTypes>);

    impl SubCmd for WalletGenPaymentAddress {
        const CMD: &'static str = "gen-payment-addr";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::PayAddressGen::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Generates a payment address from the given spending key.",
                )
                .add_args::<args::PayAddressGen<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub enum Ledger {
        Run(LedgerRun),
        RunUntil(LedgerRunUntil),
        Reset(LedgerReset),
        DumpDb(LedgerDumpDb),
        RollBack(LedgerRollBack),
    }

    impl SubCmd for Ledger {
        const CMD: &'static str = "ledger";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let run = SubCmd::parse(matches).map(Self::Run);
                let reset = SubCmd::parse(matches).map(Self::Reset);
                let dump_db = SubCmd::parse(matches).map(Self::DumpDb);
                let rollback = SubCmd::parse(matches).map(Self::RollBack);
                let run_until = SubCmd::parse(matches).map(Self::RunUntil);
                run.or(reset)
                    .or(dump_db)
                    .or(rollback)
                    .or(run_until)
                    // The `run` command is the default if no sub-command given
                    .or(Some(Self::Run(LedgerRun(args::LedgerRun {
                        start_time: None,
                    }))))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Ledger node sub-commands. If no sub-command specified, \
                     defaults to run the node.",
                )
                .subcommand(LedgerRun::def())
                .subcommand(LedgerRunUntil::def())
                .subcommand(LedgerReset::def())
                .subcommand(LedgerDumpDb::def())
                .subcommand(LedgerRollBack::def())
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRun(pub args::LedgerRun);

    impl SubCmd for LedgerRun {
        const CMD: &'static str = "run";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerRun::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Run Namada ledger node.")
                .add_args::<args::LedgerRun>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRunUntil(pub args::LedgerRunUntil);

    impl SubCmd for LedgerRunUntil {
        const CMD: &'static str = "run-until";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerRunUntil::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Run Namada ledger node until a given height. Then halt \
                     or suspend.",
                )
                .add_args::<args::LedgerRunUntil>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerReset;

    impl SubCmd for LedgerReset {
        const CMD: &'static str = "reset";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|_matches| Self)
        }

        fn def() -> App {
            App::new(Self::CMD).about(
                "Delete Namada ledger node's and Tendermint node's storage \
                 data.",
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerDumpDb(pub args::LedgerDumpDb);

    impl SubCmd for LedgerDumpDb {
        const CMD: &'static str = "dump-db";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerDumpDb::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Dump Namada ledger node's DB from a block into a file.")
                .add_args::<args::LedgerDumpDb>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRollBack;

    impl SubCmd for LedgerRollBack {
        const CMD: &'static str = "rollback";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|_matches| Self)
        }

        fn def() -> App {
            App::new(Self::CMD).about(
                "Roll Namada state back to the previous height. This command \
                 does not create a backup of neither the Namada nor the \
                 Tendermint state before execution: for extra safety, it is \
                 recommended to make a backup in advance.",
            )
        }
    }

    #[derive(Clone, Debug)]
    pub enum Config {
        Gen(ConfigGen),
        UpdateLocalConfig(LocalConfig),
    }

    impl SubCmd for Config {
        const CMD: &'static str = "config";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let gen = SubCmd::parse(matches).map(Self::Gen);
                let gas_tokens =
                    SubCmd::parse(matches).map(Self::UpdateLocalConfig);
                gen.or(gas_tokens)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .subcommand_required(true)
                .arg_required_else_help(true)
                .about("Configuration sub-commands.")
                .subcommand(ConfigGen::def())
                .subcommand(LocalConfig::def())
        }
    }

    #[derive(Clone, Debug)]
    pub struct ConfigGen;

    impl SubCmd for ConfigGen {
        const CMD: &'static str = "gen";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|_matches| Self)
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Generate the default configuration file.")
        }
    }

    #[derive(Clone, Debug)]
    pub struct LocalConfig(pub args::UpdateLocalConfig);

    impl SubCmd for LocalConfig {
        const CMD: &'static str = "update-local-config";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::UpdateLocalConfig::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Update the validator's local configuration.")
                .add_args::<args::UpdateLocalConfig>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryResult(pub args::QueryResult<args::CliTypes>);

    impl SubCmd for QueryResult {
        const CMD: &'static str = "tx-result";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryResult(args::QueryResult::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the result of a transaction.")
                .add_args::<args::QueryResult<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposal(pub args::QueryProposal<args::CliTypes>);

    impl SubCmd for QueryProposal {
        const CMD: &'static str = "query-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProposal(args::QueryProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query proposals.")
                .add_args::<args::QueryProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposalResult(
        pub args::QueryProposalResult<args::CliTypes>,
    );

    impl SubCmd for QueryProposalResult {
        const CMD: &'static str = "query-proposal-result";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProposalResult(args::QueryProposalResult::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query proposals result.")
                .add_args::<args::QueryProposalResult<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProtocolParameters(
        pub args::QueryProtocolParameters<args::CliTypes>,
    );

    impl SubCmd for QueryProtocolParameters {
        const CMD: &'static str = "query-protocol-parameters";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProtocolParameters(args::QueryProtocolParameters::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query protocol parameters.")
                .add_args::<args::QueryProtocolParameters<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryPgf(pub args::QueryPgf<args::CliTypes>);

    impl SubCmd for QueryPgf {
        const CMD: &'static str = "query-pgf";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryPgf(args::QueryPgf::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query pgf stewards and continuous funding.")
                .add_args::<args::QueryPgf<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxCustom(pub args::TxCustom<args::CliTypes>);

    impl SubCmd for TxCustom {
        const CMD: &'static str = "tx";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| TxCustom(args::TxCustom::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Send a transaction with custom WASM code.")
                .add_args::<args::TxCustom<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxTransfer(pub args::TxTransfer<crate::cli::args::CliTypes>);

    impl SubCmd for TxTransfer {
        const CMD: &'static str = "transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| TxTransfer(args::TxTransfer::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Send a signed transfer transaction.")
                .add_args::<args::TxTransfer<crate::cli::args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxIbcTransfer(pub args::TxIbcTransfer<args::CliTypes>);

    impl SubCmd for TxIbcTransfer {
        const CMD: &'static str = "ibc-transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxIbcTransfer(args::TxIbcTransfer::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Send a signed IBC transfer transaction.")
                .add_args::<args::TxIbcTransfer<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUpdateAccount(pub args::TxUpdateAccount<args::CliTypes>);

    impl SubCmd for TxUpdateAccount {
        const CMD: &'static str = "update-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUpdateAccount(args::TxUpdateAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Send a signed transaction to update account's validity \
                     predicate.",
                )
                .add_args::<args::TxUpdateAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitAccount(pub args::TxInitAccount<args::CliTypes>);

    impl SubCmd for TxInitAccount {
        const CMD: &'static str = "init-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitAccount(args::TxInitAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Send a signed transaction to create a new established \
                     account.",
                )
                .add_args::<args::TxInitAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxBecomeValidator(pub args::TxBecomeValidator<args::CliTypes>);

    impl SubCmd for TxBecomeValidator {
        const CMD: &'static str = "become-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxBecomeValidator(args::TxBecomeValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Send a signed transaction to become a validator.")
                .add_args::<args::TxBecomeValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitValidator(pub args::TxInitValidator<args::CliTypes>);

    impl SubCmd for TxInitValidator {
        const CMD: &'static str = "init-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitValidator(args::TxInitValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Send a signed transaction to create an established \
                     account and then become a validator.",
                )
                .add_args::<args::TxInitValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUnjailValidator(pub args::TxUnjailValidator<args::CliTypes>);

    impl SubCmd for TxUnjailValidator {
        const CMD: &'static str = "unjail-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUnjailValidator(args::TxUnjailValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Send a signed transaction to unjail a jailed validator.",
                )
                .add_args::<args::TxUnjailValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxDeactivateValidator(
        pub args::TxDeactivateValidator<args::CliTypes>,
    );

    impl SubCmd for TxDeactivateValidator {
        const CMD: &'static str = "deactivate-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxDeactivateValidator(args::TxDeactivateValidator::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Send a signed transaction to deactivate a validator.")
                .add_args::<args::TxDeactivateValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxReactivateValidator(
        pub args::TxReactivateValidator<args::CliTypes>,
    );

    impl SubCmd for TxReactivateValidator {
        const CMD: &'static str = "reactivate-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxReactivateValidator(args::TxReactivateValidator::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Send a signed transaction to reactivate an inactive \
                     validator.",
                )
                .add_args::<args::TxReactivateValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Bond(pub args::Bond<args::CliTypes>);

    impl SubCmd for Bond {
        const CMD: &'static str = "bond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Bond(args::Bond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Bond tokens in PoS system.")
                .add_args::<args::Bond<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Unbond(pub args::Unbond<args::CliTypes>);

    impl SubCmd for Unbond {
        const CMD: &'static str = "unbond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Unbond(args::Unbond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Unbond tokens from a PoS bond.")
                .add_args::<args::Unbond<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Withdraw(pub args::Withdraw<args::CliTypes>);

    impl SubCmd for Withdraw {
        const CMD: &'static str = "withdraw";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Withdraw(args::Withdraw::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Withdraw tokens from previously unbonded PoS bond.")
                .add_args::<args::Withdraw<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ClaimRewards(pub args::ClaimRewards<args::CliTypes>);

    impl SubCmd for ClaimRewards {
        const CMD: &'static str = "claim-rewards";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| ClaimRewards(args::ClaimRewards::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Claim available rewards tokens from bonds that \
                     contributed in consensus.",
                )
                .add_args::<args::ClaimRewards<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Redelegate(pub args::Redelegate<args::CliTypes>);

    impl SubCmd for Redelegate {
        const CMD: &'static str = "redelegate";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Redelegate(args::Redelegate::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Redelegate bonded tokens from one validator to another.",
                )
                .add_args::<args::Redelegate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryEpoch(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryEpoch {
        const CMD: &'static str = "epoch";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryEpoch(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the epoch of the last committed block.")
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryAccount(pub args::QueryAccount<args::CliTypes>);

    impl SubCmd for QueryAccount {
        const CMD: &'static str = "query-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryAccount(args::QueryAccount::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query the substorage space of a specific enstablished \
                     address.",
                )
                .add_args::<args::QueryAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryConversions(pub args::QueryConversions<args::CliTypes>);

    impl SubCmd for QueryConversions {
        const CMD: &'static str = "conversions";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryConversions(args::QueryConversions::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query currently applicable conversions.")
                .add_args::<args::QueryConversions<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryMaspRewardTokens(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryMaspRewardTokens {
        const CMD: &'static str = "masp-reward-tokens";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryMaspRewardTokens(args::Query::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query the tokens which can earn MASP rewards while \
                     shielded.",
                )
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBlock(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryBlock {
        const CMD: &'static str = "block";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBlock(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the last committed block.")
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBalance(pub args::QueryBalance<args::CliTypes>);

    impl SubCmd for QueryBalance {
        const CMD: &'static str = "balance";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBalance(args::QueryBalance::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query balance(s) of tokens.")
                .add_args::<args::QueryBalance<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBonds(pub args::QueryBonds<args::CliTypes>);

    impl SubCmd for QueryBonds {
        const CMD: &'static str = "bonds";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBonds(args::QueryBonds::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query PoS bond(s).")
                .add_args::<args::QueryBonds<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBondedStake(pub args::QueryBondedStake<args::CliTypes>);

    impl SubCmd for QueryBondedStake {
        const CMD: &'static str = "bonded-stake";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryBondedStake(args::QueryBondedStake::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query PoS bonded stake.")
                .add_args::<args::QueryBondedStake<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignTx(pub args::SignTx<args::CliTypes>);

    impl SubCmd for SignTx {
        const CMD: &'static str = "sign-tx";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| SignTx(args::SignTx::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query PoS bonded stake.")
                .add_args::<args::SignTx<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryValidatorState(
        pub args::QueryValidatorState<args::CliTypes>,
    );

    impl SubCmd for QueryValidatorState {
        const CMD: &'static str = "validator-state";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryValidatorState(args::QueryValidatorState::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the state of a PoS validator.")
                .add_args::<args::QueryValidatorState<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryTransfers(pub args::QueryTransfers<args::CliTypes>);

    impl SubCmd for QueryTransfers {
        const CMD: &'static str = "show-transfers";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryTransfers(args::QueryTransfers::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the accepted transfers to date.")
                .add_args::<args::QueryTransfers<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryCommissionRate(
        pub args::QueryCommissionRate<args::CliTypes>,
    );

    impl SubCmd for QueryCommissionRate {
        const CMD: &'static str = "commission-rate";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryCommissionRate(args::QueryCommissionRate::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query a validator's commission rate.")
                .add_args::<args::QueryCommissionRate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryMetaData(pub args::QueryMetaData<args::CliTypes>);

    impl SubCmd for QueryMetaData {
        const CMD: &'static str = "validator-metadata";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryMetaData(args::QueryMetaData::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query a validator's metadata.")
                .add_args::<args::QueryMetaData<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QuerySlashes(pub args::QuerySlashes<args::CliTypes>);

    impl SubCmd for QuerySlashes {
        const CMD: &'static str = "slashes";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QuerySlashes(args::QuerySlashes::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query PoS applied slashes.")
                .add_args::<args::QuerySlashes<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRewards(pub args::QueryRewards<args::CliTypes>);

    impl SubCmd for QueryRewards {
        const CMD: &'static str = "rewards";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryRewards(args::QueryRewards::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query the latest rewards available to claim for a given \
                     delegation (or self-bond).",
                )
                .add_args::<args::QueryRewards<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryDelegations(pub args::QueryDelegations<args::CliTypes>);

    impl SubCmd for QueryDelegations {
        const CMD: &'static str = "delegations";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryDelegations(args::QueryDelegations::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Find PoS delegations from the given owner address.")
                .add_args::<args::QueryDelegations<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryFindValidator(pub args::QueryFindValidator<args::CliTypes>);

    impl SubCmd for QueryFindValidator {
        const CMD: &'static str = "find-validator";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryFindValidator(args::QueryFindValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Find a PoS validator by its Tendermint address.")
                .add_args::<args::QueryFindValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRawBytes(pub args::QueryRawBytes<args::CliTypes>);

    impl SubCmd for QueryRawBytes {
        const CMD: &'static str = "query-bytes";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryRawBytes(args::QueryRawBytes::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Query the raw bytes of a given storage key")
                .add_args::<args::QueryRawBytes<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitProposal(pub args::InitProposal<args::CliTypes>);

    impl SubCmd for TxInitProposal {
        const CMD: &'static str = "init-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitProposal(args::InitProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Create a new proposal.")
                .add_args::<args::InitProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUpdateStewardCommission(
        pub args::UpdateStewardCommission<args::CliTypes>,
    );

    impl SubCmd for TxUpdateStewardCommission {
        const CMD: &'static str = "update-steward-rewards";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUpdateStewardCommission(args::UpdateStewardCommission::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Update how steward commissions are split.")
                .add_args::<args::UpdateStewardCommission<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxResignSteward(pub args::ResignSteward<args::CliTypes>);

    impl SubCmd for TxResignSteward {
        const CMD: &'static str = "resign-steward";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxResignSteward(args::ResignSteward::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Craft a transaction to resign as a steward.")
                .add_args::<args::ResignSteward<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxCommissionRateChange(
        pub args::CommissionRateChange<args::CliTypes>,
    );

    impl SubCmd for TxCommissionRateChange {
        const CMD: &'static str = "change-commission-rate";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxCommissionRateChange(args::CommissionRateChange::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Change commission rate.")
                .add_args::<args::CommissionRateChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxMetadataChange(pub args::MetaDataChange<args::CliTypes>);

    impl SubCmd for TxMetadataChange {
        const CMD: &'static str = "change-metadata";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxMetadataChange(args::MetaDataChange::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Change validator's metadata, including the commission \
                     rate if desired.",
                )
                .add_args::<args::MetaDataChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxChangeConsensusKey(
        pub args::ConsensusKeyChange<args::CliTypes>,
    );

    impl SubCmd for TxChangeConsensusKey {
        const CMD: &'static str = "change-consensus-key";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxChangeConsensusKey(args::ConsensusKeyChange::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Change consensus key.")
                .add_args::<args::ConsensusKeyChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxVoteProposal(pub args::VoteProposal<args::CliTypes>);

    impl SubCmd for TxVoteProposal {
        const CMD: &'static str = "vote-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxVoteProposal(args::VoteProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Vote a proposal.")
                .add_args::<args::VoteProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxRevealPk(pub args::RevealPk<args::CliTypes>);

    impl SubCmd for TxRevealPk {
        const CMD: &'static str = "reveal-pk";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| TxRevealPk(args::RevealPk::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Submit a tx to reveal the public key an implicit \
                     account. Typically, you don't have to do this manually \
                     and the client will detect when a tx to reveal PK is \
                     needed and submit it automatically. This will write the \
                     PK into the account's storage so that it can be used for \
                     signature verification on transactions authorized by \
                     this account.",
                )
                .add_args::<args::RevealPk<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenIbcShieldedTransafer(
        pub args::GenIbcShieldedTransafer<args::CliTypes>,
    );

    impl SubCmd for GenIbcShieldedTransafer {
        const CMD: &'static str = "ibc-gen-shielded";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                GenIbcShieldedTransafer(args::GenIbcShieldedTransafer::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Generate shielded transfer for IBC.")
                .add_args::<args::GenIbcShieldedTransafer<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct EpochSleep(pub args::Query<args::CliTypes>);

    impl SubCmd for EpochSleep {
        const CMD: &'static str = "epoch-sleep";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query for the current epoch, then sleep until the next \
                     epoch.",
                )
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub enum Utils {
        JoinNetwork(JoinNetwork),
        FetchWasms(FetchWasms),
        ValidateWasm(ValidateWasm),
        InitNetwork(InitNetwork),
        DeriveGenesisAddresses(DeriveGenesisAddresses),
        GenesisBond(GenesisBond),
        InitGenesisEstablishedAccount(InitGenesisEstablishedAccount),
        InitGenesisValidator(InitGenesisValidator),
        PkToTmAddress(PkToTmAddress),
        DefaultBaseDir(DefaultBaseDir),
        EpochSleep(EpochSleep),
        ValidateGenesisTemplates(ValidateGenesisTemplates),
        TestGenesis(TestGenesis),
        SignGenesisTxs(SignGenesisTxs),
    }

    impl SubCmd for Utils {
        const CMD: &'static str = "utils";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let join_network =
                    SubCmd::parse(matches).map(Self::JoinNetwork);
                let fetch_wasms = SubCmd::parse(matches).map(Self::FetchWasms);
                let validate_wasm =
                    SubCmd::parse(matches).map(Self::ValidateWasm);
                let init_network =
                    SubCmd::parse(matches).map(Self::InitNetwork);
                let derive_addresses =
                    SubCmd::parse(matches).map(Self::DeriveGenesisAddresses);
                let genesis_bond =
                    SubCmd::parse(matches).map(Self::GenesisBond);
                let init_established = SubCmd::parse(matches)
                    .map(Self::InitGenesisEstablishedAccount);
                let init_genesis =
                    SubCmd::parse(matches).map(Self::InitGenesisValidator);
                let pk_to_tm_address =
                    SubCmd::parse(matches).map(Self::PkToTmAddress);
                let default_base_dir =
                    SubCmd::parse(matches).map(Self::DefaultBaseDir);
                let epoch_sleep = SubCmd::parse(matches).map(Self::EpochSleep);
                let validate_genesis_templates =
                    SubCmd::parse(matches).map(Self::ValidateGenesisTemplates);
                let genesis_tx =
                    SubCmd::parse(matches).map(Self::SignGenesisTxs);
                let test_genesis =
                    SubCmd::parse(matches).map(Self::TestGenesis);
                join_network
                    .or(fetch_wasms)
                    .or(validate_wasm)
                    .or(init_network)
                    .or(derive_addresses)
                    .or(genesis_bond)
                    .or(init_established)
                    .or(init_genesis)
                    .or(pk_to_tm_address)
                    .or(default_base_dir)
                    .or(epoch_sleep)
                    .or(validate_genesis_templates)
                    .or(test_genesis)
                    .or(genesis_tx)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Utilities.")
                .subcommand(JoinNetwork::def())
                .subcommand(FetchWasms::def())
                .subcommand(ValidateWasm::def())
                .subcommand(InitNetwork::def())
                .subcommand(DeriveGenesisAddresses::def())
                .subcommand(GenesisBond::def())
                .subcommand(InitGenesisEstablishedAccount::def())
                .subcommand(InitGenesisValidator::def())
                .subcommand(PkToTmAddress::def())
                .subcommand(DefaultBaseDir::def())
                .subcommand(EpochSleep::def())
                .subcommand(ValidateGenesisTemplates::def())
                .subcommand(TestGenesis::def())
                .subcommand(SignGenesisTxs::def())
                .subcommand_required(true)
                .arg_required_else_help(true)
        }
    }

    #[derive(Clone, Debug)]
    pub struct JoinNetwork(pub args::JoinNetwork);

    impl SubCmd for JoinNetwork {
        const CMD: &'static str = "join-network";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::JoinNetwork::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Configure Namada to join an existing network.")
                .add_args::<args::JoinNetwork>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct FetchWasms(pub args::FetchWasms);

    impl SubCmd for FetchWasms {
        const CMD: &'static str = "fetch-wasms";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::FetchWasms::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Ensure pre-built wasms are present")
                .add_args::<args::FetchWasms>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateWasm(pub args::ValidateWasm);

    impl SubCmd for ValidateWasm {
        const CMD: &'static str = "validate-wasm";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::ValidateWasm::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Check that the provided wasm code is valid by the Namada \
                     standards.",
                )
                .add_args::<args::ValidateWasm>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitNetwork(pub args::InitNetwork);

    impl SubCmd for InitNetwork {
        const CMD: &'static str = "init-network";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::InitNetwork::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Initialize a new test network.")
                .add_args::<args::InitNetwork>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveGenesisAddresses(pub args::DeriveGenesisAddresses);

    impl SubCmd for DeriveGenesisAddresses {
        const CMD: &'static str = "derive-genesis-addresses";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::DeriveGenesisAddresses::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Derive account addresses from a genesis txs toml file.")
                .add_args::<args::DeriveGenesisAddresses>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisEstablishedAccount(
        pub args::InitGenesisEstablishedAccount,
    );

    impl SubCmd for InitGenesisEstablishedAccount {
        const CMD: &'static str = "init-genesis-established-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::InitGenesisEstablishedAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Initialize an established account available at genesis.",
                )
                .add_args::<args::InitGenesisEstablishedAccount>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenesisBond(pub args::GenesisBond);

    impl SubCmd for GenesisBond {
        const CMD: &'static str = "genesis-bond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::GenesisBond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Bond to a validator at pre-genesis.")
                .add_args::<args::GenesisBond>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisValidator(pub args::InitGenesisValidator);

    impl SubCmd for InitGenesisValidator {
        const CMD: &'static str = "init-genesis-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::InitGenesisValidator::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Initialize genesis validator's address, consensus key \
                     and validator account key and use it in the ledger's \
                     node. Appends validator creation and self-bond txs to a \
                     .toml file containing an established account tx.",
                )
                .add_args::<args::InitGenesisValidator>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateGenesisTemplates(pub args::ValidateGenesisTemplates);

    impl SubCmd for ValidateGenesisTemplates {
        const CMD: &'static str = "validate-genesis-templates";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::ValidateGenesisTemplates::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Validate genesis templates.")
                .add_args::<args::ValidateGenesisTemplates>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestGenesis(pub args::TestGenesis);

    impl SubCmd for TestGenesis {
        const CMD: &'static str = "test-genesis";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::TestGenesis::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Dry run genesis files and get a report on problems that \
                     may be found.",
                )
                .add_args::<args::TestGenesis>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignGenesisTxs(pub args::SignGenesisTxs);

    impl SubCmd for SignGenesisTxs {
        const CMD: &'static str = "sign-genesis-txs";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::SignGenesisTxs::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Sign genesis transaction(s).")
                .add_args::<args::SignGenesisTxs>()
        }
    }

    /// Used as sub-commands (`SubCmd` instance) in `namadar` binary.
    #[derive(Clone, Debug)]
    pub enum EthBridgePool {
        /// The [`super::Context`] provides access to the wallet and the
        /// config. It will generate a new wallet and config, if they
        /// don't exist.
        WithContext(EthBridgePoolWithCtx),
        /// Utils don't have [`super::Context`], only the global arguments.
        WithoutContext(EthBridgePoolWithoutCtx),
    }

    /// Ethereum Bridge pool commands requiring [`super::Context`].
    #[derive(Clone, Debug)]
    pub enum EthBridgePoolWithCtx {
        /// Get a recommendation on a batch of transfers
        /// to relay.
        RecommendBatch(RecommendBatch),
    }

    /// Ethereum Bridge pool commands not requiring [`super::Context`].
    #[derive(Clone, Debug)]
    pub enum EthBridgePoolWithoutCtx {
        /// Construct a proof that a set of transfers is in the pool.
        /// This can be used to relay transfers across the
        /// bridge to Ethereum.
        ConstructProof(ConstructProof),
        /// Construct and relay a Bridge pool proof to
        /// Ethereum directly.
        RelayProof(RelayProof),
        /// Query the contents of the pool.
        QueryPool(QueryEthBridgePool),
        /// Query to provable contents of the pool.
        QuerySigned(QuerySignedBridgePool),
        /// Check the confirmation status of `TransferToEthereum`
        /// events.
        QueryRelays(QueryRelayProgress),
    }

    impl Cmd for EthBridgePool {
        fn add_sub(app: App) -> App {
            app.subcommand(RecommendBatch::def().display_order(1))
                .subcommand(ConstructProof::def().display_order(1))
                .subcommand(RelayProof::def().display_order(1))
                .subcommand(QueryEthBridgePool::def().display_order(1))
                .subcommand(QuerySignedBridgePool::def().display_order(1))
                .subcommand(QueryRelayProgress::def().display_order(1))
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            use EthBridgePoolWithCtx::*;
            use EthBridgePoolWithoutCtx::*;

            let recommend = Self::parse_with_ctx(matches, RecommendBatch);
            let construct_proof =
                Self::parse_without_ctx(matches, ConstructProof);
            let relay_proof = Self::parse_without_ctx(matches, RelayProof);
            let query_pool = Self::parse_without_ctx(matches, QueryPool);
            let query_signed = Self::parse_without_ctx(matches, QuerySigned);
            let query_relays = Self::parse_without_ctx(matches, QueryRelays);

            construct_proof
                .or(recommend)
                .or(relay_proof)
                .or(query_pool)
                .or(query_signed)
                .or(query_relays)
        }
    }

    impl EthBridgePool {
        /// A helper method to parse sub cmds with context
        fn parse_with_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> EthBridgePoolWithCtx,
        ) -> Option<Self> {
            T::parse(matches).map(|sub| Self::WithContext(sub_to_self(sub)))
        }

        /// A helper method to parse sub cmds without context
        fn parse_without_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> EthBridgePoolWithoutCtx,
        ) -> Option<Self> {
            T::parse(matches).map(|sub| Self::WithoutContext(sub_to_self(sub)))
        }
    }

    impl SubCmd for EthBridgePool {
        const CMD: &'static str = "ethereum-bridge-pool";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(Cmd::parse)
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Functionality for interacting with the Ethereum bridge \
                     pool. This pool holds transfers waiting to be relayed to \
                     Ethereum.",
                )
                .subcommand_required(true)
                .subcommand(ConstructProof::def().display_order(1))
                .subcommand(RecommendBatch::def().display_order(1))
                .subcommand(RelayProof::def().display_order(1))
                .subcommand(QueryEthBridgePool::def().display_order(1))
                .subcommand(QuerySignedBridgePool::def().display_order(1))
                .subcommand(QueryRelayProgress::def().display_order(1))
        }
    }

    #[derive(Clone, Debug)]
    pub struct AddToEthBridgePool(pub args::EthereumBridgePool<args::CliTypes>);

    impl SubCmd for AddToEthBridgePool {
        const CMD: &'static str = "add-erc20-transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::EthereumBridgePool::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Add a new transfer to the Ethereum Bridge pool.")
                .arg_required_else_help(true)
                .add_args::<args::EthereumBridgePool<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ConstructProof(pub args::BridgePoolProof<args::CliTypes>);

    impl SubCmd for ConstructProof {
        const CMD: &'static str = "construct-proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::BridgePoolProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Construct a merkle proof that the given transfers are in \
                     the pool.",
                )
                .arg_required_else_help(true)
                .add_args::<args::BridgePoolProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct RelayProof(pub args::RelayBridgePoolProof<args::CliTypes>);

    impl SubCmd for RelayProof {
        const CMD: &'static str = "relay-proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::RelayBridgePoolProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Construct a merkle proof that the given transfers are in \
                     the pool and relay it to Ethereum.",
                )
                .arg_required_else_help(true)
                .add_args::<args::RelayBridgePoolProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct RecommendBatch(pub args::RecommendBatch<args::CliTypes>);

    impl SubCmd for RecommendBatch {
        const CMD: &'static str = "recommend-batch";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::RecommendBatch::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Get a recommended batch of transfers from the bridge \
                     pool to relay to Ethereum.",
                )
                .arg_required_else_help(true)
                .add_args::<args::RecommendBatch<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryEthBridgePool(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryEthBridgePool {
        const CMD: &'static str = "query";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Get the contents of the Ethereum Bridge pool.")
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QuerySignedBridgePool(pub args::Query<args::CliTypes>);

    impl SubCmd for QuerySignedBridgePool {
        const CMD: &'static str = "query-signed";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Get the contents of the Ethereum Bridge pool with a \
                     signed Merkle root.",
                )
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRelayProgress(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryRelayProgress {
        const CMD: &'static str = "query-relayed";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Get the confirmation status of transfers to Ethereum.")
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    /// Used as sub-commands (`SubCmd` instance) in `namadar` binary.
    #[derive(Clone, Debug)]
    pub enum ValidatorSet {
        /// Query the Bridge validator set in Namada, at the given epoch,
        /// or the latest one, if none is provided.
        BridgeValidatorSet(BridgeValidatorSet),
        /// Query the Governance validator set in Namada, at the given epoch,
        /// or the latest one, if none is provided.
        GovernanceValidatorSet(GovernanceValidatorSet),
        /// Query an Ethereum ABI encoding of a proof of the consensus
        /// validator set in Namada, at the given epoch, or the next
        /// one, if none is provided.
        ValidatorSetProof(ValidatorSetProof),
        /// Relay a validator set update to Namada's Ethereum bridge
        /// smart contracts.
        ValidatorSetUpdateRelay(ValidatorSetUpdateRelay),
    }

    impl SubCmd for ValidatorSet {
        const CMD: &'static str = "validator-set";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let bridge_validator_set = BridgeValidatorSet::parse(matches)
                    .map(Self::BridgeValidatorSet);
                let governance_validator_set =
                    GovernanceValidatorSet::parse(matches)
                        .map(Self::GovernanceValidatorSet);
                let validator_set_proof = ValidatorSetProof::parse(matches)
                    .map(Self::ValidatorSetProof);
                let relay = ValidatorSetUpdateRelay::parse(matches)
                    .map(Self::ValidatorSetUpdateRelay);
                bridge_validator_set
                    .or(governance_validator_set)
                    .or(validator_set_proof)
                    .or(relay)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Validator set queries, that return data in a format to \
                     be consumed by the Namada Ethereum bridge smart \
                     contracts.",
                )
                .subcommand_required(true)
                .subcommand(BridgeValidatorSet::def().display_order(1))
                .subcommand(GovernanceValidatorSet::def().display_order(1))
                .subcommand(ValidatorSetProof::def().display_order(1))
                .subcommand(ValidatorSetUpdateRelay::def().display_order(1))
        }
    }

    #[derive(Clone, Debug)]
    pub struct BridgeValidatorSet(pub args::BridgeValidatorSet<args::CliTypes>);

    impl SubCmd for BridgeValidatorSet {
        const CMD: &'static str = "bridge";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::BridgeValidatorSet::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query the Bridge validator set in Namada, at the given \
                     epoch, or the latest one, if none is provided.",
                )
                .add_args::<args::BridgeValidatorSet<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GovernanceValidatorSet(
        pub args::GovernanceValidatorSet<args::CliTypes>,
    );

    impl SubCmd for GovernanceValidatorSet {
        const CMD: &'static str = "governance";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::GovernanceValidatorSet::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query the Governance validator set in Namada, at the \
                     given epoch, or the latest one, if none is provided.",
                )
                .add_args::<args::GovernanceValidatorSet<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidatorSetProof(pub args::ValidatorSetProof<args::CliTypes>);

    impl SubCmd for ValidatorSetProof {
        const CMD: &'static str = "proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::ValidatorSetProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Query an Ethereum ABI encoding of a proof of the \
                     consensus validator set in Namada, at the requested \
                     epoch, or the next one, if no epoch is provided.",
                )
                .add_args::<args::ValidatorSetProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidatorSetUpdateRelay(
        pub args::ValidatorSetUpdateRelay<args::CliTypes>,
    );

    impl SubCmd for ValidatorSetUpdateRelay {
        const CMD: &'static str = "relay";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::ValidatorSetUpdateRelay::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Relay a validator set update to Namada's Ethereum bridge \
                     smart contracts.",
                )
                .add_args::<args::ValidatorSetUpdateRelay<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct PkToTmAddress(pub args::PkToTmAddress);

    impl SubCmd for PkToTmAddress {
        const CMD: &'static str = "pk-to-tm";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::PkToTmAddress::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Convert a validator's consensus public key to a \
                     Tendermint address.",
                )
                .add_args::<args::PkToTmAddress>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DefaultBaseDir(pub args::DefaultBaseDir);

    impl SubCmd for DefaultBaseDir {
        const CMD: &'static str = "default-base-dir";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::DefaultBaseDir::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(
                    "Print the default base directory that would be used if \
                     --base-dir or NAMADA_BASE_DIR were not used to set the \
                     base directory.",
                )
                .add_args::<args::DefaultBaseDir>()
        }
    }
}

pub mod args {
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::env;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;

    use namada::ibc::core::host::types::identifiers::{ChannelId, PortId};
    use namada::types::address::{Address, EstablishedAddress};
    use namada::types::chain::{ChainId, ChainIdPrefix};
    use namada::types::dec::Dec;
    use namada::types::ethereum_events::EthAddress;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::*;
    use namada::types::masp::PaymentAddress;
    use namada::types::storage::{self, BlockHeight, Epoch};
    use namada::types::time::DateTimeUtc;
    use namada::types::token;
    use namada::types::token::NATIVE_MAX_DECIMAL_PLACES;
    use namada::types::transaction::GasLimit;
    pub use namada_sdk::args::*;
    pub use namada_sdk::tx::{
        TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
        TX_CHANGE_COMMISSION_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
        TX_CHANGE_METADATA_WASM, TX_CLAIM_REWARDS_WASM,
        TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
        TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM, TX_REDELEGATE_WASM,
        TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM,
        TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
        TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
        VP_USER_WASM,
    };

    use super::context::*;
    use super::utils::*;
    use super::{ArgGroup, ArgMatches};
    use crate::client::utils::PRE_GENESIS_DIR;
    use crate::config::genesis::GenesisAddress;
    use crate::config::{self, Action, ActionAtHeight};
    use crate::facade::tendermint::Timeout;
    use crate::facade::tendermint_config::net::Address as TendermintAddress;

    pub const ADDRESS: Arg<WalletAddress> = arg("address");
    pub const ALIAS_OPT: ArgOpt<String> = ALIAS.opt();
    pub const ALIAS: Arg<String> = arg("alias");
    pub const ALIAS_FORCE: ArgFlag = flag("alias-force");
    pub const ALIAS_MANY: ArgMulti<String, GlobPlus> = arg_multi("aliases");
    pub const ALLOW_DUPLICATE_IP: ArgFlag = flag("allow-duplicate-ip");
    pub const AMOUNT: Arg<token::DenominatedAmount> = arg("amount");
    pub const ARCHIVE_DIR: ArgOpt<PathBuf> = arg_opt("archive-dir");
    pub const BALANCE_OWNER: ArgOpt<WalletBalanceOwner> = arg_opt("owner");
    pub const BASE_DIR: ArgDefault<PathBuf> = arg_default(
        "base-dir",
        DefaultFn(|| match env::var("NAMADA_BASE_DIR") {
            Ok(dir) => PathBuf::from(dir),
            Err(_) => config::get_default_namada_folder(),
        }),
    );
    pub const BLOCK_HEIGHT: Arg<BlockHeight> = arg("block-height");
    pub const BLOCK_HEIGHT_OPT: ArgOpt<BlockHeight> = arg_opt("height");
    pub const BRIDGE_POOL_GAS_AMOUNT: ArgDefault<token::DenominatedAmount> =
        arg_default(
            "pool-gas-amount",
            DefaultFn(|| {
                token::DenominatedAmount::new(
                    token::Amount::zero(),
                    NATIVE_MAX_DECIMAL_PLACES.into(),
                )
            }),
        );
    pub const BRIDGE_POOL_GAS_PAYER: ArgOpt<WalletAddress> =
        arg_opt("pool-gas-payer");
    pub const BRIDGE_POOL_GAS_TOKEN: ArgDefaultFromCtx<WalletAddress> =
        arg_default_from_ctx(
            "pool-gas-token",
            DefaultFn(|| "NAM".parse().unwrap()),
        );
    pub const BRIDGE_POOL_TARGET: Arg<EthAddress> = arg("target");
    pub const BROADCAST_ONLY: ArgFlag = flag("broadcast-only");
    pub const CHAIN_ID: Arg<ChainId> = arg("chain-id");
    pub const CHAIN_ID_OPT: ArgOpt<ChainId> = CHAIN_ID.opt();
    pub const CHAIN_ID_PREFIX: Arg<ChainIdPrefix> = arg("chain-prefix");
    pub const CHANNEL_ID: Arg<ChannelId> = arg("channel-id");
    pub const CODE_PATH: Arg<PathBuf> = arg("code-path");
    pub const CODE_PATH_OPT: ArgOpt<PathBuf> = CODE_PATH.opt();
    pub const COMMISSION_RATE: Arg<Dec> = arg("commission-rate");
    pub const COMMISSION_RATE_OPT: ArgOpt<Dec> = COMMISSION_RATE.opt();
    pub const CONSENSUS_TIMEOUT_COMMIT: ArgDefault<Timeout> = arg_default(
        "consensus-timeout-commit",
        DefaultFn(|| Timeout::from_str("1s").unwrap()),
    );
    pub const CONVERSION_TABLE: Arg<PathBuf> = arg("conversion-table");
    pub const DAEMON_MODE: ArgFlag = flag("daemon");
    pub const DAEMON_MODE_RETRY_DUR: ArgOpt<Duration> = arg_opt("retry-sleep");
    pub const DAEMON_MODE_SUCCESS_DUR: ArgOpt<Duration> =
        arg_opt("success-sleep");
    pub const DATA_PATH_OPT: ArgOpt<PathBuf> = arg_opt("data-path");
    pub const DATA_PATH: Arg<PathBuf> = arg("data-path");
    pub const DECRYPT: ArgFlag = flag("decrypt");
    pub const DESCRIPTION_OPT: ArgOpt<String> = arg_opt("description");
    pub const DISPOSABLE_SIGNING_KEY: ArgFlag = flag("disposable-gas-payer");
    pub const DESTINATION_VALIDATOR: Arg<WalletAddress> =
        arg("destination-validator");
    pub const DISCORD_OPT: ArgOpt<String> = arg_opt("discord-handle");
    pub const DO_IT: ArgFlag = flag("do-it");
    pub const DONT_ARCHIVE: ArgFlag = flag("dont-archive");
    pub const DONT_PREFETCH_WASM: ArgFlag = flag("dont-prefetch-wasm");
    pub const DRY_RUN_TX: ArgFlag = flag("dry-run");
    pub const DRY_RUN_WRAPPER_TX: ArgFlag = flag("dry-run-wrapper");
    pub const DUMP_TX: ArgFlag = flag("dump-tx");
    pub const EPOCH: ArgOpt<Epoch> = arg_opt("epoch");
    pub const ERC20: Arg<EthAddress> = arg("erc20");
    pub const ETH_CONFIRMATIONS: Arg<u64> = arg("confirmations");
    pub const ETH_GAS: ArgOpt<u64> = arg_opt("eth-gas");
    pub const ETH_GAS_PRICE: ArgOpt<u64> = arg_opt("eth-gas-price");
    pub const ETH_ADDRESS: Arg<EthAddress> = arg("ethereum-address");
    pub const ETH_ADDRESS_OPT: ArgOpt<EthAddress> = ETH_ADDRESS.opt();
    pub const ETH_RPC_ENDPOINT: ArgDefault<String> = arg_default(
        "eth-rpc-endpoint",
        DefaultFn(|| "http://localhost:8545".into()),
    );
    pub const ETH_SYNC: ArgFlag = flag("sync");
    pub const EXPIRATION_OPT: ArgOpt<DateTimeUtc> = arg_opt("expiration");
    pub const EMAIL: Arg<String> = arg("email");
    pub const EMAIL_OPT: ArgOpt<String> = EMAIL.opt();
    pub const FEE_UNSHIELD_SPENDING_KEY: ArgOpt<WalletTransferSource> =
        arg_opt("gas-spending-key");
    pub const FEE_AMOUNT_OPT: ArgOpt<token::DenominatedAmount> =
        arg_opt("gas-price");
    pub const FEE_PAYER_OPT: ArgOpt<WalletPublicKey> = arg_opt("gas-payer");
    pub const FILE_PATH: Arg<String> = arg("file");
    pub const FORCE: ArgFlag = flag("force");
    pub const GAS_LIMIT: ArgDefault<GasLimit> =
        arg_default("gas-limit", DefaultFn(|| GasLimit::from(25_000)));
    pub const FEE_TOKEN: ArgDefaultFromCtx<WalletAddress> =
        arg_default_from_ctx("gas-token", DefaultFn(|| "NAM".parse().unwrap()));
    pub const FEE_PAYER: Arg<WalletAddress> = arg("fee-payer");
    pub const FEE_AMOUNT: ArgDefault<token::DenominatedAmount> = arg_default(
        "fee-amount",
        DefaultFn(|| {
            token::DenominatedAmount::new(
                token::Amount::default(),
                NATIVE_MAX_DECIMAL_PLACES.into(),
            )
        }),
    );
    pub const GENESIS_BOND_SOURCE: ArgOpt<GenesisAddress> = arg_opt("source");
    pub const GENESIS_PATH: Arg<PathBuf> = arg("genesis-path");
    pub const GENESIS_TIME: Arg<DateTimeUtc> = arg("genesis-time");
    pub const GENESIS_VALIDATOR: ArgOpt<String> =
        arg("genesis-validator").opt();
    pub const GENESIS_VALIDATOR_ADDRESS: Arg<EstablishedAddress> =
        arg("validator");
    pub const HALT_ACTION: ArgFlag = flag("halt");
    pub const HASH_LIST: Arg<String> = arg("hash-list");
    pub const HD_WALLET_DERIVATION_PATH: ArgDefault<String> =
        arg_default("hd-path", DefaultFn(|| "default".to_string()));
    pub const HISTORIC: ArgFlag = flag("historic");
    pub const IBC_TRANSFER_MEMO_PATH: ArgOpt<PathBuf> = arg_opt("memo-path");
    pub const INPUT_OPT: ArgOpt<PathBuf> = arg_opt("input");
    pub const LEDGER_ADDRESS_ABOUT: &str =
        "Address of a ledger node as \"{scheme}://{host}:{port}\". If the \
         scheme is not supplied, it is assumed to be TCP.";
    pub const LEDGER_ADDRESS_DEFAULT: ArgDefault<TendermintAddress> =
        LEDGER_ADDRESS.default(DefaultFn(|| {
            let raw = "127.0.0.1:26657";
            TendermintAddress::from_str(raw).unwrap()
        }));
    pub const LEDGER_ADDRESS: Arg<TendermintAddress> = arg("node");
    pub const LIST_FIND_ADDRESSES_ONLY: ArgFlag = flag("addr");
    pub const LIST_FIND_KEYS_ONLY: ArgFlag = flag("keys");
    pub const LOCALHOST: ArgFlag = flag("localhost");
    pub const MAX_COMMISSION_RATE_CHANGE: Arg<Dec> =
        arg("max-commission-rate-change");
    pub const MAX_ETH_GAS: ArgOpt<u64> = arg_opt("max_eth-gas");
    pub const MEMO_OPT: ArgOpt<String> = arg_opt("memo");
    pub const MODE: ArgOpt<String> = arg_opt("mode");
    pub const NET_ADDRESS: Arg<SocketAddr> = arg("net-address");
    pub const NAMADA_START_TIME: ArgOpt<DateTimeUtc> = arg_opt("time");
    pub const NO_CONVERSIONS: ArgFlag = flag("no-conversions");
    pub const NUT: ArgFlag = flag("nut");
    pub const OUT_FILE_PATH_OPT: ArgOpt<PathBuf> = arg_opt("out-file-path");
    pub const OUTPUT: ArgOpt<PathBuf> = arg_opt("output");
    pub const OUTPUT_FOLDER_PATH: ArgOpt<PathBuf> =
        arg_opt("output-folder-path");
    pub const OWNER: Arg<WalletAddress> = arg("owner");
    pub const OWNER_OPT: ArgOpt<WalletAddress> = OWNER.opt();
    pub const PATH: Arg<PathBuf> = arg("path");
    pub const PIN: ArgFlag = flag("pin");
    pub const PORT_ID: ArgDefault<PortId> = arg_default(
        "port-id",
        DefaultFn(|| PortId::from_str("transfer").unwrap()),
    );
    pub const PRE_GENESIS: ArgFlag = flag("pre-genesis");
    pub const PROPOSAL_ETH: ArgFlag = flag("eth");
    pub const PROPOSAL_PGF_STEWARD: ArgFlag = flag("pgf-stewards");
    pub const PROPOSAL_PGF_FUNDING: ArgFlag = flag("pgf-funding");
    pub const PROPOSAL_OFFLINE: ArgFlag = flag("offline");
    pub const PROTOCOL_KEY: ArgOpt<WalletPublicKey> = arg_opt("protocol-key");
    pub const PRE_GENESIS_PATH: ArgOpt<PathBuf> = arg_opt("pre-genesis-path");
    pub const PUBLIC_KEY: Arg<WalletPublicKey> = arg("public-key");
    pub const PUBLIC_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("public-keys");
    pub const PROPOSAL_ID: Arg<u64> = arg("proposal-id");
    pub const PROPOSAL_ID_OPT: ArgOpt<u64> = arg_opt("proposal-id");
    pub const PROPOSAL_VOTE_PGF_OPT: ArgOpt<String> = arg_opt("pgf");
    pub const PROPOSAL_VOTE_ETH_OPT: ArgOpt<String> = arg_opt("eth");
    pub const PROPOSAL_VOTE: Arg<String> = arg("vote");
    pub const RAW_ADDRESS: Arg<Address> = arg("address");
    pub const RAW_ADDRESS_ESTABLISHED: Arg<EstablishedAddress> = arg("address");
    pub const RAW_ADDRESS_OPT: ArgOpt<Address> = RAW_ADDRESS.opt();
    pub const RAW_KEY_GEN: ArgFlag = flag("raw");
    pub const RAW_PAYMENT_ADDRESS: Arg<PaymentAddress> = arg("payment-address");
    pub const RAW_PAYMENT_ADDRESS_OPT: ArgOpt<PaymentAddress> =
        RAW_PAYMENT_ADDRESS.opt();
    pub const RAW_PUBLIC_KEY: Arg<common::PublicKey> = arg("public-key");
    pub const RAW_PUBLIC_KEY_OPT: ArgOpt<common::PublicKey> =
        RAW_PUBLIC_KEY.opt();
    pub const RAW_PUBLIC_KEY_HASH: Arg<String> = arg("public-key-hash");
    pub const RAW_PUBLIC_KEY_HASH_OPT: ArgOpt<String> =
        RAW_PUBLIC_KEY_HASH.opt();
    pub const RECEIVER: Arg<String> = arg("receiver");
    pub const RELAYER: Arg<Address> = arg("relayer");
    pub const SAFE_MODE: ArgFlag = flag("safe-mode");
    pub const SCHEME: ArgDefault<SchemeType> =
        arg_default("scheme", DefaultFn(|| SchemeType::Ed25519));
    pub const SELF_BOND_AMOUNT: Arg<token::DenominatedAmount> =
        arg("self-bond-amount");
    pub const SENDER: Arg<String> = arg("sender");
    pub const SHIELDED: ArgFlag = flag("shielded");
    pub const SIGNER: ArgOpt<WalletAddress> = arg_opt("signer");
    pub const SIGNING_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("signing-keys");
    pub const SIGNATURES: ArgMulti<PathBuf, GlobStar> = arg_multi("signatures");
    pub const SOURCE: Arg<WalletAddress> = arg("source");
    pub const SOURCE_OPT: ArgOpt<WalletAddress> = SOURCE.opt();
    pub const STEWARD: Arg<WalletAddress> = arg("steward");
    pub const SOURCE_VALIDATOR: Arg<WalletAddress> = arg("source-validator");
    pub const STORAGE_KEY: Arg<storage::Key> = arg("storage-key");
    pub const SUSPEND_ACTION: ArgFlag = flag("suspend");
    pub const TEMPLATES_PATH: Arg<PathBuf> = arg("templates-path");
    pub const TIMEOUT_HEIGHT: ArgOpt<u64> = arg_opt("timeout-height");
    pub const TIMEOUT_SEC_OFFSET: ArgOpt<u64> = arg_opt("timeout-sec-offset");
    pub const TM_ADDRESS: Arg<String> = arg("tm-address");
    pub const TOKEN_OPT: ArgOpt<WalletAddress> = TOKEN.opt();
    pub const TOKEN: Arg<WalletAddress> = arg("token");
    pub const TOKEN_STR: Arg<String> = arg("token");
    pub const TRANSFER_SOURCE: Arg<WalletTransferSource> = arg("source");
    pub const TRANSFER_TARGET: Arg<WalletTransferTarget> = arg("target");
    pub const TRANSPARENT: ArgFlag = flag("transparent");
    pub const TX_HASH: Arg<String> = arg("tx-hash");
    pub const THRESHOLD: ArgOpt<u8> = arg_opt("threshold");
    pub const UNSAFE_DONT_ENCRYPT: ArgFlag = flag("unsafe-dont-encrypt");
    pub const UNSAFE_SHOW_SECRET: ArgFlag = flag("unsafe-show-secret");
    pub const USE_DEVICE: ArgFlag = flag("use-device");
    pub const VALIDATOR: Arg<WalletAddress> = arg("validator");
    pub const VALIDATOR_OPT: ArgOpt<WalletAddress> = VALIDATOR.opt();
    pub const VALIDATOR_ACCOUNT_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("account-key");
    pub const VALIDATOR_ACCOUNT_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("account-keys");
    pub const VALIDATOR_CONSENSUS_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("consensus-key");
    pub const VALIDATOR_CODE_PATH: ArgOpt<PathBuf> =
        arg_opt("validator-code-path");
    pub const VALIDATOR_ETH_COLD_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("eth-cold-key");
    pub const VALIDATOR_ETH_HOT_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("eth-hot-key");
    pub const VALUE: Arg<String> = arg("value");
    pub const VIEWING_KEY: Arg<WalletViewingKey> = arg("key");
    pub const VP: ArgOpt<String> = arg_opt("vp");
    pub const WALLET_ALIAS_FORCE: ArgFlag = flag("wallet-alias-force");
    pub const WASM_CHECKSUMS_PATH: Arg<PathBuf> = arg("wasm-checksums-path");
    pub const WASM_DIR: ArgOpt<PathBuf> = arg_opt("wasm-dir");
    pub const WEBSITE_OPT: ArgOpt<String> = arg_opt("website");
    pub const TX_PATH: Arg<PathBuf> = arg("tx-path");
    pub const TX_PATH_OPT: ArgOpt<PathBuf> = TX_PATH.opt();

    /// Global command arguments
    #[derive(Clone, Debug)]
    pub struct Global {
        pub is_pre_genesis: bool,
        pub chain_id: Option<ChainId>,
        pub base_dir: PathBuf,
        pub wasm_dir: Option<PathBuf>,
    }

    impl Global {
        /// Parse global arguments
        pub fn parse(matches: &ArgMatches) -> Self {
            let is_pre_genesis = PRE_GENESIS.parse(matches);
            let chain_id = CHAIN_ID_OPT.parse(matches);
            let base_dir = BASE_DIR.parse(matches);
            let wasm_dir = WASM_DIR.parse(matches);
            Global {
                is_pre_genesis,
                chain_id,
                base_dir,
                wasm_dir,
            }
        }

        /// Add global args definition. Should be added to every top-level
        /// command.
        pub fn def(app: App) -> App {
            app.arg(CHAIN_ID_OPT.def().help("The chain ID."))
                .arg(BASE_DIR.def().help(
                    "The base directory is where the nodes, client and wallet \
                     configuration and state is stored. This value can also \
                     be set via `NAMADA_BASE_DIR` environment variable, but \
                     the argument takes precedence, if specified. Defaults to \
                     `$XDG_DATA_HOME/namada` (`$HOME/.local/share/namada` \
                     where `XDG_DATA_HOME` is unset) on \
                     Unix,`$HOME/Library/Application Support/Namada` on \
                     Mac,and `%AppData%\\Namada` on Windows.",
                ))
                .arg(WASM_DIR.def().help(
                    "Directory with built WASM validity predicates, \
                     transactions. This value can also be set via \
                     `NAMADA_WASM_DIR` environment variable, but the argument \
                     takes precedence, if specified.",
                ))
                .arg(
                    PRE_GENESIS
                        .def()
                        .help("Dispatch pre-genesis specific logic."),
                )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRun {
        pub start_time: Option<DateTimeUtc>,
    }

    impl Args for LedgerRun {
        fn parse(matches: &ArgMatches) -> Self {
            let start_time = NAMADA_START_TIME.parse(matches);
            Self { start_time }
        }

        fn def(app: App) -> App {
            app.arg(NAMADA_START_TIME.def().help(
                "The start time of the ledger. Accepts a relaxed form of \
                 RFC3339. A space or a 'T' are accepted as the separator \
                 between the date and time components. Additional spaces are \
                 allowed between each component.\nAll of these examples are \
                 equivalent:\n2023-01-20T12:12:12Z\n2023-01-20 \
                 12:12:12Z\n2023-  01-20T12:  12:12Z",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRunUntil {
        pub time: Option<DateTimeUtc>,
        pub action_at_height: ActionAtHeight,
    }

    impl Args for LedgerRunUntil {
        fn parse(matches: &ArgMatches) -> Self {
            Self {
                time: NAMADA_START_TIME.parse(matches),
                action_at_height: ActionAtHeight {
                    height: BLOCK_HEIGHT.parse(matches),
                    action: if HALT_ACTION.parse(matches) {
                        Action::Halt
                    } else {
                        Action::Suspend
                    },
                },
            }
        }

        fn def(app: App) -> App {
            app.arg(
                NAMADA_START_TIME
                    .def()
                    .help("The start time of the ledger."),
            )
            .arg(BLOCK_HEIGHT.def().help("The block height to run until."))
            .arg(HALT_ACTION.def().help("Halt at the given block height"))
            .arg(
                SUSPEND_ACTION
                    .def()
                    .help("Suspend consensus at the given block height"),
            )
            .group(
                ArgGroup::new("find_flags")
                    .args([HALT_ACTION.name, SUSPEND_ACTION.name])
                    .required(true),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerDumpDb {
        // TODO: allow to specify height
        pub block_height: Option<BlockHeight>,
        pub out_file_path: PathBuf,
        pub historic: bool,
    }

    impl Args for LedgerDumpDb {
        fn parse(matches: &ArgMatches) -> Self {
            let block_height = BLOCK_HEIGHT_OPT.parse(matches);
            let out_file_path = OUT_FILE_PATH_OPT
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from("db_dump".to_string()));
            let historic = HISTORIC.parse(matches);

            Self {
                block_height,
                out_file_path,
                historic,
            }
        }

        fn def(app: App) -> App {
            app.arg(BLOCK_HEIGHT_OPT.def().help(
                "The block height to dump. Defaults to latest committed
                block.",
            ))
            .arg(OUT_FILE_PATH_OPT.def().help(
                "Path for the output file (omitting file extension). Defaults \
                 to \"db_dump.{block_height}.toml\" in the current working \
                 directory.",
            ))
            .arg(
                HISTORIC
                    .def()
                    .help("If provided, dump also the diff of the last height"),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct UpdateLocalConfig {
        pub config_path: PathBuf,
    }

    impl Args for UpdateLocalConfig {
        fn parse(matches: &ArgMatches) -> Self {
            let config_path = DATA_PATH.parse(matches);
            Self { config_path }
        }

        fn def(app: App) -> App {
            app.arg(DATA_PATH.def().help(
                "The path to the toml file containing the updated local \
                 configuration.",
            ))
        }
    }

    /// Convert CLI args to SDK args, with contextual data.
    pub trait CliToSdk<SDK>: Args {
        /// Convert CLI args to SDK args, with contextual data.
        fn to_sdk(self, ctx: &mut Context) -> SDK;
    }

    /// Convert CLI args to SDK args, without contextual data.
    pub trait CliToSdkCtxless<SDK>: Args {
        /// Convert CLI args to SDK args, without contextual data.
        fn to_sdk_ctxless(self) -> SDK;
    }

    impl<CLI, SDK> CliToSdk<SDK> for CLI
    where
        CLI: Args + CliToSdkCtxless<SDK>,
    {
        #[inline]
        fn to_sdk(self, _: &mut Context) -> SDK {
            self.to_sdk_ctxless()
        }
    }

    impl CliToSdk<QueryResult<SdkTypes>> for QueryResult<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryResult<SdkTypes> {
            QueryResult::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                tx_hash: self.tx_hash,
            }
        }
    }

    impl Args for QueryResult<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let tx_hash = TX_HASH.parse(matches);
            Self { query, tx_hash }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                TX_HASH
                    .def()
                    .help("The hash of the transaction being looked up."),
            )
        }
    }

    impl CliToSdk<EthereumBridgePool<SdkTypes>> for EthereumBridgePool<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> EthereumBridgePool<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            EthereumBridgePool::<SdkTypes> {
                nut: self.nut,
                tx,
                asset: self.asset,
                recipient: self.recipient,
                sender: chain_ctx.get(&self.sender),
                amount: self.amount,
                fee_amount: self.fee_amount,
                fee_payer: self
                    .fee_payer
                    .map(|fee_payer| chain_ctx.get(&fee_payer)),
                fee_token: chain_ctx.get(&self.fee_token),
                code_path: self.code_path,
            }
        }
    }

    impl Args for EthereumBridgePool<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let asset = ERC20.parse(matches);
            let recipient = BRIDGE_POOL_TARGET.parse(matches);
            let sender = SOURCE.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let fee_amount =
                InputAmount::Unvalidated(BRIDGE_POOL_GAS_AMOUNT.parse(matches));
            let fee_payer = BRIDGE_POOL_GAS_PAYER.parse(matches);
            let fee_token = BRIDGE_POOL_GAS_TOKEN.parse(matches);
            let code_path = PathBuf::from(TX_BRIDGE_POOL_WASM);
            let nut = NUT.parse(matches);
            Self {
                tx,
                asset,
                recipient,
                sender,
                amount,
                fee_amount,
                fee_payer,
                fee_token,
                code_path,
                nut,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    ERC20
                        .def()
                        .help("The Ethereum address of the ERC20 token."),
                )
                .arg(
                    BRIDGE_POOL_TARGET
                        .def()
                        .help("The Ethereum address receiving the tokens."),
                )
                .arg(
                    SOURCE.def().help("The Namada address sending the tokens."),
                )
                .arg(
                    AMOUNT.def().help(
                        "The amount of tokens being sent across the bridge.",
                    ),
                )
                .arg(BRIDGE_POOL_GAS_AMOUNT.def().help(
                    "The amount of gas you wish to pay to have this transfer \
                     relayed to Ethereum.",
                ))
                .arg(BRIDGE_POOL_GAS_PAYER.def().help(
                    "The Namada address of the account paying the gas. By \
                     default, it is the same as the source.",
                ))
                .arg(BRIDGE_POOL_GAS_TOKEN.def().help(
                    "The token for paying the Bridge pool gas fees. Defaults \
                     to NAM.",
                ))
                .arg(NUT.def().help(
                    "Add Non Usable Tokens (NUTs) to the Bridge pool. These \
                     are usually obtained from invalid transfers to Namada.",
                ))
        }
    }

    impl CliToSdk<RecommendBatch<SdkTypes>> for RecommendBatch<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> RecommendBatch<SdkTypes> {
            let chain_ctx = ctx.borrow_chain_or_exit();
            RecommendBatch::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                max_gas: self.max_gas,
                gas: self.gas,
                conversion_table: {
                    let file = std::io::BufReader::new(
                        std::fs::File::open(self.conversion_table).expect(
                            "Failed to open the provided file to the \
                             conversion table",
                        ),
                    );
                    let table: HashMap<String, f64> =
                        serde_json::from_reader(file)
                            .expect("Failed to parse conversion table");
                    table
                        .into_iter()
                        .map(|(token, conversion_rate)| {
                            let token_from_ctx =
                                FromContext::<Address>::new(token);
                            let address = chain_ctx.get(&token_from_ctx);
                            let alias = token_from_ctx.raw;
                            (
                                address,
                                BpConversionTableEntry {
                                    alias,
                                    conversion_rate,
                                },
                            )
                        })
                        .collect()
                },
            }
        }
    }

    impl Args for RecommendBatch<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let max_gas = MAX_ETH_GAS.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let conversion_table = CONVERSION_TABLE.parse(matches);
            Self {
                query,
                max_gas,
                gas,
                conversion_table,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(MAX_ETH_GAS.def().help(
                    "The maximum amount Ethereum gas that can be spent during \
                     the relay call.",
                ))
                .arg(ETH_GAS.def().help(
                    "Under ideal conditions, relaying transfers will yield a \
                     net profit. If that is not possible, setting this \
                     optional value will result in a batch transfer that \
                     costs as close to the given value as possible without \
                     exceeding it.",
                ))
                .arg(CONVERSION_TABLE.def().help(
                    "Path to a JSON object containing a mapping between token \
                     aliases (or addresses) and their conversion rates in gwei",
                ))
        }
    }

    impl CliToSdkCtxless<BridgePoolProof<SdkTypes>> for BridgePoolProof<CliTypes> {
        fn to_sdk_ctxless(self) -> BridgePoolProof<SdkTypes> {
            BridgePoolProof::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                transfers: self.transfers,
                relayer: self.relayer,
            }
        }
    }

    impl Args for BridgePoolProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let hashes = HASH_LIST.parse(matches);
            let relayer = RELAYER.parse(matches);
            Self {
                query,
                transfers: hashes
                    .split_whitespace()
                    .map(|hash| {
                        KeccakHash::try_from(hash).unwrap_or_else(|_| {
                            tracing::info!(
                                "Could not parse '{}' as a Keccak hash.",
                                hash
                            );
                            safe_exit(1)
                        })
                    })
                    .collect(),
                relayer,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(HASH_LIST.def().help(
                    "Whitespace separated Keccak hash list of transfers in \
                     the Bridge pool.",
                ))
                .arg(
                    RELAYER
                        .def()
                        .help("The rewards address for relaying this proof."),
                )
        }
    }

    impl CliToSdkCtxless<RelayBridgePoolProof<SdkTypes>>
        for RelayBridgePoolProof<CliTypes>
    {
        fn to_sdk_ctxless(self) -> RelayBridgePoolProof<SdkTypes> {
            RelayBridgePoolProof::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                transfers: self.transfers,
                relayer: self.relayer,
                confirmations: self.confirmations,
                eth_rpc_endpoint: (),
                gas: self.gas,
                gas_price: self.gas_price,
                eth_addr: self.eth_addr,
                sync: self.sync,
                safe_mode: self.safe_mode,
            }
        }
    }

    impl Args for RelayBridgePoolProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let safe_mode = SAFE_MODE.parse(matches);
            let query = Query::parse(matches);
            let hashes = HASH_LIST.parse(matches);
            let relayer = RELAYER.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let gas_price = ETH_GAS_PRICE.parse(matches);
            let eth_rpc_endpoint = ETH_RPC_ENDPOINT.parse(matches);
            let eth_addr = ETH_ADDRESS_OPT.parse(matches);
            let confirmations = ETH_CONFIRMATIONS.parse(matches);
            let sync = ETH_SYNC.parse(matches);
            Self {
                query,
                sync,
                transfers: hashes
                    .split(' ')
                    .map(|hash| {
                        KeccakHash::try_from(hash).unwrap_or_else(|_| {
                            tracing::info!(
                                "Could not parse '{}' as a Keccak hash.",
                                hash
                            );
                            safe_exit(1)
                        })
                    })
                    .collect(),
                relayer,
                gas,
                gas_price,
                eth_rpc_endpoint,
                eth_addr,
                confirmations,
                safe_mode,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(SAFE_MODE.def().help(
                    "Safe mode overrides keyboard interrupt signals, to \
                     ensure Ethereum transfers aren't canceled midway through.",
                ))
                .arg(HASH_LIST.def().help(
                    "Whitespace separated Keccak hash list of transfers in \
                     the Bridge pool.",
                ))
                .arg(
                    RELAYER
                        .def()
                        .help("The rewards address for relaying this proof."),
                )
                .arg(ETH_ADDRESS_OPT.def().help(
                    "The address of the Ethereum wallet to pay the gas fees. \
                     If unset, the default wallet is used.",
                ))
                .arg(ETH_GAS.def().help(
                    "The Ethereum gas that can be spent during the relay call.",
                ))
                .arg(
                    ETH_GAS_PRICE.def().help(
                        "The price of Ethereum gas, during the relay call.",
                    ),
                )
                .arg(ETH_RPC_ENDPOINT.def().help("The Ethereum RPC endpoint."))
                .arg(
                    ETH_CONFIRMATIONS
                        .def()
                        .help("The number of block confirmations on Ethereum."),
                )
                .arg(ETH_SYNC.def().help(
                    "Synchronize with the network, or exit immediately, if \
                     the Ethereum node has fallen behind.",
                ))
        }
    }

    impl CliToSdkCtxless<BridgeValidatorSet<SdkTypes>>
        for BridgeValidatorSet<CliTypes>
    {
        fn to_sdk_ctxless(self) -> BridgeValidatorSet<SdkTypes> {
            BridgeValidatorSet::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                epoch: self.epoch,
            }
        }
    }

    impl Args for BridgeValidatorSet<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let epoch = EPOCH.parse(matches);
            Self { query, epoch }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                EPOCH.def().help(
                    "The epoch of the Bridge set of validators to query.",
                ),
            )
        }
    }

    impl CliToSdkCtxless<GovernanceValidatorSet<SdkTypes>>
        for GovernanceValidatorSet<CliTypes>
    {
        fn to_sdk_ctxless(self) -> GovernanceValidatorSet<SdkTypes> {
            GovernanceValidatorSet::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                epoch: self.epoch,
            }
        }
    }

    impl Args for GovernanceValidatorSet<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let epoch = EPOCH.parse(matches);
            Self { query, epoch }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(EPOCH.def().help(
                "The epoch of the Governance set of validators to query.",
            ))
        }
    }

    impl CliToSdkCtxless<ValidatorSetProof<SdkTypes>>
        for ValidatorSetProof<CliTypes>
    {
        fn to_sdk_ctxless(self) -> ValidatorSetProof<SdkTypes> {
            ValidatorSetProof::<SdkTypes> {
                query: self.query.to_sdk_ctxless(),
                epoch: self.epoch,
            }
        }
    }

    impl Args for ValidatorSetProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let epoch = EPOCH.parse(matches);
            Self { query, epoch }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                EPOCH
                    .def()
                    .help("The epoch of the set of validators to be proven."),
            )
        }
    }

    impl CliToSdkCtxless<ValidatorSetUpdateRelay<SdkTypes>>
        for ValidatorSetUpdateRelay<CliTypes>
    {
        fn to_sdk_ctxless(self) -> ValidatorSetUpdateRelay<SdkTypes> {
            ValidatorSetUpdateRelay::<SdkTypes> {
                daemon: self.daemon,
                query: self.query.to_sdk_ctxless(),
                confirmations: self.confirmations,
                eth_rpc_endpoint: (),
                epoch: self.epoch,
                gas: self.gas,
                gas_price: self.gas_price,
                eth_addr: self.eth_addr,
                sync: self.sync,
                retry_dur: self.retry_dur,
                success_dur: self.success_dur,
                safe_mode: self.safe_mode,
            }
        }
    }

    impl Args for ValidatorSetUpdateRelay<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let safe_mode = SAFE_MODE.parse(matches);
            let daemon = DAEMON_MODE.parse(matches);
            let query = Query::parse(matches);
            let epoch = EPOCH.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let gas_price = ETH_GAS_PRICE.parse(matches);
            let eth_rpc_endpoint = ETH_RPC_ENDPOINT.parse(matches);
            let eth_addr = ETH_ADDRESS_OPT.parse(matches);
            let confirmations = ETH_CONFIRMATIONS.parse(matches);
            let sync = ETH_SYNC.parse(matches);
            let retry_dur =
                DAEMON_MODE_RETRY_DUR.parse(matches).map(|dur| dur.0);
            let success_dur =
                DAEMON_MODE_SUCCESS_DUR.parse(matches).map(|dur| dur.0);
            Self {
                sync,
                daemon,
                query,
                epoch,
                gas,
                gas_price,
                confirmations,
                eth_rpc_endpoint,
                eth_addr,
                retry_dur,
                success_dur,
                safe_mode,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(SAFE_MODE.def().help(
                    "Safe mode overrides keyboard interrupt signals, to \
                     ensure Ethereum transfers aren't canceled midway through.",
                ))
                .arg(DAEMON_MODE.def().help(
                    "Run in daemon mode, which will continuously perform \
                     validator set updates.",
                ))
                .arg(DAEMON_MODE_RETRY_DUR.def().help(
                    "The amount of time to sleep between failed daemon mode \
                     relays.",
                ))
                .arg(DAEMON_MODE_SUCCESS_DUR.def().help(
                    "The amount of time to sleep between successful daemon \
                     mode relays.",
                ))
                .arg(ETH_ADDRESS_OPT.def().help(
                    "The address of the Ethereum wallet to pay the gas fees. \
                     If unset, the default wallet is used.",
                ))
                .arg(
                    EPOCH
                        .def()
                        .help("The epoch of the set of validators to relay."),
                )
                .arg(ETH_GAS.def().help(
                    "The Ethereum gas that can be spent during the relay call.",
                ))
                .arg(
                    ETH_GAS_PRICE.def().help(
                        "The price of Ethereum gas, during the relay call.",
                    ),
                )
                .arg(ETH_RPC_ENDPOINT.def().help("The Ethereum RPC endpoint."))
                .arg(
                    ETH_CONFIRMATIONS
                        .def()
                        .help("The number of block confirmations on Ethereum."),
                )
                .arg(ETH_SYNC.def().help(
                    "Synchronize with the network, or exit immediately, if \
                     the Ethereum node has fallen behind.",
                ))
        }
    }

    impl CliToSdk<TxCustom<SdkTypes>> for TxCustom<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxCustom<SdkTypes> {
            TxCustom::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                code_path: self.code_path,
                data_path: self.data_path.map(|data_path| {
                    std::fs::read(data_path)
                        .expect("Expected a file at given path")
                }),
                serialized_tx: self.serialized_tx.map(|path| {
                    std::fs::read(path).expect("Expected a file at given path")
                }),
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            }
        }
    }

    impl Args for TxCustom<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let code_path = CODE_PATH_OPT.parse(matches);
            let data_path = DATA_PATH_OPT.parse(matches);
            let serialized_tx = TX_PATH_OPT.parse(matches);
            let owner = OWNER.parse(matches);
            Self {
                tx,
                code_path,
                data_path,
                serialized_tx,
                owner,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    CODE_PATH_OPT
                        .def()
                        .help("The path to the transaction's WASM code.")
                        .conflicts_with(TX_PATH_OPT.name),
                )
                .arg(
                    DATA_PATH_OPT
                        .def()
                        .help(
                            "The data file at this path containing arbitrary \
                             bytes will be passed to the transaction code \
                             when it's executed.",
                        )
                        .requires(CODE_PATH_OPT.name)
                        .conflicts_with(TX_PATH_OPT.name),
                )
                .arg(
                    TX_PATH_OPT
                        .def()
                        .help("The path to a serialized transaction.")
                        .conflicts_with_all([
                            CODE_PATH_OPT.name,
                            DATA_PATH_OPT.name,
                        ]),
                )
                .arg(OWNER.def().help(
                    "The address corresponding to the signatures or signing \
                     keys.",
                ))
        }
    }

    impl CliToSdk<TxTransfer<SdkTypes>> for TxTransfer<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxTransfer<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxTransfer::<SdkTypes> {
                tx,
                source: chain_ctx.get_cached(&self.source),
                target: chain_ctx.get(&self.target),
                token: chain_ctx.get(&self.token),
                amount: self.amount,
                native_token: chain_ctx.native_token.clone(),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = TRANSFER_SOURCE.parse(matches);
            let target = TRANSFER_TARGET.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let tx_code_path = PathBuf::from(TX_TRANSFER_WASM);
            Self {
                tx,
                source,
                target,
                token,
                amount,
                tx_code_path,
                native_token: (),
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(TRANSFER_SOURCE.def().help(
                    "The source account address. The source's key may be used \
                     to produce the signature.",
                ))
                .arg(TRANSFER_TARGET.def().help(
                    "The target account address. The target's key may be used \
                     to produce the signature.",
                ))
                .arg(TOKEN.def().help("The transfer token."))
                .arg(AMOUNT.def().help("The amount to transfer in decimal."))
        }
    }

    impl CliToSdk<TxIbcTransfer<SdkTypes>> for TxIbcTransfer<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxIbcTransfer<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxIbcTransfer::<SdkTypes> {
                tx,
                source: chain_ctx.get_cached(&self.source),
                receiver: self.receiver,
                token: chain_ctx.get(&self.token),
                amount: self.amount,
                port_id: self.port_id,
                channel_id: self.channel_id,
                timeout_height: self.timeout_height,
                timeout_sec_offset: self.timeout_sec_offset,
                memo: self.memo,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxIbcTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = TRANSFER_SOURCE.parse(matches);
            let receiver = RECEIVER.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let port_id = PORT_ID.parse(matches);
            let channel_id = CHANNEL_ID.parse(matches);
            let timeout_height = TIMEOUT_HEIGHT.parse(matches);
            let timeout_sec_offset = TIMEOUT_SEC_OFFSET.parse(matches);
            let memo = IBC_TRANSFER_MEMO_PATH.parse(matches).map(|path| {
                std::fs::read_to_string(path)
                    .expect("Expected a file at given path")
            });
            let tx_code_path = PathBuf::from(TX_IBC_WASM);
            Self {
                tx,
                source,
                receiver,
                token,
                amount,
                port_id,
                channel_id,
                timeout_height,
                timeout_sec_offset,
                memo,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SOURCE.def().help(
                    "The source account address. The source's key is used to \
                     produce the signature.",
                ))
                .arg(RECEIVER.def().help(
                    "The receiver address on the destination chain as string.",
                ))
                .arg(TOKEN.def().help("The transfer token."))
                .arg(AMOUNT.def().help("The amount to transfer in decimal."))
                .arg(PORT_ID.def().help("The port ID."))
                .arg(CHANNEL_ID.def().help("The channel ID."))
                .arg(
                    TIMEOUT_HEIGHT
                        .def()
                        .help("The timeout height of the destination chain."),
                )
                .arg(TIMEOUT_SEC_OFFSET.def().help("The timeout as seconds."))
                .arg(
                    IBC_TRANSFER_MEMO_PATH
                        .def()
                        .help("The path for the memo field of ICS20 transfer."),
                )
        }
    }

    impl CliToSdk<TxInitAccount<SdkTypes>> for TxInitAccount<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxInitAccount<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxInitAccount::<SdkTypes> {
                tx,
                vp_code_path: self.vp_code_path,
                tx_code_path: self.tx_code_path,
                public_keys: self
                    .public_keys
                    .iter()
                    .map(|pk| chain_ctx.get(pk))
                    .collect(),
                threshold: self.threshold,
            }
        }
    }

    impl Args for TxInitAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let vp_code_path = CODE_PATH_OPT
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from(VP_USER_WASM));
            let tx_code_path = PathBuf::from(TX_INIT_ACCOUNT_WASM);
            let public_keys = PUBLIC_KEYS.parse(matches);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                vp_code_path,
                public_keys,
                threshold,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(CODE_PATH_OPT.def().help(
                    "The path to the validity predicate WASM code to be used \
                     for the new account. Uses the default user VP if none \
                     specified.",
                ))
                .arg(PUBLIC_KEYS.def().help(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding.",
                ))
                .arg(THRESHOLD.def().help(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided.",
                ))
        }
    }

    impl CliToSdk<TxBecomeValidator<SdkTypes>> for TxBecomeValidator<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxBecomeValidator<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxBecomeValidator::<SdkTypes> {
                tx,
                scheme: self.scheme,
                address: chain_ctx.get(&self.address),
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                eth_cold_key: self.eth_cold_key.map(|x| chain_ctx.get(&x)),
                eth_hot_key: self.eth_hot_key.map(|x| chain_ctx.get(&x)),
                protocol_key: self.protocol_key.map(|x| chain_ctx.get(&x)),
                commission_rate: self.commission_rate,
                max_commission_rate_change: self.max_commission_rate_change,
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxBecomeValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let address = ADDRESS.parse(matches);
            let scheme = SCHEME.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let eth_cold_key = VALIDATOR_ETH_COLD_KEY.parse(matches);
            let eth_hot_key = VALIDATOR_ETH_HOT_KEY.parse(matches);
            let protocol_key = PROTOCOL_KEY.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_BECOME_VALIDATOR_WASM);
            Self {
                tx,
                address,
                scheme,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email,
                description,
                website,
                discord_handle,
                unsafe_dont_encrypt,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(ADDRESS.def().help(
                    "Address of an account that will become a validator.",
                ))
                .arg(SCHEME.def().help(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1.",
                ))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(
                    "A consensus key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     ed25519.",
                ))
                .arg(VALIDATOR_ETH_COLD_KEY.def().help(
                    "An Eth cold key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     secp256k1.",
                ))
                .arg(VALIDATOR_ETH_HOT_KEY.def().help(
                    "An Eth hot key for the validator account. A new one will \
                     be generated if none given. Note that this must be \
                     secp256k1.",
                ))
                .arg(PROTOCOL_KEY.def().help(
                    "A public key for signing protocol transactions. A new \
                     one will be generated if none given.",
                ))
                .arg(COMMISSION_RATE.def().help(
                    "The commission rate charged by the validator for \
                     delegation rewards. Expressed as a decimal between 0 and \
                     1. This is a required parameter.",
                ))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. \
                     Expressed as a decimal between 0 and 1. This is a \
                     required parameter.",
                ))
                .arg(EMAIL.def().help("The validator's email."))
                .arg(DESCRIPTION_OPT.def().help("The validator's description."))
                .arg(WEBSITE_OPT.def().help("The validator's website."))
                .arg(DISCORD_OPT.def().help("The validator's discord handle."))
                .arg(VALIDATOR_CODE_PATH.def().help(
                    "The path to the validity predicate WASM code to be used \
                     for the validator account. Uses the default validator VP \
                     if none specified.",
                ))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network.",
                ))
        }
    }

    impl CliToSdk<TxInitValidator<SdkTypes>> for TxInitValidator<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxInitValidator<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxInitValidator::<SdkTypes> {
                tx,
                scheme: self.scheme,
                account_keys: self
                    .account_keys
                    .iter()
                    .map(|x| chain_ctx.get(x))
                    .collect(),
                threshold: self.threshold,
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                eth_cold_key: self.eth_cold_key.map(|x| chain_ctx.get(&x)),
                eth_hot_key: self.eth_hot_key.map(|x| chain_ctx.get(&x)),
                protocol_key: self.protocol_key.map(|x| chain_ctx.get(&x)),
                commission_rate: self.commission_rate,
                max_commission_rate_change: self.max_commission_rate_change,
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                validator_vp_code_path: self
                    .validator_vp_code_path
                    .to_path_buf(),
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_init_account_code_path: self
                    .tx_init_account_code_path
                    .to_path_buf(),
                tx_become_validator_code_path: self
                    .tx_become_validator_code_path
                    .to_path_buf(),
            }
        }
    }

    impl Args for TxInitValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let scheme = SCHEME.parse(matches);
            let account_keys = VALIDATOR_ACCOUNT_KEYS.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let eth_cold_key = VALIDATOR_ETH_COLD_KEY.parse(matches);
            let eth_hot_key = VALIDATOR_ETH_HOT_KEY.parse(matches);
            let protocol_key = PROTOCOL_KEY.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let validator_vp_code_path = VALIDATOR_CODE_PATH
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from(VP_USER_WASM));
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_init_account_code_path = PathBuf::from(TX_INIT_ACCOUNT_WASM);
            let tx_become_validator_code_path =
                PathBuf::from(TX_BECOME_VALIDATOR_WASM);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                scheme,
                account_keys,
                threshold,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email,
                description,
                website,
                discord_handle,
                validator_vp_code_path,
                unsafe_dont_encrypt,
                tx_init_account_code_path,
                tx_become_validator_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SCHEME.def().help(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1.",
                ))
                .arg(VALIDATOR_ACCOUNT_KEYS.def().help(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding. A new one will be generated if \
                     none given.",
                ))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(
                    "A consensus key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     ed25519.",
                ))
                .arg(VALIDATOR_ETH_COLD_KEY.def().help(
                    "An Eth cold key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     secp256k1.",
                ))
                .arg(VALIDATOR_ETH_HOT_KEY.def().help(
                    "An Eth hot key for the validator account. A new one will \
                     be generated if none given. Note that this must be \
                     secp256k1.",
                ))
                .arg(PROTOCOL_KEY.def().help(
                    "A public key for signing protocol transactions. A new \
                     one will be generated if none given.",
                ))
                .arg(COMMISSION_RATE.def().help(
                    "The commission rate charged by the validator for \
                     delegation rewards. Expressed as a decimal between 0 and \
                     1. This is a required parameter.",
                ))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. \
                     Expressed as a decimal between 0 and 1. This is a \
                     required parameter.",
                ))
                .arg(EMAIL.def().help("The validator's email."))
                .arg(DESCRIPTION_OPT.def().help("The validator's description."))
                .arg(WEBSITE_OPT.def().help("The validator's website."))
                .arg(DISCORD_OPT.def().help("The validator's discord handle."))
                .arg(VALIDATOR_CODE_PATH.def().help(
                    "The path to the validity predicate WASM code to be used \
                     for the validator account. Uses the default validator VP \
                     if none specified.",
                ))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network.",
                ))
                .arg(THRESHOLD.def().help(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided.",
                ))
        }
    }

    impl CliToSdk<TxUpdateAccount<SdkTypes>> for TxUpdateAccount<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxUpdateAccount<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            TxUpdateAccount::<SdkTypes> {
                tx,
                vp_code_path: self.vp_code_path,
                tx_code_path: self.tx_code_path,
                addr: chain_ctx.get(&self.addr),
                public_keys: self
                    .public_keys
                    .iter()
                    .map(|pk| chain_ctx.get(pk))
                    .collect(),
                threshold: self.threshold,
            }
        }
    }

    impl Args for TxUpdateAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let vp_code_path = CODE_PATH_OPT.parse(matches);
            let addr = ADDRESS.parse(matches);
            let tx_code_path = PathBuf::from(TX_UPDATE_ACCOUNT_WASM);
            let public_keys = PUBLIC_KEYS.parse(matches);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                vp_code_path,
                addr,
                tx_code_path,
                public_keys,
                threshold,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    CODE_PATH_OPT.def().help(
                        "The path to the new validity predicate WASM code.",
                    ),
                )
                .arg(ADDRESS.def().help(
                    "The account's address. It's key is used to produce the \
                     signature.",
                ))
                .arg(PUBLIC_KEYS.def().help(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding.",
                ))
                .arg(THRESHOLD.def().help(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided.",
                ))
        }
    }

    impl CliToSdk<Bond<SdkTypes>> for Bond<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> Bond<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            Bond::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                amount: self.amount,
                source: self.source.map(|x| chain_ctx.get(&x)),
                native_token: chain_ctx.native_token.clone(),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for Bond<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_BOND_WASM);
            Self {
                tx,
                validator,
                amount,
                source,
                tx_code_path,
                native_token: (),
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help("Validator address."))
                .arg(AMOUNT.def().help("Amount of tokens to stake in a bond."))
                .arg(SOURCE_OPT.def().help(
                    "Source address for delegations. For self-bonds, the \
                     validator is also the source.",
                ))
        }
    }

    impl CliToSdk<Unbond<SdkTypes>> for Unbond<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> Unbond<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            Unbond::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                amount: self.amount,
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for Unbond<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_UNBOND_WASM);
            Self {
                tx,
                validator,
                amount,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help("Validator address."))
                .arg(
                    AMOUNT
                        .def()
                        .help("Amount of tokens to unbond from a bond."),
                )
                .arg(SOURCE_OPT.def().help(
                    "Source address for unbonding from delegations. For \
                     unbonding from self-bonds, the validator is also the \
                     source.",
                ))
        }
    }

    impl CliToSdk<UpdateStewardCommission<SdkTypes>>
        for UpdateStewardCommission<CliTypes>
    {
        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> UpdateStewardCommission<SdkTypes> {
            UpdateStewardCommission::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                steward: ctx.borrow_chain_or_exit().get(&self.steward),
                commission: std::fs::read(self.commission).expect(""),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for UpdateStewardCommission<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let steward = STEWARD.parse(matches);
            let commission = DATA_PATH.parse(matches);
            let tx_code_path = PathBuf::from(TX_UPDATE_STEWARD_COMMISSION);
            Self {
                tx,
                steward,
                commission,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(STEWARD.def().help("Steward address."))
                .arg(DATA_PATH.def().help(
                    "The path to the file that describes the commission \
                     split. The file must contain a map from namada address \
                     to a percentage. Percentages must sum to 1 or less.",
                ))
        }
    }

    impl CliToSdk<ResignSteward<SdkTypes>> for ResignSteward<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> ResignSteward<SdkTypes> {
            ResignSteward::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                steward: ctx.borrow_chain_or_exit().get(&self.steward),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for ResignSteward<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let steward = STEWARD.parse(matches);
            let tx_code_path = PathBuf::from(TX_RESIGN_STEWARD);
            Self {
                tx,
                steward,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(STEWARD.def().help("Steward address."))
        }
    }

    impl CliToSdk<Redelegate<SdkTypes>> for Redelegate<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> Redelegate<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            Redelegate::<SdkTypes> {
                tx,
                src_validator: chain_ctx.get(&self.src_validator),
                dest_validator: chain_ctx.get(&self.dest_validator),
                owner: chain_ctx.get(&self.owner),
                amount: self.amount,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for Redelegate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let src_validator = SOURCE_VALIDATOR.parse(matches);
            let dest_validator = DESTINATION_VALIDATOR.parse(matches);
            let owner = OWNER.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let tx_code_path = PathBuf::from(TX_REDELEGATE_WASM);
            Self {
                tx,
                src_validator,
                dest_validator,
                owner,
                amount,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    SOURCE_VALIDATOR
                        .def()
                        .help("Source validator address for the redelegation."),
                )
                .arg(DESTINATION_VALIDATOR.def().help(
                    "Destination validator address for the redelegation.",
                ))
                .arg(OWNER.def().help(
                    "Delegator (owner) address of the bonds that are being \
                     redelegated.",
                ))
                .arg(AMOUNT.def().help("Amount of tokens to redelegate."))
        }
    }

    impl CliToSdk<InitProposal<SdkTypes>> for InitProposal<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> InitProposal<SdkTypes> {
            InitProposal::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                proposal_data: std::fs::read(self.proposal_data).expect(""),
                is_offline: self.is_offline,
                is_pgf_stewards: self.is_pgf_stewards,
                is_pgf_funding: self.is_pgf_funding,
                native_token: ctx.borrow_chain_or_exit().native_token.clone(),
                tx_code_path: self.tx_code_path,
            }
        }
    }

    impl Args for InitProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let proposal_data = DATA_PATH.parse(matches);
            let is_offline = PROPOSAL_OFFLINE.parse(matches);
            let is_pgf_stewards = PROPOSAL_PGF_STEWARD.parse(matches);
            let is_pgf_funding = PROPOSAL_PGF_FUNDING.parse(matches);
            let tx_code_path = PathBuf::from(TX_INIT_PROPOSAL);

            Self {
                tx,
                proposal_data,
                native_token: (),
                tx_code_path,
                is_offline,
                is_pgf_stewards,
                is_pgf_funding,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(DATA_PATH.def().help(
                    "The data path file (json) that describes the proposal.",
                ))
                .arg(
                    PROPOSAL_OFFLINE
                        .def()
                        .help(
                            "Flag if the proposal should be serialized \
                             offline (only for default types).",
                        )
                        .conflicts_with_all([
                            PROPOSAL_PGF_FUNDING.name,
                            PROPOSAL_PGF_STEWARD.name,
                            PROPOSAL_ETH.name,
                        ]),
                )
                .arg(
                    PROPOSAL_ETH
                        .def()
                        .help("Flag if the proposal is of type eth.")
                        .conflicts_with_all([
                            PROPOSAL_PGF_FUNDING.name,
                            PROPOSAL_PGF_STEWARD.name,
                        ]),
                )
                .arg(
                    PROPOSAL_PGF_STEWARD
                        .def()
                        .help(
                            "Flag if the proposal is of type pgf-stewards. \
                             Used to elect/remove stewards.",
                        )
                        .conflicts_with_all([
                            PROPOSAL_ETH.name,
                            PROPOSAL_PGF_FUNDING.name,
                        ]),
                )
                .arg(
                    PROPOSAL_PGF_FUNDING
                        .def()
                        .help(
                            "Flag if the proposal is of type pgf-funding. \
                             Used to control continuous/retro pgf fundings.",
                        )
                        .conflicts_with_all([
                            PROPOSAL_ETH.name,
                            PROPOSAL_PGF_STEWARD.name,
                        ]),
                )
        }
    }

    impl CliToSdk<VoteProposal<SdkTypes>> for VoteProposal<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> VoteProposal<SdkTypes> {
            VoteProposal::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                proposal_id: self.proposal_id,
                vote: self.vote,
                voter: ctx.borrow_chain_or_exit().get(&self.voter),
                is_offline: self.is_offline,
                proposal_data: self.proposal_data.map(|path| {
                    std::fs::read(path)
                        .expect("Should be able to read the file.")
                }),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for VoteProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let proposal_id = PROPOSAL_ID_OPT.parse(matches);
            let vote = PROPOSAL_VOTE.parse(matches);
            let voter = ADDRESS.parse(matches);
            let is_offline = PROPOSAL_OFFLINE.parse(matches);
            let proposal_data = DATA_PATH_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_VOTE_PROPOSAL);

            Self {
                tx,
                proposal_id,
                vote,
                is_offline,
                voter,
                proposal_data,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    PROPOSAL_ID_OPT
                        .def()
                        .help("The proposal identifier.")
                        .conflicts_with_all([
                            PROPOSAL_OFFLINE.name,
                            DATA_PATH_OPT.name,
                        ]),
                )
                .arg(
                    PROPOSAL_VOTE
                        .def()
                        .help("The vote for the proposal. Either yay or nay."),
                )
                .arg(
                    PROPOSAL_OFFLINE
                        .def()
                        .help("Flag if the proposal vote should run offline.")
                        .conflicts_with(PROPOSAL_ID.name),
                )
                .arg(
                    DATA_PATH_OPT
                        .def()
                        .help(
                            "The data path file (json) that describes the \
                             proposal.",
                        )
                        .requires(PROPOSAL_OFFLINE.name)
                        .conflicts_with(PROPOSAL_ID.name),
                )
                .arg(ADDRESS.def().help("The address of the voter."))
        }
    }

    impl CliToSdk<RevealPk<SdkTypes>> for RevealPk<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> RevealPk<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            RevealPk::<SdkTypes> {
                tx,
                public_key: chain_ctx.get(&self.public_key),
            }
        }
    }

    impl Args for RevealPk<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let public_key = PUBLIC_KEY.parse(matches);

            Self { tx, public_key }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(PUBLIC_KEY.def().help("A public key to reveal."))
        }
    }

    impl CliToSdk<QueryProposal<SdkTypes>> for QueryProposal<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryProposal<SdkTypes> {
            QueryProposal::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                proposal_id: self.proposal_id,
            }
        }
    }

    impl Args for QueryProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let proposal_id = PROPOSAL_ID_OPT.parse(matches);

            Self { query, proposal_id }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(PROPOSAL_ID_OPT.def().help("The proposal identifier."))
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposalResult<C: NamadaTypes = SdkTypes> {
        /// Common query args
        pub query: Query<C>,
        /// Proposal id
        pub proposal_id: Option<u64>,
        /// Flag if proposal result should be run on offline data
        pub offline: bool,
        /// The folder containing the proposal and votes
        pub proposal_folder: Option<PathBuf>,
    }

    impl CliToSdk<QueryProposalResult<SdkTypes>> for QueryProposalResult<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryProposalResult<SdkTypes> {
            QueryProposalResult::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                proposal_id: self.proposal_id,
                offline: self.offline,
                proposal_folder: self.proposal_folder,
            }
        }
    }

    impl Args for QueryProposalResult<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let proposal_id = PROPOSAL_ID_OPT.parse(matches);
            let offline = PROPOSAL_OFFLINE.parse(matches);
            let proposal_folder = DATA_PATH_OPT.parse(matches);

            Self {
                query,
                proposal_id,
                offline,
                proposal_folder,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    PROPOSAL_ID_OPT
                        .def()
                        .help("The proposal identifier.")
                        .conflicts_with_all([
                            PROPOSAL_OFFLINE.name,
                            DATA_PATH_OPT.name,
                        ]),
                )
                .arg(
                    PROPOSAL_OFFLINE
                        .def()
                        .help(
                            "Flag if the proposal result should run on \
                             offline data.",
                        )
                        .conflicts_with(PROPOSAL_ID.name)
                        .requires(DATA_PATH_OPT.name),
                )
                .arg(
                    DATA_PATH_OPT
                        .def()
                        .help(
                            "The path to the folder containing the proposal \
                             and votes files in json format.",
                        )
                        .conflicts_with(PROPOSAL_ID.name)
                        .requires(PROPOSAL_OFFLINE.name),
                )
        }
    }

    impl CliToSdk<QueryProtocolParameters<SdkTypes>>
        for QueryProtocolParameters<CliTypes>
    {
        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> QueryProtocolParameters<SdkTypes> {
            QueryProtocolParameters::<SdkTypes> {
                query: self.query.to_sdk(ctx),
            }
        }
    }

    impl Args for QueryProtocolParameters<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);

            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl Args for QueryPgf<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);

            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl CliToSdk<QueryPgf<SdkTypes>> for QueryPgf<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryPgf<SdkTypes> {
            QueryPgf::<SdkTypes> {
                query: self.query.to_sdk(ctx),
            }
        }
    }

    impl CliToSdk<Withdraw<SdkTypes>> for Withdraw<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> Withdraw<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            Withdraw::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for Withdraw<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_WITHDRAW_WASM);
            Self {
                tx,
                validator,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help("Validator address."))
                .arg(SOURCE_OPT.def().help(
                    "Source address for withdrawing from delegations. For \
                     withdrawing from self-bonds, this arg does not need to \
                     be supplied.",
                ))
        }
    }

    impl CliToSdk<ClaimRewards<SdkTypes>> for ClaimRewards<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> ClaimRewards<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            ClaimRewards::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for ClaimRewards<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CLAIM_REWARDS_WASM);
            Self {
                tx,
                validator,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help("Validator address."))
                .arg(SOURCE_OPT.def().help(
                    "Source address for claiming rewards for a bond. For \
                     self-bonds, the validator is also the source.",
                ))
        }
    }

    impl CliToSdk<QueryConversions<SdkTypes>> for QueryConversions<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryConversions<SdkTypes> {
            QueryConversions::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                token: self.token.map(|x| ctx.borrow_chain_or_exit().get(&x)),
                epoch: self.epoch,
            }
        }
    }

    impl Args for QueryConversions<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let token = TOKEN_OPT.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                epoch,
                token,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    EPOCH
                        .def()
                        .help("The epoch for which to query conversions."),
                )
                .arg(
                    TOKEN_OPT.def().help(
                        "The token address for which to query conversions.",
                    ),
                )
        }
    }

    impl CliToSdk<QueryAccount<SdkTypes>> for QueryAccount<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryAccount<SdkTypes> {
            QueryAccount::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            }
        }
    }

    impl Args for QueryAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER.parse(matches);
            Self { query, owner }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                OWNER
                    .def()
                    .help("The substorage space address to query.")
                    .required(true),
            )
        }
    }

    impl CliToSdk<QueryBalance<SdkTypes>> for QueryBalance<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryBalance<SdkTypes> {
            let query = self.query.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            QueryBalance::<SdkTypes> {
                query,
                owner: self.owner.map(|x| chain_ctx.get_cached(&x)),
                token: self.token.map(|x| chain_ctx.get(&x)),
                no_conversions: self.no_conversions,
            }
        }
    }

    impl Args for QueryBalance<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = BALANCE_OWNER.parse(matches);
            let token = TOKEN_OPT.parse(matches);
            let no_conversions = NO_CONVERSIONS.parse(matches);
            Self {
                query,
                owner,
                token,
                no_conversions,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    BALANCE_OWNER
                        .def()
                        .help("The account address whose balance to query."),
                )
                .arg(
                    TOKEN_OPT
                        .def()
                        .help("The token's address whose balance to query."),
                )
                .arg(
                    NO_CONVERSIONS.def().help(
                        "Whether not to automatically perform conversions.",
                    ),
                )
        }
    }

    impl CliToSdk<QueryTransfers<SdkTypes>> for QueryTransfers<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryTransfers<SdkTypes> {
            let query = self.query.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            QueryTransfers::<SdkTypes> {
                query,
                owner: self.owner.map(|x| chain_ctx.get_cached(&x)),
                token: self.token.map(|x| chain_ctx.get(&x)),
            }
        }
    }

    impl Args for QueryTransfers<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = BALANCE_OWNER.parse(matches);
            let token = TOKEN_OPT.parse(matches);
            Self {
                query,
                owner,
                token,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(BALANCE_OWNER.def().help(
                    "The account address that queried transfers must involve.",
                ))
                .arg(TOKEN_OPT.def().help(
                    "The token address that queried transfers must involve.",
                ))
        }
    }

    impl CliToSdk<QueryBonds<SdkTypes>> for QueryBonds<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryBonds<SdkTypes> {
            let query = self.query.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            QueryBonds::<SdkTypes> {
                query,
                owner: self.owner.map(|x| chain_ctx.get(&x)),
                validator: self.validator.map(|x| chain_ctx.get(&x)),
            }
        }
    }

    impl Args for QueryBonds<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER_OPT.parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            Self {
                query,
                owner,
                validator,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    OWNER_OPT.def().help(
                        "The owner account address whose bonds to query.",
                    ),
                )
                .arg(
                    VALIDATOR_OPT
                        .def()
                        .help("The validator's address whose bonds to query."),
                )
        }
    }

    impl CliToSdk<QueryBondedStake<SdkTypes>> for QueryBondedStake<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryBondedStake<SdkTypes> {
            QueryBondedStake::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: self
                    .validator
                    .map(|x| ctx.borrow_chain_or_exit().get(&x)),
                epoch: self.epoch,
            }
        }
    }

    impl Args for QueryBondedStake<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR_OPT.def().help(
                    "The validator's address whose bonded stake to query.",
                ))
                .arg(EPOCH.def().help(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified).",
                ))
        }
    }

    impl CliToSdk<QueryValidatorState<SdkTypes>> for QueryValidatorState<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryValidatorState<SdkTypes> {
            QueryValidatorState::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                epoch: self.epoch,
            }
        }
    }

    impl Args for QueryValidatorState<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    VALIDATOR.def().help(
                        "The validator's address whose state is queried.",
                    ),
                )
                .arg(EPOCH.def().help(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified).",
                ))
        }
    }

    impl CliToSdk<CommissionRateChange<SdkTypes>>
        for CommissionRateChange<CliTypes>
    {
        fn to_sdk(self, ctx: &mut Context) -> CommissionRateChange<SdkTypes> {
            CommissionRateChange::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                rate: self.rate,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for CommissionRateChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let rate = COMMISSION_RATE.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_COMMISSION_WASM);
            Self {
                tx,
                validator,
                rate,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(
                    "The validator's address whose commission rate to change.",
                ))
                .arg(
                    COMMISSION_RATE
                        .def()
                        .help("The desired new commission rate."),
                )
        }
    }

    impl CliToSdk<ConsensusKeyChange<SdkTypes>> for ConsensusKeyChange<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> ConsensusKeyChange<SdkTypes> {
            let tx = self.tx.to_sdk(ctx);
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            ConsensusKeyChange::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for ConsensusKeyChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_CONSENSUS_KEY_WASM);
            Self {
                tx,
                validator,
                consensus_key,
                unsafe_dont_encrypt,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(
                    "The validator's address whose consensus key to change.",
                ))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(
                    "The desired new consensus key. A new one will be \
                     generated if none given. Note this key must be ed25519.",
                ))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network.",
                ))
        }
    }

    impl CliToSdk<MetaDataChange<SdkTypes>> for MetaDataChange<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> MetaDataChange<SdkTypes> {
            MetaDataChange::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                commission_rate: self.commission_rate,
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for MetaDataChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let email = EMAIL_OPT.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let commission_rate = COMMISSION_RATE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_METADATA_WASM);
            Self {
                tx,
                validator,
                email,
                description,
                website,
                discord_handle,
                commission_rate,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(
                    "The validator's address whose commission rate to change.",
                ))
                .arg(EMAIL_OPT.def().help(
                    "The desired new validator email. To remove the existing \
                     email, pass an empty string to this argument.",
                ))
                .arg(DESCRIPTION_OPT.def().help(
                    "The desired new validator description. To remove the \
                     existing description, pass an empty string to this \
                     argument.",
                ))
                .arg(WEBSITE_OPT.def().help(
                    "The desired new validator website. To remove the \
                     existing website, pass an empty string to this argument.",
                ))
                .arg(DISCORD_OPT.def().help(
                    "The desired new validator discord handle. To remove the \
                     existing discord handle, pass an empty string to this \
                     argument.",
                ))
                .arg(
                    COMMISSION_RATE_OPT
                        .def()
                        .help("The desired new commission rate."),
                )
        }
    }

    impl CliToSdk<TxUnjailValidator<SdkTypes>> for TxUnjailValidator<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> TxUnjailValidator<SdkTypes> {
            TxUnjailValidator::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxUnjailValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_UNJAIL_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help("The address of the jailed validator to unjail."),
            )
        }
    }

    impl CliToSdk<TxDeactivateValidator<SdkTypes>>
        for TxDeactivateValidator<CliTypes>
    {
        fn to_sdk(self, ctx: &mut Context) -> TxDeactivateValidator<SdkTypes> {
            TxDeactivateValidator::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxDeactivateValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_DEACTIVATE_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help("The address of the jailed validator to deactivate."),
            )
        }
    }

    impl CliToSdk<TxReactivateValidator<SdkTypes>>
        for TxReactivateValidator<CliTypes>
    {
        fn to_sdk(self, ctx: &mut Context) -> TxReactivateValidator<SdkTypes> {
            TxReactivateValidator::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            }
        }
    }

    impl Args for TxReactivateValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_REACTIVATE_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help("The address of the jailed validator to deactivate."),
            )
        }
    }

    impl CliToSdk<SignTx<SdkTypes>> for SignTx<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> SignTx<SdkTypes> {
            SignTx::<SdkTypes> {
                tx: self.tx.to_sdk(ctx),
                tx_data: std::fs::read(self.tx_data).expect(""),
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            }
        }
    }

    impl Args for SignTx<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let tx_path = TX_PATH.parse(matches);
            let owner = OWNER.parse(matches);
            Self {
                tx,
                tx_data: tx_path,
                owner,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    TX_PATH.def().help(
                        "The path to the tx file with the serialized tx.",
                    ),
                )
                .arg(OWNER.def().help("The address of the account owner"))
        }
    }

    impl CliToSdk<GenIbcShieldedTransafer<SdkTypes>>
        for GenIbcShieldedTransafer<CliTypes>
    {
        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> GenIbcShieldedTransafer<SdkTypes> {
            let query = self.query.to_sdk(ctx);
            let chain_ctx = ctx.borrow_chain_or_exit();
            GenIbcShieldedTransafer::<SdkTypes> {
                query,
                output_folder: self.output_folder,
                target: chain_ctx.get(&self.target),
                token: self.token,
                amount: self.amount,
                port_id: self.port_id,
                channel_id: self.channel_id,
            }
        }
    }

    impl Args for GenIbcShieldedTransafer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let output_folder = OUTPUT_FOLDER_PATH.parse(matches);
            let target = TRANSFER_TARGET.parse(matches);
            let token = TOKEN_STR.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let port_id = PORT_ID.parse(matches);
            let channel_id = CHANNEL_ID.parse(matches);
            Self {
                query,
                output_folder,
                target,
                token,
                amount,
                port_id,
                channel_id,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(OUTPUT_FOLDER_PATH.def().help(
                    "The output folder path where the artifact will be stored.",
                ))
                .arg(TRANSFER_TARGET.def().help("The target address."))
                .arg(TOKEN.def().help("The transfer token."))
                .arg(AMOUNT.def().help("The amount to transfer in decimal."))
                .arg(
                    PORT_ID
                        .def()
                        .help("The port ID via which the token is received."),
                )
                .arg(
                    CHANNEL_ID.def().help(
                        "The channel ID via which the token is received.",
                    ),
                )
        }
    }

    impl CliToSdk<QueryCommissionRate<SdkTypes>> for QueryCommissionRate<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryCommissionRate<SdkTypes> {
            QueryCommissionRate::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                epoch: self.epoch,
            }
        }
    }

    impl Args for QueryCommissionRate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR.def().help(
                    "The validator's address whose commission rate to query.",
                ))
                .arg(EPOCH.def().help(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified).",
                ))
        }
    }

    impl CliToSdk<QueryMetaData<SdkTypes>> for QueryMetaData<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryMetaData<SdkTypes> {
            QueryMetaData::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
            }
        }
    }

    impl Args for QueryMetaData<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            Self { query, validator }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help("The validator's address whose metadata to query."),
            )
        }
    }

    impl CliToSdk<QuerySlashes<SdkTypes>> for QuerySlashes<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QuerySlashes<SdkTypes> {
            QuerySlashes::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: self
                    .validator
                    .map(|x| ctx.borrow_chain_or_exit().get(&x)),
            }
        }
    }

    impl Args for QuerySlashes<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            Self { query, validator }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                VALIDATOR_OPT
                    .def()
                    .help("The validator's address whose slashes to query."),
            )
        }
    }

    impl CliToSdk<QueryRewards<SdkTypes>> for QueryRewards<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryRewards<SdkTypes> {
            QueryRewards::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                source: self.source.map(|x| ctx.borrow_chain_or_exit().get(&x)),
            }
        }
    }

    impl Args for QueryRewards<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let validator = VALIDATOR.parse(matches);
            Self {
                query,
                source,
                validator,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(SOURCE_OPT.def().help(
                    "Source address for the rewards query. For self-bonds, \
                     this arg does not need to be supplied.",
                ))
                .arg(
                    VALIDATOR
                        .def()
                        .help("Validator address for the rewards query."),
                )
        }
    }

    impl Args for QueryDelegations<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER.parse(matches);
            Self { query, owner }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                OWNER.def().help(
                    "The address of the owner of the delegations to find.",
                ),
            )
        }
    }

    impl CliToSdk<QueryDelegations<SdkTypes>> for QueryDelegations<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryDelegations<SdkTypes> {
            QueryDelegations::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            }
        }
    }

    impl Args for QueryFindValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let tm_addr = TM_ADDRESS.parse(matches);
            Self { query, tm_addr }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                TM_ADDRESS
                    .def()
                    .help("The address of the validator in Tendermint."),
            )
        }
    }

    impl CliToSdk<QueryFindValidator<SdkTypes>> for QueryFindValidator<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryFindValidator<SdkTypes> {
            QueryFindValidator::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                tm_addr: self.tm_addr,
            }
        }
    }

    impl CliToSdk<QueryRawBytes<SdkTypes>> for QueryRawBytes<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> QueryRawBytes<SdkTypes> {
            QueryRawBytes::<SdkTypes> {
                query: self.query.to_sdk(ctx),
                storage_key: self.storage_key,
            }
        }
    }

    impl Args for QueryRawBytes<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let storage_key = STORAGE_KEY.parse(matches);
            let query = Query::parse(matches);
            Self { storage_key, query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(STORAGE_KEY.def().help("Storage key"))
        }
    }

    /// The concrete types being used in the CLI
    #[derive(Clone, Debug)]
    pub struct CliTypes;

    impl NamadaTypes for CliTypes {
        type Address = WalletAddress;
        type BalanceOwner = WalletBalanceOwner;
        type BpConversionTable = PathBuf;
        type Data = PathBuf;
        type EthereumAddress = String;
        type Keypair = WalletKeypair;
        type NativeAddress = ();
        type PublicKey = WalletPublicKey;
        type TendermintAddress = TendermintAddress;
        type TransferSource = WalletTransferSource;
        type TransferTarget = WalletTransferTarget;
        type ViewingKey = WalletViewingKey;
    }

    impl CliToSdk<Tx<SdkTypes>> for Tx<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> Tx<SdkTypes> {
            let ctx = ctx.borrow_mut_chain_or_exit();
            Tx::<SdkTypes> {
                dry_run: self.dry_run,
                dry_run_wrapper: self.dry_run_wrapper,
                dump_tx: self.dump_tx,
                output_folder: self.output_folder,
                force: self.force,
                broadcast_only: self.broadcast_only,
                ledger_address: (),
                initialized_account_alias: self.initialized_account_alias,
                wallet_alias_force: self.wallet_alias_force,
                fee_amount: self.fee_amount,
                fee_token: ctx.get(&self.fee_token),
                fee_unshield: self
                    .fee_unshield
                    .map(|ref fee_unshield| ctx.get_cached(fee_unshield)),
                gas_limit: self.gas_limit,
                signing_keys: self
                    .signing_keys
                    .iter()
                    .map(|key| ctx.get(key))
                    .collect(),
                signatures: self
                    .signatures
                    .iter()
                    .map(|path| std::fs::read(path).unwrap())
                    .collect(),
                disposable_signing_key: self.disposable_signing_key,
                tx_reveal_code_path: self.tx_reveal_code_path,
                password: self.password,
                expiration: self.expiration,
                chain_id: self
                    .chain_id
                    .or_else(|| Some(ctx.config.ledger.chain_id.clone())),
                wrapper_fee_payer: self.wrapper_fee_payer.map(|x| ctx.get(&x)),
                memo: self.memo,
                use_device: self.use_device,
            }
        }
    }

    impl Args for Tx<CliTypes> {
        fn def(app: App) -> App {
            app.arg(
                DRY_RUN_TX
                    .def()
                    .help("Simulate the transaction application.")
                    .conflicts_with(DRY_RUN_WRAPPER_TX.name),
            )
            .arg(
                DRY_RUN_WRAPPER_TX
                    .def()
                    .help(
                        "Simulate the complete transaction application. This \
                         estimates the gas cost of the transaction.",
                    )
                    .conflicts_with(DRY_RUN_TX.name),
            )
            .arg(DUMP_TX.def().help("Dump transaction bytes to a file."))
            .arg(FORCE.def().help(
                "Submit the transaction even if it doesn't pass client checks.",
            ))
            .arg(BROADCAST_ONLY.def().help(
                "Do not wait for the transaction to be applied. This will \
                 return once the transaction is added to the mempool.",
            ))
            .arg(
                LEDGER_ADDRESS_DEFAULT
                    .def()
                    .help(LEDGER_ADDRESS_ABOUT)
                    // This used to be "ledger-address", alias for compatibility
                    .alias("ledger-address"),
            )
            .arg(ALIAS_OPT.def().help(
                "If any new account is initialized by the tx, use the given \
                 alias to save it in the wallet. If multiple accounts are \
                 initialized, the alias will be the prefix of each new \
                 address joined with a number.",
            ))
            .arg(FEE_AMOUNT_OPT.def().help(
                "The amount being paid, per gas unit, for the inclusion of \
                 this transaction",
            ))
            .arg(FEE_TOKEN.def().help("The token for paying the gas"))
            .arg(FEE_UNSHIELD_SPENDING_KEY.def().help(
                "The spending key to be used for fee unshielding. If none is \
                 provided, fee will be paid from the unshielded balance only.",
            ))
            .arg(GAS_LIMIT.def().help(
                "The multiplier of the gas limit resolution defining the \
                 maximum amount of gas needed to run transaction.",
            ))
            .arg(WALLET_ALIAS_FORCE.def().help(
                "Override the alias without confirmation if it already exists.",
            ))
            .arg(EXPIRATION_OPT.def().help(
                "The expiration datetime of the transaction, after which the \
                 tx won't be accepted anymore. All of these examples are \
                 equivalent:\n2012-12-12T12:12:12Z\n2012-12-12 \
                 12:12:12Z\n2012-  12-12T12:  12:12Z",
            ))
            .arg(
                DISPOSABLE_SIGNING_KEY
                    .def()
                    .help(
                        "Generates an ephemeral, disposable keypair to sign \
                         the wrapper transaction. This keypair will be \
                         immediately discarded after use.",
                    )
                    .requires(FEE_UNSHIELD_SPENDING_KEY.name),
            )
            .arg(
                SIGNING_KEYS
                    .def()
                    .help(
                        "Sign the transaction with the key for the given \
                         public key, public key hash or alias from your \
                         wallet.",
                    )
                    .conflicts_with_all([SIGNATURES.name]),
            )
            .arg(
                SIGNATURES
                    .def()
                    .help(
                        "List of file paths containing a serialized signature \
                         to be attached to a transaction. Requires to provide \
                         a gas payer.",
                    )
                    .conflicts_with_all([SIGNING_KEYS.name])
                    .requires(FEE_PAYER_OPT.name),
            )
            .arg(OUTPUT_FOLDER_PATH.def().help(
                "The output folder path where the artifact will be stored.",
            ))
            .arg(CHAIN_ID_OPT.def().help("The chain ID."))
            .arg(
                FEE_PAYER_OPT
                    .def()
                    .help(
                        "The implicit address of the gas payer. It defaults \
                         to the address associated to the first key passed to \
                         --signing-keys.",
                    )
                    .conflicts_with(DISPOSABLE_SIGNING_KEY.name),
            )
            .arg(USE_DEVICE.def().help(
                "Use an attached hardware wallet device to sign the \
                 transaction.",
            ))
            .arg(
                MEMO_OPT
                    .def()
                    .help("Attach a plaintext memo to the transaction."),
            )
        }

        fn parse(matches: &ArgMatches) -> Self {
            let dry_run = DRY_RUN_TX.parse(matches);
            let dry_run_wrapper = DRY_RUN_WRAPPER_TX.parse(matches);
            let dump_tx = DUMP_TX.parse(matches);
            let force = FORCE.parse(matches);
            let broadcast_only = BROADCAST_ONLY.parse(matches);
            let ledger_address = LEDGER_ADDRESS_DEFAULT.parse(matches);
            let initialized_account_alias = ALIAS_OPT.parse(matches);
            let fee_amount =
                FEE_AMOUNT_OPT.parse(matches).map(InputAmount::Unvalidated);
            let fee_token = FEE_TOKEN.parse(matches);
            let fee_unshield = FEE_UNSHIELD_SPENDING_KEY.parse(matches);
            let _wallet_alias_force = WALLET_ALIAS_FORCE.parse(matches);
            let gas_limit = GAS_LIMIT.parse(matches);
            let wallet_alias_force = WALLET_ALIAS_FORCE.parse(matches);
            let expiration = EXPIRATION_OPT.parse(matches);
            let disposable_signing_key = DISPOSABLE_SIGNING_KEY.parse(matches);
            let signing_keys = SIGNING_KEYS.parse(matches);
            let signatures = SIGNATURES.parse(matches);
            let tx_reveal_code_path = PathBuf::from(TX_REVEAL_PK);
            let chain_id = CHAIN_ID_OPT.parse(matches);
            let password = None;
            let memo = MEMO_OPT.parse(matches).map(String::into_bytes);
            let wrapper_fee_payer = FEE_PAYER_OPT.parse(matches);
            let output_folder = OUTPUT_FOLDER_PATH.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            Self {
                dry_run,
                dry_run_wrapper,
                dump_tx,
                force,
                broadcast_only,
                ledger_address,
                initialized_account_alias,
                wallet_alias_force,
                fee_amount,
                fee_token,
                fee_unshield,
                gas_limit,
                expiration,
                disposable_signing_key,
                signing_keys,
                signatures,
                tx_reveal_code_path,
                password,
                chain_id,
                wrapper_fee_payer,
                output_folder,
                memo,
                use_device,
            }
        }
    }

    impl CliToSdkCtxless<Query<SdkTypes>> for Query<CliTypes> {
        fn to_sdk_ctxless(self) -> Query<SdkTypes> {
            Query::<SdkTypes> { ledger_address: () }
        }
    }

    impl Args for Query<CliTypes> {
        fn def(app: App) -> App {
            app.arg(
                LEDGER_ADDRESS_DEFAULT
                    .def()
                    .help(LEDGER_ADDRESS_ABOUT)
                    // This used to be "ledger-address", alias for compatibility
                    .alias("ledger-address"),
            )
        }

        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS_DEFAULT.parse(matches);
            Self { ledger_address }
        }
    }

    impl CliToSdk<PayAddressGen<SdkTypes>> for PayAddressGen<CliTypes> {
        fn to_sdk(self, ctx: &mut Context) -> PayAddressGen<SdkTypes> {
            use namada_sdk::wallet::Wallet;

            use crate::wallet::CliWalletUtils;

            let find_viewing_key = |w: &mut Wallet<CliWalletUtils>| {
                w.find_viewing_key(&self.viewing_key.raw)
                    .map(Clone::clone)
                    .unwrap_or_else(|_| {
                        eprintln!(
                            "Unknown viewing key {}",
                            self.viewing_key.raw
                        );
                        safe_exit(1)
                    })
            };
            let viewing_key = if ctx.global_args.is_pre_genesis {
                let wallet_path =
                    ctx.global_args.base_dir.join(PRE_GENESIS_DIR);
                let mut wallet = crate::wallet::load_or_new(&wallet_path);
                find_viewing_key(&mut wallet)
            } else {
                find_viewing_key(&mut ctx.borrow_mut_chain_or_exit().wallet)
            };
            PayAddressGen::<SdkTypes> {
                alias: self.alias,
                alias_force: self.alias_force,
                viewing_key,
                pin: self.pin,
            }
        }
    }

    impl Args for PayAddressGen<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let viewing_key = VIEWING_KEY.parse(matches);
            let pin = PIN.parse(matches);
            Self {
                alias,
                alias_force,
                viewing_key,
                pin,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS.def().help(
                    "An alias to be associated with the payment address.",
                ),
            )
            .arg(ALIAS_FORCE.def().help(
                "Override the alias without confirmation if it already exists.",
            ))
            .arg(VIEWING_KEY.def().help("The viewing key."))
            .arg(PIN.def().help(
                "Require that the single transaction to this address be \
                 pinned.",
            ))
        }
    }

    impl Args for KeyDerive {
        fn parse(matches: &ArgMatches) -> Self {
            let scheme = SCHEME.parse(matches);
            let shielded = SHIELDED.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            let derivation_path = HD_WALLET_DERIVATION_PATH.parse(matches);
            Self {
                scheme,
                shielded,
                alias,
                alias_force,
                unsafe_dont_encrypt,
                use_device,
                derivation_path,
            }
        }

        fn def(app: App) -> App {
            app.arg(SCHEME.def().conflicts_with(SHIELDED.name).help(
                "For the transparent pool, the type of key that should be \
                 derived. Argument must be either ed25519 or secp256k1. If \
                 none provided, the default key scheme is ed25519.\nNot \
                 applicable for the shielded pool.",
            ))
            .arg(
                SHIELDED
                    .def()
                    .help("Derive a spending key for the shielded pool."),
            )
            .arg(ALIAS.def().help("The key and address alias."))
            .arg(
                ALIAS_FORCE
                    .def()
                    .help("Force overwrite the alias if it already exists."),
            )
            .arg(UNSAFE_DONT_ENCRYPT.def().help(
                "UNSAFE: Do not encrypt the keypair. Do not use this for keys \
                 used in a live network.",
            ))
            .arg(USE_DEVICE.def().help(
                "Derive an address and public key from the seed stored on the \
                 connected hardware wallet.",
            ))
            .arg(HD_WALLET_DERIVATION_PATH.def().help(
                "HD key derivation path. Use keyword `default` to refer to a \
                 scheme default path:\n- m/44'/60'/0'/0/0 for secp256k1 \
                 scheme\n- m/44'/877'/0'/0'/0' for ed25519 scheme.\nFor \
                 ed25519, all path indices will be promoted to hardened \
                 indexes. If none is specified, the scheme default path is \
                 used.",
            ))
        }
    }

    impl Args for KeyGen {
        fn parse(matches: &ArgMatches) -> Self {
            let scheme = SCHEME.parse(matches);
            let shielded = SHIELDED.parse(matches);
            let raw = RAW_KEY_GEN.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let derivation_path = HD_WALLET_DERIVATION_PATH.parse(matches);
            Self {
                scheme,
                shielded,
                raw,
                alias,
                alias_force,
                unsafe_dont_encrypt,
                derivation_path,
            }
        }

        fn def(app: App) -> App {
            app.arg(SCHEME.def().conflicts_with(SHIELDED.name).help(
                "For the transparent pool, the type of key that should be \
                 generated. Argument must be either ed25519 or secp256k1. If \
                 none provided, the default key scheme is ed25519.\nNot \
                 applicable for the shielded pool.",
            ))
            .arg(
                SHIELDED
                    .def()
                    .help("Generate a spending key for the shielded pool."),
            )
            .arg(
                RAW_KEY_GEN
                    .def()
                    .conflicts_with(HD_WALLET_DERIVATION_PATH.name)
                    .help(
                        "Generate a random non-HD secret / spending key. No \
                         mnemonic code is generated.",
                    ),
            )
            .arg(ALIAS.def().help("The key and address alias."))
            .arg(ALIAS_FORCE.def().help(
                "Override the alias without confirmation if it already exists.",
            ))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(
                "UNSAFE: Do not encrypt the keypair. Do not use this for keys \
                 used in a live network.",
            ))
            .arg(HD_WALLET_DERIVATION_PATH.def().help(
                "HD key derivation path. Use keyword `default` to refer to a \
                 scheme default path:\n- m/44'/60'/0'/0/0 for secp256k1 \
                 scheme\n- m/44'/877'/0'/0'/0' for ed25519 scheme.\nFor \
                 ed25519, all path indices will be promoted to hardened \
                 indexes. If none is specified, the scheme default path is \
                 used.",
            ))
        }
    }

    impl Args for KeyAddressList {
        fn parse(matches: &ArgMatches) -> Self {
            let transparent_only = TRANSPARENT.parse(matches);
            let shielded_only = SHIELDED.parse(matches);
            let keys_only = LIST_FIND_KEYS_ONLY.parse(matches);
            let addresses_only = LIST_FIND_ADDRESSES_ONLY.parse(matches);
            let decrypt = DECRYPT.parse(matches);
            let unsafe_show_secret = UNSAFE_SHOW_SECRET.parse(matches);
            Self {
                transparent_only,
                shielded_only,
                keys_only,
                addresses_only,
                decrypt,
                unsafe_show_secret,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                TRANSPARENT
                    .def()
                    .help("List transparent keys / addresses only."),
            )
            .arg(
                SHIELDED
                    .def()
                    .help("List keys / addresses of the shielded pool only."),
            )
            .group(
                ArgGroup::new("only_group_1")
                    .args([TRANSPARENT.name, SHIELDED.name]),
            )
            .arg(LIST_FIND_KEYS_ONLY.def().help("List keys only."))
            .arg(LIST_FIND_ADDRESSES_ONLY.def().help("List addresses only."))
            .group(ArgGroup::new("only_group_2").args([
                LIST_FIND_KEYS_ONLY.name,
                LIST_FIND_ADDRESSES_ONLY.name,
            ]))
            .arg(DECRYPT.def().help("Decrypt keys that are encrypted."))
            .arg(
                UNSAFE_SHOW_SECRET
                    .def()
                    .help("UNSAFE: Print the secret / spending keys."),
            )
        }
    }

    impl Args for KeyAddressFind {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS_OPT.parse(matches);
            let address = RAW_ADDRESS_OPT.parse(matches);
            let public_key = RAW_PUBLIC_KEY_OPT.parse(matches);
            let public_key_hash = RAW_PUBLIC_KEY_HASH_OPT.parse(matches);
            let payment_address = RAW_PAYMENT_ADDRESS_OPT.parse(matches);
            let keys_only = LIST_FIND_KEYS_ONLY.parse(matches);
            let addresses_only = LIST_FIND_ADDRESSES_ONLY.parse(matches);
            let decrypt = DECRYPT.parse(matches);
            let unsafe_show_secret = UNSAFE_SHOW_SECRET.parse(matches);
            Self {
                alias,
                address,
                public_key,
                public_key_hash,
                payment_address,
                keys_only,
                addresses_only,
                decrypt,
                unsafe_show_secret,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS_OPT
                    .def()
                    .help("An alias associated with the keys / addresses."),
            )
            .arg(
                RAW_ADDRESS_OPT.def().help(
                    "The bech32m encoded string of a transparent address.",
                ),
            )
            .arg(
                RAW_PUBLIC_KEY_OPT.def().help(
                    "A public key associated with the transparent keypair.",
                ),
            )
            .arg(RAW_PUBLIC_KEY_HASH_OPT.def().help(
                "A public key hash associated with the transparent keypair.",
            ))
            .arg(RAW_PAYMENT_ADDRESS_OPT.def().help(
                "The bech32m encoded string of a shielded payment address.",
            ))
            .group(
                ArgGroup::new("addr_find_args")
                    .args([
                        ALIAS_OPT.name,
                        RAW_ADDRESS_OPT.name,
                        RAW_PUBLIC_KEY_OPT.name,
                        RAW_PUBLIC_KEY_HASH_OPT.name,
                        RAW_PAYMENT_ADDRESS_OPT.name,
                    ])
                    .required(true),
            )
            .arg(LIST_FIND_KEYS_ONLY.def().help("Find keys only."))
            .arg(LIST_FIND_ADDRESSES_ONLY.def().help("Find addresses only."))
            .group(ArgGroup::new("only_group").args([
                LIST_FIND_KEYS_ONLY.name,
                LIST_FIND_ADDRESSES_ONLY.name,
            ]))
            .arg(PRE_GENESIS.def().help(
                "Use pre-genesis wallet, instead of for the current chain, if \
                 any.",
            ))
            .arg(DECRYPT.def().help("Decrypt keys that are encrypted."))
            .arg(
                UNSAFE_SHOW_SECRET
                    .def()
                    .help("UNSAFE: Print the secret / spending key."),
            )
        }
    }

    impl Args for KeyAddressAdd {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let value = VALUE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            Self {
                alias,
                alias_force,
                value,
                unsafe_dont_encrypt,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS
                    .def()
                    .help("An alias to be associated with the new entry."),
            )
            .arg(ALIAS_FORCE.def().help(
                "Override the alias without confirmation if it already exists.",
            ))
            .arg(VALUE.def().help(
                "Any value of the following:\n- transparent pool secret \
                 key\n- transparent pool public key\n- transparent pool \
                 address\n- shielded pool spending key\n- shielded pool \
                 viewing key\n- shielded pool payment address ",
            ))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(
                "UNSAFE: Do not encrypt the added keys. Do not use this for \
                 keys used in a live network.",
            ))
        }
    }

    impl Args for KeyAddressRemove {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let do_it = DO_IT.parse(matches);
            Self { alias, do_it }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS.def().help("An alias to be removed."))
                .arg(DO_IT.def().help("Confirm alias removal.").required(true))
        }
    }

    impl Args for KeyExport {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            Self { alias }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS.def().help("The alias of the key you wish to export."),
            )
        }
    }

    impl Args for KeyImport {
        fn parse(matches: &ArgMatches) -> Self {
            let file_path = FILE_PATH.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            Self {
                alias,
                alias_force,
                file_path,
                unsafe_dont_encrypt,
            }
        }

        fn def(app: App) -> App {
            app.arg(FILE_PATH.def().help(
                "Path to the file containing the key you wish to import.",
            ))
            .arg(ALIAS.def().help("The alias assigned to the."))
            .arg(
                ALIAS_FORCE
                    .def()
                    .help("An alias to be associated with the imported entry."),
            )
            .arg(UNSAFE_DONT_ENCRYPT.def().help(
                "UNSAFE: Do not encrypt the imported keys. Do not use this \
                 for keys used in a live network.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct JoinNetwork {
        pub chain_id: ChainId,
        pub genesis_validator: Option<String>,
        pub pre_genesis_path: Option<PathBuf>,
        pub dont_prefetch_wasm: bool,
        pub allow_duplicate_ip: bool,
    }

    impl Args for JoinNetwork {
        fn parse(matches: &ArgMatches) -> Self {
            let chain_id = CHAIN_ID.parse(matches);
            let genesis_validator = GENESIS_VALIDATOR.parse(matches);
            let pre_genesis_path = PRE_GENESIS_PATH.parse(matches);
            let dont_prefetch_wasm = DONT_PREFETCH_WASM.parse(matches);
            let allow_duplicate_ip = ALLOW_DUPLICATE_IP.parse(matches);
            Self {
                chain_id,
                genesis_validator,
                pre_genesis_path,
                dont_prefetch_wasm,
                allow_duplicate_ip,
            }
        }

        fn def(app: App) -> App {
            app.arg(CHAIN_ID.def().help("The chain ID. The chain must be known in the repository: \
                                          https://github.com/heliaxdev/anoma-network-config"))
                .arg(GENESIS_VALIDATOR.def().help("The alias of the genesis validator that you want to set up as, if any."))
                .arg(PRE_GENESIS_PATH.def().help("The path to the pre-genesis directory for genesis validator, if any. Defaults to \"{base-dir}/pre-genesis/{genesis-validator}\"."))
            .arg(DONT_PREFETCH_WASM.def().help(
                "Do not pre-fetch WASM.",
            ))
            .arg(ALLOW_DUPLICATE_IP.def().help(
                "Toggle to disable guard against peers connecting from the \
                 same IP. This option shouldn't be used in mainnet.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct PkToTmAddress {
        pub public_key: common::PublicKey,
    }

    impl Args for PkToTmAddress {
        fn parse(matches: &ArgMatches) -> Self {
            let public_key = RAW_PUBLIC_KEY.parse(matches);
            Self { public_key }
        }

        fn def(app: App) -> App {
            app.arg(RAW_PUBLIC_KEY.def().help(
                "The consensus public key to be converted to Tendermint \
                 address.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct DefaultBaseDir {}

    impl Args for DefaultBaseDir {
        fn parse(_matches: &ArgMatches) -> Self {
            Self {}
        }

        fn def(app: App) -> App {
            app
        }
    }

    #[derive(Clone, Debug)]
    pub struct FetchWasms {
        pub chain_id: ChainId,
    }

    impl Args for FetchWasms {
        fn parse(matches: &ArgMatches) -> Self {
            let chain_id = CHAIN_ID.parse(matches);
            Self { chain_id }
        }

        fn def(app: App) -> App {
            app.arg(CHAIN_ID.def().help("The chain ID. The chain must be known in the https://github.com/heliaxdev/anoma-network-config repository, in which case it should have pre-built wasms available for download."))
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateWasm {
        pub code_path: PathBuf,
    }

    impl Args for ValidateWasm {
        fn parse(matches: &ArgMatches) -> Self {
            let code_path = CODE_PATH.parse(matches);
            Self { code_path }
        }

        fn def(app: App) -> App {
            app.arg(
                CODE_PATH
                    .def()
                    .help("The path to the wasm file to validate."),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitNetwork {
        pub templates_path: PathBuf,
        pub wasm_checksums_path: PathBuf,
        pub chain_id_prefix: ChainIdPrefix,
        pub genesis_time: DateTimeUtc,
        pub consensus_timeout_commit: Timeout,
        pub dont_archive: bool,
        pub archive_dir: Option<PathBuf>,
    }

    impl Args for InitNetwork {
        fn parse(matches: &ArgMatches) -> Self {
            let templates_path = TEMPLATES_PATH.parse(matches);
            let wasm_checksums_path = WASM_CHECKSUMS_PATH.parse(matches);
            let chain_id_prefix = CHAIN_ID_PREFIX.parse(matches);
            let genesis_time = GENESIS_TIME.parse(matches);
            let consensus_timeout_commit =
                CONSENSUS_TIMEOUT_COMMIT.parse(matches);
            let dont_archive = DONT_ARCHIVE.parse(matches);
            let archive_dir = ARCHIVE_DIR.parse(matches);
            Self {
                templates_path,
                wasm_checksums_path,
                chain_id_prefix,
                genesis_time,
                consensus_timeout_commit,
                dont_archive,
                archive_dir,
            }
        }

        fn def(app: App) -> App {
            app.arg(TEMPLATES_PATH.def().help(
                "Path to the directory with genesis templates to be used to \
                 initialize the network.",
            ))
            .arg(
                WASM_CHECKSUMS_PATH
                    .def()
                    .help("Path to the WASM checksums file."),
            )
            .arg(CHAIN_ID_PREFIX.def().help(
                "The chain ID prefix. Up to 19 alphanumeric, '.', '-' or '_' \
                 characters.",
            ))
            .arg(GENESIS_TIME.def().help(
                "The start time of the network in RFC 3339 and ISO 8601 \
                 format. For example: \"2021-12-31T00:00:00Z\".",
            ))
            .arg(CONSENSUS_TIMEOUT_COMMIT.def().help(
                "The Tendermint consensus timeout_commit configuration as \
                 e.g. `1s` or `1000ms`. Defaults to 10 seconds.",
            ))
            .arg(
                DONT_ARCHIVE
                    .def()
                    .help("Do NOT create the release archive."),
            )
            .arg(ARCHIVE_DIR.def().help(
                "Specify a directory into which to store the archive. Default \
                 is the current working directory.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveGenesisAddresses {
        pub genesis_txs_path: PathBuf,
    }

    impl Args for DeriveGenesisAddresses {
        fn parse(matches: &ArgMatches) -> Self {
            let genesis_txs_path = PATH.parse(matches);
            Self { genesis_txs_path }
        }

        fn def(app: App) -> App {
            app.arg(PATH.def().help("Path to the genesis txs toml file."))
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisEstablishedAccount {
        pub vp: String,
        pub wallet_aliases: Vec<String>,
        pub threshold: u8,
        pub output_path: PathBuf,
    }

    impl Args for InitGenesisEstablishedAccount {
        fn parse(matches: &ArgMatches) -> Self {
            use crate::config::genesis::utils::VP_USER;
            let wallet_aliases = ALIAS_MANY.parse(matches);
            let vp = VP.parse(matches).unwrap_or_else(|| VP_USER.to_string());
            let threshold = THRESHOLD.parse(matches).unwrap_or(1);
            let output_path = PATH.parse(matches);
            Self {
                wallet_aliases,
                vp,
                threshold,
                output_path,
            }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS_MANY.def().help(
                "Comma separated list of aliases of the keys to use from the \
                 wallet.",
            ))
            .arg(THRESHOLD.def().help(
                "The minimum number of signatures to be provided for \
                 authorization. Must be less than or equal to the maximum \
                 number of key aliases provided.",
            ))
            .arg(VP.def().help(
                "The validity predicate of the account. Defaults to `vp_user`.",
            ))
            .arg(PATH.def().help(
                "The path of the .toml file to write the established account \
                 transaction to. Overwrites the file if it exists.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenesisBond {
        pub source: GenesisAddress,
        pub validator: EstablishedAddress,
        pub bond_amount: token::DenominatedAmount,
        pub output: PathBuf,
    }

    impl Args for GenesisBond {
        fn parse(matches: &ArgMatches) -> Self {
            let validator = GENESIS_VALIDATOR_ADDRESS.parse(matches);
            let source =
                GENESIS_BOND_SOURCE.parse(matches).unwrap_or_else(|| {
                    GenesisAddress::EstablishedAddress(validator.clone())
                });
            let bond_amount = AMOUNT.parse(matches);
            let output = PATH.parse(matches);
            Self {
                source,
                validator,
                bond_amount,
                output,
            }
        }

        fn def(app: App) -> App {
            app.arg(GENESIS_VALIDATOR_ADDRESS.def().help("Validator address."))
                .arg(AMOUNT.def().help("Amount of tokens to stake in a bond."))
                .arg(GENESIS_BOND_SOURCE.def().help(
                    "Source address for delegations. For self-bonds, the \
                     validator is also the source.",
                ))
                .arg(
                    PATH.def()
                        .help("Output toml file to write transactions to."),
                )
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisValidator {
        pub alias: String,
        pub commission_rate: Dec,
        pub max_commission_rate_change: Dec,
        pub net_address: SocketAddr,
        pub unsafe_dont_encrypt: bool,
        pub key_scheme: SchemeType,
        pub self_bond_amount: token::DenominatedAmount,
        pub email: String,
        pub description: Option<String>,
        pub website: Option<String>,
        pub discord_handle: Option<String>,
        pub address: EstablishedAddress,
        pub tx_path: PathBuf,
    }

    impl Args for InitGenesisValidator {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let net_address = NET_ADDRESS.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let key_scheme = SCHEME.parse(matches);
            // this must be an amount of native tokens
            let self_bond_amount = SELF_BOND_AMOUNT.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let address = RAW_ADDRESS_ESTABLISHED.parse(matches);
            let tx_path = PATH.parse(matches);
            Self {
                alias,
                net_address,
                unsafe_dont_encrypt,
                key_scheme,
                commission_rate,
                max_commission_rate_change,
                self_bond_amount,
                email,
                description,
                website,
                discord_handle,
                tx_path,
                address,
            }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS.def().help("The validator address alias."))
                .arg(RAW_ADDRESS_ESTABLISHED.def().help(
                    "The address of an established account to be promoted to \
                     a validator.",
                ))
                .arg(PATH.def().help(
                    "The .toml file containing an established account tx from \
                     which to create a validator.",
                ))
                .arg(NET_ADDRESS.def().help(
                    "Static {host:port} of your validator node's P2P address. \
                     Namada uses port `26656` for P2P connections by default, \
                     but you can configure a different value.",
                ))
                .arg(COMMISSION_RATE.def().help(
                    "The commission rate charged by the validator for \
                     delegation rewards. This is a required parameter.",
                ))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. This is \
                     a required parameter.",
                ))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network.",
                ))
                .arg(SCHEME.def().help(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1.",
                ))
                .arg(
                    SELF_BOND_AMOUNT.def().help(
                        "The amount of native token to self-bond in PoS.",
                    ),
                )
                .arg(EMAIL.def().help(
                    "The email address of the validator. This is a required \
                     parameter.",
                ))
                .arg(DESCRIPTION_OPT.def().help(
                    "The validator's description. This is an optional \
                     parameter.",
                ))
                .arg(WEBSITE_OPT.def().help(
                    "The validator's website. This is an optional parameter.",
                ))
                .arg(DISCORD_OPT.def().help(
                    "The validator's discord handle. This is an optional \
                     parameter.",
                ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateGenesisTemplates {
        /// Templates dir
        pub path: PathBuf,
    }

    impl Args for ValidateGenesisTemplates {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            Self { path }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def()
                    .help("Path to the directory with the template files."),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestGenesis {
        /// Templates dir
        pub path: PathBuf,
        pub wasm_dir: PathBuf,
    }

    impl Args for TestGenesis {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            let wasm_dir = WASM_DIR.parse(matches).unwrap_or_default();
            Self { path, wasm_dir }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def()
                    .help("Path to the directory with the template files."),
            )
            .arg(WASM_DIR.def().help(
                "Optional wasm directory to provide as part of verifying \
                 genesis template files",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignGenesisTxs {
        pub path: PathBuf,
        pub output: Option<PathBuf>,
        pub validator_alias: Option<String>,
        pub use_device: bool,
    }

    impl Args for SignGenesisTxs {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            let output = OUTPUT.parse(matches);
            let validator_alias = ALIAS_OPT.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            Self {
                path,
                output,
                validator_alias,
                use_device,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def()
                    .help("Path to the unsigned transactions TOML file."),
            )
            .arg(OUTPUT.def().help(
                "Save the output to a TOML file. When not supplied, the \
                 signed transactions will be printed to stdout instead.",
            ))
            .arg(
                ALIAS_OPT
                    .def()
                    .help("Optional alias to a validator wallet."),
            )
            .arg(USE_DEVICE.def().help(
                "Derive an address and public key from the seed stored on the \
                 connected hardware wallet.",
            ))
        }
    }
}

pub fn namada_cli() -> (cmds::Namada, String) {
    let app = namada_app();
    let matches = app.get_matches();
    let raw_sub_cmd =
        matches.subcommand().map(|(raw, _matches)| raw.to_string());
    let result = cmds::Namada::parse(&matches);
    match (result, raw_sub_cmd) {
        (Some(cmd), Some(raw_sub)) => return (cmd, raw_sub),
        _ => {
            namada_app().print_help().unwrap();
        }
    }
    safe_exit(2);
}

pub fn namada_node_cli() -> Result<(cmds::NamadaNode, Context)> {
    let app = namada_node_app();
    cmds::NamadaNode::parse_or_print_help(app)
}

#[allow(clippy::large_enum_variant)]
pub enum NamadaClient {
    WithoutContext(cmds::Utils, args::Global),
    WithContext(Box<(cmds::NamadaClientWithContext, Context)>),
}

pub fn namada_client_cli() -> Result<NamadaClient> {
    let app = namada_client_app();
    let matches = app.clone().get_matches();
    match Cmd::parse(&matches) {
        Some(cmd) => {
            let global_args = args::Global::parse(&matches);
            match cmd {
                cmds::NamadaClient::WithContext(sub_cmd) => {
                    let context = Context::new::<CliIo>(global_args)?;
                    Ok(NamadaClient::WithContext(Box::new((sub_cmd, context))))
                }
                cmds::NamadaClient::WithoutContext(sub_cmd) => {
                    Ok(NamadaClient::WithoutContext(sub_cmd, global_args))
                }
            }
        }
        None => {
            let mut app = app;
            app.print_help().unwrap();
            safe_exit(2);
        }
    }
}

pub fn namada_wallet_cli() -> Result<(cmds::NamadaWallet, Context)> {
    let app = namada_wallet_app();
    cmds::NamadaWallet::parse_or_print_help(app)
}

pub enum NamadaRelayer {
    EthBridgePoolWithCtx(Box<(cmds::EthBridgePoolWithCtx, Context)>),
    EthBridgePoolWithoutCtx(cmds::EthBridgePoolWithoutCtx),
    ValidatorSet(cmds::ValidatorSet),
}

pub fn namada_relayer_cli() -> Result<NamadaRelayer> {
    let app = namada_relayer_app();
    let matches = app.clone().get_matches();
    match Cmd::parse(&matches) {
        Some(cmd) => match cmd {
            cmds::NamadaRelayer::EthBridgePool(
                cmds::EthBridgePool::WithContext(sub_cmd),
            ) => {
                let global_args = args::Global::parse(&matches);
                let context = Context::new::<StdIo>(global_args)?;
                Ok(NamadaRelayer::EthBridgePoolWithCtx(Box::new((
                    sub_cmd, context,
                ))))
            }
            cmds::NamadaRelayer::EthBridgePool(
                cmds::EthBridgePool::WithoutContext(sub_cmd),
            ) => Ok(NamadaRelayer::EthBridgePoolWithoutCtx(sub_cmd)),
            cmds::NamadaRelayer::ValidatorSet(sub_cmd) => {
                Ok(NamadaRelayer::ValidatorSet(sub_cmd))
            }
        },
        None => {
            let mut app = app;
            app.print_help().unwrap();
            safe_exit(2);
        }
    }
}

fn namada_app() -> App {
    let app = App::new(APP_NAME)
        .version(namada_version())
        .about("Namada command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::Namada::add_sub(args::Global::def(app))
}

fn namada_node_app() -> App {
    let app = App::new(APP_NAME)
        .version(namada_version())
        .about("Namada node command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaNode::add_sub(args::Global::def(app))
}

fn namada_client_app() -> App {
    let app = App::new(APP_NAME)
        .version(namada_version())
        .about("Namada client command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaClient::add_sub(args::Global::def(app))
}

fn namada_wallet_app() -> App {
    let app = App::new(APP_NAME)
        .version(namada_version())
        .about("Namada wallet command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaWallet::add_sub(args::Global::def(app))
}

fn namada_relayer_app() -> App {
    let app = App::new(APP_NAME)
        .version(namada_version())
        .about("Namada relayer command line interface.")
        .subcommand_required(true);
    cmds::NamadaRelayer::add_sub(args::Global::def(app))
}
