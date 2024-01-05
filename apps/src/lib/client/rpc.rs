//! Client RPC queries

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, read_dir};
use std::io;
use std::iter::Iterator;
use std::str::FromStr;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXLOWER;
use itertools::Either;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::core::ledger::governance::cli::offline::{
    find_offline_proposal, find_offline_votes, read_offline_files,
    OfflineSignedProposal, OfflineVote,
};
use namada::core::ledger::governance::parameters::GovernanceParameters;
use namada::core::ledger::governance::storage::keys as governance_storage;
use namada::core::ledger::governance::storage::proposal::{
    StoragePgfFunding, StorageProposal,
};
use namada::core::ledger::governance::utils::{
    compute_proposal_result, ProposalVotes, TallyType, TallyVote, VotePower,
};
use namada::core::ledger::pgf::parameters::PgfParameters;
use namada::core::ledger::pgf::storage::steward::StewardDetail;
use namada::ledger::events::Event;
use namada::ledger::ibc::storage::{
    ibc_denom_key, ibc_denom_key_prefix, is_ibc_denom_key,
};
use namada::ledger::parameters::{storage as param_storage, EpochDuration};
use namada::ledger::pos::types::{CommissionPair, Slash};
use namada::ledger::pos::PosParams;
use namada::ledger::queries::RPC;
use namada::proof_of_stake::types::{ValidatorState, WeightedValidator};
use namada::types::address::{Address, InternalAddress, MASP};
use namada::types::hash::Hash;
use namada::types::ibc::{is_ibc_denom, IbcTokenHash};
use namada::types::io::Io;
use namada::types::key::*;
use namada::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use namada::types::storage::{BlockHeight, BlockResults, Epoch, Key, KeySeg};
use namada::types::token::{Change, MaspDenom};
use namada::types::{storage, token};
use namada_sdk::error::{is_pinned_error, Error, PinnedBalanceError};
use namada_sdk::masp::{Conversions, MaspAmount, MaspChange};
use namada_sdk::proof_of_stake::types::ValidatorMetaData;
use namada_sdk::rpc::{
    self, enriched_bonds_and_unbonds, query_epoch, TxResponse,
};
use namada_sdk::tx::{display_inner_resp, display_wrapper_resp_and_get_result};
use namada_sdk::wallet::AddressVpType;
use namada_sdk::{display, display_line, edisplay_line, error, prompt, Namada};
use tokio::time::Instant;

use crate::cli::{self, args};
use crate::facade::tendermint::merkle::proof::ProofOps;
use crate::facade::tendermint_rpc::error::Error as TError;

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status(
    namada: &impl Namada,
    status: namada_sdk::rpc::TxEventQuery<'_>,
    deadline: Instant,
) -> Event {
    rpc::query_tx_status(namada, status, deadline)
        .await
        .unwrap()
}

/// Query and print the epoch of the last committed block
pub async fn query_and_print_epoch(context: &impl Namada) -> Epoch {
    let epoch = rpc::query_epoch(context.client()).await.unwrap();
    display_line!(context.io(), "Last committed epoch: {}", epoch);
    epoch
}

/// Query the last committed block
pub async fn query_block(context: &impl Namada) {
    let block = namada_sdk::rpc::query_block(context.client())
        .await
        .unwrap();
    match block {
        Some(block) => {
            display_line!(
                context.io(),
                "Last committed block ID: {}, height: {}, time: {}",
                block.hash,
                block.height,
                block.time
            );
        }
        None => {
            display_line!(context.io(), "No block has been committed yet.");
        }
    }
}

/// Query the results of the last committed block
pub async fn query_results<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    _args: args::Query,
) -> Vec<BlockResults> {
    unwrap_client_response::<C, Vec<BlockResults>>(
        RPC.shell().read_results(client).await,
    )
}

/// Query the specified accepted transfers from the ledger
pub async fn query_transfers(
    context: &impl Namada,
    args: args::QueryTransfers,
) {
    let query_token = args.token;
    let wallet = context.wallet().await;
    let query_owner = args.owner.map_or_else(
        || Either::Right(wallet.get_addresses().into_values().collect()),
        Either::Left,
    );
    let mut shielded = context.shielded_mut().await;
    let _ = shielded.load().await;
    // Obtain the effects of all shielded and transparent transactions
    let transfers = shielded
        .query_tx_deltas(
            context.client(),
            &query_owner,
            &query_token,
            &wallet.get_viewing_keys(),
        )
        .await
        .unwrap();
    // To facilitate lookups of human-readable token names
    let vks = wallet.get_viewing_keys();
    // To enable ExtendedFullViewingKeys to be displayed instead of ViewingKeys
    let fvk_map: HashMap<_, _> = vks
        .values()
        .map(|fvk| (ExtendedFullViewingKey::from(*fvk).fvk.vk, fvk))
        .collect();
    // Now display historical shielded and transparent transactions
    for ((height, idx), (epoch, tfer_delta, tx_delta)) in transfers {
        // Check if this transfer pertains to the supplied owner
        let mut relevant = match &query_owner {
            Either::Left(BalanceOwner::FullViewingKey(fvk)) => tx_delta
                .contains_key(&ExtendedFullViewingKey::from(*fvk).fvk.vk),
            Either::Left(BalanceOwner::Address(owner)) => {
                tfer_delta.contains_key(owner)
            }
            Either::Left(BalanceOwner::PaymentAddress(_owner)) => false,
            Either::Right(_) => true,
        };
        // Realize and decode the shielded changes to enable relevance check
        let mut shielded_accounts = HashMap::new();
        for (acc, amt) in tx_delta {
            // Realize the rewards that would have been attained upon the
            // transaction's reception
            let amt = shielded
                .compute_exchanged_amount(
                    context.client(),
                    context.io(),
                    amt,
                    epoch,
                    Conversions::new(),
                )
                .await
                .unwrap()
                .0;
            let dec =
                shielded.decode_amount(context.client(), amt, epoch).await;
            shielded_accounts.insert(acc, dec);
        }
        // Check if this transfer pertains to the supplied token
        relevant &= match &query_token {
            Some(token) => {
                let check = |(tok, chg): (&Address, &Change)| {
                    tok == token && !chg.is_zero()
                };
                tfer_delta.values().cloned().any(
                    |MaspChange { ref asset, change }| check((asset, &change)),
                ) || shielded_accounts
                    .values()
                    .cloned()
                    .any(|x| x.iter().any(check))
            }
            None => true,
        };
        // Filter out those entries that do not satisfy user query
        if !relevant {
            continue;
        }
        display_line!(
            context.io(),
            "Height: {}, Index: {}, Transparent Transfer:",
            height,
            idx
        );
        // Display the transparent changes first
        for (account, MaspChange { ref asset, change }) in tfer_delta {
            if account != MASP {
                display!(context.io(), "  {}:", account);
                let token_alias =
                    lookup_token_alias(context, asset, &account).await;
                let sign = match change.cmp(&Change::zero()) {
                    Ordering::Greater => "+",
                    Ordering::Less => "-",
                    Ordering::Equal => "",
                };
                display!(
                    context.io(),
                    " {}{} {}",
                    sign,
                    context.format_amount(asset, change.into()).await,
                    token_alias
                );
            }
            display_line!(context.io(), "");
        }
        // Then display the shielded changes afterwards
        // TODO: turn this to a display impl
        // (account, amt)
        for (account, masp_change) in shielded_accounts {
            if fvk_map.contains_key(&account) {
                display!(context.io(), "  {}:", fvk_map[&account]);
                for (token_addr, val) in masp_change {
                    let token_alias =
                        lookup_token_alias(context, &token_addr, &MASP).await;
                    let sign = match val.cmp(&Change::zero()) {
                        Ordering::Greater => "+",
                        Ordering::Less => "-",
                        Ordering::Equal => "",
                    };
                    display!(
                        context.io(),
                        " {}{} {}",
                        sign,
                        context.format_amount(&token_addr, val.into()).await,
                        token_alias,
                    );
                }
                display_line!(context.io(), "");
            }
        }
    }
}

/// Query the raw bytes of given storage key
pub async fn query_raw_bytes<N: Namada>(
    context: &N,
    args: args::QueryRawBytes,
) {
    let response = unwrap_client_response::<N::Client, _>(
        RPC.shell()
            .storage_value(
                context.client(),
                None,
                None,
                false,
                &args.storage_key,
            )
            .await,
    );
    if !response.data.is_empty() {
        display_line!(
            context.io(),
            "Found data: 0x{}",
            HEXLOWER.encode(&response.data)
        );
    } else {
        display_line!(
            context.io(),
            "No data found for key {}",
            args.storage_key
        );
    }
}

/// Query token balance(s)
pub async fn query_balance(context: &impl Namada, args: args::QueryBalance) {
    // Query the balances of shielded or transparent account types depending on
    // the CLI arguments
    match &args.owner {
        Some(BalanceOwner::FullViewingKey(_viewing_key)) => {
            query_shielded_balance(context, args).await
        }
        Some(BalanceOwner::Address(_owner)) => {
            query_transparent_balance(context, args).await
        }
        Some(BalanceOwner::PaymentAddress(_owner)) => {
            query_pinned_balance(context, args).await
        }
        None => {
            // Print pinned balance
            query_pinned_balance(context, args.clone()).await;
            // Print shielded balance
            query_shielded_balance(context, args.clone()).await;
            // Then print transparent balance
            query_transparent_balance(context, args).await;
        }
    };
}

/// Query token balance(s)
pub async fn query_transparent_balance(
    context: &impl Namada,
    args: args::QueryBalance,
) {
    let prefix = Key::from(
        Address::Internal(namada::types::address::InternalAddress::Multitoken)
            .to_db_key(),
    );
    match (args.token, args.owner) {
        (Some(base_token), Some(owner)) => {
            let owner = owner.address().unwrap();
            let tokens =
                query_tokens(context, Some(&base_token), Some(&owner)).await;
            for (token_alias, token) in tokens {
                let balance_key = token::balance_key(&token, &owner);
                match query_storage_value::<_, token::Amount>(
                    context.client(),
                    &balance_key,
                )
                .await
                {
                    Ok(balance) => {
                        let balance =
                            context.format_amount(&token, balance).await;
                        display_line!(
                            context.io(),
                            "{}: {}",
                            token_alias,
                            balance
                        );
                    }
                    Err(e) => {
                        display_line!(context.io(), "Querying error: {e}");
                        display_line!(
                            context.io(),
                            "No {} balance found for {}",
                            token_alias,
                            owner
                        )
                    }
                }
            }
        }
        (None, Some(owner)) => {
            let owner = owner.address().unwrap();
            let tokens = query_tokens(context, None, Some(&owner)).await;
            for (token_alias, token) in tokens {
                let balance =
                    get_token_balance(context.client(), &token, &owner).await;
                if !balance.is_zero() {
                    let balance = context.format_amount(&token, balance).await;
                    display_line!(context.io(), "{}: {}", token_alias, balance);
                }
            }
        }
        (Some(base_token), None) => {
            let tokens = query_tokens(context, Some(&base_token), None).await;
            for (_, token) in tokens {
                let prefix = token::balance_prefix(&token);
                let balances =
                    query_storage_prefix::<token::Amount>(context, &prefix)
                        .await;
                if let Some(balances) = balances {
                    print_balances(context, balances, Some(&token), None).await;
                }
            }
        }
        (None, None) => {
            let balances = query_storage_prefix(context, &prefix).await;
            if let Some(balances) = balances {
                print_balances(context, balances, None, None).await;
            }
        }
    }
}

/// Query the token pinned balance(s)
pub async fn query_pinned_balance(
    context: &impl Namada,
    args: args::QueryBalance,
) {
    // Map addresses to token names
    let wallet = context.wallet().await;
    let owners = if let Some(pa) = args.owner.and_then(|x| x.payment_address())
    {
        vec![pa]
    } else {
        wallet
            .get_payment_addrs()
            .into_values()
            .filter(PaymentAddress::is_pinned)
            .collect()
    };
    // Get the viewing keys with which to try note decryptions
    let viewing_keys: Vec<ViewingKey> = wallet
        .get_viewing_keys()
        .values()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    let _ = context.shielded_mut().await.load().await;
    // Print the token balances by payment address
    for owner in owners {
        let mut balance =
            Err(Error::from(PinnedBalanceError::InvalidViewingKey));
        // Find the viewing key that can recognize payments the current payment
        // address
        for vk in &viewing_keys {
            balance = context
                .shielded_mut()
                .await
                .compute_exchanged_pinned_balance(context, owner, vk)
                .await;
            if !is_pinned_error(&balance) {
                break;
            }
        }
        // If a suitable viewing key was not found, then demand it from the user
        if is_pinned_error(&balance) {
            let vk_str =
                prompt!(context.io(), "Enter the viewing key for {}: ", owner)
                    .await;
            let fvk = match ExtendedViewingKey::from_str(vk_str.trim()) {
                Ok(fvk) => fvk,
                _ => {
                    edisplay_line!(context.io(), "Invalid viewing key entered");
                    continue;
                }
            };
            let vk = ExtendedFullViewingKey::from(fvk).fvk.vk;
            // Use the given viewing key to decrypt pinned transaction data
            balance = context
                .shielded_mut()
                .await
                .compute_exchanged_pinned_balance(context, owner, &vk)
                .await
        }

        // Now print out the received quantities according to CLI arguments
        match (balance, args.token.as_ref()) {
            (Err(Error::Pinned(PinnedBalanceError::InvalidViewingKey)), _) => {
                display_line!(
                    context.io(),
                    "Supplied viewing key cannot decode transactions to given \
                     payment address."
                )
            }
            (
                Err(Error::Pinned(PinnedBalanceError::NoTransactionPinned)),
                _,
            ) => {
                display_line!(
                    context.io(),
                    "Payment address {} has not yet been consumed.",
                    owner
                )
            }
            (Err(other), _) => {
                display_line!(
                    context.io(),
                    "Error in Querying Pinned balance {}",
                    other
                )
            }
            (Ok((balance, epoch)), Some(base_token)) => {
                let tokens =
                    query_tokens(context, Some(base_token), None).await;
                for (token_alias, token) in &tokens {
                    let total_balance = balance
                        .get(&(epoch, token.clone()))
                        .cloned()
                        .unwrap_or_default();

                    if total_balance.is_zero() {
                        display_line!(
                            context.io(),
                            "Payment address {} was consumed during epoch {}. \
                             Received no shielded {}",
                            owner,
                            epoch,
                            token_alias
                        );
                    } else {
                        let formatted = context
                            .format_amount(token, total_balance.into())
                            .await;
                        display_line!(
                            context.io(),
                            "Payment address {} was consumed during epoch {}. \
                             Received {} {}",
                            owner,
                            epoch,
                            formatted,
                            token_alias,
                        );
                    }
                }
            }
            (Ok((balance, epoch)), None) => {
                let mut found_any = false;

                for ((_, token_addr), value) in balance
                    .iter()
                    .filter(|((token_epoch, _), _)| *token_epoch == epoch)
                {
                    if !found_any {
                        display_line!(
                            context.io(),
                            "Payment address {} was consumed during epoch {}. \
                             Received:",
                            owner,
                            epoch
                        );
                        found_any = true;
                    }
                    let formatted = context
                        .format_amount(token_addr, (*value).into())
                        .await;
                    let token_alias =
                        lookup_token_alias(context, token_addr, &MASP).await;
                    display_line!(
                        context.io(),
                        " {}: {}",
                        token_alias,
                        formatted,
                    );
                }
                if !found_any {
                    display_line!(
                        context.io(),
                        "Payment address {} was consumed during epoch {}. \
                         Received no shielded assets.",
                        owner,
                        epoch
                    );
                }
            }
        }
    }
}

async fn print_balances(
    context: &impl Namada,
    balances: impl Iterator<Item = (storage::Key, token::Amount)>,
    token: Option<&Address>,
    target: Option<&Address>,
) {
    let stdout = io::stdout();
    let mut w = stdout.lock();
    let wallet = context.wallet().await;

    let mut print_num = 0;
    let mut print_token = None;
    for (key, balance) in balances {
        // Get the token, the owner, and the balance with the token and the
        // owner
        let (t, o, s) = match token::is_any_token_balance_key(&key) {
            Some([tok, owner]) => (
                tok.clone(),
                owner.clone(),
                format!(
                    ": {}, owned by {}",
                    context.format_amount(tok, balance).await,
                    wallet.lookup_alias(owner)
                ),
            ),
            None => continue,
        };
        let token_alias = lookup_token_alias(context, &t, &o).await;
        // Get the token and the balance
        let (t, s) = match (token, target) {
            // the given token and the given target are the same as the
            // retrieved ones
            (Some(token), Some(target)) if t == *token && o == *target => {
                (t, s)
            }
            // the given token is the same as the retrieved one
            (Some(token), None) if t == *token => (t, s),
            // the given target is the same as the retrieved one
            (None, Some(target)) if o == *target => (t, s),
            // no specified token or target
            (None, None) => (t, s),
            // otherwise, this balance will not be printed
            _ => continue,
        };
        // Print the token if it isn't printed yet
        match &print_token {
            Some(token) if *token == t => {
                // the token has been already printed
            }
            _ => {
                display_line!(context.io(), &mut w; "Token {}", token_alias)
                    .unwrap();
                print_token = Some(t);
            }
        }
        // Print the balance
        display_line!(context.io(), &mut w; "{}", s).unwrap();
        print_num += 1;
    }

    if print_num == 0 {
        match (token, target) {
            (Some(_), Some(target)) | (None, Some(target)) => display_line!(
                context.io(),
                &mut w;
                "No balances owned by {}",
                wallet.lookup_alias(target)
            )
            .unwrap(),
            (Some(token), None) => {
                let token_alias = wallet.lookup_alias(token);
                display_line!(context.io(), &mut w; "No balances for token {}", token_alias).unwrap()
            }
            (None, None) => {
                display_line!(context.io(), &mut w; "No balances").unwrap()
            }
        }
    }
}

async fn lookup_token_alias(
    context: &impl Namada,
    token: &Address,
    owner: &Address,
) -> String {
    if let Address::Internal(InternalAddress::IbcToken(trace_hash)) = token {
        let ibc_denom_key =
            ibc_denom_key(owner.to_string(), trace_hash.to_string());
        match query_storage_value::<_, String>(context.client(), &ibc_denom_key)
            .await
        {
            Ok(ibc_denom) => get_ibc_denom_alias(context, ibc_denom).await,
            Err(_) => token.to_string(),
        }
    } else {
        context.wallet().await.lookup_alias(token)
    }
}

/// Returns pairs of token alias and token address
async fn query_tokens(
    context: &impl Namada,
    base_token: Option<&Address>,
    owner: Option<&Address>,
) -> BTreeMap<String, Address> {
    let wallet = context.wallet().await;
    let mut base_token = base_token;
    // Base tokens
    let mut tokens = match base_token {
        Some(base_token) => {
            let mut map = BTreeMap::new();
            if let Some(alias) = wallet.find_alias(base_token) {
                map.insert(alias.to_string(), base_token.clone());
            }
            map
        }
        None => wallet.tokens_with_aliases(),
    };

    // Check all IBC denoms if the token isn't an pre-existing token
    if tokens.is_empty() {
        base_token = None;
    }
    let prefixes = match (base_token, owner) {
        (Some(base_token), Some(owner)) => vec![
            ibc_denom_key_prefix(Some(base_token.to_string())),
            ibc_denom_key_prefix(Some(owner.to_string())),
        ],
        (Some(base_token), None) => {
            vec![ibc_denom_key_prefix(Some(base_token.to_string()))]
        }
        (None, Some(_)) => {
            // Check all IBC denoms because the owner might not know IBC token
            // transfers in the same chain
            vec![ibc_denom_key_prefix(None)]
        }
        (None, None) => vec![ibc_denom_key_prefix(None)],
    };

    for prefix in prefixes {
        let ibc_denoms = query_storage_prefix::<String>(context, &prefix).await;
        if let Some(ibc_denoms) = ibc_denoms {
            for (key, ibc_denom) in ibc_denoms {
                if let Some((_, hash)) = is_ibc_denom_key(&key) {
                    let ibc_denom_alias =
                        get_ibc_denom_alias(context, ibc_denom).await;
                    let hash: IbcTokenHash = hash.parse().expect(
                        "Parsing an IBC token hash from storage shouldn't fail",
                    );
                    let ibc_token =
                        Address::Internal(InternalAddress::IbcToken(hash));
                    tokens.insert(ibc_denom_alias, ibc_token);
                }
            }
        }
    }
    tokens
}

async fn get_ibc_denom_alias(
    context: &impl Namada,
    ibc_denom: impl AsRef<str>,
) -> String {
    let wallet = context.wallet().await;
    is_ibc_denom(&ibc_denom)
        .map(|(trace_path, base_token)| {
            let base_token_alias = match Address::decode(&base_token) {
                Ok(base_token) => wallet.lookup_alias(&base_token),
                Err(_) => base_token,
            };
            if trace_path.is_empty() {
                base_token_alias
            } else {
                format!("{}/{}", trace_path, base_token_alias)
            }
        })
        .unwrap_or(ibc_denom.as_ref().to_string())
}

/// Query Proposals
pub async fn query_proposal(context: &impl Namada, args: args::QueryProposal) {
    let current_epoch = query_and_print_epoch(context).await;

    if let Some(id) = args.proposal_id {
        let proposal =
            query_proposal_by_id(context.client(), id).await.unwrap();
        if let Some(proposal) = proposal {
            display_line!(
                context.io(),
                "{}",
                proposal.to_string_with_status(current_epoch)
            );
        } else {
            edisplay_line!(context.io(), "No proposal found with id: {}", id);
        }
    } else {
        let last_proposal_id_key = governance_storage::get_counter_key();
        let last_proposal_id: u64 =
            query_storage_value(context.client(), &last_proposal_id_key)
                .await
                .unwrap();

        let from_id = if last_proposal_id > 10 {
            last_proposal_id - 10
        } else {
            0
        };

        display_line!(context.io(), "id: {}", last_proposal_id);

        for id in from_id..last_proposal_id {
            let proposal = query_proposal_by_id(context.client(), id)
                .await
                .unwrap()
                .expect("Proposal should be written to storage.");
            display_line!(context.io(), "{}", proposal);
        }
    }
}

/// Query proposal by Id
pub async fn query_proposal_by_id<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Option<StorageProposal>, error::Error> {
    namada_sdk::rpc::query_proposal_by_id(client, proposal_id).await
}

/// Query token shielded balance(s)
pub async fn query_shielded_balance(
    context: &impl Namada,
    args: args::QueryBalance,
) {
    // Used to control whether balances for all keys or a specific key are
    // printed
    let owner = args.owner.and_then(|x| x.full_viewing_key());
    // Used to control whether conversions are automatically performed
    let no_conversions = args.no_conversions;
    // Viewing keys are used to query shielded balances. If a spending key is
    // provided, then convert to a viewing key first.
    let viewing_keys = match owner {
        Some(viewing_key) => vec![viewing_key],
        None => context
            .wallet()
            .await
            .get_viewing_keys()
            .values()
            .copied()
            .collect(),
    };
    {
        let mut shielded = context.shielded_mut().await;
        let _ = shielded.load().await;
        let fvks: Vec<_> = viewing_keys
            .iter()
            .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
            .collect();
        shielded.fetch(context.client(), &[], &fvks).await.unwrap();
        // Save the update state so that future fetches can be short-circuited
        let _ = shielded.save().await;
    }
    // The epoch is required to identify timestamped tokens
    let epoch = query_and_print_epoch(context).await;
    // Map addresses to token names
    match (args.token, owner.is_some()) {
        // Here the user wants to know the balance for a specific token
        (Some(base_token), true) => {
            let tokens =
                query_tokens(context, Some(&base_token), Some(&MASP)).await;
            for (token_alias, token) in tokens {
                // Query the multi-asset balance at the given spending key
                let viewing_key =
                    ExtendedFullViewingKey::from(viewing_keys[0]).fvk.vk;
                let balance: MaspAmount = if no_conversions {
                    context
                        .shielded_mut()
                        .await
                        .compute_shielded_balance(
                            context.client(),
                            &viewing_key,
                        )
                        .await
                        .unwrap()
                        .expect("context should contain viewing key")
                } else {
                    context
                        .shielded_mut()
                        .await
                        .compute_exchanged_balance(
                            context.client(),
                            context.io(),
                            &viewing_key,
                            epoch,
                        )
                        .await
                        .unwrap()
                        .expect("context should contain viewing key")
                };

                let total_balance = balance
                    .get(&(epoch, token.clone()))
                    .cloned()
                    .unwrap_or_default();
                if total_balance.is_zero() {
                    display_line!(
                        context.io(),
                        "No shielded {} balance found for given key",
                        token_alias
                    );
                } else {
                    display_line!(
                        context.io(),
                        "{}: {}",
                        token_alias,
                        context
                            .format_amount(
                                &token,
                                token::Amount::from(total_balance),
                            )
                            .await
                    );
                }
            }
        }
        // Here the user wants to know the balance of all tokens across users
        (None, false) => {
            // Maps asset types to balances divided by viewing key
            let mut balances = HashMap::new();
            for fvk in viewing_keys {
                // Query the multi-asset balance at the given spending key
                let viewing_key = ExtendedFullViewingKey::from(fvk).fvk.vk;
                let balance = if no_conversions {
                    context
                        .shielded_mut()
                        .await
                        .compute_shielded_balance(
                            context.client(),
                            &viewing_key,
                        )
                        .await
                        .unwrap()
                        .expect("context should contain viewing key")
                } else {
                    context
                        .shielded_mut()
                        .await
                        .compute_exchanged_balance(
                            context.client(),
                            context.io(),
                            &viewing_key,
                            epoch,
                        )
                        .await
                        .unwrap()
                        .expect("context should contain viewing key")
                };
                for (key, value) in balance.iter() {
                    if !balances.contains_key(key) {
                        balances.insert(key.clone(), Vec::new());
                    }
                    balances.get_mut(key).unwrap().push((fvk, *value));
                }
            }

            // Print non-zero balances whose asset types can be decoded
            // TODO Implement a function for this

            let mut balance_map = HashMap::new();
            for ((asset_epoch, token_addr), balances) in balances {
                if asset_epoch == epoch {
                    // remove this from here, should not be making the
                    // hashtable creation any uglier
                    if balances.is_empty() {
                        display_line!(
                            context.io(),
                            "No shielded {} balance found for any wallet key",
                            &token_addr
                        );
                    }
                    for (fvk, value) in balances {
                        balance_map.insert((fvk, token_addr.clone()), value);
                    }
                }
            }
            for ((fvk, token), token_balance) in balance_map {
                // Only assets with the current timestamp count
                let alias = lookup_token_alias(context, &token, &MASP).await;
                display_line!(context.io(), "Shielded Token {}:", alias);
                let formatted =
                    context.format_amount(&token, token_balance.into()).await;
                display_line!(
                    context.io(),
                    "  {}, owned by {}",
                    formatted,
                    fvk
                );
            }
        }
        // Here the user wants to know the balance for a specific token across
        // users
        (Some(base_token), false) => {
            let tokens = query_tokens(context, Some(&base_token), None).await;
            for (token_alias, token) in tokens {
                // Compute the unique asset identifier from the token address
                let token = token;
                let _asset_type = AssetType::new(
                    (token.clone(), epoch.0).serialize_to_vec().as_ref(),
                )
                .unwrap();
                let mut found_any = false;
                display_line!(context.io(), "Shielded Token {}:", token_alias);
                for fvk in &viewing_keys {
                    // Query the multi-asset balance at the given spending key
                    let viewing_key = ExtendedFullViewingKey::from(*fvk).fvk.vk;
                    let balance = if no_conversions {
                        context
                            .shielded_mut()
                            .await
                            .compute_shielded_balance(
                                context.client(),
                                &viewing_key,
                            )
                            .await
                            .unwrap()
                            .expect("context should contain viewing key")
                    } else {
                        context
                            .shielded_mut()
                            .await
                            .compute_exchanged_balance(
                                context.client(),
                                context.io(),
                                &viewing_key,
                                epoch,
                            )
                            .await
                            .unwrap()
                            .expect("context should contain viewing key")
                    };

                    for ((_, address), val) in balance.iter() {
                        if !val.is_zero() {
                            found_any = true;
                        }
                        let formatted =
                            context.format_amount(address, (*val).into()).await;
                        display_line!(
                            context.io(),
                            "  {}, owned by {}",
                            formatted,
                            fvk
                        );
                    }
                }
                if !found_any {
                    display_line!(
                        context.io(),
                        "No shielded {} balance found for any wallet key",
                        token_alias,
                    );
                }
            }
        }
        // Here the user wants to know all possible token balances for a key
        (None, true) => {
            // Query the multi-asset balance at the given spending key
            let viewing_key =
                ExtendedFullViewingKey::from(viewing_keys[0]).fvk.vk;
            if no_conversions {
                let balance = context
                    .shielded_mut()
                    .await
                    .compute_shielded_balance(context.client(), &viewing_key)
                    .await
                    .unwrap()
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                print_decoded_balance_with_epoch(context, balance).await;
            } else {
                let balance = context
                    .shielded_mut()
                    .await
                    .compute_exchanged_balance(
                        context.client(),
                        context.io(),
                        &viewing_key,
                        epoch,
                    )
                    .await
                    .unwrap()
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                print_decoded_balance(context, balance, epoch).await;
            }
        }
    }
}

pub async fn print_decoded_balance(
    context: &impl Namada,
    decoded_balance: MaspAmount,
    epoch: Epoch,
) {
    if decoded_balance.is_empty() {
        display_line!(context.io(), "No shielded balance found for given key");
    } else {
        for ((_, token_addr), amount) in decoded_balance
            .iter()
            .filter(|((token_epoch, _), _)| *token_epoch == epoch)
        {
            display_line!(
                context.io(),
                "{} : {}",
                lookup_token_alias(context, token_addr, &MASP).await,
                context.format_amount(token_addr, (*amount).into()).await,
            );
        }
    }
}

pub async fn print_decoded_balance_with_epoch(
    context: &impl Namada,
    decoded_balance: MaspAmount,
) {
    let tokens = context
        .wallet()
        .await
        .get_addresses_with_vp_type(AddressVpType::Token);
    if decoded_balance.is_empty() {
        display_line!(context.io(), "No shielded balance found for given key");
    }
    for ((epoch, token_addr), value) in decoded_balance.iter() {
        let asset_value = (*value).into();
        let alias = tokens
            .get(token_addr)
            .map(|a| a.to_string())
            .unwrap_or_else(|| token_addr.to_string());
        display_line!(
            context.io(),
            "{} | {} : {}",
            alias,
            epoch,
            context.format_amount(token_addr, asset_value).await,
        );
    }
}

/// Query token amount of owner.
pub async fn get_token_balance<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    token: &Address,
    owner: &Address,
) -> token::Amount {
    namada_sdk::rpc::get_token_balance(client, token, owner)
        .await
        .unwrap()
}

pub async fn query_proposal_result(
    context: &impl Namada,
    args: args::QueryProposalResult,
) {
    if args.proposal_id.is_some() {
        let proposal_id =
            args.proposal_id.expect("Proposal id should be defined.");
        let proposal = if let Some(proposal) =
            query_proposal_by_id(context.client(), proposal_id)
                .await
                .unwrap()
        {
            proposal
        } else {
            edisplay_line!(context.io(), "Proposal {} not found.", proposal_id);
            return;
        };

        let proposal_result_key =
            governance_storage::get_proposal_result_key(proposal_id);
        let proposal_result =
        // Try to directly query the result in storage first
            match query_storage_value(context.client(), &proposal_result_key).await {
                Ok(result) => result,
                Err(_) => {
                    // If failure, run the tally
                    let is_author_steward = query_pgf_stewards(context.client())
                        .await
                        .iter()
                        .any(|steward| steward.address.eq(&proposal.author));
                    let tally_type = proposal.get_tally_type(is_author_steward);
                    let total_voting_power = get_total_staked_tokens(
                        context.client(),
                        proposal.voting_end_epoch,
                    )
                    .await;

                    let votes = compute_proposal_votes(
                        context.client(),
                        proposal_id,
                        proposal.voting_end_epoch,
                    )
                    .await;

                    compute_proposal_result(
                        votes,
                        total_voting_power,
                        tally_type,
                    )
                }
            };

        display_line!(context.io(), "Proposal Id: {} ", proposal_id);
        display_line!(context.io(), "{:4}{}", "", proposal_result);
    } else {
        let proposal_folder = args.proposal_folder.expect(
            "The argument --proposal-folder is required with --offline.",
        );
        let data_directory = read_dir(&proposal_folder).unwrap_or_else(|_| {
            panic!(
                "Should be able to read {} directory.",
                proposal_folder.to_string_lossy()
            )
        });
        let files = read_offline_files(data_directory);
        let proposal_path = find_offline_proposal(&files);

        let proposal = if let Some(path) = proposal_path {
            let proposal_file =
                fs::File::open(path).expect("file should open read only");
            let proposal: OfflineSignedProposal =
                serde_json::from_reader(proposal_file)
                    .expect("file should be proper JSON");

            let author_account = rpc::get_account_info(
                context.client(),
                &proposal.proposal.author,
            )
            .await
            .unwrap()
            .expect("Account should exist.");

            let proposal = proposal.validate(
                &author_account.public_keys_map,
                author_account.threshold,
                false,
            );

            if proposal.is_ok() {
                proposal.unwrap()
            } else {
                edisplay_line!(
                    context.io(),
                    "The offline proposal is not valid."
                );
                return;
            }
        } else {
            edisplay_line!(
                context.io(),
                "Couldn't find a file name offline_proposal_*.json."
            );
            return;
        };

        let votes = find_offline_votes(&files)
            .iter()
            .map(|path| {
                let vote_file = fs::File::open(path).expect("");
                let vote: OfflineVote =
                    serde_json::from_reader(vote_file).expect("");
                vote
            })
            .collect::<Vec<OfflineVote>>();

        let proposal_votes =
            compute_offline_proposal_votes(context, &proposal, votes.clone())
                .await;
        let total_voting_power = get_total_staked_tokens(
            context.client(),
            proposal.proposal.tally_epoch,
        )
        .await;

        let proposal_result = compute_proposal_result(
            proposal_votes,
            total_voting_power,
            TallyType::TwoThirds,
        );

        display_line!(
            context.io(),
            "Proposal offline: {}",
            proposal.proposal.hash()
        );
        display_line!(context.io(), "Parsed {} votes.", votes.len());
        display_line!(context.io(), "{:4}{}", "", proposal_result);
    }
}

pub async fn query_account(context: &impl Namada, args: args::QueryAccount) {
    let account = rpc::get_account_info(context.client(), &args.owner)
        .await
        .unwrap();
    if let Some(account) = account {
        display_line!(context.io(), "Address: {}", account.address);
        display_line!(context.io(), "Threshold: {}", account.threshold);
        display_line!(context.io(), "Public keys:");
        for (public_key, _) in account.public_keys_map.pk_to_idx {
            display_line!(context.io(), "- {}", public_key);
        }
    } else {
        display_line!(context.io(), "No account exists for {}", args.owner);
    }
}

pub async fn query_pgf(context: &impl Namada, _args: args::QueryPgf) {
    let stewards = query_pgf_stewards(context.client()).await;
    let fundings = query_pgf_fundings(context.client()).await;

    match stewards.is_empty() {
        true => {
            display_line!(
                context.io(),
                "Pgf stewards: no stewards are currently set."
            )
        }
        false => {
            display_line!(context.io(), "Pgf stewards:");
            for steward in stewards {
                display_line!(context.io(), "{:4}- {}", "", steward.address);
                display_line!(context.io(), "{:4}  Reward distribution:", "");
                for (address, percentage) in steward.reward_distribution {
                    display_line!(
                        context.io(),
                        "{:6}- {} to {}",
                        "",
                        percentage,
                        address
                    );
                }
            }
        }
    }

    match fundings.is_empty() {
        true => {
            display_line!(
                context.io(),
                "Pgf fundings: no fundings are currently set."
            )
        }
        false => {
            display_line!(context.io(), "Pgf fundings:");
            for funding in fundings {
                display_line!(
                    context.io(),
                    "{:4}- {} for {}",
                    "",
                    funding.detail.target,
                    funding.detail.amount.to_string_native()
                );
            }
        }
    }
}

pub async fn query_protocol_parameters(
    context: &impl Namada,
    _args: args::QueryProtocolParameters,
) {
    let governance_parameters =
        query_governance_parameters(context.client()).await;
    display_line!(context.io(), "Governance Parameters\n");
    display_line!(
        context.io(),
        "{:4}Min. proposal fund: {}",
        "",
        governance_parameters.min_proposal_fund.to_string_native()
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal code size: {}",
        "",
        governance_parameters.max_proposal_code_size
    );
    display_line!(
        context.io(),
        "{:4}Min. proposal voting period: {}",
        "",
        governance_parameters.min_proposal_voting_period
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal period: {}",
        "",
        governance_parameters.max_proposal_period
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal content size: {}",
        "",
        governance_parameters.max_proposal_content_size
    );
    display_line!(
        context.io(),
        "{:4}Min. proposal grace epochs: {}",
        "",
        governance_parameters.min_proposal_grace_epochs
    );

    let pgf_parameters = query_pgf_parameters(context.client()).await;
    display_line!(context.io(), "Public Goods Funding Parameters\n");
    display_line!(
        context.io(),
        "{:4}Pgf inflation rate: {}",
        "",
        pgf_parameters.pgf_inflation_rate
    );
    display_line!(
        context.io(),
        "{:4}Steward inflation rate: {}",
        "",
        pgf_parameters.stewards_inflation_rate
    );

    display_line!(context.io(), "Protocol parameters");
    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration: EpochDuration =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Min. epoch duration: {}",
        "",
        epoch_duration.min_duration
    );
    display_line!(
        context.io(),
        "{:4}Min. number of blocks: {}",
        "",
        epoch_duration.min_num_of_blocks
    );

    let key = param_storage::get_max_expected_time_per_block_key();
    let max_block_duration: u64 = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Max. block duration: {}",
        "",
        max_block_duration
    );

    let key = param_storage::get_tx_whitelist_storage_key();
    let vp_whitelist: Vec<String> = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}VP whitelist: {:?}", "", vp_whitelist);

    let key = param_storage::get_tx_whitelist_storage_key();
    let tx_whitelist: Vec<String> = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Transactions whitelist: {:?}",
        "",
        tx_whitelist
    );

    let key = param_storage::get_max_block_gas_key();
    let max_block_gas: u64 = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}Max block gas: {:?}", "", max_block_gas);

    let key = param_storage::get_fee_unshielding_gas_limit_key();
    let fee_unshielding_gas_limit: u64 =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Fee unshielding gas limit: {:?}",
        "",
        fee_unshielding_gas_limit
    );

    let key = param_storage::get_fee_unshielding_descriptions_limit_key();
    let fee_unshielding_descriptions_limit: u64 =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Fee unshielding descriptions limit: {:?}",
        "",
        fee_unshielding_descriptions_limit
    );

    let key = param_storage::get_gas_cost_key();
    let gas_cost_table: BTreeMap<Address, token::Amount> =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}Gas cost table:", "");
    for (token, gas_cost) in gas_cost_table {
        display_line!(context.io(), "{:8}{}: {:?}", "", token, gas_cost);
    }

    display_line!(context.io(), "PoS parameters");
    let pos_params = query_pos_parameters(context.client()).await;
    display_line!(
        context.io(),
        "{:4}Block proposer reward: {}",
        "",
        pos_params.block_proposer_reward
    );
    display_line!(
        context.io(),
        "{:4}Block vote reward: {}",
        "",
        pos_params.block_vote_reward
    );
    display_line!(
        context.io(),
        "{:4}Duplicate vote minimum slash rate: {}",
        "",
        pos_params.duplicate_vote_min_slash_rate
    );
    display_line!(
        context.io(),
        "{:4}Light client attack minimum slash rate: {}",
        "",
        pos_params.light_client_attack_min_slash_rate
    );
    display_line!(
        context.io(),
        "{:4}Max. validator slots: {}",
        "",
        pos_params.max_validator_slots
    );
    display_line!(
        context.io(),
        "{:4}Pipeline length: {}",
        "",
        pos_params.pipeline_len
    );
    display_line!(
        context.io(),
        "{:4}Unbonding length: {}",
        "",
        pos_params.unbonding_len
    );
    display_line!(
        context.io(),
        "{:4}Votes per token: {}",
        "",
        pos_params.tm_votes_per_token
    );
}

pub async fn query_bond<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

pub async fn query_unbond_with_slashing<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    source: &Address,
    validator: &Address,
) -> HashMap<(Epoch, Epoch), token::Amount> {
    unwrap_client_response::<C, HashMap<(Epoch, Epoch), token::Amount>>(
        RPC.vp()
            .pos()
            .unbond_with_slashing(client, source, validator)
            .await,
    )
}

pub async fn query_pos_parameters<C: namada::ledger::queries::Client + Sync>(
    client: &C,
) -> PosParams {
    unwrap_client_response::<C, PosParams>(
        RPC.vp().pos().pos_params(client).await,
    )
}

pub async fn query_consensus_keys<C: namada::ledger::queries::Client + Sync>(
    client: &C,
) -> BTreeSet<common::PublicKey> {
    unwrap_client_response::<C, BTreeSet<common::PublicKey>>(
        RPC.vp().pos().consensus_key_set(client).await,
    )
}

pub async fn query_pgf_stewards<C: namada::ledger::queries::Client + Sync>(
    client: &C,
) -> Vec<StewardDetail> {
    unwrap_client_response::<C, _>(RPC.vp().pgf().stewards(client).await)
}

pub async fn query_pgf_fundings<C: namada::ledger::queries::Client + Sync>(
    client: &C,
) -> Vec<StoragePgfFunding> {
    unwrap_client_response::<C, _>(RPC.vp().pgf().funding(client).await)
}

pub async fn query_pgf_parameters<C: namada::ledger::queries::Client + Sync>(
    client: &C,
) -> PgfParameters {
    unwrap_client_response::<C, _>(RPC.vp().pgf().parameters(client).await)
}

pub async fn query_and_print_unbonds(
    context: &impl Namada,
    source: &Address,
    validator: &Address,
) {
    let unbonds =
        query_unbond_with_slashing(context.client(), source, validator).await;
    let current_epoch = query_epoch(context.client()).await.unwrap();

    let mut total_withdrawable = token::Amount::zero();
    let mut not_yet_withdrawable = HashMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        if withdraw_epoch <= current_epoch {
            total_withdrawable += amount;
        } else {
            let withdrawable_amount =
                not_yet_withdrawable.entry(withdraw_epoch).or_default();
            *withdrawable_amount += amount;
        }
    }
    if !total_withdrawable.is_zero() {
        display_line!(
            context.io(),
            "Total withdrawable now: {}.",
            total_withdrawable.to_string_native()
        );
    }
    if !not_yet_withdrawable.is_empty() {
        display_line!(context.io(), "Current epoch: {current_epoch}.");
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        display_line!(
            context.io(),
            "Amount {} withdrawable starting from epoch {withdraw_epoch}.",
            amount.to_string_native(),
        );
    }
}

pub async fn query_withdrawable_tokens<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .withdrawable_tokens(client, bond_source, validator, &epoch)
            .await,
    )
}

/// Query PoS bond(s) and unbond(s)
pub async fn query_bonds(
    context: &impl Namada,
    args: args::QueryBonds,
) -> std::io::Result<()> {
    let epoch = query_and_print_epoch(context).await;

    let source = args.owner;
    let validator = args.validator;

    let stdout = io::stdout();
    let mut w = stdout.lock();

    let bonds_and_unbonds = enriched_bonds_and_unbonds(
        context.client(),
        epoch,
        &source,
        &validator,
    )
    .await
    .unwrap();

    for (bond_id, details) in &bonds_and_unbonds.data {
        let bond_type = if bond_id.source == bond_id.validator {
            format!("Self-bonds from {}", bond_id.validator)
        } else {
            format!(
                "Delegations from {} to {}",
                bond_id.source, bond_id.validator
            )
        };
        display_line!(context.io(), &mut w; "{}:", bond_type)?;
        for bond in &details.data.bonds {
            display_line!(
                context.io(),
                &mut w;
                "  Remaining active bond from epoch {}: Δ {}",
                bond.start,
                bond.amount.to_string_native()
            )?;
        }
        if !details.bonds_total.is_zero() {
            display_line!(
                context.io(),
                &mut w;
                "Active (slashed) bonds total: {}",
                details.bonds_total_active().to_string_native()
            )?;
        }
        display_line!(context.io(), &mut w; "Bonds total: {}", details.bonds_total.to_string_native())?;
        display_line!(context.io(), &mut w; "")?;

        if !details.data.unbonds.is_empty() {
            let bond_type = if bond_id.source == bond_id.validator {
                format!("Unbonded self-bonds from {}", bond_id.validator)
            } else {
                format!("Unbonded delegations from {}", bond_id.source)
            };
            display_line!(context.io(), &mut w; "{}:", bond_type)?;
            for unbond in &details.data.unbonds {
                display_line!(
                    context.io(),
                    &mut w;
                    "  Withdrawable from epoch {} (active from {}): Δ {}",
                    unbond.withdraw,
                    unbond.start,
                    unbond.amount.to_string_native()
                )?;
            }
            display_line!(
                context.io(),
                &mut w;
                "Unbonded total: {}",
                details.unbonds_total.to_string_native()
            )?;
        }
        display_line!(
            context.io(),
            &mut w;
            "Withdrawable total: {}",
            details.total_withdrawable.to_string_native()
        )?;
        display_line!(context.io(), &mut w; "")?;
    }
    if bonds_and_unbonds.bonds_total != bonds_and_unbonds.bonds_total_slashed {
        display_line!(
            context.io(),
            &mut w;
            "All bonds total active: {}",
            bonds_and_unbonds.bonds_total_active().to_string_native()
        )?;
    }
    display_line!(
        context.io(),
        &mut w;
        "All bonds total: {}",
        bonds_and_unbonds.bonds_total.to_string_native()
    )?;

    if bonds_and_unbonds.unbonds_total
        != bonds_and_unbonds.unbonds_total_slashed
    {
        display_line!(
            context.io(),
            &mut w;
            "All unbonds total active: {}",
            bonds_and_unbonds.unbonds_total_active().to_string_native()
        )?;
    }
    display_line!(
        context.io(),
        &mut w;
        "All unbonds total: {}",
        bonds_and_unbonds.unbonds_total.to_string_native()
    )?;
    display_line!(
        context.io(),
        &mut w;
        "All unbonds total withdrawable: {}",
        bonds_and_unbonds.total_withdrawable.to_string_native()
    )?;
    Ok(())
}

/// Query PoS bonded stake
pub async fn query_bonded_stake<N: Namada>(
    context: &N,
    args: args::QueryBondedStake,
) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_and_print_epoch(context).await,
    };

    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find bonded stake for the given validator
            let stake =
                get_validator_stake(context.client(), epoch, &validator).await;
            match stake {
                Some(stake) => {
                    // TODO: show if it's in consensus set, below capacity, or
                    // below threshold set
                    display_line!(
                        context.io(),
                        "Bonded stake of validator {validator}: {}",
                        stake.to_string_native()
                    )
                }
                None => {
                    display_line!(
                        context.io(),
                        "No bonded stake found for {validator}"
                    );
                }
            }
        }
        None => {
            let consensus: BTreeSet<WeightedValidator> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp()
                        .pos()
                        .consensus_validator_set(context.client(), &Some(epoch))
                        .await,
                );
            let below_capacity: BTreeSet<WeightedValidator> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp()
                        .pos()
                        .below_capacity_validator_set(
                            context.client(),
                            &Some(epoch),
                        )
                        .await,
                );

            // Iterate all validators
            let stdout = io::stdout();
            let mut w = stdout.lock();

            display_line!(context.io(), &mut w; "Consensus validators:")
                .unwrap();
            for val in consensus.into_iter().rev() {
                display_line!(
                    context.io(),
                    &mut w;
                    "  {}: {}",
                    val.address.encode(),
                    val.bonded_stake.to_string_native()
                )
                .unwrap();
            }
            if !below_capacity.is_empty() {
                display_line!(context.io(), &mut w; "Below capacity validators:")
                    .unwrap();
                for val in below_capacity.into_iter().rev() {
                    display_line!(
                        context.io(),
                        &mut w;
                        "  {}: {}",
                        val.address.encode(),
                        val.bonded_stake.to_string_native()
                    )
                    .unwrap();
                }
            }
        }
    }

    let total_staked_tokens =
        get_total_staked_tokens(context.client(), epoch).await;
    display_line!(
        context.io(),
        "Total bonded stake: {}",
        total_staked_tokens.to_string_native()
    );
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Option<CommissionPair> {
    unwrap_client_response::<C, Option<CommissionPair>>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query and return validator's metadata
pub async fn query_metadata<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    validator: &Address,
) -> Option<ValidatorMetaData> {
    unwrap_client_response::<C, Option<ValidatorMetaData>>(
        RPC.vp().pos().validator_metadata(client, validator).await,
    )
}

/// Query and return validator's state
pub async fn query_validator_state<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Option<ValidatorState> {
    unwrap_client_response::<C, Option<ValidatorState>>(
        RPC.vp()
            .pos()
            .validator_state(client, validator, &epoch)
            .await,
    )
}

/// Query and return the available reward tokens corresponding to the bond
pub async fn query_rewards<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Address,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp().pos().rewards(client, validator, source).await,
    )
}

/// Query a validator's state information
pub async fn query_and_print_validator_state(
    context: &impl Namada,
    args: args::QueryValidatorState,
) {
    let validator = args.validator;
    let state: Option<ValidatorState> =
        query_validator_state(context.client(), &validator, args.epoch).await;

    match state {
        Some(state) => match state {
            ValidatorState::Consensus => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the consensus set"
                )
            }
            ValidatorState::BelowCapacity => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the below-capacity set"
                )
            }
            ValidatorState::BelowThreshold => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the below-threshold set"
                )
            }
            ValidatorState::Inactive => {
                display_line!(context.io(), "Validator {validator} is inactive")
            }
            ValidatorState::Jailed => {
                display_line!(context.io(), "Validator {validator} is jailed")
            }
        },
        None => display_line!(
            context.io(),
            "Validator {validator} is either not a validator, or an epoch \
             before the current epoch has been queried (and the validator \
             state information is no longer stored)"
        ),
    }
}

/// Query PoS validator's commission rate information
pub async fn query_and_print_commission_rate(
    context: &impl Namada,
    args: args::QueryCommissionRate,
) {
    let validator = args.validator;

    let info: Option<CommissionPair> =
        query_commission_rate(context.client(), &validator, args.epoch).await;
    match info {
        Some(CommissionPair {
            commission_rate: rate,
            max_commission_change_per_epoch: change,
        }) => {
            display_line!(
                context.io(),
                "Validator {} commission rate: {}, max change per epoch: {}",
                validator.encode(),
                rate,
                change
            );
        }
        None => {
            display_line!(
                context.io(),
                "Address {} is not a validator (did not find commission rate \
                 and max change)",
                validator.encode(),
            );
        }
    }
}

/// Query PoS validator's metadata
pub async fn query_and_print_metadata(
    context: &impl Namada,
    args: args::QueryMetaData,
) {
    let validator = args.validator;

    let metadata: Option<ValidatorMetaData> =
        query_metadata(context.client(), &validator).await;

    match metadata {
        Some(ValidatorMetaData {
            email,
            description,
            website,
            discord_handle,
        }) => {
            display_line!(
                context.io(),
                "Validator {} metadata:\nEmail: {}",
                validator.encode(),
                email
            );
            if let Some(description) = description {
                display_line!(context.io(), "Description: {}", description);
            } else {
                display_line!(context.io(), "No description");
            }
            if let Some(website) = website {
                display_line!(context.io(), "Website: {}", website);
            } else {
                display_line!(context.io(), "No website");
            }
            if let Some(discord_handle) = discord_handle {
                display_line!(
                    context.io(),
                    "Discord handle: {}",
                    discord_handle
                );
            } else {
                display_line!(context.io(), "No discord handle");
            }
        }
        None => display_line!(
            context.io(),
            "Validator {} does not have an email set and may not exist",
            validator.encode()
        ),
    }

    // Get commission rate info for the current epoch
    let info: Option<CommissionPair> =
        query_commission_rate(context.client(), &validator, None).await;
    match info {
        Some(CommissionPair {
            commission_rate: rate,
            max_commission_change_per_epoch: change,
        }) => {
            display_line!(
                context.io(),
                "Validator {} commission rate: {}, max change per epoch: {}",
                validator.encode(),
                rate,
                change
            );
        }
        None => {
            display_line!(
                context.io(),
                "Address {} is not a validator (did not find commission rate \
                 and max change)",
                validator.encode(),
            );
        }
    }
}

/// Query PoS slashes
pub async fn query_slashes<N: Namada>(context: &N, args: args::QuerySlashes) {
    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find slashes for the given validator
            let slashes: Vec<Slash> = unwrap_client_response::<N::Client, _>(
                RPC.vp()
                    .pos()
                    .validator_slashes(context.client(), &validator)
                    .await,
            );
            if !slashes.is_empty() {
                display_line!(context.io(), "Processed slashes:");
                let stdout = io::stdout();
                let mut w = stdout.lock();
                for slash in slashes {
                    display_line!(
                        context.io(),
                        &mut w;
                        "Infraction epoch {}, block height {}, type {}, rate \
                         {}",
                        slash.epoch,
                        slash.block_height,
                        slash.r#type,
                        slash.rate
                    )
                    .unwrap();
                }
            } else {
                display_line!(
                    context.io(),
                    "No processed slashes found for {}",
                    validator.encode()
                )
            }
            // Find enqueued slashes to be processed in the future for the given
            // validator
            let enqueued_slashes: HashMap<
                Address,
                BTreeMap<Epoch, Vec<Slash>>,
            > = unwrap_client_response::<N::Client, _>(
                RPC.vp().pos().enqueued_slashes(context.client()).await,
            );
            let enqueued_slashes = enqueued_slashes.get(&validator).cloned();
            if let Some(enqueued) = enqueued_slashes {
                display_line!(
                    context.io(),
                    "\nEnqueued slashes for future processing"
                );
                for (epoch, slashes) in enqueued {
                    display_line!(
                        context.io(),
                        "To be processed in epoch {}",
                        epoch
                    );
                    for slash in slashes {
                        let stdout = io::stdout();
                        let mut w = stdout.lock();
                        display_line!(
                            context.io(),
                            &mut w;
                            "Infraction epoch {}, block height {}, type {}",
                            slash.epoch, slash.block_height, slash.r#type,
                        )
                        .unwrap();
                    }
                }
            } else {
                display_line!(
                    context.io(),
                    "No enqueued slashes found for {}",
                    validator.encode()
                )
            }
        }
        None => {
            let all_slashes: HashMap<Address, Vec<Slash>> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp().pos().slashes(context.client()).await,
                );

            if !all_slashes.is_empty() {
                let stdout = io::stdout();
                let mut w = stdout.lock();
                display_line!(context.io(), "Processed slashes:");
                for (validator, slashes) in all_slashes.into_iter() {
                    for slash in slashes {
                        display_line!(
                            context.io(),
                            &mut w;
                            "Infraction epoch {}, block height {}, rate {}, \
                             type {}, validator {}",
                            slash.epoch,
                            slash.block_height,
                            slash.rate,
                            slash.r#type,
                            validator,
                        )
                        .unwrap();
                    }
                }
            } else {
                display_line!(context.io(), "No processed slashes found")
            }

            // Find enqueued slashes to be processed in the future for the given
            // validator
            let enqueued_slashes: HashMap<
                Address,
                BTreeMap<Epoch, Vec<Slash>>,
            > = unwrap_client_response::<N::Client, _>(
                RPC.vp().pos().enqueued_slashes(context.client()).await,
            );
            if !enqueued_slashes.is_empty() {
                display_line!(
                    context.io(),
                    "\nEnqueued slashes for future processing"
                );
                for (validator, slashes_by_epoch) in enqueued_slashes {
                    for (epoch, slashes) in slashes_by_epoch {
                        display_line!(
                            context.io(),
                            "\nTo be processed in epoch {}",
                            epoch
                        );
                        for slash in slashes {
                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            display_line!(
                                context.io(),
                                &mut w;
                                "Infraction epoch {}, block height {}, type \
                                 {}, validator {}",
                                slash.epoch,
                                slash.block_height,
                                slash.r#type,
                                validator
                            )
                            .unwrap();
                        }
                    }
                }
            } else {
                display_line!(
                    context.io(),
                    "\nNo enqueued slashes found for future processing"
                )
            }
        }
    }
}

pub async fn query_and_print_rewards<N: Namada>(
    context: &N,
    args: args::QueryRewards,
) {
    let (source, validator) = (args.source, args.validator);

    let rewards = query_rewards(context.client(), &source, &validator).await;
    display_line!(
        context.io(),
        "Current rewards available for claim: {} NAM",
        rewards.to_string_native()
    );
}

pub async fn query_delegations<N: Namada>(
    context: &N,
    args: args::QueryDelegations,
) {
    let owner = args.owner;
    let delegations: HashSet<Address> = unwrap_client_response::<N::Client, _>(
        RPC.vp()
            .pos()
            .delegation_validators(context.client(), &owner)
            .await,
    );
    if delegations.is_empty() {
        display_line!(context.io(), "No delegations found");
    } else {
        display_line!(context.io(), "Found delegations to:");
        for delegation in delegations {
            display_line!(context.io(), "  {delegation}");
        }
    }
}

pub async fn query_find_validator<N: Namada>(
    context: &N,
    args: args::QueryFindValidator,
) {
    let args::QueryFindValidator {
        query: _,
        tm_addr,
        mut validator_addr,
    } = args;
    if let Some(tm_addr) = tm_addr {
        if tm_addr.len() != 40 {
            edisplay_line!(
                context.io(),
                "Expected 40 characters in Tendermint address, got {}",
                tm_addr.len()
            );
            cli::safe_exit(1);
        }
        let tm_addr = tm_addr.to_ascii_uppercase();
        let validator = unwrap_client_response::<N::Client, _>(
            RPC.vp()
                .pos()
                .validator_by_tm_addr(context.client(), &tm_addr)
                .await,
        );
        match validator {
            Some(address) => {
                display_line!(
                    context.io(),
                    "Found validator address \"{address}\"."
                );
                if validator_addr.is_none() {
                    validator_addr = Some(address);
                }
            }
            None => {
                display_line!(
                    context.io(),
                    "No validator with Tendermint address {tm_addr} found."
                )
            }
        }
    }
    if let Some(validator_addr) = validator_addr {
        if let Some(consensus_key) = unwrap_client_response::<N::Client, _>(
            RPC.vp()
                .pos()
                .consensus_key(context.client(), &validator_addr)
                .await,
        ) {
            let pkh: PublicKeyHash = (&consensus_key).into();
            display_line!(context.io(), "Consensus key: {consensus_key}");
            display_line!(
                context.io(),
                "Tendermint key: {}",
                tm_consensus_key_raw_hash(&consensus_key)
            );
            display_line!(context.io(), "Consensus key hash: {}", pkh);
        } else {
            display_line!(
                context.io(),
                "Consensus key for validator {validator_addr} could not be \
                 found."
            )
        }
    }
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
    index: u8,
) -> Result<Option<common::PublicKey>, error::Error> {
    rpc::get_public_key_at(client, address, index).await
}

/// Check if the given address has any bonds.
pub async fn is_validator<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::is_validator(client, address)
        .await
        .unwrap()
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::is_delegator(client, address)
        .await
        .unwrap()
}

pub async fn is_delegator_at<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> bool {
    namada_sdk::rpc::is_delegator_at(client, address, epoch)
        .await
        .unwrap()
}

/// Check if the given address has any bonds.
pub async fn has_bonds<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::has_bonds(client, address).await.unwrap()
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::known_address(client, address)
        .await
        .unwrap()
}

/// Query for all conversions.
pub async fn query_conversions(
    context: &impl Namada,
    args: args::QueryConversions,
) {
    // The chosen token type of the conversions
    let target_token = args.token;
    // To facilitate human readable token addresses
    let tokens = context
        .wallet()
        .await
        .get_addresses_with_vp_type(AddressVpType::Token);
    let conversions = rpc::query_conversions(context.client())
        .await
        .expect("Conversions should be defined");
    // Track whether any non-sentinel conversions are found
    let mut conversions_found = false;
    for (addr, epoch, amt) in conversions.values() {
        // If the user has specified any targets, then meet them
        // If we have a sentinel conversion, then skip printing
        if matches!(&target_token, Some(target) if target != addr)
            || matches!(&args.epoch, Some(target) if target != epoch)
            || amt.is_zero()
        {
            continue;
        }
        conversions_found = true;
        // Print the asset to which the conversion applies
        display!(
            context.io(),
            "{}[{}]: ",
            tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
            epoch,
        );
        // Now print out the components of the allowed conversion
        let mut prefix = "";
        for (asset_type, val) in amt.components() {
            // Look up the address and epoch of asset to facilitate pretty
            // printing
            let (addr, epoch, _) = &conversions[asset_type];
            // Now print out this component of the conversion
            display!(
                context.io(),
                "{}{} {}[{}]",
                prefix,
                val,
                tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
                epoch
            );
            // Future iterations need to be prefixed with +
            prefix = " + ";
        }
        // Allowed conversions are always implicit equations
        display_line!(context.io(), " = 0");
    }
    if !conversions_found {
        display_line!(
            context.io(),
            "No conversions found satisfying specified criteria."
        );
    }
}

/// Query a conversion.
pub async fn query_conversion<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    MaspDenom,
    Epoch,
    masp_primitives::transaction::components::I128Sum,
    MerklePath<Node>,
)> {
    namada_sdk::rpc::query_conversion(client, asset_type).await
}

/// Query to read the tokens that earn masp rewards.
pub async fn query_masp_reward_tokens(context: &impl Namada) {
    let tokens = namada_sdk::rpc::query_masp_reward_tokens(context.client())
        .await
        .expect("The tokens that may earn MASP rewards should be defined");
    display_line!(context.io(), "The following tokens may ear MASP rewards:");
    for (alias, address) in tokens {
        display_line!(context.io(), "{}: {}", alias, address);
    }
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash(
    context: &impl Namada,
    code_path: impl AsRef<str>,
) -> Result<Hash, error::Error> {
    rpc::query_wasm_code_hash(context, code_path).await
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C: namada::ledger::queries::Client + Sync, T>(
    client: &C,
    key: &storage::Key,
) -> Result<T, error::Error>
where
    T: BorshDeserialize,
{
    namada_sdk::rpc::query_storage_value(client, key).await
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> (Option<Vec<u8>>, Option<ProofOps>) {
    namada_sdk::rpc::query_storage_value_bytes(client, key, height, prove)
        .await
        .unwrap()
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<'b, T>(
    context: &'b impl Namada,
    key: &storage::Key,
) -> Option<impl 'b + Iterator<Item = (storage::Key, T)>>
where
    T: BorshDeserialize,
{
    rpc::query_storage_prefix(context, key).await.unwrap()
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    key: &storage::Key,
) -> bool {
    namada_sdk::rpc::query_has_storage_key(client, key)
        .await
        .unwrap()
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transaction.
pub async fn query_tx_events<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    tx_event_query: namada_sdk::rpc::TxEventQuery<'_>,
) -> std::result::Result<
    Option<Event>,
    <C as namada::ledger::queries::Client>::Error,
> {
    namada_sdk::rpc::query_tx_events(client, tx_event_query).await
}

/// Lookup the full response accompanying the specified transaction event
// TODO: maybe remove this in favor of `query_tx_status`
pub async fn query_tx_response<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    tx_query: namada_sdk::rpc::TxEventQuery<'_>,
) -> Result<TxResponse, TError> {
    namada_sdk::rpc::query_tx_response(client, tx_query).await
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.
pub async fn query_result(context: &impl Namada, args: args::QueryResult) {
    // First try looking up application event pertaining to given hash.
    let inner_resp = query_tx_response(
        context.client(),
        namada_sdk::rpc::TxEventQuery::Applied(&args.tx_hash),
    )
    .await;
    match inner_resp {
        Ok(resp) => {
            display_inner_resp(context, &resp);
        }
        Err(err1) => {
            // If this fails then instead look for an acceptance event.
            let wrapper_resp = query_tx_response(
                context.client(),
                namada_sdk::rpc::TxEventQuery::Accepted(&args.tx_hash),
            )
            .await;
            match wrapper_resp {
                Ok(resp) => {
                    display_wrapper_resp_and_get_result(context, &resp);
                }
                Err(err2) => {
                    // Print the errors that caused the lookups to fail
                    edisplay_line!(context.io(), "{}\n{}", err1, err2);
                    cli::safe_exit(1)
                }
            }
        }
    }
}

pub async fn epoch_sleep(context: &impl Namada, _args: args::Query) {
    let start_epoch = query_and_print_epoch(context).await;
    loop {
        tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        let current_epoch = query_epoch(context.client()).await.unwrap();
        if current_epoch > start_epoch {
            display_line!(context.io(), "Reached epoch {}", current_epoch);
            break;
        }
    }
}

pub async fn get_bond_amount_at<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let total_active = unwrap_client_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    );
    Some(total_active)
}

pub async fn get_all_validators<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> HashSet<Address> {
    namada_sdk::rpc::get_all_validators(client, epoch)
        .await
        .unwrap()
}

pub async fn get_total_staked_tokens<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    epoch: Epoch,
) -> token::Amount {
    namada_sdk::rpc::get_total_staked_tokens(client, epoch)
        .await
        .unwrap()
}

/// Get the total stake of a validator at the given epoch. The total stake is a
/// sum of validator's self-bonds and delegations to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::zero())`.
async fn get_validator_stake<C: namada::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    validator: &Address,
) -> Option<token::Amount> {
    unwrap_client_response::<C, Option<token::Amount>>(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
}

pub async fn get_delegators_delegation<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    address: &Address,
) -> HashSet<Address> {
    namada_sdk::rpc::get_delegators_delegation(client, address)
        .await
        .unwrap()
}

pub async fn get_delegators_delegation_at<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> HashMap<Address, token::Amount> {
    namada_sdk::rpc::get_delegators_delegation_at(client, address, epoch)
        .await
        .unwrap()
}

pub async fn query_governance_parameters<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
) -> GovernanceParameters {
    namada_sdk::rpc::query_governance_parameters(client).await
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: namada::ledger::queries::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|err| {
        eprintln!("Error in the query: {:?}", err);
        cli::safe_exit(1)
    })
}

pub async fn compute_offline_proposal_votes(
    context: &impl Namada,
    proposal: &OfflineSignedProposal,
    votes: Vec<OfflineVote>,
) -> ProposalVotes {
    let mut validators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();
    for vote in votes {
        let is_validator = is_validator(context.client(), &vote.address).await;
        let is_delegator = is_delegator(context.client(), &vote.address).await;
        if is_validator {
            let validator_stake = get_validator_stake(
                context.client(),
                proposal.proposal.tally_epoch,
                &vote.address,
            )
            .await
            .unwrap_or_default();
            validators_vote.insert(vote.address.clone(), vote.clone().into());
            validator_voting_power
                .insert(vote.address.clone(), validator_stake);
        } else if is_delegator {
            let validators = get_delegators_delegation_at(
                context.client(),
                &vote.address.clone(),
                proposal.proposal.tally_epoch,
            )
            .await;

            for validator in vote.delegations.clone() {
                let delegator_stake =
                    validators.get(&validator).cloned().unwrap_or_default();

                delegators_vote
                    .insert(vote.address.clone(), vote.clone().into());
                delegator_voting_power
                    .entry(vote.address.clone())
                    .or_default()
                    .insert(validator, delegator_stake);
            }
        } else {
            display_line!(
                context.io(),
                "Skipping vote, not a validator/delegator at epoch {}.",
                proposal.proposal.tally_epoch
            );
        }
    }

    ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    }
}

pub async fn compute_proposal_votes<
    C: namada::ledger::queries::Client + Sync,
>(
    client: &C,
    proposal_id: u64,
    epoch: Epoch,
) -> ProposalVotes {
    let votes = namada_sdk::rpc::query_proposal_votes(client, proposal_id)
        .await
        .unwrap();

    let mut validators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();

    for vote in votes {
        if vote.is_validator() {
            let validator_stake =
                get_validator_stake(client, epoch, &vote.validator.clone())
                    .await
                    .unwrap_or_default();

            validators_vote.insert(vote.validator.clone(), vote.data.into());
            validator_voting_power.insert(vote.validator, validator_stake);
        } else {
            let delegator_stake = get_bond_amount_at(
                client,
                &vote.delegator,
                &vote.validator,
                epoch,
            )
            .await
            .unwrap_or_default();

            delegators_vote.insert(vote.delegator.clone(), vote.data.into());
            delegator_voting_power
                .entry(vote.delegator.clone())
                .or_default()
                .insert(vote.validator, delegator_stake);
        }
    }

    ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    }
}
