//! Client RPC queries

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Write};
use std::iter::Iterator;
use std::str::FromStr;

use async_std::fs;
use async_std::path::PathBuf;
use async_std::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use eyre::{eyre, Context as EyreContext};
use itertools::{Itertools, Either};
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::primitives::ViewingKey;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::Amount;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::ledger::events::Event;
use namada::ledger::governance::parameters::GovParams;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::native_vp::governance::utils::Votes;
use namada::ledger::parameters::{storage as param_storage, EpochDuration};
use namada::ledger::pos::types::{decimal_mult_u64, WeightedValidator};
use namada::ledger::pos::{
    self, is_validator_slashes_key, BondId, Bonds, PosParams, Slash, Unbonds,
};
use namada::ledger::masp::ShieldedUtils;
use namada::ledger::queries::{self, RPC};
use namada::ledger::storage::ConversionState;
use namada::types::address::{masp, tokens, Address};
use namada::types::governance::{
    OfflineProposal, OfflineVote, ProposalResult, ProposalVote, TallyResult,
    VotePower,
};
use namada::ledger::masp::ShieldedContext;
use namada::types::hash::Hash;
use namada::types::key::*;
use namada::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use namada::types::storage::{
    BlockHeight, BlockResults, Epoch, Key, KeySeg, PrefixValue,
};
use namada::types::token::balance_key;
use namada::types::{address, storage, token};
use rust_decimal::Decimal;
use tokio::time::{Duration, Instant};

use crate::wallet::Wallet;
use crate::cli::{self, args};
use crate::client::tendermint_rpc_types::TxResponse;
use namada::ledger::masp::{Conversions, PinnedBalanceError};
use crate::facade::tendermint::merkle::proof::Proof;
use crate::facade::tendermint_rpc::error::Error as TError;
use crate::facade::tendermint_rpc::query::Query;
use crate::facade::tendermint_rpc::{
    Client, HttpClient, Order, WebSocketClient,
};

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status<C>(
    client: &C,
    status: TxEventQuery<'_>,
    deadline: Instant,
) -> Event
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    const ONE_SECOND: Duration = Duration::from_secs(1);
    // sleep for the duration of `backoff`,
    // and update the underlying value
    async fn sleep_update(query: TxEventQuery<'_>, backoff: &mut Duration) {
        tracing::debug!(
            ?query,
            duration = ?backoff,
            "Retrying tx status query after timeout",
        );
        // simple linear backoff - if an event is not available,
        // increase the backoff duration by one second
        tokio::time::sleep(*backoff).await;
        *backoff += ONE_SECOND;
    }
    tokio::time::timeout_at(deadline, async move {
        let mut backoff = ONE_SECOND;

        loop {
            tracing::debug!(query = ?status, "Querying tx status");
            let maybe_event = match query_tx_events(client, status).await {
                Ok(response) => response,
                Err(err) => {
                    tracing::debug!(%err, "ABCI query failed");
                    sleep_update(status, &mut backoff).await;
                    continue;
                }
            };
            if let Some(e) = maybe_event {
                break Ok(e);
            }
            sleep_update(status, &mut backoff).await;
        }
    })
    .await
    .map_err(|_| {
        eprintln!("Transaction status query deadline of {deadline:?} exceeded");
    })
    .and_then(|result| result)
    .unwrap_or_else(|_| cli::safe_exit(1))
}

/// Query the epoch of the last committed block
pub async fn query_epoch<C>(client: &C) -> Epoch
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    let epoch = unwrap_client_response(RPC.shell().epoch(client.clone()).await);
    println!("Last committed epoch: {}", epoch);
    epoch
}

/// Query the last committed block
pub async fn query_block(
    client: &HttpClient,
) -> crate::facade::tendermint_rpc::endpoint::block::Response {
    let response = client.latest_block().await.unwrap();
    println!(
        "Last committed block ID: {}, height: {}, time: {}",
        response.block_id,
        response.block.header.height,
        response.block.header.time
    );
    response
}

/// Query the results of the last committed block
pub async fn query_results(client: &HttpClient) -> Vec<BlockResults> {
    unwrap_client_response(RPC.shell().read_results(&client.clone()).await)
}

/// Query the specified accepted transfers from the ledger
pub async fn query_transfers<U: ShieldedUtils<C = HttpClient>>(
    client: &HttpClient,
    wallet: &mut Wallet<std::path::PathBuf>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryTransfers
) {
    let query_token = args.token;
    let query_owner = args.owner
        .map_or_else(
            || Either::Right(wallet.get_addresses().into_values().collect()),
            Either::Left,
        );
    let _ = shielded.load();
    // Obtain the effects of all shielded and transparent transactions
    let transfers = shielded.query_tx_deltas(
        client,
        &query_owner,
        &query_token,
        &wallet.get_viewing_keys(),
    )
    .await;
    // To facilitate lookups of human-readable token names
    let tokens = tokens();
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
                    client,
                    amt,
                    epoch,
                    Conversions::new(),
                )
                .await
                .0;
            let dec =
                shielded.decode_amount(client, amt, epoch).await;
            shielded_accounts.insert(acc, dec);
        }
        // Check if this transfer pertains to the supplied token
        relevant &= match &query_token {
            Some(token) => {
                tfer_delta.values().any(|x| x[token] != 0)
                    || shielded_accounts.values().any(|x| x[token] != 0)
            }
            None => true,
        };
        // Filter out those entries that do not satisfy user query
        if !relevant {
            continue;
        }
        println!("Height: {}, Index: {}, Transparent Transfer:", height, idx);
        // Display the transparent changes first
        for (account, amt) in tfer_delta {
            if account != masp() {
                print!("  {}:", account);
                for (addr, val) in amt.components() {
                    let addr_enc = addr.encode();
                    let readable =
                        tokens.get(addr).cloned().unwrap_or(addr_enc.as_str());
                    let sign = match val.cmp(&0) {
                        Ordering::Greater => "+",
                        Ordering::Less => "-",
                        Ordering::Equal => "",
                    };
                    print!(
                        " {}{} {}",
                        sign,
                        token::Amount::from(val.unsigned_abs()),
                        readable
                    );
                }
                println!();
            }
        }
        // Then display the shielded changes afterwards
        // TODO: turn this to a display impl
        for (account, amt) in shielded_accounts {
            if fvk_map.contains_key(&account) {
                print!("  {}:", fvk_map[&account]);
                for (addr, val) in amt.components() {
                    let addr_enc = addr.encode();
                    let readable =
                        tokens.get(addr).cloned().unwrap_or(addr_enc.as_str());
                    let sign = match val.cmp(&0) {
                        Ordering::Greater => "+",
                        Ordering::Less => "-",
                        Ordering::Equal => "",
                    };
                    print!(
                        " {}{} {}",
                        sign,
                        token::Amount::from(val.unsigned_abs()),
                        readable
                    );
                }
                println!();
            }
        }
    }
}

/// Query the raw bytes of given storage key
pub async fn query_raw_bytes(client: &HttpClient, args: args::QueryRawBytes) {
    let response = unwrap_client_response(
        RPC.shell()
            .storage_value(client, None, None, false, &args.storage_key)
            .await,
    );
    if !response.data.is_empty() {
        println!("Found data: 0x{}", HEXLOWER.encode(&response.data));
    } else {
        println!("No data found for key {}", args.storage_key);
    }
}

/// Query token balance(s)
pub async fn query_balance<U: ShieldedUtils<C = HttpClient>>(
    client: &HttpClient,
    wallet: &mut Wallet<std::path::PathBuf>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryBalance,
) {
    // Query the balances of shielded or transparent account types depending on
    // the CLI arguments
    match &args.owner {
        Some(BalanceOwner::FullViewingKey(_viewing_key)) => {
            query_shielded_balance(client, wallet, shielded, args).await
        }
        Some(BalanceOwner::Address(_owner)) => {
            query_transparent_balance(client, wallet, args).await
        }
        Some(BalanceOwner::PaymentAddress(_owner)) => {
            query_pinned_balance(client, wallet, shielded, args).await
        }
        None => {
            // Print pinned balance
            query_pinned_balance(client, wallet, shielded, args.clone()).await;
            // Print shielded balance
            query_shielded_balance(client, wallet, shielded, args.clone()).await;
            // Then print transparent balance
            query_transparent_balance(client, wallet, args).await;
        }
    };
}

/// Query token balance(s)
pub async fn query_transparent_balance(
    client: &HttpClient,
    wallet: &mut Wallet<std::path::PathBuf>,
    args: args::QueryBalance,
) {
    let tokens = address::tokens();
    match (args.token, args.owner) {
        (Some(token), Some(owner)) => {
            let key = match &args.sub_prefix {
                Some(sub_prefix) => {
                    let sub_prefix = Key::parse(sub_prefix).unwrap();
                    let prefix =
                        token::multitoken_balance_prefix(&token, &sub_prefix);
                    token::multitoken_balance_key(
                        &prefix,
                        &owner.address().unwrap(),
                    )
                }
                None => token::balance_key(&token, &owner.address().unwrap()),
            };
            let currency_code = tokens
                .get(&token)
                .map(|c| Cow::Borrowed(*c))
                .unwrap_or_else(|| Cow::Owned(token.to_string()));
            match query_storage_value::<token::Amount,HttpClient>(&client, &key).await {
                Some(balance) => match &args.sub_prefix {
                    Some(sub_prefix) => {
                        println!(
                            "{} with {}: {}",
                            currency_code, sub_prefix, balance
                        );
                    }
                    None => println!("{}: {}", currency_code, balance),
                },
                None => {
                    println!("No {} balance found for {}", currency_code, owner)
                }
            }
        }
        (None, Some(owner)) => {
            for (token, _) in tokens {
                let prefix = token.to_db_key().into();
                let balances =
                    query_storage_prefix::<token::Amount>(&client, &prefix)
                        .await;
                if let Some(balances) = balances {
                    print_balances(
                        wallet,
                        balances,
                        &token,
                        owner.address().as_ref(),
                    );
                }
            }
        }
        (Some(token), None) => {
            let prefix = token.to_db_key().into();
            let balances =
                query_storage_prefix::<token::Amount>(&client, &prefix).await;
            if let Some(balances) = balances {
                print_balances(wallet, balances, &token, None);
            }
        }
        (None, None) => {
            for (token, _) in tokens {
                let key = token::balance_prefix(&token);
                let balances =
                    query_storage_prefix::<token::Amount>(&client, &key).await;
                if let Some(balances) = balances {
                    print_balances(wallet, balances, &token, None);
                }
            }
        }
    }
}

/// Query the token pinned balance(s)
pub async fn query_pinned_balance<U: ShieldedUtils<C = HttpClient>>(
    client: &HttpClient,
    wallet: &mut Wallet<std::path::PathBuf>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryBalance,
) {
    // Map addresses to token names
    let tokens = address::tokens();
    let owners = if let Some(pa) = args
        .owner
        .and_then(|x| x.payment_address())
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
    let _ = shielded.load();
    // Print the token balances by payment address
    for owner in owners {
        let mut balance = Err(PinnedBalanceError::InvalidViewingKey);
        // Find the viewing key that can recognize payments the current payment
        // address
        for vk in &viewing_keys {
            balance = shielded
                .compute_exchanged_pinned_balance(
                    client,
                    owner,
                    vk,
                )
                .await;
            if balance != Err(PinnedBalanceError::InvalidViewingKey) {
                break;
            }
        }
        // If a suitable viewing key was not found, then demand it from the user
        if balance == Err(PinnedBalanceError::InvalidViewingKey) {
            print!("Enter the viewing key for {}: ", owner);
            io::stdout().flush().unwrap();
            let mut vk_str = String::new();
            io::stdin().read_line(&mut vk_str).unwrap();
            let fvk = match ExtendedViewingKey::from_str(vk_str.trim()) {
                Ok(fvk) => fvk,
                _ => {
                    eprintln!("Invalid viewing key entered");
                    continue;
                }
            };
            let vk = ExtendedFullViewingKey::from(fvk).fvk.vk;
            // Use the given viewing key to decrypt pinned transaction data
            balance = shielded
                .compute_exchanged_pinned_balance(
                    client,
                    owner,
                    &vk,
                )
                .await
        }
        // Now print out the received quantities according to CLI arguments
        match (balance, args.token.as_ref()) {
            (Err(PinnedBalanceError::InvalidViewingKey), _) => println!(
                "Supplied viewing key cannot decode transactions to given \
                 payment address."
            ),
            (Err(PinnedBalanceError::NoTransactionPinned), _) => {
                println!("Payment address {} has not yet been consumed.", owner)
            }
            (Ok((balance, epoch)), Some(token)) => {
                // Extract and print only the specified token from the total
                let (_asset_type, balance) =
                    value_by_address(&balance, token.clone(), epoch);
                let currency_code = tokens
                    .get(&token)
                    .map(|c| Cow::Borrowed(*c))
                    .unwrap_or_else(|| Cow::Owned(token.to_string()));
                if balance == 0 {
                    println!(
                        "Payment address {} was consumed during epoch {}. \
                         Received no shielded {}",
                        owner, epoch, currency_code
                    );
                } else {
                    let asset_value = token::Amount::from(balance as u64);
                    println!(
                        "Payment address {} was consumed during epoch {}. \
                         Received {} {}",
                        owner, epoch, asset_value, currency_code
                    );
                }
            }
            (Ok((balance, epoch)), None) => {
                let mut found_any = false;
                // Print balances by human-readable token names
                let balance = shielded
                    .decode_amount(client, balance, epoch)
                    .await;
                for (addr, value) in balance.components() {
                    let asset_value = token::Amount::from(*value as u64);
                    if !found_any {
                        println!(
                            "Payment address {} was consumed during epoch {}. \
                             Received:",
                            owner, epoch
                        );
                        found_any = true;
                    }
                    let addr_enc = addr.encode();
                    println!(
                        "  {}: {}",
                        tokens.get(addr).cloned().unwrap_or(addr_enc.as_str()),
                        asset_value,
                    );
                }
                if !found_any {
                    println!(
                        "Payment address {} was consumed during epoch {}. \
                         Received no shielded assets.",
                        owner, epoch
                    );
                }
            }
        }
    }
}

fn print_balances(
    wallet: &Wallet<std::path::PathBuf>,
    balances: impl Iterator<Item = (storage::Key, token::Amount)>,
    token: &Address,
    target: Option<&Address>,
) {
    let stdout = io::stdout();
    let mut w = stdout.lock();

    // Token
    let tokens = address::tokens();
    let currency_code = tokens
        .get(token)
        .map(|c| Cow::Borrowed(*c))
        .unwrap_or_else(|| Cow::Owned(token.to_string()));
    writeln!(w, "Token {}", currency_code).unwrap();

    let print_num = balances
        .filter_map(
            |(key, balance)| match token::is_any_multitoken_balance_key(&key) {
                Some((sub_prefix, owner)) => Some((
                    owner.clone(),
                    format!(
                        "with {}: {}, owned by {}",
                        sub_prefix,
                        balance,
                        lookup_alias(wallet, owner)
                    ),
                )),
                None => token::is_any_token_balance_key(&key).map(|owner| {
                    (
                        owner.clone(),
                        format!(
                            ": {}, owned by {}",
                            balance,
                            lookup_alias(wallet, owner)
                        ),
                    )
                }),
            },
        )
        .filter_map(|(o, s)| match target {
            Some(t) if o == *t => Some(s),
            Some(_) => None,
            None => Some(s),
        })
        .map(|s| {
            writeln!(w, "{}", s).unwrap();
        })
        .count();

    if print_num == 0 {
        match target {
            Some(t) => {
                writeln!(w, "No balances owned by {}", lookup_alias(wallet, t))
                    .unwrap()
            }
            None => {
                writeln!(w, "No balances for token {}", currency_code).unwrap()
            }
        }
    }
}

/// Query Proposals
pub async fn query_proposal(client: &HttpClient, args: args::QueryProposal) {
    async fn print_proposal(
        client: &HttpClient,
        id: u64,
        current_epoch: Epoch,
        details: bool,
    ) -> Option<()> {
        let author_key = gov_storage::get_author_key(id);
        let start_epoch_key = gov_storage::get_voting_start_epoch_key(id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);

        let author =
            query_storage_value::<Address,HttpClient>(client, &author_key).await?;
        let start_epoch =
            query_storage_value::<Epoch,HttpClient>(client, &start_epoch_key).await?;
        let end_epoch =
            query_storage_value::<Epoch,HttpClient>(client, &end_epoch_key).await?;

        if details {
            let content_key = gov_storage::get_content_key(id);
            let grace_epoch_key = gov_storage::get_grace_epoch_key(id);
            let content = query_storage_value::<HashMap<String, String>,HttpClient>(
                client,
                &content_key,
            )
            .await?;
            let grace_epoch =
                query_storage_value::<Epoch,HttpClient>(client, &grace_epoch_key).await?;

            println!("Proposal: {}", id);
            println!("{:4}Author: {}", "", author);
            println!("{:4}Content:", "");
            for (key, value) in &content {
                println!("{:8}{}: {}", "", key, value);
            }
            println!("{:4}Start Epoch: {}", "", start_epoch);
            println!("{:4}End Epoch: {}", "", end_epoch);
            println!("{:4}Grace Epoch: {}", "", grace_epoch);
            if start_epoch > current_epoch {
                println!("{:4}Status: pending", "");
            } else if start_epoch <= current_epoch && current_epoch <= end_epoch
            {
                let votes = get_proposal_votes(client, start_epoch, id).await;
                let partial_proposal_result =
                    compute_tally(client, start_epoch, votes).await;
                println!(
                    "{:4}Yay votes: {}",
                    "", partial_proposal_result.total_yay_power
                );
                println!(
                    "{:4}Nay votes: {}",
                    "", partial_proposal_result.total_nay_power
                );
                println!("{:4}Status: on-going", "");
            } else {
                let votes = get_proposal_votes(client, start_epoch, id).await;
                let proposal_result =
                    compute_tally(client, start_epoch, votes).await;
                println!("{:4}Status: done", "");
                println!("{:4}Result: {}", "", proposal_result);
            }
        } else {
            println!("Proposal: {}", id);
            println!("{:4}Author: {}", "", author);
            println!("{:4}Start Epoch: {}", "", start_epoch);
            println!("{:4}End Epoch: {}", "", end_epoch);
            if start_epoch > current_epoch {
                println!("{:4}Status: pending", "");
            } else if start_epoch <= current_epoch && current_epoch <= end_epoch
            {
                println!("{:4}Status: on-going", "");
            } else {
                println!("{:4}Status: done", "");
            }
        }

        Some(())
    }

    let current_epoch = query_epoch(client).await;
    match args.proposal_id {
        Some(id) => {
            if print_proposal(&client, id, current_epoch, true)
                .await
                .is_none()
            {
                eprintln!("No valid proposal was found with id {}", id)
            }
        }
        None => {
            let last_proposal_id_key = gov_storage::get_counter_key();
            let last_proposal_id =
                query_storage_value::<u64,HttpClient>(&client, &last_proposal_id_key)
                    .await
                    .unwrap();

            for id in 0..last_proposal_id {
                if print_proposal(&client, id, current_epoch, false)
                    .await
                    .is_none()
                {
                    eprintln!("No valid proposal was found with id {}", id)
                };
            }
        }
    }
}

/// Get the component of the given amount corresponding to the given token
pub fn value_by_address(
    amt: &masp_primitives::transaction::components::Amount,
    token: Address,
    epoch: Epoch,
) -> (AssetType, i64) {
    // Compute the unique asset identifier from the token address
    let asset_type = AssetType::new(
        (token, epoch.0)
            .try_to_vec()
            .expect("token addresses should serialize")
            .as_ref(),
    )
    .unwrap();
    (asset_type, amt[&asset_type])
}

/// Query token shielded balance(s)
pub async fn query_shielded_balance<U: ShieldedUtils<C = HttpClient>>(
    client: &HttpClient,
    wallet: &mut Wallet<std::path::PathBuf>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryBalance,
) {
    // Used to control whether balances for all keys or a specific key are
    // printed
    let owner = args
        .owner
        .and_then(|x| x.full_viewing_key());
    // Used to control whether conversions are automatically performed
    let no_conversions = args.no_conversions;
    // Viewing keys are used to query shielded balances. If a spending key is
    // provided, then convert to a viewing key first.
    let viewing_keys = match owner {
        Some(viewing_key) => vec![viewing_key],
        None => wallet.get_viewing_keys().values().copied().collect(),
    };
    let _ = shielded.load();
    let fvks: Vec<_> = viewing_keys
        .iter()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    shielded.fetch(client, &[], &fvks).await;
    // Save the update state so that future fetches can be short-circuited
    let _ = shielded.save();
    // The epoch is required to identify timestamped tokens
    let epoch = query_epoch(client).await;
    // Map addresses to token names
    let tokens = address::tokens();
    match (args.token, owner.is_some()) {
        // Here the user wants to know the balance for a specific token
        (Some(token), true) => {
            // Query the multi-asset balance at the given spending key
            let viewing_key =
                ExtendedFullViewingKey::from(viewing_keys[0]).fvk.vk;
            let balance: Amount<AssetType> = if no_conversions {
                shielded
                    .compute_shielded_balance(&viewing_key)
                    .expect("context should contain viewing key")
            } else {
                shielded
                    .compute_exchanged_balance(
                        client,
                        &viewing_key,
                        epoch,
                    )
                    .await
                    .expect("context should contain viewing key")
            };
            // Compute the unique asset identifier from the token address
            let token = token;
            let asset_type = AssetType::new(
                (token.clone(), epoch.0)
                    .try_to_vec()
                    .expect("token addresses should serialize")
                    .as_ref(),
            )
            .unwrap();
            let currency_code = tokens
                .get(&token)
                .map(|c| Cow::Borrowed(*c))
                .unwrap_or_else(|| Cow::Owned(token.to_string()));
            if balance[&asset_type] == 0 {
                println!(
                    "No shielded {} balance found for given key",
                    currency_code
                );
            } else {
                let asset_value =
                    token::Amount::from(balance[&asset_type] as u64);
                println!("{}: {}", currency_code, asset_value);
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
                    shielded
                        .compute_shielded_balance(&viewing_key)
                        .expect("context should contain viewing key")
                } else {
                    shielded
                        .compute_exchanged_balance(
                            client,
                            &viewing_key,
                            epoch,
                        )
                        .await
                        .expect("context should contain viewing key")
                };
                for (asset_type, value) in balance.components() {
                    if !balances.contains_key(asset_type) {
                        balances.insert(*asset_type, Vec::new());
                    }
                    balances.get_mut(asset_type).unwrap().push((fvk, *value));
                }
            }

            // These are the asset types for which we have human-readable names
            let mut read_tokens = HashSet::new();
            // Print non-zero balances whose asset types can be decoded
            for (asset_type, balances) in balances {
                // Decode the asset type
                let decoded = shielded
                    .decode_asset_type(client, asset_type)
                    .await;
                match decoded {
                    Some((addr, asset_epoch)) if asset_epoch == epoch => {
                        // Only assets with the current timestamp count
                        let addr_enc = addr.encode();
                        println!(
                            "Shielded Token {}:",
                            tokens
                                .get(&addr)
                                .cloned()
                                .unwrap_or(addr_enc.as_str())
                        );
                        read_tokens.insert(addr);
                    }
                    _ => continue,
                }

                let mut found_any = false;
                for (fvk, value) in balances {
                    let value = token::Amount::from(value as u64);
                    println!("  {}, owned by {}", value, fvk);
                    found_any = true;
                }
                if !found_any {
                    println!(
                        "No shielded {} balance found for any wallet key",
                        asset_type
                    );
                }
            }
            // Print zero balances for remaining assets
            for (token, currency_code) in tokens {
                if !read_tokens.contains(&token) {
                    println!("Shielded Token {}:", currency_code);
                    println!(
                        "No shielded {} balance found for any wallet key",
                        currency_code
                    );
                }
            }
        }
        // Here the user wants to know the balance for a specific token across
        // users
        (Some(token), false) => {
            // Compute the unique asset identifier from the token address
            let token = token;
            let asset_type = AssetType::new(
                (token.clone(), epoch.0)
                    .try_to_vec()
                    .expect("token addresses should serialize")
                    .as_ref(),
            )
            .unwrap();
            let currency_code = tokens
                .get(&token)
                .map(|c| Cow::Borrowed(*c))
                .unwrap_or_else(|| Cow::Owned(token.to_string()));
            println!("Shielded Token {}:", currency_code);
            let mut found_any = false;
            for fvk in viewing_keys {
                // Query the multi-asset balance at the given spending key
                let viewing_key = ExtendedFullViewingKey::from(fvk).fvk.vk;
                let balance = if no_conversions {
                    shielded
                        .compute_shielded_balance(&viewing_key)
                        .expect("context should contain viewing key")
                } else {
                    shielded
                        .compute_exchanged_balance(
                            client,
                            &viewing_key,
                            epoch,
                        )
                        .await
                        .expect("context should contain viewing key")
                };
                if balance[&asset_type] != 0 {
                    let asset_value =
                        token::Amount::from(balance[&asset_type] as u64);
                    println!("  {}, owned by {}", asset_value, fvk);
                    found_any = true;
                }
            }
            if !found_any {
                println!(
                    "No shielded {} balance found for any wallet key",
                    currency_code
                );
            }
        }
        // Here the user wants to know all possible token balances for a key
        (None, true) => {
            // Query the multi-asset balance at the given spending key
            let viewing_key =
                ExtendedFullViewingKey::from(viewing_keys[0]).fvk.vk;
            let balance;
            if no_conversions {
                balance = shielded
                    .compute_shielded_balance(&viewing_key)
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                let decoded_balance = shielded
                    .decode_all_amounts(client, balance)
                    .await;
                print_decoded_balance_with_epoch(decoded_balance);
            } else {
                balance = shielded
                    .compute_exchanged_balance(
                        client,
                        &viewing_key,
                        epoch,
                    )
                    .await
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                let decoded_balance = shielded
                    .decode_amount(client, balance, epoch)
                    .await;
                print_decoded_balance(decoded_balance);
            }
        }
    }
}

pub fn print_decoded_balance(decoded_balance: Amount<Address>) {
    let tokens = address::tokens();
    let mut found_any = false;
    for (addr, value) in decoded_balance.components() {
        let asset_value = token::Amount::from(*value as u64);
        let addr_enc = addr.encode();
        println!(
            "{} : {}",
            tokens.get(addr).cloned().unwrap_or(addr_enc.as_str()),
            asset_value
        );
        found_any = true;
    }
    if !found_any {
        println!("No shielded balance found for given key");
    }
}

pub fn print_decoded_balance_with_epoch(
    decoded_balance: Amount<(Address, Epoch)>,
) {
    let tokens = address::tokens();
    let mut found_any = false;
    for ((addr, epoch), value) in decoded_balance.components() {
        let asset_value = token::Amount::from(*value as u64);
        let addr_enc = addr.encode();
        println!(
            "{} | {} : {}",
            tokens.get(addr).cloned().unwrap_or(addr_enc.as_str()),
            epoch,
            asset_value
        );
        found_any = true;
    }
    if !found_any {
        println!("No shielded balance found for given key");
    }
}

/// Query token amount of owner.
pub async fn get_token_balance(
    client: &HttpClient,
    token: &Address,
    owner: &Address,
) -> Option<token::Amount> {
    let balance_key = balance_key(token, owner);
    query_storage_value(client, &balance_key).await
}

pub async fn query_proposal_result(
    client: &HttpClient,
    args: args::QueryProposalResult,
) {
    let current_epoch = query_epoch(client).await;

    match args.proposal_id {
        Some(id) => {
            let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
            let end_epoch =
                query_storage_value::<Epoch,HttpClient>(&client, &end_epoch_key).await;

            match end_epoch {
                Some(end_epoch) => {
                    if current_epoch > end_epoch {
                        let votes =
                            get_proposal_votes(&client, end_epoch, id).await;
                        let proposal_result =
                            compute_tally(&client, end_epoch, votes).await;
                        println!("Proposal: {}", id);
                        println!("{:4}Result: {}", "", proposal_result);
                    } else {
                        eprintln!("Proposal is still in progress.");
                        cli::safe_exit(1)
                    }
                }
                None => {
                    eprintln!("Error while retriving proposal.");
                    cli::safe_exit(1)
                }
            }
        }
        None => {
            if args.offline {
                match args.proposal_folder {
                    Some(path) => {
                        let mut dir = fs::read_dir(&path)
                            .await
                            .expect("Should be able to read the directory.");
                        let mut files = HashSet::new();
                        let mut is_proposal_present = false;

                        while let Some(entry) = dir.next().await {
                            match entry {
                                Ok(entry) => match entry.file_type().await {
                                    Ok(entry_stat) => {
                                        if entry_stat.is_file() {
                                            if entry.file_name().eq(&"proposal")
                                            {
                                                is_proposal_present = true
                                            } else if entry
                                                .file_name()
                                                .to_string_lossy()
                                                .starts_with("proposal-vote-")
                                            {
                                                // Folder may contain other
                                                // files than just the proposal
                                                // and the votes
                                                files.insert(entry.path());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Can't read entry type: {}.",
                                            e
                                        );
                                        cli::safe_exit(1)
                                    }
                                },
                                Err(e) => {
                                    eprintln!("Can't read entry: {}.", e);
                                    cli::safe_exit(1)
                                }
                            }
                        }

                        if !is_proposal_present {
                            eprintln!(
                                "The folder must contain the offline proposal \
                                 in a file named \"proposal\""
                            );
                            cli::safe_exit(1)
                        }

                        let file = File::open(path.join("proposal"))
                            .expect("Proposal file must exist.");
                        let proposal: OfflineProposal =
                            serde_json::from_reader(file).expect(
                                "JSON was not well-formatted for proposal.",
                            );

                        let public_key = get_public_key(
                            client,
                            &proposal.address,
                        )
                        .await
                        .expect("Public key should exist.");

                        if !proposal.check_signature(&public_key) {
                            eprintln!("Bad proposal signature.");
                            cli::safe_exit(1)
                        }

                        let votes = get_proposal_offline_votes(
                            &client,
                            proposal.clone(),
                            files,
                        )
                        .await;
                        let proposal_result =
                            compute_tally(&client, proposal.tally_epoch, votes)
                                .await;

                        println!("{:4}Result: {}", "", proposal_result);
                    }
                    None => {
                        eprintln!(
                            "Offline flag must be followed by data-path."
                        );
                        cli::safe_exit(1)
                    }
                };
            } else {
                eprintln!(
                    "Either --proposal-id or --data-path should be provided \
                     as arguments."
                );
                cli::safe_exit(1)
            }
        }
    }
}

pub async fn query_protocol_parameters(
    client: &HttpClient,
    _args: args::QueryProtocolParameters,
) {
    let gov_parameters = get_governance_parameters(&client).await;
    println!("Governance Parameters\n {:4}", gov_parameters);

    println!("Protocol parameters");
    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration = query_storage_value::<EpochDuration,HttpClient>(&client, &key)
        .await
        .expect("Parameter should be definied.");
    println!(
        "{:4}Min. epoch duration: {}",
        "", epoch_duration.min_duration
    );
    println!(
        "{:4}Min. number of blocks: {}",
        "", epoch_duration.min_num_of_blocks
    );

    let key = param_storage::get_max_expected_time_per_block_key();
    let max_block_duration = query_storage_value::<u64,HttpClient>(&client, &key)
        .await
        .expect("Parameter should be definied.");
    println!("{:4}Max. block duration: {}", "", max_block_duration);

    let key = param_storage::get_tx_whitelist_storage_key();
    let vp_whitelist = query_storage_value::<Vec<String>,HttpClient>(&client, &key)
        .await
        .expect("Parameter should be definied.");
    println!("{:4}VP whitelist: {:?}", "", vp_whitelist);

    let key = param_storage::get_tx_whitelist_storage_key();
    let tx_whitelist = query_storage_value::<Vec<String>,HttpClient>(&client, &key)
        .await
        .expect("Parameter should be definied.");
    println!("{:4}Transactions whitelist: {:?}", "", tx_whitelist);

    println!("PoS parameters");
    let key = pos::params_key();
    let pos_params = query_storage_value::<PosParams,HttpClient>(&client, &key)
        .await
        .expect("Parameter should be definied.");
    println!(
        "{:4}Block proposer reward: {}",
        "", pos_params.block_proposer_reward
    );
    println!(
        "{:4}Block vote reward: {}",
        "", pos_params.block_vote_reward
    );
    println!(
        "{:4}Duplicate vote minimum slash rate: {}",
        "", pos_params.duplicate_vote_min_slash_rate
    );
    println!(
        "{:4}Light client attack minimum slash rate: {}",
        "", pos_params.light_client_attack_min_slash_rate
    );
    println!(
        "{:4}Max. validator slots: {}",
        "", pos_params.max_validator_slots
    );
    println!("{:4}Pipeline length: {}", "", pos_params.pipeline_len);
    println!("{:4}Unbonding length: {}", "", pos_params.unbonding_len);
    println!("{:4}Votes per token: {}", "", pos_params.tm_votes_per_token);
}

/// Query PoS bond(s)
pub async fn query_bonds(client: &HttpClient, args: args::QueryBonds) {
    let epoch = query_epoch(client).await;
    match (args.owner, args.validator) {
        (Some(owner), Some(validator)) => {
            let source = owner;
            let validator = validator;
            // Find owner's delegations to the given validator
            let bond_id = pos::BondId { source, validator };
            let bond_key = pos::bond_key(&bond_id);
            let bonds =
                query_storage_value::<pos::Bonds,HttpClient>(&client, &bond_key).await;
            // Find owner's unbonded delegations from the given
            // validator
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<pos::Unbonds,HttpClient>(&client, &unbond_key).await;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<pos::Slashes,HttpClient>(&client, &slashes_key)
                    .await
                    .unwrap_or_default();

            let stdout = io::stdout();
            let mut w = stdout.lock();

            if let Some(bonds) = &bonds {
                let bond_type = if bond_id.source == bond_id.validator {
                    "Self-bonds"
                } else {
                    "Delegations"
                };
                writeln!(w, "{}:", bond_type).unwrap();
                process_bonds_query(
                    bonds, &slashes, &epoch, None, None, None, &mut w,
                );
            }

            if let Some(unbonds) = &unbonds {
                let bond_type = if bond_id.source == bond_id.validator {
                    "Unbonded self-bonds"
                } else {
                    "Unbonded delegations"
                };
                writeln!(w, "{}:", bond_type).unwrap();
                process_unbonds_query(
                    unbonds, &slashes, &epoch, None, None, None, &mut w,
                );
            }

            if bonds.is_none() && unbonds.is_none() {
                writeln!(
                    w,
                    "No delegations found for {} to validator {}",
                    bond_id.source,
                    bond_id.validator.encode()
                )
                .unwrap();
            }
        }
        (None, Some(validator)) => {
            let validator = validator;
            // Find validator's self-bonds
            let bond_id = pos::BondId {
                source: validator.clone(),
                validator,
            };
            let bond_key = pos::bond_key(&bond_id);
            let bonds =
                query_storage_value::<pos::Bonds,HttpClient>(&client, &bond_key).await;
            // Find validator's unbonded self-bonds
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<pos::Unbonds,HttpClient>(&client, &unbond_key).await;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<pos::Slashes,HttpClient>(&client, &slashes_key)
                    .await
                    .unwrap_or_default();

            let stdout = io::stdout();
            let mut w = stdout.lock();

            if let Some(bonds) = &bonds {
                writeln!(w, "Self-bonds:").unwrap();
                process_bonds_query(
                    bonds, &slashes, &epoch, None, None, None, &mut w,
                );
            }

            if let Some(unbonds) = &unbonds {
                writeln!(w, "Unbonded self-bonds:").unwrap();
                process_unbonds_query(
                    unbonds, &slashes, &epoch, None, None, None, &mut w,
                );
            }

            if bonds.is_none() && unbonds.is_none() {
                writeln!(
                    w,
                    "No self-bonds found for validator {}",
                    bond_id.validator.encode()
                )
                .unwrap();
            }
        }
        (Some(owner), None) => {
            let owner = owner;
            // Find owner's bonds to any validator
            let bonds_prefix = pos::bonds_for_source_prefix(&owner);
            let bonds =
                query_storage_prefix::<pos::Bonds>(&client, &bonds_prefix)
                    .await;
            // Find owner's unbonds to any validator
            let unbonds_prefix = pos::unbonds_for_source_prefix(&owner);
            let unbonds =
                query_storage_prefix::<pos::Unbonds>(&client, &unbonds_prefix)
                    .await;

            let mut total: token::Amount = 0.into();
            let mut total_active: token::Amount = 0.into();
            let mut any_bonds = false;
            if let Some(bonds) = bonds {
                for (key, bonds) in bonds {
                    match pos::is_bond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes,HttpClient>(
                                &client,
                                &slashes_key,
                            )
                            .await
                            .unwrap_or_default();

                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            any_bonds = true;
                            let bond_type: Cow<str> = if source == validator {
                                "Self-bonds".into()
                            } else {
                                format!(
                                    "Delegations from {} to {}",
                                    source, validator
                                )
                                .into()
                            };
                            writeln!(w, "{}:", bond_type).unwrap();
                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                &epoch,
                                Some(&source),
                                Some(total),
                                Some(total_active),
                                &mut w,
                            );
                            total = tot;
                            total_active = tot_active;
                        }
                        None => {
                            panic!("Unexpected storage key {}", key)
                        }
                    }
                }
            }
            if total_active != 0.into() && total_active != total {
                println!("Active bonds total: {}", total_active);
            }

            let mut total: token::Amount = 0.into();
            let mut total_withdrawable: token::Amount = 0.into();
            if let Some(unbonds) = unbonds {
                for (key, unbonds) in unbonds {
                    match pos::is_unbond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes,HttpClient>(
                                &client,
                                &slashes_key,
                            )
                            .await
                            .unwrap_or_default();

                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            any_bonds = true;
                            let bond_type: Cow<str> = if source == validator {
                                "Unbonded self-bonds".into()
                            } else {
                                format!("Unbonded delegations from {}", source)
                                    .into()
                            };
                            writeln!(w, "{}:", bond_type).unwrap();
                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                &epoch,
                                Some(&source),
                                Some(total),
                                Some(total_withdrawable),
                                &mut w,
                            );
                            total = tot;
                            total_withdrawable = tot_withdrawable;
                        }
                        None => {
                            panic!("Unexpected storage key {}", key)
                        }
                    }
                }
            }
            if total_withdrawable != 0.into() {
                println!("Withdrawable total: {}", total_withdrawable);
            }

            if !any_bonds {
                println!("No self-bonds or delegations found for {}", owner);
            }
        }
        (None, None) => {
            // Find all the bonds
            let bonds_prefix = pos::bonds_prefix();
            let bonds =
                query_storage_prefix::<pos::Bonds>(&client, &bonds_prefix)
                    .await;
            // Find all the unbonds
            let unbonds_prefix = pos::unbonds_prefix();
            let unbonds =
                query_storage_prefix::<pos::Unbonds>(&client, &unbonds_prefix)
                    .await;

            let mut total: token::Amount = 0.into();
            let mut total_active: token::Amount = 0.into();
            if let Some(bonds) = bonds {
                for (key, bonds) in bonds {
                    match pos::is_bond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes,HttpClient>(
                                &client,
                                &slashes_key,
                            )
                            .await
                            .unwrap_or_default();

                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            let bond_type = if source == validator {
                                format!("Self-bonds for {}", validator.encode())
                            } else {
                                format!(
                                    "Delegations from {} to validator {}",
                                    source,
                                    validator.encode()
                                )
                            };
                            writeln!(w, "{}:", bond_type).unwrap();
                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                &epoch,
                                Some(&source),
                                Some(total),
                                Some(total_active),
                                &mut w,
                            );
                            total = tot;
                            total_active = tot_active;
                        }
                        None => {
                            panic!("Unexpected storage key {}", key)
                        }
                    }
                }
            }
            if total_active != 0.into() && total_active != total {
                println!("Bond total active: {}", total_active);
            }
            println!("Bond total: {}", total);

            let mut total: token::Amount = 0.into();
            let mut total_withdrawable: token::Amount = 0.into();
            if let Some(unbonds) = unbonds {
                for (key, unbonds) in unbonds {
                    match pos::is_unbond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes,HttpClient>(
                                &client,
                                &slashes_key,
                            )
                            .await
                            .unwrap_or_default();

                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            let bond_type = if source == validator {
                                format!(
                                    "Unbonded self-bonds for {}",
                                    validator.encode()
                                )
                            } else {
                                format!(
                                    "Unbonded delegations from {} to \
                                     validator {}",
                                    source,
                                    validator.encode()
                                )
                            };
                            writeln!(w, "{}:", bond_type).unwrap();
                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                &epoch,
                                Some(&source),
                                Some(total),
                                Some(total_withdrawable),
                                &mut w,
                            );
                            total = tot;
                            total_withdrawable = tot_withdrawable;
                        }
                        None => {
                            panic!("Unexpected storage key {}", key)
                        }
                    }
                }
            }
            if total_withdrawable != 0.into() {
                println!("Withdrawable total: {}", total_withdrawable);
            }
            println!("Unbonded total: {}", total);
        }
    }
}

/// Query PoS bonded stake
pub async fn query_bonded_stake(client: &HttpClient, args: args::QueryBondedStake) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_epoch(client).await,
    };

    // Find the validator set
    let validator_set_key = pos::validator_set_key();
    let validator_sets =
        query_storage_value::<pos::ValidatorSets,HttpClient>(&client, &validator_set_key)
            .await
            .expect("Validator set should always be set");
    let validator_set = validator_sets
        .get(epoch)
        .expect("Validator set should be always set in the current epoch");

    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find bonded stake for the given validator
            let validator_deltas_key = pos::validator_deltas_key(&validator);
            let validator_deltas = query_storage_value::<pos::ValidatorDeltas,HttpClient>(
                &client,
                &validator_deltas_key,
            )
            .await;
            match validator_deltas.and_then(|data| data.get(epoch)) {
                Some(val_stake) => {
                    let bonded_stake: u64 = val_stake.try_into().expect(
                        "The sum of the bonded stake deltas shouldn't be \
                         negative",
                    );
                    let weighted = WeightedValidator {
                        address: validator.clone(),
                        bonded_stake,
                    };
                    let is_active = validator_set.active.contains(&weighted);
                    if !is_active {
                        debug_assert!(
                            validator_set.inactive.contains(&weighted)
                        );
                    }
                    println!(
                        "Validator {} is {}, bonded stake: {}",
                        validator.encode(),
                        if is_active { "active" } else { "inactive" },
                        bonded_stake,
                    )
                }
                None => {
                    println!("No bonded stake found for {}", validator.encode())
                }
            }
        }
        None => {
            // Iterate all validators
            let stdout = io::stdout();
            let mut w = stdout.lock();

            writeln!(w, "Active validators:").unwrap();
            for active in &validator_set.active {
                writeln!(
                    w,
                    "  {}: {}",
                    active.address.encode(),
                    active.bonded_stake
                )
                .unwrap();
            }
            if !validator_set.inactive.is_empty() {
                writeln!(w, "Inactive validators:").unwrap();
                for inactive in &validator_set.inactive {
                    writeln!(
                        w,
                        "  {}: {}",
                        inactive.address.encode(),
                        inactive.bonded_stake
                    )
                    .unwrap();
                }
            }
        }
    }
    let total_deltas_key = pos::total_deltas_key();
    let total_deltas =
        query_storage_value::<pos::TotalDeltas,HttpClient>(&client, &total_deltas_key)
            .await
            .expect("Total bonded stake should always be set");
    let total_bonded_stake = total_deltas
        .get(epoch)
        .expect("Total bonded stake should be always set in the current epoch");
    let total_bonded_stake: u64 = total_bonded_stake
        .try_into()
        .expect("total_bonded_stake should be a positive value");

    println!("Total bonded stake: {}", total_bonded_stake);
}

/// Query PoS validator's commission rate
pub async fn query_commission_rate(
    client: &HttpClient,
    args: args::QueryCommissionRate,
) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_epoch(client).await,
    };
    let validator = args.validator;
    let is_validator =
        is_validator(client, &validator).await;

    if is_validator {
        let validator_commission_key =
            pos::validator_commission_rate_key(&validator);
        let validator_max_commission_change_key =
            pos::validator_max_commission_rate_change_key(&validator);
        let commission_rates = query_storage_value::<pos::CommissionRates,HttpClient>(
            &client,
            &validator_commission_key,
        )
        .await;
        let max_rate_change = query_storage_value::<Decimal,HttpClient>(
            &client,
            &validator_max_commission_change_key,
        )
        .await;
        let max_rate_change =
            max_rate_change.expect("No max rate change found");
        let commission_rates =
            commission_rates.expect("No commission rate found ");
        match commission_rates.get(epoch) {
            Some(rate) => {
                println!(
                    "Validator {} commission rate: {}, max change per epoch: \
                     {}",
                    validator.encode(),
                    *rate,
                    max_rate_change,
                )
            }
            None => {
                println!(
                    "No commission rate found for {} in epoch {}",
                    validator.encode(),
                    epoch
                )
            }
        }
    } else {
        println!("Cannot find validator with address {}", validator);
    }
}

/// Query PoS slashes
pub async fn query_slashes(client: &HttpClient, args: args::QuerySlashes) {
    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find slashes for the given validator
            let slashes_key = pos::validator_slashes_key(&validator);
            let slashes =
                query_storage_value::<pos::Slashes,HttpClient>(&client, &slashes_key)
                    .await;
            match slashes {
                Some(slashes) => {
                    let stdout = io::stdout();
                    let mut w = stdout.lock();
                    for slash in slashes {
                        writeln!(
                            w,
                            "Slash epoch {}, rate {}, type {}",
                            slash.epoch, slash.rate, slash.r#type
                        )
                        .unwrap();
                    }
                }
                None => {
                    println!("No slashes found for {}", validator.encode())
                }
            }
        }
        None => {
            // Iterate slashes for all validators
            let slashes_prefix = pos::slashes_prefix();
            let slashes =
                query_storage_prefix::<pos::Slashes>(&client, &slashes_prefix)
                    .await;

            match slashes {
                Some(slashes) => {
                    let stdout = io::stdout();
                    let mut w = stdout.lock();
                    for (slashes_key, slashes) in slashes {
                        if let Some(validator) =
                            is_validator_slashes_key(&slashes_key)
                        {
                            for slash in slashes {
                                writeln!(
                                    w,
                                    "Slash epoch {}, block height {}, rate \
                                     {}, type {}, validator {}",
                                    slash.epoch,
                                    slash.block_height,
                                    slash.rate,
                                    slash.r#type,
                                    validator,
                                )
                                .unwrap();
                            }
                        } else {
                            eprintln!("Unexpected slashes key {}", slashes_key);
                        }
                    }
                }
                None => {
                    println!("No slashes found")
                }
            }
        }
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<C>(client: &C, tx_bytes: Vec<u8>)
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = unwrap_client_response(
        RPC.shell().dry_run_tx(client, data, height, prove).await,
    )
    .data;
    println!("Dry-run result: {}", result);
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C>(
    client: &C,
    address: &Address,
) -> Option<common::PublicKey>
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    let key = pk_key(address);
    query_storage_value(client, &key).await
}

/// Check if the given address is a known validator.
pub async fn is_validator(
    client: &HttpClient,
    address: &Address,
) -> bool {
    unwrap_client_response(RPC.vp().pos().is_validator(client, address).await)
}

/// Check if a given address is a known delegator
pub async fn is_delegator(
    client: &HttpClient,
    address: &Address,
) -> bool {
    let bonds_prefix = pos::bonds_for_source_prefix(address);
    let bonds =
        query_storage_prefix::<pos::Bonds>(&client, &bonds_prefix).await;
    bonds.is_some() && bonds.unwrap().count() > 0
}

pub async fn is_delegator_at(
    client: &HttpClient,
    address: &Address,
    epoch: Epoch,
) -> bool {
    let key = pos::bonds_for_source_prefix(address);
    let bonds_iter = query_storage_prefix::<pos::Bonds>(client, &key).await;
    if let Some(mut bonds) = bonds_iter {
        bonds.any(|(_, bond)| bond.get(epoch).is_some())
    } else {
        false
    }
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C>(client: &C, address: &Address) -> bool
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = storage::Key::validity_predicate(address);
            query_has_storage_key(client, &key).await
        }
        Address::Implicit(_) | Address::Internal(_) => true,
    }
}

/// Accumulate slashes starting from `epoch_start` until (optionally)
/// `withdraw_epoch` and apply them to the token amount `delta`.
fn apply_slashes(
    slashes: &[Slash],
    mut delta: token::Amount,
    epoch_start: Epoch,
    withdraw_epoch: Option<Epoch>,
    mut w: Option<&mut std::io::StdoutLock>,
) -> token::Amount {
    let mut slashed = token::Amount::default();
    for slash in slashes {
        if slash.epoch >= epoch_start
            && slash.epoch < withdraw_epoch.unwrap_or_else(|| u64::MAX.into())
        {
            if let Some(w) = w.as_mut() {
                writeln!(
                    *w,
                    "    ⚠ Slash: {} from epoch {}",
                    slash.rate, slash.epoch
                )
                .unwrap();
            }
            let raw_delta: u64 = delta.into();
            let current_slashed =
                token::Amount::from(decimal_mult_u64(slash.rate, raw_delta));
            slashed += current_slashed;
            delta -= current_slashed;
        }
    }
    if let Some(w) = w.as_mut() {
        if slashed != 0.into() {
            writeln!(*w, "    ⚠ Slash total: {}", slashed).unwrap();
            writeln!(*w, "    ⚠ After slashing: Δ {}", delta).unwrap();
        }
    }
    delta
}

/// Process the result of a blonds query to determine total bonds
/// and total active bonds. This includes taking into account
/// an aggregation of slashes since the start of the given epoch.
fn process_bonds_query(
    bonds: &Bonds,
    slashes: &[Slash],
    epoch: &Epoch,
    source: Option<&Address>,
    total: Option<token::Amount>,
    total_active: Option<token::Amount>,
    w: &mut std::io::StdoutLock,
) -> (token::Amount, token::Amount) {
    let mut total_active = total_active.unwrap_or_else(|| 0.into());
    let mut current_total: token::Amount = 0.into();
    for bond in bonds.iter() {
        for (epoch_start, &(mut delta)) in bond.pos_deltas.iter().sorted() {
            writeln!(w, "  Active from epoch {}: Δ {}", epoch_start, delta)
                .unwrap();
            delta = apply_slashes(slashes, delta, *epoch_start, None, Some(w));
            current_total += delta;
            if epoch >= epoch_start {
                total_active += delta;
            }
        }
    }
    let total = total.unwrap_or_else(|| 0.into()) + current_total;
    match source {
        Some(addr) => {
            writeln!(w, "  Bonded total from {}: {}", addr, current_total)
                .unwrap();
        }
        None => {
            if total_active != 0.into() && total_active != total {
                writeln!(w, "Active bonds total: {}", total_active).unwrap();
            }
            writeln!(w, "Bonds total: {}", total).unwrap();
        }
    }
    (total, total_active)
}

/// Process the result of an unbonds query to determine total bonds
/// and total withdrawable bonds. This includes taking into account
/// an aggregation of slashes since the start of the given epoch up
/// until the withdrawal epoch.
fn process_unbonds_query(
    unbonds: &Unbonds,
    slashes: &[Slash],
    epoch: &Epoch,
    source: Option<&Address>,
    total: Option<token::Amount>,
    total_withdrawable: Option<token::Amount>,
    w: &mut std::io::StdoutLock,
) -> (token::Amount, token::Amount) {
    let mut withdrawable = total_withdrawable.unwrap_or_else(|| 0.into());
    let mut current_total: token::Amount = 0.into();
    for deltas in unbonds.iter() {
        for ((epoch_start, epoch_end), &(mut delta)) in
            deltas.deltas.iter().sorted()
        {
            let withdraw_epoch = *epoch_end + 1_u64;
            writeln!(
                w,
                "  Withdrawable from epoch {} (active from {}): Δ {}",
                withdraw_epoch, epoch_start, delta
            )
            .unwrap();
            delta = apply_slashes(
                slashes,
                delta,
                *epoch_start,
                Some(withdraw_epoch),
                Some(w),
            );
            current_total += delta;
            if epoch > epoch_end {
                withdrawable += delta;
            }
        }
    }
    let total = total.unwrap_or_else(|| 0.into()) + current_total;
    match source {
        Some(addr) => {
            writeln!(w, "  Unbonded total from {}: {}", addr, current_total)
                .unwrap();
        }
        None => {
            if withdrawable != 0.into() {
                writeln!(w, "Withdrawable total: {}", withdrawable).unwrap();
            }
            writeln!(w, "Unbonded total: {}", total).unwrap();
        }
    }
    (total, withdrawable)
}

/// Query for all conversions.
pub async fn query_conversions(client: &HttpClient, args: args::QueryConversions) {
    // The chosen token type of the conversions
    let target_token = args.token;
    // To facilitate human readable token addresses
    let tokens = address::tokens();
    let masp_addr = masp();
    let key_prefix: Key = masp_addr.to_db_key().into();
    let state_key = key_prefix
        .push(&(token::CONVERSION_KEY_PREFIX.to_owned()))
        .unwrap();
    let conv_state =
        query_storage_value::<ConversionState,HttpClient>(&client, &state_key)
            .await
            .expect("Conversions should be defined");
    // Track whether any non-sentinel conversions are found
    let mut conversions_found = false;
    for (addr, epoch, conv, _) in conv_state.assets.values() {
        let amt: masp_primitives::transaction::components::Amount =
            conv.clone().into();
        // If the user has specified any targets, then meet them
        // If we have a sentinel conversion, then skip printing
        if matches!(&target_token, Some(target) if target != addr)
            || matches!(&args.epoch, Some(target) if target != epoch)
            || amt == masp_primitives::transaction::components::Amount::zero()
        {
            continue;
        }
        conversions_found = true;
        // Print the asset to which the conversion applies
        let addr_enc = addr.encode();
        print!(
            "{}[{}]: ",
            tokens.get(addr).cloned().unwrap_or(addr_enc.as_str()),
            epoch,
        );
        // Now print out the components of the allowed conversion
        let mut prefix = "";
        for (asset_type, val) in amt.components() {
            // Look up the address and epoch of asset to facilitate pretty
            // printing
            let (addr, epoch, _, _) = &conv_state.assets[asset_type];
            // Now print out this component of the conversion
            let addr_enc = addr.encode();
            print!(
                "{}{} {}[{}]",
                prefix,
                val,
                tokens.get(addr).cloned().unwrap_or(addr_enc.as_str()),
                epoch
            );
            // Future iterations need to be prefixed with +
            prefix = " + ";
        }
        // Allowed conversions are always implicit equations
        println!(" = 0");
    }
    if !conversions_found {
        println!("No conversions found satisfying specified criteria.");
    }
}

/// Query a conversion.
pub async fn query_conversion(
    client: HttpClient,
    asset_type: AssetType,
) -> Option<(
    Address,
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
)> {
    Some(unwrap_client_response(
        RPC.shell().read_conversion(&client, &asset_type).await,
    ))
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<T,C>(
    client: &C,
    key: &storage::Key,
) -> Option<T>
where
    T: BorshDeserialize,
    C: queries::Client<Error = queries::tm::Error> + Sync,
{
    // In case `T` is a unit (only thing that encodes to 0 bytes), we have to
    // use `storage_has_key` instead of `storage_value`, because `storage_value`
    // returns 0 bytes when the key is not found.
    let maybe_unit = T::try_from_slice(&[]);
    if let Ok(unit) = maybe_unit {
        return if unwrap_client_response(
            RPC.shell().storage_has_key(client, key).await,
        ) {
            Some(unit)
        } else {
            None
        };
    }

    let response = unwrap_client_response(
        RPC.shell()
            .storage_value(client, None, None, false, key)
            .await,
    );
    if response.data.is_empty() {
        return None;
    }
    T::try_from_slice(&response.data[..])
        .map(Some)
        .unwrap_or_else(|err| {
            eprintln!("Error decoding the value: {}", err);
            cli::safe_exit(1)
        })
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes(
    client: &HttpClient,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> (Option<Vec<u8>>, Option<Proof>) {
    let data = None;
    let response = unwrap_client_response(
        RPC.shell()
            .storage_value(client, data, height, prove, key)
            .await,
    );
    if response.data.is_empty() {
        (None, response.proof)
    } else {
        (Some(response.data), response.proof)
    }
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<T>(
    client: &HttpClient,
    key: &storage::Key,
) -> Option<impl Iterator<Item = (storage::Key, T)>>
where
    T: BorshDeserialize,
{
    let values = unwrap_client_response(
        RPC.shell()
            .storage_prefix(client, None, None, false, key)
            .await,
    );
    let decode =
        |PrefixValue { key, value }: PrefixValue| match T::try_from_slice(
            &value[..],
        ) {
            Err(err) => {
                eprintln!(
                    "Skipping a value for key {}. Error in decoding: {}",
                    key, err
                );
                None
            }
            Ok(value) => Some((key, value)),
        };
    if values.data.is_empty() {
        None
    } else {
        Some(values.data.into_iter().filter_map(decode))
    }
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<C>(client: &C, key: &storage::Key) -> bool
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    unwrap_client_response(RPC.shell().storage_has_key(client, key).await)
}

/// Represents a query for an event pertaining to the specified transaction
#[derive(Debug, Copy, Clone)]
pub enum TxEventQuery<'a> {
    Accepted(&'a str),
    Applied(&'a str),
}

impl<'a> TxEventQuery<'a> {
    /// The event type to which this event query pertains
    fn event_type(self) -> &'static str {
        match self {
            TxEventQuery::Accepted(_) => "accepted",
            TxEventQuery::Applied(_) => "applied",
        }
    }

    /// The transaction to which this event query pertains
    fn tx_hash(self) -> &'a str {
        match self {
            TxEventQuery::Accepted(tx_hash) => tx_hash,
            TxEventQuery::Applied(tx_hash) => tx_hash,
        }
    }
}

/// Transaction event queries are semantically a subset of general queries
impl<'a> From<TxEventQuery<'a>> for Query {
    fn from(tx_query: TxEventQuery<'a>) -> Self {
        match tx_query {
            TxEventQuery::Accepted(tx_hash) => {
                Query::default().and_eq("accepted.hash", tx_hash)
            }
            TxEventQuery::Applied(tx_hash) => {
                Query::default().and_eq("applied.hash", tx_hash)
            }
        }
    }
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transation.
pub async fn query_tx_events<C>(
    client: &C,
    tx_event_query: TxEventQuery<'_>,
) -> eyre::Result<Option<Event>>
where
    C: queries::Client<Error = queries::tm::Error> + Sync
{
    let tx_hash: Hash = tx_event_query.tx_hash().try_into()?;
    match tx_event_query {
        TxEventQuery::Accepted(_) => RPC
            .shell()
            .accepted(client, &tx_hash)
            .await
            .wrap_err_with(|| {
                eyre!("Failed querying whether a transaction was accepted")
            }),
        TxEventQuery::Applied(_) => RPC
            .shell()
            .applied(client, &tx_hash)
            .await
            .wrap_err_with(|| {
                eyre!("Error querying whether a transaction was applied")
            }),
    }
}

/// Lookup the full response accompanying the specified transaction event
// TODO: maybe remove this in favor of `query_tx_status`
pub async fn query_tx_response(
    client: &WebSocketClient,
    tx_query: TxEventQuery<'_>,
) -> Result<TxResponse, TError> {
    // Find all blocks that apply a transaction with the specified hash
    let blocks = &client
        .block_search(tx_query.into(), 1, 255, Order::Ascending)
        .await
        .expect("Unable to query for transaction with given hash")
        .blocks;
    // Get the block results corresponding to a block to which
    // the specified transaction belongs
    let block = &blocks
        .get(0)
        .ok_or_else(|| {
            TError::server(
                "Unable to find a block applying the given transaction"
                    .to_string(),
            )
        })?
        .block;
    let response_block_results = client
        .block_results(block.header.height)
        .await
        .expect("Unable to retrieve block containing transaction");
    // Search for the event where the specified transaction is
    // applied to the blockchain
    let query_event_opt =
        response_block_results.end_block_events.and_then(|events| {
            events
                .iter()
                .find(|event| {
                    event.type_str == tx_query.event_type()
                        && event.attributes.iter().any(|tag| {
                            tag.key.as_ref() == "hash"
                                && tag.value.as_ref() == tx_query.tx_hash()
                        })
                })
                .cloned()
        });
    let query_event = query_event_opt.ok_or_else(|| {
        TError::server(
            "Unable to find the event corresponding to the specified \
             transaction"
                .to_string(),
        )
    })?;
    // Reformat the event attributes so as to ease value extraction
    let event_map: std::collections::HashMap<&str, &str> = query_event
        .attributes
        .iter()
        .map(|tag| (tag.key.as_ref(), tag.value.as_ref()))
        .collect();
    // Summarize the transaction results that we were searching for
    let result = TxResponse {
        info: event_map["info"].to_string(),
        log: event_map["log"].to_string(),
        height: event_map["height"].to_string(),
        hash: event_map["hash"].to_string(),
        code: event_map["code"].to_string(),
        gas_used: event_map["gas_used"].to_string(),
        initialized_accounts: serde_json::from_str(
            event_map["initialized_accounts"],
        )
        .unwrap_or_default(),
    };
    Ok(result)
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.
pub async fn query_result(client: &WebSocketClient, args: args::QueryResult) {
    // First try looking up application event pertaining to given hash.
    let tx_response = query_tx_response(
        client,
        TxEventQuery::Applied(&args.tx_hash),
    )
    .await;
    match tx_response {
        Ok(result) => {
            println!(
                "Transaction was applied with result: {}",
                serde_json::to_string_pretty(&result).unwrap()
            )
        }
        Err(err1) => {
            // If this fails then instead look for an acceptance event.
            let tx_response = query_tx_response(
                client,
                TxEventQuery::Accepted(&args.tx_hash),
            )
            .await;
            match tx_response {
                Ok(result) => println!(
                    "Transaction was accepted with result: {}",
                    serde_json::to_string_pretty(&result).unwrap()
                ),
                Err(err2) => {
                    // Print the errors that caused the lookups to fail
                    eprintln!("{}\n{}", err1, err2);
                    cli::safe_exit(1)
                }
            }
        }
    }
}

pub async fn get_proposal_votes(
    client: &HttpClient,
    epoch: Epoch,
    proposal_id: u64,
) -> Votes {
    let validators = get_all_validators(client, epoch).await;

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter =
        query_storage_prefix::<ProposalVote>(client, &vote_prefix_key).await;

    let mut yay_validators: HashMap<Address, VotePower> = HashMap::new();
    let mut yay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();
    let mut nay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();

    if let Some(vote_iter) = vote_iter {
        for (key, vote) in vote_iter {
            let voter_address = gov_storage::get_voter_address(&key)
                .expect("Vote key should contain the voting address.")
                .clone();
            if vote.is_yay() && validators.contains(&voter_address) {
                let amount: VotePower =
                    get_validator_stake(client, epoch, &voter_address)
                        .await
                        .into();
                yay_validators.insert(voter_address, amount);
            } else if !validators.contains(&voter_address) {
                let validator_address =
                    gov_storage::get_vote_delegation_address(&key)
                        .expect(
                            "Vote key should contain the delegation address.",
                        )
                        .clone();
                let delegator_token_amount = get_bond_amount_at(
                    client,
                    &voter_address,
                    &validator_address,
                    epoch,
                )
                .await;
                if let Some(amount) = delegator_token_amount {
                    if vote.is_yay() {
                        let entry =
                            yay_delegators.entry(voter_address).or_default();
                        entry
                            .insert(validator_address, VotePower::from(amount));
                    } else {
                        let entry =
                            nay_delegators.entry(voter_address).or_default();
                        entry
                            .insert(validator_address, VotePower::from(amount));
                    }
                }
            }
        }
    }

    Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    }
}

pub async fn get_proposal_offline_votes(
    client: &HttpClient,
    proposal: OfflineProposal,
    files: HashSet<PathBuf>,
) -> Votes {
    let validators = get_all_validators(client, proposal.tally_epoch).await;

    let proposal_hash = proposal.compute_hash();

    let mut yay_validators: HashMap<Address, VotePower> = HashMap::new();
    let mut yay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();
    let mut nay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();

    for path in files {
        let file = File::open(&path).expect("Proposal file must exist.");
        let proposal_vote: OfflineVote = serde_json::from_reader(file)
            .expect("JSON was not well-formatted for offline vote.");

        let key = pk_key(&proposal_vote.address);
        let public_key = query_storage_value(client, &key)
            .await
            .expect("Public key should exist.");

        if !proposal_vote.proposal_hash.eq(&proposal_hash)
            || !proposal_vote.check_signature(&public_key)
        {
            continue;
        }

        if proposal_vote.vote.is_yay()
            && validators.contains(&proposal_vote.address)
        {
            let amount: VotePower = get_validator_stake(
                client,
                proposal.tally_epoch,
                &proposal_vote.address,
            )
            .await
            .into();
            yay_validators.insert(proposal_vote.address, amount);
        } else if is_delegator_at(
            client,
            &proposal_vote.address,
            proposal.tally_epoch,
        )
        .await
        {
            let key = pos::bonds_for_source_prefix(&proposal_vote.address);
            let bonds_iter =
                query_storage_prefix::<pos::Bonds>(client, &key).await;
            if let Some(bonds) = bonds_iter {
                for (key, epoched_bonds) in bonds {
                    // Look-up slashes for the validator in this key and
                    // apply them if any
                    let validator = pos::get_validator_address_from_bond(&key)
                        .expect(
                            "Delegation key should contain validator address.",
                        );
                    let slashes_key = pos::validator_slashes_key(&validator);
                    let slashes = query_storage_value::<pos::Slashes,HttpClient>(
                        client,
                        &slashes_key,
                    )
                    .await
                    .unwrap_or_default();
                    let mut delegated_amount: token::Amount = 0.into();
                    let bond = epoched_bonds
                        .get(proposal.tally_epoch)
                        .expect("Delegation bond should be defined.");
                    let mut to_deduct = bond.neg_deltas;
                    for (start_epoch, &(mut delta)) in
                        bond.pos_deltas.iter().sorted()
                    {
                        // deduct bond's neg_deltas
                        if to_deduct > delta {
                            to_deduct -= delta;
                            // If the whole bond was deducted, continue to
                            // the next one
                            continue;
                        } else {
                            delta -= to_deduct;
                            to_deduct = token::Amount::default();
                        }

                        delta = apply_slashes(
                            &slashes,
                            delta,
                            *start_epoch,
                            None,
                            None,
                        );
                        delegated_amount += delta;
                    }

                    let validator_address =
                        pos::get_validator_address_from_bond(&key).expect(
                            "Delegation key should contain validator address.",
                        );
                    if proposal_vote.vote.is_yay() {
                        let entry = yay_delegators
                            .entry(proposal_vote.address.clone())
                            .or_default();
                        entry.insert(
                            validator_address,
                            VotePower::from(delegated_amount),
                        );
                    } else {
                        let entry = nay_delegators
                            .entry(proposal_vote.address.clone())
                            .or_default();
                        entry.insert(
                            validator_address,
                            VotePower::from(delegated_amount),
                        );
                    }
                }
            }
        }
    }

    Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    }
}

// Compute the result of a proposal
pub async fn compute_tally(
    client: &HttpClient,
    epoch: Epoch,
    votes: Votes,
) -> ProposalResult {
    let total_staked_tokens: VotePower =
        get_total_staked_tokens(client, epoch).await.into();

    let Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::from(0_u64);
    for (_, amount) in yay_validators.clone().into_iter() {
        total_yay_staked_tokens += amount;
    }

    // YAY: Add delegator amount whose validator didn't vote / voted nay
    for (_, vote_map) in yay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if !yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens += vote_power;
            }
        }
    }

    // NAY: Remove delegator amount whose validator validator vote yay
    for (_, vote_map) in nay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens -= vote_power;
            }
        }
    }

    if total_yay_staked_tokens >= (total_staked_tokens / 3) * 2 {
        ProposalResult {
            result: TallyResult::Passed,
            total_voting_power: total_staked_tokens,
            total_yay_power: total_yay_staked_tokens,
            total_nay_power: 0,
        }
    } else {
        ProposalResult {
            result: TallyResult::Rejected,
            total_voting_power: total_staked_tokens,
            total_yay_power: total_yay_staked_tokens,
            total_nay_power: 0,
        }
    }
}

pub async fn get_bond_amount_at(
    client: &HttpClient,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let slashes_key = pos::validator_slashes_key(validator);
    let slashes = query_storage_value::<pos::Slashes,HttpClient>(client, &slashes_key)
        .await
        .unwrap_or_default();
    let bond_key = pos::bond_key(&BondId {
        source: delegator.clone(),
        validator: validator.clone(),
    });
    let epoched_bonds = query_storage_value::<Bonds,HttpClient>(client, &bond_key).await;
    match epoched_bonds {
        Some(epoched_bonds) => {
            let mut delegated_amount: token::Amount = 0.into();
            for bond in epoched_bonds.iter() {
                let mut to_deduct = bond.neg_deltas;
                for (epoch_start, &(mut delta)) in
                    bond.pos_deltas.iter().sorted()
                {
                    // deduct bond's neg_deltas
                    if to_deduct > delta {
                        to_deduct -= delta;
                        // If the whole bond was deducted, continue to
                        // the next one
                        continue;
                    } else {
                        delta -= to_deduct;
                        to_deduct = token::Amount::default();
                    }

                    delta = apply_slashes(
                        &slashes,
                        delta,
                        *epoch_start,
                        None,
                        None,
                    );
                    if epoch >= *epoch_start {
                        delegated_amount += delta;
                    }
                }
            }
            Some(delegated_amount)
        }
        None => None,
    }
}

pub async fn get_all_validators(
    client: &HttpClient,
    epoch: Epoch,
) -> HashSet<Address> {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .validator_addresses(client, &Some(epoch))
            .await,
    )
}

pub async fn get_total_staked_tokens(
    client: &HttpClient,
    epoch: Epoch,
) -> token::Amount {
    unwrap_client_response(
        RPC.vp().pos().total_stake(client, &Some(epoch)).await,
    )
}

async fn get_validator_stake(
    client: &HttpClient,
    epoch: Epoch,
    validator: &Address,
) -> token::Amount {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
}

pub async fn get_delegators_delegation(
    client: &HttpClient,
    address: &Address,
) -> HashSet<Address> {
    unwrap_client_response(RPC.vp().pos().delegations(client, address).await)
}

pub async fn get_governance_parameters(client: &HttpClient) -> GovParams {
    use namada::types::token::Amount;
    let key = gov_storage::get_max_proposal_code_size_key();
    let max_proposal_code_size = query_storage_value::<u64,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_content_key();
    let max_proposal_content_size = query_storage_value::<u64,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_fund_key();
    let min_proposal_fund = query_storage_value::<Amount,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_grace_epoch_key();
    let min_proposal_grace_epochs = query_storage_value::<u64,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_period_key();
    let min_proposal_period = query_storage_value::<u64,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_period_key();
    let max_proposal_period = query_storage_value::<u64,HttpClient>(client, &key)
        .await
        .expect("Parameter should be definied.");

    GovParams {
        min_proposal_fund: u64::from(min_proposal_fund),
        max_proposal_code_size,
        min_proposal_period,
        max_proposal_period,
        max_proposal_content_size,
        min_proposal_grace_epochs,
    }
}

/// Try to find an alias for a given address from the wallet. If not found,
/// formats the address into a string.
fn lookup_alias(wallet: &Wallet<std::path::PathBuf>, addr: &Address) -> String {
    match wallet.find_alias(addr) {
        Some(alias) => format!("{}", alias),
        None => format!("{}", addr),
    }
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<T>(response: Result<T, queries::tm::Error>) -> T {
    response.unwrap_or_else(|err| {
        eprintln!("Error in the query {}", err);
        cli::safe_exit(1)
    })
}
