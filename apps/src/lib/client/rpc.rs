//! Client RPC queries

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::iter::Iterator;
use std::str::FromStr;
use std::time::Duration;

use async_std::fs;
use async_std::path::PathBuf;
use async_std::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use itertools::Either;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::transaction::components::Amount;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::core::types::transaction::governance::ProposalType;
use namada::ledger::events::Event;
use namada::ledger::governance::parameters::GovParams;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::masp::{
    Conversions, PinnedBalanceError, ShieldedContext, ShieldedUtils,
};
use namada::ledger::native_vp::governance::utils::{self, Votes};
use namada::ledger::parameters::{storage as param_storage, EpochDuration};
use namada::ledger::pos::{
    self, BondId, BondsAndUnbondsDetail, CommissionPair, PosParams, Slash,
};
use namada::ledger::queries::RPC;
use namada::ledger::rpc::{
    enriched_bonds_and_unbonds, query_epoch, TxResponse,
};
use namada::ledger::storage::ConversionState;
use namada::ledger::wallet::{AddressVpType, Wallet};
use namada::proof_of_stake::types::WeightedValidator;
use namada::types::address::{masp, Address};
use namada::types::governance::{
    OfflineProposal, OfflineVote, ProposalVote, VotePower, VoteType,
};
use namada::types::hash::Hash;
use namada::types::key::*;
use namada::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use namada::types::storage::{BlockHeight, BlockResults, Epoch, Key, KeySeg};
use namada::types::{storage, token};

use crate::cli::{self, args};
use crate::facade::tendermint::merkle::proof::Proof;
use crate::facade::tendermint_rpc::error::Error as TError;
use crate::wallet::CliWalletUtils;

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    status: namada::ledger::rpc::TxEventQuery<'_>,
    deadline: Duration,
) -> Event {
    namada::ledger::rpc::query_tx_status(client, status, deadline).await
}

/// Query and print the epoch of the last committed block
pub async fn query_and_print_epoch<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
) -> Epoch {
    let epoch = namada::ledger::rpc::query_epoch(client).await;
    println!("Last committed epoch: {}", epoch);
    epoch
}

/// Query the last committed block
pub async fn query_block<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
) {
    let block = namada::ledger::rpc::query_block(client).await;
    match block {
        Some(block) => {
            println!(
                "Last committed block ID: {}, height: {}, time: {}",
                block.hash, block.height, block.time
            );
        }
        None => {
            println!("No block has been committed yet.");
        }
    }
}

/// Query the results of the last committed block
pub async fn query_results<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    _args: args::Query,
) -> Vec<BlockResults> {
    unwrap_client_response::<C, Vec<BlockResults>>(
        RPC.shell().read_results(client).await,
    )
}

/// Query the specified accepted transfers from the ledger
pub async fn query_transfers<
    C: namada::ledger::queries::Client + Send + Sync,
    U: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryTransfers,
) {
    let query_token = args.token;
    let query_owner = args.owner.map_or_else(
        || Either::Right(wallet.get_addresses().into_values().collect()),
        Either::Left,
    );
    let _ = shielded.load().await;
    // Obtain the effects of all shielded and transparent transactions
    let transfers = shielded
        .query_tx_deltas(
            client,
            &query_owner,
            &query_token,
            &wallet.get_viewing_keys(),
        )
        .await;
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
                    client,
                    amt,
                    epoch,
                    Conversions::new(),
                )
                .await
                .0;
            let dec = shielded.decode_amount(client, amt, epoch).await;
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
                    let token_alias = lookup_alias(wallet, addr);
                    let sign = match val.cmp(&0) {
                        Ordering::Greater => "+",
                        Ordering::Less => "-",
                        Ordering::Equal => "",
                    };
                    print!(
                        " {}{} {}",
                        sign,
                        token::Amount::from(val.unsigned_abs()),
                        token_alias
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
                    let token_alias = lookup_alias(wallet, addr);
                    let sign = match val.cmp(&0) {
                        Ordering::Greater => "+",
                        Ordering::Less => "-",
                        Ordering::Equal => "",
                    };
                    print!(
                        " {}{} {}",
                        sign,
                        token::Amount::from(val.unsigned_abs()),
                        token_alias
                    );
                }
                println!();
            }
        }
    }
}

/// Query the raw bytes of given storage key
pub async fn query_raw_bytes<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    args: args::QueryRawBytes,
) {
    let response = unwrap_client_response::<C, _>(
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
pub async fn query_balance<
    C: namada::ledger::queries::Client + Send + Sync,
    U: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
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
            query_shielded_balance(client, wallet, shielded, args.clone())
                .await;
            // Then print transparent balance
            query_transparent_balance(client, wallet, args).await;
        }
    };
}

/// Query token balance(s)
pub async fn query_transparent_balance<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
    args: args::QueryBalance,
) {
    let tokens = wallet.get_addresses_with_vp_type(AddressVpType::Token);
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
            let token_alias = lookup_alias(wallet, &token);
            match query_storage_value::<C, token::Amount>(client, &key).await {
                Some(balance) => match &args.sub_prefix {
                    Some(sub_prefix) => {
                        println!(
                            "{} with {}: {}",
                            token_alias, sub_prefix, balance
                        );
                    }
                    None => println!("{}: {}", token_alias, balance),
                },
                None => {
                    println!("No {} balance found for {}", token_alias, owner)
                }
            }
        }
        (None, Some(owner)) => {
            for token in tokens {
                let prefix =
                    token::balance_key(&token, &owner.address().unwrap());
                let balances =
                    query_storage_prefix::<C, token::Amount>(client, &prefix)
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
            let prefix = token::balance_prefix(&token);
            let balances =
                query_storage_prefix::<C, token::Amount>(client, &prefix).await;
            if let Some(balances) = balances {
                print_balances(wallet, balances, &token, None);
            }
        }
        (None, None) => {
            for token in tokens {
                let key = token::balance_prefix(&token);
                let balances =
                    query_storage_prefix::<C, token::Amount>(client, &key)
                        .await;
                if let Some(balances) = balances {
                    print_balances(wallet, balances, &token, None);
                }
            }
        }
    }
}

/// Query the token pinned balance(s)
pub async fn query_pinned_balance<
    C: namada::ledger::queries::Client + Send + Sync,
    U: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
    shielded: &mut ShieldedContext<U>,
    args: args::QueryBalance,
) {
    // Map addresses to token names
    let tokens = wallet.get_addresses_with_vp_type(AddressVpType::Token);
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
    let _ = shielded.load().await;
    // Print the token balances by payment address
    for owner in owners {
        let mut balance = Err(PinnedBalanceError::InvalidViewingKey);
        // Find the viewing key that can recognize payments the current payment
        // address
        for vk in &viewing_keys {
            balance = shielded
                .compute_exchanged_pinned_balance(client, owner, vk)
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
                .compute_exchanged_pinned_balance(client, owner, &vk)
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
                let token_alias = lookup_alias(wallet, token);
                if balance == 0 {
                    println!(
                        "Payment address {} was consumed during epoch {}. \
                         Received no shielded {}",
                        owner, epoch, token_alias
                    );
                } else {
                    let asset_value = token::Amount::from(balance as u64);
                    println!(
                        "Payment address {} was consumed during epoch {}. \
                         Received {} {}",
                        owner, epoch, asset_value, token_alias
                    );
                }
            }
            (Ok((balance, epoch)), None) => {
                let mut found_any = false;
                // Print balances by human-readable token names
                let balance =
                    shielded.decode_amount(client, balance, epoch).await;
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
                    println!(
                        "  {}: {}",
                        tokens
                            .get(addr)
                            .cloned()
                            .unwrap_or_else(|| addr.clone()),
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
    wallet: &Wallet<CliWalletUtils>,
    balances: impl Iterator<Item = (storage::Key, token::Amount)>,
    token: &Address,
    target: Option<&Address>,
) {
    let stdout = io::stdout();
    let mut w = stdout.lock();

    let token_alias = lookup_alias(wallet, token);
    writeln!(w, "Token {}", token_alias).unwrap();

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
                writeln!(w, "No balances for token {}", token_alias).unwrap()
            }
        }
    }
}

/// Query Proposals
pub async fn query_proposal<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    args: args::QueryProposal,
) {
    async fn print_proposal<
        C: namada::ledger::queries::Client + Send + Sync,
    >(
        client: &C,
        id: u64,
        current_epoch: Epoch,
        details: bool,
    ) -> Option<()> {
        let author_key = gov_storage::get_author_key(id);
        let start_epoch_key = gov_storage::get_voting_start_epoch_key(id);
        let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
        let proposal_type_key = gov_storage::get_proposal_type_key(id);

        let author =
            query_storage_value::<C, Address>(client, &author_key).await?;
        let start_epoch =
            query_storage_value::<C, Epoch>(client, &start_epoch_key).await?;
        let end_epoch =
            query_storage_value::<C, Epoch>(client, &end_epoch_key).await?;
        let proposal_type =
            query_storage_value::<C, ProposalType>(client, &proposal_type_key)
                .await?;

        if details {
            let content_key = gov_storage::get_content_key(id);
            let grace_epoch_key = gov_storage::get_grace_epoch_key(id);
            let content = query_storage_value::<C, HashMap<String, String>>(
                client,
                &content_key,
            )
            .await?;
            let grace_epoch =
                query_storage_value::<C, Epoch>(client, &grace_epoch_key)
                    .await?;

            println!("Proposal: {}", id);
            println!("{:4}Type: {}", "", proposal_type);
            println!("{:4}Author: {}", "", author);
            println!("{:4}Content:", "");
            for (key, value) in &content {
                println!("{:8}{}: {}", "", key, value);
            }
            println!("{:4}Start Epoch: {}", "", start_epoch);
            println!("{:4}End Epoch: {}", "", end_epoch);
            println!("{:4}Grace Epoch: {}", "", grace_epoch);
            let votes = get_proposal_votes(client, start_epoch, id).await;
            let total_stake =
                get_total_staked_tokens(client, start_epoch).await.into();
            if start_epoch > current_epoch {
                println!("{:4}Status: pending", "");
            } else if start_epoch <= current_epoch && current_epoch <= end_epoch
            {
                match utils::compute_tally(votes, total_stake, &proposal_type) {
                    Ok(partial_proposal_result) => {
                        println!(
                            "{:4}Yay votes: {}",
                            "", partial_proposal_result.total_yay_power
                        );
                        println!(
                            "{:4}Nay votes: {}",
                            "", partial_proposal_result.total_nay_power
                        );
                        println!("{:4}Status: on-going", "");
                    }
                    Err(msg) => {
                        eprintln!("Error in tally computation: {}", msg)
                    }
                }
            } else {
                match utils::compute_tally(votes, total_stake, &proposal_type) {
                    Ok(proposal_result) => {
                        println!("{:4}Status: done", "");
                        println!("{:4}Result: {}", "", proposal_result);
                    }
                    Err(msg) => {
                        eprintln!("Error in tally computation: {}", msg)
                    }
                }
            }
        } else {
            println!("Proposal: {}", id);
            println!("{:4}Type: {}", "", proposal_type);
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

    let current_epoch = query_and_print_epoch(client).await;
    match args.proposal_id {
        Some(id) => {
            if print_proposal::<C>(client, id, current_epoch, true)
                .await
                .is_none()
            {
                eprintln!("No valid proposal was found with id {}", id)
            }
        }
        None => {
            let last_proposal_id_key = gov_storage::get_counter_key();
            let last_proposal_id =
                query_storage_value::<C, u64>(client, &last_proposal_id_key)
                    .await
                    .unwrap();

            for id in 0..last_proposal_id {
                if print_proposal::<C>(client, id, current_epoch, false)
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
pub async fn query_shielded_balance<
    C: namada::ledger::queries::Client + Send + Sync,
    U: ShieldedUtils,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
    shielded: &mut ShieldedContext<U>,
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
        None => wallet.get_viewing_keys().values().copied().collect(),
    };
    let _ = shielded.load().await;
    let fvks: Vec<_> = viewing_keys
        .iter()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    shielded.fetch(client, &[], &fvks).await;
    // Save the update state so that future fetches can be short-circuited
    let _ = shielded.save().await;
    // The epoch is required to identify timestamped tokens
    let epoch = query_and_print_epoch(client).await;
    // Map addresses to token names
    let tokens = wallet.get_addresses_with_vp_type(AddressVpType::Token);
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
                    .compute_exchanged_balance(client, &viewing_key, epoch)
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
            let token_alias = lookup_alias(wallet, &token);
            if balance[&asset_type] == 0 {
                println!(
                    "No shielded {} balance found for given key",
                    token_alias
                );
            } else {
                let asset_value =
                    token::Amount::from(balance[&asset_type] as u64);
                println!("{}: {}", token_alias, asset_value);
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
                        .compute_exchanged_balance(client, &viewing_key, epoch)
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
                let decoded =
                    shielded.decode_asset_type(client, asset_type).await;
                match decoded {
                    Some((addr, asset_epoch)) if asset_epoch == epoch => {
                        // Only assets with the current timestamp count
                        println!(
                            "Shielded Token {}:",
                            tokens
                                .get(&addr)
                                .cloned()
                                .unwrap_or_else(|| addr.clone())
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
            for token in tokens {
                if !read_tokens.contains(&token) {
                    let token_alias = lookup_alias(wallet, &token);
                    println!("Shielded Token {}:", token_alias);
                    println!(
                        "No shielded {} balance found for any wallet key",
                        token_alias
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
            let token_alias = lookup_alias(wallet, &token);
            println!("Shielded Token {}:", token_alias);
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
                        .compute_exchanged_balance(client, &viewing_key, epoch)
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
                    token_alias
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
                let decoded_balance =
                    shielded.decode_all_amounts(client, balance).await;
                print_decoded_balance_with_epoch(wallet, decoded_balance);
            } else {
                balance = shielded
                    .compute_exchanged_balance(client, &viewing_key, epoch)
                    .await
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                let decoded_balance =
                    shielded.decode_amount(client, balance, epoch).await;
                print_decoded_balance(wallet, decoded_balance);
            }
        }
    }
}

pub fn print_decoded_balance(
    wallet: &mut Wallet<CliWalletUtils>,
    decoded_balance: Amount<Address>,
) {
    let mut found_any = false;
    for (addr, value) in decoded_balance.components() {
        let asset_value = token::Amount::from(*value as u64);
        println!("{} : {}", lookup_alias(wallet, addr), asset_value);
        found_any = true;
    }
    if !found_any {
        println!("No shielded balance found for given key");
    }
}

pub fn print_decoded_balance_with_epoch(
    wallet: &mut Wallet<CliWalletUtils>,
    decoded_balance: Amount<(Address, Epoch)>,
) {
    let tokens = wallet.get_addresses_with_vp_type(AddressVpType::Token);
    let mut found_any = false;
    for ((addr, epoch), value) in decoded_balance.components() {
        let asset_value = token::Amount::from(*value as u64);
        println!(
            "{} | {} : {}",
            tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
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
pub async fn get_token_balance<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    token: &Address,
    owner: &Address,
) -> Option<token::Amount> {
    namada::ledger::rpc::get_token_balance(client, token, owner).await
}

pub async fn query_proposal_result<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    args: args::QueryProposalResult,
) {
    let current_epoch = query_epoch(client).await;

    match args.proposal_id {
        Some(id) => {
            let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
            let end_epoch =
                query_storage_value::<C, Epoch>(client, &end_epoch_key).await;

            match end_epoch {
                Some(end_epoch) => {
                    if current_epoch > end_epoch {
                        let votes =
                            get_proposal_votes(client, end_epoch, id).await;
                        let proposal_type_key =
                            gov_storage::get_proposal_type_key(id);
                        let proposal_type = query_storage_value::<
                            C,
                            ProposalType,
                        >(
                            client, &proposal_type_key
                        )
                        .await
                        .expect("Could not read proposal type from storage");
                        let total_stake =
                            get_total_staked_tokens(client, end_epoch)
                                .await
                                .into();
                        println!("Proposal: {}", id);
                        match utils::compute_tally(
                            votes,
                            total_stake,
                            &proposal_type,
                        ) {
                            Ok(proposal_result) => {
                                println!("{:4}Result: {}", "", proposal_result)
                            }
                            Err(msg) => {
                                eprintln!("Error in tally computation: {}", msg)
                            }
                        }
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

                        let public_key =
                            get_public_key(client, &proposal.address)
                                .await
                                .expect("Public key should exist.");

                        if !proposal.check_signature(&public_key) {
                            eprintln!("Bad proposal signature.");
                            cli::safe_exit(1)
                        }

                        let votes = get_proposal_offline_votes(
                            client,
                            proposal.clone(),
                            files,
                        )
                        .await;
                        let total_stake = get_total_staked_tokens(
                            client,
                            proposal.tally_epoch,
                        )
                        .await
                        .into();
                        match utils::compute_tally(
                            votes,
                            total_stake,
                            &ProposalType::Default(None),
                        ) {
                            Ok(proposal_result) => {
                                println!("{:4}Result: {}", "", proposal_result)
                            }
                            Err(msg) => {
                                eprintln!("Error in tally computation: {}", msg)
                            }
                        }
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

pub async fn query_protocol_parameters<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    _args: args::QueryProtocolParameters,
) {
    let gov_parameters = get_governance_parameters(client).await;
    println!("Governance Parameters\n {:4}", gov_parameters);

    println!("Protocol parameters");
    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration = query_storage_value::<C, EpochDuration>(client, &key)
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
    let max_block_duration = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}Max. block duration: {}", "", max_block_duration);

    let key = param_storage::get_tx_whitelist_storage_key();
    let vp_whitelist = query_storage_value::<C, Vec<String>>(client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}VP whitelist: {:?}", "", vp_whitelist);

    let key = param_storage::get_tx_whitelist_storage_key();
    let tx_whitelist = query_storage_value::<C, Vec<String>>(client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}Transactions whitelist: {:?}", "", tx_whitelist);

    println!("PoS parameters");
    let key = pos::params_key();
    let pos_params = query_storage_value::<C, PosParams>(client, &key)
        .await
        .expect("Parameter should be defined.");
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

pub async fn query_bond<C: namada::ledger::queries::Client + Send + Sync>(
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
    C: namada::ledger::queries::Client + Send + Sync,
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

pub async fn query_and_print_unbonds<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    source: &Address,
    validator: &Address,
) {
    let unbonds = query_unbond_with_slashing(client, source, validator).await;
    let current_epoch = query_epoch(client).await;

    let mut total_withdrawable = token::Amount::default();
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
    if total_withdrawable != token::Amount::default() {
        println!("Total withdrawable now: {total_withdrawable}.");
    }
    if !not_yet_withdrawable.is_empty() {
        println!("Current epoch: {current_epoch}.")
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        println!(
            "Amount {amount} withdrawable starting from epoch \
             {withdraw_epoch}."
        );
    }
}

pub async fn query_withdrawable_tokens<
    C: namada::ledger::queries::Client + Send + Sync,
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
pub async fn query_bonds<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    _wallet: &mut Wallet<CliWalletUtils>,
    args: args::QueryBonds,
) -> std::io::Result<()> {
    let epoch = query_and_print_epoch(client).await;

    let source = args.owner;
    let validator = args.validator;

    let stdout = io::stdout();
    let mut w = stdout.lock();

    let bonds_and_unbonds =
        enriched_bonds_and_unbonds(client, epoch, &source, &validator).await;

    for (bond_id, details) in &bonds_and_unbonds.data {
        let bond_type = if bond_id.source == bond_id.validator {
            format!("Self-bonds from {}", bond_id.validator)
        } else {
            format!(
                "Delegations from {} to {}",
                bond_id.source, bond_id.validator
            )
        };
        writeln!(w, "{}:", bond_type)?;
        for bond in &details.data.bonds {
            writeln!(
                w,
                "  Remaining active bond from epoch {}: Δ {}",
                bond.start, bond.amount
            )?;
        }
        if details.bonds_total_slashed != token::Amount::default() {
            writeln!(
                w,
                "Active (slashed) bonds total: {}",
                details.bonds_total_active()
            )?;
        }
        writeln!(w, "Bonds total: {}", details.bonds_total)?;
        writeln!(w)?;

        if !details.data.unbonds.is_empty() {
            let bond_type = if bond_id.source == bond_id.validator {
                format!("Unbonded self-bonds from {}", bond_id.validator)
            } else {
                format!("Unbonded delegations from {}", bond_id.source)
            };
            writeln!(w, "{}:", bond_type)?;
            for unbond in &details.data.unbonds {
                writeln!(
                    w,
                    "  Withdrawable from epoch {} (active from {}): Δ {}",
                    unbond.withdraw, unbond.start, unbond.amount
                )?;
            }
            writeln!(w, "Unbonded total: {}", details.unbonds_total)?;
        }
        writeln!(w, "Withdrawable total: {}", details.total_withdrawable)?;
        writeln!(w)?;
    }
    if bonds_and_unbonds.bonds_total != bonds_and_unbonds.bonds_total_slashed {
        writeln!(
            w,
            "All bonds total active: {}",
            bonds_and_unbonds.bonds_total_active()
        )?;
    }
    writeln!(w, "All bonds total: {}", bonds_and_unbonds.bonds_total)?;

    if bonds_and_unbonds.unbonds_total
        != bonds_and_unbonds.unbonds_total_slashed
    {
        writeln!(
            w,
            "All unbonds total active: {}",
            bonds_and_unbonds.unbonds_total_active()
        )?;
    }
    writeln!(w, "All unbonds total: {}", bonds_and_unbonds.unbonds_total)?;
    writeln!(
        w,
        "All unbonds total withdrawable: {}",
        bonds_and_unbonds.total_withdrawable
    )?;
    Ok(())
}

/// Query PoS bonded stake
pub async fn query_bonded_stake<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    args: args::QueryBondedStake,
) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_and_print_epoch(client).await,
    };

    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find bonded stake for the given validator
            let stake = get_validator_stake(client, epoch, &validator).await;
            match stake {
                Some(stake) => {
                    // TODO: show if it's in consensus set, below capacity, or
                    // below threshold set
                    println!("Bonded stake of validator {validator}: {stake}",)
                }
                None => {
                    println!("No bonded stake found for {validator}")
                }
            }
        }
        None => {
            let consensus =
                unwrap_client_response::<C, HashSet<WeightedValidator>>(
                    RPC.vp()
                        .pos()
                        .consensus_validator_set(client, &Some(epoch))
                        .await,
                );
            let below_capacity =
                unwrap_client_response::<C, HashSet<WeightedValidator>>(
                    RPC.vp()
                        .pos()
                        .below_capacity_validator_set(client, &Some(epoch))
                        .await,
                );

            // Iterate all validators
            let stdout = io::stdout();
            let mut w = stdout.lock();

            writeln!(w, "Consensus validators:").unwrap();
            for val in consensus {
                writeln!(w, "  {}: {}", val.address.encode(), val.bonded_stake)
                    .unwrap();
            }
            if !below_capacity.is_empty() {
                writeln!(w, "Below capacity validators:").unwrap();
                for val in &below_capacity {
                    writeln!(
                        w,
                        "  {}: {}",
                        val.address.encode(),
                        val.bonded_stake
                    )
                    .unwrap();
                }
            }
        }
    }

    let total_staked_tokens = get_total_staked_tokens(client, epoch).await;
    println!("Total bonded stake: {total_staked_tokens}");
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<
    C: namada::ledger::queries::Client + Send + Sync,
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

/// Query PoS validator's commission rate information
pub async fn query_and_print_commission_rate<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    _wallet: &mut Wallet<CliWalletUtils>,
    args: args::QueryCommissionRate,
) {
    let validator = args.validator;

    let info: Option<CommissionPair> =
        query_commission_rate(client, &validator, args.epoch).await;
    match info {
        Some(CommissionPair {
            commission_rate: rate,
            max_commission_change_per_epoch: change,
        }) => {
            println!(
                "Validator {} commission rate: {}, max change per epoch: {}",
                validator.encode(),
                rate,
                change
            );
        }
        None => {
            println!(
                "Address {} is not a validator (did not find commission rate \
                 and max change)",
                validator.encode(),
            );
        }
    }
}

/// Query PoS slashes
pub async fn query_slashes<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    _wallet: &mut Wallet<CliWalletUtils>,
    args: args::QuerySlashes,
) {
    let params_key = pos::params_key();
    let params = query_storage_value::<C, PosParams>(client, &params_key)
        .await
        .expect("Parameter should be defined.");

    match args.validator {
        Some(validator) => {
            let validator = validator;
            // Find slashes for the given validator
            let slashes: Vec<Slash> = unwrap_client_response::<C, Vec<Slash>>(
                RPC.vp().pos().validator_slashes(client, &validator).await,
            );
            if !slashes.is_empty() {
                let stdout = io::stdout();
                let mut w = stdout.lock();
                for slash in slashes {
                    writeln!(
                        w,
                        "Slash epoch {}, type {}, rate {}",
                        slash.epoch, slash.r#type, slash.rate
                    )
                    .unwrap();
                }
            } else {
                println!("No slashes found for {}", validator.encode())
            }
        }
        None => {
            let all_slashes: HashMap<Address, Vec<Slash>> =
                unwrap_client_response::<C, HashMap<Address, Vec<Slash>>>(
                    RPC.vp().pos().slashes(client).await,
                );

            if !all_slashes.is_empty() {
                let stdout = io::stdout();
                let mut w = stdout.lock();
                for (validator, slashes) in all_slashes.into_iter() {
                    for slash in slashes {
                        writeln!(
                            w,
                            "Slash epoch {}, block height {}, rate {}, type \
                             {}, validator {}",
                            slash.epoch,
                            slash.block_height,
                            slash.r#type.get_slash_rate(&params),
                            slash.r#type,
                            validator,
                        )
                        .unwrap();
                    }
                }
            } else {
                println!("No slashes found")
            }
        }
    }
}

pub async fn query_delegations<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    _wallet: &mut Wallet<CliWalletUtils>,
    args: args::QueryDelegations,
) {
    let owner = args.owner;
    let delegations = unwrap_client_response::<C, HashSet<Address>>(
        RPC.vp().pos().delegation_validators(client, &owner).await,
    );
    if delegations.is_empty() {
        println!("No delegations found");
    } else {
        println!("Found delegations to:");
        for delegation in delegations {
            println!("  {delegation}");
        }
    }
}

pub async fn query_find_validator<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    args: args::QueryFindValidator,
) {
    let args::QueryFindValidator { query: _, tm_addr } = args;
    if tm_addr.len() != 40 {
        eprintln!(
            "Expected 40 characters in Tendermint address, got {}",
            tm_addr.len()
        );
        cli::safe_exit(1);
    }
    let tm_addr = tm_addr.to_ascii_uppercase();
    let validator = unwrap_client_response::<C, _>(
        RPC.vp().pos().validator_by_tm_addr(client, &tm_addr).await,
    );
    match validator {
        Some(address) => println!("Found validator address \"{address}\"."),
        None => {
            println!("No validator with Tendermint address {tm_addr} found.")
        }
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    tx_bytes: Vec<u8>,
) {
    println!(
        "Dry-run result: {}",
        namada::ledger::rpc::dry_run_tx(client, tx_bytes).await
    );
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    address: &Address,
) -> Option<common::PublicKey> {
    namada::ledger::rpc::get_public_key(client, address).await
}

/// Check if the given address is a known validator.
pub async fn is_validator<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada::ledger::rpc::is_validator(client, address).await
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada::ledger::rpc::is_delegator(client, address).await
}

pub async fn is_delegator_at<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> bool {
    namada::ledger::rpc::is_delegator_at(client, address, epoch).await
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada::ledger::rpc::known_address(client, address).await
}

/// Query for all conversions.
pub async fn query_conversions<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    wallet: &mut Wallet<CliWalletUtils>,
    args: args::QueryConversions,
) {
    // The chosen token type of the conversions
    let target_token = args.token;
    // To facilitate human readable token addresses
    let tokens = wallet.get_addresses_with_vp_type(AddressVpType::Token);
    let masp_addr = masp();
    let key_prefix: Key = masp_addr.to_db_key().into();
    let state_key = key_prefix
        .push(&(token::CONVERSION_KEY_PREFIX.to_owned()))
        .unwrap();
    let conv_state =
        query_storage_value::<C, ConversionState>(client, &state_key)
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
        print!(
            "{}[{}]: ",
            tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
            epoch,
        );
        // Now print out the components of the allowed conversion
        let mut prefix = "";
        for (asset_type, val) in amt.components() {
            // Look up the address and epoch of asset to facilitate pretty
            // printing
            let (addr, epoch, _, _) = &conv_state.assets[asset_type];
            // Now print out this component of the conversion
            print!(
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
        println!(" = 0");
    }
    if !conversions_found {
        println!("No conversions found satisfying specified criteria.");
    }
}

/// Query a conversion.
pub async fn query_conversion<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
)> {
    namada::ledger::rpc::query_conversion(client, asset_type).await
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    code_path: impl AsRef<str>,
) -> Option<Hash> {
    namada::ledger::rpc::query_wasm_code_hash(client, code_path).await
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<
    C: namada::ledger::queries::Client + Send + Sync,
    T,
>(
    client: &C,
    key: &storage::Key,
) -> Option<T>
where
    T: BorshDeserialize,
{
    namada::ledger::rpc::query_storage_value(client, key).await
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> (Option<Vec<u8>>, Option<Proof>) {
    namada::ledger::rpc::query_storage_value_bytes(client, key, height, prove)
        .await
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<
    C: namada::ledger::queries::Client + Send + Sync,
    T,
>(
    client: &C,
    key: &storage::Key,
) -> Option<impl Iterator<Item = (storage::Key, T)>>
where
    T: BorshDeserialize,
{
    namada::ledger::rpc::query_storage_prefix(client, key).await
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    key: &storage::Key,
) -> bool {
    namada::ledger::rpc::query_has_storage_key(client, key).await
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transation.
pub async fn query_tx_events<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    tx_event_query: namada::ledger::rpc::TxEventQuery<'_>,
) -> std::result::Result<
    Option<Event>,
    <C as namada::ledger::queries::Client>::Error,
> {
    namada::ledger::rpc::query_tx_events(client, tx_event_query).await
}

/// Lookup the full response accompanying the specified transaction event
// TODO: maybe remove this in favor of `query_tx_status`
pub async fn query_tx_response<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    tx_query: namada::ledger::rpc::TxEventQuery<'_>,
) -> Result<TxResponse, TError> {
    namada::ledger::rpc::query_tx_response(client, tx_query).await
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.
pub async fn query_result<C: namada::ledger::queries::Client + Send + Sync>(
    client: &C,
    args: args::QueryResult,
) {
    // First try looking up application event pertaining to given hash.
    let tx_response = query_tx_response(
        client,
        namada::ledger::rpc::TxEventQuery::Applied(&args.tx_hash),
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
                namada::ledger::rpc::TxEventQuery::Accepted(&args.tx_hash),
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

pub async fn get_proposal_votes<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    epoch: Epoch,
    proposal_id: u64,
) -> Votes {
    namada::ledger::rpc::get_proposal_votes(client, epoch, proposal_id).await
}

pub async fn get_proposal_offline_votes<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    proposal: OfflineProposal,
    files: HashSet<PathBuf>,
) -> Votes {
    // let validators = get_all_validators(client, proposal.tally_epoch).await;

    let proposal_hash = proposal.compute_hash();

    let mut yay_validators: HashMap<Address, (VotePower, ProposalVote)> =
        HashMap::new();
    let mut delegators: HashMap<
        Address,
        HashMap<Address, (VotePower, ProposalVote)>,
    > = HashMap::new();

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
            // && validators.contains(&proposal_vote.address)
            && unwrap_client_response::<C,bool>(
                RPC.vp().pos().is_validator(client, &proposal_vote.address).await,
            )
        {
            let amount: VotePower = get_validator_stake(
                client,
                proposal.tally_epoch,
                &proposal_vote.address,
            )
            .await
            .unwrap_or_default()
            .into();
            yay_validators.insert(
                proposal_vote.address,
                (amount, ProposalVote::Yay(VoteType::Default)),
            );
        } else if is_delegator_at(
            client,
            &proposal_vote.address,
            proposal.tally_epoch,
        )
        .await
        {
            // TODO: decide whether to do this with `bond_with_slashing` RPC
            // endpoint or with `bonds_and_unbonds`
            let bonds_and_unbonds: pos::types::BondsAndUnbondsDetails =
                unwrap_client_response::<C, pos::types::BondsAndUnbondsDetails>(
                    RPC.vp()
                        .pos()
                        .bonds_and_unbonds(
                            client,
                            &Some(proposal_vote.address.clone()),
                            &None,
                        )
                        .await,
                );
            for (
                BondId {
                    source: _,
                    validator,
                },
                BondsAndUnbondsDetail {
                    bonds,
                    unbonds: _,
                    slashes: _,
                },
            ) in bonds_and_unbonds
            {
                let mut delegated_amount = token::Amount::default();
                for delta in bonds {
                    if delta.start <= proposal.tally_epoch {
                        delegated_amount += delta.amount
                            - delta.slashed_amount.unwrap_or_default();
                    }
                }

                let entry = delegators
                    .entry(proposal_vote.address.clone())
                    .or_default();
                entry.insert(
                    validator,
                    (
                        VotePower::from(delegated_amount),
                        proposal_vote.vote.clone(),
                    ),
                );
            }

            // let key = pos::bonds_for_source_prefix(&proposal_vote.address);
            // let bonds_iter =
            //     query_storage_prefix::<pos::Bonds>(client, &key).await;
            // if let Some(bonds) = bonds_iter {
            //     for (key, epoched_bonds) in bonds {
            //         // Look-up slashes for the validator in this key and
            //         // apply them if any
            //         let validator =
            // pos::get_validator_address_from_bond(&key)
            //             .expect(
            //                 "Delegation key should contain validator
            // address.",             );
            //         let slashes_key = pos::validator_slashes_key(&validator);
            //         let slashes = query_storage_value::<pos::Slashes>(
            //             client,
            //             &slashes_key,
            //         )
            //         .await
            //         .unwrap_or_default();
            //         let mut delegated_amount: token::Amount = 0.into();
            //         let bond = epoched_bonds
            //             .get(proposal.tally_epoch)
            //             .expect("Delegation bond should be defined.");
            //         let mut to_deduct = bond.neg_deltas;
            //         for (start_epoch, &(mut delta)) in
            //             bond.pos_deltas.iter().sorted()
            //         {
            //             // deduct bond's neg_deltas
            //             if to_deduct > delta {
            //                 to_deduct -= delta;
            //                 // If the whole bond was deducted, continue to
            //                 // the next one
            //                 continue;
            //             } else {
            //                 delta -= to_deduct;
            //                 to_deduct = token::Amount::default();
            //             }

            //             delta = apply_slashes(
            //                 &slashes,
            //                 delta,
            //                 *start_epoch,
            //                 None,
            //                 None,
            //             );
            //             delegated_amount += delta;
            //         }

            //         let validator_address =
            //             pos::get_validator_address_from_bond(&key).expect(
            //                 "Delegation key should contain validator
            // address.",             );
            //         if proposal_vote.vote.is_yay() {
            //             let entry = yay_delegators
            //                 .entry(proposal_vote.address.clone())
            //                 .or_default();
            //             entry.insert(
            //                 validator_address,
            //                 VotePower::from(delegated_amount),
            //             );
            //         } else {
            //             let entry = nay_delegators
            //                 .entry(proposal_vote.address.clone())
            //                 .or_default();
            //             entry.insert(
            //                 validator_address,
            //                 VotePower::from(delegated_amount),
            //             );
            //         }
            //     }
            // }
        }
    }

    Votes {
        yay_validators,
        delegators,
    }
}

pub async fn get_bond_amount_at<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let (_total, total_active) =
        unwrap_client_response::<C, (token::Amount, token::Amount)>(
            RPC.vp()
                .pos()
                .bond_with_slashing(client, delegator, validator, &Some(epoch))
                .await,
        );
    Some(total_active)
}

pub async fn get_all_validators<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    epoch: Epoch,
) -> HashSet<Address> {
    namada::ledger::rpc::get_all_validators(client, epoch).await
}

pub async fn get_total_staked_tokens<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    epoch: Epoch,
) -> token::Amount {
    namada::ledger::rpc::get_total_staked_tokens(client, epoch).await
}

async fn get_validator_stake<
    C: namada::ledger::queries::Client + Send + Sync,
>(
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
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
    address: &Address,
) -> HashSet<Address> {
    namada::ledger::rpc::get_delegators_delegation(client, address).await
}

pub async fn get_governance_parameters<
    C: namada::ledger::queries::Client + Send + Sync,
>(
    client: &C,
) -> GovParams {
    namada::ledger::rpc::get_governance_parameters(client).await
}

/// Try to find an alias for a given address from the wallet. If not found,
/// formats the address into a string.
fn lookup_alias(wallet: &Wallet<CliWalletUtils>, addr: &Address) -> String {
    match wallet.find_alias(addr) {
        Some(alias) => format!("{}", alias),
        None => format!("{}", addr),
    }
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: namada::ledger::queries::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|_err| {
        eprintln!("Error in the query");
        cli::safe_exit(1)
    })
}
