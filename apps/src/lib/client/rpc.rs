//! Client RPC queries

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
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
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::primitives::ViewingKey;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::Amount;
use masp_primitives::zip32::ExtendedFullViewingKey;
#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::events::Event;
use namada::ledger::governance::parameters::GovParams;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::native_vp::governance::utils::Votes;
use namada::ledger::parameters::{storage as param_storage, EpochDuration};
use namada::ledger::pos::{
    self, BondId, BondsAndUnbondsDetail, CommissionPair, PosParams, Slash,
};
use namada::ledger::queries::{self, RPC};
use namada::ledger::storage::ConversionState;
use namada::proto::{SignedTxData, Tx};
use namada::types::address::{masp, tokens, Address};
use namada::types::governance::{
    OfflineProposal, OfflineVote, ProposalResult, ProposalVote, TallyResult,
    VotePower,
};
use namada::types::hash::Hash;
use namada::types::key::*;
use namada::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use namada::types::storage::{
    BlockHeight, BlockResults, Epoch, Key, KeySeg, PrefixValue, TxIndex,
};
use namada::types::token::{balance_key, Transfer};
use namada::types::transaction::{
    process_tx, AffineCurve, DecryptedTx, EllipticCurve, PairingEngine, TxType,
    WrapperTx,
};
use namada::types::{address, storage, token};
use tokio::time::{Duration, Instant};

use crate::cli::{self, args, Context};
use crate::client::tendermint_rpc_types::TxResponse;
use crate::client::tx::{
    Conversions, PinnedBalanceError, TransactionDelta, TransferDelta,
};
use crate::facade::tendermint::merkle::proof::Proof;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::error::Error as TError;
use crate::facade::tendermint_rpc::query::Query;
use crate::facade::tendermint_rpc::{
    Client, HttpClient, Order, SubscriptionClient, WebSocketClient,
};

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status(
    status: TxEventQuery<'_>,
    address: TendermintAddress,
    deadline: Instant,
) -> Event {
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
        let client = HttpClient::new(address).unwrap();
        let mut backoff = ONE_SECOND;

        loop {
            tracing::debug!(query = ?status, "Querying tx status");
            let maybe_event = match query_tx_events(&client, status).await {
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

/// Query and print the epoch of the last committed block
pub async fn query_and_print_epoch(args: args::Query) -> Epoch {
    let client = HttpClient::new(args.ledger_address).unwrap();
    let epoch = unwrap_client_response(RPC.shell().epoch(&client).await);
    println!("Last committed epoch: {}", epoch);
    epoch
}

/// Query the epoch of the last committed block
pub async fn query_epoch(client: &HttpClient) -> Epoch {
    unwrap_client_response(RPC.shell().epoch(client).await)
}

/// Query the last committed block
pub async fn query_block(
    args: args::Query,
) -> crate::facade::tendermint_rpc::endpoint::block::Response {
    let client = HttpClient::new(args.ledger_address).unwrap();
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
pub async fn query_results(args: args::Query) -> Vec<BlockResults> {
    let client = HttpClient::new(args.ledger_address).unwrap();
    unwrap_client_response(RPC.shell().read_results(&client).await)
}

/// Obtain the known effects of all accepted shielded and transparent
/// transactions. If an owner is specified, then restrict the set to only
/// transactions crediting/debiting the given owner. If token is specified, then
/// restrict set to only transactions involving the given token.
pub async fn query_tx_deltas(
    ctx: &mut Context,
    ledger_address: TendermintAddress,
    query_owner: &Option<BalanceOwner>,
    query_token: &Option<Address>,
) -> BTreeMap<(BlockHeight, TxIndex), (Epoch, TransferDelta, TransactionDelta)>
{
    const TXS_PER_PAGE: u8 = 100;
    // Connect to the Tendermint server holding the transactions
    let client = HttpClient::new(ledger_address.clone()).unwrap();
    // Build up the context that will be queried for transactions
    let _ = ctx.shielded.load();
    let vks = ctx.wallet.get_viewing_keys();
    let fvks: Vec<_> = vks
        .values()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    ctx.shielded.fetch(&ledger_address, &[], &fvks).await;
    // Save the update state so that future fetches can be short-circuited
    let _ = ctx.shielded.save();
    // Required for filtering out rejected transactions from Tendermint
    // responses
    let block_results = query_results(args::Query { ledger_address }).await;
    let mut transfers = ctx.shielded.get_tx_deltas().clone();
    // Construct the set of addresses relevant to user's query
    let relevant_addrs = match &query_owner {
        Some(BalanceOwner::Address(owner)) => vec![owner.clone()],
        // MASP objects are dealt with outside of tx_search
        Some(BalanceOwner::FullViewingKey(_viewing_key)) => vec![],
        Some(BalanceOwner::PaymentAddress(_owner)) => vec![],
        // Unspecified owner means all known addresses are considered relevant
        None => ctx.wallet.get_addresses().into_values().collect(),
    };
    // Find all transactions to or from the relevant address set
    for addr in relevant_addrs {
        for prop in ["transfer.source", "transfer.target"] {
            // Query transactions involving the current address
            let mut tx_query = Query::eq(prop, addr.encode());
            // Elaborate the query if requested by the user
            if let Some(token) = &query_token {
                tx_query = tx_query.and_eq("transfer.token", token.encode());
            }
            for page in 1.. {
                let txs = &client
                    .tx_search(
                        tx_query.clone(),
                        true,
                        page,
                        TXS_PER_PAGE,
                        Order::Ascending,
                    )
                    .await
                    .expect("Unable to query for transactions")
                    .txs;
                for response_tx in txs {
                    let height = BlockHeight(response_tx.height.value());
                    let idx = TxIndex(response_tx.index);
                    // Only process yet unprocessed transactions which have been
                    // accepted by node VPs
                    let should_process = !transfers
                        .contains_key(&(height, idx))
                        && block_results[u64::from(height) as usize]
                            .is_accepted(idx.0 as usize);
                    if !should_process {
                        continue;
                    }
                    let tx = Tx::try_from(response_tx.tx.as_ref())
                        .expect("Ill-formed Tx");
                    let mut wrapper = None;
                    let mut transfer = None;
                    extract_payload(tx, &mut wrapper, &mut transfer);
                    // Epoch data is not needed for transparent transactions
                    let epoch = wrapper.map(|x| x.epoch).unwrap_or_default();
                    if let Some(transfer) = transfer {
                        // Skip MASP addresses as they are already handled by
                        // ShieldedContext
                        if transfer.source == masp()
                            || transfer.target == masp()
                        {
                            continue;
                        }
                        // Describe how a Transfer simply subtracts from one
                        // account and adds the same to another
                        let mut delta = TransferDelta::default();
                        let tfer_delta = Amount::from_nonnegative(
                            transfer.token.clone(),
                            u64::from(transfer.amount),
                        )
                        .expect("invalid value for amount");
                        delta.insert(
                            transfer.source,
                            Amount::zero() - &tfer_delta,
                        );
                        delta.insert(transfer.target, tfer_delta);
                        // No shielded accounts are affected by this Transfer
                        transfers.insert(
                            (height, idx),
                            (epoch, delta, TransactionDelta::new()),
                        );
                    }
                }
                // An incomplete page signifies no more transactions
                if (txs.len() as u8) < TXS_PER_PAGE {
                    break;
                }
            }
        }
    }
    transfers
}

/// Query the specified accepted transfers from the ledger
pub async fn query_transfers(mut ctx: Context, args: args::QueryTransfers) {
    let query_token = args.token.as_ref().map(|x| ctx.get(x));
    let query_owner = args.owner.as_ref().map(|x| ctx.get_cached(x));
    // Obtain the effects of all shielded and transparent transactions
    let transfers = query_tx_deltas(
        &mut ctx,
        args.query.ledger_address.clone(),
        &query_owner,
        &query_token,
    )
    .await;
    // To facilitate lookups of human-readable token names
    let tokens = tokens();
    let vks = ctx.wallet.get_viewing_keys();
    // To enable ExtendedFullViewingKeys to be displayed instead of ViewingKeys
    let fvk_map: HashMap<_, _> = vks
        .values()
        .map(|fvk| (ExtendedFullViewingKey::from(*fvk).fvk.vk, fvk))
        .collect();
    // Connect to the Tendermint server holding the transactions
    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    // Now display historical shielded and transparent transactions
    for ((height, idx), (epoch, tfer_delta, tx_delta)) in transfers {
        // Check if this transfer pertains to the supplied owner
        let mut relevant = match &query_owner {
            Some(BalanceOwner::FullViewingKey(fvk)) => tx_delta
                .contains_key(&ExtendedFullViewingKey::from(*fvk).fvk.vk),
            Some(BalanceOwner::Address(owner)) => {
                tfer_delta.contains_key(owner)
            }
            Some(BalanceOwner::PaymentAddress(_owner)) => false,
            None => true,
        };
        // Realize and decode the shielded changes to enable relevance check
        let mut shielded_accounts = HashMap::new();
        for (acc, amt) in tx_delta {
            // Realize the rewards that would have been attained upon the
            // transaction's reception
            let amt = ctx
                .shielded
                .compute_exchanged_amount(
                    client.clone(),
                    amt,
                    epoch,
                    Conversions::new(),
                )
                .await
                .0;
            let dec =
                ctx.shielded.decode_amount(client.clone(), amt, epoch).await;
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

/// Extract the payload from the given Tx object
fn extract_payload(
    tx: Tx,
    wrapper: &mut Option<WrapperTx>,
    transfer: &mut Option<Transfer>,
) {
    match process_tx(tx) {
        Ok(TxType::Wrapper(wrapper_tx)) => {
            let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
            extract_payload(
                Tx::from(match wrapper_tx.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted {
                        tx,
                        #[cfg(not(feature = "mainnet"))]
                        has_valid_pow: false,
                    },
                    _ => DecryptedTx::Undecryptable(wrapper_tx.clone()),
                }),
                wrapper,
                transfer,
            );
            *wrapper = Some(wrapper_tx);
        }
        Ok(TxType::Decrypted(DecryptedTx::Decrypted {
            tx,
            #[cfg(not(feature = "mainnet"))]
                has_valid_pow: _,
        })) => {
            let empty_vec = vec![];
            let tx_data = tx.data.as_ref().unwrap_or(&empty_vec);
            let _ = SignedTxData::try_from_slice(tx_data).map(|signed| {
                Transfer::try_from_slice(&signed.data.unwrap()[..])
                    .map(|tfer| *transfer = Some(tfer))
            });
        }
        _ => {}
    }
}

/// Query the raw bytes of given storage key
pub async fn query_raw_bytes(_ctx: Context, args: args::QueryRawBytes) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let response = unwrap_client_response(
        RPC.shell()
            .storage_value(&client, None, None, false, &args.storage_key)
            .await,
    );
    if !response.data.is_empty() {
        println!("Found data: 0x{}", HEXLOWER.encode(&response.data));
    } else {
        println!("No data found for key {}", args.storage_key);
    }
}

/// Query token balance(s)
pub async fn query_balance(mut ctx: Context, args: args::QueryBalance) {
    // Query the balances of shielded or transparent account types depending on
    // the CLI arguments
    match args.owner.as_ref().map(|x| ctx.get_cached(x)) {
        Some(BalanceOwner::FullViewingKey(_viewing_key)) => {
            query_shielded_balance(&mut ctx, args).await
        }
        Some(BalanceOwner::Address(_owner)) => {
            query_transparent_balance(&mut ctx, args).await
        }
        Some(BalanceOwner::PaymentAddress(_owner)) => {
            query_pinned_balance(&mut ctx, args).await
        }
        None => {
            // Print pinned balance
            query_pinned_balance(&mut ctx, args.clone()).await;
            // Print shielded balance
            query_shielded_balance(&mut ctx, args.clone()).await;
            // Then print transparent balance
            query_transparent_balance(&mut ctx, args).await;
        }
    };
}

/// Query token balance(s)
pub async fn query_transparent_balance(
    ctx: &mut Context,
    args: args::QueryBalance,
) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let tokens = address::tokens();
    match (args.token, args.owner) {
        (Some(token), Some(owner)) => {
            let token = ctx.get(&token);
            let owner = ctx.get_cached(&owner);
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
            match query_storage_value::<token::Amount>(&client, &key).await {
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
            let owner = ctx.get_cached(&owner);
            for (token, _) in tokens {
                let prefix = token.to_db_key().into();
                let balances =
                    query_storage_prefix::<token::Amount>(&client, &prefix)
                        .await;
                if let Some(balances) = balances {
                    print_balances(
                        ctx,
                        balances,
                        &token,
                        owner.address().as_ref(),
                    );
                }
            }
        }
        (Some(token), None) => {
            let token = ctx.get(&token);
            let prefix = token.to_db_key().into();
            let balances =
                query_storage_prefix::<token::Amount>(&client, &prefix).await;
            if let Some(balances) = balances {
                print_balances(ctx, balances, &token, None);
            }
        }
        (None, None) => {
            for (token, _) in tokens {
                let key = token::balance_prefix(&token);
                let balances =
                    query_storage_prefix::<token::Amount>(&client, &key).await;
                if let Some(balances) = balances {
                    print_balances(ctx, balances, &token, None);
                }
            }
        }
    }
}

/// Query the token pinned balance(s)
pub async fn query_pinned_balance(ctx: &mut Context, args: args::QueryBalance) {
    // Map addresses to token names
    let tokens = address::tokens();
    let owners = if let Some(pa) = args
        .owner
        .and_then(|x| ctx.get_cached(&x).payment_address())
    {
        vec![pa]
    } else {
        ctx.wallet
            .get_payment_addrs()
            .into_values()
            .filter(PaymentAddress::is_pinned)
            .collect()
    };
    // Get the viewing keys with which to try note decryptions
    let viewing_keys: Vec<ViewingKey> = ctx
        .wallet
        .get_viewing_keys()
        .values()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    // Build up the context that will be queried for asset decodings
    let _ = ctx.shielded.load();
    // Establish connection with which to do exchange rate queries
    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    // Print the token balances by payment address
    for owner in owners {
        let mut balance = Err(PinnedBalanceError::InvalidViewingKey);
        // Find the viewing key that can recognize payments the current payment
        // address
        for vk in &viewing_keys {
            balance = ctx
                .shielded
                .compute_exchanged_pinned_balance(
                    &args.query.ledger_address,
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
            balance = ctx
                .shielded
                .compute_exchanged_pinned_balance(
                    &args.query.ledger_address,
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
                let token = ctx.get(token);
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
                let balance = ctx
                    .shielded
                    .decode_amount(client.clone(), balance, epoch)
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
    ctx: &Context,
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
                        lookup_alias(ctx, owner)
                    ),
                )),
                None => token::is_any_token_balance_key(&key).map(|owner| {
                    (
                        owner.clone(),
                        format!(
                            ": {}, owned by {}",
                            balance,
                            lookup_alias(ctx, owner)
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
                writeln!(w, "No balances owned by {}", lookup_alias(ctx, t))
                    .unwrap()
            }
            None => {
                writeln!(w, "No balances for token {}", currency_code).unwrap()
            }
        }
    }
}

/// Query Proposals
pub async fn query_proposal(_ctx: Context, args: args::QueryProposal) {
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
            query_storage_value::<Address>(client, &author_key).await?;
        let start_epoch =
            query_storage_value::<Epoch>(client, &start_epoch_key).await?;
        let end_epoch =
            query_storage_value::<Epoch>(client, &end_epoch_key).await?;

        if details {
            let content_key = gov_storage::get_content_key(id);
            let grace_epoch_key = gov_storage::get_grace_epoch_key(id);
            let content = query_storage_value::<HashMap<String, String>>(
                client,
                &content_key,
            )
            .await?;
            let grace_epoch =
                query_storage_value::<Epoch>(client, &grace_epoch_key).await?;

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

    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    let current_epoch = query_and_print_epoch(args.query.clone()).await;
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
                query_storage_value::<u64>(&client, &last_proposal_id_key)
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
pub async fn query_shielded_balance(
    ctx: &mut Context,
    args: args::QueryBalance,
) {
    // Used to control whether balances for all keys or a specific key are
    // printed
    let owner = args
        .owner
        .and_then(|x| ctx.get_cached(&x).full_viewing_key());
    // Used to control whether conversions are automatically performed
    let no_conversions = args.no_conversions;
    // Viewing keys are used to query shielded balances. If a spending key is
    // provided, then convert to a viewing key first.
    let viewing_keys = match owner {
        Some(viewing_key) => vec![viewing_key],
        None => ctx.wallet.get_viewing_keys().values().copied().collect(),
    };
    // Build up the context that will be queried for balances
    let _ = ctx.shielded.load();
    let fvks: Vec<_> = viewing_keys
        .iter()
        .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
        .collect();
    ctx.shielded
        .fetch(&args.query.ledger_address, &[], &fvks)
        .await;
    // Save the update state so that future fetches can be short-circuited
    let _ = ctx.shielded.save();
    // The epoch is required to identify timestamped tokens
    let epoch = query_and_print_epoch(args.query.clone()).await;
    // Establish connection with which to do exchange rate queries
    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    // Map addresses to token names
    let tokens = address::tokens();
    match (args.token, owner.is_some()) {
        // Here the user wants to know the balance for a specific token
        (Some(token), true) => {
            // Query the multi-asset balance at the given spending key
            let viewing_key =
                ExtendedFullViewingKey::from(viewing_keys[0]).fvk.vk;
            let balance: Amount<AssetType> = if no_conversions {
                ctx.shielded
                    .compute_shielded_balance(&viewing_key)
                    .expect("context should contain viewing key")
            } else {
                ctx.shielded
                    .compute_exchanged_balance(
                        client.clone(),
                        &viewing_key,
                        epoch,
                    )
                    .await
                    .expect("context should contain viewing key")
            };
            // Compute the unique asset identifier from the token address
            let token = ctx.get(&token);
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
                    ctx.shielded
                        .compute_shielded_balance(&viewing_key)
                        .expect("context should contain viewing key")
                } else {
                    ctx.shielded
                        .compute_exchanged_balance(
                            client.clone(),
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
                let decoded = ctx
                    .shielded
                    .decode_asset_type(client.clone(), asset_type)
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
            let token = ctx.get(&token);
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
                    ctx.shielded
                        .compute_shielded_balance(&viewing_key)
                        .expect("context should contain viewing key")
                } else {
                    ctx.shielded
                        .compute_exchanged_balance(
                            client.clone(),
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
                balance = ctx
                    .shielded
                    .compute_shielded_balance(&viewing_key)
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                let decoded_balance = ctx
                    .shielded
                    .decode_all_amounts(client.clone(), balance)
                    .await;
                print_decoded_balance_with_epoch(decoded_balance);
            } else {
                balance = ctx
                    .shielded
                    .compute_exchanged_balance(
                        client.clone(),
                        &viewing_key,
                        epoch,
                    )
                    .await
                    .expect("context should contain viewing key");
                // Print balances by human-readable token names
                let decoded_balance = ctx
                    .shielded
                    .decode_amount(client.clone(), balance, epoch)
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
    _ctx: Context,
    args: args::QueryProposalResult,
) {
    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    let current_epoch = query_and_print_epoch(args.query.clone()).await;

    match args.proposal_id {
        Some(id) => {
            let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
            let end_epoch =
                query_storage_value::<Epoch>(&client, &end_epoch_key).await;

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
                            &proposal.address,
                            args.query.ledger_address.clone(),
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
    _ctx: Context,
    args: args::QueryProtocolParameters,
) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    let gov_parameters = get_governance_parameters(&client).await;
    println!("Governance Parameters\n {:4}", gov_parameters);

    println!("Protocol parameters");
    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration = query_storage_value::<EpochDuration>(&client, &key)
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
    let max_block_duration = query_storage_value::<u64>(&client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}Max. block duration: {}", "", max_block_duration);

    let key = param_storage::get_tx_whitelist_storage_key();
    let vp_whitelist = query_storage_value::<Vec<String>>(&client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}VP whitelist: {:?}", "", vp_whitelist);

    let key = param_storage::get_tx_whitelist_storage_key();
    let tx_whitelist = query_storage_value::<Vec<String>>(&client, &key)
        .await
        .expect("Parameter should be defined.");
    println!("{:4}Transactions whitelist: {:?}", "", tx_whitelist);

    println!("PoS parameters");
    let key = pos::params_key();
    let pos_params = query_storage_value::<PosParams>(&client, &key)
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

pub async fn query_bond(
    client: &HttpClient,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

pub async fn query_unbond_with_slashing(
    client: &HttpClient,
    source: &Address,
    validator: &Address,
) -> HashMap<(Epoch, Epoch), token::Amount> {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .unbond_with_slashing(client, source, validator)
            .await,
    )
}

pub async fn query_and_print_unbonds(
    client: &HttpClient,
    source: &Address,
    validator: &Address,
) {
    let unbonds = query_unbond_with_slashing(client, source, validator).await;
    let current_epoch = query_epoch(client).await;
    let (withdrawable, not_yet_withdrawable): (HashMap<_, _>, HashMap<_, _>) =
        unbonds.into_iter().partition(|((_, withdraw_epoch), _)| {
            withdraw_epoch <= &current_epoch
        });
    let total_withdrawable = withdrawable
        .into_iter()
        .fold(token::Amount::default(), |acc, (_, amount)| acc + amount);
    if total_withdrawable != token::Amount::default() {
        println!("Total withdrawable now: {total_withdrawable}.");
    }
    if !not_yet_withdrawable.is_empty() {
        println!("Current epoch: {current_epoch}.")
    }
    for ((_start_epoch, withdraw_epoch), amount) in not_yet_withdrawable {
        println!(
            "Amount {amount} withdrawable starting from epoch \
             {withdraw_epoch}."
        );
    }
}

pub async fn query_withdrawable_tokens(
    client: &HttpClient,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .withdrawable_tokens(client, bond_source, validator, &epoch)
            .await,
    )
}

/// Query PoS bond(s) and unbond(s)
pub async fn query_bonds(ctx: Context, args: args::QueryBonds) {
    let _epoch = query_and_print_epoch(args.query.clone()).await;
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    let source = args.owner.map(|owner| ctx.get(&owner));
    let validator = args.validator.map(|val| ctx.get(&val));

    let stdout = io::stdout();
    let mut w = stdout.lock();

    let bonds_and_unbonds: pos::types::BondsAndUnbondsDetails =
        unwrap_client_response(
            RPC.vp()
                .pos()
                .bonds_and_unbonds(&client, &source, &validator)
                .await,
        );
    let mut bonds_total: token::Amount = 0.into();
    let mut bonds_total_slashed: token::Amount = 0.into();
    let mut unbonds_total: token::Amount = 0.into();
    let mut unbonds_total_slashed: token::Amount = 0.into();
    let mut total_withdrawable: token::Amount = 0.into();
    for (bond_id, details) in bonds_and_unbonds {
        let mut total: token::Amount = 0.into();
        let mut total_slashed: token::Amount = 0.into();
        let bond_type = if bond_id.source == bond_id.validator {
            format!("Self-bonds from {}", bond_id.validator)
        } else {
            format!(
                "Delegations from {} to {}",
                bond_id.source, bond_id.validator
            )
        };
        writeln!(w, "{}:", bond_type).unwrap();
        for bond in details.bonds {
            writeln!(
                w,
                "  Remaining active bond from epoch {}: Δ {}",
                bond.start, bond.amount
            )
            .unwrap();
            total += bond.amount;
            total_slashed += bond.slashed_amount.unwrap_or_default();
        }
        if total_slashed != token::Amount::default() {
            writeln!(
                w,
                "Active (slashed) bonds total: {}",
                total - total_slashed
            )
            .unwrap();
        }
        writeln!(w, "Bonds total: {}", total).unwrap();
        bonds_total += total;
        bonds_total_slashed += total_slashed;

        let mut withdrawable = token::Amount::default();
        if !details.unbonds.is_empty() {
            let mut total: token::Amount = 0.into();
            let mut total_slashed: token::Amount = 0.into();
            let bond_type = if bond_id.source == bond_id.validator {
                format!("Unbonded self-bonds from {}", bond_id.validator)
            } else {
                format!("Unbonded delegations from {}", bond_id.source)
            };
            writeln!(w, "{}:", bond_type).unwrap();
            for unbond in details.unbonds {
                total += unbond.amount;
                total_slashed += unbond.slashed_amount.unwrap_or_default();
                writeln!(
                    w,
                    "  Withdrawable from epoch {} (active from {}): Δ {}",
                    unbond.withdraw, unbond.start, unbond.amount
                )
                .unwrap();
            }
            withdrawable = total - total_slashed;
            writeln!(w, "Unbonded total: {}", total).unwrap();

            unbonds_total += total;
            unbonds_total_slashed += total_slashed;
            total_withdrawable += withdrawable;
        }
        writeln!(w, "Withdrawable total: {}", withdrawable).unwrap();
        println!();
    }
    if bonds_total != bonds_total_slashed {
        println!(
            "All bonds total active: {}",
            bonds_total - bonds_total_slashed
        );
    }
    println!("All bonds total: {}", bonds_total);

    if unbonds_total != unbonds_total_slashed {
        println!(
            "All unbonds total active: {}",
            unbonds_total - unbonds_total_slashed
        );
    }
    println!("All unbonds total: {}", unbonds_total);
    println!("All unbonds total withdrawable: {}", total_withdrawable);
}

/// Query PoS bonded stake
pub async fn query_bonded_stake(ctx: Context, args: args::QueryBondedStake) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_and_print_epoch(args.query.clone()).await,
    };
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    match args.validator {
        Some(validator) => {
            let validator = ctx.get(&validator);
            // Find bonded stake for the given validator
            let stake = get_validator_stake(&client, epoch, &validator).await;
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
            let consensus = unwrap_client_response(
                RPC.vp()
                    .pos()
                    .consensus_validator_set(&client, &Some(epoch))
                    .await,
            );
            let below_capacity = unwrap_client_response(
                RPC.vp()
                    .pos()
                    .below_capacity_validator_set(&client, &Some(epoch))
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

    let total_staked_tokens = get_total_staked_tokens(&client, epoch).await;
    println!("Total bonded stake: {total_staked_tokens}");
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate(
    client: &HttpClient,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Option<CommissionPair> {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query PoS validator's commission rate information
pub async fn query_and_print_commission_rate(
    ctx: Context,
    args: args::QueryCommissionRate,
) {
    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
    let validator = ctx.get(&args.validator);

    let info: Option<CommissionPair> =
        query_commission_rate(&client, &validator, args.epoch).await;
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
pub async fn query_slashes(ctx: Context, args: args::QuerySlashes) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let params_key = pos::params_key();
    let params = query_storage_value::<PosParams>(&client, &params_key)
        .await
        .expect("Parameter should be defined.");

    match args.validator {
        Some(validator) => {
            let validator = ctx.get(&validator);
            // Find slashes for the given validator
            let slashes: Vec<Slash> = unwrap_client_response(
                RPC.vp().pos().validator_slashes(&client, &validator).await,
            );
            if !slashes.is_empty() {
                let stdout = io::stdout();
                let mut w = stdout.lock();
                for slash in slashes {
                    writeln!(
                        w,
                        "Slash epoch {}, type {}, rate {}",
                        slash.epoch,
                        slash.r#type,
                        slash.r#type.get_slash_rate(&params)
                    )
                    .unwrap();
                }
            } else {
                println!("No slashes found for {}", validator.encode())
            }
        }
        None => {
            let all_slashes: HashMap<Address, Vec<Slash>> =
                unwrap_client_response(RPC.vp().pos().slashes(&client).await);

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

pub async fn query_delegations(ctx: Context, args: args::QueryDelegations) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let owner = ctx.get(&args.owner);
    let delegations = unwrap_client_response(
        RPC.vp().pos().delegation_validators(&client, &owner).await,
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

/// Dry run a transaction
pub async fn dry_run_tx(ledger_address: &TendermintAddress, tx_bytes: Vec<u8>) {
    let client = HttpClient::new(ledger_address.clone()).unwrap();
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = unwrap_client_response(
        RPC.shell().dry_run_tx(&client, data, height, prove).await,
    )
    .data;
    println!("Dry-run result: {}", result);
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key(
    address: &Address,
    ledger_address: TendermintAddress,
) -> Option<common::PublicKey> {
    let client = HttpClient::new(ledger_address).unwrap();
    let key = pk_key(address);
    query_storage_value(&client, &key).await
}

/// Check if the given address is a known validator.
pub async fn is_validator(client: &HttpClient, address: &Address) -> bool {
    unwrap_client_response(RPC.vp().pos().is_validator(client, address).await)
}

/// Check if a given address is a known delegator
pub async fn is_delegator(client: &HttpClient, address: &Address) -> bool {
    unwrap_client_response(
        RPC.vp().pos().is_delegator(client, address, &None).await,
    )
}

/// Check if a given address is a known delegator at a particular epoch
pub async fn is_delegator_at(
    client: &HttpClient,
    address: &Address,
    epoch: Epoch,
) -> bool {
    unwrap_client_response(
        RPC.vp()
            .pos()
            .is_delegator(client, address, &Some(epoch))
            .await,
    )
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address(
    address: &Address,
    ledger_address: TendermintAddress,
) -> bool {
    let client = HttpClient::new(ledger_address).unwrap();
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = storage::Key::validity_predicate(address);
            query_has_storage_key(&client, &key).await
        }
        Address::Implicit(_) | Address::Internal(_) => true,
    }
}

#[cfg(not(feature = "mainnet"))]
/// Check if the given address is a testnet faucet account address.
pub async fn is_faucet_account(
    address: &Address,
    ledger_address: TendermintAddress,
) -> bool {
    let client = HttpClient::new(ledger_address).unwrap();
    unwrap_client_response(RPC.vp().is_faucet(&client, address).await)
}

#[cfg(not(feature = "mainnet"))]
/// Get faucet account address, if any is setup for the network.
pub async fn get_faucet_address(
    ledger_address: TendermintAddress,
) -> Option<Address> {
    let client = HttpClient::new(ledger_address).unwrap();
    unwrap_client_response(RPC.vp().get_faucet_address(&client).await)
}

#[cfg(not(feature = "mainnet"))]
/// Obtain a PoW challenge for a withdrawal from a testnet faucet account, if
/// any is setup for the network.
pub async fn get_testnet_pow_challenge(
    source: Address,
    ledger_address: TendermintAddress,
) -> testnet_pow::Challenge {
    let client = HttpClient::new(ledger_address).unwrap();
    unwrap_client_response(
        RPC.vp().testnet_pow_challenge(&client, source).await,
    )
}

/// Query for all conversions.
pub async fn query_conversions(ctx: Context, args: args::QueryConversions) {
    // The chosen token type of the conversions
    let target_token = args.token.as_ref().map(|x| ctx.get(x));
    // To facilitate human readable token addresses
    let tokens = address::tokens();
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let masp_addr = masp();
    let key_prefix: Key = masp_addr.to_db_key().into();
    let state_key = key_prefix
        .push(&(token::CONVERSION_KEY_PREFIX.to_owned()))
        .unwrap();
    let conv_state =
        query_storage_value::<ConversionState>(&client, &state_key)
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
pub async fn query_storage_value<T>(
    client: &HttpClient,
    key: &storage::Key,
) -> Option<T>
where
    T: BorshDeserialize,
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
pub async fn query_has_storage_key(
    client: &HttpClient,
    key: &storage::Key,
) -> bool {
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
pub async fn query_tx_events(
    client: &HttpClient,
    tx_event_query: TxEventQuery<'_>,
) -> eyre::Result<Option<Event>> {
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
    ledger_address: &TendermintAddress,
    tx_query: TxEventQuery<'_>,
) -> Result<TxResponse, TError> {
    // Connect to the Tendermint server holding the transactions
    let (client, driver) = WebSocketClient::new(ledger_address.clone()).await?;
    let driver_handle = tokio::spawn(async move { driver.run().await });
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
    // Signal to the driver to terminate.
    client.close()?;
    // Await the driver's termination to ensure proper connection closure.
    let _ = driver_handle.await.unwrap_or_else(|x| {
        eprintln!("{}", x);
        cli::safe_exit(1)
    });
    Ok(result)
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.
pub async fn query_result(_ctx: Context, args: args::QueryResult) {
    // First try looking up application event pertaining to given hash.
    let tx_response = query_tx_response(
        &args.query.ledger_address,
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
                &args.query.ledger_address,
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
                        .unwrap_or_default()
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
    // let validators = get_all_validators(client, proposal.tally_epoch).await;

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
            // && validators.contains(&proposal_vote.address)
            && unwrap_client_response(
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
            yay_validators.insert(proposal_vote.address, amount);
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
                unwrap_client_response(
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
                if proposal_vote.vote.is_yay() {
                    let entry = yay_delegators
                        .entry(proposal_vote.address.clone())
                        .or_default();
                    entry.insert(validator, VotePower::from(delegated_amount));
                } else {
                    let entry = nay_delegators
                        .entry(proposal_vote.address.clone())
                        .or_default();
                    entry.insert(validator, VotePower::from(delegated_amount));
                }
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
    let (_total, total_active) = unwrap_client_response(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    );
    Some(total_active)
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

/// Get the total stake of a validator at the given epoch. The total stake is a
/// sum of validator's self-bonds and delegations to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
async fn get_validator_stake(
    client: &HttpClient,
    epoch: Epoch,
    validator: &Address,
) -> Option<token::Amount> {
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
    unwrap_client_response(
        RPC.vp().pos().delegation_validators(client, address).await,
    )
}

pub async fn get_governance_parameters(client: &HttpClient) -> GovParams {
    use namada::types::token::Amount;
    let key = gov_storage::get_max_proposal_code_size_key();
    let max_proposal_code_size = query_storage_value::<u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_content_key();
    let max_proposal_content_size = query_storage_value::<u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_fund_key();
    let min_proposal_fund = query_storage_value::<Amount>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_grace_epoch_key();
    let min_proposal_grace_epochs = query_storage_value::<u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_period_key();
    let min_proposal_period = query_storage_value::<u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_period_key();
    let max_proposal_period = query_storage_value::<u64>(client, &key)
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
fn lookup_alias(ctx: &Context, addr: &Address) -> String {
    match ctx.wallet.find_alias(addr) {
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
