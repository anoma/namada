pub(super) mod eth_bridge;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use namada_core::ledger::storage::LastBlock;
use namada_core::types::account::{Account, AccountPublicKeysMap};
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::storage::{BlockHeight, BlockResults, KeySeg};
use namada_core::types::token::MaspDenom;

use self::eth_bridge::{EthBridge, ETH_BRIDGE};
use crate::ibc::core::ics04_channel::packet::Sequence;
use crate::ibc::core::ics24_host::identifier::{ChannelId, ClientId, PortId};
use crate::ledger::events::log::dumb_queries;
use crate::ledger::events::{Event, EventType};
use crate::ledger::queries::types::{RequestCtx, RequestQuery};
use crate::ledger::queries::{require_latest_height, EncodedResponseQuery};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, DB};
use crate::ledger::storage_api::{self, ResultExt, StorageRead};
use crate::tendermint::merkle::proof::Proof;
use crate::types::storage::{self, Epoch, PrefixValue};
#[cfg(any(test, feature = "async-client"))]
use crate::types::transaction::TxResult;

type Conversion = (
    Address,
    MaspDenom,
    Epoch,
    masp_primitives::transaction::components::I32Sum,
    MerklePath<Node>,
);

router! {SHELL,
    // Shell provides storage read access, block metadata and can dry-run a tx

    // Ethereum bridge specific queries
    ( "eth_bridge" ) = (sub ETH_BRIDGE),

    // Epoch of the last committed block
    ( "epoch" ) -> Epoch = epoch,

    // Epoch of the input block height
    ( "epoch_at_height" / [height: BlockHeight]) -> Option<Epoch> = epoch_at_height,

    // Query the last committed block
    ( "last_block" ) -> Option<LastBlock> = last_block,

    // Raw storage access - read value
    ( "value" / [storage_key: storage::Key] )
        -> Vec<u8> = (with_options storage_value),

    // Dry run a transaction
    ( "dry_run_tx" ) -> TxResult = (with_options dry_run_tx),

    // Raw storage access - prefix iterator
    ( "prefix" / [storage_key: storage::Key] )
        -> Vec<PrefixValue> = (with_options storage_prefix),

    // Raw storage access - is given storage key present?
    ( "has_key" / [storage_key: storage::Key] )
        -> bool = storage_has_key,

    // Conversion state access - read conversion
    ( "conv" / [asset_type: AssetType] ) -> Conversion = read_conversion,

    // Block results access - read bit-vec
    ( "results" ) -> Vec<BlockResults> = read_results,

    // was the transaction accepted?
    ( "accepted" / [tx_hash: Hash] ) -> Option<Event> = accepted,

    // was the transaction applied?
    ( "applied" / [tx_hash: Hash] ) -> Option<Event> = applied,

    // Query account subspace
    ( "account" / [owner: Address] ) -> Option<Account> = account,

    // Query public key revealad
    ( "revealed" / [owner: Address] ) -> bool = revealed,

    // IBC UpdateClient event
    ( "ibc_client_update" / [client_id: ClientId] / [consensus_height: BlockHeight] ) -> Option<Event> = ibc_client_update,

    // IBC packet event
    ( "ibc_packet" / [event_type: EventType] / [source_port: PortId] / [source_channel: ChannelId] / [destination_port: PortId] / [destination_channel: ChannelId] / [sequence: Sequence]) -> Option<Event> = ibc_packet,
}

// Handlers:

#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
fn dry_run_tx<D, H>(
    mut ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use namada_core::ledger::gas::{Gas, GasMetering, TxGasMeter};
    use namada_core::ledger::storage::TempWlStorage;
    use namada_core::types::transaction::DecryptedTx;

    use crate::ledger::protocol::{self, ShellParams};
    use crate::proto::Tx;
    use crate::types::storage::TxIndex;
    use crate::types::transaction::wrapper::wrapper_tx::PairingEngine;
    use crate::types::transaction::{AffineCurve, EllipticCurve, TxType};

    let mut tx = Tx::try_from(&request.data[..]).into_storage_result()?;
    tx.validate_tx().into_storage_result()?;

    let mut temp_wl_storage = TempWlStorage::new(&ctx.wl_storage.storage);
    let mut cumulated_gas = Gas::default();

    // Wrapper dry run to allow estimating the gas cost of a transaction
    let mut tx_gas_meter = match tx.header().tx_type {
        TxType::Wrapper(wrapper) => {
            let mut tx_gas_meter =
                TxGasMeter::new(wrapper.gas_limit.to_owned());
            protocol::apply_wrapper_tx(
                tx.clone(),
                &wrapper,
                None,
                &request.data,
                ShellParams::new(
                    &mut tx_gas_meter,
                    &mut temp_wl_storage,
                    &mut ctx.vp_wasm_cache,
                    &mut ctx.tx_wasm_cache,
                ),
                None,
            )
            .into_storage_result()?;

            temp_wl_storage.write_log.commit_tx();
            cumulated_gas = tx_gas_meter.get_tx_consumed_gas();

            // NOTE: the encryption key for a dry-run should always be an
            // hardcoded, dummy one
            let _privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
            TxGasMeter::new_from_sub_limit(tx_gas_meter.get_available_gas())
        }
        TxType::Protocol(_) | TxType::Decrypted(_) => {
            // If dry run only the inner tx, use the max block gas as the gas
            // limit
            TxGasMeter::new(
                namada_core::ledger::gas::get_max_block_gas(ctx.wl_storage)
                    .unwrap()
                    .into(),
            )
        }
        TxType::Raw => {
            // Cast tx to a decrypted for execution
            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));

            // If dry run only the inner tx, use the max block gas as the gas
            // limit
            TxGasMeter::new(
                namada_core::ledger::gas::get_max_block_gas(ctx.wl_storage)
                    .unwrap()
                    .into(),
            )
        }
    };

    let mut data = protocol::apply_wasm_tx(
        tx,
        &TxIndex(0),
        ShellParams::new(
            &mut tx_gas_meter,
            &mut temp_wl_storage,
            &mut ctx.vp_wasm_cache,
            &mut ctx.tx_wasm_cache,
        ),
    )
    .into_storage_result()?;
    cumulated_gas = cumulated_gas
        .checked_add(tx_gas_meter.get_tx_consumed_gas())
        .ok_or(namada_core::ledger::storage_api::Error::SimpleMessage(
            "Overflow in gas",
        ))?;
    // Account gas for both inner and wrapper (if available)
    data.gas_used = cumulated_gas;
    // NOTE: the keys changed by the wrapper transaction (if any) are not
    // returned from this function
    let data = data.try_to_vec().into_storage_result()?;
    Ok(EncodedResponseQuery {
        data,
        proof: None,
        info: Default::default(),
    })
}

/// Query to read block results from storage
pub fn read_results<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<BlockResults>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let (iter, _gas) = ctx.wl_storage.storage.iter_results();
    let mut results = vec![
        BlockResults::default();
        ctx.wl_storage.storage.block.height.0 as usize + 1
    ];
    for (key, value, _gas) in iter {
        let key = u64::parse(key.clone()).map_err(|_| {
            storage_api::Error::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("expected integer for block height {}", key),
            ))
        })?;
        let value = BlockResults::try_from_slice(&value).map_err(|_| {
            storage_api::Error::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected BlockResults bytes",
            ))
        })?;
        let idx: usize = key.try_into().map_err(|_| {
            storage_api::Error::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected block height to fit into usize",
            ))
        })?;
        results[idx] = value;
    }
    Ok(results)
}

/// Query to read a conversion from storage
fn read_conversion<D, H>(
    ctx: RequestCtx<'_, D, H>,
    asset_type: AssetType,
) -> storage_api::Result<Conversion>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // Conversion values are constructed on request
    if let Some(((addr, denom), epoch, conv, pos)) = ctx
        .wl_storage
        .storage
        .conversion_state
        .assets
        .get(&asset_type)
    {
        Ok((
            addr.clone(),
            *denom,
            *epoch,
            Into::<masp_primitives::transaction::components::I32Sum>::into(
                conv.clone(),
            ),
            ctx.wl_storage.storage.conversion_state.tree.path(*pos),
        ))
    } else {
        Err(storage_api::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No conversion found for asset type: {}", asset_type),
        )))
    }
}

#[cfg(not(all(feature = "wasm-runtime", feature = "ferveo-tpke")))]
fn dry_run_tx<D, H>(
    _ctx: RequestCtx<'_, D, H>,
    _request: &RequestQuery,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    unimplemented!("Dry running tx requires \"wasm-runtime\" feature.")
}

fn epoch<D, H>(ctx: RequestCtx<'_, D, H>) -> storage_api::Result<Epoch>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let data = ctx.wl_storage.storage.last_epoch;
    Ok(data)
}

fn epoch_at_height<D, H>(
    ctx: RequestCtx<'_, D, H>,
    height: BlockHeight,
) -> storage_api::Result<Option<Epoch>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    Ok(ctx.wl_storage.storage.block.pred_epochs.get_epoch(height))
}

fn last_block<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Option<LastBlock>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    Ok(ctx.wl_storage.storage.last_block.clone())
}

/// Returns data with `vec![]` when the storage key is not found. For all
/// borsh-encoded types, it is safe to check `data.is_empty()` to see if the
/// value was found, except for unit - see `fn query_storage_value` in
/// `apps/src/lib/client/rpc.rs` for unit type handling via `storage_has_key`.
fn storage_value<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    storage_key: storage::Key,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if let Some(past_height_limit) = ctx.storage_read_past_height_limit {
        if request.height.0 + past_height_limit
            < ctx.wl_storage.storage.get_last_block_height().0
        {
            return Err(storage_api::Error::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Cannot query more than {past_height_limit} blocks in the \
                     past (configured via \
                     `shell.storage_read_past_height_limit`)."
                ),
            )));
        }
    }

    match ctx
        .wl_storage
        .storage
        .read_with_height(&storage_key, request.height)
        .into_storage_result()?
    {
        (Some(value), _gas) => {
            let proof = if request.prove {
                let proof = ctx
                    .wl_storage
                    .storage
                    .get_existence_proof(&storage_key, &value, request.height)
                    .into_storage_result()?;
                Some(proof)
            } else {
                None
            };
            Ok(EncodedResponseQuery {
                data: value,
                proof,
                info: Default::default(),
            })
        }
        (None, _gas) => {
            let proof = if request.prove {
                let proof = ctx
                    .wl_storage
                    .storage
                    .get_non_existence_proof(&storage_key, request.height)
                    .into_storage_result()?;
                Some(proof)
            } else {
                None
            };
            Ok(EncodedResponseQuery {
                data: vec![],
                proof,
                info: format!("No value found for key: {}", storage_key),
            })
        }
    }
}

fn storage_prefix<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    storage_key: storage::Key,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;

    let iter = storage_api::iter_prefix_bytes(ctx.wl_storage, &storage_key)?;
    let data: storage_api::Result<Vec<PrefixValue>> = iter
        .map(|iter_result| {
            let (key, value) = iter_result?;
            Ok(PrefixValue { key, value })
        })
        .collect();
    let data = data?;
    let proof = if request.prove {
        let mut ops = vec![];
        for PrefixValue { key, value } in &data {
            let mut proof: crate::tendermint::merkle::proof::Proof = ctx
                .wl_storage
                .storage
                .get_existence_proof(key, value, request.height)
                .into_storage_result()?;
            ops.append(&mut proof.ops);
        }
        // ops is not empty in this case
        let proof = Proof { ops };
        Some(proof)
    } else {
        None
    };
    let data = data.try_to_vec().into_storage_result()?;
    Ok(EncodedResponseQuery {
        data,
        proof,
        ..Default::default()
    })
}

fn storage_has_key<D, H>(
    ctx: RequestCtx<'_, D, H>,
    storage_key: storage::Key,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let data = StorageRead::has_key(ctx.wl_storage, &storage_key)?;
    Ok(data)
}

fn accepted<D, H>(
    ctx: RequestCtx<'_, D, H>,
    tx_hash: Hash,
) -> storage_api::Result<Option<Event>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let matcher = dumb_queries::QueryMatcher::accepted(tx_hash);
    Ok(ctx
        .event_log
        .iter_with_matcher(matcher)
        .by_ref()
        .next()
        .cloned())
}

fn applied<D, H>(
    ctx: RequestCtx<'_, D, H>,
    tx_hash: Hash,
) -> storage_api::Result<Option<Event>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let matcher = dumb_queries::QueryMatcher::applied(tx_hash);
    Ok(ctx
        .event_log
        .iter_with_matcher(matcher)
        .by_ref()
        .next()
        .cloned())
}

fn ibc_client_update<D, H>(
    ctx: RequestCtx<'_, D, H>,
    client_id: ClientId,
    consensus_height: BlockHeight,
) -> storage_api::Result<Option<Event>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let matcher = dumb_queries::QueryMatcher::ibc_update_client(
        client_id,
        consensus_height,
    );
    Ok(ctx
        .event_log
        .iter_with_matcher(matcher)
        .by_ref()
        .next()
        .cloned())
}

fn ibc_packet<D, H>(
    ctx: RequestCtx<'_, D, H>,
    event_type: EventType,
    source_port: PortId,
    source_channel: ChannelId,
    destination_port: PortId,
    destination_channel: ChannelId,
    sequence: Sequence,
) -> storage_api::Result<Option<Event>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let matcher = dumb_queries::QueryMatcher::ibc_packet(
        event_type,
        source_port,
        source_channel,
        destination_port,
        destination_channel,
        sequence,
    );
    Ok(ctx
        .event_log
        .iter_with_matcher(matcher)
        .by_ref()
        .next()
        .cloned())
}

fn account<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
) -> storage_api::Result<Option<Account>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let account_exists = storage_api::account::exists(ctx.wl_storage, &owner)?;

    if account_exists {
        let public_keys =
            storage_api::account::public_keys(ctx.wl_storage, &owner)?;
        let threshold =
            storage_api::account::threshold(ctx.wl_storage, &owner)?;

        Ok(Some(Account {
            public_keys_map: AccountPublicKeysMap::from_iter(public_keys),
            address: owner,
            threshold: threshold.unwrap_or(1),
        }))
    } else {
        Ok(None)
    }
}

fn revealed<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let public_keys =
        storage_api::account::public_keys(ctx.wl_storage, &owner)?;

    Ok(!public_keys.is_empty())
}

#[cfg(test)]
mod test {
    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_test_utils::TestWasms;

    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::ledger::storage_api::{self, StorageWrite};
    use crate::proto::{Code, Data, Tx};
    use crate::types::hash::Hash;
    use crate::types::storage::Key;
    use crate::types::transaction::decrypted::DecryptedTx;
    use crate::types::transaction::TxType;
    use crate::types::{address, token};

    #[test]
    fn test_shell_queries_router_paths() {
        let path = RPC.shell().epoch_path();
        assert_eq!("/shell/epoch", path);

        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let key = token::balance_key(&token_addr, &owner);
        let path = RPC.shell().storage_value_path(&key);
        assert_eq!(format!("/shell/value/{}", key), path);

        let path = RPC.shell().dry_run_tx_path();
        assert_eq!("/shell/dry_run_tx", path);

        let path = RPC.shell().storage_prefix_path(&key);
        assert_eq!(format!("/shell/prefix/{}", key), path);

        let path = RPC.shell().storage_has_key_path(&key);
        assert_eq!(format!("/shell/has_key/{}", key), path);
    }

    #[tokio::test]
    async fn test_shell_queries_router_with_client() -> storage_api::Result<()>
    {
        // Initialize the `TestClient`
        let mut client = TestClient::new(RPC);
        // store the wasm code
        let tx_no_op = TestWasms::TxNoOp.read_bytes();
        let tx_hash = Hash::sha256(&tx_no_op);
        let key = Key::wasm_code(&tx_hash);
        let len_key = Key::wasm_code_len(&tx_hash);
        client.wl_storage.storage.write(&key, &tx_no_op).unwrap();
        client
            .wl_storage
            .storage
            .write(&len_key, (tx_no_op.len() as u64).try_to_vec().unwrap())
            .unwrap();

        // Request last committed epoch
        let read_epoch = RPC.shell().epoch(&client).await.unwrap();
        let current_epoch = client.wl_storage.storage.last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let mut outer_tx =
            Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        outer_tx.header.chain_id = client.wl_storage.storage.chain_id.clone();
        outer_tx.set_code(Code::from_hash(tx_hash));
        outer_tx.set_data(Data::new(vec![]));
        let tx_bytes = outer_tx.to_bytes();
        let result = RPC
            .shell()
            .dry_run_tx(&client, Some(tx_bytes), None, false)
            .await
            .unwrap();
        assert!(result.data.is_accepted());

        // Request storage value for a balance key ...
        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let balance_key = token::balance_key(&token_addr, &owner);
        // ... there should be no value yet.
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert!(read_balance.data.is_empty());

        // Request storage prefix iterator
        let balance_prefix = token::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert!(read_balances.data.is_empty());

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(!has_balance_key);

        // Then write some balance ...
        let balance = token::Amount::native_whole(1000);
        StorageWrite::write(&mut client.wl_storage, &balance_key, balance)?;
        // It has to be committed to be visible in a query
        client.wl_storage.commit_tx();
        client.wl_storage.commit_block().unwrap();
        // ... there should be the same value now
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert_eq!(
            balance,
            token::Amount::try_from_slice(&read_balance.data).unwrap()
        );

        // Request storage prefix iterator
        let balance_prefix = token::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert_eq!(read_balances.data.len(), 1);

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(has_balance_key);

        Ok(())
    }
}
