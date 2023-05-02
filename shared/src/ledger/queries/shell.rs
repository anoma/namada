use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::storage::BlockResults;

use crate::ledger::events::log::dumb_queries;
use crate::ledger::events::Event;
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
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
);

router! {SHELL,
    // Epoch of the last committed block
    ( "epoch" ) -> Epoch = epoch,

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

    // Block results access - read bit-vec
    ( "results" ) -> Vec<BlockResults> = read_results,

    // Conversion state access - read conversion
    ( "conv" / [asset_type: AssetType] ) -> Conversion = read_conversion,

    // was the transaction accepted?
    ( "accepted" / [tx_hash: Hash] ) -> Option<Event> = accepted,

    // was the transaction applied?
    ( "applied" / [tx_hash: Hash] ) -> Option<Event> = applied,

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
    use std::collections::BTreeMap;

    use namada_core::ledger::gas::TxGasMeter;
    use namada_core::ledger::parameters;

    use crate::ledger::protocol;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::proto::Tx;
    use crate::types::storage::TxIndex;
    use crate::types::transaction::wrapper::wrapper_tx::PairingEngine;
    use crate::types::transaction::{
        AffineCurve, DecryptedTx, EllipticCurve, TxType,
    };
    let gas_table: BTreeMap<String, u64> = ctx
        .wl_storage
        .read(&parameters::storage::get_gas_table_storage_key())
        .expect("Error while reading storage")
        .expect("Missing gas table in storage");

    let mut tx: TxType = Tx::try_from(&request.data[..])
        .into_storage_result()?
        .try_into()
        .unwrap();

    let mut write_log = WriteLog::default();

    // Wrapper dry run to allow estimating the gas cost of a transaction
    let mut tx_gas_meter = if let TxType::Wrapper(wrapper) = &tx {
        let mut tx_gas_meter =
            TxGasMeter::new(wrapper.gas_limit.to_owned().into());
        protocol::apply_tx(
            tx.to_owned(),
            &request.data,
            TxIndex::default(),
            &mut tx_gas_meter,
            &gas_table,
            &mut write_log,
            &ctx.wl_storage.storage,
            &mut ctx.vp_wasm_cache,
            &mut ctx.tx_wasm_cache,
            None,
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .into_storage_result()?;

        write_log.commit_tx();

        // NOTE: the encryption key for a dry-run should always be an hardcoded, dummy one
        let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
        tx = TxType::Decrypted(DecryptedTx::Decrypted {
            tx: wrapper
                .decrypt(privkey)
                .expect("Could not decrypt the inner tx"),
                    #[cfg(not(feature = "mainnet"))]
                    // To be able to dry-run testnet faucet withdrawal, pretend 
                    // that we got a valid PoW
                    has_valid_pow: true,
        });
        TxGasMeter::new(
            tx_gas_meter
                .tx_gas_limit
                .checked_sub(tx_gas_meter.get_current_transaction_gas())
                .unwrap_or_default(),
        )
    } else {
        // Cast to decrypted if needed
        if let TxType::Raw(raw_tx) = tx {
            tx = TxType::Decrypted(DecryptedTx::Decrypted {
                tx: raw_tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: true,
            });
        }
        // If dry run only the inner tx, use the max block gas as the gas limit
        TxGasMeter::new(
            ctx.wl_storage
                .read(&parameters::storage::get_max_block_gas_key())
                .expect("Error while reading storage key")
                .expect("Missing parameter in storage"),
        )
    };

    let data = protocol::apply_tx(
        tx,
        &vec![],
        TxIndex(0),
        &mut tx_gas_meter,
        &gas_table,
        &mut write_log,
        &ctx.wl_storage.storage,
        &mut ctx.vp_wasm_cache,
        &mut ctx.tx_wasm_cache,
        None,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .into_storage_result()?;
    // NOTE: the keys changed by the wrapper transaction (if any) are not returned from this function
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
    iter.for_each(|(key, value, _gas)| {
        let key = key
            .parse::<usize>()
            .expect("expected integer for block height");
        let value = BlockResults::try_from_slice(&value)
            .expect("expected BlockResults bytes");
        results[key] = value;
    });
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
    if let Some((addr, epoch, conv, pos)) = ctx
        .wl_storage
        .storage
        .conversion_state
        .assets
        .get(&asset_type)
    {
        Ok((
            addr.clone(),
            *epoch,
            Into::<masp_primitives::transaction::components::Amount>::into(
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
            < ctx.wl_storage.storage.last_height.0
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

#[cfg(test)]
mod test {
    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_test_utils::TestWasms;

    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::ledger::storage_api::{self, StorageWrite};
    use crate::proto::Tx;
    use crate::types::hash::Hash;
    use crate::types::storage::Key;
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
        let tx = Tx::new(
            tx_hash.to_vec(),
            None,
            client.wl_storage.storage.chain_id.clone(),
            None,
        );
        let tx_bytes = tx.to_bytes();
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
        let balance = token::Amount::from(1000);
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
