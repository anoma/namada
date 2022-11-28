use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use tendermint::merkle::proof::Proof;

use crate::ledger::eth_bridge::storage::bridge_pool::{
    get_key_from_hash, get_signed_root_key,
};
use crate::ledger::events::log::dumb_queries;
use crate::ledger::events::Event;
use crate::ledger::queries::types::{RequestCtx, RequestQuery};
use crate::ledger::queries::{require_latest_height, EncodedResponseQuery};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, MerkleTree, StoreRef, StoreType, DB};
use crate::ledger::storage_api::{self, CustomError, ResultExt, StorageRead};
use crate::types::address::Address;
use crate::types::eth_abi::EncodeCell;
use crate::types::eth_bridge_pool::{
    MultiSignedMerkleRoot, PendingTransfer, RelayProof,
};
use crate::types::hash::Hash;
use crate::types::keccak::KeccakHash;
use crate::types::storage::MembershipProof::BridgePool;
#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
use crate::types::storage::TxIndex;
use crate::types::storage::{
    self, BlockResults, Epoch, MerkleValue, PrefixValue,
};
#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
use crate::types::transaction::TxResult;

type Conversion = (
    Address,
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
);

#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
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

    // Conversion state access - read conversion
    ( "conv" / [asset_type: AssetType] ) -> Conversion = read_conversion,

    // Block results access - read bit-vec
    ( "results" ) -> Vec<BlockResults> = read_results,

    // was the transaction accepted?
    ( "accepted" / [tx_hash: Hash] ) -> Option<Event> = accepted,

    // was the transaction applied?
    ( "applied" / [tx_hash: Hash] ) -> Option<Event> = applied,

    // Get the current contents of the Ethereum bridge pool
    ( "eth_bridge_pool" / "contents" )
        -> Vec<PendingTransfer> = read_ethereum_bridge_pool,

    // Generate a merkle proof for the inclusion of requested transfers in the Ethereum bridge pool
    ( "eth_bridge_pool" / "proof" )
        -> EncodeCell<RelayProof> = (with_options generate_bridge_pool_proof),
}

#[cfg(not(all(feature = "wasm-runtime", feature = "ferveo-tpke")))]
router! {SHELL,
    // Epoch of the last committed block
    ( "epoch" ) -> Epoch = epoch,

    // Raw storage access - read value
    ( "value" / [storage_key: storage::Key] )
        -> Vec<u8> = (with_options storage_value),

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
    ( "accepted" / [tx_hash: Hash]) -> Option<Event> = accepted,

    // was the transaction applied?
    ( "applied" / [tx_hash: Hash]) -> Option<Event> = applied,

    // Get the current contents of the Ethereum bridge pool
    ( "eth_bridge_pool" / "contents" )
        -> Vec<PendingTransfer> = read_ethereum_bridge_pool,

    // Generate a merkle proof for the inclusion of requested
    // transfers in the Ethereum bridge pool
    ( "eth_bridge_pool" / "proof" )
        -> EncodeCell<RelayProof> = (with_options generate_bridge_pool_proof),
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
    use crate::ledger::gas::BlockGasMeter;
    use crate::ledger::protocol::{self, ShellParams};
    use crate::ledger::storage::write_log::WriteLog;
    use crate::proto::Tx;

    let mut gas_meter = BlockGasMeter::default();
    let mut write_log = WriteLog::default();
    let tx = Tx::try_from(&request.data[..]).into_storage_result()?;
    let data = protocol::apply_wasm_tx(
        tx,
        request.data.len(),
        &TxIndex(0),
        ShellParams {
            block_gas_meter: &mut gas_meter,
            write_log: &mut write_log,
            storage: ctx.storage,
            vp_wasm_cache: &mut ctx.vp_wasm_cache,
            tx_wasm_cache: &mut ctx.tx_wasm_cache,
        },
    )
    .into_storage_result()?;
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
    let (iter, _gas) = ctx.storage.iter_results();
    let mut results =
        vec![BlockResults::default(); ctx.storage.block.height.0 as usize + 1];
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
    if let Some((addr, epoch, conv, pos)) =
        ctx.storage.conversion_state.assets.get(&asset_type)
    {
        Ok((
            addr.clone(),
            *epoch,
            Into::<masp_primitives::transaction::components::Amount>::into(
                conv.clone(),
            ),
            ctx.storage.conversion_state.tree.path(*pos),
        ))
    } else {
        Err(storage_api::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No conversion found for asset type: {}", asset_type),
        )))
    }
}

fn epoch<D, H>(ctx: RequestCtx<'_, D, H>) -> storage_api::Result<Epoch>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let data = ctx.storage.last_epoch;
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
        if request.height.0 + past_height_limit < ctx.storage.last_height.0 {
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
        .storage
        .read_with_height(&storage_key, request.height)
        .into_storage_result()?
    {
        (Some(value), _gas) => {
            let proof = if request.prove {
                let proof = ctx
                    .storage
                    .get_existence_proof(
                        &storage_key,
                        value.clone().into(),
                        request.height,
                    )
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

    let (iter, _gas) = ctx.storage.iter_prefix(&storage_key);
    let data: storage_api::Result<Vec<PrefixValue>> = iter
        .map(|(key, value, _gas)| {
            let key = storage::Key::parse(key).into_storage_result()?;
            Ok(PrefixValue { key, value })
        })
        .collect();
    let data = data?;
    let proof = if request.prove {
        let mut ops = vec![];
        for PrefixValue { key, value } in &data {
            let mut proof = ctx
                .storage
                .get_existence_proof(key, value.clone().into(), request.height)
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
    let data = StorageRead::has_key(ctx.storage, &storage_key)?;
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

/// Read the current contents of the Ethereum bridge
/// pool.
fn read_ethereum_bridge_pool<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<PendingTransfer>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let stores = ctx
        .storage
        .db
        .read_merkle_tree_stores(ctx.storage.last_height)
        .expect("We should always be able to read the database")
        .expect(
            "Every signed root should correspond to an existing block height",
        );
    let store = match stores.get_store(StoreType::BridgePool) {
        StoreRef::BridgePool(store) => store,
        _ => unreachable!(),
    };

    let transfers: Vec<PendingTransfer> = store
        .iter()
        .map(|hash| {
            let res = ctx
                .storage
                .read(&get_key_from_hash(hash))
                .unwrap()
                .0
                .unwrap();
            BorshDeserialize::try_from_slice(res.as_slice()).unwrap()
        })
        .collect();
    Ok(transfers)
}

/// Generate a merkle proof for the inclusion of the
/// requested transfers in the Ethereum bridge pool.
fn generate_bridge_pool_proof<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if let Ok(transfer_hashes) =
        <Vec<KeccakHash>>::try_from_slice(request.data.as_slice())
    {
        // get the latest signed merkle root of the Ethereum bridge pool
        let signed_root: MultiSignedMerkleRoot = match ctx
            .storage
            .read(&get_signed_root_key())
            .expect("Reading the database should not faile")
        {
            (Some(bytes), _) => {
                BorshDeserialize::try_from_slice(bytes.as_slice()).unwrap()
            }
            _ => {
                return Err(storage_api::Error::SimpleMessage(
                    "No signed root for the Ethereum bridge pool exists in \
                     storage.",
                ));
            }
        };

        // get the merkle tree corresponding to the above root.
        let tree = MerkleTree::<H>::new(
            ctx.storage
                .db
                .read_merkle_tree_stores(signed_root.height)
                .expect("We should always be able to read the database")
                .expect(
                    "Every signed root should correspond to an existing block \
                     height",
                ),
        );
        // from the hashes of the transfers, get the actual values.
        let mut missing_hashes = vec![];
        let (keys, values): (Vec<_>, Vec<PendingTransfer>) = transfer_hashes
            .iter()
            .filter_map(|hash| {
                let key = get_key_from_hash(hash);
                match ctx.storage.read(&key) {
                    Ok((Some(bytes), _)) => {
                        PendingTransfer::try_from_slice(&bytes[..])
                            .ok()
                            .map(|transfer| (key, transfer))
                    }
                    _ => {
                        missing_hashes.push(hash);
                        None
                    }
                }
            })
            .unzip();
        if !missing_hashes.is_empty() {
            return Err(storage_api::Error::Custom(CustomError(
                format!(
                    "One or more of the provided hashes had no corresponding \
                     transfer in storage: {:?}",
                    missing_hashes
                )
                .into(),
            )));
        }
        // get the membership proof
        match tree.get_sub_tree_existence_proof(
            &keys,
            values.into_iter().map(MerkleValue::from).collect(),
        ) {
            Ok(BridgePool(proof)) => {
                let data = EncodeCell::new(&RelayProof {
                    // TODO: use actual validators
                    validator_args: Default::default(),
                    root: signed_root,
                    proof,
                    // TODO: Use real nonce
                    nonce: 0.into(),
                })
                .try_to_vec()
                .into_storage_result()?;
                Ok(EncodedResponseQuery {
                    data,
                    ..Default::default()
                })
            }
            Err(e) => Err(storage_api::Error::new(e)),
            _ => unreachable!(),
        }
    } else {
        Err(storage_api::Error::SimpleMessage(
            "Could not deserialize transfers",
        ))
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use borsh::{BorshDeserialize, BorshSerialize};

    use crate::ledger::eth_bridge::storage::bridge_pool::{
        get_pending_key, get_signed_root_key, BridgePoolTree,
    };
    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::ledger::storage_api::{self, StorageWrite};
    use crate::proto::Tx;
    use crate::types::address::Address;
    use crate::types::eth_abi::Encode;
    use crate::types::eth_bridge_pool::{
        GasFee, MultiSignedMerkleRoot, PendingTransfer, RelayProof,
        TransferToEthereum,
    };
    use crate::types::ethereum_events::EthAddress;
    use crate::types::{address, token};

    const TX_NO_OP_WASM: &str = "../wasm_for_tests/tx_no_op.wasm";

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
    }

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

        // Request last committed epoch
        let read_epoch = RPC.shell().epoch(&client).await.unwrap();
        let current_epoch = client.storage.last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let tx_no_op = std::fs::read(TX_NO_OP_WASM).expect("cannot load wasm");
        let tx = Tx::new(tx_no_op, None);
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
        StorageWrite::write(&mut client.storage, &balance_key, balance)?;
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

    /// Test that reading the bridge pool works
    #[tokio::test]
    async fn test_read_bridge_pool() {
        let mut client = TestClient::new(RPC);

        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // check the response
        let pool = RPC
            .shell()
            .read_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(pool, Vec::from([transfer]));
    }

    /// Test that reading the bridge pool always gets
    /// the latest pool
    #[tokio::test]
    async fn test_bridge_pool_updates() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // update the pool
        client
            .storage
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // check the response
        let pool = RPC
            .shell()
            .read_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(pool, Vec::from([transfer2]));
    }

    /// Test that we can get a merkle proof even if the signed
    /// merkle roots is lagging behind the pool
    #[tokio::test]
    async fn test_get_merkle_proof() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
        };

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .storage
            .write(&get_signed_root_key(), signed_root.try_to_vec().unwrap())
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        let resp = RPC
            .shell()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    vec![transfer.keccak256()]
                        .try_to_vec()
                        .expect("Test failed"),
                ),
                None,
                false,
            )
            .await
            .unwrap();

        let tree = BridgePoolTree::new(
            transfer.keccak256(),
            BTreeSet::from([transfer.keccak256()]),
        );
        let proof = tree
            .get_membership_proof(vec![transfer])
            .expect("Test failed");

        let proof = RelayProof {
            validator_args: Default::default(),
            root: signed_root,
            proof,
            // TODO: Use a real nonce
            nonce: 0.into(),
        }
        .encode()
        .into_inner();
        assert_eq!(proof, resp.data.into_inner());
    }

    /// Test if the no merkle tree including a transfer
    /// has had its root signed, then we cannot generate
    /// a proof.
    #[tokio::test]
    async fn test_cannot_get_proof() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
        };

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .storage
            .write(&get_signed_root_key(), signed_root.try_to_vec().unwrap())
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // this is in the pool, but its merkle root has not been signed yet
        let resp = RPC
            .shell()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    vec![transfer2.keccak256()]
                        .try_to_vec()
                        .expect("Test failed"),
                ),
                None,
                false,
            )
            .await;
        // thus proof generation should fail
        assert!(resp.is_err());
    }
}
