//! Ethereum bridge related shell queries.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::eth_bridge::storage::bridge_pool::get_key_from_hash;
use namada_core::ledger::storage::merkle_tree::StoreRef;
use namada_core::ledger::storage::{
    DBIter, MerkleTree, StorageHasher, StoreType, DB,
};
use namada_core::ledger::storage_api::{
    self, CustomError, ResultExt, StorageRead,
};
use namada_core::types::vote_extensions::validator_set_update::{
    ValidatorSetArgs, VotingPowersMap,
};
use namada_ethereum_bridge::storage::bridge_pool::get_signed_root_key;
use namada_ethereum_bridge::storage::proof::EthereumProof;
use namada_ethereum_bridge::storage::vote_tallies;

use crate::ledger::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};
use crate::types::eth_abi::EncodeCell;
use crate::types::eth_bridge_pool::{
    MultiSignedMerkleRoot, PendingTransfer, RelayProof,
};
use crate::types::keccak::KeccakHash;
use crate::types::storage::Epoch;
use crate::types::storage::MembershipProof::BridgePool;

router! {ETH_BRIDGE,
    // Get the current contents of the Ethereum bridge pool
    ( "pool" / "contents" )
        -> Vec<PendingTransfer> = read_ethereum_bridge_pool,

    // Generate a merkle proof for the inclusion of requested
    // transfers in the Ethereum bridge pool
    ( "pool" / "proof" )
        -> EncodeCell<RelayProof> = (with_options generate_bridge_pool_proof),

    // Request a proof of a validator set signed off for
    // the given epoch.
    //
    // The request may fail if a proof is not considered complete yet.
    ( "validator_set" / "proof" / [epoch: Epoch] )
        -> EncodeCell<EthereumProof<VotingPowersMap>> = read_valset_upd_proof,

    // Request the set of active validator at the given epoch.
    //
    // The request may fail if no validator set exists at that epoch.
    ( "validator_set" / "active" / [epoch: Epoch] )
        -> EncodeCell<ValidatorSetArgs> = read_active_valset,
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
            .expect("Reading the database should not fail")
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
        let (keys, values): (Vec<_>, Vec<_>) = transfer_hashes
            .iter()
            .filter_map(|hash| {
                let key = get_key_from_hash(hash);
                match ctx.storage.read(&key) {
                    Ok((Some(bytes), _)) => Some((key, bytes)),
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
            values.iter().map(|v| v.as_slice()).collect(),
        ) {
            Ok(BridgePool(proof)) => {
                let data = EncodeCell::new(&RelayProof {
                    // TODO: use actual validators
                    validator_args: Default::default(),
                    root: signed_root,
                    proof,
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

/// Read a validator set update proof from storage.
///
/// This method may fail if a complete proof (i.e. with more than
/// 2/3 of the total voting power behind it) is not available yet.
fn read_valset_upd_proof<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Epoch,
) -> storage_api::Result<EncodeCell<EthereumProof<VotingPowersMap>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let valset_upd_keys = vote_tallies::Keys::from(&epoch);

    let seen = StorageRead::read(ctx.storage, &valset_upd_keys.seen())?
        .unwrap_or(false);
    if !seen {
        return Err(storage_api::Error::Custom(CustomError(
            format!(
                "Validator set update proof is not yet available for the \
                 queried epoch: {epoch:?}"
            )
            .into(),
        )));
    }

    // return ABI encoded proof; need to implement `AbiEncode`
    // for `EncodeCell<EthereumProof<VotingPowersMap>>`
    todo!()
}

/// Read the active set of validators at the given [`Epoch`].
///
/// This method may fail if no set of validators exists yet,
/// at that [`Epoch`].
fn read_active_valset<D, H>(
    _ctx: RequestCtx<'_, D, H>,
    _epoch: Epoch,
) -> storage_api::Result<EncodeCell<ValidatorSetArgs>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    todo!()
}

#[cfg(test)]
mod test_ethbridge_router {
    use std::collections::BTreeSet;

    use borsh::BorshSerialize;
    use namada_core::ledger::eth_bridge::storage::bridge_pool::{
        get_pending_key, get_signed_root_key, BridgePoolTree,
    };

    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::types::address::Address;
    use crate::types::eth_abi::Encode;
    use crate::types::eth_bridge_pool::{
        GasFee, MultiSignedMerkleRoot, PendingTransfer, RelayProof,
        TransferToEthereum,
    };
    use crate::types::ethereum_events::EthAddress;

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
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
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // check the response
        let pool = RPC
            .shell()
            .eth_bridge()
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
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
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
            .write(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // check the response
        let pool = RPC
            .shell()
            .eth_bridge()
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
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
            nonce: 0.into(),
        };

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .storage
            .write(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
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
            .eth_bridge()
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
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .storage
            .write(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
            nonce: 0.into(),
        };

        // commit the changes and increase block height
        client.storage.commit().expect("Test failed");
        client.storage.block.height = client.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .storage
            .write(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
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
            .eth_bridge()
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
