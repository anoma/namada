//! Ethereum bridge related shell queries.

use std::collections::HashMap;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::eth_bridge::storage::bridge_pool::get_key_from_hash;
use namada_core::ledger::storage::merkle_tree::StoreRef;
use namada_core::ledger::storage::{DBIter, StorageHasher, StoreType, DB};
use namada_core::ledger::storage_api::{
    self, CustomError, ResultExt, StorageRead,
};
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum,
};
use namada_core::types::ethereum_structs::RelayProof;
use namada_core::types::storage::{BlockHeight, DbKeySeg, Key};
use namada_core::types::token::Amount;
use namada_core::types::vote_extensions::validator_set_update::{
    ValidatorSetArgs, VotingPowersMap,
};
use namada_core::types::voting_power::FractionalVotingPower;
use namada_ethereum_bridge::parameters::UpgradeableContract;
use namada_ethereum_bridge::protocol::transactions::votes::{
    EpochedVotingPower, EpochedVotingPowerExt,
};
use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
use namada_ethereum_bridge::storage::proof::{sort_sigs, EthereumProof};
use namada_ethereum_bridge::storage::vote_tallies::{eth_msgs_prefix, Keys};
use namada_ethereum_bridge::storage::{
    bridge_contract_key, governance_contract_key, native_erc20_key,
    vote_tallies,
};
use namada_proof_of_stake::pos_queries::PosQueries;

use crate::ledger::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};
use crate::types::eth_abi::{Encode, EncodeCell};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::keccak::KeccakHash;
use crate::types::storage::Epoch;
use crate::types::storage::MembershipProof::BridgePool;

/// Contains information about the flow control of some ERC20
/// wrapped asset.
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize,
)]
pub struct Erc20FlowControl {
    /// Whether the wrapped asset is whitelisted.
    whitelisted: bool,
    /// Total minted supply of some wrapped asset.
    supply: Amount,
    /// The token cap of some wrapped asset.
    cap: Amount,
}

pub type RelayProofBytes = Vec<u8>;

router! {ETH_BRIDGE,
    // Get the current contents of the Ethereum bridge pool
    ( "pool" / "contents" )
        -> Vec<PendingTransfer> = read_ethereum_bridge_pool,

    // Get the contents of the Ethereum bridge pool covered by
    // the latest signed Merkle tree root.
    ( "pool" / "signed_contents" )
        -> Vec<PendingTransfer> = read_signed_ethereum_bridge_pool,

    // Generate a merkle proof for the inclusion of requested
    // transfers in the Ethereum bridge pool
    ( "pool" / "proof" )
        -> RelayProofBytes = (with_options generate_bridge_pool_proof),

    // Iterates over all ethereum events and returns the amount of
    // voting power backing each `TransferToEthereum` event.
    ( "pool" / "transfer_to_eth_progress" )
        -> HashMap<TransferToEthereum, FractionalVotingPower>
        = transfer_to_ethereum_progress,

    // Request a proof of a validator set signed off for
    // the given epoch.
    //
    // The request may fail if a proof is not considered complete yet.
    ( "validator_set" / "proof" / [epoch: Epoch] )
        -> EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>
        = read_valset_upd_proof,

    // Request the set of consensus validator at the given epoch.
    //
    // The request may fail if no validator set exists at that epoch.
    ( "validator_set" / "consensus" / [epoch: Epoch] )
        -> EncodeCell<ValidatorSetArgs> = read_consensus_valset,

    // Read the address and version of the Ethereum bridge's Governance
    // smart contract.
    ( "contracts" / "governance" )
        -> UpgradeableContract = read_governance_contract,

    // Read the address and version of the Ethereum bridge's Bridge
    // smart contract.
    ( "contracts" / "bridge" )
        -> UpgradeableContract = read_bridge_contract,

    // Read the address of the Ethereum bridge's native ERC20
    // smart contract.
    ( "contracts" / "native_erc20" )
        -> EthAddress = read_native_erc20_contract,

    // Read the voting powers map for the requested validator set
    // at the given block height.
    ( "voting_powers" / "height" / [height: BlockHeight] )
        -> VotingPowersMap = voting_powers_at_height,

    // Read the voting powers map for the requested validator set
    // at the given block height.
    ( "voting_powers" / "epoch" / [epoch: Epoch] )
        -> VotingPowersMap = voting_powers_at_epoch,

    // Read the total supply and respective cap of some wrapped
    // ERC20 token in Namada.
    ( "erc20" / "flow_control" / [asset: EthAddress] )
        -> Erc20FlowControl = get_erc20_flow_control,
}

/// Read the total supply and respective cap of some wrapped
/// ERC20 token in Namada.
fn get_erc20_flow_control<D, H>(
    ctx: RequestCtx<'_, D, H>,
    asset: EthAddress,
) -> storage_api::Result<Erc20FlowControl>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let ethbridge_queries = ctx.wl_storage.ethbridge_queries();

    let whitelisted = ethbridge_queries.is_token_whitelisted(&asset);
    let supply = ethbridge_queries
        .get_token_supply(&asset)
        .unwrap_or_default();
    let cap = ethbridge_queries.get_token_cap(&asset).unwrap_or_default();

    Ok(Erc20FlowControl {
        whitelisted,
        supply,
        cap,
    })
}

/// Helper function to read a smart contract from storage.
fn read_contract<T, D, H>(
    key: &Key,
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    let Some(contract) = StorageRead::read(ctx.wl_storage, key)? else {
        return Err(storage_api::Error::SimpleMessage(
            "Failed to read contract: The Ethereum bridge \
             storage is not initialized",
        ));
    };
    Ok(contract)
}

/// Read the address and version of the Ethereum bridge's Governance
/// smart contract.
#[inline]
fn read_governance_contract<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<UpgradeableContract>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_contract(&governance_contract_key(), ctx)
}

/// Read the address and version of the Ethereum bridge's Bridge
/// smart contract.
#[inline]
fn read_bridge_contract<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<UpgradeableContract>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_contract(&bridge_contract_key(), ctx)
}

/// Read the address of the Ethereum bridge's native ERC20
/// smart contract.
#[inline]
fn read_native_erc20_contract<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<EthAddress>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_contract(&native_erc20_key(), ctx)
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
    Ok(read_ethereum_bridge_pool_at_height(
        ctx.wl_storage.storage.get_last_block_height(),
        ctx,
    ))
}

/// Read the contents of the Ethereum bridge
/// pool covered by the latest signed root.
fn read_signed_ethereum_bridge_pool<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<PendingTransfer>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // get the latest signed merkle root of the Ethereum bridge pool
    let (_, height) = ctx
        .wl_storage
        .ethbridge_queries()
        .get_signed_bridge_pool_root()
        .ok_or(storage_api::Error::SimpleMessage(
            "No signed root for the Ethereum bridge pool exists in storage.",
        ))
        .into_storage_result()?;
    Ok(read_ethereum_bridge_pool_at_height(height, ctx))
}

/// Read the Ethereum bridge pool contents at a specified height.
fn read_ethereum_bridge_pool_at_height<D, H>(
    height: BlockHeight,
    ctx: RequestCtx<'_, D, H>,
) -> Vec<PendingTransfer>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // get the backing store of the merkle tree corresponding
    // at the specified height.
    let merkle_tree = ctx
        .wl_storage
        .storage
        .get_merkle_tree(height)
        .expect("We should always be able to read the database");
    let stores = merkle_tree.stores();
    let store = match stores.store(&StoreType::BridgePool) {
        StoreRef::BridgePool(store) => store,
        _ => unreachable!(),
    };

    let transfers: Vec<PendingTransfer> = store
        .keys()
        .map(|hash| {
            let value = ctx
                .wl_storage
                .storage
                .read_with_height(&get_key_from_hash(hash), height)
                .unwrap()
                .0
                .unwrap();
            PendingTransfer::try_from_slice(&value).unwrap()
        })
        .collect();
    transfers
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
    if let Ok((transfer_hashes, relayer)) =
        <(Vec<KeccakHash>, Address)>::try_from_slice(request.data.as_slice())
    {
        // get the latest signed merkle root of the Ethereum bridge pool
        let (signed_root, height) = ctx
            .wl_storage
            .ethbridge_queries()
            .get_signed_bridge_pool_root()
            .ok_or(storage_api::Error::SimpleMessage(
                "No signed root for the Ethereum bridge pool exists in \
                 storage.",
            ))
            .into_storage_result()?;

        // get the merkle tree corresponding to the above root.
        let tree = ctx
            .wl_storage
            .storage
            .get_merkle_tree(height)
            .into_storage_result()?;
        // from the hashes of the transfers, get the actual values.
        let mut missing_hashes = vec![];
        let (keys, values): (Vec<_>, Vec<_>) = transfer_hashes
            .iter()
            .filter_map(|hash| {
                let key = get_key_from_hash(hash);
                match ctx.wl_storage.read_bytes(&key) {
                    Ok(Some(bytes)) => Some((key, bytes)),
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
        let transfers = values
            .iter()
            .map(|bytes| {
                PendingTransfer::try_from_slice(bytes)
                    .expect("Deserializing storage shouldn't fail")
                    .into()
            })
            .collect();
        // get the membership proof
        match tree.get_sub_tree_existence_proof(
            &keys,
            values.iter().map(|v| v.as_slice()).collect(),
        ) {
            Ok(BridgePool(proof)) => {
                let (validator_args, voting_powers) = ctx
                    .wl_storage
                    .ethbridge_queries()
                    .get_validator_set_args(None);
                let data = RelayProof {
                    validator_set_args: validator_args.into(),
                    signatures: sort_sigs(
                        &voting_powers,
                        &signed_root.signatures,
                    ),
                    transfers,
                    pool_root: signed_root.data.0.0,
                    proof: proof.proof.into_iter().map(|hash| hash.0).collect(),
                    proof_flags: proof.flags,
                    batch_nonce: signed_root.data.1.into(),
                    relayer_address: relayer.to_string(),
                };
                let data = ethers::abi::AbiEncode::encode(data)
                    .try_to_vec()
                    .expect("Serializing a relay proof should not fail.");
                Ok(EncodedResponseQuery {
                    data,
                    ..Default::default()
                })
            }
            Ok(_) => unreachable!(),
            Err(e) => Err(storage_api::Error::new(e)),
        }
    } else {
        Err(storage_api::Error::SimpleMessage(
            "Could not deserialize transfers",
        ))
    }
}

/// Iterates over all ethereum events
/// and returns the amount of voting power
/// backing each `TransferToEthereum` event.
fn transfer_to_ethereum_progress<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<HashMap<TransferToEthereum, FractionalVotingPower>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut pending_events = HashMap::new();
    for (mut key, value) in ctx
        .wl_storage
        .iter_prefix(&eth_msgs_prefix())?
        .filter_map(|(k, v, _)| {
            let key = Key::from_str(&k).expect(
                "Iterating over keys from storage shouldn't not yield \
                 un-parsable keys.",
            );
            match key.segments.last() {
                Some(DbKeySeg::StringSeg(ref seg))
                    if seg == Keys::segments().body =>
                {
                    Some((key, v))
                }
                _ => None,
            }
        })
    {
        // we checked above that key is not empty, so this write is fine
        *key.segments.last_mut().unwrap() =
            DbKeySeg::StringSeg(Keys::segments().seen.into());
        // check if the event has been seen
        let is_seen = ctx
            .wl_storage
            .read::<bool>(&key)
            .into_storage_result()?
            .expect(
                "Iterating over storage should not yield keys without values.",
            );
        if is_seen {
            continue;
        }

        if let Ok(EthereumEvent::TransfersToEthereum { transfers, .. }) =
            EthereumEvent::try_from_slice(&value)
        {
            // read the voting power behind the event
            *key.segments.last_mut().unwrap() =
                DbKeySeg::StringSeg(Keys::segments().voting_power.into());
            let voting_power = ctx
                .wl_storage
                .read::<EpochedVotingPower>(&key)
                .into_storage_result()?
                .expect(
                    "Iterating over storage should not yield keys without \
                     values.",
                )
                .average_voting_power(ctx.wl_storage);
            for transfer in transfers {
                pending_events.insert(transfer, voting_power);
            }
        }
    }
    Ok(pending_events)
}

/// Read a validator set update proof from storage.
///
/// This method may fail if a complete proof (i.e. with more than
/// 2/3 of the total voting power behind it) is not available yet.
fn read_valset_upd_proof<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Epoch,
) -> storage_api::Result<EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if epoch.0 == 0 {
        return Err(storage_api::Error::Custom(CustomError(
            "Validator set update proofs should only be requested from epoch \
             1 onwards"
                .into(),
        )));
    }
    let current_epoch = ctx.wl_storage.storage.last_epoch;
    if epoch > current_epoch.next() {
        return Err(storage_api::Error::Custom(CustomError(
            format!(
                "Requesting validator set update proof for {epoch:?}, but the \
                 last installed epoch is still {current_epoch:?}"
            )
            .into(),
        )));
    }

    if !ctx.wl_storage.ethbridge_queries().valset_upd_seen(epoch) {
        return Err(storage_api::Error::Custom(CustomError(
            format!(
                "Validator set update proof is not yet available for the \
                 queried epoch: {epoch:?}"
            )
            .into(),
        )));
    }

    let valset_upd_keys = vote_tallies::Keys::from(&epoch);
    let proof: EthereumProof<VotingPowersMap> =
        StorageRead::read(ctx.wl_storage, &valset_upd_keys.body())?.expect(
            "EthereumProof is seen in storage, therefore it must exist",
        );

    // NOTE: we pass the epoch of the new set of validators
    Ok(proof.map(|set| (epoch, set)).encode())
}

/// Read the consensus set of validators at the given [`Epoch`].
///
/// This method may fail if no set of validators exists yet,
/// at that [`Epoch`].
fn read_consensus_valset<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Epoch,
) -> storage_api::Result<EncodeCell<ValidatorSetArgs>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.wl_storage.storage.last_epoch;
    if epoch > current_epoch.next() {
        Err(storage_api::Error::Custom(CustomError(
            format!(
                "Requesting consensus validator set at {epoch:?}, but the \
                 last installed epoch is still {current_epoch:?}"
            )
            .into(),
        )))
    } else {
        Ok(ctx
            .wl_storage
            .ethbridge_queries()
            .get_validator_set_args(Some(epoch))
            .0
            .encode())
    }
}

/// Retrieve the consensus validator voting powers at the
/// given [`BlockHeight`].
fn voting_powers_at_height<D, H>(
    ctx: RequestCtx<'_, D, H>,
    height: BlockHeight,
) -> storage_api::Result<VotingPowersMap>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let maybe_epoch = ctx.wl_storage.pos_queries().get_epoch(height);
    let Some(epoch) = maybe_epoch else {
        return Err(storage_api::Error::SimpleMessage(
            "The epoch of the requested height does not exist",
        ));
    };
    voting_powers_at_epoch(ctx, epoch)
}

/// Retrieve the consensus validator voting powers at the
/// given [`Epoch`].
fn voting_powers_at_epoch<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Epoch,
) -> storage_api::Result<VotingPowersMap>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.wl_storage.storage.get_current_epoch().0;
    if epoch > current_epoch + 1u64 {
        return Err(storage_api::Error::SimpleMessage(
            "The requested epoch cannot be queried",
        ));
    }
    let (_, voting_powers) = ctx
        .wl_storage
        .ethbridge_queries()
        .get_validator_set_args(Some(epoch));
    Ok(voting_powers)
}

#[cfg(test)]
mod test_ethbridge_router {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use namada_core::ledger::eth_bridge::storage::bridge_pool::{
        get_pending_key, get_signed_root_key, BridgePoolTree,
    };
    use namada_core::ledger::eth_bridge::storage::whitelist;
    use namada_core::ledger::storage::mockdb::MockDBWriteBatch;
    use namada_core::ledger::storage_api::StorageWrite;
    use namada_core::types::address::testing::established_address_1;
    use namada_core::types::storage::BlockHeight;
    use namada_core::types::vote_extensions::validator_set_update;
    use namada_core::types::vote_extensions::validator_set_update::{
        EthAddrBook, VotingPowersMapExt,
    };
    use namada_core::types::voting_power::{
        EthBridgeVotingPower, FractionalVotingPower,
    };
    use namada_ethereum_bridge::protocol::transactions::validator_set_update::aggregate_votes;
    use namada_ethereum_bridge::storage::proof::BridgePoolRootProof;
    use namada_proof_of_stake::pos_queries::PosQueries;

    use super::test_utils::bertha_address;
    use super::*;
    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::types::eth_abi::Encode;
    use crate::types::eth_bridge_pool::{
        GasFee, PendingTransfer, TransferToEthereum, TransferToEthereumKind,
    };
    use crate::types::ethereum_events::EthAddress;

    /// Test that reading the consensus validator set works.
    #[tokio::test]
    async fn test_read_consensus_valset() {
        let mut client = TestClient::new(RPC);
        let epoch = Epoch(0);
        assert_eq!(client.wl_storage.storage.last_epoch, epoch);

        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // commit the changes
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let validator_set = RPC
            .shell()
            .eth_bridge()
            .read_consensus_valset(&client, &epoch)
            .await
            .unwrap();
        let expected = {
            let total_power = client
                .wl_storage
                .pos_queries()
                .get_total_voting_power(Some(epoch))
                .into();

            let voting_powers_map: VotingPowersMap = client
                .wl_storage
                .ethbridge_queries()
                .get_consensus_eth_addresses(Some(epoch))
                .iter()
                .map(|(addr_book, _, power)| (addr_book, power))
                .collect();
            let (validators, voting_powers) = voting_powers_map
                .get_sorted()
                .into_iter()
                .map(|(&EthAddrBook { hot_key_addr, .. }, &power)| {
                    let voting_power: EthBridgeVotingPower =
                        FractionalVotingPower::new(power.into(), total_power)
                            .expect("Fractional voting power should be >1")
                            .into();
                    (hot_key_addr, voting_power)
                })
                .unzip();

            ValidatorSetArgs {
                epoch,
                validators,
                voting_powers,
            }
            .encode()
        };

        assert_eq!(validator_set, expected);
    }

    /// Test that when reading an consensus validator set too far ahead,
    /// RPC clients are met with an error.
    #[tokio::test]
    async fn test_read_consensus_valset_too_far_ahead() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.wl_storage.storage.last_epoch.0, 0);

        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // commit the changes
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let result = RPC
            .shell()
            .eth_bridge()
            .read_consensus_valset(&client, &Epoch(999_999))
            .await;
        let Err(err) = result else {
            panic!("Test failed");
        };

        assert!(
            err.to_string()
                .split_once("but the last installed epoch is still")
                .is_some()
        );
    }

    /// Test that reading a validator set proof works.
    #[tokio::test]
    async fn test_read_valset_upd_proof() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.wl_storage.storage.last_epoch.0, 0);

        // write validator to storage
        let keys = test_utils::init_default_storage(&mut client.wl_storage);

        // write proof to storage
        let vext = validator_set_update::Vext {
            voting_powers: VotingPowersMap::new(),
            validator_addr: established_address_1(),
            signing_epoch: 0.into(),
        }
        .sign(
            &keys
                .get(&established_address_1())
                .expect("Test failed")
                .eth_bridge,
        );
        let tx_result = aggregate_votes(
            &mut client.wl_storage,
            validator_set_update::VextDigest::singleton(vext.clone()),
            0.into(),
        )
        .expect("Test failed");
        assert!(!tx_result.changed_keys.is_empty());

        // commit the changes
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let proof = RPC
            .shell()
            .eth_bridge()
            .read_valset_upd_proof(&client, &Epoch(1))
            .await
            .unwrap();
        let expected = {
            let mut proof =
                EthereumProof::new((1.into(), vext.data.voting_powers));
            proof.attach_signature(
                client
                    .wl_storage
                    .ethbridge_queries()
                    .get_eth_addr_book(&established_address_1(), Some(0.into()))
                    .expect("Test failed"),
                vext.sig,
            );
            proof.encode()
        };

        assert_eq!(proof, expected);
    }

    /// Test that when reading a validator set proof too far ahead,
    /// RPC clients are met with an error.
    #[tokio::test]
    async fn test_read_valset_upd_proof_too_far_ahead() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.wl_storage.storage.last_epoch.0, 0);

        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // commit the changes
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let result = RPC
            .shell()
            .eth_bridge()
            .read_valset_upd_proof(&client, &Epoch(999_999))
            .await;
        let Err(err) = result else {
            panic!("Test failed");
        };

        assert!(
            err.to_string()
                .split_once("but the last installed epoch is still")
                .is_some()
        );
    }

    /// Test that reading the bridge pool works
    #[tokio::test]
    async fn test_read_bridge_pool() {
        let mut client = TestClient::new(RPC);

        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
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
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

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
                kind: TransferToEthereumKind::Erc20,
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
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        client
            .wl_storage
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

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
                kind: TransferToEthereumKind::Erc20,
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

        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // write a transfer into the bridge pool
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .wl_storage
            .write_bytes(
                &get_signed_root_key(),
                (signed_root.clone(), BlockHeight::from(0))
                    .try_to_vec()
                    .unwrap(),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    (vec![transfer.keccak256()], bertha_address())
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
            BTreeMap::from([(transfer.keccak256(), 1.into())]),
        );
        let proof = tree
            .get_membership_proof(vec![transfer.clone()])
            .expect("Test failed");

        let (validator_args, voting_powers) = client
            .wl_storage
            .ethbridge_queries()
            .get_validator_set_args(None);
        let data = RelayProof {
            validator_set_args: validator_args.into(),
            signatures: sort_sigs(&voting_powers, &signed_root.signatures),
            transfers: vec![transfer.into()],
            pool_root: signed_root.data.0.0,
            proof: proof.proof.into_iter().map(|hash| hash.0).collect(),
            proof_flags: proof.flags,
            batch_nonce: Default::default(),
            relayer_address: bertha_address().to_string(),
        };
        let proof = ethers::abi::AbiEncode::encode(data);
        assert_eq!(proof, resp.data);
    }

    /// Test if the merkle tree including a transfer
    /// has had its root signed, then we cannot generate
    /// a proof.
    #[tokio::test]
    async fn test_cannot_get_proof() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
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
        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // write a transfer into the bridge pool
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };

        // commit the changes and increase block height
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .wl_storage
            .write_bytes(
                &get_signed_root_key(),
                (signed_root, BlockHeight::from(0)).try_to_vec().unwrap(),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // this is in the pool, but its merkle root has not been signed yet
        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    (vec![transfer2.keccak256()], bertha_address())
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

    /// Test that the RPC call for bridge pool transfers
    /// covered by a signed merkle root behaves correctly.
    #[tokio::test]
    async fn test_read_signed_bp_transfers() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
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
        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // write a transfer into the bridge pool
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .wl_storage
            .write_bytes(
                &get_signed_root_key(),
                (signed_root, BlockHeight::from(0)).try_to_vec().unwrap(),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;
        let resp = RPC
            .shell()
            .eth_bridge()
            .read_signed_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(resp, vec![transfer]);
    }

    /// Test that we can get the backing voting power for
    /// each pending TransferToEthereum event.
    #[tokio::test]
    async fn test_transfer_to_eth_progress() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
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
        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // write a transfer into the bridge pool
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        let event_transfer =
            namada_core::types::ethereum_events::TransferToEthereum {
                kind: transfer.transfer.kind,
                asset: transfer.transfer.asset,
                receiver: transfer.transfer.recipient,
                amount: transfer.transfer.amount,
                gas_payer: transfer.gas_fee.payer.clone(),
                gas_amount: transfer.gas_fee.amount,
                sender: transfer.transfer.sender.clone(),
            };
        let eth_event = EthereumEvent::TransfersToEthereum {
            nonce: Default::default(),
            transfers: vec![event_transfer.clone()],
            valid_transfers_map: vec![true],
            relayer: bertha_address(),
        };
        let eth_msg_key = vote_tallies::Keys::from(&eth_event);
        let voting_power = FractionalVotingPower::HALF;
        client
            .wl_storage
            .write_bytes(
                &eth_msg_key.body(),
                eth_event.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        client
            .wl_storage
            .write_bytes(
                &eth_msg_key.voting_power(),
                EpochedVotingPower::from([(0.into(), voting_power)])
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        client
            .wl_storage
            .write(&eth_msg_key.seen(), false)
            .expect("Test failed");
        // commit the changes and increase block height
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client
            .wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        client.wl_storage.storage.block.height += 1;
        let resp = RPC
            .shell()
            .eth_bridge()
            .transfer_to_ethereum_progress(&client)
            .await
            .unwrap();
        let expected: HashMap<
            namada_core::types::ethereum_events::TransferToEthereum,
            FractionalVotingPower,
        > = [(event_transfer, voting_power)].into_iter().collect();
        assert_eq!(expected, resp);
    }

    /// Test if the a transfer has been removed from the
    /// pool (either because it was transferred or timed out),
    /// a proof is not generated for it, even if it was
    /// covered by a signed merkle root at a previous block
    /// height.
    #[tokio::test]
    async fn test_cannot_get_proof_for_removed_transfer() {
        let mut client = TestClient::new(RPC);
        // write validator to storage
        test_utils::init_default_storage(&mut client.wl_storage);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
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
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .wl_storage
            .write_bytes(
                &get_pending_key(&transfer2),
                transfer2.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .wl_storage
            .write_bytes(
                &get_signed_root_key(),
                (signed_root, BlockHeight::from(0)).try_to_vec().unwrap(),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.wl_storage.commit_block().expect("Test failed");
        client.wl_storage.storage.block.height += 1;
        // this was in the pool, covered by an old signed Merkle root.
        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    vec![(transfer.keccak256(), bertha_address())]
                        .try_to_vec()
                        .expect("Test failed"),
                ),
                None,
                false,
            )
            .await;
        assert!(resp.is_ok());

        // remove a transfer from the pool.
        client
            .wl_storage
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");

        // this was in the pool, covered by an old signed Merkle root.
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
            .await;
        // thus proof generation should fail
        assert!(resp.is_err());
    }

    /// Test reading the supply and cap of an ERC20 token.
    #[tokio::test]
    async fn test_get_erc20_flow_control() {
        const ERC20_TOKEN: EthAddress = EthAddress([0; 20]);

        let mut client = TestClient::new(RPC);
        assert_eq!(client.wl_storage.storage.last_epoch.0, 0);

        // initialize storage
        test_utils::init_default_storage(&mut client.wl_storage);

        // check supply - should be 0
        let result = RPC
            .shell()
            .eth_bridge()
            .get_erc20_flow_control(&client, &ERC20_TOKEN)
            .await;
        assert_matches!(
            result,
            Ok(f) if f.supply.is_zero() && f.cap.is_zero()
        );

        // write tokens to storage
        let supply_amount = Amount::native_whole(123);
        let cap_amount = Amount::native_whole(12345);
        let key = whitelist::Key {
            asset: ERC20_TOKEN,
            suffix: whitelist::KeyType::WrappedSupply,
        }
        .into();
        client
            .wl_storage
            .write(&key, supply_amount)
            .expect("Test failed");
        let key = whitelist::Key {
            asset: ERC20_TOKEN,
            suffix: whitelist::KeyType::Cap,
        }
        .into();
        client
            .wl_storage
            .write(&key, cap_amount)
            .expect("Test failed");

        // check that the supply was updated
        let result = RPC
            .shell()
            .eth_bridge()
            .get_erc20_flow_control(&client, &ERC20_TOKEN)
            .await;
        assert_matches!(
            result,
            Ok(f) if f.supply == supply_amount && f.cap == cap_amount
        );
    }
}

#[cfg(any(feature = "testing", test))]
#[allow(dead_code)]
mod test_utils {
    use namada_core::types::address::Address;
    pub use namada_ethereum_bridge::test_utils::*;

    /// An established user address for testing & development
    pub fn bertha_address() -> Address {
        Address::decode(
            "atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw",
        )
        .expect("The token address decoding shouldn't fail")
    }
}
