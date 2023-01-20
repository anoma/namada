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
    EthAddrBook, ValidatorSetArgs, VotingPowersMap, VotingPowersMapExt,
};
use namada_core::types::voting_power::{
    EthBridgeVotingPower, FractionalVotingPower,
};
use namada_ethereum_bridge::storage::bridge_pool::get_signed_root_key;
use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
use namada_ethereum_bridge::storage::proof::EthereumProof;
use namada_ethereum_bridge::storage::vote_tallies;
use namada_proof_of_stake::pos_queries::PosQueries;

use crate::ledger::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};
use crate::types::eth_abi::{Encode, EncodeCell};
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
        -> EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>
        = read_valset_upd_proof,

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
                let data = RelayProof {
                    // TODO: use actual validators
                    validator_args: Default::default(),
                    root: signed_root,
                    proof,
                }
                .encode()
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
) -> storage_api::Result<EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if epoch.0 == 0 {
        return Err(storage_api::Error::Custom(CustomError(
            "Validator set update proofs should only be requested from
             epoch 1 onwards"
                .into(),
        )));
    }
    let current_epoch = ctx.storage.last_epoch;
    if epoch > current_epoch.next() {
        return Err(storage_api::Error::Custom(CustomError(
            format!(
                "Requesting validator set update proof for {epoch:?}, but the \
                 last installed epoch is still {current_epoch:?}"
            )
            .into(),
        )));
    }

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

    let proof: EthereumProof<VotingPowersMap> =
        StorageRead::read(ctx.storage, &valset_upd_keys.body())?.expect(
            "EthereumProof is seen in storage, therefore it must exist",
        );

    // NOTE: `epoch - 1` is the epoch where we signed the proof
    Ok(proof.map(|set| (epoch - 1, set)).encode())
}

/// Read the active set of validators at the given [`Epoch`].
///
/// This method may fail if no set of validators exists yet,
/// at that [`Epoch`].
fn read_active_valset<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Epoch,
) -> storage_api::Result<EncodeCell<ValidatorSetArgs>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.storage.last_epoch;
    if epoch > current_epoch.next() {
        return Err(storage_api::Error::Custom(CustomError(
            format!(
                "Requesting active validator set at {epoch:?}, but the last \
                 installed epoch is still {current_epoch:?}"
            )
            .into(),
        )));
    }

    let total_power = ctx.storage.get_total_voting_power(Some(epoch)).into();

    let voting_powers_map: VotingPowersMap = ctx
        .storage
        .get_active_eth_addresses(Some(epoch))
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

    Ok(ValidatorSetArgs {
        epoch,
        validators,
        voting_powers,
    }
    .encode())
}

#[cfg(test)]
mod test_ethbridge_router {
    use std::collections::BTreeSet;

    use borsh::BorshSerialize;
    use namada_core::ledger::eth_bridge::storage::bridge_pool::{
        get_pending_key, get_signed_root_key, BridgePoolTree,
    };
    use namada_core::types::address::testing::established_address_1;
    use namada_core::types::vote_extensions::validator_set_update;
    use namada_ethereum_bridge::protocol::transactions::validator_set_update::aggregate_votes;

    use super::test_utils::bertha_address;
    use super::*;
    use crate::ledger::queries::testing::TestClient;
    use crate::ledger::queries::RPC;
    use crate::types::eth_abi::Encode;
    use crate::types::eth_bridge_pool::{
        GasFee, MultiSignedMerkleRoot, PendingTransfer, RelayProof,
        TransferToEthereum,
    };
    use crate::types::ethereum_events::EthAddress;

    /// Test that reading the active validator set works.
    #[tokio::test]
    async fn test_read_active_valset() {
        let mut client = TestClient::new(RPC);
        let epoch = Epoch(0);
        assert_eq!(client.storage.last_epoch, epoch);

        // write validator to storage
        test_utils::setup_default_storage(&mut client.storage);

        // commit the changes
        client.storage.commit().expect("Test failed");

        // check the response
        let validator_set = RPC
            .shell()
            .eth_bridge()
            .read_active_valset(&client, &epoch)
            .await
            .unwrap();
        let expected = {
            let total_power =
                client.storage.get_total_voting_power(Some(epoch)).into();

            let voting_powers_map: VotingPowersMap = client
                .storage
                .get_active_eth_addresses(Some(epoch))
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

    /// Test that when reading an active validator set too far ahead,
    /// RPC clients are met with an error.
    #[tokio::test]
    async fn test_read_active_valset_too_far_ahead() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.storage.last_epoch.0, 0);

        // write validator to storage
        test_utils::setup_default_storage(&mut client.storage);

        // commit the changes
        client.storage.commit().expect("Test failed");

        // check the response
        let result = RPC
            .shell()
            .eth_bridge()
            .read_active_valset(&client, &Epoch(999_999))
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
        assert_eq!(client.storage.last_epoch.0, 0);

        // write validator to storage
        let keys = test_utils::setup_default_storage(&mut client.storage);

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
            &mut client.storage,
            validator_set_update::VextDigest::singleton(vext.clone()),
        )
        .expect("Test failed");
        assert!(!tx_result.changed_keys.is_empty());

        // commit the changes
        client.storage.commit().expect("Test failed");

        // check the response
        let proof = RPC
            .shell()
            .eth_bridge()
            .read_valset_upd_proof(&client, &Epoch(1))
            .await
            .unwrap();
        let expected = {
            let mut proof =
                EthereumProof::new((0.into(), vext.data.voting_powers));
            proof.attach_signature(
                client
                    .storage
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
        assert_eq!(client.storage.last_epoch.0, 0);

        // write validator to storage
        test_utils::setup_default_storage(&mut client.storage);

        // commit the changes
        client.storage.commit().expect("Test failed");

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

// temporary home for test utils lol.
// this code is borrowed from the `ethereum_bridge` crate.
#[cfg(any(feature = "testing", test))]
#[allow(dead_code)]
mod test_utils {
    use std::collections::{BTreeSet, HashMap};

    use borsh::BorshSerialize;
    use namada_core::ledger::storage::testing::TestStorage;
    use namada_core::types::address::{self, Address};
    use namada_core::types::key::{
        self, protocol_pk_key, RefTo, SecretKey, SigScheme,
    };
    use namada_core::types::token;
    use namada_proof_of_stake::epoched::Epoched;
    use namada_proof_of_stake::types::{
        ValidatorConsensusKeys, ValidatorEthKey, ValidatorSet,
        WeightedValidator,
    };
    use namada_proof_of_stake::PosBase;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    /// Validator keys used for testing purposes.
    pub struct TestValidatorKeys {
        /// Consensus keypair.
        pub consensus: key::common::SecretKey,
        /// Protocol keypair.
        pub protocol: key::common::SecretKey,
        /// Ethereum hot keypair.
        pub eth_bridge: key::common::SecretKey,
        /// Ethereum cold keypair.
        pub eth_gov: key::common::SecretKey,
    }

    /// Set up a [`TestStorage`] initialized at genesis with a single
    /// validator.
    ///
    /// The validator's address is [`address::testing::established_address_1`].
    #[inline]
    pub fn setup_default_storage(
        storage: &mut TestStorage,
    ) -> HashMap<Address, TestValidatorKeys> {
        setup_storage_with_validators(
            storage,
            HashMap::from_iter([(
                address::testing::established_address_1(),
                100_u64.into(),
            )]),
        )
    }

    /// Set up a [`TestStorage`] initialized at genesis with the given
    /// validators.
    pub fn setup_storage_with_validators(
        storage: &mut TestStorage,
        active_validators: HashMap<Address, token::Amount>,
    ) -> HashMap<Address, TestValidatorKeys> {
        // write validator set
        let validator_set = ValidatorSet {
            active: active_validators
                .iter()
                .map(|(address, bonded_stake)| WeightedValidator {
                    bonded_stake: u64::from(*bonded_stake),
                    address: address.clone(),
                })
                .collect(),
            inactive: BTreeSet::default(),
        };
        let validator_sets = Epoched::init_at_genesis(validator_set, 0);
        storage.write_validator_set(&validator_sets);

        // write validator keys
        let mut all_keys = HashMap::new();
        for validator in active_validators.into_keys() {
            let keys = setup_storage_validator(storage, &validator);
            all_keys.insert(validator, keys);
        }

        all_keys
    }

    /// Set up a single validator in [`TestStorage`] with some
    /// arbitrary keys.
    fn setup_storage_validator(
        storage: &mut TestStorage,
        validator: &Address,
    ) -> TestValidatorKeys {
        // register protocol key
        let protocol_key = gen_ed25519_keypair();
        storage
            .write(
                &protocol_pk_key(validator),
                protocol_key.ref_to().try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // register consensus key
        let consensus_key = gen_ed25519_keypair();
        storage.write_validator_consensus_key(
            validator,
            &ValidatorConsensusKeys::init_at_genesis(consensus_key.ref_to(), 0),
        );

        // register ethereum keys
        let hot_key = gen_secp256k1_keypair();
        let cold_key = gen_secp256k1_keypair();
        storage.write_validator_eth_hot_key(
            validator,
            &ValidatorEthKey::init_at_genesis(hot_key.ref_to(), 0),
        );
        storage.write_validator_eth_cold_key(
            validator,
            &ValidatorEthKey::init_at_genesis(cold_key.ref_to(), 0),
        );

        TestValidatorKeys {
            consensus: consensus_key,
            protocol: protocol_key,
            eth_bridge: hot_key,
            eth_gov: cold_key,
        }
    }

    /// Generate a random [`key::secp256k1`] keypair.
    pub fn gen_secp256k1_keypair() -> key::common::SecretKey {
        let mut rng: ThreadRng = thread_rng();
        key::secp256k1::SigScheme::generate(&mut rng)
            .try_to_sk()
            .unwrap()
    }

    /// Generate a random [`key::ed25519`] keypair.
    pub fn gen_ed25519_keypair() -> key::common::SecretKey {
        let mut rng: ThreadRng = thread_rng();
        key::ed25519::SigScheme::generate(&mut rng)
            .try_to_sk()
            .unwrap()
    }

    /// An established user address for testing & development
    pub fn bertha_address() -> Address {
        Address::decode(
            "atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw",
        )
        .expect("The token address decoding shouldn't fail")
    }
}
