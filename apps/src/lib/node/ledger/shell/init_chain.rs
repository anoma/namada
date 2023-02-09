//! Implementation of chain initialization for the Shell
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::parameters::storage::get_staked_ratio_key;
use namada::ledger::parameters::Parameters;
use namada::ledger::pos::{into_tm_voting_power, staking_token_address};
use namada::ledger::storage_api::token::{
    credit_tokens, read_balance, read_total_supply,
};
use namada::ledger::storage_api::StorageWrite;
use namada::types::key::*;
use rust_decimal::Decimal;
#[cfg(not(feature = "dev"))]
use sha2::{Digest, Sha256};

use super::*;
use crate::facade::tendermint_proto::abci;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
use crate::facade::tendermint_proto::google::protobuf;
use crate::wasm_loader;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new genesis for the chain with specified id. This includes
    /// 1. A set of initial users and tokens
    /// 2. Setting up the validity predicates for both users and tokens
    pub fn init_chain(
        &mut self,
        init: request::InitChain,
        num_validators: u64,
    ) -> Result<response::InitChain> {
        let mut response = response::InitChain::default();
        let (current_chain_id, _) = self.wl_storage.storage.get_chain_id();
        if current_chain_id != init.chain_id {
            return Err(Error::ChainId(format!(
                "Current chain ID: {}, Tendermint chain ID: {}",
                current_chain_id, init.chain_id
            )));
        }
        #[cfg(not(feature = "dev"))]
        let genesis =
            genesis::genesis(&self.base_dir, &self.wl_storage.storage.chain_id);
        #[cfg(not(feature = "dev"))]
        {
            let genesis_bytes = genesis.try_to_vec().unwrap();
            let errors =
                self.wl_storage.storage.chain_id.validate(genesis_bytes);
            use itertools::Itertools;
            assert!(
                errors.is_empty(),
                "Chain ID validation failed: {}",
                errors.into_iter().format(". ")
            );
        }
        #[cfg(feature = "dev")]
        let genesis = genesis::genesis(num_validators);

        let ts: protobuf::Timestamp = init.time.expect("Missing genesis time");
        let initial_height = init
            .initial_height
            .try_into()
            .expect("Unexpected block height");
        // TODO hacky conversion, depends on https://github.com/informalsystems/tendermint-rs/issues/870
        let genesis_time: DateTimeUtc = (Utc
            .timestamp_opt(ts.seconds, ts.nanos as u32))
        .single()
        .expect("genesis time should be a valid timestamp")
        .into();

        // Initialize protocol parameters
        let genesis::Parameters {
            epoch_duration,
            max_proposal_bytes,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp_code_path,
            implicit_vp_sha256,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            wrapper_tx_fees,
        } = genesis.parameters;
        // borrow necessary for release build, annoys clippy on dev build
        #[allow(clippy::needless_borrow)]
        let implicit_vp =
            wasm_loader::read_wasm(&self.wasm_dir, &implicit_vp_code_path)
                .map_err(Error::ReadingWasm)?;
        // In dev, we don't check the hash
        #[cfg(feature = "dev")]
        let _ = implicit_vp_sha256;
        #[cfg(not(feature = "dev"))]
        {
            let mut hasher = Sha256::new();
            hasher.update(&implicit_vp);
            let vp_code_hash = hasher.finalize();
            assert_eq!(
                vp_code_hash.as_slice(),
                &implicit_vp_sha256,
                "Invalid implicit account's VP sha256 hash for {}",
                implicit_vp_code_path
            );
        }
        #[cfg(not(feature = "mainnet"))]
        // Try to find a faucet account
        let faucet_account = {
            genesis.established_accounts.iter().find_map(
                |genesis::EstablishedAccount {
                     address,
                     vp_code_path,
                     ..
                 }| {
                    if vp_code_path == "vp_testnet_faucet.wasm" {
                        Some(address.clone())
                    } else {
                        None
                    }
                },
            )
        };

        let parameters = Parameters {
            epoch_duration,
            max_proposal_bytes,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            #[cfg(not(feature = "mainnet"))]
            faucet_account,
            #[cfg(not(feature = "mainnet"))]
            wrapper_tx_fees,
        };
        parameters.init_storage(&mut self.wl_storage.storage);

        // Initialize governance parameters
        genesis
            .gov_params
            .init_storage(&mut self.wl_storage.storage);

        // Depends on parameters being initialized
        self.wl_storage
            .storage
            .init_genesis_epoch(initial_height, genesis_time, &parameters)
            .expect("Initializing genesis epoch must not fail");

        // Loaded VP code cache to avoid loading the same files multiple times
        let mut vp_code_cache: HashMap<String, Vec<u8>> = HashMap::default();

        // Initialize genesis established accounts
        for genesis::EstablishedAccount {
            address,
            vp_code_path,
            vp_sha256,
            public_key,
            storage,
        } in genesis.established_accounts
        {
            let vp_code = match vp_code_cache.get(&vp_code_path).cloned() {
                Some(vp_code) => vp_code,
                None => {
                    let wasm =
                        wasm_loader::read_wasm(&self.wasm_dir, &vp_code_path)
                            .map_err(Error::ReadingWasm)?;
                    vp_code_cache.insert(vp_code_path.clone(), wasm.clone());
                    wasm
                }
            };

            // In dev, we don't check the hash
            #[cfg(feature = "dev")]
            let _ = vp_sha256;
            #[cfg(not(feature = "dev"))]
            {
                let mut hasher = Sha256::new();
                hasher.update(&vp_code);
                let vp_code_hash = hasher.finalize();
                assert_eq!(
                    vp_code_hash.as_slice(),
                    &vp_sha256,
                    "Invalid established account's VP sha256 hash for {}",
                    vp_code_path
                );
            }

            self.wl_storage
                .write_bytes(&Key::validity_predicate(&address), vp_code)
                .unwrap();

            if let Some(pk) = public_key {
                let pk_storage_key = pk_key(&address);
                self.wl_storage
                    .write_bytes(&pk_storage_key, pk.try_to_vec().unwrap())
                    .unwrap();
            }

            for (key, value) in storage {
                self.wl_storage.write_bytes(&key, value).unwrap();
            }

            // When using a faucet WASM, initialize its PoW challenge storage
            #[cfg(not(feature = "mainnet"))]
            if vp_code_path == "vp_testnet_faucet.wasm" {
                let difficulty =
                    genesis.faucet_pow_difficulty.unwrap_or_default();
                // withdrawal limit defaults to 1000 NAM when not set
                let withdrawal_limit = genesis
                    .faucet_withdrawal_limit
                    .unwrap_or_else(|| token::Amount::whole(1_000));
                testnet_pow::init_faucet_storage(
                    &mut self.wl_storage,
                    &address,
                    difficulty,
                    withdrawal_limit,
                )
                .expect("Couldn't init faucet storage")
            }
        }

        // Initialize genesis implicit
        // TODO: verify if we can get the total initial token supply from simply
        // looping over the set of implicit accounts
        for genesis::ImplicitAccount { public_key } in genesis.implicit_accounts
        {
            let address: address::Address = (&public_key).into();
            let pk_storage_key = pk_key(&address);
            self.wl_storage.write(&pk_storage_key, public_key).unwrap();
        }

        // Initialize genesis token accounts
        for genesis::TokenAccount {
            address,
            vp_code_path,
            vp_sha256,
            balances,
        } in genesis.token_accounts
        {
            let vp_code =
                vp_code_cache.get_or_insert_with(vp_code_path.clone(), || {
                    wasm_loader::read_wasm(&self.wasm_dir, &vp_code_path)
                        .unwrap()
                });

            // In dev, we don't check the hash
            #[cfg(feature = "dev")]
            let _ = vp_sha256;
            #[cfg(not(feature = "dev"))]
            {
                let mut hasher = Sha256::new();
                hasher.update(&vp_code);
                let vp_code_hash = hasher.finalize();
                assert_eq!(
                    vp_code_hash.as_slice(),
                    &vp_sha256,
                    "Invalid token account's VP sha256 hash for {}",
                    vp_code_path
                );
            }

            self.wl_storage
                .write_bytes(&Key::validity_predicate(&address), vp_code)
                .unwrap();

            for (owner, amount) in balances {
                credit_tokens(&mut self.wl_storage, &address, &owner, amount)
                    .unwrap();
            }
        }

        // Initialize genesis validator accounts
        for validator in &genesis.validators {
            let vp_code = vp_code_cache.get_or_insert_with(
                validator.validator_vp_code_path.clone(),
                || {
                    wasm_loader::read_wasm(
                        &self.wasm_dir,
                        &validator.validator_vp_code_path,
                    )
                    .unwrap()
                },
            );

            #[cfg(not(feature = "dev"))]
            {
                let mut hasher = Sha256::new();
                hasher.update(&vp_code);
                let vp_code_hash = hasher.finalize();
                assert_eq!(
                    vp_code_hash.as_slice(),
                    &validator.validator_vp_sha256,
                    "Invalid validator VP sha256 hash for {}",
                    validator.validator_vp_code_path
                );
            }

            let addr = &validator.pos_data.address;
            self.wl_storage
                .write_bytes(&Key::validity_predicate(addr), vp_code)
                .expect("Unable to write user VP");
            // Validator account key
            let pk_key = pk_key(addr);
            self.wl_storage
                .write(&pk_key, &validator.account_key)
                .expect("Unable to set genesis user public key");

            // Balances
            // Account balance (tokens not staked in PoS)
            credit_tokens(
                &mut self.wl_storage,
                &staking_token_address(),
                addr,
                validator.non_staked_balance,
            )
            .unwrap();

            self.wl_storage
                .write(&protocol_pk_key(addr), &validator.protocol_key)
                .expect("Unable to set genesis user protocol public key");

            self.wl_storage
                .write(
                    &dkg_session_keys::dkg_pk_key(addr),
                    &validator.dkg_public_key,
                )
                .expect("Unable to set genesis user public DKG session key");
        }

        // PoS system depends on epoch being initialized. Write the total
        // genesis staking token balance to storage after
        // initialization.
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        pos::init_genesis_storage(
            &mut self.wl_storage,
            &genesis.pos_params,
            genesis
                .validators
                .clone()
                .into_iter()
                .map(|validator| validator.pos_data),
            current_epoch,
        );

        let total_nam =
            read_total_supply(&self.wl_storage, &staking_token_address())
                .unwrap();
        // At this stage in the chain genesis, the PoS address balance is the
        // same as the number of staked tokens
        let total_staked_nam = read_balance(
            &self.wl_storage,
            &staking_token_address(),
            &address::POS,
        )
        .unwrap();

        println!("READ TOTAL NAM BALANCE = {}", total_nam);
        println!("READ TOTAL STAKED NAM BALANCE = {}\n", total_staked_nam);

        // Set the ratio of staked to total NAM tokens in the parameters storage
        self.wl_storage
            .write(
                &get_staked_ratio_key(),
                Decimal::from(total_staked_nam) / Decimal::from(total_nam),
            )
            .expect("unable to set staked ratio of NAM in storage");

        ibc::init_genesis_storage(&mut self.wl_storage.storage);

        // Set the initial validator set
        for validator in genesis.validators {
            let mut abci_validator = abci::ValidatorUpdate::default();
            let consensus_key: common::PublicKey =
                validator.pos_data.consensus_key.clone();
            let pub_key = TendermintPublicKey {
                sum: Some(key_to_tendermint(&consensus_key).unwrap()),
            };
            abci_validator.pub_key = Some(pub_key);
            abci_validator.power = into_tm_voting_power(
                genesis.pos_params.tm_votes_per_token,
                validator.pos_data.tokens,
            );
            response.validators.push(abci_validator);
        }

        self.wl_storage
            .commit_genesis()
            .expect("Must be able to commit genesis state");

        Ok(response)
    }
}

trait HashMapExt<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    /// Inserts a value computed from `f` into the map if the given `key` is not
    /// present, then returns a clone of the value from the map.
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V;
}

impl<K, V> HashMapExt<K, V> for HashMap<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V {
        use std::collections::hash_map::Entry;
        match self.entry(key) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => v.insert(f()).clone(),
        }
    }
}
