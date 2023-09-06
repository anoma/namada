//! Implementation of chain initialization for the Shell
use std::collections::HashMap;
use std::hash::Hash;

use namada::ledger::eth_bridge::EthBridgeStatus;
use namada::ledger::parameters::{self, Parameters};
use namada::ledger::pos::{staking_token_address, PosParams};
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::ledger::storage_api::token::{
    credit_tokens, read_balance, read_total_supply, write_denom,
};
use namada::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};
use namada::ledger::{ibc, pos};
use namada::types::dec::Dec;
use namada::types::hash::Hash as CodeHash;
use namada::types::key::*;
use namada::types::time::{DateTimeUtc, TimeZone, Utc};

use super::*;
use crate::facade::tendermint_proto::google::protobuf;
use crate::facade::tower_abci::{request, response};
use crate::wasm_loader;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new genesis for the chain with specified id. This includes
    /// 1. A set of initial users and tokens
    /// 2. Setting up the validity predicates for both users and tokens
    /// 3. Validators
    /// 4. The PoS system
    /// 5. The Ethereum bridge parameters
    ///
    /// INVARIANT: This method must not commit the state changes to DB.
    pub fn init_chain(
        &mut self,
        init: request::InitChain,
        #[cfg(any(test, feature = "dev"))] num_validators: u64,
    ) -> Result<response::InitChain> {
        let (current_chain_id, _) = self.wl_storage.storage.get_chain_id();
        if current_chain_id != init.chain_id {
            return Err(Error::ChainId(format!(
                "Current chain ID: {}, Tendermint chain ID: {}",
                current_chain_id, init.chain_id
            )));
        }
        #[cfg(not(any(test, feature = "dev")))]
        let genesis =
            genesis::genesis(&self.base_dir, &self.wl_storage.storage.chain_id);
        #[cfg(not(any(test, feature = "dev")))]
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
        #[cfg(any(test, feature = "dev"))]
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
            max_block_gas,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp_code_path,
            implicit_vp_sha256,
            epochs_per_year,
            max_signatures_per_transaction,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            gas_cost,
            fee_unshielding_gas_limit,
            fee_unshielding_descriptions_limit,
        } = genesis.parameters;
        // Store wasm codes into storage
        let checksums = wasm_loader::Checksums::read_checksums(&self.wasm_dir);
        for (name, full_name) in checksums.0.iter() {
            let code = wasm_loader::read_wasm(&self.wasm_dir, name)
                .map_err(Error::ReadingWasm)?;
            let code_hash = CodeHash::sha256(&code);
            let code_len = u64::try_from(code.len())
                .map_err(|e| Error::LoadingWasm(e.to_string()))?;

            let elements = full_name.split('.').collect::<Vec<&str>>();
            let checksum = elements.get(1).ok_or_else(|| {
                Error::LoadingWasm(format!("invalid full name: {}", full_name))
            })?;
            assert_eq!(
                code_hash.to_string(),
                checksum.to_uppercase(),
                "Invalid wasm code sha256 hash for {}",
                name
            );

            if (tx_whitelist.is_empty() && vp_whitelist.is_empty())
                || tx_whitelist.contains(&code_hash.to_string().to_lowercase())
                || vp_whitelist.contains(&code_hash.to_string().to_lowercase())
            {
                #[cfg(not(test))]
                if name.starts_with("tx_") {
                    self.tx_wasm_cache.pre_compile(&code);
                } else if name.starts_with("vp_") {
                    self.vp_wasm_cache.pre_compile(&code);
                }

                let code_key = Key::wasm_code(&code_hash);
                let code_len_key = Key::wasm_code_len(&code_hash);
                let hash_key = Key::wasm_hash(name);
                let code_name_key = Key::wasm_code_name(name.to_owned());

                self.wl_storage.write_bytes(&code_key, code)?;
                self.wl_storage.write(&code_len_key, code_len)?;
                self.wl_storage.write_bytes(&hash_key, code_hash)?;
                self.wl_storage.write_bytes(&code_name_key, code_hash)?;
            } else {
                tracing::warn!("The wasm {name} isn't whitelisted.");
            }
        }

        // check if implicit_vp wasm is stored
        let implicit_vp_code_hash =
            read_wasm_hash(&self.wl_storage, &implicit_vp_code_path)?.ok_or(
                Error::LoadingWasm(format!(
                    "Unknown vp code path: {}",
                    implicit_vp_code_path
                )),
            )?;
        // In dev, we don't check the hash
        #[cfg(feature = "dev")]
        let _ = implicit_vp_sha256;
        #[cfg(not(feature = "dev"))]
        {
            assert_eq!(
                implicit_vp_code_hash.0.as_slice(),
                &implicit_vp_sha256,
                "Invalid implicit account's VP sha256 hash for {}",
                implicit_vp_code_path
            );
        }

        let parameters = Parameters {
            epoch_duration,
            max_proposal_bytes,
            max_block_gas,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp_code_hash,
            epochs_per_year,
            max_signatures_per_transaction,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            gas_cost,
            fee_unshielding_gas_limit,
            fee_unshielding_descriptions_limit,
        };
        parameters
            .init_storage(&mut self.wl_storage)
            .expect("Initializing chain parameters must not fail");

        // Initialize governance parameters
        genesis
            .gov_params
            .init_storage(&mut self.wl_storage)
            .expect("Initializing chain parameters must not fail");

        // Initialize pgf parameters
        genesis
            .pgf_params
            .init_storage(&mut self.wl_storage)
            .expect("Initializing chain parameters must not fail");

        // configure the Ethereum bridge if the configuration is set.
        if let Some(config) = genesis.ethereum_bridge_params {
            tracing::debug!("Initializing Ethereum bridge storage.");
            config.init_storage(&mut self.wl_storage);
            self.update_eth_oracle();
        } else {
            self.wl_storage
                .write_bytes(
                    &namada::eth_bridge::storage::active_key(),
                    EthBridgeStatus::Disabled.try_to_vec().unwrap(),
                )
                .unwrap();
        }

        // Depends on parameters being initialized
        self.wl_storage
            .storage
            .init_genesis_epoch(initial_height, genesis_time, &parameters)
            .expect("Initializing genesis epoch must not fail");

        // Initialize genesis established accounts
        self.initialize_established_accounts(
            genesis.established_accounts,
            &implicit_vp_code_path,
        )?;

        // Initialize genesis implicit
        self.initialize_implicit_accounts(genesis.implicit_accounts);

        // Initialize genesis token accounts
        self.initialize_token_accounts(genesis.token_accounts);

        // Initialize genesis validator accounts
        let staking_token = staking_token_address(&self.wl_storage);
        self.initialize_validators(
            &staking_token,
            &genesis.validators,
            &implicit_vp_code_path,
        );
        // set the initial validators set
        self.set_initial_validators(
            &staking_token,
            genesis.validators,
            &genesis.pos_params,
        )
    }

    /// Initialize genesis established accounts
    fn initialize_established_accounts(
        &mut self,
        accounts: Vec<genesis::EstablishedAccount>,
        implicit_vp_code_path: &str,
    ) -> Result<()> {
        for genesis::EstablishedAccount {
            address,
            vp_code_path,
            vp_sha256,
            public_key,
            storage,
        } in accounts
        {
            let vp_code_hash = read_wasm_hash(&self.wl_storage, &vp_code_path)?
                .ok_or(Error::LoadingWasm(format!(
                    "Unknown vp code path: {}",
                    implicit_vp_code_path
                )))?;

            // In dev, we don't check the hash
            #[cfg(feature = "dev")]
            let _ = vp_sha256;
            #[cfg(not(feature = "dev"))]
            {
                assert_eq!(
                    vp_code_hash.0.as_slice(),
                    &vp_sha256,
                    "Invalid established account's VP sha256 hash for {}",
                    vp_code_path
                );
            }

            self.wl_storage
                .write_bytes(&Key::validity_predicate(&address), vp_code_hash)
                .unwrap();

            if let Some(pk) = public_key {
                storage_api::account::set_public_key_at(
                    &mut self.wl_storage,
                    &address,
                    &pk,
                    0,
                )?;
            }

            for (key, value) in storage {
                self.wl_storage.write_bytes(&key, value).unwrap();
            }
        }

        Ok(())
    }

    /// Initialize genesis implicit accounts
    fn initialize_implicit_accounts(
        &mut self,
        accounts: Vec<genesis::ImplicitAccount>,
    ) {
        // Initialize genesis implicit
        for genesis::ImplicitAccount { public_key } in accounts {
            let address: address::Address = (&public_key).into();
            storage_api::account::set_public_key_at(
                &mut self.wl_storage,
                &address,
                &public_key,
                0,
            )
            .unwrap();
        }
    }

    /// Initialize genesis token accounts
    fn initialize_token_accounts(
        &mut self,
        accounts: Vec<genesis::TokenAccount>,
    ) {
        // Initialize genesis token accounts
        for genesis::TokenAccount {
            address,
            denom,
            balances,
        } in accounts
        {
            // associate a token with its denomination.
            write_denom(&mut self.wl_storage, &address, denom).unwrap();
            for (owner, amount) in balances {
                credit_tokens(&mut self.wl_storage, &address, &owner, amount)
                    .unwrap();
            }
        }
    }

    /// Initialize genesis validator accounts
    fn initialize_validators(
        &mut self,
        staking_token: &Address,
        validators: &[genesis::Validator],
        implicit_vp_code_path: &str,
    ) {
        // Initialize genesis validator accounts
        for validator in validators {
            let vp_code_hash = read_wasm_hash(
                &self.wl_storage,
                &validator.validator_vp_code_path,
            )
            .unwrap()
            .ok_or(Error::LoadingWasm(format!(
                "Unknown vp code path: {}",
                implicit_vp_code_path
            )))
            .expect("Reading wasms should not fail");

            #[cfg(not(feature = "dev"))]
            {
                assert_eq!(
                    vp_code_hash.0.as_slice(),
                    &validator.validator_vp_sha256,
                    "Invalid validator VP sha256 hash for {}",
                    validator.validator_vp_code_path
                );
            }

            let addr = &validator.pos_data.address;
            self.wl_storage
                .write_bytes(&Key::validity_predicate(addr), vp_code_hash)
                .expect("Unable to write user VP");
            // Validator account key
            storage_api::account::set_public_key_at(
                &mut self.wl_storage,
                addr,
                &validator.account_key,
                0,
            )
            .unwrap();

            // Balances
            // Account balance (tokens not staked in PoS)
            credit_tokens(
                &mut self.wl_storage,
                staking_token,
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
    }

    /// Initialize the PoS and set the initial validator set
    fn set_initial_validators(
        &mut self,
        staking_token: &Address,
        validators: Vec<genesis::Validator>,
        pos_params: &PosParams,
    ) -> Result<response::InitChain> {
        let mut response = response::InitChain::default();
        // PoS system depends on epoch being initialized. Write the total
        // genesis staking token balance to storage after
        // initialization.
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        pos::init_genesis_storage(
            &mut self.wl_storage,
            pos_params,
            validators.into_iter().map(|validator| validator.pos_data),
            current_epoch,
        );

        let total_nam = read_total_supply(&self.wl_storage, staking_token)?;
        // At this stage in the chain genesis, the PoS address balance is the
        // same as the number of staked tokens
        let total_staked_nam =
            read_balance(&self.wl_storage, staking_token, &address::POS)?;

        tracing::info!(
            "Genesis total native tokens: {}.",
            total_nam.to_string_native()
        );
        tracing::info!(
            "Total staked tokens: {}.",
            total_staked_nam.to_string_native()
        );

        // Set the ratio of staked to total NAM tokens in the parameters storage
        parameters::update_staked_ratio_parameter(
            &mut self.wl_storage,
            &(Dec::from(total_staked_nam) / Dec::from(total_nam)),
        )
        .expect("unable to set staked ratio of NAM in storage");

        ibc::init_genesis_storage(&mut self.wl_storage);

        // Set the initial validator set
        response.validators = self
            .get_abci_validator_updates(true)
            .expect("Must be able to set genesis validator set");
        debug_assert!(!response.validators.is_empty());

        Ok(response)
    }
}

fn read_wasm_hash(
    storage: &impl StorageRead,
    path: impl AsRef<str>,
) -> storage_api::Result<Option<CodeHash>> {
    let hash_key = Key::wasm_hash(path);
    match storage.read_bytes(&hash_key)? {
        Some(value) => {
            let hash = CodeHash::try_from(&value[..]).into_storage_result()?;
            Ok(Some(hash))
        }
        None => Ok(None),
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

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use namada::ledger::storage::DBIter;

    use crate::node::ledger::shell::test_utils::{self, TestShell};

    /// Test that the init-chain handler never commits changes directly to the
    /// DB.
    #[test]
    fn test_init_chain_doesnt_commit_db() {
        let (shell, _recv, _, _) = test_utils::setup();

        // Collect all storage key-vals into a sorted map
        let store_block_state = |shell: &TestShell| -> BTreeMap<_, _> {
            shell
                .wl_storage
                .storage
                .db
                .iter_prefix(None)
                .map(|(key, val, _gas)| (key, val))
                .collect()
        };

        // Store the full state in sorted map
        let initial_storage_state: std::collections::BTreeMap<String, Vec<u8>> =
            store_block_state(&shell);

        // Store the full state again
        let storage_state: std::collections::BTreeMap<String, Vec<u8>> =
            store_block_state(&shell);

        // The storage state must be unchanged
        itertools::assert_equal(
            initial_storage_state.iter(),
            storage_state.iter(),
        );
    }
}
