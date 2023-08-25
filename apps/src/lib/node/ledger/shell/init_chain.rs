//! Implementation of chain initialization for the Shell
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::eth_bridge::EthBridgeStatus;
use namada::ledger::parameters::Parameters;
use namada::ledger::pos::PosParams;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::ledger::storage_api::token::{credit_tokens, write_denom};
use namada::ledger::storage_api::StorageWrite;
use namada::ledger::{ibc, pos};
use namada::proof_of_stake::{BecomeValidator, Epoch};
use namada::types::hash::Hash as CodeHash;
use namada::types::key::*;
use namada::types::time::{DateTimeUtc, TimeZone, Utc};
use namada::types::token;

use super::*;
use crate::config::genesis::chain::{
    FinalizedEstablishedAccountTx, FinalizedTokenConfig,
    FinalizedValidatorAccountTx,
};
use crate::config::genesis::templates::{TokenBalances, TokenConfig};
use crate::config::genesis::transactions::{
    BondTx, EstablishedAccountTx, SignedBondTx, SignedTransferTx, TransferTx,
    ValidatorAccountTx,
};
use crate::facade::tendermint_proto::abci;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
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
        #[cfg(test)] num_validators: u64,
    ) -> Result<response::InitChain> {
        let mut response = response::InitChain::default();
        let chain_id = self.wl_storage.storage.chain_id.as_str();
        if chain_id != init.chain_id.as_str() {
            return Err(Error::ChainId(format!(
                "Current chain ID: {}, Tendermint chain ID: {}",
                chain_id, init.chain_id
            )));
        }

        // Read the genesis files
        #[cfg(not(test))]
        let genesis = {
            let chain_dir = self.base_dir.join(chain_id);
            genesis::chain::Finalized::read_toml_files(&chain_dir)
                .expect("Missing genesis files")
        };
        #[cfg(test)]
        let genesis = genesis::make_dev_genesis(num_validators);
        #[cfg(test)]
        {
            // update the native token from the genesis file
            let native_token = genesis.get_native_token().clone();
            self.wl_storage.storage.native_token = native_token;
        }

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
        let parameters = genesis.get_chain_parameters(&self.wasm_dir);
        self.store_wasms(&parameters)?;
        parameters.init_storage(&mut self.wl_storage)?;

        // Initialize governance parameters
        let gov_params = genesis.get_gov_params();
        gov_params.init_storage(&mut self.wl_storage)?;

        // configure the Ethereum bridge if the configuration is set.
        if let Some(config) = genesis.get_eth_bridge_params() {
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

        // PoS system depends on epoch being initialized
        let pos_params = genesis.get_pos_params();
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        pos::namada_proof_of_stake::init_genesis(
            &mut self.wl_storage,
            &pos_params,
            current_epoch,
        )
        .expect("Must be able to initialize PoS genesis storage");

        // Loaded VP code cache to avoid loading the same files multiple times
        let mut vp_cache: HashMap<String, Vec<u8>> = HashMap::default();

        self.init_token_accounts(&genesis);
        self.init_token_balances(&genesis);
        self.apply_genesis_txs_established_account(&genesis, &mut vp_cache);
        self.apply_genesis_txs_validator_account(
            &genesis,
            &mut vp_cache,
            &pos_params,
            current_epoch,
        );
        self.apply_genesis_txs_transfer(&genesis);
        self.apply_genesis_txs_bonds(&genesis);

        pos::namada_proof_of_stake::store_total_consensus_stake(
            &mut self.wl_storage,
            Default::default(),
        ).expect("Could not compute total consensus stake at genesis");
        // This has to be done after `apply_genesis_txs_validator_account`
        pos::namada_proof_of_stake::copy_genesis_validator_sets(
            &mut self.wl_storage,
            &pos_params,
            current_epoch,
        )
        .expect("Must be able to copy PoS genesis validator sets");

        ibc::init_genesis_storage(&mut self.wl_storage);

        // Set the initial validator set
        if let Some(txs) = genesis.transactions.validator_account.as_ref() {
            for FinalizedValidatorAccountTx {
                address: _,
                tx:
                    ValidatorAccountTx {
                        alias,
                        consensus_key,
                        ..
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init a validator account {alias}"
                );

                let mut abci_validator = abci::ValidatorUpdate::default();
                let pub_key = TendermintPublicKey {
                    sum: Some(
                        key_to_tendermint(&consensus_key.pk.raw).unwrap(),
                    ),
                };
                abci_validator.pub_key = Some(pub_key);
                // TODO Read from PoS - must be after bonds txs
                let stake = token::Amount::default();
                abci_validator.power =
                    into_tm_voting_power(pos_params.tm_votes_per_token, stake);
                response.validators.push(abci_validator);
            }
        }

        Ok(response)
    }

    /// Look-up WASM code of a genesis VP by its name
    fn lookup_vp(
        &self,
        name: &str,
        genesis: &genesis::chain::Finalized,
        vp_cache: &mut HashMap<String, Vec<u8>>,
    ) -> Vec<u8> {
        let config =
            genesis.vps.wasm.get(name).unwrap_or_else(|| {
                panic!("Missing validity predicate for {name}")
            });
        let vp_filename = &config.filename;
        vp_cache.get_or_insert_with(vp_filename.clone(), || {
            wasm_loader::read_wasm(&self.wasm_dir, vp_filename).unwrap()
        })
    }

    fn store_wasms(&mut self, params: &Parameters) -> Result<()> {
        let Parameters {
            tx_whitelist,
            vp_whitelist,
            implicit_vp_code_hash,
            ..
        } = params;
        let mut is_implicit_vp_stored = false;
        let checksums = wasm_loader::Checksums::read_checksums(&self.wasm_dir);
        for (name, full_name) in checksums.0.iter() {
            let code = wasm_loader::read_wasm(&self.wasm_dir, name)
                .map_err(Error::ReadingWasm)?;
            let code_hash = CodeHash::sha256(&code);
            let elements = full_name.split('.').collect::<Vec<&str>>();
            let checksum = elements.get(1).ok_or_else(|| {
                Error::LoadingWasm(format!("invalid full name: {}", full_name))
            })?;
            assert_eq!(
                code_hash.to_string(),
                checksum.to_uppercase(),
                "Invalid wasm  code sha256 hash for {}",
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
                self.wl_storage.write_bytes(&code_key, code)?;

                let hash_key = Key::wasm_hash(name);
                self.wl_storage.write_bytes(&hash_key, code_hash)?;
                if &code_hash == implicit_vp_code_hash {
                    is_implicit_vp_stored = true;
                }
            } else {
                tracing::warn!("The wasm {name} isn't whitelisted.");
            }
        }
        // check if implicit_vp wasm is stored
        assert!(
            is_implicit_vp_stored,
            "No VP found matching the expected implicit VP sha256 hash: {}",
            implicit_vp_code_hash
        );
        Ok(())
    }

    /// Init genesis token accounts
    fn init_token_accounts(&mut self, genesis: &genesis::chain::Finalized) {
        for (alias, token) in &genesis.tokens.token {
            tracing::debug!("Initializing token {alias}");

            let FinalizedTokenConfig {
                address,
                config: TokenConfig { denom },
            } = token;
            // associate a token with its denomination.
            write_denom(&mut self.wl_storage, address, *denom).unwrap();
        }
    }

    /// Init genesis token balances
    fn init_token_balances(&mut self, genesis: &genesis::chain::Finalized) {
        for (token_alias, TokenBalances(balances)) in &genesis.balances.token {
            tracing::debug!("Initializing token balances {token_alias}");

            let token_address = &genesis
                .tokens
                .token
                .get(token_alias)
                .expect("Token with configured balance not found in genesis.")
                .address;
            for (owner_pk, balance) in balances {
                let owner = Address::from(&owner_pk.raw);

                let pk_storage_key = pk_key(&owner);
                self.wl_storage
                    .write(&pk_storage_key, owner_pk.try_to_vec().unwrap())
                    .unwrap();

                credit_tokens(
                    &mut self.wl_storage,
                    token_address,
                    &owner,
                    *balance,
                )
                .expect("Couldn't credit initial balance");
            }
        }
    }

    /// Apply genesis txs to initialize established accounts
    fn apply_genesis_txs_established_account(
        &mut self,
        genesis: &genesis::chain::Finalized,
        vp_cache: &mut HashMap<String, Vec<u8>>,
    ) {
        if let Some(txs) = genesis.transactions.established_account.as_ref() {
            for FinalizedEstablishedAccountTx {
                address,
                tx:
                    EstablishedAccountTx {
                        alias,
                        vp,
                        public_key,
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init an established account \
                     {alias}"
                );

                let vp_code = self.lookup_vp(vp, genesis, vp_cache);
                self.wl_storage
                    .write_bytes(&Key::validity_predicate(address), vp_code)
                    .unwrap();

                if let Some(pk) = public_key {
                    let pk_storage_key = pk_key(address);
                    self.wl_storage
                        .write_bytes(&pk_storage_key, pk.try_to_vec().unwrap())
                        .unwrap();
                }

                // When using a faucet WASM, initialize its PoW challenge
                // storage
                #[cfg(not(feature = "mainnet"))]
                if vp.as_str() == "vp_testnet_faucet" {
                    let difficulty = genesis
                        .parameters
                        .parameters
                        .faucet_pow_difficulty
                        .unwrap_or_default();
                    // withdrawal limit defaults to 1000 NAM when not set
                    let withdrawal_limit = genesis
                        .parameters
                        .parameters
                        .faucet_withdrawal_limit
                        .unwrap_or_else(|| token::Amount::native_whole(1_000));
                    testnet_pow::init_faucet_storage(
                        &mut self.wl_storage,
                        address,
                        difficulty,
                        withdrawal_limit.into(),
                    )
                    .expect("Couldn't init faucet storage")
                }
            }
        }
    }

    /// Apply genesis txs to initialize validator accounts
    fn apply_genesis_txs_validator_account(
        &mut self,
        genesis: &genesis::chain::Finalized,
        vp_cache: &mut HashMap<String, Vec<u8>>,
        params: &PosParams,
        current_epoch: Epoch,
    ) {
        if let Some(txs) = genesis.transactions.validator_account.as_ref() {
            for FinalizedValidatorAccountTx {
                address,
                tx:
                    ValidatorAccountTx {
                        alias,
                        vp,
                        dkg_key,
                        commission_rate,
                        max_commission_rate_change,
                        net_address: _,
                        account_key,
                        consensus_key,
                        protocol_key,
                        tendermint_node_key: _,
                        eth_hot_key,
                        eth_cold_key,
                    },
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to init a validator account {alias}"
                );

                let vp_code = self.lookup_vp(vp, genesis, vp_cache);

                self.wl_storage
                    .write_bytes(&Key::validity_predicate(address), vp_code)
                    .expect("Unable to write user VP");
                // Validator account key
                let pk_key = pk_key(address);
                self.wl_storage
                    .write(&pk_key, &account_key.pk.raw)
                    .expect("Unable to set genesis user public key");
                self.wl_storage
                    .write(&protocol_pk_key(address), &protocol_key.pk.raw)
                    .expect("Unable to set genesis user protocol public key");

                self.wl_storage
                    .write(&dkg_session_keys::dkg_pk_key(address), &dkg_key.raw)
                    .expect(
                        "Unable to set genesis user public DKG session key",
                    );

                // TODO: replace pos::init_genesis validators arg with
                // init_genesis_validator from here
                if let Err(err) = pos::namada_proof_of_stake::become_validator(
                    BecomeValidator {
                        storage: &mut self.wl_storage,
                        params,
                        address,
                        consensus_key: &consensus_key.pk.raw,
                        eth_cold_key: &eth_cold_key.pk.raw,
                        eth_hot_key: &eth_hot_key.pk.raw,
                        current_epoch,
                        commission_rate: *commission_rate,
                        max_commission_rate_change: *max_commission_rate_change,
                        offset_opt: Some(0),
                    },
                ) {
                    tracing::warn!(
                        "Genesis init genesis validator tx for {alias} failed \
                         with {err}. Skipping."
                    );
                    continue;
                }
            }
        }
    }

    /// Apply genesis txs to transfer tokens
    fn apply_genesis_txs_transfer(
        &mut self,
        genesis: &genesis::chain::Finalized,
    ) {
        if let Some(txs) = &genesis.transactions.transfer {
            for SignedTransferTx {
                data:
                    TransferTx {
                        token,
                        source,
                        target,
                        amount,
                    },
                signature: _,
            } in txs
            {
                let token = match genesis.get_token_address(token) {
                    Some(token) => {
                        tracing::debug!(
                            "Applying genesis tx to transfer {} of token \
                             {token} from {source} to {target}",
                            amount
                                .denominated(token, &self.wl_storage)
                                .unwrap(),
                        );
                        token
                    }
                    None => {
                        tracing::warn!(
                            "Genesis token transfer tx uses an unknown token \
                             alias {token}. Skipping."
                        );
                        continue;
                    }
                };
                let target = match genesis.get_user_address(target) {
                    Some(target) => target,
                    None => {
                        tracing::warn!(
                            "Genesis token transfer tx uses an unknown target \
                             alias {target}. Skipping."
                        );
                        continue;
                    }
                };
                let source: Address = (&source.raw).into();
                tracing::debug!(
                    "Transfer addresses: token {token} from {source} to \
                     {target}"
                );

                if let Err(err) = storage_api::token::transfer(
                    &mut self.wl_storage,
                    token,
                    &source,
                    target,
                    *amount,
                ) {
                    tracing::warn!(
                        "Genesis token transfer tx failed with: {err}. \
                         Skipping."
                    );
                    continue;
                };
            }
        }
    }

    /// Apply genesis txs to transfer tokens
    fn apply_genesis_txs_bonds(&mut self, genesis: &genesis::chain::Finalized) {
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        if let Some(txs) = &genesis.transactions.bond {
            for SignedBondTx {
                data:
                    BondTx {
                        source,
                        validator,
                        amount,
                    },
                signature: _,
            } in txs
            {
                tracing::debug!(
                    "Applying genesis tx to bond {} native tokens from \
                     {source} to {validator}",
                    amount.to_string_native(),
                );

                let source = match source {
                    genesis::transactions::AliasOrPk::Alias(alias) => {
                        match genesis.get_user_address(alias) {
                            Some(addr) => addr.clone(),
                            None => {
                                tracing::warn!(
                                    "Cannot find bond source address with \
                                     alias \"{alias}\". Skipping."
                                );
                                continue;
                            }
                        }
                    }
                    genesis::transactions::AliasOrPk::PublicKey(pk) => {
                        Address::from(&pk.raw)
                    }
                };

                let validator = match genesis.get_validator_address(validator) {
                    Some(addr) => addr,
                    None => {
                        tracing::warn!(
                            "Cannot find bond validator address with alias \
                             \"{validator}\". Skipping."
                        );
                        continue;
                    }
                };

                if let Err(err) = pos::namada_proof_of_stake::bond_tokens(
                    &mut self.wl_storage,
                    Some(&source),
                    validator,
                    *amount,
                    current_epoch,
                    Some(0),
                ) {
                    tracing::warn!(
                        "Genesis bond tx failed with: {err}. Skipping."
                    );
                    continue;
                };
            }
        }
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
