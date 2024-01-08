//! A "faucet" account for testnet.
//!
//! This VP allows anyone to withdraw up to
//! [`testnet_pow::read_withdrawal_limit`] tokens without the faucet's
//! signature, but with a valid PoW challenge solution that cannot be replayed.
//!
//! Any other storage key changes are allowed only with a valid signature.

use namada_vp_prelude::*;
use once_cell::unsync::Lazy;

#[validity_predicate(gas = 0)]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Tx,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_testnet_faucet called with user addr: {}, key_changed: {:?}, \
         verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    let valid_sig = Lazy::new(|| {
        matches!(verify_signatures(ctx, &tx_data, &addr), Ok(true))
    });

    if !is_valid_tx(ctx, &tx_data)? {
        return reject();
    }

    for key in keys_changed.iter() {
        let is_valid = if let Some([token, owner]) =
            token::is_any_token_balance_key(key)
        {
            if owner == &addr {
                let pre: token::Amount = ctx.read_pre(key)?.unwrap_or_default();
                let post: token::Amount =
                    ctx.read_post(key)?.unwrap_or_default();
                let change = post.change() - pre.change();
                let maybe_denom = token::read_denom(&ctx.pre(), token)?;
                if maybe_denom.is_none() {
                    debug_log!(
                        "A denomination for token address {} does not exist \
                         in storage",
                        token,
                    );
                    return reject();
                }
                let denom = maybe_denom.unwrap();
                if !change.non_negative() {
                    // Allow to withdraw without a sig if there's a valid PoW
                    if ctx.has_valid_pow() {
                        let max_free_debit =
                            testnet_pow::read_withdrawal_limit(
                                &ctx.pre(),
                                &addr,
                            )?;

                        token::Amount::from_uint(change.abs(), 0).unwrap()
                            <= token::Amount::from_uint(max_free_debit, denom)
                                .unwrap()
                    } else {
                        debug_log!("No PoW solution, a signature is required");
                        // Debit without a solution has to signed
                        *valid_sig
                    }
                } else {
                    // credit is permissive
                    true
                }
            } else {
                // balance changes of other accounts
                true
            }
        } else if let Some(owner) = key.is_validity_predicate() {
            let has_post: bool = ctx.has_key_post(key)?;
            if owner == &addr {
                if has_post {
                    let vp_hash: Vec<u8> = ctx.read_bytes_post(key)?.unwrap();
                    return Ok(*valid_sig && is_vp_whitelisted(ctx, &vp_hash)?);
                } else {
                    return reject();
                }
            } else {
                let vp_hash: Vec<u8> = ctx.read_bytes_post(key)?.unwrap();
                return is_vp_whitelisted(ctx, &vp_hash);
            }
        } else {
            // Allow any other key change if authorized by a signature
            *valid_sig
        };

        if !is_valid {
            debug_log!("key {} modification failed vp", key);
            return reject();
        }
    }

    accept()
}

#[cfg(test)]
mod tests {
    use address::testing::arb_non_internal_address;
    use namada::tx::{Code, Data, Signature};
    use namada::types::transaction::TxType;
    use namada_test_utils::TestWasms;
    // Use this as `#[test]` annotation to enable logging
    use namada_tests::log::test;
    use namada_tests::tx::{self, tx_host_env, TestTxEnv};
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::account::AccountPublicKeysMap;
    use namada_vp_prelude::key::RefTo;
    use namada_vp_prelude::BorshSerializeExt;
    use proptest::prelude::*;
    use storage::testing::arb_account_storage_key_no_vp;

    use super::*;

    /// Allows anyone to withdraw up to 1_000 tokens in a single tx
    pub const MAX_FREE_DEBIT: i128 = 1_000_000_000; // in micro units

    /// Test that no-op transaction (i.e. no storage modifications) accepted.
    #[test]
    fn test_no_op_transaction() {
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let addr: Address = address::testing::established_address_1();
        let keys_changed: BTreeSet<storage::Key> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = BTreeSet::default();

        // The VP env must be initialized before calling `validate_tx`
        vp_host_env::init();

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).unwrap()
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx_host_env::ctx(),
                &source,
                address,
                &token,
                amount,
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            !validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a validity predicate update with a valid signature is
    /// accepted.
    #[test]
    fn test_signed_vp_update_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = &keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key.clone()]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Signature(Signature::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    prop_compose! {
        /// Generates an account address and a storage key inside its storage.
        fn arb_account_storage_subspace_key()
            // Generate an address
            (address in arb_non_internal_address())
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            (storage_key in arb_account_storage_key_no_vp(address.clone()),
            // Use the generated address too
            address in Just(address))
        -> (Address, Key) {
            (address, storage_key)
        }
    }

    proptest! {
    /// Test that a debit of more than [`MAX_FREE_DEBIT`] tokens without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_over_limit_rejected(amount in (MAX_FREE_DEBIT as u64 + 1..)) {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        // Init the VP
        let vp_owner = address::testing::established_address_1();
        let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
        let withdrawal_limit = token::Amount::from_uint(MAX_FREE_DEBIT as u64, 0).unwrap();
        testnet_pow::init_faucet_storage(&mut tx_env.wl_storage, &vp_owner, difficulty, withdrawal_limit.into()).unwrap();

        let target = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from_uint(amount, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        tx_env.commit_genesis();
        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into()
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
        // Apply transfer in a transaction
        tx_host_env::token::transfer(tx::ctx(), address, &target, &token, amount).unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
        vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(!validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
    }

    /// Test that a debit of less than or equal to [`MAX_FREE_DEBIT`] tokens
    /// without a valid signature but with a valid PoW solution is accepted.
    #[test]
    fn test_unsigned_debit_under_limit_accepted(amount in (..MAX_FREE_DEBIT as u64 + 1)) {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        // Init the VP
        let vp_owner = address::testing::established_address_1();
        let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
        let withdrawal_limit = token::Amount::from_uint(MAX_FREE_DEBIT as u64, 0).unwrap();
        testnet_pow::init_faucet_storage(&mut tx_env.wl_storage, &vp_owner, difficulty, withdrawal_limit.into()).unwrap();

        let target = address::testing::established_address_2();
        let target_key = key::testing::keypair_1();
        let _public_key = target_key.ref_to();
        let token = address::nam();
        let amount = token::Amount::from_uint(amount, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(&mut tx_env.wl_storage, &token, token::NATIVE_MAX_DECIMAL_PLACES.into()).unwrap();
        tx_env.commit_genesis();

        // Construct a PoW solution like a client would
        let challenge = testnet_pow::Challenge::new(&mut tx_env.wl_storage, &vp_owner, target.clone()).unwrap();
        let solution = challenge.solve();
        let solution_bytes = solution.serialize_to_vec();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Don't call `Solution::invalidate_if_valid` - this is done by the
            // shell's finalize_block.
            let valid = solution.validate(tx::ctx(), address, target.clone()).unwrap();
            assert!(valid);
            // Apply transfer in a transaction
            tx_host_env::token::transfer(tx::ctx(), address, &target, &token, amount).unwrap();
        });

        let mut vp_env = vp_host_env::take();
        // This is set by the protocol when the wrapper tx has a valid PoW
        vp_env.has_valid_pow = true;
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(solution_bytes));
        tx_data.set_code(Code::new(vec![], None));
        tx_data.add_section(Section::Signature(Signature::new(
            vec![tx_data.raw_header_hash()],
            [(0, target_key)].into_iter().collect(),
            None,
        )));
        let keys_changed: BTreeSet<storage::Key> =
        vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
    }

        /// Test that a signed tx that performs arbitrary storage writes or
        /// deletes to the account is accepted.
        #[test]
        fn test_signed_arb_storage_write(
            (vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Init the VP
            let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
            let withdrawal_limit = token::Amount::from_uint(MAX_FREE_DEBIT as u64, 0).unwrap();
            testnet_pow::init_faucet_storage(&mut tx_env.wl_storage, &vp_owner, difficulty, withdrawal_limit.into()).unwrap();

            let keypair = key::testing::keypair_1();
            let public_key = &keypair.ref_to();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let pks_map = AccountPublicKeysMap::from_iter(vec![public_key.clone()]);

            let mut vp_env = vp_host_env::take();
            let mut tx = vp_env.tx.clone();
            tx.set_data(Data::new(vec![]));
            tx.set_code(Code::new(vec![], None));
            tx.add_section(Section::Signature(Signature::new(
                vec![tx.raw_header_hash()],
                pks_map.index_secret_keys(vec![keypair]),
                None,
            )));
            let signed_tx = tx.clone();
            vp_env.tx = signed_tx.clone();
            let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers).unwrap());
        }
    }
}
