//! Implicit account VP. All implicit accounts share this same VP.
//!
//! This VP currently provides a signature verification against a public key for
//! sending tokens (receiving tokens is permissive).
//!
//! It allows to reveal a PK, as long as its address matches with the address
//! that can be derived from the PK.
//!
//! It allows to bond, unbond and withdraw tokens to and from PoS system with a
//! valid signature.
//!
//! Any other storage key changes are allowed only with a valid signature.

use namada_vp_prelude::storage::KeySeg;
use namada_vp_prelude::*;
use once_cell::unsync::Lazy;

enum KeyType<'a> {
    /// Public key - written once revealed
    Pk(&'a Address),
    Token(&'a Address),
    PoS,
    GovernanceVote(&'a Address),
    Unknown,
}

impl<'a> From<&'a storage::Key> for KeyType<'a> {
    fn from(key: &'a storage::Key) -> KeyType<'a> {
        if let Some(address) = key::is_pk_key(key) {
            Self::Pk(address)
        } else if let Some(address) = token::is_any_token_balance_key(key) {
            Self::Token(address)
        } else if let Some((_, address)) =
            token::is_any_multitoken_balance_key(key)
        {
            Self::Token(address)
        } else if proof_of_stake::is_pos_key(key) {
            Self::PoS
        } else if gov_storage::is_vote_key(key) {
            let voter_address = gov_storage::get_voter_address(key);
            if let Some(address) = voter_address {
                Self::GovernanceVote(address)
            } else {
                Self::Unknown
            }
        } else {
            Self::Unknown
        }
    }
}

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Vec<u8>,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_user called with user addr: {}, key_changed: {:?}, verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    let signed_tx_data =
        Lazy::new(|| SignedTxData::try_from_slice(&tx_data[..]));

    let valid_sig = Lazy::new(|| match &*signed_tx_data {
        Ok(signed_tx_data) => {
            let pk = key::get(ctx, &addr);
            match pk {
                Ok(Some(pk)) => {
                    matches!(
                        ctx.verify_tx_signature(&pk, &signed_tx_data.sig),
                        Ok(true)
                    )
                }
                _ => false,
            }
        }
        _ => false,
    });

    if !is_valid_tx(ctx, &tx_data)? {
        return reject();
    }

    for key in keys_changed.iter() {
        let key_type: KeyType = key.into();
        let is_valid = match key_type {
            KeyType::Pk(owner) => {
                if owner == &addr {
                    if ctx.has_key_pre(key)? {
                        // If the PK is already reveal, reject the tx
                        return reject();
                    }
                    let post: Option<key::common::PublicKey> =
                        ctx.read_post(key)?;
                    match post {
                        Some(pk) => {
                            let addr_from_pk: Address = (&pk).into();
                            // Check that address matches with the address
                            // derived from the PK
                            if addr_from_pk != addr {
                                return reject();
                            }
                        }
                        None => {
                            // Revealed PK cannot be deleted
                            return reject();
                        }
                    }
                }
                true
            }
            KeyType::Token(owner) => {
                if owner == &addr {
                    let pre: token::Amount =
                        ctx.read_pre(key)?.unwrap_or_default();
                    let post: token::Amount =
                        ctx.read_post(key)?.unwrap_or_default();
                    let change = post.change() - pre.change();
                    // debit has to signed, credit doesn't
                    let valid = change >= 0 || *valid_sig;
                    debug_log!(
                        "token key: {}, change: {}, valid_sig: {}, valid \
                         modification: {}",
                        key,
                        change,
                        *valid_sig,
                        valid
                    );
                    valid
                } else {
                    debug_log!(
                        "This address ({}) is not of owner ({}) of token key: \
                         {}",
                        addr,
                        owner,
                        key
                    );
                    // If this is not the owner, allow any change
                    true
                }
            }
            KeyType::PoS => {
                // Allow the account to be used in PoS
                let bond_id = proof_of_stake::is_bond_key(key)
                    .or_else(|| proof_of_stake::is_unbond_key(key));
                let valid = match bond_id {
                    Some(bond_id) => {
                        // Bonds and unbonds changes for this address
                        // must be signed
                        bond_id.source != addr || *valid_sig
                    }
                    None => {
                        // Any other PoS changes are allowed without signature
                        true
                    }
                };
                debug_log!(
                    "PoS key {} {}",
                    key,
                    if valid { "accepted" } else { "rejected" }
                );
                valid
            }
            KeyType::GovernanceVote(voter) => {
                if voter == &addr {
                    *valid_sig
                } else {
                    true
                }
            }
            KeyType::Unknown => {
                if key.segments.get(0) == Some(&addr.to_db_key()) {
                    // Unknown changes to this address space require a valid
                    // signature
                    *valid_sig
                } else {
                    // Unknown changes anywhere else are permitted
                    true
                }
            }
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
    // Use this as `#[test]` annotation to enable logging
    use namada_tests::log::test;
    use namada_tests::tx::{self, tx_host_env, TestTxEnv};
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::key::RefTo;
    use proptest::prelude::*;
    use storage::testing::arb_account_storage_key_no_vp;

    use super::*;

    const VP_ALWAYS_TRUE_WASM: &str =
        "../../wasm_for_tests/vp_always_true.wasm";

    /// Test that no-op transaction (i.e. no storage modifications) accepted.
    #[test]
    fn test_no_op_transaction() {
        let tx_data: Vec<u8> = vec![];
        let addr: Address = address::testing::established_address_1();
        let keys_changed: BTreeSet<storage::Key> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = BTreeSet::default();

        // The VP env must be initialized before calling `validate_tx`
        vp_host_env::init();

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).unwrap()
        );
    }

    /// Test that a PK can be revealed when it's not revealed and cannot be
    /// revealed anymore once it's already revealed.
    #[test]
    fn test_can_reveal_pk() {
        // The SK to be used for the implicit account
        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let addr: Address = (&public_key).into();

        // Initialize a tx environment
        let tx_env = TestTxEnv::default();

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Apply reveal_pk in a transaction
            tx_host_env::key::reveal_pk(tx::ctx(), &public_key).unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            validate_tx(&CTX, tx_data, addr.clone(), keys_changed, verifiers)
                .unwrap(),
            "Revealing PK that's not yet revealed and is matching the address \
             must be accepted"
        );

        // Commit the transaction and create another tx_env
        let vp_env = vp_host_env::take();
        tx_host_env::set_from_vp_env(vp_env);
        tx_host_env::commit_tx_and_block();
        let tx_env = tx_host_env::take();

        // Try to reveal it again
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Apply reveal_pk in a transaction
            tx_host_env::key::reveal_pk(tx::ctx(), &public_key).unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            !validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).unwrap(),
            "Revealing PK that's already revealed should be rejected"
        );
    }

    /// Test that a revealed PK that doesn't correspond to the account's address
    /// is rejected.
    #[test]
    fn test_reveal_wrong_pk_rejected() {
        // The SK to be used for the implicit account
        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let addr: Address = (&public_key).into();

        // Another SK to be revealed for the address above (not matching it)
        let mismatched_sk = key::testing::keypair_2();
        let mismatched_pk = mismatched_sk.ref_to();

        // Initialize a tx environment
        let tx_env = TestTxEnv::default();

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Do the same as reveal_pk, but with the wrong key
            let key = namada_tx_prelude::key::pk_key(&addr);
            tx_host_env::ctx().write(&key, &mismatched_pk).unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            !validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).unwrap(),
            "Mismatching PK must be rejected"
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let source = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from(10_098_123);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, None, amount);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                address,
                &token,
                None,
                amount,
                &None,
                &None,
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a debit transfer without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_transfer_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from(10_098_123);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, None, amount);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                None,
                amount,
                &None,
                &None,
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            !validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a debit transfer with a valid signature is accepted.
    #[test]
    fn test_signed_debit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from(10_098_123);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, None, amount);

        tx_env.write_public_key(&vp_owner, &public_key);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                None,
                amount,
                &None,
                &None,
            )
            .unwrap();
        });

        let mut vp_env = vp_host_env::take();
        let tx = vp_env.tx.clone();
        let signed_tx = tx.sign(&secret_key);
        let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
        vp_env.tx = signed_tx;
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a transfer on with accounts other than self is accepted.
    #[test]
    fn test_transfer_between_other_parties_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let source = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::nam();
        let amount = token::Amount::from(10_098_123);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&source, &token, None, amount);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            tx::ctx().insert_verifier(address).unwrap();
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                &target,
                &token,
                None,
                amount,
                &None,
                &None,
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Generates a keypair, derive an implicit address from it and generate
    /// a storage key inside its storage.
    fn arb_account_storage_subspace_key()
    -> impl Strategy<Value = (key::common::SecretKey, Address, Key)> {
        // Generate a keypair
        key::testing::arb_common_keypair().prop_flat_map(|sk| {
            let pk = sk.ref_to();
            let addr: Address = (&pk).into();
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            let storage_key = arb_account_storage_key_no_vp(addr.clone());
            (Just(sk), Just(addr), storage_key)
        })
    }

    proptest! {
        /// Test that an unsigned tx that performs arbitrary storage writes or
        /// deletes to  the account is rejected.
        #[test]
        fn test_unsigned_arb_storage_write_rejected(
            (_sk, vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let vp_env = vp_host_env::take();
            let tx_data: Vec<u8> = vec![];
            let keys_changed: BTreeSet<storage::Key> =
                vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(!validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
        }
    }

    proptest! {
        /// Test that a signed tx that performs arbitrary storage writes or
        /// deletes to the account is accepted.
        #[test]
        fn test_signed_arb_storage_write(
            (secret_key, vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            let public_key = secret_key.ref_to();
            tx_env.write_public_key(&vp_owner, &public_key);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let mut vp_env = vp_host_env::take();
            let tx = vp_env.tx.clone();
            let signed_tx = tx.sign(&secret_key);
            let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
            vp_env.tx = signed_tx;
            let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
        }
    }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, &vp_code)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            !validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a tx is rejected if not whitelisted
    #[test]
    fn test_tx_not_whitelisted_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        let vp_hash = sha256(&vp_code);
        tx_env.init_parameters(
            None,
            Some(vec![vp_hash.to_string()]),
            Some(vec!["some_hash".to_string()]),
        );

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        tx_env.write_public_key(&vp_owner, &public_key);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, &vp_code)
                .unwrap();
        });

        let mut vp_env = vp_host_env::take();
        let tx = vp_env.tx.clone();
        let signed_tx = tx.sign(&secret_key);
        let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
        vp_env.tx = signed_tx;
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            !validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    #[test]
    fn test_tx_whitelisted_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        // hardcoded hash of VP_ALWAYS_TRUE_WASM
        tx_env.init_parameters(None, None, Some(vec!["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string().to_lowercase()]));

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        tx_env.write_public_key(&vp_owner, &public_key);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, &vp_code)
                .unwrap();
        });

        let mut vp_env = vp_host_env::take();
        let tx = vp_env.tx.clone();
        let signed_tx = tx.sign(&secret_key);
        let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
        vp_env.tx = signed_tx;
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }
}
