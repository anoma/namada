pub mod tx;
pub mod vp;

#[cfg(test)]
mod tests {

    use anoma_shared::types::{address, Key};
    use anoma_vm_env::tx_prelude::{BorshSerialize, KeyValIterator};
    use itertools::Itertools;

    use super::tx::*;
    use super::vp::*;

    #[test]
    fn test_tx_read_write() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(
            None, read_value,
            "Trying to read a key that doesn't exists shouldn't find any value"
        );

        // Write some value
        let value = "test".repeat(4);
        tx_host_env::write(key, value.clone());

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(
            Some(value),
            read_value,
            "After a value has been written, we should get back the same \
             value when we read it"
        );

        let value = vec![1_u8; 1000];
        tx_host_env::write(key, value.clone());
        let read_value: Option<Vec<u8>> = tx_host_env::read(key);
        assert_eq!(
            Some(value),
            read_value,
            "Writing to an existing key should override the previous value"
        );
    }

    #[test]
    fn test_tx_has_key() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        assert!(
            !tx_host_env::has_key(key),
            "Before a key-value is written, its key shouldn't be found"
        );

        // Write some value
        let value = "test".to_string();
        tx_host_env::write(key, value);

        assert!(
            tx_host_env::has_key(key),
            "After a key-value has been written, its key should be found"
        );
    }

    #[test]
    fn test_tx_delete() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Trying to delete a key that doesn't exists should be a no-op
        let key = "key";
        tx_host_env::delete(key);

        let value = "test".to_string();
        tx_host_env::write(key, value);
        assert!(
            tx_host_env::has_key(key),
            "After a key-value has been written, its key should be found"
        );

        // Then delete it
        tx_host_env::delete(key);

        assert!(
            !tx_host_env::has_key(key),
            "After a key has been deleted, its key shouldn't be found"
        );
    }

    #[test]
    #[ignore = "There's a bug in iter_prefix because of its allocations, which \
                override our result pointer. We'll probably need to use \
                registers for this one"]
    fn test_tx_iter() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let iter: KeyValIterator<Vec<u8>> = tx_host_env::iter_prefix("empty");
        assert_eq!(
            iter.count(),
            0,
            "Trying to iter a prefix that doesn't have any matching keys \
             should yield an empty iterator."
        );

        // Write some values directly into the storage first
        let prefix = "key";
        for i in 0..10_i32 {
            let key = Key::parse(format!("{}/{}", prefix, i)).unwrap();
            let value = i.try_to_vec().unwrap();
            env.storage.write(&key, value).unwrap();
            env.storage.commit().unwrap();
        }

        // Then try to iterate over their prefix
        let iter: KeyValIterator<i32> = tx_host_env::iter_prefix(prefix);
        let expected = (0..10).map(|i| (format!("{}/{}", prefix, i), i));
        itertools::assert_equal(iter.sorted(), expected.sorted());
    }

    #[test]
    fn test_tx_insert_verifier() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        assert!(env.verifiers.is_empty(), "pre-condition");
        let verifier = address::testing::established_address_1();
        tx_host_env::insert_verifier(verifier.clone());
        assert!(
            env.verifiers.contains(&verifier),
            "The verifier should have been inserted"
        );
        assert_eq!(
            env.verifiers.len(),
            1,
            "There should be only one verifier inserted"
        );
    }

    #[test]
    #[should_panic]
    fn test_tx_init_account_with_invalid_vp() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let code = vec![];
        tx_host_env::init_account(code);
    }

    #[test]
    fn test_tx_init_account_with_valid_vp() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let code = std::fs::read("res/wasm/vp_template.wasm")
            .expect("cannot load user VP");
        tx_host_env::init_account(code);
    }

    #[test]
    fn test_tx_get_metadata() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        assert_eq!(tx_host_env::get_chain_id(), env.storage.get_chain_id().0);
        assert_eq!(
            tx_host_env::get_block_height(),
            env.storage.get_block_height().0
        );
        assert_eq!(
            tx_host_env::get_block_hash(),
            env.storage.get_block_hash().0
        );
    }

    /// An example how to write a VP host environment integration test
    #[test]
    fn test_vp_host_env() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        // We can add some data to the environment
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        let value = "test".to_string();
        let value_raw = value.try_to_vec().unwrap();
        env.write_log.write(&key, value_raw);

        let read_pre_value: Option<String> = vp_host_env::read_pre(key_raw);
        assert_eq!(None, read_pre_value);
        let read_post_value: Option<String> = vp_host_env::read_post(key_raw);
        assert_eq!(Some(value), read_post_value);
    }

    #[test]
    fn test_vp_eval() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        // evaluating without any code should fail
        let empty_code = vec![];
        let input_data = vec![];
        let result = vp_host_env::eval(empty_code, input_data);
        assert!(!result);

        // evaluating the VP template which always returns `true` should pass
        let vp_template = std::fs::read("res/wasm/vp_template.wasm")
            .expect("cannot load user VP");
        let input_data = vec![];
        let result = vp_host_env::eval(vp_template, input_data);
        assert!(result);
    }
}
