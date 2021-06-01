pub mod tx;
pub mod vp;

#[cfg(test)]
mod tests {
    use anoma_shared::types::Key;
    use anoma_vm_env::tx_prelude::BorshSerialize;

    use super::tx::*;
    use super::vp::*;

    /// An example how to write a tx host environment integration test
    #[test]
    fn test_tx_host_env() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        let value = "test".to_string();
        tx_host_env::write(key, value.clone());

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(Some(value), read_value);
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
        // TODO check in the wasm source code to tests resources
        let vp_template = std::fs::read("../vps/vp_template/vp.wasm")
            .expect("cannot load user VP");
        let input_data = vec![];
        let result = vp_host_env::eval(vp_template, input_data);
        assert!(result);
    }
}
