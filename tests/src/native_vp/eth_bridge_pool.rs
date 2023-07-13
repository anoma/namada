#[cfg(test)]
mod test_bridge_pool_vp {
    use std::path::PathBuf;

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::core::ledger::eth_bridge::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
    use namada::ledger::eth_bridge::{
        wrapped_erc20s, Contracts, EthereumBridgeConfig, UpgradeableContract,
    };
    use namada::ledger::native_vp::ethereum_bridge::bridge_pool_vp::BridgePoolVp;
    use namada::proto::{Code, Data, Section, Signature, Tx};
    use namada::types::address::{nam, wnam};
    use namada::types::chain::ChainId;
    use namada::types::eth_bridge_pool::{
        GasFee, PendingTransfer, TransferToEthereum, TransferToEthereumKind,
    };
    use namada::types::ethereum_events::EthAddress;
    use namada::types::key::{common, ed25519, SecretKey};
    use namada::types::token::Amount;
    use namada::types::transaction::TxType;
    use namada_apps::wallet::defaults::{albert_address, bertha_address};
    use namada_apps::wasm_loader;

    use crate::native_vp::TestNativeVpEnv;
    use crate::tx::{tx_host_env, TestTxEnv};

    const ADD_TRANSFER_WASM: &str = "tx_bridge_pool.wasm";
    const ASSET: EthAddress = EthAddress([1; 20]);
    const BERTHA_WEALTH: u64 = 1_000_000;
    const BERTHA_TOKENS: u64 = 10_000;
    const GAS_FEE: u64 = 100;
    const TOKENS: u64 = 10;

    /// A signing keypair for good old Bertha.
    fn bertha_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            240, 3, 224, 69, 201, 148, 60, 53, 112, 79, 80, 107, 101, 127, 186,
            6, 176, 162, 113, 224, 62, 8, 183, 187, 124, 234, 244, 251, 92, 36,
            119, 243,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// Gets the absolute path to wasm directory
    fn wasm_dir() -> PathBuf {
        let mut current_path = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        while current_path.file_name().unwrap() != "tests" {
            current_path.pop();
        }
        current_path.pop();
        current_path.join("wasm")
    }

    /// Create necessary accounts and balances for the test.
    fn setup_env(tx: Tx) -> TestTxEnv {
        let mut env = TestTxEnv {
            tx,
            ..Default::default()
        };
        let config = EthereumBridgeConfig {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: Default::default(),
            contracts: Contracts {
                native_erc20: wnam(),
                bridge: UpgradeableContract {
                    address: EthAddress([42; 20]),
                    version: Default::default(),
                },
                governance: UpgradeableContract {
                    address: EthAddress([18; 20]),
                    version: Default::default(),
                },
            },
        };
        // initialize Ethereum bridge storage
        config.init_storage(&mut env.wl_storage);
        // initialize Bertha's account
        env.spawn_accounts([&albert_address(), &bertha_address(), &nam()]);
        // enrich Albert
        env.credit_tokens(&albert_address(), &nam(), BERTHA_WEALTH.into());
        // enrich Bertha
        env.credit_tokens(&bertha_address(), &nam(), BERTHA_WEALTH.into());
        // Bertha has ERC20 tokens too.
        let token = wrapped_erc20s::token(&ASSET);
        env.credit_tokens(&bertha_address(), &token, BERTHA_TOKENS.into());
        env
    }

    fn validate_tx(tx: Tx) {
        let env = setup_env(tx);
        tx_host_env::set(env);
        let mut tx_env = tx_host_env::take();
        tx_env.execute_tx().expect("Test failed.");
        let vp_env = TestNativeVpEnv::from_tx_env(tx_env, BRIDGE_POOL_ADDRESS);
        let result = vp_env
            .validate_tx(|ctx| BridgePoolVp { ctx })
            .expect("Test failed");
        assert!(result);
    }

    fn create_tx(transfer: PendingTransfer, keypair: &common::SecretKey) -> Tx {
        let data = transfer.try_to_vec().expect("Test failed");
        let wasm_code =
            wasm_loader::read_wasm_or_exit(wasm_dir(), ADD_TRANSFER_WASM);
        let mut tx = Tx::new(TxType::Raw);
        tx.header.chain_id = ChainId::default();
        tx.set_data(Data::new(data));
        tx.set_code(Code::new(wasm_code));
        tx.add_section(Section::Signature(Signature::new(
            vec![*tx.data_sechash(), *tx.code_sechash()],
            keypair,
        )));
        tx
    }

    #[test]
    fn validate_erc20_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_mint_wnam_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_mint_wnam_different_sender_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                amount: Amount::from(GAS_FEE),
                payer: albert_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }
}
