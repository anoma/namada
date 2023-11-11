//! Default addresses and keys.

#[cfg(any(test, feature = "testing", feature = "benches"))]
pub use dev::{
    addresses, albert_address, albert_keypair, bertha_address, bertha_keypair,
    christel_address, christel_keypair, daewon_address, daewon_keypair,
    ester_address, ester_keypair, keys, tokens, validator_address,
    validator_keypair, validator_keys,
};

#[cfg(any(test, feature = "testing", feature = "benches"))]
mod dev {
    use std::collections::HashMap;

    use namada::ledger::{governance, pgf, pos};
    use namada::types::address::{
        apfel, btc, dot, eth, kartoffel, nam, schnitzel, Address,
    };
    use namada::types::key::*;
    use namada_sdk::wallet::alias::Alias;
    use namada_sdk::wallet::pre_genesis::ValidatorWallet;

    /// Get protocol, eth_bridge, and dkg keys from the validator pre-genesis
    /// wallet
    pub fn validator_keys() -> (common::SecretKey, common::SecretKey) {
        let protocol_key = get_validator_pre_genesis_wallet()
            .store
            .validator_keys
            .protocol_keypair;
        let eth_bridge_key = get_validator_pre_genesis_wallet().eth_hot_key;
        (protocol_key, eth_bridge_key)
    }

    /// The default keys with their aliases.
    pub fn keys() -> HashMap<Alias, common::SecretKey> {
        vec![
            ("albert".into(), albert_keypair()),
            ("bertha".into(), bertha_keypair()),
            ("christel".into(), christel_keypair()),
            ("daewon".into(), daewon_keypair()),
            ("ester".into(), ester_keypair()),
            ("validator".into(), validator_keypair()),
        ]
        .into_iter()
        .collect()
    }

    /// The default tokens with their aliases.
    pub fn tokens() -> HashMap<Address, &'static str> {
        vec![
            (nam(), "NAM"),
            (btc(), "BTC"),
            (eth(), "ETH"),
            (dot(), "DOT"),
            (schnitzel(), "Schnitzel"),
            (apfel(), "Apfel"),
            (kartoffel(), "Kartoffel"),
        ]
        .into_iter()
        .collect()
    }

    /// The default addresses with their aliases.
    pub fn addresses() -> HashMap<Alias, Address> {
        let mut addresses: HashMap<Alias, Address> = vec![
            ("pos".into(), pos::ADDRESS),
            ("pos_slash_pool".into(), pos::SLASH_POOL_ADDRESS),
            ("governance".into(), governance::ADDRESS),
            ("governance".into(), pgf::ADDRESS),
            ("validator".into(), validator_address()),
            ("albert".into(), albert_address()),
            ("bertha".into(), bertha_address()),
            ("christel".into(), christel_address()),
            ("daewon".into(), daewon_address()),
            ("ester".into(), ester_address()),
        ]
        .into_iter()
        .collect();
        let token_addresses = tokens()
            .into_iter()
            .map(|(addr, alias)| (alias.into(), addr));
        addresses.extend(token_addresses);
        addresses
    }

    /// An established user address for testing & development
    pub fn albert_address() -> Address {
        Address::decode("tnam1qxgzrwqn9qny9fzd7xnlrdkf7hhj9ecyx5mv3sgw")
            .expect("The token address decoding shouldn't fail")
    }

    /// An established user address for testing & development
    pub fn bertha_address() -> Address {
        Address::decode("tnam1qyctxtpnkhwaygye0sftkq28zedf774xc5a2m7st")
            .expect("The token address decoding shouldn't fail")
    }

    /// An established user address for testing & development
    pub fn christel_address() -> Address {
        Address::decode("tnam1q99ylwumqqs5r7uwgmyu7e94n07vjeqr4g970na0")
            .expect("The token address decoding shouldn't fail")
    }

    /// An implicit user address for testing & development
    pub fn daewon_address() -> Address {
        // "tnam1qq83g60hemh00tza9naxmrhg7stz7neqhytnj6l0"
        (&daewon_keypair().ref_to()).into()
    }

    /// An implicit user address for testing & development
    pub fn ester_address() -> Address {
        (&ester_keypair().ref_to()).into()
    }

    /// An established validator address for testing & development
    pub fn validator_address() -> Address {
        Address::decode("tnam1qxcc0xpgs72z6s5kx9ayvejs3mftf05jkutgz2cc")
            .expect("The token address decoding shouldn't fail")
    }

    /// Get an unecrypted keypair from the pre-genesis wallet.
    pub fn get_unencrypted_keypair(name: &str) -> common::SecretKey {
        let mut root_dir = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        // Find the project root dir
        while !root_dir.join("rust-toolchain.toml").exists() {
            root_dir.pop();
        }
        let path = root_dir.join("genesis/localnet/src/pre-genesis");
        let wallet = crate::wallet::load(&path).unwrap();
        let sk = match wallet.get_keys().get(name).unwrap().0 {
            namada_sdk::wallet::StoredKeypair::Encrypted(_) => {
                panic!("{}'s keypair should not be encrypted", name)
            }
            namada_sdk::wallet::StoredKeypair::Raw(sk) => sk,
        };
        sk.clone()
    }

    /// Get albert's keypair from the pre-genesis wallet.
    pub fn albert_keypair() -> common::SecretKey {
        get_unencrypted_keypair("albert-key")
    }

    /// Get bertha's keypair from the pre-genesis wallet.
    pub fn bertha_keypair() -> common::SecretKey {
        get_unencrypted_keypair("bertha-key")
    }

    /// Get christel's keypair from the pre-genesis wallet.
    pub fn christel_keypair() -> common::SecretKey {
        get_unencrypted_keypair("christel-key")
    }

    /// Get daewon's keypair from the pre-genesis wallet.
    pub fn daewon_keypair() -> common::SecretKey {
        get_unencrypted_keypair("daewon")
    }

    /// Get ester's keypair from the pre-genesis wallet.
    pub fn ester_keypair() -> common::SecretKey {
        get_unencrypted_keypair("ester")
    }

    /// Get validator pre-genesis wallet
    pub fn get_validator_pre_genesis_wallet() -> ValidatorWallet {
        let mut root_dir = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        // Find the project root dir
        while !root_dir.join("rust-toolchain.toml").exists() {
            root_dir.pop();
        }
        let path =
            root_dir.join("genesis/localnet/src/pre-genesis/validator-0");
        crate::wallet::pre_genesis::load(&path).unwrap()
    }

    /// Get the validator consensus keypair from the wallet.
    pub fn validator_keypair() -> common::SecretKey {
        let mut root_dir = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        // Find the project root dir
        while !root_dir.join("rust-toolchain.toml").exists() {
            root_dir.pop();
        }
        let path =
            root_dir.join("genesis/localnet/src/pre-genesis/validator-0");

        let wallet = crate::wallet::pre_genesis::load(&path).unwrap();
        wallet.consensus_key
    }
}
