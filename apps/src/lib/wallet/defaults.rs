//! Default addresses and keys.

#[cfg(any(test, feature = "testing", feature = "benches"))]
pub use dev::{
    addresses, albert_address, albert_keypair, bertha_address, bertha_keypair,
    christel_address, christel_keypair, daewon_address, daewon_keypair,
    ester_address, ester_keypair, keys, validator_address, validator_keypair,
    validator_keys,
};

#[cfg(any(test, feature = "testing", feature = "benches"))]
mod dev {
    use std::collections::HashMap;

    use borsh::BorshDeserialize;
    use namada::ledger::{governance, pgf, pos};
    use namada::types::address::{
        apfel, btc, dot, eth, kartoffel, nam, schnitzel, Address,
    };
    use namada::types::key::dkg_session_keys::DkgKeypair;
    use namada::types::key::*;
    use namada_sdk::wallet::alias::Alias;

    /// N.B. these are the corresponding values from
    /// `genesis/pre-genesis/validator-0/validator-wallet.toml`.
    ///
    /// If that wallet is regenerated, these values must be changed to fix unit
    /// tests.
    pub fn validator_keys() -> (common::SecretKey, common::SecretKey, DkgKeypair)
    {
        // ed25519 bytes
        let bytes: [u8; 33] = [
            0, 217, 87, 83, 250, 179, 159, 135, 229, 194, 14, 202, 177, 38,
            144, 254, 250, 103, 233, 113, 100, 202, 111, 23, 214, 122, 235,
            165, 8, 131, 185, 61, 222,
        ];
        // secp256k1 bytes
        let eth_bridge_key_bytes = [
            1, 38, 59, 91, 81, 119, 89, 252, 48, 195, 171, 237, 19, 144, 123,
            117, 231, 121, 218, 231, 14, 54, 117, 19, 90, 120, 141, 231, 199,
            7, 110, 254, 191,
        ];
        // DkgKeypair
        let dkg_bytes = [
            32, 0, 0, 0, 208, 36, 153, 32, 179, 193, 163, 222, 29, 238, 154,
            53, 181, 71, 213, 162, 59, 130, 225, 93, 57, 20, 161, 254, 52, 1,
            172, 184, 112, 189, 160, 102,
        ];

        (
            BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap(),
            BorshDeserialize::deserialize(&mut eth_bridge_key_bytes.as_ref())
                .unwrap(),
            BorshDeserialize::deserialize(&mut dkg_bytes.as_ref()).unwrap(),
        )
    }

    /// The default keys with their aliases.
    pub fn keys() -> Vec<(Alias, common::SecretKey)> {
        vec![
            ("albert".into(), albert_keypair()),
            ("bertha".into(), bertha_keypair()),
            ("christel".into(), christel_keypair()),
            ("daewon".into(), daewon_keypair()),
            ("ester".into(), ester_keypair()),
            ("validator".into(), validator_keypair()),
        ]
    }

    /// Deprecated function, soon to be deleted. Generates default tokens
    fn tokens() -> HashMap<Address, &'static str> {
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
    pub fn addresses() -> Vec<(Alias, Address)> {
        let mut addresses: Vec<(Alias, Address)> = vec![
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
        ];
        let token_addresses = tokens()
            .into_iter()
            .map(|(addr, alias)| (alias.into(), addr));
        addresses.extend(token_addresses);
        addresses
    }

    /// An established user address for testing & development
    pub fn albert_address() -> Address {
        Address::decode("atest1v4ehgw368ycryv2z8qcnxv3cxgmrgvjpxs6yg333gym5vv2zxepnj334g4rryvj9xucrgve4x3xvr4").expect("The token address decoding shouldn't fail")
    }

    /// An established user address for testing & development
    pub fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw").expect("The token address decoding shouldn't fail")
    }

    /// An established user address for testing & development
    pub fn christel_address() -> Address {
        Address::decode("atest1v4ehgw36x3qng3jzggu5yvpsxgcngv2xgguy2dpkgvu5x33kx3pr2w2zgep5xwfkxscrxs2pj8075p").expect("The token address decoding shouldn't fail")
    }

    /// An implicit user address for testing & development
    pub fn daewon_address() -> Address {
        // "atest1d9khqw36xprrzdpk89rrws69g4z5vd6pgv65gvjrgeqnv3pcg4zns335xymry335gcerqs3etd0xfa"
        (&daewon_keypair().ref_to()).into()
    }

    /// An implicit user address for testing & development
    pub fn ester_address() -> Address {
        (&ester_keypair().ref_to()).into()
    }

    /// An established validator address for testing & development
    pub fn validator_address() -> Address {
        Address::decode("atest1v4ehgw36ggcnsdee8qerswph8y6ry3p5xgunvve3xaqngd3kxc6nqwz9gseyydzzg5unys3ht2n48q").expect("The token address decoding shouldn't fail")
    }

    /// N.B. this is the corresponding value from
    /// `genesis/pre-genesis/wallet.toml`.
    pub fn albert_keypair() -> common::SecretKey {
        let bytes = [
            131, 49, 140, 204, 234, 198, 192, 138, 1, 119, 102, 120, 64, 180,
            185, 63, 14, 69, 94, 69, 212, 195, 140, 40, 183, 59, 143, 132, 98,
            251, 245, 72,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// N.B. this is the corresponding value from
    /// `genesis/pre-genesis/wallet.toml`.
    pub fn bertha_keypair() -> common::SecretKey {
        let bytes = [
            115, 237, 97, 129, 119, 32, 210, 119, 132, 231, 169, 188, 164, 166,
            6, 104, 215, 99, 166, 247, 236, 172, 45, 69, 237, 31, 36, 26, 165,
            197, 158, 153,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// N.B. this is the corresponding value from
    /// `genesis/pre-genesis/wallet.toml`.
    pub fn christel_keypair() -> common::SecretKey {
        let bytes = [
            54, 37, 185, 57, 165, 142, 246, 4, 2, 215, 207, 143, 192, 66, 80,
            2, 108, 193, 186, 144, 204, 48, 40, 175, 28, 230, 178, 43, 232, 87,
            255, 199,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// N.B. this is the corresponding value from
    /// `genesis/pre-genesis/wallet.toml`.
    pub fn daewon_keypair() -> common::SecretKey {
        let bytes = [
            209, 158, 34, 108, 14, 125, 18, 61, 121, 245, 144, 139, 89, 72,
            212, 196, 97, 182, 106, 95, 138, 169, 86, 0, 194, 139, 85, 171,
            111, 93, 199, 114,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// N.B. this is the corresponding value from
    /// `genesis/pre-genesis/wallet.toml`.
    pub fn ester_keypair() -> common::SecretKey {
        let bytes = [
            54, 144, 147, 226, 3, 93, 132, 247, 42, 126, 90, 23, 200, 155, 122,
            147, 139, 93, 8, 204, 135, 178, 40, 152, 5, 227, 175, 204, 102,
            239, 154, 66,
        ];
        let sk = secp256k1::SecretKey::try_from_slice(&bytes).unwrap();
        sk.try_to_sk().unwrap()
    }

    /// N.B. this is the consensus key from
    /// `genesis/pre-genesis/validator-0/validator-wallet.toml`.
    /// If that wallet is regenerated, this value must be changed to fix unit
    /// tests.
    pub fn validator_keypair() -> common::SecretKey {
        let bytes = [
            194, 41, 223, 103, 103, 178, 152, 145, 161, 212, 82, 133, 69, 13,
            133, 136, 238, 11, 198, 182, 29, 41, 75, 249, 88, 0, 28, 215, 217,
            63, 234, 78,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }
}
