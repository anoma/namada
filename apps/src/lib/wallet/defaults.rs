//! Default addresses and keys.

#[cfg(any(test, feature = "testing"))]
pub use dev::{
    addresses, albert_address, albert_keypair, bertha_address, bertha_keypair,
    christel_address, christel_keypair, daewon_address, daewon_keypair,
    ester_address, ester_keypair, keys, validator_address, validator_keypair,
    validator_keys,
};

#[cfg(any(test, feature = "testing"))]
mod dev {
    use std::collections::HashMap;

    use borsh::BorshDeserialize;
    use namada::ledger::wallet::alias::Alias;
    use namada::ledger::{governance, pos};
    use namada::types::address::{
        apfel, btc, dot, eth, kartoffel, nam, schnitzel, Address,
    };
    use namada::types::key::dkg_session_keys::DkgKeypair;
    use namada::types::key::*;

    /// Generate a new protocol signing keypair, eth hot key and DKG session
    /// keypair
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

    pub fn albert_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            115, 191, 32, 247, 18, 101, 5, 106, 26, 203, 48, 145, 39, 41, 41,
            196, 252, 190, 245, 222, 96, 209, 34, 36, 40, 214, 169, 156, 235,
            78, 188, 33,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    pub fn bertha_keypair() -> common::SecretKey {
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

    pub fn christel_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            65, 198, 96, 145, 237, 227, 84, 182, 107, 55, 209, 235, 115, 105,
            71, 190, 234, 137, 176, 188, 181, 174, 183, 49, 131, 230, 46, 39,
            70, 20, 130, 253,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    pub fn daewon_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            235, 250, 15, 1, 145, 250, 172, 218, 247, 27, 63, 212, 60, 47, 164,
            57, 187, 156, 182, 144, 107, 174, 38, 81, 37, 40, 19, 142, 68, 135,
            57, 50,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    pub fn ester_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::secp256k1::gen_keypair`]
        let bytes = [
            54, 144, 147, 226, 3, 93, 132, 247, 42, 126, 90, 23, 200, 155, 122,
            147, 139, 93, 8, 204, 135, 178, 40, 152, 5, 227, 175, 204, 102,
            239, 154, 66,
        ];
        let sk = secp256k1::SecretKey::try_from_slice(&bytes).unwrap();
        sk.try_to_sk().unwrap()
    }

    pub fn validator_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            80, 110, 166, 33, 135, 254, 34, 138, 253, 44, 214, 71, 50, 230, 39,
            246, 124, 201, 68, 138, 194, 251, 192, 36, 55, 160, 211, 68, 65,
            189, 121, 217,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }
}
