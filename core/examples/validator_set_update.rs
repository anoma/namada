//! Print out the raw bytes for an example validator set update that should be
//! signed by Namada validators. The Ethereum smart contracts should be
//! independently constructing these raw bytes and checking provided signatures
//! over it.

use namada_core::proto::Signable;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::key::{common, secp256k1, SecretKey, SigScheme};
use namada_core::types::storage::Epoch;
use namada_core::types::vote_extensions::validator_set_update::{
    self, EthAddrBook, SerializeWithAbiEncode, VotingPowersMap,
};
use namada_core::types::{address, token};

fn main() {
    // the validator_addr doesn't affect the final bytes to be signed, so this
    // can be any arbitrary address
    let validator_addr = address::testing::established_address_1();

    // the final bytes to be signed is a function of `voting_powers` +
    // `signing_epoch`
    // these values can be tweaked to test out different raw bytes
    let voting_powers = VotingPowersMap::from([
        (
            EthAddrBook {
                hot_key_addr: EthAddress([1; 20]),
                cold_key_addr: EthAddress([2; 20]),
            },
            token::Amount::from(100),
        ),
        (
            EthAddrBook {
                hot_key_addr: EthAddress([3; 20]),
                cold_key_addr: EthAddress([4; 20]),
            },
            token::Amount::from(200),
        ),
    ]);
    let signing_epoch = Epoch(0);
    let signing_key = gen_secp256k1_keypair();

    let vext = validator_set_update::Vext {
        voting_powers,
        validator_addr,
        signing_epoch,
    };
    let signable = SerializeWithAbiEncode::as_signable(&vext);
    println!(
        "Raw bytes as lossy UTF-8: {}",
        String::from_utf8_lossy(&signable)
    );
    println!("Raw bytes: {:?}", &signable);
    println!(
        "Raw bytes (hex-encoded): {}",
        data_encoding::HEXLOWER.encode(&signable)
    );

    let common::SecretKey::Secp256k1(secp256k1_key) = signing_key.clone() else { unreachable!() };
    println!("secp256k1 key: {:#?}", secp256k1_key);

    let signed = vext.sign(&signing_key);
    let common::Signature::Secp256k1(secp256k1_sig) = signed.sig else { unreachable!() };
    println!("secp256k1 signature: {:#?}", secp256k1_sig);
}

fn gen_secp256k1_keypair() -> common::SecretKey {
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    let mut rng: ThreadRng = thread_rng();
    secp256k1::SigScheme::generate(&mut rng)
        .try_to_sk()
        .unwrap()
}
