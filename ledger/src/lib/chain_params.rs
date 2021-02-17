//! The parameters used for the chain's genesis

use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::{prelude::ThreadRng, thread_rng};
use sha2::{Sha256, Digest};

pub struct Genesis {
    pub validators: Vec<Validator>,
}

#[derive(Debug)]
pub struct Validator {
    pub address: String,
    pub pk: PublicKey,
    // TODO only in "dev"
    pub sk: SecretKey,
    pub voting_power: u64,
}

pub fn genesis(validator_count: usize) -> Genesis {
    let mut rng: ThreadRng = thread_rng();
    let mut validators = vec![];
    for _ in 0..validator_count {
        let keypair = Keypair::generate(&mut rng);
        let pk = keypair.public;
        let sk = keypair.secret;
        let mut hasher = Sha256::new();
        hasher.update(pk.to_bytes());
        // let address = hasher.finalize();
        let address = "TODO";
        validators.push(Validator {
            address,
            pk,
            sk,
            voting_power: 10,
        });
    }
    Genesis { validators }
}
