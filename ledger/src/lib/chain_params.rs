//! The parameters used for the chain's genesis

use ed25519_dalek::Keypair;
use rand::{prelude::ThreadRng, thread_rng};
use sha2::{Sha256, Digest};

pub struct Genesis {
    pub validators: Vec<Validator>,
}

#[derive(Debug)]
pub struct Validator {
    pub address: String,
    pub keypair: Keypair,
    pub voting_power: u64,
}

pub fn genesis(validator_count: usize) -> Genesis {
    let mut rng: ThreadRng = thread_rng();
    let mut validators = vec![];
    for _ in 0..validator_count {
        let keypair = Keypair::generate(&mut rng);
        let mut hasher = Sha256::new();
        hasher.update(keypair.public.to_bytes());
        let address = format!("{:.40X}", hasher.finalize());
        validators.push(Validator {
            address,
keypair,
            voting_power: 10,
        });
    }
    Genesis { validators }
}
