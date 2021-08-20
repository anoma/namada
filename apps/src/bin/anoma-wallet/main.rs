use std::collections::{HashMap, HashSet};

use anoma::types::{
    address::Address,
    key::ed25519::{Keypair, PublicKey},
};

pub type Alias = String;

pub struct Store {
    pub keys: HashMap<Alias, Keypair>,
    pub addresses: HashSet<Address>,
}

impl Store {
    pub fn fetch_by_alias(&self, alias: Alias) -> Option<&Keypair> {
        self.keys.get(&alias)
    }

    pub fn fetch_by_public_key(
        &self,
        public_key: PublicKey,
    ) -> Option<&Keypair> {
        self.keys
            .values()
            .find(|keypair| public_key.is_same_key(keypair.public))
    }

    pub fn insert_keypair(
        &mut self,
        alias: Alias,
        keypair: Keypair,
    ) -> Option<Keypair> {
        self.keys.insert(alias, keypair)
    }
}

fn generate_keypair(alias: Alias, store: &mut Store) -> Option<Keypair> {
    use rand::rngs::OsRng;

    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    store.insert_keypair(alias, keypair)
}

pub fn main() {}
