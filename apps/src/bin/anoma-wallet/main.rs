use std::collections::{HashMap, HashSet};

use anoma::types::key::ed25519::{Keypair, PublicKey};
use anoma::types::address::Address;

pub type Alias = String;

pub struct Store {
    pub keys: HashMap<Alias, Keypair>,
    pub addresses: HashSet<Address>
}

impl Store {
    pub fn fetch_by_alias(&self, alias: Alias) -> Option<&Keypair> {
        self.keys.get(&alias)
    }

    pub fn fetch_by_public_key(&self, public_key: PublicKey) -> Option<&Keypair> {
        self.keys.values().find(|keypair| {
           public_key.is_same_key(keypair.public) 
        })
    }
}

pub fn main() {
}