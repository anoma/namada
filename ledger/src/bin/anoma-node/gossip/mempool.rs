use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;

use anoma::protobuf::types::Intent;
pub use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentId(pub Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for IntentId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl IntentId {
    pub fn new(intent: &Intent) -> Self {
        let mut s = DefaultHasher::new();
        intent.hash(&mut s);
        IntentId::from(s.finish().to_string())
    }
}

#[derive(Debug)]
pub struct Mempool {
    intents: HashMap<IntentId, Intent>,
    history: Vec<IntentId>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            intents: HashMap::default(),
            history: Vec::new(),
        }
    }

    pub fn put(&mut self, id: &IntentId, intent: Intent) {
        let already_exists_intent = self.intents.insert(id.clone(), intent);
        if already_exists_intent.is_none() {
            self.history.push(id.clone());
        }
    }
}
