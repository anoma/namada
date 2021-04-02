use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use anoma::protobuf::types::Intent;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {}

type Result<T> = std::result::Result<T, Error>;

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
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            intents: HashMap::default(),
        }
    }

    pub fn put(&mut self, intent: Intent) -> Result<bool> {
        let already_exists_intent =
            self.intents.insert(IntentId::new(&intent), intent);
        Ok(already_exists_intent.is_none())
    }

    // TODO This is inefficient.
    pub fn find_map(
        &mut self,
        intent1: &Intent,
        f: &dyn Fn(&Intent, &Intent) -> bool,
    ) -> bool {
        let id1: &IntentId = &IntentId::new(intent1);
        let res = self.intents.iter().find(|(id2, intent2)| {
            if &id1 == id2 {
                false
            } else {
                f(intent1, &intent2)
            }
        });
        res.is_some()
    }
}
