use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
pub use std::hash::{Hash, Hasher};

use anoma::protobuf::types::Intent;

#[derive(Debug)]
pub enum MempoolError {}

type Result<T> = std::result::Result<T, MempoolError>;

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
        let id = IntentId::new(&intent);
        let already_exists_intent = self.intents.insert(id.clone(), intent);
        Ok(already_exists_intent.is_none())
    }

    // XXX TODO This is inefficient.
    pub fn find_map<O>(
        &mut self,
        intent1: &Intent,
        f: &dyn Fn(&Intent, &Intent) -> Option<O>,
    ) -> Option<O> {
        let id1: IntentId = IntentId::new(intent1);
        println!("mempool trying to find match for {:?}", id1);
        self.intents.iter().find_map(|(id2, intent2)| {
            println!("matching {:?} & {:?}", id1, id2);
            if &id1 == id2 {
                println!("matching same id {:?}", id1);
                None
            } else {
                println!("matching2 {:?} & {:?}", id1, id2);
                f(intent1, &intent2)
            }
        })
    }
}
