use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use anoma::protobuf::types::{Intent, PublicFilter};
use libp2p::PeerId;
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
pub struct IntentMempool(HashMap<IntentId,Intent>);

impl IntentMempool{
    pub fn new() -> Self {
        Self(HashMap::default())
    }

    pub fn put(&mut self, intent: Intent) -> Result<bool> {
        Ok(self.0.insert(IntentId::new(&intent), intent).is_none())
    }

    // TODO This is inefficient.
    pub fn find_map<F: Fn(&Intent, &Intent) -> bool>(
        &mut self,
        intent1: &Intent,
        f: F,
    ) -> bool {
        let id1: &IntentId = &IntentId::new(intent1);
        let res = self.0.iter().find(|(id2, intent2)| {
            if &id1 == id2 {
                false
            } else {
                f(intent1, &intent2)
            }
        });
        res.is_some()
    }
}

#[derive(Debug)]
pub struct FilterMempool(HashMap<PeerId, PublicFilter>);

impl FilterMempool{
    pub fn new() -> Self {
        Self(HashMap::default())
    }

    pub fn put(&mut self, peer_id:PeerId, filter: PublicFilter) -> Result<bool> {
        Ok(self.0.insert(peer_id, filter).is_none())
    }
}
