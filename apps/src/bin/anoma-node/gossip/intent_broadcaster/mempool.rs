use std::collections::HashMap;

use anoma::protobuf::types::Intent;
use anoma::protobuf::IntentId;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct IntentMempool(HashMap<IntentId, Intent>);

impl IntentMempool {
    pub fn new() -> Self {
        Self(HashMap::default())
    }

    pub fn put(&mut self, intent: Intent) -> Result<bool> {
        Ok(self.0.insert(IntentId::new(&intent), intent).is_none())
    }

    pub fn remove(&mut self, intent_id: &IntentId) -> bool {
        self.0.remove(intent_id).is_some()
    }

    // TODO This is inefficient.
    pub fn find_map<F: Fn(&IntentId, &Intent, &IntentId, &Intent) -> bool>(
        &mut self,
        intent1: &Intent,
        f: F,
    ) -> bool {
        let id1: &IntentId = &IntentId::new(intent1);
        let res = self.0.iter().find(|(id2, intent2)| {
            if &id1 == id2 {
                false
            } else {
                f(&id1, intent1, &id2, &intent2)
            }
        });
        res.is_some()
    }
}
