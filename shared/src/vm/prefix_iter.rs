use std::collections::HashMap;

use crate::ledger::storage;

pub struct PrefixIterators<'iter, DB>
where
    DB: storage::DBIter<'iter>,
{
    index: PrefixIteratorId,
    iterators: HashMap<PrefixIteratorId, DB::PrefixIter>,
}

impl<'iter, DB> PrefixIterators<'iter, DB>
where
    DB: storage::DBIter<'iter>,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, iter: DB::PrefixIter) -> PrefixIteratorId {
        let id = self.index;
        self.iterators.insert(id, iter);
        self.index = id.next_id();
        id
    }

    pub fn next(
        &mut self,
        id: PrefixIteratorId,
    ) -> Option<<DB::PrefixIter as Iterator>::Item> {
        match self.iterators.get_mut(&id) {
            Some(iter) => iter.next(),
            None => None,
        }
    }
}

impl<'iter, DB> Default for PrefixIterators<'iter, DB>
where
    DB: storage::DBIter<'iter>,
{
    fn default() -> Self {
        Self {
            index: PrefixIteratorId::new(0),
            iterators: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrefixIteratorId(u64);

impl PrefixIteratorId {
    pub fn new(id: u64) -> Self {
        PrefixIteratorId(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }

    fn next_id(&self) -> PrefixIteratorId {
        PrefixIteratorId(self.0 + 1)
    }
}
