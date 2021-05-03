use std::collections::HashMap;

use crate::shell::storage::DBIter;

pub struct PrefixIterators<'iter, DB>
where
    DB: DBIter<'iter>,
{
    index: PrefixIteratorId,
    iterators: HashMap<PrefixIteratorId, <DB as DBIter<'iter>>::PrefixIter>,
}

impl<'iter, DB> PrefixIterators<'iter, DB>
where
    DB: DBIter<'iter>,
{
    pub fn new() -> Self {
        PrefixIterators {
            index: PrefixIteratorId::new(0),
            iterators: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        iter: <DB as DBIter<'iter>>::PrefixIter,
    ) -> PrefixIteratorId {
        let id = self.index;
        self.iterators.insert(id, iter);
        self.index = id.next_id();
        id
    }

    pub fn next(
        &mut self,
        id: PrefixIteratorId,
    ) -> Option<<<DB as DBIter<'iter>>::PrefixIter as Iterator>::Item> {
        match self.iterators.get_mut(&id) {
            Some(iter) => iter.next(),
            None => None,
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
