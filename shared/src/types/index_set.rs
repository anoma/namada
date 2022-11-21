//! Set data structure optimized to store [`usize`] values.

use std::collections::BTreeMap;

/// The storage unit for the bits in an [`IndexSet`].
#[allow(dead_code)]
type IndexSetStorage = u128;

/// The width, in bytes, of the storage unit for an [`IndexSet`].
#[allow(dead_code)]
const INDEX_SET_STORAGE_WIDTH: usize = std::mem::size_of::<IndexSetStorage>();

/// Set data structure optimized to store [`usize`] values.
#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
pub struct IndexSet {
    /// Map of indices to bit vectors, containing the actual boolean
    /// values to be asserted.
    ///
    /// If the bit `B` is set, at the bit vector with index `S`, then
    /// the index `INDEX_SET_STORAGE_WIDTH * S + B` is in the set.
    bit_sets: BTreeMap<usize, IndexSetStorage>,
}

impl IndexSet {
    /// Add a new index to this [`IndexSet`].
    #[allow(dead_code)]
    pub fn insert(&mut self, index: usize) {
        // theset let exprs will get optimized into a single op,
        // since they're ordered in sequence, which is nice
        let map_index = index / INDEX_SET_STORAGE_WIDTH;
        let bit_set_index = index % INDEX_SET_STORAGE_WIDTH;

        let set = self.bit_sets.entry(map_index).or_insert(0);
        *set |= 1 << bit_set_index;
    }

    /// Return an iterator over the transaction indices in
    /// this [`IndexSet`], in ascending order.
    #[allow(dead_code)]
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.bit_sets.iter().flat_map(|(&map_index, &set)| {
            (0..INDEX_SET_STORAGE_WIDTH).into_iter().flat_map(
                move |bit_set_index| {
                    let is_bit_set = (set & (1 << bit_set_index)) != 0;
                    is_bit_set.then(|| {
                        map_index as usize * INDEX_SET_STORAGE_WIDTH
                            + bit_set_index as usize
                    })
                },
            )
        })
    }

    /// Merge two [`IndexSet`] instances.
    ///
    /// Corresponds to a mutating union set operation,
    /// between `self` and `other`.
    #[allow(dead_code)]
    #[inline]
    pub fn merge(&mut self, other: IndexSet) {
        for (&map_index, &other_set) in other.bit_sets.iter() {
            let set = self.bit_sets.entry(map_index).or_insert(0);
            *set |= other_set;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test [`IndexSet`] index insert ops.
    #[test]
    fn test_index_set_insert() {
        let mut set = IndexSet::default();
        let mut indices = vec![1, 4, 6, 3, 1, 100, 123, 12, 3];

        // insert some elements into the set
        for i in indices.iter().copied() {
            set.insert(i);
        }

        // check if the set contains the same elements
        // we inserted, in ascending order
        indices.sort_unstable();
        indices.dedup();

        let set_indices: Vec<_> = set.iter().collect();
        assert_eq!(indices, set_indices);

        // check that the no. of storage elements used is lower
        // than the max no. of bitsets we would otherwise need
        let storage_elements_max =
            indices[indices.len() - 1] / INDEX_SET_STORAGE_WIDTH;
        assert!(set.bit_sets.len() <= storage_elements_max);
    }
}
