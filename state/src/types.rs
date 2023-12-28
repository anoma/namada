//! The key and values that may be persisted in a DB.

/// A key-value pair as raw bytes
pub type KVBytes = (Box<[u8]>, Box<[u8]>);

/// Storage prefix iterator generic wrapper type.
pub struct PrefixIterator<I> {
    /// The concrete iterator implementation
    pub iter: I,
    /// The prefix that is being iterated. This prefix will be stripped from
    /// the returned matched keys.
    pub stripped_prefix: String,
}

impl<I> PrefixIterator<I> {
    /// Initialize a new prefix iterator
    pub fn new<E>(iter: I, stripped_prefix: String) -> Self
    where
        E: std::error::Error,
        I: Iterator<Item = std::result::Result<KVBytes, E>>,
    {
        PrefixIterator {
            iter,
            stripped_prefix,
        }
    }
}

impl<I> std::fmt::Debug for PrefixIterator<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrefixIterator")
    }
}
