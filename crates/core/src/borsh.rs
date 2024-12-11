//! Borsh binary encoding (re-exported) from official crate with custom
//! ext.

pub use borsh::*;

/// Extensions to types implementing [`BorshSerialize`].
pub trait BorshSerializeExt {
    /// Serialize a value to a [`Vec`] of bytes.
    fn serialize_to_vec(&self) -> Vec<u8>;
}

impl<T: BorshSerialize> BorshSerializeExt for T {
    fn serialize_to_vec(&self) -> Vec<u8> {
        let Ok(vec) = borsh::to_vec(self) else {
            unreachable!("Serializing to a Vec should be infallible");
        };
        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_equal() {
        let to_seriailze =
            "this is some cool shizzle I can guarantee that much - t. knower";
        let serialized_this_lib = to_seriailze.serialize_to_vec();
        let serialized_borsh_native = borsh::to_vec(&to_seriailze).unwrap();
        assert_eq!(serialized_this_lib, serialized_borsh_native);
    }
}
