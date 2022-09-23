use borsh::BorshSerialize;

/// Hash borsh encoded data into a storage sub-key.
/// This is a sha256 as an uppercase hexadecimal string.
pub fn hash_for_storage_key(data: impl BorshSerialize) -> String {
    let bytes = data.try_to_vec().unwrap();
    let hash = crate::types::hash::Hash::sha256(bytes);
    hash.to_string()
}
