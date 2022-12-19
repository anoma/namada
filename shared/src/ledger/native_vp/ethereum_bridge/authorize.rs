//! Functionality to do with checking whether a transaction is authorized by the
//! "owner" of some key under this account
use eyre::Result;
use namada_core::types::address::Address;

use crate::ledger::native_vp::StorageReader;

pub(super) fn is_authorized(
    _reader: impl StorageReader,
    _tx_data: &[u8],
    _owner: &Address,
) -> Result<bool> {
    tracing::warn!(
        "authorize::is_authorized is not implemented, so all transfers are \
         authorized"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::native_vp;
    use crate::types::address;

    #[test]
    fn test_is_authorized_established_address() -> Result<()> {
        let reader = native_vp::testing::FakeStorageReader::default();
        let tx_data = vec![];
        let owner = address::testing::established_address_1();

        let authorized = is_authorized(reader, &tx_data, &owner)?;

        assert!(authorized);
        Ok(())
    }
}
