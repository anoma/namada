//! Functionality to do with checking whether a transaction is authorized by the
//! "owner" of some key under this account
use eyre::Result;

use super::store;
use crate::types::address::Address;

pub(super) fn is_authorized(
    _reader: impl store::Reader,
    _tx_data: &[u8],
    _owner: &Address,
) -> Result<bool> {
    // TODO: integrate with how `anomac transfer` transactions will work from <https://github.com/anoma/namada/pull/297>
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::address;

    #[test]
    fn test_is_authorized_established_address() -> Result<()> {
        let reader = store::testing::FakeReader::default();
        let tx_data = vec![];
        let owner = address::testing::established_address_1();

        let authorized = is_authorized(reader, &tx_data, &owner)?;

        assert!(authorized);
        Ok(())
    }
}
