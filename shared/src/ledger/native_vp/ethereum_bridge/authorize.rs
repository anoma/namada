//! Functionality to do with checking whether a transaction is authorized by the
//! "owner" of some key under this account
use std::collections::BTreeSet;

use namada_core::types::address::Address;

/// For wrapped ERC20 transfers, checks that `verifiers` contains the `sender`'s
/// address - we delegate to the sender's VP to authorize the transfer (for
/// regular Namada accounts, this will be `vp_implicit` or `vp_user`).
pub(super) fn is_authorized(
    verifiers: &BTreeSet<Address>,
    sender: &Address,
) -> bool {
    verifiers.contains(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::address;

    #[test]
    fn test_is_authorized_passes() {
        let owner = address::testing::established_address_1();
        let verifiers = BTreeSet::from([owner.clone()]);
        assert!(verifiers.contains(&owner));

        let authorized = is_authorized(&verifiers, &owner);

        assert!(authorized);
    }

    #[test]
    fn test_is_authorized_fails() {
        let owner = address::testing::established_address_1();
        let verifiers = BTreeSet::default();
        assert!(!verifiers.contains(&owner));

        let authorized = is_authorized(&verifiers, &owner);

        assert!(!authorized);
    }
}
