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
    receiver: &Address,
) -> bool {
    verifiers.contains(sender) && verifiers.contains(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::address;

    #[test]
    fn test_is_authorized_passes() {
        let sender = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let verifiers = BTreeSet::from([sender.clone(), receiver.clone()]);

        let authorized = is_authorized(&verifiers, &sender, &receiver);

        assert!(authorized);
    }

    #[test]
    fn test_is_authorized_fails() {
        let sender = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let verifiers = BTreeSet::default();

        let authorized = is_authorized(&verifiers, &sender, &receiver);

        assert!(!authorized);

        let verifiers = BTreeSet::from([sender.clone()]);

        let authorized = is_authorized(&verifiers, &sender, &receiver);

        assert!(!authorized);

        let verifiers = BTreeSet::from([receiver.clone()]);

        let authorized = is_authorized(&verifiers, &sender, &receiver);

        assert!(!authorized);
    }
}
