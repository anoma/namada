//! Contains types necessary for processing Ethereum events
//! in vote extensions.

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use num_rational::Ratio;

use super::EthereumEvent;
use crate::proto::Signed;
use crate::types::address::Address;
use crate::types::key::common::Signature;
use crate::types::storage::BlockHeight;

/// This struct will be created and signed over by each
/// validator as their vote extension.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VoteExtension {
    /// The current height of Anoma.
    pub block_height: BlockHeight,
    /// The new ethereum events seen. These should be
    /// deterministically ordered.
    pub ethereum_events: Vec<EthereumEvent>,
}

impl VoteExtension {
    /// Creates a [`VoteExtension`] without any Ethereum events.
    pub fn empty(block_height: BlockHeight) -> Self {
        Self {
            block_height,
            ethereum_events: Vec::new(),
        }
    }
}

/// A fraction of the total voting power. This should always be a reduced
/// fraction that is between zero and one inclusive.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct FractionalVotingPower(Ratio<u64>);

impl FractionalVotingPower {
    /// Create a new FractionalVotingPower. It must be between zero and one
    /// inclusive.
    pub fn new(numer: u64, denom: u64) -> Result<Self> {
        if denom == 0 {
            return Err(eyre!("denominator can't be zero"));
        }
        let ratio: Ratio<u64> = (numer, denom).into();
        if ratio > 1.into() {
            return Err(eyre!(
                "fractional voting power cannot be greater than one"
            ));
        }
        Ok(Self(ratio))
    }
}

impl From<&FractionalVotingPower> for (u64, u64) {
    fn from(ratio: &FractionalVotingPower) -> Self {
        (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
    }
}

impl BorshSerialize for FractionalVotingPower {
    fn serialize<W: ark_serialize::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let (numer, denom): (u64, u64) = self.into();
        (numer, denom).serialize(writer)
    }
}

impl BorshDeserialize for FractionalVotingPower {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let (numer, denom): (u64, u64) = BorshDeserialize::deserialize(buf)?;
        Ok(FractionalVotingPower(Ratio::<u64>::new(numer, denom)))
    }
}

impl BorshSchema for FractionalVotingPower {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields =
            borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                u64::declaration(),
                u64::declaration()
            ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
        "FractionalVotingPower".into()
    }
}

/// Aggregates an Ethereum event with the corresponding
// validators who saw this event.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct MultiSignedEthEvent {
    /// The Ethereum event that was signed.
    pub event: EthereumEvent,
    /// List of addresses of validators who signed this event
    pub signers: HashSet<Address>,
}

/// Compresses a set of signed `VoteExtension` instances, to save
/// space on a block.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct VoteExtensionDigest {
    /// The signatures and signing address of each VoteExtension
    pub signatures: Vec<(Signature, Address)>,
    /// The events that were reported
    pub events: Vec<MultiSignedEthEvent>,
    /// The validators who saw no events
    pub nulls: HashSet<Address>,
}

impl VoteExtensionDigest {
    /// Decompresses a set of signed `VoteExtension` instances.
    pub fn decompress(
        self,
        last_height: BlockHeight,
    ) -> Vec<Signed<VoteExtension>> {
        let VoteExtensionDigest {
            signatures,
            events,
            nulls,
        } = self;

        let mut extensions = vec![];

        for (sig, addr) in signatures.into_iter() {
            let mut ext = VoteExtension::empty(last_height);

            // TODO: perhaps remove the `nulls` field,
            // as this code will behave much the same without it
            if !nulls.contains(&addr) {
                for event in events.iter() {
                    if event.signers.contains(&addr) {
                        ext.ethereum_events.push(event.event.clone());
                    }
                }
                // TODO: we probably need a manual `Ord` impl for
                // `EthereumEvent`, such that this `sort()` is
                // always deterministic, regardless
                // of crate versions changing and such
                ext.ethereum_events.sort();
            }

            let signed = Signed { data: ext, sig };
            extensions.push(signed);
        }
        extensions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::super::EthereumEvent;
    use super::*;
    use crate::proto::Signed;
    use crate::types::address::Address;
    use crate::types::ethereum_events::Uint;
    use crate::types::hash::Hash;
    use crate::types::key;
    use crate::types::key::RefTo;
    use crate::types::storage::BlockHeight;

    /// Test the hashing of an Ethereum event
    #[test]
    fn test_ethereum_event_hash() {
        let nonce = Uint::from(123u64);
        let event = EthereumEvent::TransfersToNamada {
            nonce,
            transfers: vec![],
        };
        let hash = event.hash().unwrap();

        assert_eq!(
            hash,
            Hash([
                94, 131, 116, 129, 41, 204, 178, 144, 24, 8, 185, 16, 103, 236,
                209, 191, 20, 89, 145, 17, 41, 233, 31, 98, 185, 6, 217, 204,
                80, 38, 224, 23
            ])
        );
    }

    /// This test is ultimately just exercising the underlying
    /// library we use for fractions, we want to make sure
    /// operators work as expected with our FractionalVotingPower
    /// type itself
    #[test]
    fn test_fractional_voting_power_ord_eq() {
        assert!(
            FractionalVotingPower::new(2, 3).unwrap()
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                == FractionalVotingPower::new(2, 6).unwrap()
        );
    }

    /// Test error handling on the FractionalVotingPower type
    #[test]
    fn test_fractional_voting_power_valid_fractions() {
        assert!(FractionalVotingPower::new(0, 0).is_err());
        assert!(FractionalVotingPower::new(1, 0).is_err());
        assert!(FractionalVotingPower::new(0, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 2).is_ok());
        assert!(FractionalVotingPower::new(3, 2).is_err());
    }

    /// Test decompression of a set of Ethereum events
    #[test]
    fn test_decompress_ethereum_events() {
        // we need to construct a `Vec<Signed<VoteExtension>>`
        let sk_1 = key::testing::keypair_1();
        let sk_2 = key::testing::keypair_2();

        let last_block_height = BlockHeight(123);

        let ev_1 = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let ev_2 = EthereumEvent::TransfersToEthereum {
            nonce: 2u64.into(),
            transfers: vec![],
        };

        let ext = {
            let mut ext = VoteExtension::empty(last_block_height);

            ext.ethereum_events.push(ev_1.clone());
            ext.ethereum_events.push(ev_2.clone());
            ext.ethereum_events.sort();

            ext
        };

        // assume both v1 and v2 saw the same events,
        // so each of them signs `ext` with their respective sk
        let ext_1 = Signed::new(&sk_1, ext.clone());
        let ext_2 = Signed::new(&sk_2, ext);

        let ext = vec![ext_1, ext_2];

        // we have the `Signed<VoteExtension>` instances we need,
        // let us now compress them into a single `VoteExtensionDigest`
        let signatures: Vec<(_, Address)> = vec![
            (ext[0].sig.clone(), (&sk_1.ref_to()).into()),
            (ext[1].sig.clone(), (&sk_2.ref_to()).into()),
        ];
        let signers = {
            let mut s = HashSet::new();
            s.insert(signatures[0].1.clone());
            s.insert(signatures[1].1.clone());
            s
        };
        let events = vec![
            MultiSignedEthEvent {
                event: ev_1.clone(),
                signers: signers.clone(),
            },
            MultiSignedEthEvent {
                event: ev_2.clone(),
                signers,
            },
        ];

        let digest = VoteExtensionDigest {
            events,
            signatures,
            nulls: HashSet::new(),
        };

        // finally, decompress the `VoteExtensionDigest` back into a
        // `Vec<Signed<VoteExtension>>`
        let decompressed = digest.decompress(last_block_height);

        assert_eq!(ext, decompressed);
    }
}
