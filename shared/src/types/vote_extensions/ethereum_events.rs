//! Contains types necessary for processing Ethereum events
//! in vote extensions.

use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::proto::Signed;
use crate::types::address::Address;
use crate::types::ethereum_events::EthereumEvent;
use crate::types::key::common::{self, Signature};
use crate::types::storage::BlockHeight;

/// Represents a set of [`EthereumEvent`] instances
/// seen by some validator.
///
/// This struct will be created and signed over by each
/// active validator, to be included as a vote extension at the end of a
/// Tendermint PreCommit phase.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vext {
    /// The block height for which this [`Vext`] was made.
    pub block_height: BlockHeight,
    /// TODO: the validator's address is temporarily being included
    /// until we're able to map a Tendermint address to a validator
    /// address (see <https://github.com/anoma/namada/issues/200>)
    pub validator_addr: Address,
    /// The new ethereum events seen. These should be
    /// deterministically ordered.
    pub ethereum_events: Vec<EthereumEvent>,
}

impl Vext {
    /// Creates a [`Vext`] without any Ethereum events.
    pub fn empty(block_height: BlockHeight, validator_addr: Address) -> Self {
        Self {
            block_height,
            ethereum_events: Vec::new(),
            validator_addr,
        }
    }

    /// Sign a [`Vext`] with a validator's `signing_key`,
    /// and return the signed data.
    pub fn sign(self, signing_key: &common::SecretKey) -> Signed<Self> {
        Signed::new(signing_key, self)
    }
}

/// Aggregates an Ethereum event with the corresponding
// validators who saw this event.
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct MultiSignedEthEvent {
    /// The Ethereum event that was signed.
    pub event: EthereumEvent,
    /// List of addresses of validators who signed this event
    pub signers: HashSet<Address>,
}

/// Compresses a set of signed [`Vext`] instances, to save
/// space on a block.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VextDigest {
    /// The signatures and signing address of each [`Vext`]
    pub signatures: HashMap<Address, Signature>,
    /// The events that were reported
    pub events: Vec<MultiSignedEthEvent>,
}

impl BorshSchema for VextDigest {
    fn add_definitions_recursively(
        definitions: &mut HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields =
            borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                HashMap::<Address, Signature>::declaration(),
                Vec::<MultiSignedEthEvent>::declaration()
            ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
        "ethereum_events::VextDigest".into()
    }
}

impl VextDigest {
    /// Decompresses a set of signed [`Vext`] instances.
    pub fn decompress(self, last_height: BlockHeight) -> Vec<Signed<Vext>> {
        let VextDigest { signatures, events } = self;

        let mut extensions = vec![];

        for (addr, sig) in signatures.into_iter() {
            let mut ext = Vext::empty(last_height, addr.clone());

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

            let signed = Signed::new_from(ext, sig);
            extensions.push(signed);
        }
        extensions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::proto::Signed;
    use crate::types::address::{self, Address};
    use crate::types::ethereum_events::{EthereumEvent, Uint};
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

    /// Test decompression of a set of Ethereum events
    #[test]
    fn test_decompress_ethereum_events() {
        // we need to construct a `Vec<Signed<Vext>>`
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

        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();

        let ext = |validator: Address| -> Vext {
            let mut ext = Vext::empty(last_block_height, validator);

            ext.ethereum_events.push(ev_1.clone());
            ext.ethereum_events.push(ev_2.clone());
            ext.ethereum_events.sort();

            ext
        };

        // assume both v1 and v2 saw the same events,
        // so each of them signs `ext` with their respective sk
        let ext_1 = Signed::new(&sk_1, ext(validator_1.clone()));
        let ext_2 = Signed::new(&sk_2, ext(validator_2.clone()));

        let ext = vec![ext_1, ext_2];

        // we have the `Signed<Vext>` instances we need,
        // let us now compress them into a single `VextDigest`
        let signatures: HashMap<_, _> = [
            (validator_1.clone(), ext[0].sig.clone()),
            (validator_2.clone(), ext[1].sig.clone()),
        ]
        .into_iter()
        .collect();
        let signers = {
            let mut s = HashSet::new();
            s.insert(validator_1);
            s.insert(validator_2);
            s
        };
        let events = vec![
            MultiSignedEthEvent {
                event: ev_1,
                signers: signers.clone(),
            },
            MultiSignedEthEvent {
                event: ev_2,
                signers,
            },
        ];

        let digest = VextDigest { events, signatures };

        // finally, decompress the `VextDigest` back into a
        // `Vec<Signed<Vext>>`
        let mut decompressed = digest
            .decompress(last_block_height)
            .into_iter()
            .collect::<Vec<Signed<Vext>>>();

        // decompressing yields an arbitrary ordering of `Vext`
        // instances, which is fine
        if decompressed[0].data.validator_addr != ext[0].data.validator_addr {
            decompressed.swap(0, 1);
        }

        assert_eq!(ext, decompressed);
        assert!(decompressed[0].verify(&sk_1.ref_to()).is_ok());
        assert!(decompressed[1].verify(&sk_2.ref_to()).is_ok());
    }
}
