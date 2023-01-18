//! Proofs over some arbitrary data.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::types::eth_abi;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::vote_extensions::validator_set_update::{
    EthAddrBook, VotingPowersMap,
};

/// Ethereum proofs contain the [`secp256k1`] signatures of validators
/// over some data to be signed.
///
/// At any given time, an [`EthereumProof`] will be considered
/// "complete" once a number of signatures pertaining to validators
/// reflecting more than 2/3 of the bonded stake on Namada is available.
#[derive(Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct EthereumProof<T> {
    /// The signatures contained in the proof.
    pub signatures: HashMap<EthAddrBook, secp256k1::Signature>,
    /// The signed data.
    pub data: T,
}

impl<T> EthereumProof<T> {
    /// Return an incomplete [`EthereumProof`].
    pub fn new(data: T) -> Self {
        Self {
            data,
            signatures: HashMap::new(),
        }
    }

    /// Add a new signature to this [`EthereumProof`].
    pub fn attach_signature(
        &mut self,
        addr_book: EthAddrBook,
        signature: common::Signature,
    ) {
        if let common::Signature::Secp256k1(sig) = signature {
            self.signatures.insert(addr_book, sig);
        }
    }

    /// Add a new batch of signatures to this [`EthereumProof`].
    pub fn attach_signature_batch<I>(&mut self, batch: I)
    where
        I: IntoIterator<Item = (EthAddrBook, common::Signature)>,
    {
        for (addr_book, signature) in batch {
            self.attach_signature(addr_book, signature);
        }
    }
}

impl eth_abi::Encode<1> for EthereumProof<VotingPowersMap> {
    // TODO: finish this
    fn tokenize(&self) -> [eth_abi::Token; 1] {
        let bridge_hash = eth_abi::Token::FixedBytes(vec![]);
        let gov_hash = eth_abi::Token::FixedBytes(vec![]);
        let signatures = eth_abi::Token::Array(vec![]);
        [eth_abi::Token::Tuple(vec![
            bridge_hash,
            gov_hash,
            signatures,
        ])]
    }
}

#[cfg(test)]
mod test_ethbridge_proofs {
    //! Test ethereum bridge proofs.

    use assert_matches::assert_matches;
    use namada_core::proto::Signed;
    use namada_core::types::ethereum_events::EthAddress;
    use namada_core::types::key;

    use super::*;

    /// Test that adding a non-secp256k1 signature to an [`EthereumProof`] is a
    /// NOOP.
    #[test]
    fn test_add_non_secp256k1_is_noop() {
        let mut proof = EthereumProof::new(());
        assert!(proof.signatures.is_empty());
        let key = key::testing::keypair_1();
        assert_matches!(&key, common::SecretKey::Ed25519(_));
        let signed = Signed::<&'static str>::new(&key, ":)))))))");
        proof.attach_signature(
            EthAddrBook {
                hot_key_addr: EthAddress([0; 20]),
                cold_key_addr: EthAddress([0; 20]),
            },
            signed.sig,
        );
        assert!(proof.signatures.is_empty());
    }
}
