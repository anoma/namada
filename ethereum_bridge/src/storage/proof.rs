//! Proofs over some arbitrary data.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::types::eth_abi;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::vote_extensions::validator_set_update::{
    valset_upd_toks_to_hashes, EthAddrBook, VotingPowersMap, VotingPowersMapExt,
};

/// Ethereum proofs contain the [`secp256k1`] signatures of validators
/// over some data to be signed.
///
/// At any given time, an [`EthereumProof`] will be considered
/// "complete" once a number of signatures pertaining to validators
/// reflecting more than 2/3 of the bonded stake on Namada is available.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
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

    /// Map a function over the inner data of this [`EthereumProof`].
    #[inline]
    pub fn map<F, O>(self, mut f: F) -> EthereumProof<O>
    where
        F: FnMut(T) -> O,
    {
        EthereumProof {
            signatures: self.signatures,
            data: f(self.data),
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
    pub fn attach_signature_batch<I, K>(&mut self, batch: I)
    where
        I: IntoIterator<Item = (EthAddrBook, K)>,
        K: Into<common::Signature>,
    {
        for (addr_book, signature) in batch {
            self.attach_signature(addr_book, signature.into());
        }
    }
}

impl eth_abi::Encode<1> for EthereumProof<(Epoch, VotingPowersMap)> {
    fn tokenize(&self) -> [eth_abi::Token; 1] {
        let (hot_key_addrs, cold_key_addrs, voting_powers) =
            self.data.1.get_abi_encoded();
        let signatures = (hot_key_addrs.iter().zip(cold_key_addrs.iter()))
            .map(|addresses| {
                let (bridge_addr, gov_addr) = match addresses {
                    (
                        &eth_abi::Token::Address(hot),
                        &eth_abi::Token::Address(cold),
                    ) => (hot, cold),
                    _ => unreachable!(
                        "Hot and cold key address tokens should have the \
                         correct variant"
                    ),
                };
                let addr_book = EthAddrBook {
                    hot_key_addr: bridge_addr.into(),
                    cold_key_addr: gov_addr.into(),
                };
                let sig = &self.signatures[&addr_book];
                let [tokenized_sig] = sig.tokenize();
                tokenized_sig
            })
            .collect();
        let (KeccakHash(bridge_hash), KeccakHash(gov_hash)) =
            valset_upd_toks_to_hashes(
                self.data.0,
                hot_key_addrs,
                cold_key_addrs,
                voting_powers,
            );
        [eth_abi::Token::Tuple(vec![
            eth_abi::Token::FixedBytes(bridge_hash.to_vec()),
            eth_abi::Token::FixedBytes(gov_hash.to_vec()),
            eth_abi::Token::Array(signatures),
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
