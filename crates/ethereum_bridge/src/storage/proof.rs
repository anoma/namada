//! Proofs over some arbitrary data.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethers::abi::Tokenizable;
use namada_core::eth_abi::Encode;
use namada_core::ethereum_events::Uint;
use namada_core::keccak::KeccakHash;
use namada_core::key::{common, secp256k1};
use namada_core::storage::Epoch;
use namada_core::{eth_abi, ethereum_structs};
use namada_vote_ext::validator_set_update::{
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

pub type BridgePoolRootProof = EthereumProof<(KeccakHash, Uint)>;

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
    pub fn map<F, R>(self, mut f: F) -> EthereumProof<R>
    where
        F: FnMut(T) -> R,
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

/// Sort signatures based on voting powers in descending order.
/// Puts a dummy signature in place of invalid or missing signatures.
pub fn sort_sigs(
    voting_powers: &VotingPowersMap,
    signatures: &HashMap<EthAddrBook, secp256k1::Signature>,
) -> Vec<ethereum_structs::Signature> {
    voting_powers
        .get_sorted()
        .into_iter()
        .map(|(addr_book, _)| {
            signatures
                .get(addr_book)
                .map(|sig| {
                    let (r, s, v) = sig.clone().into_eth_rsv();
                    ethereum_structs::Signature { r, s, v }
                })
                .unwrap_or(ethereum_structs::Signature {
                    r: [0; 32],
                    s: [0; 32],
                    v: 0,
                })
        })
        .collect()
}

impl Encode<1> for EthereumProof<(Epoch, VotingPowersMap)> {
    fn tokenize(&self) -> [eth_abi::Token; 1] {
        let signatures = sort_sigs(&self.data.1, &self.signatures);
        let (bridge_validators, governance_validators) =
            self.data.1.get_abi_encoded();
        let (KeccakHash(bridge_hash), KeccakHash(gov_hash)) =
            valset_upd_toks_to_hashes(
                self.data.0,
                bridge_validators,
                governance_validators,
            );
        [eth_abi::Token::Tuple(vec![
            eth_abi::Token::FixedBytes(bridge_hash.to_vec()),
            eth_abi::Token::FixedBytes(gov_hash.to_vec()),
            Tokenizable::into_token(signatures),
        ])]
    }
}

#[cfg(test)]
mod test_ethbridge_proofs {
    //! Test ethereum bridge proofs.

    use assert_matches::assert_matches;
    use namada_core::ethereum_events::EthAddress;
    use namada_core::key;
    use namada_tx::Signed;

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
