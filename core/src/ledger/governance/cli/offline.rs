use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, ReadDir};
use std::path::PathBuf;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::onchain::ProposalVote;
use super::validation::{is_valid_tally_epoch, ProposalValidation};
use crate::proto::SignatureIndex;
use crate::types::account::AccountPublicKeysMap;
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::key::{common, RefTo, SigScheme};
use crate::types::storage::Epoch;

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The offline proposal structure
pub struct OfflineProposal {
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The epoch from which this changes are executed
    pub tally_epoch: Epoch,
}

impl OfflineProposal {
    /// Validate the offline proposal
    pub fn validate(
        self,
        current_epoch: Epoch,
    ) -> Result<Self, ProposalValidation> {
        is_valid_tally_epoch(self.tally_epoch, current_epoch)?;

        Ok(self)
    }

    /// Hash an offline proposal
    pub fn hash(&self) -> Hash {
        let content_serialized = serde_json::to_vec(&self.content)
            .expect("Conversion to bytes shouldn't fail.");
        let author_serialized = serde_json::to_vec(&self.author)
            .expect("Conversion to bytes shouldn't fail.");
        let tally_epoch_serialized = serde_json::to_vec(&self.tally_epoch)
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_serialized = &[
            content_serialized,
            author_serialized,
            tally_epoch_serialized,
        ]
        .concat();
        Hash::sha256(proposal_serialized)
    }

    /// Sign an offline proposal
    pub fn sign(
        self,
        signing_keys: Vec<common::SecretKey>,
        account_public_keys_map: &AccountPublicKeysMap,
    ) -> OfflineSignedProposal {
        let proposal_hash = self.hash();

        let signatures_index = compute_signatures_index(
            &signing_keys,
            account_public_keys_map,
            &proposal_hash,
        );

        OfflineSignedProposal {
            proposal: self,
            signatures: signatures_index,
        }
    }
}

impl TryFrom<&[u8]> for OfflineProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The signed offline proposal structure
pub struct OfflineSignedProposal {
    /// The proposal content
    pub proposal: OfflineProposal,
    /// The signatures over proposal data
    pub signatures: BTreeSet<SignatureIndex>,
}

impl TryFrom<&[u8]> for OfflineSignedProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

impl OfflineSignedProposal {
    /// Serialize the proposal to file. Returns the filename if successful.
    pub fn serialize(&self) -> Result<String, serde_json::Error> {
        let proposal_filename =
            format!("offline_proposal_{}.json", self.proposal.hash());

        let out = File::create(&proposal_filename)
            .expect("Should be able to create a file.");
        serde_json::to_writer_pretty(out, self)?;

        Ok(proposal_filename)
    }

    /// Check whether the signature is valid or not
    fn check_signature(
        &self,
        account_public_keys_map: &AccountPublicKeysMap,
        threshold: u8,
    ) -> bool {
        let proposal_hash = self.proposal.hash();
        if self.signatures.len() < threshold as usize {
            return false;
        }

        let valid_signatures = compute_total_valid_signatures(
            &self.signatures,
            account_public_keys_map,
            &proposal_hash,
        );

        valid_signatures >= threshold
    }

    /// Validate an offline proposal
    pub fn validate(
        self,
        account_public_keys_map: &AccountPublicKeysMap,
        threshold: u8,
    ) -> Result<Self, ProposalValidation> {
        let valid_signature =
            self.check_signature(account_public_keys_map, threshold);
        if !valid_signature {
            Err(ProposalValidation::OkNoSignature)
        } else {
            Ok(self)
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The offline proposal structure
pub struct OfflineVote {
    /// The proposal data hash
    pub proposal_hash: Hash,
    /// The proposal vote
    pub vote: ProposalVote,
    /// The signature over proposal data
    pub signatures: BTreeSet<SignatureIndex>,
    /// The address corresponding to the signature pk
    pub address: Address,
    /// The validators address to which this address delegated to
    pub delegations: Vec<Address>,
}

impl OfflineVote {
    /// Create an offline vote for a proposal
    pub fn new(
        proposal: &OfflineSignedProposal,
        vote: ProposalVote,
        address: Address,
        delegations: Vec<Address>,
    ) -> Self {
        let proposal_hash = proposal.proposal.hash();

        Self {
            proposal_hash,
            vote,
            delegations,
            signatures: BTreeSet::default(),
            address,
        }
    }

    /// Sign the offline vote
    pub fn sign(
        self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: &AccountPublicKeysMap,
    ) -> Self {
        let proposal_vote_data = self
            .vote
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let delegations_hash = self
            .delegations
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");

        let vote_hash = Hash::sha256(
            [
                self.proposal_hash.to_vec(),
                proposal_vote_data,
                delegations_hash,
            ]
            .concat(),
        );

        let signatures = compute_signatures_index(
            &keypairs,
            account_public_keys_map,
            &vote_hash,
        );

        Self { signatures, ..self }
    }

    /// Check if the vote is yay
    pub fn is_yay(&self) -> bool {
        self.vote.is_yay()
    }

    /// compute the hash of a proposal
    pub fn compute_hash(&self) -> Hash {
        let proposal_hash_data = self
            .proposal_hash
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_vote_data = self
            .vote
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let delegations_hash = self
            .delegations
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let vote_serialized =
            &[proposal_hash_data, proposal_vote_data, delegations_hash]
                .concat();

        Hash::sha256(vote_serialized)
    }

    /// Check whether the signature is valid or not
    pub fn check_signature(
        &self,
        account_public_keys_map: &AccountPublicKeysMap,
        threshold: u8,
    ) -> bool {
        if self.signatures.len() < threshold as usize {
            return false;
        }
        let vote_data_hash = self.compute_hash();

        let valid_signatures = compute_total_valid_signatures(
            &self.signatures,
            account_public_keys_map,
            &vote_data_hash,
        );

        valid_signatures >= threshold
    }

    /// Serialize the proposal to file. Returns the filename if successful.
    pub fn serialize(&self) -> Result<String, serde_json::Error> {
        let vote_filename = format!(
            "offline_vote_{}_{}.json",
            self.proposal_hash, self.address
        );

        let out = File::create(&vote_filename).unwrap();
        serde_json::to_writer_pretty(out, self)?;

        Ok(vote_filename)
    }
}

/// Compute the signatures index
fn compute_signatures_index(
    keys: &[common::SecretKey],
    account_public_keys_map: &AccountPublicKeysMap,
    hashed_data: &Hash,
) -> BTreeSet<SignatureIndex> {
    keys.iter()
        .filter_map(|signing_key| {
            let public_key = signing_key.ref_to();
            let public_key_index =
                account_public_keys_map.get_index_from_public_key(&public_key);
            if public_key_index.is_some() {
                let signature =
                    common::SigScheme::sign(signing_key, hashed_data);
                Some(SignatureIndex::from_single_signature(signature))
            } else {
                None
            }
        })
        .collect::<BTreeSet<SignatureIndex>>()
}

/// Compute the total amount of signatures
fn compute_total_valid_signatures(
    signatures: &BTreeSet<SignatureIndex>,
    account_public_keys_map: &AccountPublicKeysMap,
    hashed_data: &Hash,
) -> u8 {
    signatures.iter().fold(0_u8, |acc, signature_index| {
        let public_key = account_public_keys_map
            .get_public_key_from_index(signature_index.index);
        if let Some(pk) = public_key {
            let sig_check = common::SigScheme::verify_signature(
                &pk,
                hashed_data,
                &signature_index.signature,
            );
            if sig_check.is_ok() { acc + 1 } else { acc }
        } else {
            acc
        }
    })
}

/// Read all offline files from a folder
pub fn read_offline_files(path: ReadDir) -> Vec<PathBuf> {
    path.filter_map(|path| {
        if let Ok(path) = path {
            let file_type = path.file_type();
            if let Ok(file_type) = file_type {
                if file_type.is_file()
                    && path.file_name().to_string_lossy().contains("offline_")
                {
                    Some(path.path())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    })
    .collect::<Vec<PathBuf>>()
}

/// Find offline votes from a folder
pub fn find_offline_proposal(files: &[PathBuf]) -> Option<PathBuf> {
    files
        .iter()
        .filter(|path| path.to_string_lossy().contains("offline_proposal_"))
        .cloned()
        .collect::<Vec<PathBuf>>()
        .first()
        .cloned()
}

/// Find offline votes from a folder
pub fn find_offline_votes(files: &[PathBuf]) -> Vec<PathBuf> {
    files
        .iter()
        .filter(|path| path.to_string_lossy().contains("offline_vote_"))
        .cloned()
        .collect::<Vec<PathBuf>>()
}
