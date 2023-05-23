use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, ReadDir};
use std::path::{Path, PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::onchain::ProposalVote;
use super::validation::{is_valid_tally_epoch, ProposalValidation};
use crate::proto::SignatureIndex;
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
    pub fn validate(&self, current_epoch: Epoch) -> ProposalValidation {
        let is_valid_tally_epoch =
            is_valid_tally_epoch(self.tally_epoch, current_epoch);
        if !is_valid_tally_epoch.ok() {
            is_valid_tally_epoch
        } else {
            ProposalValidation::Ok
        }
    }
}

impl OfflineProposal {
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
        pks_map: HashMap<common::PublicKey, u64>,
    ) -> OfflineSignedProposal {
        let proposal_hash = self.hash();

        let signatures_index =
            compute_signatures_index(&signing_keys, &pks_map, &proposal_hash);

        OfflineSignedProposal {
            proposal: self,
            signatures: signatures_index,
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The offline proposal structure
pub struct OfflineSignedProposal {
    /// The proposal content
    pub proposal: OfflineProposal,
    /// The signatures over proposal data
    pub signatures: BTreeSet<SignatureIndex>,
}

impl OfflineSignedProposal {
    /// Serialize the proposal to file. Returns the filename if successful.
    pub fn serialize(&self, path: &Path) -> Option<String> {
        let proposal_filename =
            format!("offline_proposal_{}.json", self.proposal.hash());
        let proposal_file_path = path
            .parent()
            .expect("No parent found")
            .join(proposal_filename);

        let out = File::create(&proposal_file_path).unwrap();
        match serde_json::to_writer_pretty(out, self) {
            Ok(_) => Some(proposal_file_path.to_string_lossy().into_owned()),
            Err(_) => None,
        }
    }

    /// Check whether the signature is valid or not
    fn check_signature(
        &self,
        pks_map: HashMap<common::PublicKey, u64>,
        threshold: u64,
    ) -> bool {
        let proposal_hash = self.proposal.hash();
        if self.signatures.len() < threshold as usize {
            return false;
        }

        let pks_map_inverted: HashMap<u64, common::PublicKey> =
            pks_map.iter().map(|(k, v)| (*v, k.clone())).collect();

        let valid_signatures = compute_total_valid_signatures(
            &self.signatures,
            &pks_map_inverted,
            &proposal_hash,
        );

        valid_signatures >= threshold
    }

    /// Validate an offline proposal
    pub fn validate(
        &self,
        pks_map: HashMap<common::PublicKey, u64>,
        threshold: u64,
    ) -> ProposalValidation {
        let valid_signature = self.check_signature(pks_map, threshold);
        if !valid_signature {
            ProposalValidation::OkNoSignature
        } else {
            ProposalValidation::Ok
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
    pub address: Address
}

impl OfflineVote {
    /// Create an offline vote for a proposal
    pub fn new(
        proposal: &OfflineSignedProposal,
        vote: ProposalVote,
        address: Address,
        signing_key: Vec<common::SecretKey>,
        pks_map: HashMap<common::PublicKey, u64>,
    ) -> Self {
        let proposal_hash = proposal.proposal.hash();
        let proposal_hash_data = proposal_hash
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_vote_data = vote
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");

        let vote_hash = Hash::sha256(
            [proposal_hash_data, proposal_vote_data].concat(),
        );

        let signatures_index =
            compute_signatures_index(&signing_key, &pks_map, &vote_hash);

        Self {
            proposal_hash,
            vote,
            signatures: signatures_index,
            address,
        }
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
        let vote_serialized =
            &[proposal_hash_data, proposal_vote_data]
                .concat();

        Hash::sha256(vote_serialized)
    }

    /// Check whether the signature is valid or not
    pub fn check_signature(
        &self,
        pks_map: HashMap<common::PublicKey, u64>,
        threshold: u64,
    ) -> bool {
        if self.signatures.len() < threshold as usize {
            return false;
        }
        let vote_data_hash = self.compute_hash();

        let pks_map_inverted: HashMap<u64, common::PublicKey> =
            pks_map.iter().map(|(k, v)| (*v, k.clone())).collect();

        let valid_signatures = compute_total_valid_signatures(
            &self.signatures,
            &pks_map_inverted,
            &vote_data_hash,
        );

        valid_signatures >= threshold
    }

    /// Serialize the proposal to file. Returns the filename if successful.
    pub fn serialize(&self, path: &Path) -> Option<String> {
        let vote_filename = format!("offline_vote_{}.json", self.proposal_hash);
        let proposal_file_path =
            path.parent().expect("No parent found").join(vote_filename);

        let out = File::create(&proposal_file_path).unwrap();
        match serde_json::to_writer_pretty(out, self) {
            Ok(_) => Some(proposal_file_path.to_string_lossy().into_owned()),
            Err(_) => None,
        }
    }
}

/// Compute the signatures index
fn compute_signatures_index(
    keys: &[common::SecretKey],
    pk_to_index_map: &HashMap<common::PublicKey, u64>,
    hashed_data: &Hash,
) -> BTreeSet<SignatureIndex> {
    keys.iter()
        .filter_map(|signing_key| {
            let pk = signing_key.ref_to();
            let pk_index = pk_to_index_map.get(&pk);
            if pk_index.is_some() {
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
    index_to_pk_map: &HashMap<u64, common::PublicKey>,
    hashed_data: &Hash,
) -> u64 {
    signatures.iter().fold(0_u64, |acc, signature_index| {
        let public_key = index_to_pk_map.get(&signature_index.index);
        if let Some(pk) = public_key {
            let sig_check = common::SigScheme::verify_signature(
                pk,
                hashed_data,
                &signature_index.sig,
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
