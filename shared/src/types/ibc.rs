//! IBC-related data definitions and transaction and validity-predicate helpers.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ibc::ics02_client::client_consensus::AnyConsensusState;
use ibc::ics02_client::client_state::AnyClientState;
use ibc::ics02_client::header::AnyHeader;
use ibc::ics24_host::identifier::ClientId;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use prost::Message;
use serde::{Deserialize, Serialize};
use tendermint_proto::Protobuf;

/// States to create a new client
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct ClientCreationData {
    /// The client state
    client_state: Vec<u8>,
    /// The consensus state
    consensus_state: Vec<u8>,
}

impl ClientCreationData {
    /// Returns the data to create a new client
    pub fn new(
        client_state: AnyClientState,
        consensus_state: AnyConsensusState,
    ) -> Self {
        let client_state = client_state
            .encode_vec()
            .expect("Encoding a client state shouldn't fail");
        let consensus_state = consensus_state
            .encode_vec()
            .expect("Encoding a consensus state shouldn't fail");
        Self {
            client_state,
            consensus_state,
        }
    }

    /// Returns the client state
    pub fn client_state(&self) -> Option<AnyClientState> {
        AnyClientState::decode_vec(&self.client_state).ok()
    }

    /// Returns the consensus state
    pub fn consensus_state(&self) -> Option<AnyConsensusState> {
        AnyConsensusState::decode_vec(&self.consensus_state).ok()
    }
}

/// Data to update a client
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct ClientUpdateData {
    /// The updated client ID
    client_id: String,
    /// The client state
    header: Vec<u8>,
}

impl ClientUpdateData {
    /// Returns the data to update a client
    pub fn new(client_id: ClientId, header: AnyHeader) -> Self {
        let client_id = client_id.as_str().to_owned();
        let mut bytes = vec![];
        header
            .encode(&mut bytes)
            .expect("Encoding a client header shouldn't fail");
        // let header = header
        //    .encode_vec()
        //    .expect("Encoding a client header shouldn't fail");
        Self {
            client_id,
            header: bytes,
        }
    }

    /// Returns the client ID
    pub fn client_id(&self) -> Option<ClientId> {
        ClientId::from_str(&self.client_id).ok()
    }

    /// Returns the header
    pub fn header(&self) -> Option<AnyHeader> {
        AnyHeader::decode_vec(&self.header).ok()
    }
}

/// Data to upgrade a client
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct ClientUpgradeData {
    /// The upgraded client ID
    client_id: String,
    /// The client state
    client_state: Vec<u8>,
    /// The consensus state
    consensus_state: Vec<u8>,
    /// The proof of the client state
    proof_client: Vec<u8>,
    /// The proof of the consensus state
    proof_consensus_state: Vec<u8>,
}

impl ClientUpgradeData {
    /// Returns the data to upgrade a client
    pub fn new(
        client_id: ClientId,
        client_state: AnyClientState,
        consensus_state: AnyConsensusState,
        client_proof: MerkleProof,
        consensus_proof: MerkleProof,
    ) -> Self {
        let client_id = client_id.as_str().to_owned();
        let client_state = client_state
            .encode_vec()
            .expect("Encoding a client state shouldn't fail");
        let consensus_state = consensus_state
            .encode_vec()
            .expect("Encoding a consensus state shouldn't fail");
        let mut proof_client = vec![];
        client_proof
            .encode(&mut proof_client)
            .expect("Encoding a client proof shouldn't fail");
        let mut proof_consensus_state = vec![];
        consensus_proof
            .encode(&mut proof_consensus_state)
            .expect("Encoding a consensus proof shouldn't fail");
        Self {
            client_id,
            client_state,
            consensus_state,
            proof_client,
            proof_consensus_state,
        }
    }

    /// Returns the client ID
    pub fn client_id(&self) -> Option<ClientId> {
        ClientId::from_str(&self.client_id).ok()
    }

    /// Returns the client state
    pub fn client_state(&self) -> Option<AnyClientState> {
        AnyClientState::decode_vec(&self.client_state).ok()
    }

    /// Returns the consensus state
    pub fn consensus_state(&self) -> Option<AnyConsensusState> {
        AnyConsensusState::decode_vec(&self.consensus_state).ok()
    }

    /// Returns the proof for client state
    pub fn proof_client(&self) -> Option<MerkleProof> {
        MerkleProof::decode(&self.proof_client[..]).ok()
    }

    /// Returns the proof for consensus state
    pub fn proof_consensus_state(&self) -> Option<MerkleProof> {
        MerkleProof::decode(&self.proof_consensus_state[..]).ok()
    }
}
