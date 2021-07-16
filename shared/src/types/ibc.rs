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
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding error: {0}")]
    DecodingError(String),
}

/// Decode result for IBC data
pub type Result<T> = std::result::Result<T, Error>;

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
    pub fn client_state(&self) -> Result<AnyClientState> {
        AnyClientState::decode_vec(&self.client_state)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the consensus state
    pub fn consensus_state(&self) -> Result<AnyConsensusState> {
        AnyConsensusState::decode_vec(&self.consensus_state)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }
}

/// Data to update a client
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct ClientUpdateData {
    /// The updated client ID
    client_id: String,
    /// The headers to update the client
    headers: Vec<Vec<u8>>,
}

impl ClientUpdateData {
    /// Returns the data to update a client
    pub fn new(client_id: ClientId, headers: Vec<AnyHeader>) -> Self {
        let client_id = client_id.as_str().to_owned();
        let headers = headers
            .iter()
            .map(|h| {
                h.encode_vec()
                    .expect("Encoding a client header shouldn't fail")
            })
            .collect();
        Self { client_id, headers }
    }

    /// Returns the client ID
    pub fn client_id(&self) -> Result<ClientId> {
        ClientId::from_str(&self.client_id)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the header
    pub fn headers(&self) -> Result<Vec<AnyHeader>> {
        let mut headers = vec![];
        for h in &self.headers {
            let header = AnyHeader::decode_vec(h)
                .map_err(|e| Error::DecodingError(e.to_string()))?;
            headers.push(header);
        }
        Ok(headers)
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
    pub fn client_id(&self) -> Result<ClientId> {
        ClientId::from_str(&self.client_id)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the client state
    pub fn client_state(&self) -> Result<AnyClientState> {
        AnyClientState::decode_vec(&self.client_state)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the consensus state
    pub fn consensus_state(&self) -> Result<AnyConsensusState> {
        AnyConsensusState::decode_vec(&self.consensus_state)
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the proof for client state
    pub fn proof_client(&self) -> Result<MerkleProof> {
        MerkleProof::decode(&self.proof_client[..])
            .map_err(|e| Error::DecodingError(e.to_string()))
    }

    /// Returns the proof for consensus state
    pub fn proof_consensus_state(&self) -> Result<MerkleProof> {
        MerkleProof::decode(&self.proof_consensus_state[..])
            .map_err(|e| Error::DecodingError(e.to_string()))
    }
}
