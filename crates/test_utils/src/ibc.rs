//! Helper functions for testing IBC client upgrade

use core::time::Duration;

use namada_core::ibc::clients::tendermint::client_state::ClientState as TmClientState;
use namada_core::ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use namada_core::ibc::clients::tendermint::types::{
    AllowUpdate, ClientState as TmClientStateType,
    ConsensusState as TmConsensusStateType, TrustThreshold,
};
use namada_core::ibc::core::client::types::Height;
use namada_core::ibc::core::host::types::path::UPGRADED_IBC_STATE;
use namada_core::ibc::primitives::proto::Any;
use namada_state::ics23_specs::ibc_proof_specs;
use namada_state::{Header, Sha256Hasher};
use prost::Message;

pub fn make_new_client_state_bytes(height: u64) -> Vec<u8> {
    let trust_threshold = TrustThreshold::ONE_THIRD;
    let trusting_period = Duration::from_secs(2400);
    let unbonding_period = Duration::from_secs(3600);
    let max_clock_drift = Duration::new(30, 0);
    let height = Height::new(0, height).unwrap();

    let client_state: TmClientState = TmClientStateType::new(
        "upgraded-chain".parse().unwrap(),
        trust_threshold,
        trusting_period,
        unbonding_period,
        max_clock_drift,
        height,
        ibc_proof_specs::<Sha256Hasher>().try_into().unwrap(),
        vec![UPGRADED_IBC_STATE.to_string()],
        AllowUpdate {
            after_expiry: true,
            after_misbehaviour: true,
        },
    )
    .unwrap()
    .into();

    Any::from(client_state).encode_to_vec()
}

pub fn make_new_consensus_state_bytes(header: Header) -> Vec<u8> {
    let consensus_state: TmConsensusState = TmConsensusStateType {
        timestamp: header
            .time
            .to_rfc3339()
            .parse()
            .expect("invalid header time"),
        root: header.hash.to_vec().into(),
        next_validators_hash: header
            .next_validators_hash
            .to_vec()
            .try_into()
            .expect("invalid next_validators_hash"),
    }
    .into();

    Any::from(consensus_state).encode_to_vec()
}
