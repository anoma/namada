//! AnyClientState and AnyConsensusState for IBC context

use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::clients::tendermint::types::{
    ClientState as TmClientStateType, ConsensusState as TmConsensusStateType,
};
use ibc::core::host::types::error::HostError;
use ibc::primitives::proto::Any;
use ibc_derive::{IbcClientState, IbcConsensusState};
#[cfg(any(test, feature = "testing"))]
use ibc_testkit::testapp::ibc::clients::mock::client_state::MockClientState;
#[cfg(any(test, feature = "testing"))]
use ibc_testkit::testapp::ibc::clients::mock::consensus_state::MockConsensusState;
use namada_systems::parameters;
use prost::Message;

use super::common::IbcCommonContext;
use super::IbcContext;

/// ClientState for light clients
#[derive(Clone, Debug, IbcClientState)]
#[validation(IbcContext<C: IbcCommonContext, Params: parameters::Read<C::Storage>>)]
#[execution(IbcContext<C: IbcCommonContext, Params: parameters::Read<C::Storage>>)]
pub enum AnyClientState {
    /// Tendermint client state
    Tendermint(TmClientState),

    #[cfg(any(test, feature = "testing"))]
    /// Mock client state for testing
    Mock(MockClientState),
}

impl From<TmClientState> for AnyClientState {
    fn from(cs: TmClientState) -> Self {
        Self::Tendermint(cs)
    }
}

impl From<TmClientStateType> for AnyClientState {
    fn from(cs: TmClientStateType) -> Self {
        Self::Tendermint(cs.into())
    }
}

impl TryFrom<AnyClientState> for TmClientState {
    type Error = HostError;

    fn try_from(any: AnyClientState) -> Result<Self, Self::Error> {
        match any {
            AnyClientState::Tendermint(cs) => Ok(cs),
            #[cfg(any(test, feature = "testing"))]
            AnyClientState::Mock(_) => Err(HostError::Other {
                description: "Unexpected client state type: Mock".to_string(),
            }),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<MockClientState> for AnyClientState {
    fn from(cs: MockClientState) -> Self {
        Self::Mock(cs)
    }
}

#[cfg(any(test, feature = "testing"))]
impl TryFrom<AnyClientState> for MockClientState {
    type Error = HostError;

    fn try_from(any: AnyClientState) -> Result<Self, Self::Error> {
        match any {
            AnyClientState::Tendermint(_) => Err(HostError::Other {
                description: "Unexpected client state type: Tendermint"
                    .to_string(),
            }),
            AnyClientState::Mock(cs) => Ok(cs),
        }
    }
}

impl From<AnyClientState> for Any {
    fn from(client_state: AnyClientState) -> Self {
        match client_state {
            AnyClientState::Tendermint(cs) => cs.into(),
            #[cfg(any(test, feature = "testing"))]
            AnyClientState::Mock(cs) => cs.into(),
        }
    }
}

impl TryFrom<Any> for AnyClientState {
    type Error = HostError;

    fn try_from(client_state: Any) -> Result<Self, Self::Error> {
        #[cfg(any(test, feature = "testing"))]
        if let Ok(cs) = MockClientState::try_from(client_state.clone()) {
            return Ok(cs.into());
        }

        let cs = TmClientState::try_from(client_state).map_err(|_| {
            HostError::Other {
                description: "Unknown client state".to_string(),
            }
        })?;
        Ok(cs.into())
    }
}

/// ConsensusState for light clients
#[derive(IbcConsensusState)]
pub enum AnyConsensusState {
    /// Tendermint consensus state
    Tendermint(TmConsensusState),

    #[cfg(any(test, feature = "testing"))]
    /// Mock consensus state for testing
    Mock(MockConsensusState),
}

impl From<TmConsensusState> for AnyConsensusState {
    fn from(cs: TmConsensusState) -> Self {
        Self::Tendermint(cs)
    }
}

impl From<TmConsensusStateType> for AnyConsensusState {
    fn from(cs: TmConsensusStateType) -> Self {
        Self::Tendermint(cs.into())
    }
}

impl TryFrom<AnyConsensusState> for TmConsensusStateType {
    type Error = HostError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Tendermint(c) => Ok(c.inner().clone()),
            #[cfg(any(test, feature = "testing"))]
            _ => Err(HostError::Other {
                description: "Unexpected consensus state type".to_string(),
            }),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<MockConsensusState> for AnyConsensusState {
    fn from(cs: MockConsensusState) -> Self {
        Self::Mock(cs)
    }
}

impl TryFrom<AnyConsensusState> for TmConsensusState {
    type Error = HostError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Tendermint(cs) => Ok(cs),
            #[cfg(any(test, feature = "testing"))]
            _ => Err(HostError::Other {
                description: "Unexpected consensus state".to_string(),
            }),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl TryFrom<AnyConsensusState> for MockConsensusState {
    type Error = HostError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Mock(cs) => Ok(cs),
            _ => Err(HostError::Other {
                description: "Unexpected consensus state".to_string(),
            }),
        }
    }
}

impl From<AnyConsensusState> for Any {
    fn from(consensus_state: AnyConsensusState) -> Self {
        match consensus_state {
            AnyConsensusState::Tendermint(cs) => cs.into(),
            #[cfg(any(test, feature = "testing"))]
            AnyConsensusState::Mock(cs) => cs.into(),
        }
    }
}

impl TryFrom<Any> for AnyConsensusState {
    type Error = HostError;

    fn try_from(consensus_state: Any) -> Result<Self, Self::Error> {
        #[cfg(any(test, feature = "testing"))]
        if let Ok(cs) = MockConsensusState::try_from(consensus_state.clone()) {
            return Ok(cs.into());
        }

        let cs = TmConsensusState::try_from(consensus_state).map_err(|_| {
            HostError::Other {
                description: "Unknown consensus state".to_string(),
            }
        })?;
        Ok(cs.into())
    }
}

impl TryFrom<Vec<u8>> for AnyConsensusState {
    type Error = HostError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Any::decode(&bytes[..])
            .map_err(|e| HostError::Other {
                description: format!("Decoding AnyConsensusState failed: {e}"),
            })?
            .try_into()
    }
}
