//! AnyClientState and AnyConsensusState for IBC context

use ibc_derive::ConsensusState;
use prost::Message;

use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::clients::ics07_tendermint::{
    CommonContext, ExecutionContext as TmExecutionContext,
    ValidationContext as TmValidationContext,
};
use crate::ibc::core::ics02_client::client_state::{
    ClientStateCommon, ClientStateExecution, ClientStateValidation, Status,
    UpdateKind,
};
use crate::ibc::core::ics02_client::client_type::ClientType;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics02_client::{
    ClientExecutionContext, ClientValidationContext,
};
use crate::ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use crate::ibc::core::ics24_host::identifier::ClientId;
use crate::ibc::core::ics24_host::path::Path;
use crate::ibc::core::ExecutionContext;
#[cfg(feature = "ibc-mocks")]
use crate::ibc::mock::client_state::MockClientContext;
#[cfg(feature = "ibc-mocks")]
use crate::ibc::mock::client_state::MockClientState;
#[cfg(feature = "ibc-mocks")]
use crate::ibc::mock::consensus_state::MockConsensusState;
use crate::ibc::Height;
use crate::ibc_proto::google::protobuf::Any;

// TODO: #[derive(ClientState)] doesn't support contexts with contexts generic
// for now
/// ClientState for light clients
#[derive(Debug, Clone)]
pub enum AnyClientState {
    /// Tendermint client state
    Tendermint(TmClientState),

    #[cfg(feature = "ibc-mocks")]
    /// Mock client state for testing
    Mock(MockClientState),
}

impl From<TmClientState> for AnyClientState {
    fn from(cs: TmClientState) -> Self {
        Self::Tendermint(cs)
    }
}

#[cfg(feature = "ibc-mocks")]
impl From<MockClientState> for AnyClientState {
    fn from(cs: MockClientState) -> Self {
        Self::Mock(cs)
    }
}

impl From<AnyClientState> for Any {
    fn from(client_state: AnyClientState) -> Self {
        match client_state {
            AnyClientState::Tendermint(cs) => cs.into(),
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => cs.into(),
        }
    }
}

impl TryFrom<Any> for AnyClientState {
    type Error = ClientError;

    fn try_from(client_state: Any) -> Result<Self, Self::Error> {
        #[cfg(feature = "ibc-mocks")]
        if let Ok(cs) = MockClientState::try_from(client_state.clone()) {
            return Ok(cs.into());
        }

        let cs = TmClientState::try_from(client_state).map_err(|_| {
            ClientError::ClientSpecific {
                description: "Unknown client state".to_string(),
            }
        })?;
        Ok(cs.into())
    }
}

/// ConsensusState for light clients
#[derive(ConsensusState)]
pub enum AnyConsensusState {
    /// Tendermint consensus state
    Tendermint(TmConsensusState),

    #[cfg(feature = "ibc-mocks")]
    /// Mock consensus state for testing
    Mock(MockConsensusState),
}

impl From<TmConsensusState> for AnyConsensusState {
    fn from(cs: TmConsensusState) -> Self {
        Self::Tendermint(cs)
    }
}

#[cfg(feature = "ibc-mocks")]
impl From<MockConsensusState> for AnyConsensusState {
    fn from(cs: MockConsensusState) -> Self {
        Self::Mock(cs)
    }
}

impl TryFrom<AnyConsensusState> for TmConsensusState {
    type Error = ClientError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Tendermint(cs) => Ok(cs),
            #[cfg(feature = "ibc-mocks")]
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: "Only Tendermint client state type is \
                                       supported"
                    .to_string(),
            }),
        }
    }
}

#[cfg(feature = "ibc-mocks")]
impl TryFrom<AnyConsensusState> for MockConsensusState {
    type Error = ClientError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Mock(cs) => Ok(cs),
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: "The type should be MockConsensusState"
                    .to_string(),
            }),
        }
    }
}

impl TryFrom<Any> for AnyConsensusState {
    type Error = ClientError;

    fn try_from(consensus_state: Any) -> Result<Self, Self::Error> {
        #[cfg(feature = "ibc-mocks")]
        if let Ok(cs) = MockConsensusState::try_from(consensus_state.clone()) {
            return Ok(cs.into());
        }

        let cs = TmConsensusState::try_from(consensus_state).map_err(|_| {
            ClientError::ClientSpecific {
                description: "Unknown consensus state".to_string(),
            }
        })?;
        Ok(cs.into())
    }
}

impl TryFrom<Vec<u8>> for AnyConsensusState {
    type Error = ClientError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Any::decode(&bytes[..])
            .map_err(ClientError::Decode)?
            .try_into()
    }
}

impl ClientStateCommon for AnyClientState {
    fn verify_consensus_state(
        &self,
        consensus_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.verify_consensus_state(consensus_state)
            }
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => {
                cs.verify_consensus_state(consensus_state)
            }
        }
    }

    fn client_type(&self) -> ClientType {
        match self {
            AnyClientState::Tendermint(cs) => cs.client_type(),
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => cs.client_type(),
        }
    }

    fn latest_height(&self) -> Height {
        match self {
            AnyClientState::Tendermint(cs) => cs.latest_height(),
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => cs.latest_height(),
        }
    }

    fn validate_proof_height(
        &self,
        proof_height: Height,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.validate_proof_height(proof_height)
            }
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => cs.validate_proof_height(proof_height),
        }
    }

    fn verify_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: CommitmentProofBytes,
        proof_upgrade_consensus_state: CommitmentProofBytes,
        root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.verify_upgrade_client(
                upgraded_client_state,
                upgraded_consensus_state,
                proof_upgrade_client,
                proof_upgrade_consensus_state,
                root,
            ),
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => cs.verify_upgrade_client(
                upgraded_client_state,
                upgraded_consensus_state,
                proof_upgrade_client,
                proof_upgrade_consensus_state,
                root,
            ),
        }
    }

    fn verify_membership(
        &self,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: Path,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.verify_membership(prefix, proof, root, path, value)
            }
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => {
                cs.verify_membership(prefix, proof, root, path, value)
            }
        }
    }

    fn verify_non_membership(
        &self,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: Path,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.verify_non_membership(prefix, proof, root, path)
            }
            #[cfg(feature = "ibc-mocks")]
            AnyClientState::Mock(cs) => {
                cs.verify_non_membership(prefix, proof, root, path)
            }
        }
    }
}

#[cfg(not(feature = "ibc-mocks"))]
impl<V> ClientStateValidation<V> for AnyClientState
where
    V: ClientValidationContext + TmValidationContext,
    ClientError: From<<V as CommonContext>::ConversionError>,
{
    fn verify_client_message(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.verify_client_message(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<bool, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.check_for_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn status(
        &self,
        ctx: &V,
        client_id: &ClientId,
    ) -> Result<Status, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.status(ctx, client_id),
        }
    }
}

#[cfg(feature = "ibc-mocks")]
impl<V> ClientStateValidation<V> for AnyClientState
where
    V: ClientValidationContext + TmValidationContext + MockClientContext,
    ClientError: From<<V as CommonContext>::ConversionError>
        + From<
            <<V as MockClientContext>::AnyConsensusState as TryInto<
                MockConsensusState,
            >>::Error,
        >,
{
    fn verify_client_message(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.verify_client_message(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
            AnyClientState::Mock(cs) => cs.verify_client_message(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<bool, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.check_for_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
            AnyClientState::Mock(cs) => cs.check_for_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn status(
        &self,
        ctx: &V,
        client_id: &ClientId,
    ) -> Result<Status, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.status(ctx, client_id),
            AnyClientState::Mock(cs) => cs.status(ctx, client_id),
        }
    }
}

#[cfg(not(feature = "ibc-mocks"))]
impl<E> ClientStateExecution<E> for AnyClientState
where
    E: ExecutionContext + TmExecutionContext,
    <E as ClientExecutionContext>::AnyClientState: From<TmClientState>,
    <E as ClientExecutionContext>::AnyConsensusState: From<TmConsensusState>,
{
    fn initialise(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        consensus_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.initialise(ctx, client_id, consensus_state)
            }
        }
    }

    fn update_state(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        header: Any,
    ) -> Result<Vec<Height>, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.update_state(ctx, client_id, header)
            }
        }
    }

    fn update_state_on_misbehaviour(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_state_on_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn update_state_on_upgrade(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<Height, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_state_on_upgrade(
                ctx,
                client_id,
                upgraded_client_state,
                upgraded_consensus_state,
            ),
        }
    }
}

#[cfg(feature = "ibc-mocks")]
impl<E> ClientStateExecution<E> for AnyClientState
where
    E: ExecutionContext + TmExecutionContext + MockClientContext,
    <E as ClientExecutionContext>::AnyClientState:
        From<TmClientState> + From<MockClientState>,
    <E as ClientExecutionContext>::AnyConsensusState:
        From<TmConsensusState> + From<MockConsensusState>,
{
    fn initialise(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        consensus_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.initialise(ctx, client_id, consensus_state)
            }
            AnyClientState::Mock(cs) => {
                cs.initialise(ctx, client_id, consensus_state)
            }
        }
    }

    fn update_state(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        header: Any,
    ) -> Result<Vec<Height>, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.update_state(ctx, client_id, header)
            }
            AnyClientState::Mock(cs) => cs.update_state(ctx, client_id, header),
        }
    }

    fn update_state_on_misbehaviour(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_state_on_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
            AnyClientState::Mock(cs) => cs.update_state_on_misbehaviour(
                ctx,
                client_id,
                client_message,
                update_kind,
            ),
        }
    }

    fn update_state_on_upgrade(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<Height, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_state_on_upgrade(
                ctx,
                client_id,
                upgraded_client_state,
                upgraded_consensus_state,
            ),
            AnyClientState::Mock(cs) => cs.update_state_on_upgrade(
                ctx,
                client_id,
                upgraded_client_state,
                upgraded_consensus_state,
            ),
        }
    }
}
