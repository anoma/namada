//! AnyClientState and AnyConsensusState for IBC context

use ibc_derive::IbcConsensusState;
#[cfg(feature = "testing")]
use ibc_testkit::testapp::ibc::clients::mock::client_state::ConsensusStateConverter as MockConsensusStateConverter;
#[cfg(feature = "testing")]
use ibc_testkit::testapp::ibc::clients::mock::client_state::MockClientContext;
#[cfg(feature = "testing")]
use ibc_testkit::testapp::ibc::clients::mock::client_state::MockClientState;
#[cfg(feature = "testing")]
use ibc_testkit::testapp::ibc::clients::mock::consensus_state::MockConsensusState;
use namada_core::ibc::clients::tendermint::client_state::ClientState as TmClientState;
use namada_core::ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use namada_core::ibc::clients::tendermint::types::{
    ClientState as TmClientStateType, ConsensusState as TmConsensusStateType,
};
use namada_core::ibc::core::client::context::client_state::{
    ClientStateCommon, ClientStateExecution, ClientStateValidation,
};
use namada_core::ibc::core::client::context::{
    ClientExecutionContext, ClientValidationContext, Convertible,
    ExtClientExecutionContext, ExtClientValidationContext,
};
use namada_core::ibc::core::client::types::error::ClientError;
use namada_core::ibc::core::client::types::{Height, Status};
use namada_core::ibc::core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use namada_core::ibc::core::host::types::identifiers::{ClientId, ClientType};
use namada_core::ibc::core::host::types::path::Path;
use namada_core::ibc::primitives::proto::Any;
use prost::Message;

// TODO: #[derive(ClientState)] doesn't support contexts with contexts generic
// for now
/// ClientState for light clients
#[derive(Debug, Clone)]
pub enum AnyClientState {
    /// Tendermint client state
    Tendermint(TmClientState),

    #[cfg(feature = "testing")]
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
    type Error = ClientError;

    fn try_from(any: AnyClientState) -> Result<Self, Self::Error> {
        match any {
            AnyClientState::Tendermint(cs) => Ok(cs),
            #[cfg(feature = "testing")]
            AnyClientState::Mock(_) => {
                Err(ClientError::UnknownConsensusStateType {
                    consensus_state_type: "mock".to_string(),
                })
            }
        }
    }
}

#[cfg(feature = "testing")]
impl From<MockClientState> for AnyClientState {
    fn from(cs: MockClientState) -> Self {
        Self::Mock(cs)
    }
}

#[cfg(feature = "testing")]
impl TryFrom<AnyClientState> for MockClientState {
    type Error = ClientError;

    fn try_from(any: AnyClientState) -> Result<Self, Self::Error> {
        match any {
            AnyClientState::Tendermint(_) => {
                Err(ClientError::UnknownConsensusStateType {
                    consensus_state_type: "tendermint".to_string(),
                })
            }
            AnyClientState::Mock(cs) => Ok(cs),
        }
    }
}

impl From<AnyClientState> for Any {
    fn from(client_state: AnyClientState) -> Self {
        match client_state {
            AnyClientState::Tendermint(cs) => cs.into(),
            #[cfg(feature = "testing")]
            AnyClientState::Mock(cs) => cs.into(),
        }
    }
}

impl TryFrom<Any> for AnyClientState {
    type Error = ClientError;

    fn try_from(client_state: Any) -> Result<Self, Self::Error> {
        #[cfg(feature = "testing")]
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
#[derive(IbcConsensusState)]
pub enum AnyConsensusState {
    /// Tendermint consensus state
    Tendermint(TmConsensusState),

    #[cfg(feature = "testing")]
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

impl TryInto<TmConsensusStateType> for AnyConsensusState {
    type Error = ClientError;

    fn try_into(self) -> Result<TmConsensusStateType, Self::Error> {
        match self {
            AnyConsensusState::Tendermint(c) => Ok(c.inner().clone()),
            #[cfg(feature = "testing")]
            AnyConsensusState::Mock(_) => {
                Err(ClientError::UnknownConsensusStateType {
                    consensus_state_type: "mock".to_string(),
                })
            }
        }
    }
}

#[cfg(feature = "testing")]
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
            #[cfg(feature = "testing")]
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: "Only Tendermint client state type is \
                                       supported"
                    .to_string(),
            }),
        }
    }
}

#[cfg(feature = "testing")]
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

impl From<AnyConsensusState> for Any {
    fn from(consensus_state: AnyConsensusState) -> Self {
        match consensus_state {
            AnyConsensusState::Tendermint(cs) => cs.into(),
            #[cfg(feature = "testing")]
            AnyConsensusState::Mock(cs) => cs.into(),
        }
    }
}

impl TryFrom<Any> for AnyConsensusState {
    type Error = ClientError;

    fn try_from(consensus_state: Any) -> Result<Self, Self::Error> {
        #[cfg(feature = "testing")]
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
            .map_err(|e| ClientError::Other {
                description: e.to_string(),
            })?
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
            #[cfg(feature = "testing")]
            AnyClientState::Mock(cs) => {
                cs.verify_consensus_state(consensus_state)
            }
        }
    }

    fn client_type(&self) -> ClientType {
        match self {
            AnyClientState::Tendermint(cs) => cs.client_type(),
            #[cfg(feature = "testing")]
            AnyClientState::Mock(cs) => cs.client_type(),
        }
    }

    fn latest_height(&self) -> Height {
        match self {
            AnyClientState::Tendermint(cs) => cs.latest_height(),
            #[cfg(feature = "testing")]
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
            #[cfg(feature = "testing")]
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
            #[cfg(feature = "testing")]
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
            #[cfg(feature = "testing")]
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
            #[cfg(feature = "testing")]
            AnyClientState::Mock(cs) => {
                cs.verify_non_membership(prefix, proof, root, path)
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
impl<V> ClientStateValidation<V> for AnyClientState
where
    V: ExtClientValidationContext,
    <V as ClientValidationContext>::ConsensusStateRef:
        Convertible<TmConsensusStateType, ClientError>,
{
    fn verify_client_message(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.verify_client_message(ctx, client_id, client_message)
            }
        }
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<bool, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.check_for_misbehaviour(ctx, client_id, client_message)
            }
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

    fn check_substitute(
        &self,
        ctx: &V,
        substitute_client_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.check_substitute(ctx, substitute_client_state)
            }
        }
    }
}

#[cfg(feature = "testing")]
impl<V> ClientStateValidation<V> for AnyClientState
where
    V: ExtClientValidationContext + MockClientContext,
    <V as ClientValidationContext>::ConsensusStateRef:
        Convertible<TmConsensusStateType, ClientError>
            + MockConsensusStateConverter,
{
    fn verify_client_message(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.verify_client_message(ctx, client_id, client_message)
            }
            AnyClientState::Mock(cs) => {
                cs.verify_client_message(ctx, client_id, client_message)
            }
        }
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<bool, ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.check_for_misbehaviour(ctx, client_id, client_message)
            }
            AnyClientState::Mock(cs) => {
                cs.check_for_misbehaviour(ctx, client_id, client_message)
            }
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

    fn check_substitute(
        &self,
        ctx: &V,
        substitute_client_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.check_substitute(ctx, substitute_client_state)
            }
            AnyClientState::Mock(cs) => {
                cs.check_substitute(ctx, substitute_client_state)
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
impl<E> ClientStateExecution<E> for AnyClientState
where
    E: ExtClientExecutionContext,
    <E as ClientValidationContext>::ConsensusStateRef:
        Convertible<TmConsensusStateType, ClientError>,
    <E as ClientExecutionContext>::ClientStateMut: From<TmClientStateType>,
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
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.update_state_on_misbehaviour(ctx, client_id, client_message)
            }
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

    fn update_on_recovery(
        &self,
        ctx: &mut E,
        subject_client_id: &ClientId,
        substitute_client_state: Any,
        substitute_consensus_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_on_recovery(
                ctx,
                subject_client_id,
                substitute_client_state,
                substitute_consensus_state,
            ),
        }
    }
}

#[cfg(feature = "testing")]
impl<E> ClientStateExecution<E> for AnyClientState
where
    E: ExtClientExecutionContext + MockClientContext,
    <E as ClientValidationContext>::ConsensusStateRef:
        Convertible<TmConsensusStateType, ClientError>
            + MockConsensusStateConverter,
    <E as ClientExecutionContext>::ClientStateMut:
        From<TmClientStateType> + From<MockClientState>,
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
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => {
                cs.update_state_on_misbehaviour(ctx, client_id, client_message)
            }
            AnyClientState::Mock(cs) => {
                cs.update_state_on_misbehaviour(ctx, client_id, client_message)
            }
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

    fn update_on_recovery(
        &self,
        ctx: &mut E,
        subject_client_id: &ClientId,
        substitute_client_state: Any,
        substitute_consensus_state: Any,
    ) -> Result<(), ClientError> {
        match self {
            AnyClientState::Tendermint(cs) => cs.update_on_recovery(
                ctx,
                subject_client_id,
                substitute_client_state,
                substitute_consensus_state,
            ),
            AnyClientState::Mock(cs) => cs.update_on_recovery(
                ctx,
                subject_client_id,
                substitute_client_state,
                substitute_consensus_state,
            ),
        }
    }
}
