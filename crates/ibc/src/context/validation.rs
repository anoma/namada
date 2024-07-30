//! ValidationContext implementation for IBC

use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::core::channel::types::channel::ChannelEnd;
use ibc::core::channel::types::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use ibc::core::channel::types::packet::Receipt;
use ibc::core::client::context::{
    ClientValidationContext, ExtClientValidationContext,
};
use ibc::core::client::types::Height;
use ibc::core::commitment_types::commitment::CommitmentPrefix;
use ibc::core::commitment_types::specs::ProofSpecs;
use ibc::core::connection::types::ConnectionEnd;
use ibc::core::handler::types::error::ContextError;
use ibc::core::host::types::identifiers::{
    ChainId, ClientId, ConnectionId, Sequence,
};
use ibc::core::host::types::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, CommitmentPath,
    ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use ibc::core::host::ValidationContext;
use ibc::cosmos_host::ValidateSelfClientContext;
use ibc::primitives::{Signer, Timestamp};
#[cfg(any(test, feature = "testing"))]
use ibc_testkit::testapp::ibc::clients::mock::client_state::MockClientState;
use namada_state::StorageRead;

use super::client::{AnyClientState, AnyConsensusState};
use super::common::IbcCommonContext;
use super::IbcContext;
use crate::storage;

const COMMITMENT_PREFIX: &[u8] = b"ibc";

impl<C> ExtClientValidationContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        ValidationContext::host_timestamp(self)
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        ValidationContext::host_height(self)
    }

    fn consensus_state_heights(
        &self,
        client_id: &ClientId,
    ) -> Result<Vec<Height>, ContextError> {
        self.inner.borrow().consensus_state_heights(client_id)
    }

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        self.inner.borrow().next_consensus_state(client_id, height)
    }

    fn prev_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        self.inner.borrow().prev_consensus_state(client_id, height)
    }
}

#[cfg(any(test, feature = "testing"))]
use ibc_testkit::testapp::ibc::clients::mock::client_state::MockClientContext;
#[cfg(any(test, feature = "testing"))]
impl<C> MockClientContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        ValidationContext::host_timestamp(self)
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        ValidationContext::host_height(self)
    }
}

impl<C> ClientValidationContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    type ClientStateRef = AnyClientState;
    type ConsensusStateRef = AnyConsensusState;

    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Self::ClientStateRef, ContextError> {
        self.inner.borrow().client_state(client_id)
    }

    fn consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ContextError> {
        let height = Height::new(
            client_cons_state_path.revision_number,
            client_cons_state_path.revision_height,
        )?;
        self.inner
            .borrow()
            .consensus_state(&client_cons_state_path.client_id, height)
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<(Timestamp, Height), ContextError> {
        self.inner.borrow().client_update_meta(client_id)
    }
}

impl<C> ValidationContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    type HostClientState = AnyClientState;
    type HostConsensusState = AnyConsensusState;
    type V = Self;

    fn get_client_validation_context(&self) -> &Self::V {
        self
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        let height = self.inner.borrow().storage().get_block_height()?;
        // the revision number is always 0
        Height::new(0, height.0).map_err(ContextError::ClientError)
    }

    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        self.inner.borrow().host_timestamp()
    }

    fn host_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Self::HostConsensusState, ContextError> {
        self.inner.borrow().host_consensus_state(height)
    }

    fn client_counter(&self) -> Result<u64, ContextError> {
        let key = storage::client_counter_key();
        self.inner.borrow().read_counter(&key)
    }

    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        self.inner.borrow().connection_end(connection_id)
    }

    fn validate_self_client(
        &self,
        client_state_of_host_on_counterparty: Self::HostClientState,
    ) -> Result<(), ContextError> {
        #[cfg(any(test, feature = "testing"))]
        {
            if MockClientState::try_from(
                client_state_of_host_on_counterparty.clone(),
            )
            .is_ok()
            {
                return Ok(());
            }
        }

        let tm_client_state =
            TmClientState::try_from(client_state_of_host_on_counterparty)?;
        ValidateSelfClientContext::validate_self_tendermint_client(
            self,
            tm_client_state.inner().clone(),
        )
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
            .expect("the prefix should be parsable")
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        let key = storage::connection_counter_key();
        self.inner.borrow().read_counter(&key)
    }

    fn channel_end(
        &self,
        path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        self.inner.borrow().channel_end(&path.0, &path.1)
    }

    fn get_next_sequence_send(
        &self,
        path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        self.inner.borrow().get_next_sequence_send(&path.0, &path.1)
    }

    fn get_next_sequence_recv(
        &self,
        path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        self.inner.borrow().get_next_sequence_recv(&path.0, &path.1)
    }

    fn get_next_sequence_ack(
        &self,
        path: &SeqAckPath,
    ) -> Result<Sequence, ContextError> {
        self.inner.borrow().get_next_sequence_ack(&path.0, &path.1)
    }

    fn get_packet_commitment(
        &self,
        path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        self.inner.borrow().packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn get_packet_receipt(
        &self,
        path: &ReceiptPath,
    ) -> Result<Receipt, ContextError> {
        self.inner.borrow().packet_receipt(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn get_packet_acknowledgement(
        &self,
        path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        self.inner.borrow().packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        let key = storage::channel_counter_key();
        self.inner.borrow().read_counter(&key)
    }

    fn max_expected_time_per_block(&self) -> core::time::Duration {
        let height = self
            .inner
            .borrow()
            .storage()
            .get_block_height()
            .expect("The height should exist");

        let estimate =
            namada_parameters::estimate_max_block_time_from_blocks_and_params(
                self.inner.borrow().storage(),
                height,
                // NB: estimate max height with up to 5 blocks in the past,
                // which will not result in too many reads
                5,
            )
            .expect("Failed to estimate max block time");

        // NB: pick a lower max blocktime estimate during tests,
        // to avoid flakes in CI
        #[cfg(any(test, feature = "testing"))]
        let estimate = estimate.min(namada_core::time::DurationSecs(5));

        estimate.into()
    }

    fn validate_message_signer(
        &self,
        _signer: &Signer,
    ) -> Result<(), ContextError> {
        // The signer of a transaction should be validated
        Ok(())
    }
}

impl<C> ValidateSelfClientContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    fn chain_id(&self) -> &ChainId {
        &self.validation_params.chain_id
    }

    fn host_current_height(&self) -> Height {
        let height = self
            .inner
            .borrow()
            .storage()
            .get_block_height()
            .expect("The height should exist");
        Height::new(0, height.0).expect("The conversion shouldn't fail")
    }

    fn proof_specs(&self) -> &ProofSpecs {
        &self.validation_params.proof_specs
    }

    fn unbonding_period(&self) -> core::time::Duration {
        self.validation_params.unbonding_period
    }

    /// Returns the host upgrade path. May be empty.
    fn upgrade_path(&self) -> &[String] {
        &self.validation_params.upgrade_path
    }
}
