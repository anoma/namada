use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;
use std::str::FromStr;

use borsh::BorshDeserialize;
use ibc::apps::nft_transfer::handler::{
    send_nft_transfer_execute, send_nft_transfer_validate,
};
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::nft_transfer::types::{
    ack_success_b64, PORT_ID_STR as NFT_PORT_ID_STR,
};
use ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::PORT_ID_STR as FT_PORT_ID_STR;
use ibc::core::channel::types::acknowledgement::AcknowledgementStatus;
use ibc::core::channel::types::commitment::compute_ack_commitment;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::entrypoint::{execute, validate};
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use masp_primitives::transaction::Transaction as MaspTransaction;
use namada_core::address::Address;
use namada_core::masp::MaspEpoch;
use namada_state::StorageRead;
use namada_systems::trans_token;

use crate::{
    decode_message, extract_masp_tx_from_packet, is_packet_forward, Error,
    IbcCommonContext, IbcContext, IbcMessage, IbcRouter, ModuleWrapper,
    NftTransferContext, NftTransferError, TokenTransferContext,
    TokenTransferError, ValidationParams,
};

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C, Params, Token>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C, Params>,
    router: IbcRouter<'a>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
    _marker: PhantomData<Token>,
}

impl<'a, C, Params, Token> IbcActions<'a, C, Params, Token>
where
    C: IbcCommonContext,
    Params: namada_systems::parameters::Read<C::Storage>,
    Token: trans_token::Keys,
{
    /// Make new IBC actions
    pub fn new(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
            verifiers,
            _marker: PhantomData,
        }
    }

    /// Add a transfer module to the router
    pub fn add_transfer_module(&mut self, module: impl ModuleWrapper + 'a) {
        self.router.add_transfer_module(module)
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.ctx.validation_params = params;
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute<Transfer: BorshDeserialize>(
        &mut self,
        tx_data: &[u8],
    ) -> Result<(Option<Transfer>, Option<MaspTransaction>), Error> {
        let message = decode_message::<Transfer>(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    self.verifiers.clone(),
                );
                // Add the source to the set of verifiers
                self.verifiers.borrow_mut().insert(
                    Address::from_str(msg.message.packet_data.sender.as_ref())
                        .map_err(|_| {
                            Error::TokenTransfer(TokenTransferError::Other(
                                format!(
                                    "Cannot convert the sender address {}",
                                    msg.message.packet_data.sender
                                ),
                            ))
                        })?,
                );
                self.insert_verifiers()?;
                if msg.transfer.is_some() {
                    token_transfer_ctx.enable_shielded_transfer();
                }
                let port_id = msg.message.port_id_on_a.clone();
                let channel_id = msg.message.chan_id_on_a.clone();
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)?;

                if let Some((_, (epoch, refund_masp_tx))) =
                    msg.transfer.as_ref().zip(msg.refund_masp_tx)
                {
                    self.save_refund_masp_tx(
                        &port_id,
                        &channel_id,
                        epoch,
                        refund_masp_tx,
                    )?;
                }

                Ok((msg.transfer, None))
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::<_, Token>::new(self.ctx.inner.clone());
                if msg.transfer.is_some() {
                    nft_transfer_ctx.enable_shielded_transfer();
                }
                let port_id = msg.message.port_id_on_a.clone();
                let channel_id = msg.message.chan_id_on_a.clone();
                // Add the source to the set of verifiers
                self.verifiers.borrow_mut().insert(
                    Address::from_str(msg.message.packet_data.sender.as_ref())
                        .map_err(|_| {
                            Error::NftTransfer(NftTransferError::Other(
                                format!(
                                    "Cannot convert the sender address {}",
                                    msg.message.packet_data.sender
                                ),
                            ))
                        })?,
                );
                self.insert_verifiers()?;
                send_nft_transfer_execute(
                    &mut self.ctx,
                    &mut nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)?;

                if let Some((_, (epoch, refund_masp_tx))) =
                    msg.transfer.as_ref().zip(msg.refund_masp_tx)
                {
                    self.save_refund_masp_tx(
                        &port_id,
                        &channel_id,
                        epoch,
                        refund_masp_tx,
                    )?;
                }

                Ok((msg.transfer, None))
            }
            IbcMessage::Envelope(envelope) => {
                if let Some(verifier) = get_envelope_verifier(envelope.as_ref())
                {
                    self.verifiers.borrow_mut().insert(
                        Address::from_str(verifier.as_ref()).map_err(|_| {
                            Error::Other(format!(
                                "Cannot convert the address {}",
                                verifier,
                            ))
                        })?,
                    );
                    self.insert_verifiers()?;
                }
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;

                // Extract MASP tx from the memo in the packet if needed
                let masp_tx = match &*envelope {
                    MsgEnvelope::Packet(PacketMsg::Recv(msg))
                        if self
                            .is_receiving_success(msg)?
                            .is_some_and(|ack_succ| ack_succ) =>
                    {
                        extract_masp_tx_from_packet(&msg.packet)
                    }
                    // Check if the refund masp tx is stored when the transfer
                    // failed, i.e. ack with an error or timeout
                    MsgEnvelope::Packet(PacketMsg::Ack(msg)) => {
                        match serde_json::from_slice::<AcknowledgementStatus>(
                            msg.acknowledgement.as_ref(),
                        ) {
                            Ok(ack) if !ack.is_successful() => {
                                let masp_epoch = self.get_masp_epoch()?;
                                self.ctx
                                    .inner
                                    .borrow()
                                    .refund_masp_tx(
                                        &msg.packet.port_id_on_a,
                                        &msg.packet.chan_id_on_a,
                                        msg.packet.seq_on_a,
                                        masp_epoch,
                                    )
                                    .map_err(|e| Error::Context(Box::new(e)))?
                            }
                            _ => None,
                        }
                    }
                    MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => {
                        let masp_epoch = self.get_masp_epoch()?;
                        self.ctx
                            .inner
                            .borrow()
                            .refund_masp_tx(
                                &msg.packet.port_id_on_a,
                                &msg.packet.chan_id_on_a,
                                msg.packet.seq_on_a,
                                masp_epoch,
                            )
                            .map_err(|e| Error::Context(Box::new(e)))?
                    }
                    _ => None,
                };
                Ok((None, masp_tx))
            }
        }
    }

    /// Check the result of receiving the packet by checking the packet
    /// acknowledgement
    pub fn is_receiving_success(
        &self,
        msg: &IbcMsgRecvPacket,
    ) -> Result<Option<bool>, Error> {
        let Some(packet_ack) = self
            .ctx
            .inner
            .borrow()
            .packet_ack(
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
                msg.packet.seq_on_a,
            )
            .map_err(|e| Error::Context(Box::new(e)))?
        else {
            return Ok(None);
        };
        let success_ack_commitment = compute_ack_commitment(
            &AcknowledgementStatus::success(ack_success_b64()).into(),
        );
        Ok(Some(packet_ack == success_ack_commitment))
    }

    /// Validate according to the message in IBC VP
    pub fn validate<Transfer: BorshDeserialize>(
        &self,
        tx_data: &[u8],
    ) -> Result<(), Error> {
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let message = decode_message::<Transfer>(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    verifiers.clone(),
                );
                self.insert_verifiers()?;
                if msg.transfer.is_some() {
                    token_transfer_ctx.enable_shielded_transfer();
                }
                send_transfer_validate(
                    &self.ctx,
                    &token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::<_, Token>::new(self.ctx.inner.clone());
                if msg.transfer.is_some() {
                    nft_transfer_ctx.enable_shielded_transfer();
                }
                send_nft_transfer_validate(
                    &self.ctx,
                    &nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)
            }
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, *envelope)
                    .map_err(|e| Error::Context(Box::new(e)))
            }
        }
    }

    fn insert_verifiers(&self) -> Result<(), Error> {
        let mut ctx = self.ctx.inner.borrow_mut();
        for verifier in self.verifiers.borrow().iter() {
            ctx.insert_verifier(verifier).map_err(Error::Verifier)?;
        }
        Ok(())
    }

    fn save_refund_masp_tx(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        epoch: MaspEpoch,
        refund_masp_tx: MaspTransaction,
    ) -> Result<(), Error> {
        let sequence = self
            .ctx
            .inner
            .borrow()
            .get_last_sequence_send(port_id, channel_id)
            .map_err(|e| Error::Context(Box::new(e)))?;
        self.ctx
            .inner
            .borrow_mut()
            .store_refund_masp_tx(
                port_id,
                channel_id,
                sequence,
                epoch,
                refund_masp_tx,
            )
            .map_err(|e| Error::Context(Box::new(e)))
    }

    fn get_masp_epoch(&self) -> Result<MaspEpoch, Error> {
        let inner = self.ctx.inner.borrow();
        let epoch =
            inner.storage().get_block_epoch().map_err(Error::Storage)?;
        let masp_epoch_multiplier =
            Params::masp_epoch_multiplier(inner.storage())
                .map_err(Error::Storage)?;
        MaspEpoch::try_from_epoch(epoch, masp_epoch_multiplier)
            .map_err(|e| Error::Other(e.to_string()))
    }
}

// Extract the involved namada address from the packet (either sender or
// receiver) to trigger its vp. Returns None if an address could not be found
fn get_envelope_verifier(
    envelope: &MsgEnvelope,
) -> Option<ibc::primitives::Signer> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
            match msg.packet.port_id_on_b.as_str() {
                FT_PORT_ID_STR => {
                    let packet_data =
                        serde_json::from_slice::<PacketData>(&msg.packet.data)
                            .ok()?;
                    if is_packet_forward(&packet_data) {
                        None
                    } else {
                        Some(packet_data.receiver)
                    }
                }
                NFT_PORT_ID_STR => {
                    serde_json::from_slice::<NftPacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.receiver)
                }
                _ => None,
            }
        }
        MsgEnvelope::Packet(PacketMsg::Ack(msg)) => serde_json::from_slice::<
            AcknowledgementStatus,
        >(
            msg.acknowledgement.as_ref(),
        )
        .map_or(None, |ack| {
            if ack.is_successful() {
                None
            } else {
                match msg.packet.port_id_on_a.as_str() {
                    FT_PORT_ID_STR => {
                        serde_json::from_slice::<PacketData>(&msg.packet.data)
                            .ok()
                            .map(|packet_data| packet_data.sender)
                    }
                    NFT_PORT_ID_STR => serde_json::from_slice::<NftPacketData>(
                        &msg.packet.data,
                    )
                    .ok()
                    .map(|packet_data| packet_data.sender),
                    _ => None,
                }
            }
        }),
        MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => {
            match msg.packet.port_id_on_a.as_str() {
                FT_PORT_ID_STR => {
                    serde_json::from_slice::<PacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.sender)
                }
                NFT_PORT_ID_STR => {
                    serde_json::from_slice::<NftPacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.sender)
                }
                _ => None,
            }
        }
        _ => None,
    }
}
