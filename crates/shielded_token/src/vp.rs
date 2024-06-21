//! MASP native VP

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::transparent::Authorization;
use masp_primitives::transaction::components::{
    I128Sum, TxIn, TxOut, ValueSum,
};
use masp_primitives::transaction::{Transaction, TransparentAddress};
use namada_core::address::Address;
use namada_core::arith::{checked, CheckedAdd, CheckedSub};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::borsh::BorshSerializeExt;
use namada_core::collections::HashSet;
use namada_core::ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use namada_core::ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use namada_core::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use namada_core::ibc::apps::transfer::types::packet::PacketData;
use namada_core::masp::{addr_taddr, encode_asset_type, ibc_taddr, MaspEpoch};
use namada_core::storage::Key;
use namada_core::token::MaspDigitPos;
use namada_core::uint::I320;
use namada_core::{governance, parameters, token};
use namada_state::{
    ConversionState, OptionExt, ResultExt, StateRead, StorageError,
};
use namada_trans_token::read_denom;
use namada_tx::action::Read;
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{Ctx, CtxPreStorageRead, NativeVp, VpEvaluator};
use namada_vp::{native_vp, VpEnv};
use ripemd::Digest as RipemdDigest;
use sha2::Digest as Sha2Digest;
use thiserror::Error;
use token::Amount;

use crate::storage_key::{
    is_masp_key, is_masp_nullifier_key, is_masp_token_map_key,
    is_masp_transfer_key, masp_commitment_anchor_key, masp_commitment_tree_key,
    masp_convert_anchor_key, masp_nullifier_key,
};
use crate::validation::verify_shielded_tx;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("MASP VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// MASP VP result
pub type Result<T> = std::result::Result<T, Error>;

/// MASP VP
pub struct MaspVp<'ctx, S, CA, EVAL, Params, Gov>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Generic types for DI
    pub _marker: PhantomData<(Params, Gov)>,
}

// The balances changed by the transaction, split between masp and non-masp
// balances. The masp collection carries the token addresses. The collection of
// the other balances maps the token address to the addresses of the
// senders/receivers, their balance diff and whether this is positive or
// negative diff
#[derive(Default, Debug, Clone)]
struct ChangedBalances {
    tokens: BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    decoder: BTreeMap<TransparentAddress, TAddrData>,
    pre: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
    post: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
}

struct IbcTransferInfo {
    src_port_id: PortId,
    src_channel_id: ChannelId,
    timeout_height: TimeoutHeight,
    timeout_timestamp: Timestamp,
    packet_data: Vec<u8>,
    ibc_traces: Vec<String>,
    amount: Amount,
    receiver: String,
}

impl TryFrom<IbcMsgTransfer> for IbcTransferInfo {
    type Error = Error;

    fn try_from(
        message: IbcMsgTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(native_vp::Error::new)?;
        let ibc_traces = vec![message.packet_data.token.denom.to_string()];
        let amount = message
            .packet_data
            .token
            .amount
            .try_into()
            .into_storage_result()?;
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount,
            receiver,
        })
    }
}

impl TryFrom<IbcMsgNftTransfer> for IbcTransferInfo {
    type Error = Error;

    fn try_from(
        message: IbcMsgNftTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(native_vp::Error::new)?;
        let ibc_traces = message
            .packet_data
            .token_ids
            .0
            .iter()
            .map(|token_id| {
                ibc_trace_for_nft(&message.packet_data.class_id, token_id)
            })
            .collect();
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount: Amount::from_u64(1),
            receiver,
        })
    }
}

impl<'view, 'ctx: 'view, S, CA, EVAL, Params, Gov>
    MaspVp<'ctx, S, CA, EVAL, Params, Gov>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    Params: parameters::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = StorageError,
        >,
    Gov: governance::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = StorageError,
        >,
{
    /// Instantiate MASP VP
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self {
            ctx,
            _marker: PhantomData,
        }
    }

    /// Return if the parameter change was done via a governance proposal
    pub fn is_valid_parameter_change(
        &'view self,
        tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        tx.tx.data(tx.cmt).map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "MASP parameter changes require tx data to be present",
                )
                .into())
            },
            |data| {
                Gov::is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "MASP parameter changes can only be performed by \
                             a governance proposal that has been accepted",
                        )
                        .into()
                    })
            },
        )
    }

    // Check that the transaction correctly revealed the nullifiers, if needed
    fn valid_nullifiers_reveal(
        &self,
        keys_changed: &BTreeSet<Key>,
        transaction: &Transaction,
    ) -> Result<()> {
        // Support set to check that a nullifier was not revealed more
        // than once in the same tx
        let mut revealed_nullifiers = HashSet::new();

        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let nullifier_key = masp_nullifier_key(&description.nullifier);
            if self.ctx.has_key_pre(&nullifier_key)?
                || revealed_nullifiers.contains(&nullifier_key)
            {
                let error = native_vp::Error::new_alloc(format!(
                    "MASP double spending attempt, the nullifier {:?} has \
                     already been revealed previously",
                    description.nullifier.0,
                ))
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }

            // Check that the nullifier is indeed committed (no temp write
            // and no delete) and carries no associated data (the latter not
            // strictly necessary for validation, but we don't expect any
            // value for this key anyway)
            self.ctx
                .read_bytes_post(&nullifier_key)?
                .is_some_and(|value| value.is_empty())
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::new_const(
                        "The nullifier should have been committed with no \
                         associated data",
                    ))
                })?;

            revealed_nullifiers.insert(nullifier_key);
        }

        // Check that no unneeded nullifier has been revealed
        for nullifier_key in
            keys_changed.iter().filter(|key| is_masp_nullifier_key(key))
        {
            if !revealed_nullifiers.contains(nullifier_key) {
                let error = native_vp::Error::new_alloc(format!(
                    "An unexpected MASP nullifier key {nullifier_key} has \
                     been revealed by the transaction"
                ))
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Check that a transaction carrying output descriptions correctly updates
    // the tree and anchor in storage
    fn valid_note_commitment_update(
        &self,
        transaction: &Transaction,
    ) -> Result<()> {
        // Check that the merkle tree in storage has been correctly updated with
        // the output descriptions cmu
        let tree_key = masp_commitment_tree_key();
        let mut previous_tree: CommitmentTree<Node> =
            self.ctx.read_pre(&tree_key)?.ok_or(Error::NativeVpError(
                native_vp::Error::SimpleMessage("Cannot read storage"),
            ))?;
        let post_tree: CommitmentTree<Node> =
            self.ctx.read_post(&tree_key)?.ok_or(Error::NativeVpError(
                native_vp::Error::SimpleMessage("Cannot read storage"),
            ))?;

        // Based on the output descriptions of the transaction, update the
        // previous tree in storage
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_outputs)
        {
            previous_tree
                .append(Node::from_scalar(description.cmu))
                .map_err(|()| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Failed to update the commitment tree",
                    ))
                })?;
        }
        // Check that the updated previous tree matches the actual post tree.
        // This verifies that all and only the necessary notes have been
        // appended to the tree
        if previous_tree != post_tree {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "The note commitment tree was incorrectly updated",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }

        Ok(())
    }

    // Check that the spend descriptions anchors of a transaction are valid
    fn valid_spend_descriptions_anchor(
        &self,
        transaction: &Transaction,
    ) -> Result<()> {
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let anchor_key = masp_commitment_anchor_key(description.anchor);

            // Check if the provided anchor was published before
            if !self.ctx.has_key_pre(&anchor_key)? {
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Spend description refers to an invalid anchor",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Check that the convert descriptions anchors of a transaction are valid
    fn valid_convert_descriptions_anchor(
        &'view self,
        transaction: &Transaction,
    ) -> Result<()> {
        if let Some(bundle) = transaction.sapling_bundle() {
            if !bundle.shielded_converts.is_empty() {
                let anchor_key = masp_convert_anchor_key();
                let expected_anchor = self
                    .ctx
                    .read_pre::<namada_core::hash::Hash>(&anchor_key)?
                    .ok_or(Error::NativeVpError(
                        native_vp::Error::SimpleMessage("Cannot read storage"),
                    ))?;

                for description in &bundle.shielded_converts {
                    // Check if the provided anchor matches the current
                    // conversion tree's one
                    if namada_core::hash::Hash(description.anchor.to_bytes())
                        != expected_anchor
                    {
                        let error = Error::NativeVpError(
                            native_vp::Error::SimpleMessage(
                                "Convert description refers to an invalid \
                                 anchor",
                            ),
                        );
                        tracing::debug!("{error}");
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }

    fn check_ibc_transfer(
        &self,
        ibc_transfer: &IbcTransferInfo,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<()> {
        let IbcTransferInfo {
            src_port_id,
            src_channel_id,
            timeout_height,
            timeout_timestamp,
            packet_data,
            ..
        } = ibc_transfer;
        let sequence = get_last_sequence_send(
            &self.ctx.post(),
            src_port_id,
            src_channel_id,
        )?;
        let commitment_key =
            commitment_key(src_port_id, src_channel_id, sequence);

        if !keys_changed.contains(&commitment_key) {
            return Err(Error::NativeVpError(native_vp::Error::AllocMessage(
                format!(
                    "Expected IBC transfer didn't happen: Port ID \
                     {src_port_id}, Channel ID {src_channel_id}, Sequence \
                     {sequence}"
                ),
            )));
        }

        // The commitment is also validated in IBC VP. Make sure that for when
        // IBC VP isn't triggered.
        let actual: PacketCommitment = self
            .ctx
            .read_bytes_post(&commitment_key)?
            .ok_or(Error::NativeVpError(native_vp::Error::AllocMessage(
                format!(
                    "Packet commitment doesn't exist: Port ID  {src_port_id}, \
                     Channel ID {src_channel_id}, Sequence {sequence}"
                ),
            )))?
            .into();
        let expected = compute_packet_commitment(
            packet_data,
            timeout_height,
            timeout_timestamp,
        );
        if actual != expected {
            return Err(Error::NativeVpError(native_vp::Error::AllocMessage(
                format!(
                    "Packet commitment mismatched: Port ID {src_port_id}, \
                     Channel ID {src_channel_id}, Sequence {sequence}"
                ),
            )));
        }

        Ok(())
    }

    fn check_packet_receiving(
        &self,
        msg: &IbcMsgRecvPacket,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<()> {
        let receipt_key = receipt_key(
            &msg.packet.port_id_on_b,
            &msg.packet.chan_id_on_b,
            msg.packet.seq_on_a,
        );
        if !keys_changed.contains(&receipt_key) {
            return Err(Error::NativeVpError(native_vp::Error::AllocMessage(
                format!(
                    "The packet has not been received: Port ID  {}, Channel \
                     ID {}, Sequence {}",
                    msg.packet.port_id_on_b,
                    msg.packet.chan_id_on_b,
                    msg.packet.seq_on_a,
                ),
            )));
        }
        Ok(())
    }

    // Apply the given transfer message to the changed balances structure
    fn apply_transfer_msg(
        &self,
        mut acc: ChangedBalances,
        ibc_transfer: &IbcTransferInfo,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<ChangedBalances> {
        self.check_ibc_transfer(ibc_transfer, keys_changed)?;

        let IbcTransferInfo {
            ibc_traces,
            src_port_id,
            src_channel_id,
            amount,
            receiver,
            ..
        } = ibc_transfer;

        let receiver = ibc_taddr(receiver.clone());
        for ibc_trace in ibc_traces {
            let token = convert_to_address(ibc_trace).into_storage_result()?;
            let delta = ValueSum::from_pair(token, *amount);
            // If there is a transfer to the IBC account, then deduplicate the
            // balance increase since we already accounted for it above
            if is_sender_chain_source(ibc_trace, src_port_id, src_channel_id) {
                let ibc_taddr = addr_taddr(IBC);
                let post_entry = acc
                    .post
                    .get(&ibc_taddr)
                    .cloned()
                    .unwrap_or(ValueSum::zero());
                acc.post.insert(
                    ibc_taddr,
                    checked!(post_entry - &delta)
                        .map_err(native_vp::Error::new)?,
                );
            }
            // Record an increase to the balance of a specific IBC receiver
            let post_entry =
                acc.post.get(&receiver).cloned().unwrap_or(ValueSum::zero());
            acc.post.insert(
                receiver,
                checked!(post_entry + &delta).map_err(native_vp::Error::new)?,
            );
        }

        Ok(acc)
    }

    // Check if IBC message was received successfully in this state transition
    fn is_receiving_success(
        &self,
        dst_port_id: &PortId,
        dst_channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<bool> {
        // Ensure that the event corresponds to the current changes to storage
        let ack_key = storage::ack_key(dst_port_id, dst_channel_id, sequence);
        // If the receive is a success, then the commitment is unique
        let succ_ack_commitment = compute_ack_commitment(
            &AcknowledgementStatus::success(ack_success_b64()).into(),
        );
        Ok(match self.ctx.read_bytes_post(&ack_key)? {
            // Success happens only if commitment equals the above
            Some(value) => {
                AcknowledgementCommitment::from(value) == succ_ack_commitment
            }
            // Acknowledgement key non-existence is failure
            None => false,
        })
    }

    // Apply the given write acknowledge to the changed balances structure
    fn apply_recv_msg(
        &self,
        mut acc: ChangedBalances,
        msg: &IbcMsgRecvPacket,
        ibc_traces: Vec<String>,
        amount: Amount,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<ChangedBalances> {
        self.check_packet_receiving(msg, keys_changed)?;

        // If the transfer was a failure, then enable funds to
        // be withdrawn from the IBC internal address
        if self.is_receiving_success(
            &msg.packet.port_id_on_b,
            &msg.packet.chan_id_on_b,
            msg.packet.seq_on_a,
        )? {
            for ibc_trace in ibc_traces {
                // Get the received token
                let token = namada_ibc::received_ibc_token(
                    ibc_trace,
                    &msg.packet.port_id_on_a,
                    &msg.packet.chan_id_on_a,
                    &msg.packet.port_id_on_b,
                    &msg.packet.chan_id_on_b,
                )
                .into_storage_result()
                .map_err(Error::NativeVpError)?;
                let delta = ValueSum::from_pair(token.clone(), amount);
                // Enable funds to be taken from the IBC internal
                // address and be deposited elsewhere
                // Required for the IBC internal Address to release
                // funds
                let ibc_taddr = addr_taddr(IBC);
                let pre_entry = acc
                    .pre
                    .get(&ibc_taddr)
                    .cloned()
                    .unwrap_or(ValueSum::zero());
                acc.pre.insert(
                    ibc_taddr,
                    checked!(pre_entry + &delta)
                        .map_err(native_vp::Error::new)?,
                );
            }
        }
        Ok(acc)
    }

    // Apply relevant IBC packets to the changed balances structure
    fn apply_ibc_packet(
        &self,
        mut acc: ChangedBalances,
        ibc_msg: IbcMessage,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<ChangedBalances> {
        match ibc_msg {
            // This event is emitted on the sender
            IbcMessage::Transfer(msg) => {
                // Get the packet commitment from post-storage that corresponds
                // to this event
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                acc.decoder.insert(ibc_taddr(receiver), addr);
                acc =
                    self.apply_transfer_msg(acc, &ibc_transfer, keys_changed)?;
            }
            IbcMessage::NftTransfer(msg) => {
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                acc.decoder.insert(ibc_taddr(receiver), addr);
                acc =
                    self.apply_transfer_msg(acc, &ibc_transfer, keys_changed)?;
            }
            // This event is emitted on the receiver
            IbcMessage::Envelope(envelope) => {
                if let MsgEnvelope::Packet(PacketMsg::Recv(msg)) = *envelope {
                    if msg.packet.port_id_on_b.as_str() == PORT_ID_STR {
                        let packet_data = serde_json::from_slice::<PacketData>(
                            &msg.packet.data,
                        )
                        .map_err(native_vp::Error::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        acc.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_denom = packet_data.token.denom.to_string();
                        let amount = packet_data
                            .token
                            .amount
                            .try_into()
                            .into_storage_result()?;
                        acc = self.apply_recv_msg(
                            acc,
                            &msg,
                            vec![ibc_denom],
                            amount,
                            keys_changed,
                        )?;
                    } else {
                        let packet_data =
                            serde_json::from_slice::<NftPacketData>(
                                &msg.packet.data,
                            )
                            .map_err(native_vp::Error::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        acc.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_traces = packet_data
                            .token_ids
                            .0
                            .iter()
                            .map(|token_id| {
                                ibc_trace_for_nft(
                                    &packet_data.class_id,
                                    token_id,
                                )
                            })
                            .collect();
                        acc = self.apply_recv_msg(
                            acc,
                            &msg,
                            ibc_traces,
                            Amount::from_u64(1),
                            keys_changed,
                        )?;
                    }
                }
            }
        }
        Result::<_>::Ok(acc)
    }

    // Apply the balance change to the changed balances structure
    fn apply_balance_change(
        &self,
        mut result: ChangedBalances,
        [token, counterpart]: [&Address; 2],
    ) -> Result<ChangedBalances> {
        let denom = read_denom(&self.ctx.pre(), token)?.ok_or_err_msg(
            "No denomination found in storage for the given token",
        )?;
        // Record the token without an epoch to facilitate later decoding
        unepoched_tokens(token, denom, &mut result.tokens)?;
        let counterpart_balance_key = balance_key(token, counterpart);
        let pre_balance: Amount = self
            .ctx
            .read_pre(&counterpart_balance_key)?
            .unwrap_or_default();
        let post_balance: Amount = self
            .ctx
            .read_post(&counterpart_balance_key)?
            .unwrap_or_default();
        // Public keys must be the hash of the sources/targets
        let addr_hash = addr_taddr(counterpart.clone());
        // Enable the decoding of these counterpart addresses
        result
            .decoder
            .insert(addr_hash, TAddrData::Addr(counterpart.clone()));
        let zero = ValueSum::zero();
        // Finally record the actual balance change starting with the initial
        // state
        let pre_entry = result.pre.get(&addr_hash).unwrap_or(&zero).clone();
        result.pre.insert(
            addr_hash,
            checked!(
                pre_entry + &ValueSum::from_pair((*token).clone(), pre_balance)
            )
            .map_err(native_vp::Error::new)?,
        );
        // And then record the final state
        let post_entry = result.post.get(&addr_hash).cloned().unwrap_or(zero);
        result.post.insert(
            addr_hash,
            checked!(
                post_entry
                    + &ValueSum::from_pair((*token).clone(), post_balance)
            )
            .map_err(native_vp::Error::new)?,
        );
        Result::<_>::Ok(result)
    }

    // Check that transfer is pinned correctly and record the balance changes
    fn validate_state_and_get_transfer_data(
        &self,
        keys_changed: &BTreeSet<Key>,
        ibc_msg: Option<IbcMessage>,
    ) -> Result<ChangedBalances> {
        // Get the changed balance keys
        let mut counterparts_balances =
            keys_changed.iter().filter_map(is_any_token_balance_key);

        // Apply the balance changes to the changed balances structure
        let mut changed_balances = counterparts_balances
            .try_fold(ChangedBalances::default(), |acc, account| {
                self.apply_balance_change(acc, account)
            })?;

        let ibc_addr = TAddrData::Addr(IBC);
        // Enable decoding the IBC address hash
        changed_balances.decoder.insert(addr_taddr(IBC), ibc_addr);

        // Note the balance changes they imply
        match ibc_msg {
            Some(ibc_msg) => {
                self.apply_ibc_packet(changed_balances, ibc_msg, keys_changed)
            }
            None => Ok(changed_balances),
        }
    }

    // Check that MASP Transaction and state changes are valid
    fn is_valid_masp_transfer(
        &'view self,
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let masp_epoch_multiplier =
            Params::masp_epoch_multiplier(&self.ctx.pre())?;
        let masp_epoch = MaspEpoch::try_from_epoch(
            self.ctx.get_block_epoch()?,
            masp_epoch_multiplier,
        )
        .map_err(|msg| {
            Error::NativeVpError(native_vp::Error::new_const(msg))
        })?;
        let conversion_state = self.ctx.state.in_mem().get_conversion_state();
        let ibc_msg = self.ctx.get_ibc_message(tx_data).ok();
        let actions = self.ctx.read_actions()?;
        let shielded_tx =
            if let Some(IbcMessage::Envelope(ref envelope)) = ibc_msg {
                extract_masp_tx_from_envelope(envelope).ok_or_else(|| {
                    native_vp::Error::new_const(
                        "Missing MASP transaction in IBC message",
                    )
                })?
            } else {
                // Get the Transaction object from the actions
                let masp_section_ref =
                    namada_tx::action::get_masp_section_ref(&actions)
                        .ok_or_else(|| {
                            native_vp::Error::new_const(
                                "Missing MASP section reference in action",
                            )
                        })?;
                tx_data
                    .tx
                    .get_masp_section(&masp_section_ref)
                    .cloned()
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "Missing MASP section in transaction",
                        )
                    })?
            };

        if u64::from(self.ctx.get_block_height()?)
            > u64::from(shielded_tx.expiry_height())
        {
            let error =
                native_vp::Error::new_const("MASP transaction is expired")
                    .into();
            tracing::debug!("{error}");
            return Err(error);
        }

        // Check the validity of the keys and get the transfer data
        let changed_balances =
            self.validate_state_and_get_transfer_data(keys_changed, ibc_msg)?;

        // Some constants that will be used repeatedly
        let zero = ValueSum::zero();
        let masp_address_hash = addr_taddr(MASP);
        verify_sapling_balancing_value(
            changed_balances
                .pre
                .get(&masp_address_hash)
                .unwrap_or(&zero),
            changed_balances
                .post
                .get(&masp_address_hash)
                .unwrap_or(&zero),
            &shielded_tx.sapling_value_balance(),
            masp_epoch,
            &changed_balances.tokens,
            conversion_state,
        )?;

        // The set of addresses that are required to authorize this transaction
        let mut authorizers = BTreeSet::new();

        // Checks on the sapling bundle
        // 1. The spend descriptions' anchors are valid
        // 2. The convert descriptions's anchors are valid
        // 3. The nullifiers provided by the transaction have not been
        // revealed previously (even in the same tx) and no unneeded
        // nullifier is being revealed by the tx
        // 4. The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions
        self.valid_spend_descriptions_anchor(&shielded_tx)?;
        self.valid_convert_descriptions_anchor(&shielded_tx)?;
        self.valid_nullifiers_reveal(keys_changed, &shielded_tx)?;
        self.valid_note_commitment_update(&shielded_tx)?;

        // Checks on the transparent bundle, if present
        let mut changed_bals_minus_txn = changed_balances.clone();
        validate_transparent_bundle(
            &shielded_tx,
            &mut changed_bals_minus_txn,
            masp_epoch,
            conversion_state,
            &mut authorizers,
        )?;

        // Ensure that every account for which balance has gone down as a result
        // of the Transaction has authorized this transaction
        for (addr, minus_txn_pre) in changed_bals_minus_txn.pre {
            // The pre-balance seen by all VPs including this one
            let pre = changed_balances.pre.get(&addr).unwrap_or(&zero);
            // The post-balance seen by all VPs including this one
            let post = changed_balances.post.get(&addr).unwrap_or(&zero);
            // The post-balance if the effects of the Transaction are removed
            let minus_txn_post =
                changed_bals_minus_txn.post.get(&addr).unwrap_or(&zero);
            // Never require a signature from the MASP VP
            if addr != masp_address_hash &&
            // Only require further authorization if without the Transaction,
            // this Tx would decrease the balance of this address
                minus_txn_post < &minus_txn_pre &&
            // Only require further authorization from this address if the
            // Transaction alters its balance
                (minus_txn_pre, minus_txn_post) != (pre.clone(), post)
            {
                // This address will need to provide further authorization
                authorizers.insert(addr);
            }
        }

        let mut actions_authorizers: HashSet<&Address> = actions
            .iter()
            .filter_map(|action| {
                if let namada_tx::action::Action::Masp(
                    namada_tx::action::MaspAction::MaspAuthorizer(addr),
                ) = action
                {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect();
        // Ensure that this transaction is authorized by all involved parties
        for authorizer in authorizers {
            if let Some(TAddrData::Addr(IBC)) =
                changed_bals_minus_txn.decoder.get(&authorizer)
            {
                // If the IBC address is a signatory, then it means that either
                // Tx - Transaction(s) causes a decrease in the IBC balance or
                // one of the Transactions' transparent inputs is the IBC. We
                // can't check whether such an action has been authorized by the
                // original sender since their address is not in this Namada
                // instance. However, we do know that the overall changes in the
                // IBC state are okay since the IBC VP does check this
                // transaction. So the best we can do is just to ensure that
                // funds intended for the IBC are not being siphoned from the
                // Transactions inside this Tx. We achieve this by not allowing
                // the IBC to be in the transparent output of any of the
                // Transaction(s).
                if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                    for vout in transp_bundle.vout.iter() {
                        if let Some(TAddrData::Ibc(_)) =
                            changed_bals_minus_txn.decoder.get(&vout.address)
                        {
                            let error = native_vp::Error::new_const(
                                "Simultaneous credit and debit of IBC account \
                                 in a MASP transaction not allowed",
                            )
                            .into();
                            tracing::debug!("{error}");
                            return Err(error);
                        }
                    }
                }
            } else if let Some(TAddrData::Addr(signer)) =
                changed_bals_minus_txn.decoder.get(&authorizer)
            {
                // Otherwise the owner's vp must have been triggered and the
                // relative action must have been written
                if !verifiers.contains(signer) {
                    let error = native_vp::Error::new_alloc(format!(
                        "The required vp of address {signer} was not triggered"
                    ))
                    .into();
                    tracing::debug!("{error}");
                    return Err(error);
                }

                // The action is required becuse the target vp might have been
                // triggered for other reasons but we need to signal it that it
                // is required to validate a discrepancy in its balance change
                // because of a masp transaction, which might require a
                // different validation than a normal balance change
                if !actions_authorizers.swap_remove(signer) {
                    let error = native_vp::Error::new_alloc(format!(
                        "The required masp authorizer action for address \
                         {signer} is missing"
                    ))
                    .into();
                    tracing::debug!("{error}");
                    return Err(error);
                }
            } else {
                // We are not able to decode the authorizer, so just fail
                let error = native_vp::Error::new_const(
                    "Unable to decode a transaction authorizer",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
        }
        // The transaction shall not push masp authorizer actions that are not
        // needed cause this might lead vps to run a wrong validation logic
        if !actions_authorizers.is_empty() {
            let error = native_vp::Error::new_const(
                "Found masp authorizer actions that are not required",
            )
            .into();
            tracing::debug!("{error}");
            return Err(error);
        }

        // Verify the proofs
        verify_shielded_tx(&shielded_tx, |gas| self.ctx.charge_gas(gas))
            .map_err(Error::NativeVpError)
    }
}

// Make a map to help recognize asset types lacking an epoch
fn unepoched_tokens(
    token: &Address,
    denom: token::Denomination,
    tokens: &mut BTreeMap<
        AssetType,
        (Address, token::Denomination, MaspDigitPos),
    >,
) -> Result<()> {
    for digit in MaspDigitPos::iter() {
        let asset_type = encode_asset_type(token.clone(), denom, digit, None)
            .wrap_err("unable to create asset type")?;
        tokens.insert(asset_type, (token.clone(), denom, digit));
    }
    Ok(())
}

fn validate_transparent_input<A: Authorization>(
    vin: &TxIn<A>,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
    authorizers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    // A decrease in the balance of an account needs to be
    // authorized by the account of this transparent input
    authorizers.insert(vin.address);
    // Non-masp sources add to the transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_add(
            &I128Sum::from_nonnegative(vin.asset_type, i128::from(vin.value))
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Overflow in input sum")?;

    let bal_ref = changed_balances
        .pre
        .entry(vin.address)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&vin.asset_type) {
        // Note how the asset's epoch must be equal to the present: users
        // must never be allowed to backdate transparent inputs to a
        // transaction for they would then be able to claim rewards while
        // locking their assets for negligible time periods.
        Some(asset) if asset.epoch == epoch => {
            let amount = token::Amount::from_masp_denominated(
                vin.value,
                asset.digit_pos,
            );
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(asset.token.clone(), amount))
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances.tokens.contains_key(&vin.asset_type) => {
            let (token, denom, digit) =
                &changed_balances.tokens[&vin.asset_type];
            // Determine what the asset type would be if it were epoched
            let epoched_asset_type =
                encode_asset_type(token.clone(), *denom, *digit, Some(epoch))
                    .wrap_err("unable to create asset type")?;
            if conversion_state.assets.contains_key(&epoched_asset_type) {
                // If such an epoched asset type is available in the
                // conversion tree, then we must reject the unepoched
                // variant
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "epoch is missing from asset type",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            } else {
                // Otherwise note the contribution to this transparent input
                let amount =
                    token::Amount::from_masp_denominated(vin.value, *digit);
                *bal_ref = bal_ref
                    .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                    .ok_or_else(|| {
                        Error::NativeVpError(native_vp::Error::SimpleMessage(
                            "Overflow in bundle balance",
                        ))
                    })?;
            }
        }
        // unrecognized asset
        _ => {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Unable to decode asset type",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
}

fn validate_transparent_output(
    out: &TxOut,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
) -> Result<()> {
    // Non-masp destinations subtract from transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_sub(
            &I128Sum::from_nonnegative(out.asset_type, i128::from(out.value))
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Underflow in output subtraction")?;

    let bal_ref = changed_balances
        .post
        .entry(out.address)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&out.asset_type) {
        Some(asset) if asset.epoch <= epoch => {
            let amount = token::Amount::from_masp_denominated(
                out.value,
                asset.digit_pos,
            );
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(asset.token.clone(), amount))
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances.tokens.contains_key(&out.asset_type) => {
            // Otherwise note the contribution to this transparent output
            let (token, _denom, digit) =
                &changed_balances.tokens[&out.asset_type];
            let amount =
                token::Amount::from_masp_denominated(out.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // unrecognized asset
        _ => {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Unable to decode asset type",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
}

// Update the transaction value pool and also ensure that the Transaction is
// consistent with the balance changes. I.e. the transparent inputs are not more
// than the initial balances and that the transparent outputs are not more than
// the final balances. Also ensure that the sapling value balance is exactly 0.
fn validate_transparent_bundle(
    shielded_tx: &Transaction,
    changed_balances: &mut ChangedBalances,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
    authorizers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    // The Sapling value balance adds to the transparent tx pool
    let mut transparent_tx_pool = shielded_tx.sapling_value_balance();

    if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
        for vin in transp_bundle.vin.iter() {
            validate_transparent_input(
                vin,
                changed_balances,
                &mut transparent_tx_pool,
                epoch,
                conversion_state,
                authorizers,
            )?;
        }

        for out in transp_bundle.vout.iter() {
            validate_transparent_output(
                out,
                changed_balances,
                &mut transparent_tx_pool,
                epoch,
                conversion_state,
            )?;
        }
    }

    // Ensure that the shielded transaction exactly balances
    match transparent_tx_pool.partial_cmp(&I128Sum::zero()) {
        None | Some(Ordering::Less) => {
            let error = native_vp::Error::new_const(
                "Transparent transaction value pool must be nonnegative. \
                 Violation may be caused by transaction being constructed in \
                 previous epoch. Maybe try again.",
            )
            .into();
            tracing::debug!("{error}");
            // The remaining value in the transparent transaction value pool
            // MUST be nonnegative.
            Err(error)
        }
        Some(Ordering::Greater) => {
            let error = native_vp::Error::new_const(
                "Transaction fees cannot be left on the MASP balance.",
            )
            .into();
            tracing::debug!("{error}");
            Err(error)
        }
        _ => Ok(()),
    }
}

// Apply the given Sapling value balance component to the accumulator
fn apply_balance_component(
    acc: &ValueSum<Address, I320>,
    val: i128,
    digit: MaspDigitPos,
    address: Address,
) -> Result<ValueSum<Address, I320>> {
    // Put val into the correct digit position
    let decoded_change =
        I320::from_masp_denominated(val, digit).map_err(|_| {
            Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Overflow in MASP value balance",
            ))
        })?;
    // Tag the numerical change with the token type
    let decoded_change = ValueSum::from_pair(address, decoded_change);
    // Apply the change to the accumulator
    acc.checked_add(&decoded_change).ok_or_else(|| {
        Error::NativeVpError(native_vp::Error::SimpleMessage(
            "Overflow in MASP value balance",
        ))
    })
}

// Verify that the pre balance + the Sapling value balance = the post balance
// using the decodings in tokens and conversion_state for assistance.
fn verify_sapling_balancing_value(
    pre: &ValueSum<Address, Amount>,
    post: &ValueSum<Address, Amount>,
    sapling_value_balance: &I128Sum,
    target_epoch: MaspEpoch,
    tokens: &BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    conversion_state: &ConversionState,
) -> Result<()> {
    let mut acc = ValueSum::<Address, I320>::from_sum(post.clone());
    for (asset_type, val) in sapling_value_balance.components() {
        // Only assets with at most the target timestamp count
        match conversion_state.assets.get(asset_type) {
            Some(asset) if asset.epoch <= target_epoch => {
                acc = apply_balance_component(
                    &acc,
                    *val,
                    asset.digit_pos,
                    asset.token.clone(),
                )?;
            }
            None if tokens.contains_key(asset_type) => {
                let (token, _denom, digit) = &tokens[asset_type];
                acc =
                    apply_balance_component(&acc, *val, *digit, token.clone())?;
            }
            _ => {
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Unable to decode asset type",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }
    }
    if acc == ValueSum::from_sum(pre.clone()) {
        Ok(())
    } else {
        let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
            "MASP balance change not equal to Sapling value balance",
        ));
        tracing::debug!("{error}");
        Err(error)
    }
}

impl<'view, 'ctx: 'view, S, CA, EVAL, Params, Gov> NativeVp<'view>
    for MaspVp<'ctx, S, CA, EVAL, Params, Gov>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    Params: parameters::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = StorageError,
        >,
    Gov: governance::Read<
            CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>,
            Err = StorageError,
        >,
{
    type Error = Error;

    fn validate_tx(
        &'view self,
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let masp_keys_changed: Vec<&Key> =
            keys_changed.iter().filter(|key| is_masp_key(key)).collect();
        let non_allowed_changes = masp_keys_changed.iter().any(|key| {
            !is_masp_transfer_key(key) && !is_masp_token_map_key(key)
        });

        let masp_token_map_changed = masp_keys_changed
            .iter()
            .any(|key| is_masp_token_map_key(key));
        let masp_transfer_changes = masp_keys_changed
            .iter()
            .any(|key| is_masp_transfer_key(key));
        // Check that the transaction didn't write unallowed masp keys
        if non_allowed_changes {
            Err(Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Found modifications to non-allowed masp keys",
            )))
        } else if masp_token_map_changed && masp_transfer_changes {
            Err(Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Cannot simultaneously do governance proposal and MASP \
                 transfer",
            )))
        } else if masp_token_map_changed {
            // The token map can only be changed by a successful governance
            // proposal
            self.is_valid_parameter_change(tx_data)
        } else if masp_transfer_changes {
            // The MASP transfer keys can only be changed by a valid Transaction
            self.is_valid_masp_transfer(tx_data, keys_changed, verifiers)
        } else {
            // Changing no MASP keys at all is also fine
            Ok(())
        }
    }
}
