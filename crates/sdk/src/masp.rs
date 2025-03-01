//! MASP verification wrappers.

mod utilities;

use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::Transaction;
use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::masp::MaspEpoch;
use namada_core::time::DurationSecs;
use namada_core::token::{Denomination, MaspDigitPos};
use namada_events::extend::{
    IndexedMaspData, MaspDataRefs as MaspDataRefsAttr, MaspTxRef, MaspTxRefs,
    ReadFromEventAttributes,
};
use namada_ibc::{decode_message, IbcMessage};
use namada_io::client::Client;
use namada_token::masp::shielded_wallet::ShieldedQueries;
pub use namada_token::masp::{utils, *};
use namada_tx::Tx;
pub use utilities::{IndexerMaspClient, LedgerMaspClient};

use crate::error::{Error, QueryError};
use crate::rpc::{
    query_block, query_conversion, query_denom, query_masp_epoch,
    query_max_block_time_estimate, query_native_token,
};
use crate::{token, MaybeSend, MaybeSync};

use crate::ibc::extract_masp_tx_from_packet;
use crate::ibc::core::channel::types::msgs::PacketMsg;
use crate::token::MaspTransaction;
use crate::ibc::core::handler::types::msgs::MsgEnvelope;
use crate::ibc::core::channel::types::commitment::AcknowledgementCommitment;
use crate::rpc::query_storage_value_bytes;
use crate::ibc::apps::nft_transfer::types::ack_success_b64;
use crate::ibc::core::channel::types::acknowledgement::AcknowledgementStatus;
use crate::ibc::core::channel::types::commitment::compute_ack_commitment;
use crate::ibc::storage;
use crate::ibc::core::host::types::identifiers::Sequence;
use crate::ChannelId;
use crate::PortId;

// Check if IBC message was received successfully in this state transition
async fn is_receiving_success(
    client: &(impl Client + Sync),
    dst_port_id: &PortId,
    dst_channel_id: &ChannelId,
    sequence: Sequence,
) -> Result<Option<bool>, Error> {
    // Ensure that the event corresponds to the current changes to storage
    let ack_key = storage::ack_key(dst_port_id, dst_channel_id, sequence);
    // If the receive is a success, then the commitment is unique
    let succ_ack_commitment = compute_ack_commitment(
        &AcknowledgementStatus::success(ack_success_b64()).into(),
    );
    Ok(match query_storage_value_bytes(client, &ack_key, None, false).await?.0 {
        // Success happens only if commitment equals the above
        Some(value) => {
            Some(AcknowledgementCommitment::from(value) == succ_ack_commitment)
        }
        // Acknowledgement key non-existence is failure
        None => None,
    })
}

/// Extract MASP transaction from IBC envelope
async fn extract_masp_tx_from_envelope(
    client: &(impl Client + Sync),
    envelope: &MsgEnvelope,
) -> Result<Option<MaspTransaction>, Error> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) if
            is_receiving_success(client, &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
                msg.packet.seq_on_a,).await?
            .is_some_and(|ack_succ| ack_succ) => {
                Ok(extract_masp_tx_from_packet(&msg.packet))
            }
        _ => Ok(None),
    }
}


/// Extract the relevant shield portions from a [`Tx`] MASP section or an IBC
/// message, if any.
#[allow(clippy::result_large_err)]
async fn extract_masp_tx(
    client: &(impl Client + Sync),
    tx: &Tx,
    masp_refs: &MaspTxRefs,
) -> Result<Vec<Transaction>, Error> {
    // NOTE: It is possible to have two identical references in a same batch:
    // this is because, some types of MASP data packet can be correctly executed
    // more than once (output descriptions). We have to make sure we account for
    // this by using collections that allow for duplicates (both in the args
    // and in the returned type): if the same reference shows up multiple
    // times in the input we must process it the same number of times to
    // ensure we contruct the correct state
    let mut acc = vec![];
    for ref masp_ref in masp_refs
        .0
        .iter() {
            match masp_ref {
                MaspTxRef::MaspSection(id) => {
                    // Simply looking for masp sections attached to the tx
                    // is not safe. We don't validate the sections attached to a
                    // transaction se we could end up with transactions carrying
                    // an unnecessary masp section. We must instead look for the
                    // required masp sections published in the events
                    let transaction = tx
                        .get_masp_section(id)
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Missing expected masp transaction with id \
                                 {id}"
                            ))
                        })?
                        .clone();
                    acc.push(transaction);
                }
                MaspTxRef::IbcData(hash) => {
                    // Dereference the masp ref to the first instance that
                    // matches is, even if it is not the exact one that produced
                    // the event, the data we extract will be exactly the same
                    let masp_ibc_tx = tx
                        .commitments()
                        .iter()
                        .find(|cmt| cmt.data_sechash() == hash)
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Couldn't find data section with hash {hash}"
                            ))
                        })?;
                    let tx_data = tx.data(masp_ibc_tx).ok_or_else(|| {
                        Error::Other(
                            "Missing expected data section".to_string(),
                        )
                    })?;

                    let IbcMessage::Envelope(envelope) =
                        decode_message::<token::Transfer>(&tx_data)
                            .map_err(|e| Error::Other(e.to_string()))?
                    else {
                        return Err(Error::Other(
                            "Expected IBC packet to be an envelope".to_string(),
                        ));
                    };

                    if let Some(transaction) =
                        extract_masp_tx_from_envelope(client, &envelope).await?
                    {
                        acc.push(transaction);
                    } else {
                        return Err(Error::Other(
                            "Failed to retrieve MASP over IBC transaction"
                                .to_string(),
                        ))
                    }
                }
            }
        }
    Ok(acc)
}

// Retrieves all the indexes at the specified height which refer
// to a valid masp transaction.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
) -> Result<Vec<IndexedMaspData>, Error> {
    Ok(client
        .block_results(height.0)
        .await
        .map_err(|e| Error::from(QueryError::General(e.to_string())))?
        .end_block_events
        .map(|events| {
            events
                .into_iter()
                .filter_map(|event| {
                    MaspDataRefsAttr::read_from_event_attributes(
                        &event.attributes,
                    )
                    .ok()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default())
}

/// An implementation of a shielded wallet
/// along with methods for interacting with a node
#[derive(Default, Debug)]
pub struct ShieldedContext<U: ShieldedUtils>(ShieldedWallet<U>);

impl<U: ShieldedUtils> From<ShieldedContext<U>> for ShieldedWallet<U> {
    fn from(ctx: ShieldedContext<U>) -> Self {
        ctx.0
    }
}
impl<U: ShieldedUtils> ShieldedContext<U> {
    /// Create a new [`ShieldedContext`]
    pub fn new(wallet: ShieldedWallet<U>) -> Self {
        Self(wallet)
    }
}

impl<U: ShieldedUtils> std::ops::Deref for ShieldedContext<U> {
    type Target = ShieldedWallet<U>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<U: ShieldedUtils> std::ops::DerefMut for ShieldedContext<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

macro_rules! wrap_err {
    ($e:expr) => {
        eyre::WrapErr::wrap_err($e, "Query failed:")
    };
}

impl<U: ShieldedUtils + MaybeSync + MaybeSend> ShieldedQueries<U>
    for ShieldedContext<U>
{
    async fn query_native_token<C: Client + Sync>(
        client: &C,
    ) -> Result<Address, eyre::Report> {
        wrap_err!(query_native_token(client).await)
    }

    async fn query_denom<C: Client + Sync>(
        client: &C,
        token: &Address,
    ) -> Option<Denomination> {
        query_denom(client, token).await
    }

    async fn query_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
    ) -> Option<(
        Address,
        Denomination,
        MaspDigitPos,
        MaspEpoch,
        I128Sum,
        MerklePath<Node>,
    )> {
        query_conversion(client, asset_type).await
    }

    async fn query_block<C: Client + Sync>(
        client: &C,
    ) -> Result<Option<u64>, eyre::Report> {
        wrap_err!(query_block(client).await.map(|b| b.map(|h| h.height.0)))
    }

    async fn query_max_block_time_estimate<C: Client + Sync>(
        client: &C,
    ) -> Result<DurationSecs, eyre::Report> {
        wrap_err!(query_max_block_time_estimate(client).await)
    }

    async fn query_masp_epoch<C: Client + Sync>(
        client: &C,
    ) -> Result<MaspEpoch, eyre::Report> {
        wrap_err!(query_masp_epoch(client).await)
    }
}
