//! MASP verification wrappers.

mod utilities;

use eyre::eyre;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::Transaction;
use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::ibc::IbcTxDataRefs;
use namada_core::masp::{MaspEpoch, MaspTxRefs};
use namada_core::storage::TxIndex;
use namada_core::time::DurationSecs;
use namada_core::token::{Denomination, MaspDigitPos};
use namada_events::extend::{
    IbcMaspTxBatchRefs as IbcMaspTxBatchRefsAttr,
    MaspTxBatchRefs as MaspTxBatchRefsAttr,
    MaspTxBlockIndex as MaspTxBlockIndexAttr, ReadFromEventAttributes,
};
use namada_ibc::{decode_message, extract_masp_tx_from_envelope, IbcMessage};
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

/// Extract the relevant shield portions of a [`Tx`], if any.
fn extract_masp_tx(
    tx: &Tx,
    masp_section_refs: &MaspTxRefs,
) -> Result<Vec<Transaction>, eyre::Error> {
    // NOTE: simply looking for masp sections attached to the tx
    // is not safe. We don't validate the sections attached to a
    // transaction se we could end up with transactions carrying
    // an unnecessary masp section. We must instead look for the
    // required masp sections coming from the events

    masp_section_refs
        .0
        .iter()
        .try_fold(vec![], |mut acc, hash| {
            match tx.get_masp_section(hash).cloned().ok_or_else(|| {
                eyre!("Missing expected masp transaction".to_string())
            }) {
                Ok(transaction) => {
                    acc.push(transaction);
                    Ok(acc)
                }
                Err(e) => Err(e),
            }
        })
}

/// Extract the relevant shield portions from the IBC messages in [`Tx`]
#[allow(clippy::result_large_err)]
fn extract_masp_tx_from_ibc_message(
    tx: &Tx,
) -> Result<Vec<Transaction>, Error> {
    let mut masp_txs = Vec::new();
    for cmt in &tx.header.batch {
        let tx_data = tx.data(cmt).ok_or_else(|| {
            Error::Other("Missing transaction data".to_string())
        })?;
        let ibc_msg = decode_message::<token::Transfer>(&tx_data)
            .map_err(|_| Error::Other("Invalid IBC message".to_string()))?;
        if let IbcMessage::Envelope(ref envelope) = ibc_msg {
            if let Some(masp_tx) = extract_masp_tx_from_envelope(envelope) {
                masp_txs.push(masp_tx);
            }
        }
    }
    if !masp_txs.is_empty() {
        Ok(masp_txs)
    } else {
        Err(Error::Other(
            "IBC message doesn't have masp transaction".to_string(),
        ))
    }
}

// Retrieves all the indexes at the specified height which refer
// to a valid masp transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
    first_idx_to_query: Option<TxIndex>,
) -> Result<
    Option<Vec<(TxIndex, Option<MaspTxRefs>, Option<IbcTxDataRefs>)>>,
    Error,
> {
    let first_idx_to_query = first_idx_to_query.unwrap_or_default();

    Ok(client
        .block_results(height.0)
        .await
        .map_err(|e| Error::from(QueryError::General(e.to_string())))?
        .end_block_events
        .map(|events| {
            events
                .into_iter()
                .filter_map(|event| {
                    let tx_index =
                        MaspTxBlockIndexAttr::read_from_event_attributes(
                            &event.attributes,
                        )
                        .ok()?;

                    if tx_index >= first_idx_to_query {
                        // Extract the references to the correct masp sections
                        let masp_section_refs =
                            MaspTxBatchRefsAttr::read_from_event_attributes(
                                &event.attributes,
                            )
                            .ok();
                        let ibc_tx_data_refs =
                            IbcMaspTxBatchRefsAttr::read_from_event_attributes(
                                &event.attributes,
                            )
                            .ok();

                        Some((tx_index, masp_section_refs, ibc_tx_data_refs))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        }))
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
