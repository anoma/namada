use borsh::BorshSerialize;
use borsh_ext::BorshSerializeExt;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::proto::Section;
use namada_core::proto::SignatureIndex;
use namada_core::proto::Signer;
use namada_core::proto::TxError;
use namada_core::proto::{Signature, Tx};
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::Fee;
use namada_core::types::transaction::GasLimit;
use std::collections::BTreeMap;
use std::str::FromStr;

pub mod account;
pub mod bridge;
pub mod governance;
pub mod ibc;
pub mod pgf;
pub mod pos;
pub mod transfer;
pub mod wrapper;

/// Generic arguments required to construct a transaction
pub struct GlobalArgs {
    timestamp: DateTimeUtc,
    expiration: Option<DateTimeUtc>,
    code_hash: Hash,
    chain_id: ChainId,
}

pub(in crate::transaction) fn build_tx(
    GlobalArgs {
        timestamp,
        expiration,
        code_hash,
        chain_id,
    }: GlobalArgs,
    data: impl BorshSerialize,
    code_tag: String,
) -> Tx {
    let mut inner_tx = Tx::new(chain_id, expiration);
    inner_tx.header.timestamp = timestamp;
    inner_tx.add_code_from_hash(code_hash, Some(code_tag));
    inner_tx.add_data(data);

    inner_tx
}

//FIXME: back to hash here
//FIXME: actually I think we need to sign a vector of one hash
pub(in crate::transaction) fn get_msg_to_sign(tx: &Tx) -> Vec<u8> {
    tx.raw_header_hash().serialize_to_vec()
}

pub(in crate::transaction) fn attach_raw_signatures(
    //FIXME: make it as the wrapper function
    mut tx: Tx,
    signatures: Vec<SignatureIndex>,
) -> Tx {
    tx.add_signatures(signatures);
    tx
}
