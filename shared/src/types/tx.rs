//! Helper structures to build transactions
use namada_core::proto::{
    Section, SignatureIndex,
};
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::chain::ChainId;
use namada_core::types::key::common;
use namada_core::types::transaction::WrapperTx;
use std::collections::BTreeSet;

use crate::types::time::DateTimeUtc;

/// A helper structure to build transations
#[derive(Default)]
pub struct TxBuilder {
    chain_id: ChainId,
    expiration: Option<DateTimeUtc>,
    sections: Vec<Section>,
    wrapper: Option<WrapperTx>,
    gas_payer: Option<common::SecretKey>,
    signing_keys: Vec<common::SecretKey>,
    account_public_keys_map: Option<AccountPublicKeysMap>,
    signatures: BTreeSet<SignatureIndex>,
}
