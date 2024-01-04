use std::collections::BTreeMap;
use std::str::FromStr;

use borsh::BorshSerialize;
use namada_core::proto::{Section, Signature, Signer, Tx};
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::hash::Hash;
use namada_core::types::key::common;
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token::DenominatedAmount;
use namada_core::types::transaction::{Fee, GasLimit};

pub mod account;
pub mod bridge;
pub mod governance;
pub mod ibc;
pub mod pgf;
pub mod pos;
pub mod transfer;

/// Generic arguments required to construct a transaction
pub struct GlobalArgs {
    pub expiration: Option<DateTimeUtc>,
    pub code_hash: Hash,
    pub chain_id: ChainId,
}

pub(in crate::transaction) fn build_tx(
    GlobalArgs {
        expiration,
        code_hash,
        chain_id,
    }: GlobalArgs,
    data: impl BorshSerialize,
    code_tag: String,
) -> Tx {
    let mut inner_tx = Tx::new(chain_id, expiration);

    inner_tx.header.timestamp =
        DateTimeUtc::from_str("2000-01-01T00:00:00Z").unwrap();
    inner_tx.add_code_from_hash(code_hash, Some(code_tag));
    inner_tx.add_data(data);

    inner_tx
}

pub(in crate::transaction) fn get_sign_bytes(tx: &Tx) -> Vec<Hash> {
    vec![tx.raw_header_hash()]
}

pub(in crate::transaction) fn get_wrapper_sign_bytes(tx: &Tx) -> Hash {
    let targets = tx.sechashes();
    // Commit to the given targets
    let partial = Signature {
        targets,
        signer: Signer::PubKeys(vec![]),
        signatures: BTreeMap::new(),
    };
    partial.get_raw_hash()
}

pub(in crate::transaction) fn attach_raw_signatures(
    mut tx: Tx,
    signer: common::PublicKey,
    signature: common::Signature,
) -> Tx {
    tx.protocol_filter();
    tx.add_section(Section::Signature(Signature {
        targets: vec![tx.raw_header_hash()],
        signer: Signer::PubKeys(vec![signer]),
        signatures: [(0, signature)].into_iter().collect(),
    }));
    tx
}

pub(in crate::transaction) fn attach_fee(
    mut tx: Tx,
    fee: DenominatedAmount,
    token: Address,
    fee_payer: common::PublicKey,
    epoch: Epoch,
    gas_limit: GasLimit
) -> Tx {
    tx.add_wrapper(
        Fee {
            amount_per_gas_unit: fee,
            token,
        },
        fee_payer,
        epoch,
        gas_limit,
        None,
    );
    tx
}


pub(in crate::transaction) fn attach_fee_signature(
    mut tx: Tx,
    signer: common::PublicKey,
    signature: common::Signature,
) -> Tx {
    tx.protocol_filter();
    tx.add_section(Section::Signature(Signature {
        targets: tx.sechashes(),
        signer: Signer::PubKeys(vec![signer]),
        signatures: [(0, signature)].into_iter().collect()
    }));
    tx
}


/// A unit test for the whole flow of constructing a tx and validating it.
#[test]
fn construct_tx() {
    use namada_core::types::key::{RefTo, SigScheme};
    use namada_core::types::token::{Amount, DenominatedAmount};
    use crate::transaction::account::RevealPk;
    use namada_sdk::wallet::StoredKeypair;

    let secret_key: StoredKeypair<common::SecretKey> = serde_json::from_str(r#""unencrypted:000d5e9d7d66f0e4307edacde6e6578e31d331bcf234352647d00d20955102d3ce""#).unwrap();
    let StoredKeypair::Raw(sk) = secret_key else {
        unreachable!()
    };

    let tx = RevealPk::new(sk.ref_to(), GlobalArgs {
        expiration: None,
        code_hash: Default::default(),
        chain_id: Default::default(),
    });
    let data = tx.get_sign_bytes();
    let signature = common::SigScheme::sign(&sk, &data[0]);
    let tx = tx.attach_signatures(sk.to_public(), signature);
    let tx = tx.attach_fee(
        DenominatedAmount::native(Amount::from(100)),
        Address::from_str("tnam1qxfj3sf6a0meahdu9t6znp05g8zx4dkjtgyn9gfu").expect("Test failed"),
        sk.ref_to(),
        0.into(),
        10000.into(),
    );
    let data = tx.get_fee_sig_bytes();
    let signature = common::SigScheme::sign(&sk, &data);
    let tx = tx.attach_fee_signature(sk.ref_to(), signature);
    assert!(tx.validate_tx().expect("Test failed").is_some());

}
