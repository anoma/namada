use anoma_shared::types::address::{Address, xan};
use anoma_shared::types::key::ed25519::*;
use anoma_shared::ledger::storage::{Key, write_log::WriteLog};
use anoma_shared::types::token::{Amount, balance_key};

use crate::node::ledger::storage;


/// A fee is an amount of a specified token
pub struct Fee {
    amount: Amount,
    token: Address,
}

/// When we receive a transaction from the mempool, it is mostly encrypted.
/// However, a small bit is decrypted that validators must verify. This
/// unencrypted portion contains the following data
///
/// 1. A fee to be payed for including (and thus decrypting later) the tx.
/// 2. The public key of the fee payer
/// 3. A signature from the fee payer.
///
/// The validator must verify the signature and then debit the fee
/// from the fee payer (whose address is derived from the public key) and
/// credit the fee to themselves.
pub fn verify_dkg_wrapper_tx(
    pk: &PublicKey,
    fee: &[u8],
    sig: &Signature,
)
-> Result<(), VerifySigError>{

    Ok(())
}

fn get_balance_from_storage(key: &Key, db: &storate::PersistentStorage, write_log: &WriteLog) {

}