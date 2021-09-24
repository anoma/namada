use std::cmp::max;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use anoma::ledger::parameters::Parameters;
use anoma::ledger::pos::PosParams;
use anoma::proto::Tx;
use anoma::types::address::Address;
use anoma::types::storage::{Key, BlockHeight};
use anoma::types::token::Amount;
use anoma::types::transaction::{Hash, hash_tx, WrapperTx, TxType};
use borsh::{BorshDeserialize, BorshSerialize};
use tendermint_proto::types::EvidenceParams;
use tendermint_rpc::{HttpClient, Client};

use crate::node::ledger::{response, storage};
use crate::node::ledger::rpc::PrefixValue;
use tendermint::abci::Transaction;


/// We use the default socket for tendermint to listen to RPC queries
const TENDERMINT_RPC_ADDRESS: &str = "tcp://0.0.0.0:26657";

/// Simple helper function for the ledger to get balances
/// of the specified token at the specified address
pub fn get_balance(
    storage: &storage::PersistentStorage,
    token: &Address,
    owner: &Address,
) -> std::result::Result<Amount, String> {
    let query_resp =
        read_storage_value(&storage,&token::balance_key(token, owner));
    if query_resp.code != 0 {
        Err("Unable to read balance of the given address".into())
    } else {
        BorshDeserialize::try_from_slice(&query_resp.value[..]).map_err(
            |_| {
                "Unable to deserialize the balance of the given address"
                    .into()
            },
        )
    }
}

/// Query to read a value from storage
pub fn read_storage_value(storage: &storage::PersistentStorage, key: &Key) -> response::Query {
    match storage.read(key) {
        Ok((Some(value), _gas)) => response::Query {
            value,
            ..Default::default()
        },
        Ok((None, _gas)) => response::Query {
            code: 1,
            info: format!("No value found for key: {}", key),
            ..Default::default()
        },
        Err(err) => response::Query {
            code: 2,
            info: format!("Storage error: {}", err),
            ..Default::default()
        },
    }
}

/// Query to read a range of values from storage with a matching prefix. The
/// value in successful response is a [`Vec<PrefixValue>`] encoded with
/// [`BorshSerialize`].
pub fn read_storage_prefix(storage: &storage::PersistentStorage, key: &Key) -> response::Query {
    let (iter, _gas) = storage.iter_prefix(key);
    let mut iter = iter.peekable();
    if iter.peek().is_none() {
        response::Query {
            code: 1,
            info: format!("No value found for key: {}", key),
            ..Default::default()
        }
    } else {
        let values: std::result::Result<
            Vec<PrefixValue>,
            anoma::types::storage::Error,
        > = iter
            .map(|(key, value, _gas)| {
                let key = Key::parse(key)?;
                Ok(PrefixValue { key, value })
            })
            .collect();
        match values {
            Ok(values) => {
                let value = values.try_to_vec().unwrap();
                response::Query {
                    value,
                    ..Default::default()
                }
            }
            Err(err) => response::Query {
                code: 1,
                info: format!(
                    "Error parsing a storage key {}: {}",
                    key, err
                ),
                ..Default::default()
            },
        }
    }
}

pub fn get_evidence_params(
    protocol_params: &Parameters,
    pos_params: &PosParams,
) -> EvidenceParams {
    // Minimum number of epochs before tokens are unbonded and can be
    // withdrawn
    let len_before_unbonded = max(pos_params.unbonding_len as i64 - 1, 0);
    let max_age_num_blocks: i64 =
        protocol_params.epoch_duration.min_num_of_blocks as i64
            * len_before_unbonded;
    let min_duration_secs =
        protocol_params.epoch_duration.min_duration.0 as i64;
    let max_age_duration =
        Some(tendermint_proto::google::protobuf::Duration {
            seconds: min_duration_secs * len_before_unbonded,
            nanos: 0,
        });
    EvidenceParams {
        max_age_num_blocks,
        max_age_duration,
        ..EvidenceParams::default()
    }
}

/// A struct to hold a extracted wrapper and
/// the hash of the Tx that submitted it
pub struct WrappedTx {
    pub wrapper: WrapperTx,
    pub hash: Hash,
}

/// Query tendermint to find the encrypted tx included in the
/// last committed block
pub fn restore_wrapper_txs(height: &BlockHeight) -> HashMap<Hash, WrappedTx> {
    let client = HttpClient::new(TENDERMINT_RPC_ADDRESS).unwrap();
    client
        .block(height)
        .await
        .unwrap()
        .block
        .data()
        .iter()
        .filter_map(|Transaction(tx) |
            match TxType::from(Tx::try_from(tx.as_ref()).unwrap()) {
                TxType::Wrapper(w) => {
                    let wrapper = WrapperTx::try_from(&w).unwrap();
                    Some((
                        wrapper.tx_hash.clone(),
                        WrappedTx {
                            wrapper,
                            hash: hash_tx(&tx),
                        }
                    ))
                }
                _ => None,
            }
        )
        .collect()
}