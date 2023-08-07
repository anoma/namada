use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use borsh::BorshDeserialize;
use data_encoding::HEXLOWER;
use namada::proof_of_stake;
use namada::proof_of_stake::storage::{
    is_below_capacity_validator_set_key, is_consensus_validator_set_key,
    is_pos_key, is_validator_set_positions_key,
};
use namada::types::address::Address;
use namada::types::storage;
use once_cell::sync::Lazy;

pub fn pretty_dump(data_path: PathBuf) {
    let data: BTreeMap<String, String> = {
        let data_raw = fs::read_to_string(&data_path).unwrap();
        toml::from_str(&data_raw).unwrap()
    };
    for (key, val_str) in data {
        let key = storage::Key::parse(&key).unwrap();
        let val_bytes =
            Lazy::new(|| HEXLOWER.decode(val_str.as_bytes()).unwrap());
        if is_pos_key(&key) {
            if let Some((epoch, stake, position)) =
                is_consensus_validator_set_key(&key)
            {
                let val = Address::try_from_slice(&val_bytes).unwrap();
                println!(
                    "Consensus set at epoch {epoch}, stake {}, {position:?}: \
                     {val}",
                    stake.to_string_native()
                );
                continue;
            } else if let Some((epoch, stake, position)) =
                is_below_capacity_validator_set_key(&key)
            {
                let val = Address::try_from_slice(&val_bytes).unwrap();
                println!(
                    "Below-capacity set at epoch {epoch}, stake {}, \
                     {position:?}: {val}",
                    stake.to_string_native()
                );
                continue;
            } else if let Some((epoch, address)) =
                is_validator_set_positions_key(&key)
            {
                let val =
                    proof_of_stake::types::Position::try_from_slice(&val_bytes)
                        .unwrap();
                println!(
                    "Validator {address} position at epoch {epoch}: {}",
                    val.0
                );
                continue;
            }
        }

        tracing::debug!("Unrecognized key {key}");
    }
}
