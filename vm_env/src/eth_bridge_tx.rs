//! code that should be executed within a transaction
use std::error::Error;
use std::ops::Add;

use anoma::ledger::eth_bridge::storage::{self, EthMsgKeys};
use anoma::ledger::pos::types::VotingPowerDelta;
use anoma::types::address::Address;
use anoma::types::ethereum_events::{EthMsgDiff, EthereumEvent};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use num_rational::Ratio;

use crate::imports::tx::{self, log_string};
use crate::proof_of_stake::PosRead;
use crate::tx_prelude::{get_block_epoch, has_key, read, PoS};

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: &str) {
    log_string(format!("[{}] {}", TX_NAME, msg))
}

fn threshold() -> Ratio<u64> {
    Ratio::new(2, 3)
}

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct EthMsg {
    pub body: EthereumEvent,
    pub voting_power: (u64, u64),
    pub seen_by: Vec<Address>,
    pub seen: bool,
}

fn write_eth_msg(eth_msg_keys: &EthMsgKeys, eth_msg: &EthMsg) {
    tx::write(&eth_msg_keys.body().to_string(), &eth_msg.body);
    tx::write(&eth_msg_keys.seen().to_string(), &eth_msg.seen);
    tx::write(&eth_msg_keys.seen_by().to_string(), &eth_msg.seen_by);
    tx::write(
        &eth_msg_keys.voting_power().to_string(),
        &eth_msg.voting_power,
    );
}

pub fn apply(tx_data: Vec<u8>) {
    if let Err(err) = apply_aux(tx_data) {
        log(&format!("ERROR: {:?}", err));
        panic!("{:?}", err)
    }
}

pub fn apply_aux(tx_data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    log(&format!("got data - {} bytes", tx_data.len()));
    log(&format!("/eth_msgs key - {}", storage::eth_msgs_key()));

    let diffs: Vec<EthMsgDiff> = BorshDeserialize::try_from_slice(&tx_data)?;
    log(&format!("deserialized diffs - length = {}", diffs.len()));

    // TODO: this should be previous block's epoch, not current epoch!
    let epoch = get_block_epoch();
    log(&format!("epoch - {}", &epoch));

    let total_voting_power_deltas = PoS.read_total_voting_power();
    log(&format!(
        "total_voting_power_deltas - {:?}",
        &total_voting_power_deltas
    ));

    let total_voting_power = match total_voting_power_deltas.get(epoch) {
        Some(total_voting_power) => total_voting_power,
        None => return Err("couldn't get total voting power")?,
    };
    log(&format!("total_voting_power - {:?}", &total_voting_power));

    for diff in diffs {
        let hash = diff.body.hash()?;
        let eth_msg_keys = storage::EthMsgKeys::new(hash);

        let eth_msg = if !has_key(&eth_msg_keys.prefix.to_string()) {
            log(&format!("key not present - {}", &eth_msg_keys.prefix));

            let mut numerator = VotingPowerDelta::default();
            for validator in diff.seen_by.iter() {
                let voting_power_deltas =
                    match PoS.read_validator_voting_power(validator) {
                        Some(voting_power) => voting_power,
                        None => {
                            return Err(
                                "couldn't get validator's voting power deltas"
                            )?;
                        }
                    };
                // TODO: use voting_power_deltas.last_update() to ensure voting
                // power is up to date?
                let voting_power = match voting_power_deltas.get(epoch) {
                    Some(voting_power) => voting_power,
                    None => {
                        return Err("couldn't get validator's voting power")?;
                    }
                };
                numerator = numerator.add(voting_power);
            }

            // TODO: be careful for overflows
            let numerator: u64 = Into::<i64>::into(numerator) as u64;
            let total_voting_power: u64 =
                Into::<i64>::into(total_voting_power) as u64;
            let fvp: Ratio<u64> = Ratio::new(numerator, total_voting_power);
            EthMsg {
                body: diff.body,
                voting_power: fvp.into(),
                seen_by: diff.seen_by,
                seen: fvp > threshold(),
            }
        } else {
            log(&format!("key present - {}", &eth_msg_keys.prefix));
            let body: Option<EthereumEvent> =
                read(&eth_msg_keys.body().to_string());
            if body.is_none() {
                return Err("couldn't read body")?;
            }
            let seen: Option<bool> = read(&eth_msg_keys.seen().to_string());
            if seen.is_none() {
                return Err("couldn't read seen")?;
            }
            let seen_by: Option<Vec<Address>> =
                read(&eth_msg_keys.seen_by().to_string());
            if seen_by.is_none() {
                return Err("couldn't read seen_by")?;
            }
            let voting_power: Option<(u64, u64)> =
                read(&eth_msg_keys.voting_power().to_string());
            if voting_power.is_none() {
                return Err("couldn't read voting_power")?;
            }
            EthMsg {
                body: body.unwrap(),
                voting_power: voting_power.unwrap(),
                seen_by: seen_by.unwrap(),
                seen: seen.unwrap(),
            }
            // TODO: apply the diff before writing back
        };
        write_eth_msg(&eth_msg_keys, &eth_msg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anoma::types::address;
    use anoma::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
    };
    use anoma::types::ethereum_events::{
        EthMsgDiff, EthereumEvent, TransferToNamada,
    };
    use anoma_tests::tx::tx_host_env;
    use borsh::BorshSerialize;

    use super::*;
    #[test]
    fn test_happy_path() {
        let sole_validator = address::testing::gen_established_address();
        let receiver = address::testing::established_address_2();

        let diff = EthMsgDiff {
            body: EthereumEvent::TransfersToNamada {
                nonce: arbitrary_nonce(),
                transfers: vec![TransferToNamada {
                    amount: arbitrary_amount(),
                    asset: arbitrary_eth_address(),
                    receiver,
                }],
            },
            seen_by: vec![sole_validator],
        };
        let tx_data = vec![diff].try_to_vec().unwrap();
        tx_host_env::init();

        let result = apply_aux(tx_data);

        if let Err(err) = result {
            panic!("apply_aux error: {:?}", err);
        }
        let env = tx_host_env::take();
        // TODO: we should touch 4 keys for storage update
        assert_eq!(env.all_touched_storage_keys().len(), 0);
        // TODO: check specific keys e.g. /eth_msg/$msg_hash/body
    }
}
