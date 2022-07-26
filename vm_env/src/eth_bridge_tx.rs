//! code that should be executed within a transaction
use std::error::Error;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada::ledger::eth_bridge::storage::eth_msgs::EthMsgKeys;
use namada::ledger::eth_bridge::storage::{self};
use namada::ledger::pos::types::VotingPower;
use namada::types::address::Address;
use namada::types::ethereum_events::{
    EthereumEvent, TransferToNamada, TxEthBridgeData,
};
use num_rational::Ratio;

use crate::imports::tx::{self, log_string};
use crate::tx_prelude::{has_key, read};

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: impl AsRef<str>) {
    log_string(format!("[{}] {}", TX_NAME, msg.as_ref()))
}

fn threshold() -> Ratio<u64> {
    Ratio::new(2, 3)
}

pub mod read {
    //! Helpers for reading from storage
    use std::error::Error;

    use crate::tx_prelude::token::Amount;
    use crate::tx_prelude::{read_bytes, BorshDeserialize};

    /// Returns the stored Amount, or 0 if not stored
    pub fn amount(key: &str) -> Result<Amount, Box<dyn Error>> {
        let bytes = match read_bytes(key) {
            Some(bytes) => bytes,
            None => return Ok(Amount::from(0)),
        };
        Amount::try_from_slice(&bytes[..]).map_err(|err| err.into())
    }

    #[cfg(test)]
    mod tests {
        use namada_tests::tx::*;

        use super::super::read;
        use crate::tx_prelude::token::Amount;

        #[test]
        fn test_amount_returns_zero_for_uninitialized_storage() {
            tx_host_env::init();

            let a = read::amount("some arbitrary key with no stored value")
                .unwrap();
            assert_eq!(a, Amount::from(0));
        }

        #[test]
        fn test_amount_returns_stored_amount() {
            tx_host_env::init();
            let key = "some arbitrary key";
            let amount = Amount::from(1_000_000);
            tx_host_env::write(key, amount);

            let a = read::amount(key).unwrap();
            assert_eq!(a, amount);
        }

        #[test]
        fn test_amount_errors_if_not_amount() {
            tx_host_env::init();
            let key = "some arbitrary key";
            let amount = "not an Amount type";
            tx_host_env::write(key, amount);

            assert!(matches!(read::amount(key), Err(_)))
        }
    }
}
pub mod update {
    use std::error::Error;

    use crate::tx_prelude::token::Amount;
    use crate::tx_prelude::{write, Key};

    /// Reads the `Amount` from key, applies update then writes it back
    pub fn amount(
        key: &Key,
        update: impl Fn(&mut Amount),
    ) -> Result<Amount, Box<dyn Error>> {
        let key = key.to_string();
        let mut amount = super::read::amount(&key)?;
        update(&mut amount);
        write(&key, amount);
        Ok(amount)
    }
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
    log(format!("writing EthMsg - {:#?}", eth_msg));
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
        log(format!("ERROR: {:?}", err));
        panic!("{:?}", err)
    }
}

pub fn apply_aux(tx_data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    log(format!("got data - {} bytes", tx_data.len()));

    let data: TxEthBridgeData = BorshDeserialize::try_from_slice(&tx_data)?;
    log(format!(
        "deserialized data - number of updates to apply = {}, \
         total_voting_power = {}, voting_powers = {:#?}",
        data.updates.len(),
        data.total_voting_power,
        data.voting_powers,
    ));

    let mut confirmed = vec![];
    for update in data.updates {
        let hash = update.body.hash()?;
        let eth_msg_keys = storage::eth_msgs::EthMsgKeys::new(hash);

        // TODO: we arbitrarily look at whether the seen key is present to
        // determine if the /eth_msg already exists in storage, but maybe there
        // is a less arbitrary way to do this
        let exists_in_storage = has_key(&eth_msg_keys.seen().to_string());

        let eth_msg = if !exists_in_storage {
            log(format!("New Ethereum event - {}", &eth_msg_keys.prefix));

            // TODO: be careful for overflows
            let mut seen_by_voting_power: VotingPower = VotingPower::from(0);
            for validator in &update.seen_by {
                match data.voting_powers.get(validator) {
                    Some(voting_power) => seen_by_voting_power += *voting_power,
                    None => {
                        return Err(format!(
                            "voting power was not provided for validator {}",
                            validator
                        ))?;
                    }
                };
            }

            let seen_by_voting_power: u64 = seen_by_voting_power.into();
            let total_voting_power: u64 = data.total_voting_power.into();
            let fvp: Ratio<u64> =
                Ratio::new(seen_by_voting_power, total_voting_power);
            let seen = fvp > threshold();
            if seen {
                confirmed.push(update.body.clone())
            }
            EthMsg {
                body: update.body,
                voting_power: fvp.into(),
                seen_by: update.seen_by.into_iter().collect(), /* this should result in a sorted vector as update.seen_by is a [`BTreeSet`] */
                seen,
            }
        } else {
            log(format!(
                "Existing Ethereum event - {}",
                &eth_msg_keys.prefix
            ));
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
            let eth_msg = EthMsg {
                body: body.unwrap(),
                voting_power: voting_power.unwrap(),
                seen_by: seen_by.unwrap(),
                seen: seen.unwrap(),
            };
            log(format!("read EthMsg - {:#?}", &eth_msg));
            // TODO: apply the diff to eth_msg and return an updated eth_msg
            // TODO: add to the confirmed vec if seen is going false -> true
            eth_msg
        };
        write_eth_msg(&eth_msg_keys, &eth_msg);
        if confirmed.is_empty() {
            log("no events were newly confirmed");
            return Ok(());
        }
        log(format!(
            "events were newly confirmed - n = {}",
            confirmed.len()
        ));
        for event in &confirmed {
            act_on(event)?;
        }
    }
    Ok(())
}

fn act_on(event: &EthereumEvent) -> Result<(), Box<dyn Error>> {
    match &event {
        EthereumEvent::TransfersToNamada { transfers, .. } => {
            act_on_transfers_to_namada(transfers)?
        }
        _ => log(format!("no actions taken for {:?}", event)),
    }
    Ok(())
}

fn act_on_transfers_to_namada(
    transfers: &[TransferToNamada],
) -> Result<(), Box<dyn Error>> {
    for TransferToNamada {
        amount,
        asset,
        receiver,
    } in transfers
    {
        // TODO: increase balance key for `asset`/balance/`receiver` by `amount`
        // TODO: increase supply key by `amount`
        let balance_key = storage::wrapped_erc20_balance(asset, receiver);
        update::amount(&balance_key, |balance| {
            log(format!("existing value for {} is {}", balance_key, balance));
            balance.receive(amount);
            log(format!("new value for {} will be {}", balance_key, balance));
        })?;

        let supply_key = storage::wrapped_erc20_supply(asset);
        update::amount(&supply_key, |supply| {
            log(format!("existing value for {} is {}", supply_key, supply));
            supply.receive(amount);
            log(format!("new value for {} will be {}", supply_key, supply));
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use borsh::BorshSerialize;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
        arbitrary_voting_power,
    };
    use namada::types::ethereum_events::{
        EthMsgUpdate, EthereumEvent, TransferToNamada, TxEthBridgeData,
    };
    use namada_tests::tx::tx_host_env;

    use super::*;
    #[test]
    fn test_apply_tx() {
        let sole_validator = address::testing::gen_established_address();
        let receiver = address::testing::established_address_2();

        let update = EthMsgUpdate {
            body: EthereumEvent::TransfersToNamada {
                nonce: arbitrary_nonce(),
                transfers: vec![TransferToNamada {
                    amount: arbitrary_amount(),
                    asset: arbitrary_eth_address(),
                    receiver,
                }],
            },
            seen_by: BTreeSet::from_iter(vec![sole_validator.clone()]),
        };
        let updates = HashSet::from_iter(vec![update]);
        let total_voting_power = arbitrary_voting_power();
        let voting_powers =
            HashMap::from_iter(vec![(sole_validator, total_voting_power)]);
        let tx_data = TxEthBridgeData {
            updates,
            total_voting_power,
            voting_powers,
        }
        .try_to_vec()
        .unwrap();
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

    #[test]
    fn test_apply_tx_bad_tx_data() {
        let tx_data = b"bad data".try_to_vec().unwrap();
        tx_host_env::init();

        let result = apply_aux(tx_data);

        assert!(result.is_err());
    }
}
