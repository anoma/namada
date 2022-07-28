//! Code for handling [`ProtocolTxType::EthereumEvents`] transactions.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use borsh::BorshSerialize;
use eyre::{eyre, Context};
use namada::ledger::pos::types::VotingPower;
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
use namada::types::ethereum_events::{EthMsgUpdate, TxEthBridgeData};

use super::super::{Error, Result};
use crate::node::ledger::protocol::transactions::ethereum_events;

pub(crate) mod eth_msg_update;
pub(crate) mod voting_powers;

const TX_WASM_NAME: &str = "tx_eth_bridge";

pub(crate) fn construct_tx(
    events: Vec<MultiSignedEthEvent>,
    total_voting_power: VotingPower,
    voting_powers: HashMap<Address, VotingPower>,
    wasm_dir: &Path,
) -> Result<Tx> {
    let updates = eth_msg_update::from_multisigneds(events);
    let tx_data = ethereum_events::construct_tx_data(
        updates,
        total_voting_power,
        voting_powers,
    )
    .map_err(|err| Error::ProtocolTxError { source: err })?;
    tracing::debug!(
        bytes = tx_data.len(),
        "serialized tx_data for state update transaction"
    );
    let tx_code = {
        let checksums = crate::wasm_loader::Checksums::read_checksums(wasm_dir);
        tracing::debug!(
            checksums = checksums.0.len(),
            wasm_dir = wasm_dir.to_string_lossy().into_owned().as_str(),
            "loaded checksums.json from wasm directory"
        );
        let file_path = checksums
            .0
            .get(&format!("{}.wasm", TX_WASM_NAME))
            .ok_or_else(|| Error::ReadWasmError {
                wasm_name: TX_WASM_NAME.to_owned(),
            })?;
        tracing::debug!(
            file_path = file_path.as_str(),
            "got file path for wasm"
        );
        crate::wasm_loader::read_wasm(&wasm_dir, file_path)
    };
    tracing::debug!(
        bytes = tx_code.len(),
        "read tx_code for state update transaction"
    );
    Ok(Tx::new(tx_code, Some(tx_data)))
}

pub(crate) fn construct_tx_data(
    updates: Vec<EthMsgUpdate>,
    total_voting_power: VotingPower,
    voting_powers: HashMap<Address, VotingPower>,
) -> eyre::Result<Vec<u8>> {
    TxEthBridgeData {
        updates,
        total_voting_power,
        voting_powers,
    }
    .try_to_vec()
    .wrap_err_with(|| eyre!("couldn't serialize updates"))
}

pub(crate) fn get_all_voters<'a>(
    v: impl Iterator<Item = &'a MultiSignedEthEvent>,
) -> HashSet<Address> {
    v.fold(HashSet::new(), |mut validators, event| {
        validators.extend(event.signers.iter().map(|addr| addr.to_owned()));
        validators
    })
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;

    use borsh::BorshDeserialize;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer, arbitrary_voting_power,
    };
    use namada::types::ethereum_events::TxEthBridgeData;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_calculate_construct_tx_data() {
        let sole_validator = address::testing::established_address_1();
        let update = eth_msg_update::from_multisigned(MultiSignedEthEvent {
            event: arbitrary_single_transfer(
                arbitrary_nonce(),
                address::testing::established_address_2(),
            ),
            signers: HashSet::from_iter(vec![sole_validator.clone()]),
        });
        let updates = vec![update.clone()];
        let total_voting_power = arbitrary_voting_power();
        let voting_powers =
            HashMap::from_iter(vec![(sole_validator, total_voting_power)]);

        let result = construct_tx_data(
            updates,
            total_voting_power,
            voting_powers.clone(),
        );

        let data = match result {
            Ok(data) => data,
            Err(err) => panic!("error: {:?}", err),
        };
        assert_eq!(
            data,
            TxEthBridgeData {
                updates: vec![update.clone()],
                total_voting_power,
                voting_powers,
            }
            .try_to_vec()
            .unwrap()
        );
    }

    // constructs a temporary fake wasm_dir with one wasm and a checksums.json
    fn fake_wasm_dir(
        wasm_name: impl AsRef<str>,
        wasm_contents: impl AsRef<[u8]>,
    ) -> PathBuf {
        let tmp_dir = tempfile::tempdir().unwrap();
        let wasm_filename_without_hash = format!("{}.wasm", wasm_name.as_ref());
        let arbitrary_hash =
            "7d7fa4553ccf115cd82ce59d4e1dc8321c41d357d02ccae29a59865aac2bb77d";
        let wasm_filename =
            format!("{}.{}.wasm", arbitrary_hash, wasm_name.as_ref());
        let wasm_path = tmp_dir.path().join(&wasm_filename);
        fs::write(&wasm_path, wasm_contents).unwrap();
        let checksums_path = tmp_dir.path().join("checksums.json");
        fs::write(
            &checksums_path,
            json!({
                wasm_filename_without_hash: wasm_filename,
            })
            .to_string(),
        )
        .unwrap();
        tmp_dir.into_path()
    }

    #[test]
    fn test_construct_tx() {
        let wasm_contents = b"arbitrary wasm contents";
        let wasm_dir = fake_wasm_dir(TX_WASM_NAME, wasm_contents);

        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: HashSet::from_iter(vec![sole_validator.clone()]),
        };
        let events = vec![with_signers];
        let total_voting_power = arbitrary_voting_power();
        let voting_powers =
            HashMap::from_iter(vec![(sole_validator, total_voting_power)]);

        let result = construct_tx(
            events.clone(),
            total_voting_power,
            voting_powers,
            &wasm_dir,
        );

        let tx = match result {
            Ok(tx) => tx,
            Err(err) => panic!("error: {:?}", err),
        };
        assert!(
            matches!(tx.data, Some(data) if TxEthBridgeData::try_from_slice(&data).is_ok())
        );
        assert_eq!(tx.code, wasm_contents);
    }

    #[test]
    fn test_construct_tx_missing_wasm() {
        let wasm_contents = b"arbitrary wasm contents";
        let wasm_name = "tx_something_else";
        assert_ne!(wasm_name, TX_WASM_NAME);
        let wasm_dir = fake_wasm_dir(wasm_name, wasm_contents);
        let events = vec![];
        let total_voting_power = arbitrary_voting_power();
        let voting_powers = HashMap::new();

        let result =
            construct_tx(events, total_voting_power, voting_powers, &wasm_dir);

        assert!(result.is_err());
    }
}
