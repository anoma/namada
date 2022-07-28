use std::path::Path;

use namada::proto::Tx;

use super::super::{Error, Result};

const TX_ETH_BRIDGE_WASM_NAME: &str = "tx_eth_bridge";

pub(crate) fn construct_tx_eth_bridge(
    wasm_dir: impl AsRef<Path>,
) -> Result<Tx> {
    let tx_data = vec![];
    tracing::debug!(
        bytes = tx_data.len(),
        "serialized tx_data for state update transaction"
    );
    let tx_code = {
        let checksums =
            crate::wasm_loader::Checksums::read_checksums(&wasm_dir);
        tracing::debug!(
            checksums = checksums.0.len(),
            wasm_dir =
                wasm_dir.as_ref().to_string_lossy().into_owned().as_str(),
            "loaded checksums.json from wasm directory"
        );
        let file_path = checksums
            .0
            .get(&format!("{}.wasm", TX_ETH_BRIDGE_WASM_NAME))
            .ok_or_else(|| Error::ReadWasmError {
                wasm_name: TX_ETH_BRIDGE_WASM_NAME.to_owned(),
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

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

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
    fn test_construct_tx_eth_bridge() {
        let wasm_contents = b"arbitrary wasm contents";
        let wasm_dir = fake_wasm_dir(TX_ETH_BRIDGE_WASM_NAME, wasm_contents);

        let result = construct_tx_eth_bridge(&wasm_dir);

        let tx = match result {
            Ok(tx) => tx,
            Err(err) => panic!("error: {:?}", err),
        };
        assert!(matches!(tx.data, Some(data) if data.is_empty()));
        assert_eq!(tx.code, wasm_contents);
    }

    #[test]
    fn test_construct_tx_eth_bridge_missing_wasm() {
        let wasm_contents = b"arbitrary wasm contents";
        let wasm_name = "tx_something_else";
        assert_ne!(wasm_name, TX_ETH_BRIDGE_WASM_NAME);
        let wasm_dir = fake_wasm_dir(wasm_name, wasm_contents);

        let result = construct_tx_eth_bridge(&wasm_dir);

        assert!(result.is_err());
    }
}
