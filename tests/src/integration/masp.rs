use std::path::PathBuf;

use color_eyre::eyre::Result;
use namada_apps::client::tx::CLIShieldedUtils;

use super::client::run;
use super::setup;
use crate::e2e::setup::constants::{AA_PAYMENT_ADDRESS, ALBERT, BTC};
use crate::e2e::setup::Bin;

#[test]
fn masp_incentives() -> Result<()> {
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let mut node = setup::setup()?;
    // Wait till epoch boundary
    let _ep0 = node.next_epoch();
    let _ = run(
        &node,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "20",
            "--node",
            "127.0.0.1:26567",
        ],
    );
    Ok(())
}
