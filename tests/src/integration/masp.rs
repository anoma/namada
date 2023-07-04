use std::path::PathBuf;

use color_eyre::eyre::Result;
use namada_apps::client::tx::CLIShieldedUtils;

use super::setup;

#[test]
fn masp_incentives() -> Result<()> {
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let mut node = setup::setup()?;
    // Wait till epoch boundary
    let ep0 = node.next_epoch();
    Ok(())
}
