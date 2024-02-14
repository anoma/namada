use std::str::FromStr;

use namada_core::types::dec::Dec;
use namada_proof_of_stake::storage::{read_pos_params, write_pos_params};
use namada_tx_prelude::*;

#[transaction(gas = 10000)]
fn apply_tx(ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    // PoS
    let mut pos_params = read_pos_params(ctx)?.owned;
    pos_params.max_inflation_rate = Dec::from_str("0.1").unwrap();
    pos_params.target_staked_ratio = Dec::from_str("0.666667").unwrap();
    pos_params.rewards_gain_p = Dec::from_str("0.25").unwrap();
    pos_params.rewards_gain_d = Dec::from_str("0.25").unwrap();
    write_pos_params(ctx, &pos_params)?;

    // PGF
    let pgf_inflation_key =
        governance::pgf::storage::keys::get_pgf_inflation_rate_key();
    let pgf_inflation_rate = Dec::from_str("0.025").unwrap();
    ctx.write(&pgf_inflation_key, pgf_inflation_rate)?;

    // Stewards
    let steward_inflation_key =
        governance::pgf::storage::keys::get_steward_inflation_rate_key();
    let steward_inflation_rate = Dec::from_str("0.001").unwrap();
    ctx.write(&steward_inflation_key, steward_inflation_rate)?;

    Ok(())
}
