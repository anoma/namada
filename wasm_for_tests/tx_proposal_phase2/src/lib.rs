use std::str::FromStr;

use dec::Dec;
use namada_proof_of_stake::storage::{read_pos_params, write_pos_params};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // PoS inflation
    let mut pos_params =
        read_pos_params::<Ctx, governance::Store<Ctx>>(ctx)?.owned;
    pos_params.max_inflation_rate = Dec::from_str("0.05").unwrap();
    pos_params.target_staked_ratio = Dec::from_str("0.4").unwrap();
    pos_params.rewards_gain_p = Dec::from_str("0.25").unwrap();
    pos_params.rewards_gain_d = Dec::from_str("0.25").unwrap();
    write_pos_params(ctx, &pos_params)?;

    // PGF inflation
    let pgf_inflation_key =
        governance::pgf::storage::keys::get_pgf_inflation_rate_key();
    let pgf_inflation_rate = Dec::from_str("0.05").unwrap();
    ctx.write(&pgf_inflation_key, pgf_inflation_rate)?;

    // PGF stewards inflation
    let steward_inflation_key =
        governance::pgf::storage::keys::get_steward_inflation_rate_key();
    let steward_inflation_rate = Dec::from_str("0.005").unwrap();
    ctx.write(&steward_inflation_key, steward_inflation_rate)?;

    Ok(())
}
