use namada_core::types::key::pk_key;
use namada_core::types::storage::Key;
use namada_core::types::transaction::{InitAccount, UpdateAccount};

use super::*;

pub fn init_account(ctx: &mut Ctx, data: InitAccount) -> EnvResult<Address> {
    let address = ctx.init_account(&data.vp_code_hash)?;

    let pk_threshold = key::threshold_key(&address);
    ctx.write(&pk_threshold, data.threshold)?;

    for (pk, index) in data.public_keys.iter().zip(0u64..) {
        let pk_key = pk_key(&address, index);
        ctx.write(&pk_key, pk)?;
    }

    Ok(address)
}

pub fn update_account(ctx: &mut Ctx, data: UpdateAccount) -> EnvResult<()> {
    if let Some(vp_code_hash) = data.vp_code_hash {
        ctx.update_validity_predicate(&data.address, vp_code_hash)?;
    }

    if let Some(threshold) = data.threshold {
        let pk_threshold = key::threshold_key(&data.address);
        ctx.write(&pk_threshold, threshold)?;
    }

    if data.public_keys.is_empty() {
        return Ok(())
    }

    let pks_prefix_key = key::pk_prefix_key(&data.address);
    let mut pks_iter = ctx.iter_prefix(&pks_prefix_key)?;

    let mut index = 0_usize;
    let total_new_pks = data.public_keys.len();
    while let Some((key, _value)) = ctx.iter_next(&mut pks_iter)? {
        if total_new_pks < index {
            let pk_key = key::pk_key(&data.address, index as u64);
            ctx.write(&pk_key, data.public_keys.get(index).unwrap())?;
        } else {
            let old_pk = Key::parse(key).unwrap();
            ctx.delete(&old_pk)?;
        }
        index += 1;
    }

    Ok(())
}