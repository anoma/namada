use namada_tx_prelude::{hash::Hash, storage::Key, *};

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    // governance
    let target_key = gov_storage::keys::get_min_proposal_grace_epochs_key();
    ctx.write(&target_key, 9_u64)?;

    // parameters
    let target_key = parameters_storage::get_vp_allowlist_storage_key();
    ctx.write(&target_key, vec!["hash"])?;

    let wasm_code_hash = Hash::sha256("test");
    let wasm_code_name = "test".to_string();

    let wasm_code_key = Key::wasm_code(&wasm_code_hash);
    ctx.write_bytes(&wasm_code_key, [])?;

    let wasm_code_len_key = Key::wasm_code_len(&wasm_code_hash);
    ctx.write(&wasm_code_len_key, 30.serialize_to_vec())?;

    let wasm_code_name_key = Key::wasm_code_name("test".to_string());
    ctx.write_bytes(&wasm_code_name_key, wasm_code_name.clone())?;

    let wasm_hash_key = Key::wasm_hash("test");
    ctx.write_bytes(&wasm_hash_key, wasm_code_name)?;

    Ok(())
}
