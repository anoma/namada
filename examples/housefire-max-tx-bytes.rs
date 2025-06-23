use namada_sdk::migrations;
use namada_sdk::parameters;
use namada_sdk::storage::DbColFam;

pub fn main() {
    // Write an example migration that updates minted balances
    let minted_balance_changes = migrations::DbChanges {
        changes: vec![migrations::DbUpdateType::Add {
            key: parameters::storage::get_max_tx_bytes_key(),
            cf: DbColFam::SUBSPACE,
            value: migrations::UpdateValue::from(2_000_000_u32),
            force: false,
        }],
    };
    std::fs::write(
        "fix_max_tx_bytes.json",
        serde_json::to_string(&minted_balance_changes).unwrap(),
    )
    .unwrap();
}
