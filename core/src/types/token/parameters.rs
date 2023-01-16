//! Custom parameters for each token type. These are used for
//! determining the shielded pool incentives.

use crate::types::address::Address;
use crate::types::storage::{Key, KeySeg};

/// The key for the nominal proportional gain of a shielded pool for a given
/// asset
pub const KP_SP_GAIN_KEY: &str = "proptional_gain";

/// The key for the nominal derivative gain of a shielded pool for a given asset
pub const KD_SP_GAIN_KEY: &str = "derivative_gain";

/// The key for the locked ratio target for a given asset
pub const LOCKED_RATIO_TARGET_KEY: &str = "locked_ratio_target";

/// The key for the max reward rate for a given asset
pub const MAX_REWARD_RATE: &str = "max_reward_rate";

/// Obtain the nominal proportional key for the given token
pub fn kp_sp_gain(token_addr: &Address) -> Key {
    key_of_token(token_addr, KP_SP_GAIN_KEY, "nominal proproitonal gains")
}

/// Obtain the nominal derivative key for the given token
pub fn kd_sp_gain(token_addr: &Address) -> Key {
    key_of_token(token_addr, KD_SP_GAIN_KEY, "nominal proproitonal gains")
}

/// The max reward rate key for the given token
pub fn max_reward_rate(token_addr: &Address) -> Key {
    key_of_token(token_addr, MAX_REWARD_RATE, "max reward rate")
}

/// Obtain the locked target ratio key for the given token
pub fn locked_token_ratio(token_addr: &Address) -> Key {
    key_of_token(
        token_addr,
        LOCKED_RATIO_TARGET_KEY,
        "nominal proproitonal gains",
    )
}

/// Gets the key for the given token address, error with the given
/// message to expect if the key is not in the address
pub fn key_of_token(
    token_addr: &Address,
    specific_key: &str,
    expect_message: &str,
) -> Key {
    Key::from(token_addr.to_db_key())
        .push(&specific_key.to_owned())
        .expect(expect_message)
}
