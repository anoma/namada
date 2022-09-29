use std::collections::HashSet;

use namada::proto::Signed;
use namada::types::intent;
pub use namada::types::intent::*;
use namada::types::key::*;

use super::*;

pub fn vp_exchange(ctx: &Ctx, intent: &Signed<Exchange>) -> EnvResult<bool> {
    let key = intent::invalid_intent_key(&intent.data.addr);

    let invalid_intent_pre: HashSet<common::Signature> =
        ctx.read_pre(&key)?.unwrap_or_default();
    let invalid_intent_post: HashSet<common::Signature> =
        ctx.read_post(&key)?.unwrap_or_default();
    Ok(!invalid_intent_pre.contains(&intent.sig)
        && invalid_intent_post.contains(&intent.sig))
}
