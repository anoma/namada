use anoma_shared::types::intent;
use anoma_shared::types::intent::Intent;
use anoma_shared::types::key::ed25519::{Signature, Signed};

// TODO It would be nicer to use a Set<Sig> but Signature does not imply Hash.
// TODO if we don't use a set, only push if sig not already part ?
pub fn invalidate_intent(intent: &Signed<Intent>) {
    use crate::imports::tx;
    let key = intent::invalid_intent_key(&intent.data.addr);
    let mut invalid_intent: Vec<Signature> =
        tx::read(&key.to_string()).unwrap_or_default();
    invalid_intent.push(intent.sig.clone());
    tx::write(&key.to_string(), invalid_intent)
}

pub fn vp(intent: &Signed<Intent>) -> bool {
    use crate::imports::vp;
    let key = intent::invalid_intent_key(&intent.data.addr);

    let invalid_intent_pre: Vec<Signature> =
        vp::read_pre(&key.to_string()).unwrap_or_default();
    let invalid_intent_post: Vec<Signature> =
        vp::read_post(&key.to_string()).unwrap_or_default();
    !invalid_intent_pre.iter().any(|sig| sig == &intent.sig)
        && invalid_intent_post.iter().any(|sig| sig == &intent.sig)
}
