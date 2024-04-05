//! Gas related events.

use namada_core::event::extend::ExtendEvent;
use namada_core::event::Event;

use super::Gas;

/// Extend an [`Event`] with gas used data.
pub struct WithGasUsed(pub Gas);

impl ExtendEvent for WithGasUsed {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(gas_used) = self;
        event["gas_used"] = gas_used.to_string();
    }
}
