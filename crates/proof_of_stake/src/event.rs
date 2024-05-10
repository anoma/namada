//! Proof of Stake events.

use namada_core::address::Address;
use namada_core::token;
use namada_core::uint::Uint;
use namada_events::extend::{ComposeEvent, EventAttributeEntry};
use namada_events::{Event, EventLevel, EventToEmit};

pub mod types {
    //! Proof of Stake event types.

    use namada_events::{event_type, EventType};

    use super::PosEvent;

    /// Slash event.
    pub const SLASH: EventType = event_type!(PosEvent, "slash");
}

/// Proof of Stake event.
#[derive(Debug)]
pub enum PosEvent {
    /// Slashing event.
    Slash {
        /// The address of the slashed validator.
        validator: Address,
        /// Amount of tokens that have been slashed.
        amount: token::Amount,
    },
}

impl EventToEmit for PosEvent {
    const DOMAIN: &'static str = "proof-of-stake";
}

impl From<PosEvent> for Event {
    fn from(pos_event: PosEvent) -> Self {
        match pos_event {
            PosEvent::Slash { validator, amount } => {
                Event::new(types::SLASH, EventLevel::Block)
                    .with(SlashedValidator(validator))
                    .with(SlashedAmount(&amount.into()))
                    .into()
            }
        }
    }
}

/// Extend an [`Event`] with slashed validator data.
pub struct SlashedValidator(pub Address);

impl EventAttributeEntry<'static> for SlashedValidator {
    type Value = Address;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "slashed-validator";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with slashed amount data.
pub struct SlashedAmount<'amt>(pub &'amt Uint);

impl<'amt> EventAttributeEntry<'amt> for SlashedAmount<'amt> {
    type Value = &'amt Uint;
    type ValueOwned = Uint;

    const KEY: &'static str = "slashed-amount";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
