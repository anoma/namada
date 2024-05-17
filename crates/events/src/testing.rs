//! Events testing utilities.

use super::{EmitEvents, Event};

/// Event sink that drops any emitted events.
pub struct VoidEventSink;

impl EmitEvents for VoidEventSink {
    fn emit<E>(&mut self, _: E)
    where
        E: Into<Event>,
    {
    }

    fn emit_many<B, E>(&mut self, _: B)
    where
        B: IntoIterator<Item = E>,
        E: Into<Event>,
    {
    }
}
