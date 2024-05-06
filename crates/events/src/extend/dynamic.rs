//! Extend [events](Event) with additional fields,
//! whose attributes are determined dynamically at
//! runtime.

use super::*;

impl Event {
    /// Get the value corresponding to a given attribute.
    #[inline]
    pub fn dyn_read_attribute<'value, DATA>(
        &self,
        reader: &DATA,
    ) -> Result<<DATA as DynReadFromEventAttributes<'value>>::Value, EventError>
    where
        DATA: DynReadFromEventAttributes<'value>,
    {
        reader.dyn_read_from_event_attributes(&self.attributes)
    }

    /// Get the value corresponding to a given attribute, if it exists.
    #[inline]
    pub fn dyn_read_attribute_opt<'value, DATA>(
        &self,
        reader: &DATA,
    ) -> Result<
        Option<<DATA as DynReadFromEventAttributes<'value>>::Value>,
        EventError,
    >
    where
        DATA: DynReadFromEventAttributes<'value>,
    {
        reader.dyn_read_opt_from_event_attributes(&self.attributes)
    }

    /// Check if a certain attribute is present in the event.
    #[inline]
    pub fn dyn_has_attribute<'value, DATA>(&self, reader: &DATA) -> bool
    where
        DATA: DynRawReadFromEventAttributes<'value>,
    {
        reader.dyn_check_if_present_in(&self.attributes)
    }

    /// Get the raw string value corresponding to a given attribute, if it
    /// exists.
    #[inline]
    pub fn dyn_raw_read_attribute<'this, 'reader: 'this, 'value, DATA>(
        &'this self,
        reader: &'reader DATA,
    ) -> Option<&'this str>
    where
        DATA: DynRawReadFromEventAttributes<'value>,
    {
        reader.dyn_raw_read_opt_from_event_attributes(&self.attributes)
    }
}

/// Checks for the presence of an attribute in the
/// provided attributes map.
pub trait EventAttributeChecker<'value, A: AttributesMap> {
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn is_present(&self, attributes: &A) -> bool;
}

/// Return a new implementation of [`EventAttributeChecker`].
pub fn attribute_checker<'value, DATA, ATTR>()
-> Box<dyn EventAttributeChecker<'value, ATTR>>
where
    DATA: EventAttributeEntry<'value> + 'static,
    ATTR: AttributesMap,
{
    Box::new(EventAttributeCheckerImpl(PhantomData::<DATA>))
}

/// Dispatch a callback on a list of attribute kinds.
pub fn dispatch_attribute<'value, I, K, A, F>(
    attributes: &A,
    dispatch_list: I,
    mut dispatch: F,
) where
    A: AttributesMap,
    I: IntoIterator<Item = (K, Box<dyn EventAttributeChecker<'value, A>>)>,
    F: FnMut(K) -> ControlFlow<()>,
{
    for (kind, checker) in dispatch_list {
        if !checker.is_present(attributes) {
            continue;
        }
        if let ControlFlow::Break(_) = dispatch(kind) {
            break;
        }
    }
}

struct EventAttributeCheckerImpl<DATA>(PhantomData<DATA>);

impl<'value, DATA, A> EventAttributeChecker<'value, A>
    for EventAttributeCheckerImpl<DATA>
where
    DATA: EventAttributeEntry<'value>,
    A: AttributesMap,
{
    fn is_present(&self, attributes: &A) -> bool {
        attributes.is_attribute(DATA::KEY)
    }
}

/// Read an attribute from an [event](Event)'s attributes.
pub trait DynReadFromEventAttributes<'value> {
    /// The attribute to be read.
    type Value;

    /// Read an attribute from the provided event attributes.
    fn dyn_read_opt_from_event_attributes<A>(
        &self,
        attributes: &A,
    ) -> Result<Option<Self::Value>, EventError>
    where
        A: AttributesMap;

    /// Read an attribute from the provided event attributes.
    fn dyn_read_from_event_attributes<A>(
        &self,
        attributes: &A,
    ) -> Result<Self::Value, EventError>
    where
        A: AttributesMap;
}

/// Read a raw (string encoded) attribute from an [event](Event)'s attributes.
pub trait DynRawReadFromEventAttributes<'value> {
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn dyn_check_if_present_in<A>(&self, attributes: &A) -> bool
    where
        A: AttributesMap;

    /// Read a string encoded attribute from the provided event attributes.
    fn dyn_raw_read_opt_from_event_attributes<A>(
        &self,
        attributes: &A,
    ) -> Option<&str>
    where
        A: AttributesMap;

    /// Read a string encoded attribute from the provided event attributes.
    fn dyn_raw_read_from_event_attributes<A>(
        &self,
        attributes: &A,
    ) -> Result<&str, EventError>
    where
        A: AttributesMap;
}

#[cfg(test)]
mod dyn_event_composition_tests {
    use super::*;

    #[test]
    fn test_event_attribute_dispatching() {
        enum AttrKind {
            Log,
            Info,
        }

        let attributes = {
            let mut attrs = BTreeMap::new();
            attrs.with_attribute(Info(String::new()));
            attrs
        };

        let log_attribute = attribute_checker::<Log, _>();
        let info_attribute = attribute_checker::<Info, _>();

        let mut found_info = false;
        let mut found_log = false;

        dispatch_attribute(
            &attributes,
            [
                (AttrKind::Info, info_attribute),
                (AttrKind::Log, log_attribute),
            ],
            |kind| {
                match kind {
                    AttrKind::Info => found_info = true,
                    AttrKind::Log => found_log = true,
                }
                ControlFlow::Continue(())
            },
        );

        assert!(found_info && !found_log);
    }
}
