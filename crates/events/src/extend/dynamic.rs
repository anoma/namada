//! Extend [events](Event) with additional fields,
//! whose attributes are determined dynamically at
//! runtime.

use super::*;

/// Checks for the presence of an attribute in the
/// provided attributes map.
pub trait EventAttributeChecker<'value, A>
where
    A: AttributesMap,
{
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn is_present(&self, attributes: &A) -> bool
    where
        A: AttributesMap;
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
    fn is_present(&self, attributes: &A) -> bool
    where
        A: AttributesMap,
    {
        attributes.is_attribute(DATA::KEY)
    }
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
