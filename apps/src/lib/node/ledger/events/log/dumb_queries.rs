//! Silly simple Tendermint query parser.
//!
//! This parser will only work with simple queries of the form:
//!
//! ```text
//! tm.event='NewBlock' AND <accepted|applied>.<$attr>='<$value>'
//! ```

use lazy_static::lazy_static;
use regex::Regex;

use crate::node::ledger::events::{Event, EventType};

/// Regular expression used to parse Tendermint queries.
const QUERY_PARSING_REGEX_STR: &str =
    r"^tm\.event='NewBlock' AND (accepted|applied)\.([\w_]+)='([^']+)'$";

lazy_static! {
    /// Compiled regular expression used to parse Tendermint queries.
    static ref QUERY_PARSING_REGEX: Regex = Regex::new(QUERY_PARSING_REGEX_STR).unwrap();
}

/// A [`QueryMatcher`] verifies if a Namada event matches a
/// given Tendermint query.
#[derive(Debug, Clone)]
pub struct QueryMatcher<'q> {
    event_type: EventType,
    attr: String,
    value: &'q str,
}

impl<'q> QueryMatcher<'q> {
    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &Event) -> bool {
        event.event_type == self.event_type
            && event
                .attributes
                .get(&self.attr)
                .map(|value| value == self.value)
                .unwrap_or_default()
    }

    /// Parses a Tendermint-like events query.
    pub fn parse(query: &'q str) -> Option<Self> {
        let captures = QUERY_PARSING_REGEX.captures(query)?;

        let event_type = match captures.get(1)?.as_str() {
            "accepted" => EventType::Accepted,
            "applied" => EventType::Applied,
            // NOTE: the regex only matches `accepted`
            // and `applied`
            _ => unreachable!(),
        };
        let attr = captures.get(2)?.as_str().to_string();
        let value = captures.get(3)?.as_str();

        Some(Self {
            event_type,
            attr,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::string::{string_regex, RegexGeneratorStrategy};

    use super::*;
    use crate::node::ledger::events::EventLevel;

    /// Returns a proptest strategy that yields Tendermint-like queries.
    fn tm_query_strat() -> RegexGeneratorStrategy<String> {
        string_regex(
            // slice out the string init and end specifiers
            &QUERY_PARSING_REGEX_STR[1..QUERY_PARSING_REGEX_STR.len() - 1],
        )
        .unwrap()
    }

    proptest! {
        /// Test if we can parse a Tendermint query, feeding [`QueryMatcher::parse`]
        /// random input data.
        #[test]
        fn test_random_inputs(query in tm_query_strat()) {
            QueryMatcher::parse(&query).unwrap();
        }
    }

    /// Test if we parse a correct Tendermint query.
    #[test]
    fn test_parse_correct_tm_query() {
        let q = QueryMatcher::parse(
            "tm.event='NewBlock' AND applied.hash='123456'",
        )
        .unwrap();

        assert_eq!(q.event_type, EventType::Applied);
        assert_eq!(&q.attr, "hash");
        assert_eq!(q.value, "123456");

        let q = QueryMatcher::parse(
            "tm.event='NewBlock' AND accepted.hash='DEADBEEF'",
        )
        .unwrap();

        assert_eq!(q.event_type, EventType::Accepted);
        assert_eq!(&q.attr, "hash");
        assert_eq!(q.value, "DEADBEEF");
    }

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        let matcher = QueryMatcher {
            event_type: EventType::Accepted,
            attr: "hash".to_string(),
            value: "DEADBEEF",
        };

        let tests = {
            let event_1 = Event {
                event_type: EventType::Accepted,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), "DEADBEEF".to_string());
                    attrs
                },
            };
            let accepted_1 = true;

            let event_2 = Event {
                event_type: EventType::Applied,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), "DEADBEEF".to_string());
                    attrs
                },
            };
            let accepted_2 = false;

            [(event_1, accepted_1), (event_2, accepted_2)]
        };

        for (ref ev, status) in tests {
            if matcher.matches(ev) != status {
                panic!("Test failed");
            }
        }
    }
}
