//! Types for dealing with time and durations.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::Read;
use std::ops::{Add, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use chrono::ParseError;
pub use chrono::{DateTime, Duration, TimeZone, Utc};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

/// Check if the given `duration` has passed since the given `start.
#[allow(clippy::arithmetic_side_effects)]
pub fn duration_passed(
    current: DateTimeUtc,
    start: DateTimeUtc,
    duration: DurationSecs,
) -> bool {
    start + duration <= current
}

/// A duration in seconds precision.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct DurationSecs(pub u64);

impl From<Duration> for DurationSecs {
    fn from(duration_chrono: Duration) -> Self {
        let duration_std = duration_chrono
            .to_std()
            .expect("Duration must not be negative");
        duration_std.into()
    }
}

impl From<std::time::Duration> for DurationSecs {
    fn from(duration_std: std::time::Duration) -> Self {
        DurationSecs(duration_std.as_secs())
    }
}

impl From<DurationSecs> for std::time::Duration {
    fn from(duration_secs: DurationSecs) -> Self {
        std::time::Duration::new(duration_secs.0, 0)
    }
}

impl Display for DurationSecs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A duration in nanos precision.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct DurationNanos {
    /// The seconds
    pub secs: u64,
    /// The nano seconds
    pub nanos: u32,
}

impl From<std::time::Duration> for DurationNanos {
    fn from(duration_std: std::time::Duration) -> Self {
        DurationNanos {
            secs: duration_std.as_secs(),
            nanos: duration_std.subsec_nanos(),
        }
    }
}

impl From<DurationNanos> for std::time::Duration {
    fn from(DurationNanos { secs, nanos }: DurationNanos) -> Self {
        Self::new(secs, nanos)
    }
}

/// An RFC 3339 timestamp (e.g., "1970-01-01T00:00:00Z").
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Rfc3339String(pub String);

/// A duration in seconds precision.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    BorshDeserializer,
)]
#[serde(try_from = "Rfc3339String", into = "Rfc3339String")]
pub struct DateTimeUtc(pub DateTime<Utc>);

/// The minimum possible `DateTime<Utc>`.
pub const MIN_UTC: DateTimeUtc = DateTimeUtc(chrono::DateTime::<Utc>::MIN_UTC);

impl Display for DateTimeUtc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_rfc3339())
    }
}

impl DateTimeUtc {
    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.9f+00:00";

    /// Returns a DateTimeUtc which corresponds to the current date.
    pub fn now() -> Self {
        Self(
            #[allow(clippy::disallowed_methods)]
            Utc::now(),
        )
    }

    /// Returns the unix timestamp associated with this [`DateTimeUtc`].
    #[inline]
    pub fn to_unix_timestamp(&self) -> i64 {
        self.0.timestamp()
    }

    /// Returns a [`DateTimeUtc`] corresponding to the provided Unix timestamp.
    #[inline]
    pub fn from_unix_timestamp(timestamp: i64) -> Option<Self> {
        Some(Self(chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)?))
    }

    /// Returns a [`DateTimeUtc`] corresponding to the Unix epoch.
    #[inline]
    pub fn unix_epoch() -> Self {
        Self::from_unix_timestamp(0)
            .expect("This operation should be infallible")
    }

    /// Returns an rfc3339 string or an error.
    pub fn to_rfc3339(&self) -> String {
        self.0.format(DateTimeUtc::FORMAT).to_string()
    }

    /// Parses a rfc3339 string, or returns an error.
    pub fn from_rfc3339(s: &str) -> Result<Self, ParseError> {
        use chrono::format;
        use chrono::format::strftime::StrftimeItems;

        let format = StrftimeItems::new(Self::FORMAT);
        let mut parsed = format::Parsed::new();
        format::parse(&mut parsed, s, format)?;

        parsed.to_datetime_with_timezone(&chrono::Utc).map(Self)
    }

    /// Returns the DateTimeUtc corresponding to one second in the future
    #[allow(clippy::arithmetic_side_effects)]
    pub fn next_second(&self) -> Self {
        *self + DurationSecs(1)
    }
}

impl FromStr for DateTimeUtc {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_rfc3339(s)
    }
}

impl Add<DurationSecs> for DateTimeUtc {
    type Output = DateTimeUtc;

    #[allow(clippy::arithmetic_side_effects)]
    fn add(self, duration: DurationSecs) -> Self::Output {
        let duration_std = std::time::Duration::from_secs(duration.0);
        let duration_chrono = Duration::from_std(duration_std).expect(
            "Duration shouldn't be larger than the maximum value supported \
             for chrono::Duration",
        );
        (self.0 + duration_chrono).into()
    }
}

impl Add<Duration> for DateTimeUtc {
    type Output = DateTimeUtc;

    #[allow(clippy::arithmetic_side_effects)]
    fn add(self, rhs: Duration) -> Self::Output {
        (self.0 + rhs).into()
    }
}

impl Sub<Duration> for DateTimeUtc {
    type Output = DateTimeUtc;

    #[allow(clippy::arithmetic_side_effects)]
    fn sub(self, rhs: Duration) -> Self::Output {
        (self.0 - rhs).into()
    }
}

impl Sub<DateTimeUtc> for DateTimeUtc {
    type Output = DurationSecs;

    #[allow(clippy::arithmetic_side_effects)]
    fn sub(self, rhs: DateTimeUtc) -> Self::Output {
        (self.0 - rhs.0)
            .to_std()
            .map(DurationSecs::from)
            .unwrap_or(DurationSecs(0))
    }
}

impl BorshSerialize for DateTimeUtc {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let raw = self.to_rfc3339();
        BorshSerialize::serialize(&raw, writer)
    }
}

impl BorshDeserialize for DateTimeUtc {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let raw: String = BorshDeserialize::deserialize_reader(reader)?;
        Self::from_rfc3339(&raw)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))
    }
}

impl BorshSchema for DateTimeUtc {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as rfc3339 `String`
        let fields =
            borsh::schema::Fields::UnnamedFields(vec!["string".into()]);
        let definition = borsh::schema::Definition::Struct { fields };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "DateTimeUtc".into()
    }
}

impl From<DateTime<Utc>> for DateTimeUtc {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

impl TryFrom<prost_types::Timestamp> for DateTimeUtc {
    type Error = prost_types::TimestampError;

    fn try_from(
        timestamp: prost_types::Timestamp,
    ) -> Result<Self, Self::Error> {
        let system_time: std::time::SystemTime = timestamp.try_into()?;
        Ok(Self(system_time.into()))
    }
}

impl From<DateTimeUtc> for prost_types::Timestamp {
    fn from(dt: DateTimeUtc) -> Self {
        let seconds = dt.0.timestamp();
        // The cast cannot wrap as the value is at most 1_999_999_999
        #[allow(clippy::cast_possible_wrap)]
        let nanos = dt.0.timestamp_subsec_nanos() as i32;
        prost_types::Timestamp { seconds, nanos }
    }
}

impl TryFrom<crate::tendermint_proto::google::protobuf::Timestamp>
    for DateTimeUtc
{
    type Error = prost_types::TimestampError;

    fn try_from(
        timestamp: crate::tendermint_proto::google::protobuf::Timestamp,
    ) -> Result<Self, Self::Error> {
        Self::try_from(prost_types::Timestamp {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        })
    }
}

impl From<DateTimeUtc> for std::time::SystemTime {
    fn from(dt: DateTimeUtc) -> Self {
        dt.0.into()
    }
}

impl TryFrom<Rfc3339String> for DateTimeUtc {
    type Error = chrono::ParseError;

    fn try_from(str: Rfc3339String) -> Result<Self, Self::Error> {
        Self::from_rfc3339(&str.0)
    }
}

impl From<DateTimeUtc> for Rfc3339String {
    fn from(dt: DateTimeUtc) -> Self {
        Self(dt.to_rfc3339())
    }
}

impl TryFrom<DateTimeUtc> for crate::tendermint::time::Time {
    type Error = crate::tendermint::Error;

    fn try_from(dt: DateTimeUtc) -> Result<Self, Self::Error> {
        Self::parse_from_rfc3339(&dt.to_rfc3339())
    }
}

impl TryFrom<crate::tendermint::time::Time> for DateTimeUtc {
    type Error = prost_types::TimestampError;

    fn try_from(t: crate::tendermint::time::Time) -> Result<Self, Self::Error> {
        crate::tendermint_proto::google::protobuf::Timestamp::from(t).try_into()
    }
}

impl From<crate::tendermint::Timeout> for DurationNanos {
    fn from(val: crate::tendermint::Timeout) -> Self {
        Self::from(std::time::Duration::from(val))
    }
}

impl From<DurationNanos> for crate::tendermint::Timeout {
    fn from(val: DurationNanos) -> Self {
        Self::from(std::time::Duration::from(val))
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_utils {
    //! Time related test utilities.

    /// Genesis time used during tests.
    pub const GENESIS_TIME: &str = "2023-08-30T00:00:00.000000000+00:00";
}

#[cfg(test)]
mod core_time_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn test_valid_reverse_datetime_utc_encoding_roundtrip(
            year in 1974..=3_000,
            month in 1..=12,
            day in 1..=28,
            hour in 0..=23,
            min in 0..=59,
            sec in 0..=59,
            nanos in 0..=999_999_999,
        )
        {
            let timestamp = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{nanos:09}+00:00");
            println!("Testing timestamp: {timestamp}");
            test_valid_reverse_datetime_utc_encoding_roundtrip_inner(&timestamp);
        }
    }

    fn test_valid_reverse_datetime_utc_encoding_roundtrip_inner(
        timestamp: &str,
    ) {
        // we should be able to parse our custom datetime
        let datetime = DateTimeUtc::from_rfc3339(timestamp).unwrap();

        // the chrono datetime, which uses a superset of
        // our datetime format should also be parsable
        let datetime_inner = DateTime::parse_from_rfc3339(timestamp)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(datetime, DateTimeUtc(datetime_inner));

        let encoded = datetime.to_rfc3339();

        assert_eq!(encoded, timestamp);
    }

    #[test]
    fn test_invalid_datetime_utc_encoding() {
        // NB: this is a valid rfc3339 string, but we enforce
        // a subset of the format to get deterministic encoding
        // results
        const TIMESTAMP: &str = "1966-03-03T00:06:56.520Z";
        // const TIMESTAMP: &str = "1966-03-03T00:06:56.520+00:00";

        // this is a valid rfc3339 string
        assert!(DateTime::parse_from_rfc3339(TIMESTAMP).is_ok());

        // but it cannot be parsed as a `DateTimeUtc`
        assert!(DateTimeUtc::from_rfc3339(TIMESTAMP).is_err());
    }

    #[test]
    fn test_valid_test_utils_genesis_time() {
        assert!(DateTimeUtc::from_rfc3339(test_utils::GENESIS_TIME).is_ok());
    }
}
