//! Types for dealing with time and durations.

use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::io::Read;
use std::ops::{Add, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use chrono::ParseError;
pub use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// Check if the given `duration` has passed since the given `start.
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
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Rfc3339String(pub String);

/// A duration in seconds precision.
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
    /// Returns a DateTimeUtc which corresponds to the current date.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Returns a [`DateTimeUtc`] corresponding to the provided Unix timestamp.
    #[inline]
    pub fn from_unix_timestamp(timestamp: i64) -> Option<Self> {
        Some(Self(chrono::Utc.from_utc_datetime(
            &chrono::NaiveDateTime::from_timestamp_opt(timestamp, 0)?,
        )))
    }

    /// Returns a [`DateTimeUtc`] corresponding to the Unix epoch.
    #[inline]
    pub fn unix_epoch() -> Self {
        Self::from_unix_timestamp(0)
            .expect("This operation should be infallible")
    }

    /// Returns an rfc3339 string or an error.
    pub fn to_rfc3339(&self) -> String {
        chrono::DateTime::to_rfc3339(&self.0)
    }

    /// Returns the DateTimeUtc corresponding to one second in the future
    pub fn next_second(&self) -> Self {
        *self + DurationSecs(0)
    }
}

impl FromStr for DateTimeUtc {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<DateTime<Utc>>()?))
    }
}

impl Add<DurationSecs> for DateTimeUtc {
    type Output = DateTimeUtc;

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

    fn add(self, rhs: Duration) -> Self::Output {
        (self.0 + rhs).into()
    }
}

impl Sub<Duration> for DateTimeUtc {
    type Output = DateTimeUtc;

    fn sub(self, rhs: Duration) -> Self::Output {
        (self.0 - rhs).into()
    }
}

impl BorshSerialize for DateTimeUtc {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let raw = self.0.to_rfc3339();
        BorshSerialize::serialize(&raw, writer)
    }
}

impl BorshDeserialize for DateTimeUtc {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let raw: String = BorshDeserialize::deserialize_reader(reader)?;
        let actual = DateTime::parse_from_rfc3339(&raw)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self(actual.into()))
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
        let utc = DateTime::parse_from_rfc3339(&str.0)?;
        Ok(Self(utc.into()))
    }
}

impl From<DateTimeUtc> for Rfc3339String {
    fn from(dt: DateTimeUtc) -> Self {
        Self(DateTime::to_rfc3339(&dt.0))
    }
}

impl TryFrom<DateTimeUtc> for crate::tendermint::time::Time {
    type Error = crate::tendermint::Error;

    fn try_from(dt: DateTimeUtc) -> Result<Self, Self::Error> {
        Self::parse_from_rfc3339(&DateTime::to_rfc3339(&dt.0))
    }
}

impl TryFrom<crate::tendermint::time::Time> for DateTimeUtc {
    type Error = chrono::ParseError;

    fn try_from(t: crate::tendermint::time::Time) -> Result<Self, Self::Error> {
        Rfc3339String(t.to_rfc3339()).try_into()
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
