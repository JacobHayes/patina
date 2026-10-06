//! Signed nanosecond serialization and optional timestamp encoding.

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

pub fn serialize<S: Serializer>(nanos: &i128, serializer: S) -> Result<S::Ok, S::Error> {
    if let Ok(value) = i64::try_from(*nanos) {
        serializer.serialize_i64(value)
    } else if let Ok(value) = u64::try_from(*nanos) {
        serializer.serialize_u64(value)
    } else {
        serializer.collect_str(nanos)
    }
}

struct Nanos;

impl Visitor<'_> for Nanos {
    type Value = i128;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("signed nanoseconds, as an integer or a decimal string")
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<i128, E> {
        Ok(i128::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<i128, E> {
        Ok(i128::from(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<i128, E> {
        value.parse().map_err(E::custom)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i128, D::Error> {
    deserializer.deserialize_any(Nanos)
}

/// The same, for a time that may be absent (`UTIME_OMIT`).
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    struct Wrapped(#[serde(with = "super")] i128);

    pub fn serialize<S: Serializer>(
        nanos: &Option<i128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match nanos {
            Some(nanos) => super::serialize(nanos, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i128>, D::Error> {
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|Wrapped(nanos)| nanos))
    }
}
