//! Optional boundary byte payload serialization and decoding.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

pub(crate) fn serialize<S: Serializer>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(bytes) => serializer.serialize_some(&super::bytes_base64::Encoded(bytes)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    deserializer.deserialize_option(OptionalPayloadVisitor)
}

struct OptionalPayloadVisitor;

impl<'de> Visitor<'de> for OptionalPayloadVisitor {
    type Value = Option<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("null or a base64 string")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        super::bytes_base64::deserialize(deserializer).map(Some)
    }
}
