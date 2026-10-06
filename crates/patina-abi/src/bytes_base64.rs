//! Base64 serialization and decoding for boundary byte payloads.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// serde_json streams collect_str directly to its writer. In particular,
// native terminal prefix export must not allocate a base64 String while a
// stopped guest may own its allocator. Full blocks are divisible by three,
// so only the final block can contain padding; wire bytes are unchanged.
pub(super) struct Encoded<'a>(pub &'a [u8]);
impl fmt::Display for Encoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = [0u8; 1024];
        for block in self.0.chunks(768) {
            let mut written = 0;
            for chunk in block.chunks(3) {
                let second = chunk.get(1).copied();
                let third = chunk.get(2).copied();
                let packed = (u32::from(chunk[0]) << 16)
                    | (u32::from(second.unwrap_or(0)) << 8)
                    | u32::from(third.unwrap_or(0));
                let quartet = [
                    ALPHABET[(packed >> 18 & 0x3f) as usize],
                    ALPHABET[(packed >> 12 & 0x3f) as usize],
                    if second.is_some() {
                        ALPHABET[(packed >> 6 & 0x3f) as usize]
                    } else {
                        b'='
                    },
                    if third.is_some() {
                        ALPHABET[(packed & 0x3f) as usize]
                    } else {
                        b'='
                    },
                ];
                out[written..written + 4].copy_from_slice(&quartet);
                written += 4;
            }
            f.write_str(std::str::from_utf8(&out[..written]).expect("base64 is ASCII"))?;
        }
        Ok(())
    }
}
impl serde::Serialize for Encoded<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn sextet(symbol: u8) -> Option<u32> {
    match symbol {
        b'A'..=b'Z' => Some(u32::from(symbol - b'A')),
        b'a'..=b'z' => Some(u32::from(symbol - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(symbol - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub(crate) fn decode(text: &str) -> Result<Vec<u8>, String> {
    let symbols = text.as_bytes();
    if symbols.len() % 4 != 0 {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            symbols.len()
        ));
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for chunk in symbols.chunks(4) {
        let padding = chunk.iter().rev().take_while(|&&s| s == b'=').count();
        if padding > 2 {
            return Err("base64 chunk has more than two padding characters".into());
        }
        let mut packed = 0u32;
        for (index, &symbol) in chunk.iter().enumerate() {
            let value = if symbol == b'=' {
                if index < 4 - padding {
                    return Err("base64 padding appears mid-chunk".into());
                }
                0
            } else {
                sextet(symbol)
                    .ok_or_else(|| format!("invalid base64 character {:?}", symbol as char))?
            };
            packed = (packed << 6) | value;
        }
        out.push((packed >> 16 & 0xff) as u8);
        if padding < 2 {
            out.push((packed >> 8 & 0xff) as u8);
        }
        if padding < 1 {
            out.push((packed & 0xff) as u8);
        }
    }
    Ok(out)
}

pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&Encoded(bytes))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_any(PayloadVisitor)
}

struct PayloadVisitor;

impl<'de> Visitor<'de> for PayloadVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a base64 string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        decode(value).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Outcome, bytes_base64};

    #[test]
    fn base64_round_trips_all_lengths_and_rejects_malformed_input() {
        for len in 0..=32usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let encoded = bytes_base64::Encoded(&bytes).to_string();
            assert_eq!(encoded.len() % 4, 0);
            assert_eq!(bytes_base64::decode(&encoded).unwrap(), bytes);
        }
        // Known vectors and fail-closed rejection of malformed strings.
        assert_eq!(bytes_base64::Encoded(b"Man").to_string(), "TWFu");
        assert_eq!(bytes_base64::Encoded(b"Ma").to_string(), "TWE=");
        assert!(bytes_base64::decode("TWFu=").is_err()); // not a multiple of 4
        assert!(bytes_base64::decode("T=Fu").is_err()); // mid-chunk padding
        assert!(bytes_base64::decode("T@Fu").is_err()); // invalid character
    }

    #[test]
    fn streamed_base64_preserves_bytes_at_buffer_and_padding_boundaries() {
        for len in [0, 1, 2, 3, 767, 768, 769, 1535, 1536, 1537, 4097] {
            let bytes = vec![255; len];
            let mut expected = "/".repeat(len / 3 * 4);
            expected.push_str(match len % 3 {
                1 => "/w==",
                2 => "//8=",
                _ => "",
            });
            for outcome in [
                Outcome::Bytes(bytes.clone()),
                Outcome::OptionalBytes(Some(bytes.clone())),
            ] {
                let mut json = Vec::new();
                serde_json::to_writer(&mut json, &outcome).unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&json).unwrap()["value"],
                    expected
                );
                assert_eq!(serde_json::from_slice::<Outcome>(&json).unwrap(), outcome);
            }
        }
    }
}
