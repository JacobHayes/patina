//! Canonical SHA-256 digest values and text encoding.

use std::fmt;

use crate::TraceError;

/// A SHA-256 digest in its one text form, `sha256:` followed by 64 lowercase
/// hex digits: how a lifecycle marker names the recovered filesystem snapshot,
/// and how the supervisor reports digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    const PREFIX: &'static str = "sha256:";

    pub fn parse(text: &str) -> Result<Self, TraceError> {
        let invalid = || {
            TraceError::Invalid(format!(
                "digest {text:?} must use sha256:<64 lowercase hex>"
            ))
        };
        let hex = text.strip_prefix(Self::PREFIX).ok_or_else(invalid)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(invalid());
        }
        let mut digest = [0_u8; 32];
        for (byte, pair) in digest
            .iter_mut()
            .zip(hex.as_bytes().as_chunks::<2>().0.iter())
        {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(digest))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Serialized in its one text form, so a stored digest reads exactly as the
/// supervisor reports it, and a malformed one is refused when it is decoded.
impl serde::Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest's text form is `sha256:` and lowercase hex, it parses back,
    /// and serde uses exactly that text: uppercase or bare hex is refused.
    #[test]
    fn sha256_digest_text_and_serde_forms_round_trip() {
        let digest = Sha256Digest([0xab; 32]);
        let text = digest.to_string();
        assert_eq!(text, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(Sha256Digest::parse(&text).unwrap(), digest);
        assert!(Sha256Digest::parse(&text.to_uppercase().replace("SHA256", "sha256")).is_err());
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"{digest}\""));
        assert_eq!(serde_json::from_str::<Sha256Digest>(&json).unwrap(), digest);
        assert!(serde_json::from_str::<Sha256Digest>("\"abab\"").is_err());
    }
}
