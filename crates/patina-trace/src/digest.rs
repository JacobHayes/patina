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
        for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_text_round_trips() {
        let digest = Sha256Digest([0xab; 32]);
        let text = digest.to_string();
        assert_eq!(text, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(Sha256Digest::parse(&text).unwrap(), digest);
    }

    #[test]
    fn sha256_digest_refuses_uppercase_hex() {
        let text = format!("sha256:{}", "AB".repeat(32));
        assert!(Sha256Digest::parse(&text).is_err());
    }
}
