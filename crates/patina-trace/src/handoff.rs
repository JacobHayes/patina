//! Canonical crash-restart handoff codec.
//!
//! The handoff is the supervisor-owned envelope around an `FsSnapshot` used to
//! transfer the recovered durable filesystem image from one guest incarnation to
//! the next. It is deliberately binary and bounded: the supervisor can seal and
//! verify the exact bytes it passes between incarnations, while the guest never
//! supplies or interprets the key.

use std::fmt;

use patina_dst_fs_mem::{FsSnapshot, FsSnapshotError};
use sha2::{Digest, Sha256};

use crate::{CrashPointRecord, FaultCrashOp};

const MAGIC: &[u8; 12] = b"PATINA-HO-v1";
const VERSION: u32 = 1;
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"patina-incarnation-handoff-snapshot-digest/v1";
const SEAL_DOMAIN: &[u8] = b"patina-incarnation-handoff-seal/v1";

/// Maximum encoded handoff payload before the fixed digest and seal trailers.
/// The filesystem snapshot itself is capped by `FsSnapshot::decode`; this adds
/// only a small allowance for supervisor metadata so a corrupt length cannot
/// drive unbounded allocation before the nested snapshot decoder runs.
pub const MAX_HANDOFF_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024 + 64 * 1024;
const MAX_FINGERPRINT_BYTES: u64 = 64 * 1024;
const DIGEST_LEN: usize = 32;
const SEAL_LEN: usize = 32;

/// Supervisor key for the handoff seal.
///
/// This is a domain-separated keyed SHA-256 integrity check, not an HMAC and not
/// a guest authentication claim. The API keeps sealing and verification
/// explicit so a later phase can swap in HMAC without changing the handoff
/// fields or allowing unsealed data to be accepted accidentally.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HandoffSealKey([u8; 32]);

impl fmt::Debug for HandoffSealKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandoffSealKey([redacted; 32])")
    }
}

impl HandoffSealKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The trace position already consumed by the crashed incarnation when the
/// restart snapshot was exported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoffConsumedState {
    /// Number of boundary operations consumed/recorded before the crash handoff.
    pub operations: u64,
    /// Last lifecycle/global-order slot consumed by the crashed incarnation.
    pub lifecycle_order: u64,
}

/// A supervisor-sealed filesystem image handoff from one incarnation to another.
#[derive(Clone, Debug)]
pub struct IncarnationHandoff {
    pub compatibility_fingerprint: String,
    pub from_incarnation: u64,
    pub to_incarnation: u64,
    pub selector: CrashPointRecord,
    pub consumed: HandoffConsumedState,
    pub snapshot: FsSnapshot,
}

impl IncarnationHandoff {
    /// Encode and seal this handoff in canonical wire format.
    pub fn seal(&self, key: &HandoffSealKey) -> Result<Vec<u8>, HandoffError> {
        validate_metadata(
            &self.compatibility_fingerprint,
            self.from_incarnation,
            self.to_incarnation,
            self.selector,
        )?;
        let snapshot_bytes = self.snapshot.encode().map_err(HandoffError::Snapshot)?;
        let mut payload = Vec::new();
        encode_string(&mut payload, &self.compatibility_fingerprint)?;
        payload.extend_from_slice(&self.from_incarnation.to_le_bytes());
        payload.extend_from_slice(&self.to_incarnation.to_le_bytes());
        payload.push(encode_op(self.selector.op));
        payload.extend_from_slice(&self.selector.ordinal.to_le_bytes());
        payload.extend_from_slice(&self.consumed.operations.to_le_bytes());
        payload.extend_from_slice(&self.consumed.lifecycle_order.to_le_bytes());
        encode_bytes(&mut payload, &snapshot_bytes)?;
        if payload.len() as u64 > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(HandoffError::LimitExceeded("handoff payload"));
        }

        let snapshot_digest = snapshot_digest(&snapshot_bytes);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&snapshot_digest);
        let seal = seal_bytes(key, &bytes);
        bytes.extend_from_slice(&seal);
        Ok(bytes)
    }

    /// Verify, decode, and snapshot-validate a handoff before accepting it.
    pub fn open(
        bytes: &[u8],
        key: &HandoffSealKey,
    ) -> Result<VerifiedIncarnationHandoff, HandoffError> {
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(HandoffError::BadMagic);
        }
        let version = reader.take_u32()?;
        if version != VERSION {
            return Err(HandoffError::UnsupportedVersion(version));
        }
        let payload_len = reader.take_u64()?;
        if payload_len > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(HandoffError::LimitExceeded("handoff payload"));
        }
        let payload = reader.take(payload_len as usize)?.to_vec();
        let recorded_digest = to_array::<DIGEST_LEN>(reader.take(DIGEST_LEN)?)?;
        let recorded_seal = to_array::<SEAL_LEN>(reader.take(SEAL_LEN)?)?;
        if !reader.is_empty() {
            return Err(HandoffError::TrailingBytes);
        }
        let sealed_len = MAGIC.len() + 4 + 8 + payload.len() + DIGEST_LEN;
        let expected_seal = seal_bytes(key, &bytes[..sealed_len]);
        if !constant_time_eq(&recorded_seal, &expected_seal) {
            return Err(HandoffError::SealMismatch);
        }

        let mut payload_reader = Reader::new(&payload);
        let compatibility_fingerprint = payload_reader.take_string("compatibility fingerprint")?;
        let from_incarnation = payload_reader.take_u64()?;
        let to_incarnation = payload_reader.take_u64()?;
        let op_code = payload_reader.take_u8()?;
        let selector = CrashPointRecord {
            op: decode_op(op_code)?,
            ordinal: payload_reader.take_u64()?,
        };
        let consumed = HandoffConsumedState {
            operations: payload_reader.take_u64()?,
            lifecycle_order: payload_reader.take_u64()?,
        };
        let snapshot_bytes = payload_reader.take_bytes()?.to_vec();
        if !payload_reader.is_empty() {
            return Err(HandoffError::Malformed(
                "trailing bytes inside handoff payload",
            ));
        }
        validate_metadata(
            &compatibility_fingerprint,
            from_incarnation,
            to_incarnation,
            selector,
        )?;
        let computed_digest = snapshot_digest(&snapshot_bytes);
        if recorded_digest != computed_digest {
            return Err(HandoffError::SnapshotDigestMismatch);
        }
        let snapshot = FsSnapshot::decode(&snapshot_bytes).map_err(HandoffError::Snapshot)?;
        Ok(VerifiedIncarnationHandoff {
            compatibility_fingerprint,
            from_incarnation,
            to_incarnation,
            selector,
            consumed,
            snapshot_digest: recorded_digest,
            snapshot_bytes,
            snapshot,
        })
    }
}

/// A handoff accepted after seal, digest, structure, and nested snapshot checks.
#[derive(Clone, Debug)]
pub struct VerifiedIncarnationHandoff {
    pub compatibility_fingerprint: String,
    pub from_incarnation: u64,
    pub to_incarnation: u64,
    pub selector: CrashPointRecord,
    pub consumed: HandoffConsumedState,
    pub snapshot_digest: [u8; 32],
    pub snapshot_bytes: Vec<u8>,
    pub snapshot: FsSnapshot,
}

#[derive(Debug)]
pub enum HandoffError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
    TrailingBytes,
    LimitExceeded(&'static str),
    Malformed(&'static str),
    SealMismatch,
    SnapshotDigestMismatch,
    Snapshot(FsSnapshotError),
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("bad incarnation handoff magic"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported incarnation handoff version {version}"
                )
            }
            Self::Truncated => formatter.write_str("truncated incarnation handoff"),
            Self::TrailingBytes => formatter.write_str("trailing bytes after incarnation handoff"),
            Self::LimitExceeded(field) => {
                write!(formatter, "incarnation handoff {field} exceeds limit")
            }
            Self::Malformed(message) => {
                write!(formatter, "malformed incarnation handoff: {message}")
            }
            Self::SealMismatch => formatter.write_str("incarnation handoff seal mismatch"),
            Self::SnapshotDigestMismatch => {
                formatter.write_str("incarnation handoff snapshot digest mismatch")
            }
            Self::Snapshot(error) => {
                write!(formatter, "invalid incarnation handoff snapshot: {error}")
            }
        }
    }
}

impl std::error::Error for HandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Snapshot(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_metadata(
    fingerprint: &str,
    from_incarnation: u64,
    to_incarnation: u64,
    selector: CrashPointRecord,
) -> Result<(), HandoffError> {
    if fingerprint.is_empty() {
        return Err(HandoffError::Malformed(
            "compatibility fingerprint is empty",
        ));
    }
    if fingerprint.len() as u64 > MAX_FINGERPRINT_BYTES {
        return Err(HandoffError::LimitExceeded("compatibility fingerprint"));
    }
    if to_incarnation <= from_incarnation {
        return Err(HandoffError::Malformed(
            "to incarnation must be greater than from incarnation",
        ));
    }
    if selector.ordinal == 0 {
        return Err(HandoffError::Malformed("crash selector ordinal is zero"));
    }
    Ok(())
}

fn encode_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), HandoffError> {
    if value.len() as u64 > MAX_FINGERPRINT_BYTES {
        return Err(HandoffError::LimitExceeded("compatibility fingerprint"));
    }
    encode_bytes(bytes, value.as_bytes())
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), HandoffError> {
    let len = u64::try_from(bytes.len()).map_err(|_| HandoffError::LimitExceeded("field"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_op(op: FaultCrashOp) -> u8 {
    match op {
        FaultCrashOp::Open => 0,
        FaultCrashOp::Write => 1,
        FaultCrashOp::Sync => 2,
        FaultCrashOp::Close => 3,
    }
}

fn decode_op(value: u8) -> Result<FaultCrashOp, HandoffError> {
    match value {
        0 => Ok(FaultCrashOp::Open),
        1 => Ok(FaultCrashOp::Write),
        2 => Ok(FaultCrashOp::Sync),
        3 => Ok(FaultCrashOp::Close),
        _ => Err(HandoffError::Malformed("unknown crash selector op")),
    }
}

fn snapshot_digest(snapshot_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DIGEST_DOMAIN);
    hasher.update((snapshot_bytes.len() as u64).to_le_bytes());
    hasher.update(snapshot_bytes);
    hasher.finalize().into()
}

fn seal_bytes(key: &HandoffSealKey, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEAL_DOMAIN);
    hasher.update(key.bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], HandoffError> {
    bytes.try_into().map_err(|_| HandoffError::Truncated)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], HandoffError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(HandoffError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(HandoffError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, HandoffError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, HandoffError> {
        Ok(u32::from_le_bytes(to_array(self.take(4)?)?))
    }

    fn take_u64(&mut self) -> Result<u64, HandoffError> {
        Ok(u64::from_le_bytes(to_array(self.take(8)?)?))
    }

    fn take_bytes(&mut self) -> Result<&'a [u8], HandoffError> {
        let len = self.take_u64()?;
        if len > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(HandoffError::LimitExceeded("field"));
        }
        self.take(len as usize)
    }

    fn take_string(&mut self, field: &'static str) -> Result<String, HandoffError> {
        let bytes = self.take_bytes()?;
        if bytes.len() as u64 > MAX_FINGERPRINT_BYTES {
            return Err(HandoffError::LimitExceeded(field));
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| HandoffError::Malformed("field is not UTF-8"))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_driver_api::FsDriver;
    use patina_dst_fs_mem::MemFs;

    use super::*;
    use patina_dst_abi::FsClock;

    fn key() -> HandoffSealKey {
        HandoffSealKey::from_bytes([7; 32])
    }

    fn handoff() -> IncarnationHandoff {
        let mut fs = MemFs::new();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/state",
                patina_dst_abi::OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"stable").unwrap();
        fs.close(fd).unwrap();
        IncarnationHandoff {
            compatibility_fingerprint: "fingerprint+crash-restart".to_string(),
            from_incarnation: 0,
            to_incarnation: 1,
            selector: CrashPointRecord {
                op: FaultCrashOp::Write,
                ordinal: 3,
            },
            consumed: HandoffConsumedState {
                operations: 8,
                lifecycle_order: 10,
            },
            snapshot: fs.export_snapshot(),
        }
    }

    #[test]
    fn handoff_seal_key_debug_is_redacted() {
        let text = format!("{:?}", key());
        assert_eq!(text, "HandoffSealKey([redacted; 32])");
        assert!(
            !text.contains("07"),
            "debug output must not leak key bytes: {text}"
        );
    }

    #[test]
    fn handoff_seal_open_is_canonical_and_validates_snapshot() {
        let encoded = handoff().seal(&key()).unwrap();
        let verified = IncarnationHandoff::open(&encoded, &key()).unwrap();
        assert_eq!(
            verified.compatibility_fingerprint,
            "fingerprint+crash-restart"
        );
        assert_eq!(verified.from_incarnation, 0);
        assert_eq!(verified.to_incarnation, 1);
        assert_eq!(verified.selector.op, FaultCrashOp::Write);
        assert_eq!(verified.selector.ordinal, 3);
        assert_eq!(verified.consumed.operations, 8);
        assert_eq!(verified.consumed.lifecycle_order, 10);
        let fs = verified.snapshot.into_memfs();
        assert_eq!(fs.contents("/state").unwrap(), b"stable");

        let repeated = handoff().seal(&key()).unwrap();
        assert_eq!(encoded, repeated, "handoff encoding must be canonical");
    }

    #[test]
    fn handoff_refuses_corruption_wrong_key_and_trailing_bytes() {
        let encoded = handoff().seal(&key()).unwrap();
        let mut corrupted = encoded.clone();
        let payload_byte = MAGIC.len() + 4 + 8 + 12;
        corrupted[payload_byte] ^= 0x01;
        assert!(matches!(
            IncarnationHandoff::open(&corrupted, &key()),
            Err(HandoffError::SealMismatch)
        ));
        assert!(matches!(
            IncarnationHandoff::open(&encoded, &HandoffSealKey::from_bytes([8; 32])),
            Err(HandoffError::SealMismatch)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            IncarnationHandoff::open(&trailing, &key()),
            Err(HandoffError::TrailingBytes)
        ));
    }

    #[test]
    fn handoff_refuses_digest_mismatch_even_with_matching_seal() {
        let mut encoded = handoff().seal(&key()).unwrap();
        let digest_offset = encoded.len() - SEAL_LEN - DIGEST_LEN;
        encoded[digest_offset] ^= 0x80;
        let new_seal = seal_bytes(&key(), &encoded[..encoded.len() - SEAL_LEN]);
        let seal_offset = encoded.len() - SEAL_LEN;
        encoded[seal_offset..].copy_from_slice(&new_seal);
        assert!(matches!(
            IncarnationHandoff::open(&encoded, &key()),
            Err(HandoffError::SnapshotDigestMismatch)
        ));
    }

    #[test]
    fn handoff_refuses_bad_nested_snapshot() {
        let mut payload = Vec::new();
        encode_string(&mut payload, "fingerprint").unwrap();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(encode_op(FaultCrashOp::Write));
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&2u64.to_le_bytes());
        payload.extend_from_slice(&3u64.to_le_bytes());
        encode_bytes(&mut payload, b"not-a-snapshot").unwrap();

        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(&snapshot_digest(b"not-a-snapshot"));
        let seal = seal_bytes(&key(), &encoded);
        encoded.extend_from_slice(&seal);

        assert!(matches!(
            IncarnationHandoff::open(&encoded, &key()),
            Err(HandoffError::Snapshot(_))
        ));
    }
}
