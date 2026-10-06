//! Regression tests for coverage.

use super::*;

pub(super) fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn covmap_bytes(counters: &[u32], deltas: &[i64]) -> Vec<u8> {
    assert_eq!(counters.len(), deltas.len());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(COVERAGE_MAP_MAGIC);
    push_u32(&mut bytes, COVERAGE_MAP_VERSION);
    push_u64(&mut bytes, counters.len() as u64);
    push_u64(&mut bytes, 1);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, counters.len() as u64);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, deltas.len() as u64);
    for counter in counters {
        push_u32(&mut bytes, *counter);
    }
    for delta in deltas {
        push_i64(&mut bytes, *delta);
    }
    bytes
}
