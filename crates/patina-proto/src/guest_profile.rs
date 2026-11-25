//! Binary format for the deterministic CPU profile sidecar (`cpu_profile.bin`) and helpers
//! shared by `patina-rt` (writer) and `patina-cli` (reader/symbolizer & coverage hasher).
//!
//! Layout of `cpu_profile.bin`:
//! ```text
//! header   16 bytes: magic "PATPROF\0" (8), version u32 (1), elf_machine u32
//! records  stream of:
//!            kind u8, reserved u8, payload_len u16, payload [u8; payload_len]
//!
//! KIND_IMAGE (1): executable ELF mapping for offline symbolization
//!   pid: u32, _pad: u32, start: u64, end: u64, bias: u64, file_off: u64,
//!   path_len: u16, path: [u8; path_len]
//!
//! KIND_SAMPLE (2): deterministic compute-point CPU stack sample (leaf frame first)
//!   vclock_ns: u64, seq: u64, weight: u64, pid: u32, tid: u32, slot: u16, depth: u16,
//!   pcs: [u64; depth]
//! ```

pub const MAGIC: [u8; 8] = *b"PATPROF\0";
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 16;

pub const KIND_IMAGE: u8 = 1;
pub const KIND_SAMPLE: u8 = 2;

/// Maximum stack frames captured per deterministic CPU sample.
pub const MAX_FRAMES: usize = 32;

/// Default sampling interval in compute events when `--profile-cpu` is given without `=N`.
pub const DEFAULT_CPU_INTERVAL: u64 = 1000;

/// Maximum path bytes recorded in a `KIND_IMAGE` record.
pub const MAX_IMAGE_PATH: usize = 384;

/// Maximum encoded size of a single record (header + payload).
pub const MAX_RECORD_BYTES: usize = 4 + 40 + MAX_IMAGE_PATH;

/// Encode the 16-byte file header for ELF machine `arch` (`EM_X86_64 = 62`, `EM_AARCH64 = 183`).
pub fn encode_header(arch: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..8].copy_from_slice(&MAGIC);
    out[8..12].copy_from_slice(&VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&arch.to_le_bytes());
    out
}

/// Encode a `KIND_IMAGE` record into `buf`, returning bytes written.
#[allow(clippy::too_many_arguments)]
pub fn encode_image(
    buf: &mut [u8],
    pid: u32,
    start: u64,
    end: u64,
    bias: u64,
    file_off: u64,
    path: &[u8],
) -> usize {
    let plen = path.len().min(MAX_IMAGE_PATH);
    let payload_len = 42 + plen;
    if buf.len() < 4 + payload_len {
        return 0;
    }
    buf[0] = KIND_IMAGE;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(payload_len as u16).to_le_bytes());
    let p = &mut buf[4..];
    p[0..4].copy_from_slice(&pid.to_le_bytes());
    p[4..8].copy_from_slice(&0u32.to_le_bytes());
    p[8..16].copy_from_slice(&start.to_le_bytes());
    p[16..24].copy_from_slice(&end.to_le_bytes());
    p[24..32].copy_from_slice(&bias.to_le_bytes());
    p[32..40].copy_from_slice(&file_off.to_le_bytes());
    p[40..42].copy_from_slice(&(plen as u16).to_le_bytes());
    p[42..42 + plen].copy_from_slice(&path[..plen]);
    4 + payload_len
}

/// Encode a `KIND_SAMPLE` record into `buf`, returning bytes written.
#[allow(clippy::too_many_arguments)]
pub fn encode_sample(
    buf: &mut [u8],
    vclock_ns: u64,
    seq: u64,
    weight: u64,
    pid: u32,
    tid: u32,
    slot: u16,
    pcs: &[u64],
) -> usize {
    let depth = pcs.len().min(MAX_FRAMES);
    let payload_len = 36 + 8 * depth;
    if buf.len() < 4 + payload_len {
        return 0;
    }
    buf[0] = KIND_SAMPLE;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(payload_len as u16).to_le_bytes());
    let p = &mut buf[4..];
    p[0..8].copy_from_slice(&vclock_ns.to_le_bytes());
    p[8..16].copy_from_slice(&seq.to_le_bytes());
    p[16..24].copy_from_slice(&weight.to_le_bytes());
    p[24..28].copy_from_slice(&pid.to_le_bytes());
    p[28..32].copy_from_slice(&tid.to_le_bytes());
    p[32..34].copy_from_slice(&slot.to_le_bytes());
    p[34..36].copy_from_slice(&(depth as u16).to_le_bytes());
    let mut i = 0;
    while i < depth {
        let off = 36 + 8 * i;
        p[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        i += 1;
    }
    4 + payload_len
}

/// AFL-style log2 hit-count bucket for a non-zero coverage byte (`1..=255` -> `1..=8`).
#[inline]
pub const fn hit_bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4..=7 => 4,
        8..=15 => 5,
        16..=31 => 6,
        32..=127 => 7,
        128..=255 => 8,
    }
}

/// Deterministic FNV-1a 64-bit edge hash for a coverage `(edge_idx, hit_bucket)` pair.
#[inline]
pub const fn edge_hash(edge_idx: u16, bucket: u8) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let b0 = (edge_idx & 0xff) as u8;
    let b1 = (edge_idx >> 8) as u8;
    h ^= b0 as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= b1 as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= bucket as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_lengths() {
        let mut buf = [0u8; MAX_RECORD_BYTES];
        let n = encode_image(&mut buf, 42, 0x1000, 0x2000, 0x1000, 0, b"/guest/app");
        assert_eq!(n, 4 + 42 + 10);
        assert_eq!(buf[0], KIND_IMAGE);
        let pcs = [0x1234, 0x5678, 0x9abc];
        let m = encode_sample(&mut buf, 999, 12, 1000, 42, 43, 0, &pcs);
        assert_eq!(m, 4 + 36 + 24);
        assert_eq!(buf[0], KIND_SAMPLE);
    }

    #[test]
    fn hit_buckets_and_hashes_distinguish_counts() {
        assert_eq!(hit_bucket(0), 0);
        assert_eq!(hit_bucket(1), 1);
        assert_eq!(hit_bucket(2), 2);
        assert_eq!(hit_bucket(5), 4);
        assert_eq!(hit_bucket(255), 8);
        assert_ne!(edge_hash(10, 1), edge_hash(10, 2));
        assert_ne!(edge_hash(10, 1), edge_hash(11, 1));
    }
}
