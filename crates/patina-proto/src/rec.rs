//! Boundary record and hashing.

use crate::draw::mix64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecKind {
    Trap = 1,
    SupDecision = 2,
    SignalDelivery = 3,
    InsnEmulation = 4,
    Fault = 5,
    CrashPoint = 6,
    /// An injected fault: `nr` the syscall, args [`INJ_*` kind, class, value, ...].
    Injected = 7,
    /// A counter preemption: `nr` 1, args [rip, N, rcx, rsp,
    /// eflags, 0], `out_hash` a hash of the general registers.
    Preempt = 8,
}

impl RecKind {
    pub fn from_u8(v: u8) -> Option<RecKind> {
        use RecKind::*;
        [
            Trap,
            SupDecision,
            SignalDelivery,
            InsnEmulation,
            Fault,
            CrashPoint,
            Injected,
            Preempt,
        ]
        .into_iter()
        .find(|k| *k as u8 == v)
    }
    pub fn name(self) -> &'static str {
        match self {
            RecKind::Trap => "trap",
            RecKind::SupDecision => "sup",
            RecKind::SignalDelivery => "signal",
            RecKind::InsnEmulation => "insn",
            RecKind::Fault => "fault",
            RecKind::CrashPoint => "crash",
            RecKind::Injected => "inject",
            RecKind::Preempt => "preempt",
        }
    }
}

/// One boundary event. Records are appended in completion order: `seq` is taken
/// when the event starts, so a trap that consulted the supervisor follows the
/// supervisor's decision record(s) in the file.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rec {
    pub seq: u64,
    pub vclock_ns: u64,
    /// Thread slot index.
    pub slot: u16,
    /// `RecKind`.
    pub kind: u8,
    /// Class code (`Class::code`) actually applied, or 0 for non-trap records.
    pub class: u8,
    /// Syscall number, op code or instruction code.
    pub nr: u32,
    pub args: [u64; 6],
    pub ret: i64,
    /// Hash of every byte written to guest memory by this call (0 if none).
    pub out_hash: u64,
    /// Hash of the bytes read from guest memory for write-like calls and paths (0 if none).
    pub in_hash: u64,
}

pub const REC_SIZE: usize = core::mem::size_of::<Rec>();
const _: () = assert!(REC_SIZE == 96);

impl Rec {
    pub fn as_bytes(&self) -> &[u8; REC_SIZE] {
        // SAFETY: repr(C), no padding (asserted size), all fields plain integers.
        unsafe { &*(self as *const Rec as *const [u8; REC_SIZE]) }
    }
    pub fn from_bytes(b: &[u8]) -> Rec {
        assert!(b.len() >= REC_SIZE);
        // SAFETY: any bit pattern is a valid Rec.
        unsafe { core::ptr::read_unaligned(b.as_ptr() as *const Rec) }
    }
}

/// 64-bit hash of a byte string (word-at-a-time multiply-xorshift; not cryptographic).
pub fn hash_bytes(seed: u64, data: &[u8]) -> u64 {
    let mut h = mix64(
        seed ^ 0x243f_6a88_85a3_08d3 ^ (data.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        h = mix64(h ^ w)
            .rotate_left(23)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut b = [0u8; 8];
        b[..rest.len()].copy_from_slice(rest);
        h = mix64(h ^ u64::from_le_bytes(b) ^ 0xff);
    }
    mix64(h)
}

/// Incremental form of `hash_bytes` over several pieces (used for iovecs).
pub struct Hasher {
    h: u64,
    n: u64,
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher {
            h: 0x452821e638d01377,
            n: 0,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.h = mix64(self.h ^ hash_bytes(self.n, data));
        self.n += data.len() as u64;
    }
    pub fn finish(&self) -> u64 {
        mix64(self.h ^ self.n)
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Running log hash after appending `rec`.
pub fn chain(prev: u64, rec: &Rec) -> u64 {
    mix64(prev.rotate_left(17) ^ hash_bytes(0, rec.as_bytes()))
}
