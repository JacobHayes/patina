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
    /// A preemption outside a system call. `nr` 1: a counter preemption, args [rip, N, rcx,
    /// rsp, eflags, 0], `out_hash` a hash of the general registers; `nr` 2: a spin point, the
    /// same with the period for N; `nr` 3: a compute point (`compute::PREEMPT_NR`).
    Preempt = 8,
    /// The object of the `Injected` record just before it: `nr` the name's full length,
    /// `ret` the process id, and the name's bytes (its last `NAME_BYTES` when longer) in
    /// `args`, `out_hash` and `in_hash`.
    Name = 9,
}

/// Name bytes one `Name` record carries.
pub const NAME_BYTES: usize = 64;

impl Rec {
    /// A `Name` record for `name` (its last `NAME_BYTES` bytes when longer).
    pub fn name(seq: u64, vclock_ns: u64, slot: u16, pid: i64, name: &[u8]) -> Rec {
        let tail = &name[name.len().saturating_sub(NAME_BYTES)..];
        let mut b = [0u8; NAME_BYTES];
        b[..tail.len()].copy_from_slice(tail);
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Rec {
            seq,
            vclock_ns,
            slot,
            kind: RecKind::Name as u8,
            class: 0,
            nr: name.len() as u32,
            args: [w(0), w(1), w(2), w(3), w(4), w(5)],
            ret: pid,
            out_hash: w(6),
            in_hash: w(7),
        }
    }

    /// The bytes of a `Name` record and whether the name was cut (only its tail kept).
    pub fn name_bytes(&self) -> ([u8; NAME_BYTES], usize, bool) {
        let mut b = [0u8; NAME_BYTES];
        let words = [
            self.args[0],
            self.args[1],
            self.args[2],
            self.args[3],
            self.args[4],
            self.args[5],
            self.out_hash,
            self.in_hash,
        ];
        for (i, w) in words.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let n = self.nr as usize;
        (b, n.min(NAME_BYTES), n > NAME_BYTES)
    }
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
            Name,
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
            RecKind::Name => "name",
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
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        h = mix64(h ^ u64::from_le_bytes(*c))
            .rotate_left(23)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
    }
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
