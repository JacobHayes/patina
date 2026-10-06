//! Opaque campaign derivation material and its declared byte claims.
//!
//! Bytes 0..8 carry the child seed; every band reads through a named claim.
//! Unclaimed original indices are 10, 17, 18, and 19; extension indices 33
//! through 63 are free. Claim a free byte for a new independent knob rather than
//! correlating unrelated knobs by reusing an existing claim.
//!
//! The original 32 bytes remain unchanged. The extension is keyed on the
//! effective hash, including guided mutation, so new extension claims preserve
//! every existing generation's seed and knob draws.
use super::GEN_BAND_BYTES;
use sha2::{Digest, Sha256};
use std::ops::Range;

pub(super) const SEED: Range<usize> = 0..8;

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(usize)]
pub(super) enum Claim {
    BUGGIFY_ACTIVATION = 8,
    BUGGIFY_FIRE = 9,
    SCHED_PCT_DEPTH = 11,
    NET_DROP = 12,
    SLEEP_JITTER_HI = 13,
    FS_ERROR = 14,
    FS_SHORT = 15,
    FS_LATENCY_HI = 16,
    NET_LATENCY = 20,
    DNS_FAIL = 21,
    DNS_LATENCY_HI = 22,
    NET_JITTER_HI = 23,
    NET_DUPLICATE = 24,
    NET_CONNECT_REFUSE = 25,
    NET_RESET = 26,
    NET_TCP_BUFFER = 27,
    ENTROPY_FAIL = 28,
    EPOCH_JUMP = 29,
    CUSTOM_OP_FAIL = 30,
    /// The whole starvation policy configuration — interval count, start window,
    /// and maximum interval length — bit-sliced out of ONE byte.
    ///
    /// The three sub-knobs are deliberately correlated with each other and with
    /// nothing else. They are not three independent faults; they are one policy's
    /// shape ("how many holds, how deep, how long"), and the campaign's
    /// disjointness rule exists to stop two UNRELATED knobs from sweeping a
    /// diagonal of their joint space. Slicing one byte gives 256 distinct
    /// starvation configurations — every generation of a thousand-generation
    /// sweep sees several — while leaving every other band's draw untouched.
    SCHED_STARVE = 31,
    /// Whether this generation starves at all. The first claim in the extension
    /// block (see [`super::generation_bands`]), and it had to be: the three
    /// starvation sub-knobs consume all eight bits of [`SCHED_STARVE`], and a
    /// gate sliced out of that same byte would decide "does this generation
    /// starve" from the very bits that decide "how", so a dampened campaign
    /// would starve only at one corner of the policy space instead of rarely
    /// across all of it.
    ///
    /// Only ever consulted below full `--starve-scale-permille`: at full scale
    /// the gate is unconditionally open, which is what keeps the default sweep
    /// unchanged.
    STARVE_FIRE = 32,
}
pub(super) use Claim::*;

pub(super) struct Bands([u8; GEN_BAND_BYTES]);
impl Bands {
    pub(super) fn new(hash: &Hash) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"patina-campaign-bands/v1");
        hasher.update(hash.0);
        let extension: [u8; 32] = hasher.finalize().into();
        let mut bands = [0; GEN_BAND_BYTES];
        bands[..32].copy_from_slice(&hash.0);
        bands[32..].copy_from_slice(&extension);
        Self(bands)
    }
    pub(super) fn read(&self, claim: Claim) -> u8 {
        self.0[claim as usize]
    }
}

#[cfg(test)]
pub(super) const EXPLORATION_CLAIMS: &[(&str, usize)] = &[
    ("buggify activation", BUGGIFY_ACTIVATION as usize),
    ("buggify fire", BUGGIFY_FIRE as usize),
    ("sched-pct depth", SCHED_PCT_DEPTH as usize),
    ("starvation policy", SCHED_STARVE as usize),
    ("starvation fire", STARVE_FIRE as usize),
];

/// The derivation input stays opaque before band expansion as well. Guidance
/// can transform it but never borrow or index its underlying array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hash([u8; 32]);

impl Hash {
    pub(crate) fn derive(seed_base: u64, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(format!("patina-campaign-{seed_base}-{generation}").as_bytes());
        Self(hasher.finalize().into())
    }

    pub(crate) fn seed(self) -> u64 {
        u64::from_le_bytes(self.0[SEED].try_into().expect("seed claim width"))
    }

    // Guidance selection is deliberately keyed on the same input as the
    // historical algorithm. These ranges are selector inputs, not fault bands.
    pub(crate) fn guidance_roll(self) -> u64 {
        const ROLL: Range<usize> = 8..10;
        u64::from(u16::from_le_bytes(self.0[ROLL].try_into().expect("roll width")) % 1000)
    }

    pub(crate) fn guidance_ticket(self, total: u64) -> u64 {
        const TICKET: Range<usize> = 10..18;
        u64::from_le_bytes(self.0[TICKET].try_into().expect("ticket width")) % total
    }

    /// Preserve the existing mask algorithm, including its forced fresh byte.
    pub(crate) fn mutate(self, fresh: &Self) -> Self {
        // 64/256 selects fresh bytes: a child keeps roughly three quarters of
        // its ancestor's configuration while the remaining bands move.
        const MUTATION_THRESHOLD: u8 = 64;
        let mut hasher = Sha256::new();
        hasher.update(b"patina-campaign-guided-mask-v1");
        hasher.update(fresh.0);
        let mask: [u8; 32] = hasher.finalize().into();
        let mut out = self.0;
        let mut took_any = false;
        for index in 0..32 {
            if mask[index] < MUTATION_THRESHOLD {
                out[index] = fresh.0[index];
                took_any = true;
            }
        }
        if !took_any {
            let index = usize::from(fresh.0[0] % 32);
            out[index] = fresh.0[index];
        }
        Self(out)
    }

    pub(crate) fn shared_bytes(self, other: Self) -> usize {
        self.0
            .iter()
            .zip(other.0)
            .filter(|(a, b)| **a == *b)
            .count()
    }
}
