//! Opaque campaign derivation material and its declared byte claims.
//!
//! Bytes 0..8 carry the child seed; every band reads through a named claim.
//! Unclaimed original indices are 10, 17, and 19; extension indices 35
//! through 63 are free. Claim a free byte for a new independent knob rather than
//! correlating unrelated knobs by reusing an existing claim.
//!
//! A generation's material is all 64 bytes: the original 32-byte hash and a
//! 32-byte extension derived from it once, when the unguided generation is
//! derived. Guided mutation then edits the 64 bytes claim by claim, so a child
//! inherits every knob it does not mutate, the extension's crash draws
//! included.
use super::GEN_BAND_BYTES;
use sha2::{Digest, Sha256};
use std::ops::Range;

pub(super) const SEED: Range<usize> = 0..8;

// The enum and complete inventory cannot grow independently. Ownership lives
// in campaign_policy and EXPLORATION_CLAIMS and is const-validated against ALL.
macro_rules! claims {
    ($( $(#[$doc:meta])* $name:ident = $index:literal, )+) => {
        #[derive(Clone, Copy)]
        #[allow(non_camel_case_types)]
        #[repr(usize)]
        pub(super) enum Claim { $( $(#[$doc])* $name = $index, )+ }
        impl Claim {
            pub(super) const ALL: &'static [Self] = &[$(Self::$name,)+];
        }
    };
}

claims! {
    BUGGIFY_ACTIVATION = 8,
    BUGGIFY_FIRE = 9,
    SCHED_PCT_DEPTH = 11,
    NET_DROP = 12,
    SLEEP_JITTER_HI = 13,
    FS_ERROR = 14,
    FS_SHORT = 15,
    FS_LATENCY_HI = 16,
    /// The edge-hook yield stride, as a power of two. An original byte, so a
    /// guided child inherits it with the rest of its ancestor's configuration.
    YIELD_STRIDE = 18,
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
    /// The per-crash-point machine-crash rate, as a power of two.
    MACHINE_CRASH = 33,
    /// The per-crash-point process-crash rate, as a power of two.
    PROCESS_CRASH = 34,
}
pub(super) use Claim::*;

pub(super) struct Bands([u8; GEN_BAND_BYTES]);
impl Bands {
    pub(super) fn new(hash: &Hash) -> Self {
        Self(hash.0)
    }
    pub(super) fn read(&self, claim: Claim) -> u8 {
        self.0[claim as usize]
    }
}

pub(super) const EXPLORATION_CLAIMS: &[Claim] = &[
    BUGGIFY_ACTIVATION,
    BUGGIFY_FIRE,
    SCHED_PCT_DEPTH,
    YIELD_STRIDE,
];

/// The derivation input stays opaque before band expansion as well. Guidance
/// can transform it but never borrow or index its underlying array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hash([u8; GEN_BAND_BYTES]);

impl Hash {
    pub(crate) fn derive(seed_base: u64, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(format!("patina-campaign-{seed_base}-{generation}").as_bytes());
        let head: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(b"patina-campaign-bands/v1");
        hasher.update(head);
        let extension: [u8; 32] = hasher.finalize().into();
        let mut bytes = [0; GEN_BAND_BYTES];
        bytes[..32].copy_from_slice(&head);
        bytes[32..].copy_from_slice(&extension);
        Self(bytes)
    }

    pub(crate) fn seed(self) -> u64 {
        u64::from_le_bytes(self.0[SEED].try_into().expect("seed claim width"))
    }

    /// `self` with one unit changed. `Replace` takes the unit's bytes from
    /// `fresh`; `Nudge` steps a one-byte knob by a small signed amount,
    /// saturating, so a child can move a threshold-shaped knob a little rather
    /// than only re-roll it. A seed nudge would be a different random stream,
    /// not a nearby one, so the seed is only ever replaced.
    ///
    /// The unit always changes: a nudge pinned at a byte's limit steps the
    /// other way, and a knob replaced by its own value steps by one.
    pub(crate) fn with_unit(self, unit: &Unit, op: UnitOp, fresh: &Self) -> Self {
        let mut out = self.0;
        let range = unit.0.clone();
        match op {
            UnitOp::Nudge(step) if range.len() == 1 => {
                let old = out[range.start];
                let stepped = old.saturating_add_signed(step);
                out[range.start] = if stepped == old {
                    old.saturating_add_signed(step.saturating_neg())
                } else {
                    stepped
                };
            }
            UnitOp::Replace | UnitOp::Nudge(_) => {
                out[range.clone()].copy_from_slice(&fresh.0[range.clone()]);
            }
        }
        if out[range.clone()] == self.0[range.clone()] {
            out[range.start] = out[range.start].wrapping_add(1);
        }
        Self(out)
    }

    /// The units on which two hashes differ.
    #[cfg(test)]
    pub(crate) fn differing_units(self, other: Self, units: &[Unit]) -> Vec<&Unit> {
        units
            .iter()
            .filter(|unit| self.0[unit.0.clone()] != other.0[unit.0.clone()])
            .collect()
    }

    /// Whether the two hashes agree on every byte outside `units`.
    #[cfg(test)]
    pub(crate) fn agrees_outside(self, other: Self, units: &[&Unit]) -> bool {
        (0..GEN_BAND_BYTES).all(|index| {
            units.iter().any(|unit| unit.0.contains(&index)) || self.0[index] == other.0[index]
        })
    }
}

/// One independently mutable part of a generation's material: the seed, or
/// one claimed knob byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unit(Range<usize>);

/// How a guided child changes one [`Unit`] of its ancestor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnitOp {
    Replace,
    Nudge(i8),
}

impl Unit {
    pub(crate) fn is_seed(&self) -> bool {
        self.0 == SEED
    }

    /// The seed plus every claim that `flags` actually reads.
    ///
    /// A claim is live when changing its byte changes the derived flags for
    /// some probe generation. Mutating a dead claim (a plane the spec did not
    /// select) would re-run the parent's
    /// configuration unchanged, so those claims are never offered.
    pub(super) fn live(flags: impl Fn(&Hash) -> Vec<String>) -> Vec<Self> {
        let mut units = vec![Self(SEED)];
        for &claim in Claim::ALL {
            let index = claim as usize;
            // Derived probes, plus uniform-byte ones: a knob that only matters
            // when another byte opens a threshold gate must be probed with the
            // gate open, and all-zero and all-0xff material opens every
            // threshold gate from one side or the other.
            let probes = (0..8)
                .map(|generation| Hash::derive(0, generation))
                .chain([0x00, 0x80, 0xff].map(|byte| Hash([byte; GEN_BAND_BYTES])));
            let live = probes.into_iter().any(|probe| {
                let base = flags(&probe);
                (0..=u8::MAX).step_by(17).any(|value| {
                    let mut bytes = probe.0;
                    bytes[index] = value;
                    flags(&Hash(bytes)) != base
                })
            });
            if live {
                units.push(Self(index..index + 1));
            }
        }
        units
    }
}
