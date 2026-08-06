//! Coverage-guided generation scheduling — the coverage-depth arc's Wave E.
//!
//! Waves A-D measure; this wave *steers*. Under `campaign --guided` a generation's
//! 32-byte derivation input is no longer the bare
//! `SHA-256("patina-campaign-<seed_base>-<gen>")`: with some probability it is a
//! mutation of the derivation input of a generation that previously found
//! something new. Because seed AND every knob are read out of that one hash
//! (`derive_flags`), steering the hash steers the whole configuration without
//! touching a single knob derivation.
//!
//! # The determinism argument
//!
//! The arc's carried-forward constraint is that guided selection stays a pure
//! function of (seed, persisted coverage state), so an extended guided campaign
//! is still reproducible. Two properties deliver that:
//!
//! * **Purity.** Every input is either the campaign seed base, the generation
//!   index, the plateau window, or the persisted novelty log. No wall clock, no
//!   host state, no in-guest computation.
//! * **Prefix-determinism (tear safety).** Generation `g` is derived from novelty
//!   entries with generation **strictly below `g`** only. The campaign-steering
//!   crash model allows an aux store to sit one generation ahead of the cursor,
//!   so a resumed campaign re-deriving generation `g` sees a log that may already
//!   contain `g`'s own entry; truncating below `g` makes the re-derivation
//!   bit-identical to the original. This is why the selection function reads the
//!   *log* rather than `union.bits` directly — a cumulative bitset cannot be
//!   rewound to a generation boundary, and the covered-edge count the selector
//!   actually wants is recoverable from the log by summation anyway.
//!
//! Ancestors may themselves have been guided, so an ancestor's effective hash is
//! defined by the same rule applied to *its* prefix. [`GuidancePlan::new`]
//! resolves that with one forward pass over the sparse log rather than recursion.

use sha2::{Digest, Sha256};

/// One generation that moved a coverage/depth dimension, with how much it moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoveltyEntry {
    pub(crate) generation: u64,
    /// Fitness weight, always >= 1 so every novel generation stays selectable.
    pub(crate) weight: u64,
}

/// Why a generation got the derivation input it did — reported so the mode can
/// be shown to have actually done something (an inert knob is a bug).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuidanceDecision {
    /// Nothing novel had happened yet, so there was nothing to steer toward.
    /// Identical to the unguided derivation, deliberately and visibly.
    NoAncestors,
    /// The exploration roll won: derive fresh, exactly as an unguided campaign.
    Explore,
    /// Mutate the derivation input of a previously productive generation.
    Exploit { ancestor: u64 },
}

impl GuidanceDecision {
    pub(crate) fn is_exploit(self) -> bool {
        matches!(self, Self::Exploit { .. })
    }
}

/// Exploitation share at zero drought, in permille.
const EXPLOIT_BASE_PERMILLE: u64 = 700;
/// Floor the exploitation share decays to once a campaign has gone a full
/// plateau window without novelty. It never reaches zero: a productive ancestor
/// stays worth revisiting, and a hard floor keeps the mode from silently
/// degenerating into the unguided scheme.
const EXPLOIT_FLOOR_PERMILLE: u64 = 200;
/// A mask byte below this takes the corresponding derivation byte from the fresh
/// hash instead of the ancestor's; 64/256 mutates ~25% of the bytes, so a child
/// keeps most of its ancestor's knob configuration.
const MUTATION_THRESHOLD: u8 = 64;
/// Drought denominator when the plateau window is disabled (`--plateau-after 0`),
/// so the decay schedule stays defined rather than dividing by zero.
const DEFAULT_DROUGHT_WINDOW: u64 = 200;

/// How much of the next generation should exploit rather than explore.
///
/// Exploitation decays with the novelty drought: while ancestors keep paying out
/// the campaign concentrates on them, and the longer nothing new is found the
/// more it broadens, so a guided campaign cannot wedge itself in a corner of the
/// space that has stopped producing.
pub(crate) fn exploit_permille(drought: u64, plateau_window: u64) -> u64 {
    let window = if plateau_window == 0 {
        DEFAULT_DROUGHT_WINDOW
    } else {
        plateau_window
    };
    let span = EXPLOIT_BASE_PERMILLE - EXPLOIT_FLOOR_PERMILLE;
    let decay = drought.saturating_mul(span) / window;
    EXPLOIT_BASE_PERMILLE
        .saturating_sub(decay)
        .max(EXPLOIT_FLOOR_PERMILLE)
}

/// The unguided derivation input: the pure per-generation hash every campaign has
/// always used. Guided mode starts from this and may replace it.
pub(crate) fn base_generation_hash(seed_base: u64, generation: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("patina-campaign-{seed_base}-{generation}").as_bytes());
    hasher.finalize().into()
}

/// Inherit most of `ancestor`'s derivation bytes, taking the rest from `fresh`.
///
/// Byte-level mutation is what makes exploitation meaningful: `derive_flags`
/// reads each knob out of a fixed byte offset, so preserving ~75% of the bytes
/// preserves ~75% of the ancestor's knob settings while the rest move. Deriving a
/// brand-new hash from the ancestor's index instead would be indistinguishable
/// from exploration — the mode would be inert.
fn mutate(ancestor: &[u8; 32], fresh: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"patina-campaign-guided-mask-v1");
    hasher.update(fresh);
    let mask: [u8; 32] = hasher.finalize().into();
    let mut out = *ancestor;
    let mut took_any = false;
    for index in 0..32 {
        if mask[index] < MUTATION_THRESHOLD {
            out[index] = fresh[index];
            took_any = true;
        }
    }
    if !took_any {
        // Always inherit at least one byte from the fresh hash so two children of
        // one ancestor cannot collapse onto an identical configuration.
        let index = usize::from(fresh[0] % 32);
        out[index] = fresh[index];
    }
    out
}

/// The resolved guidance state for one campaign invocation.
#[derive(Clone, Debug)]
pub(crate) struct GuidancePlan {
    seed_base: u64,
    plateau_window: u64,
    ancestors: Vec<NoveltyEntry>,
    /// `hashes[i]` is the effective derivation input of `ancestors[i]`, resolved
    /// against that ancestor's own prefix.
    hashes: Vec<[u8; 32]>,
}

impl GuidancePlan {
    /// Resolve a plan from a persisted novelty log. Entries must be strictly
    /// increasing by generation (both stores validate that on load); any weight
    /// below 1 is lifted to 1 so a novel generation is never unselectable.
    pub(crate) fn new(seed_base: u64, plateau_window: u64, log: &[NoveltyEntry]) -> Self {
        let ancestors: Vec<NoveltyEntry> = log
            .iter()
            .map(|entry| NoveltyEntry {
                generation: entry.generation,
                weight: entry.weight.max(1),
            })
            .collect();
        // Forward pass: ancestor i is derived from ancestors strictly below it,
        // which — the log being strictly increasing — is exactly the prefix `..i`.
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(ancestors.len());
        for index in 0..ancestors.len() {
            let (hash, _) = derive(
                seed_base,
                plateau_window,
                ancestors[index].generation,
                &ancestors[..index],
                &hashes[..index],
            );
            hashes.push(hash);
        }
        Self {
            seed_base,
            plateau_window,
            ancestors,
            hashes,
        }
    }

    /// The derivation input for `generation`, plus why it was chosen.
    pub(crate) fn generation_hash(&self, generation: u64) -> ([u8; 32], GuidanceDecision) {
        // Truncate below the generation being derived: this is the tear-safety
        // property described in the module docs.
        let cut = self
            .ancestors
            .partition_point(|entry| entry.generation < generation);
        derive(
            self.seed_base,
            self.plateau_window,
            generation,
            &self.ancestors[..cut],
            &self.hashes[..cut],
        )
    }
}

fn derive(
    seed_base: u64,
    plateau_window: u64,
    generation: u64,
    ancestors: &[NoveltyEntry],
    ancestor_hashes: &[[u8; 32]],
) -> ([u8; 32], GuidanceDecision) {
    debug_assert_eq!(ancestors.len(), ancestor_hashes.len());
    let base = base_generation_hash(seed_base, generation);
    let Some(last) = ancestors.last() else {
        return (base, GuidanceDecision::NoAncestors);
    };
    let drought = generation.saturating_sub(1).saturating_sub(last.generation);
    let roll = u64::from(u16::from_le_bytes([base[8], base[9]]) % 1000);
    if roll >= exploit_permille(drought, plateau_window) {
        return (base, GuidanceDecision::Explore);
    }
    // Fitness-proportionate choice over the novelty weights: a generation that
    // opened many edges at once is a better thing to mutate than one that opened
    // a single edge, and every novel generation stays reachable.
    let total: u64 = ancestors
        .iter()
        .fold(0u64, |sum, entry| sum.saturating_add(entry.weight));
    let mut ticket = u64::from_le_bytes([
        base[10], base[11], base[12], base[13], base[14], base[15], base[16], base[17],
    ]) % total;
    let mut chosen = ancestors.len() - 1;
    for (index, entry) in ancestors.iter().enumerate() {
        if ticket < entry.weight {
            chosen = index;
            break;
        }
        ticket -= entry.weight;
    }
    (
        mutate(&ancestor_hashes[chosen], &base),
        GuidanceDecision::Exploit {
            ancestor: ancestors[chosen].generation,
        },
    )
}

/// Running tally of what the mode actually did, so a guided campaign can be shown
/// to have steered rather than silently behaved like an unguided one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GuidanceTally {
    pub(crate) generations: u64,
    pub(crate) exploited: u64,
    pub(crate) explored: u64,
    pub(crate) no_ancestors: u64,
}

impl GuidanceTally {
    pub(crate) fn record(&mut self, decision: GuidanceDecision) {
        self.generations += 1;
        match decision {
            GuidanceDecision::Exploit { .. } => self.exploited += 1,
            GuidanceDecision::Explore => self.explored += 1,
            GuidanceDecision::NoAncestors => self.no_ancestors += 1,
        }
    }

    /// True when the mode ran but never steered anything — every generation was
    /// derived exactly as an unguided campaign would have derived it. Reported
    /// loudly: a guided campaign that guided nothing is an inert knob, and a
    /// clean result from one does not mean guidance was tested.
    pub(crate) fn is_vacuous(&self) -> bool {
        self.generations > 0 && self.exploited == 0
    }
}

/// The guided detectors reported by `cargo patina campaign --selftest`, in the
/// `(name, passed, detail)` shape the coverage and depth stores use.
pub(crate) fn campaign_detector_selftest() -> Vec<(&'static str, bool, String)> {
    vec![
        detector_no_ancestors_matches_unguided(),
        detector_guidance_changes_the_stream(),
        detector_exploit_inherits_its_ancestor(),
        detector_prefix_determinism(),
        detector_drought_broadens_exploration(),
    ]
}

fn log(entries: &[(u64, u64)]) -> Vec<NoveltyEntry> {
    entries
        .iter()
        .map(|(generation, weight)| NoveltyEntry {
            generation: *generation,
            weight: *weight,
        })
        .collect()
}

fn detector_no_ancestors_matches_unguided() -> (&'static str, bool, String) {
    const NAME: &str = "guided-no-ancestors-matches-unguided";
    let plan = GuidancePlan::new(0, 200, &[]);
    let mut ok = true;
    for generation in 0..8 {
        let (hash, decision) = plan.generation_hash(generation);
        ok &= hash == base_generation_hash(0, generation);
        ok &= decision == GuidanceDecision::NoAncestors;
    }
    (
        NAME,
        ok,
        "with nothing novel yet, guided derivation is the unguided one".to_string(),
    )
}

fn detector_guidance_changes_the_stream() -> (&'static str, bool, String) {
    const NAME: &str = "guided-changes-the-generation-stream";
    // A campaign with real novelty must derive a materially different stream from
    // the unguided one, or the mode is inert. RED: replacing `mutate` with the
    // fresh hash drives `changed` to zero.
    let plan = GuidancePlan::new(0, 200, &log(&[(0, 3), (4, 1), (9, 7)]));
    let mut changed = 0;
    let mut exploited = 0;
    for generation in 0..64 {
        let (hash, decision) = plan.generation_hash(generation);
        if hash != base_generation_hash(0, generation) {
            changed += 1;
        }
        if decision.is_exploit() {
            exploited += 1;
        }
    }
    let ok = exploited > 0 && changed == exploited;
    (
        NAME,
        ok,
        format!("{exploited}/64 generations exploited, {changed} derivations differ from unguided"),
    )
}

fn detector_exploit_inherits_its_ancestor() -> (&'static str, bool, String) {
    const NAME: &str = "guided-exploit-inherits-ancestor-bytes";
    // Exploitation must stay NEAR its ancestor: a child that shares no more with
    // its ancestor than with a random hash is exploration wearing a label.
    let plan = GuidancePlan::new(7, 200, &log(&[(0, 5), (3, 2)]));
    let mut shared_counts = Vec::new();
    let mut ok = true;
    for generation in 0..96 {
        let (hash, decision) = plan.generation_hash(generation);
        let GuidanceDecision::Exploit { ancestor } = decision else {
            continue;
        };
        let (ancestor_hash, _) = plan.generation_hash(ancestor);
        let shared = (0..32).filter(|i| hash[*i] == ancestor_hash[*i]).count();
        // Two separate claims. The per-generation floor is the one that
        // discriminates: a freshly derived hash shares 32/256 bytes with the
        // ancestor in expectation, so 8/32 is unreachable without inheritance.
        ok &= shared >= 8;
        ok &= hash != base_generation_hash(7, generation);
        shared_counts.push(shared);
    }
    shared_counts.sort_unstable();
    // The median pins the INTENDED rate (~75% inherited at a 25% mutation mask),
    // so weakening the mask is caught even though the per-generation floor is
    // deliberately loose enough to absorb the mask's binomial tail.
    let median = shared_counts
        .get(shared_counts.len() / 2)
        .copied()
        .unwrap_or(0);
    let ok = ok && !shared_counts.is_empty() && median >= 20;
    (
        NAME,
        ok,
        format!(
            "{} exploited generations, ancestor bytes kept: min {} median {median}",
            shared_counts.len(),
            shared_counts.first().copied().unwrap_or(0),
        ),
    )
}

fn detector_prefix_determinism() -> (&'static str, bool, String) {
    const NAME: &str = "guided-prefix-determinism-tear-safe";
    // The checkpoint-tear invariant: a resumed campaign re-deriving generation N
    // sees a log that already contains N's own entry, and must derive exactly what
    // the original run derived. RED: dropping the `< generation` truncation in
    // `generation_hash` makes these disagree.
    let untorn = GuidancePlan::new(0, 200, &log(&[(0, 3), (4, 1)]));
    let torn = GuidancePlan::new(0, 200, &log(&[(0, 3), (4, 1), (9, 2)]));
    let mut ok = true;
    for generation in 0..=9 {
        ok &= untorn.generation_hash(generation) == torn.generation_hash(generation);
    }
    // Past the torn generation the extra entry legitimately steers again.
    let diverges_after = (10..40).any(|g| untorn.generation_hash(g) != torn.generation_hash(g));
    (
        NAME,
        ok && diverges_after,
        "generations <= the torn one re-derive identically; later ones use it".to_string(),
    )
}

fn detector_drought_broadens_exploration() -> (&'static str, bool, String) {
    const NAME: &str = "guided-drought-broadens-exploration";
    let fresh = exploit_permille(0, 200);
    let middle = exploit_permille(100, 200);
    let stale = exploit_permille(200, 200);
    let beyond = exploit_permille(10_000, 200);
    let disabled = exploit_permille(0, 0);
    let ok = fresh == EXPLOIT_BASE_PERMILLE
        && middle < fresh
        && stale <= EXPLOIT_FLOOR_PERMILLE + 1
        && beyond == EXPLOIT_FLOOR_PERMILLE
        && disabled == EXPLOIT_BASE_PERMILLE;
    (
        NAME,
        ok,
        format!("exploit permille {fresh} -> {middle} -> {stale} -> floor {beyond}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_detectors_all_fire() {
        for (name, ok, detail) in campaign_detector_selftest() {
            assert!(ok, "{name} failed: {detail}");
        }
    }

    #[test]
    fn a_plan_is_a_pure_function_of_its_inputs() {
        let entries = log(&[(0, 2), (5, 4), (11, 1)]);
        let first = GuidancePlan::new(42, 50, &entries);
        let second = GuidancePlan::new(42, 50, &entries);
        for generation in 0..64 {
            assert_eq!(
                first.generation_hash(generation),
                second.generation_hash(generation),
                "generation {generation} must derive identically"
            );
        }
    }

    #[test]
    fn a_different_novelty_log_steers_differently() {
        let one = GuidancePlan::new(42, 50, &log(&[(0, 2)]));
        let other = GuidancePlan::new(42, 50, &log(&[(0, 2), (3, 9)]));
        assert!(
            (4..64).any(|g| one.generation_hash(g) != other.generation_hash(g)),
            "the novelty log must actually influence the stream"
        );
    }

    #[test]
    fn ancestors_are_chosen_proportionally_to_their_novelty() {
        // A heavily weighted ancestor must win most selections; an equal-weight
        // pair must split. This pins that the ticket walk reads weights at all.
        let plan = GuidancePlan::new(3, 200, &log(&[(0, 1), (1, 99)]));
        let mut heavy = 0;
        let mut light = 0;
        for generation in 2..400 {
            if let (_, GuidanceDecision::Exploit { ancestor }) = plan.generation_hash(generation) {
                if ancestor == 1 {
                    heavy += 1;
                } else {
                    light += 1;
                }
            }
        }
        assert!(heavy > 0 && light > 0, "both ancestors must be reachable");
        assert!(
            heavy > light * 5,
            "the 99:1 weight must dominate: heavy={heavy} light={light}"
        );
    }

    #[test]
    fn weights_below_one_are_lifted_so_every_novel_generation_stays_selectable() {
        let plan = GuidancePlan::new(1, 200, &log(&[(0, 0)]));
        let reached = (1..64).any(|g| {
            matches!(
                plan.generation_hash(g),
                (_, GuidanceDecision::Exploit { ancestor: 0 })
            )
        });
        assert!(reached, "a zero-weight entry must still be selectable");
    }

    #[test]
    fn tally_reports_vacuity_only_when_nothing_was_steered() {
        let mut tally = GuidanceTally::default();
        assert!(!tally.is_vacuous(), "an empty tally is not vacuous");
        tally.record(GuidanceDecision::NoAncestors);
        tally.record(GuidanceDecision::Explore);
        assert!(tally.is_vacuous(), "no exploit means the mode did nothing");
        tally.record(GuidanceDecision::Exploit { ancestor: 0 });
        assert!(!tally.is_vacuous());
        assert_eq!(tally.generations, 3);
        assert_eq!(tally.exploited, 1);
        assert_eq!(tally.explored, 1);
        assert_eq!(tally.no_ancestors, 1);
    }
}
