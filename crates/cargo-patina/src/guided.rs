//! Coverage-guided generation scheduling — the coverage-depth arc's Wave E.
//!
//! Under `campaign --guided` a generation's derivation material (its seed and
//! every knob byte, see `campaign/hash.rs`) is no longer always the bare
//! per-generation hash: with some probability it is a LOCAL mutation of the
//! material of a generation that previously found something new. The child
//! keeps its ancestor's seed and every knob except one to three mutated units,
//! where a unit is the seed or one knob the spec actually reads. Because seed
//! AND every knob are read out of that one material (`derive_flags`), steering
//! it steers the whole configuration without touching a knob derivation.
//!
//! The choices guidance makes (explore or exploit, which ancestor, which units,
//! how) come from their own keyed stream ([`Draws`]), never from the material:
//! reading them from knob bytes would correlate the decision with the knob
//! values it is choosing between.
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

use crate::campaign::gen_byte::{Hash, Unit, UnitOp};
use sha2::{Digest, Sha256};

/// One generation that opened new edge coverage, with how much it opened.
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

/// Exploitation share at zero drought, in permille.
const EXPLOIT_BASE_PERMILLE: u64 = 700;
/// Floor the exploitation share decays to once a campaign has gone a full
/// plateau window without novelty. It never reaches zero: a productive ancestor
/// stays worth revisiting, and a hard floor keeps the mode from silently
/// degenerating into the unguided scheme.
const EXPLOIT_FLOOR_PERMILLE: u64 = 200;
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
pub(crate) fn base_generation_hash(seed_base: u64, generation: u64) -> Hash {
    Hash::derive(seed_base, generation)
}

/// Guidance's own random stream for one generation: splitmix64 seeded from a
/// hash keyed apart from the generation material, so no selection ever reads a
/// knob byte.
pub(crate) struct Draws(u64);

impl Draws {
    pub(crate) fn new(seed_base: u64, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"patina-campaign-guidance/v1");
        hasher.update(seed_base.to_le_bytes());
        hasher.update(generation.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self(u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A draw in `0..bound`; `bound` must be nonzero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Most units a child mutates. One to three, AFL-havoc style: enough to step
/// off a plateau, few enough that the child stays near its ancestor.
const MAX_MUTATED_UNITS: u64 = 3;
/// Largest nudge step, in band-byte units.
const MAX_NUDGE: u64 = 16;

/// The child of `ancestor`: its material with one to three distinct units
/// changed. A changed unit is replaced with `fresh`'s value, or, for a knob,
/// half the time nudged a small step so threshold-shaped behaviour can be
/// approached gradually. Everything else, the seed included unless the seed is
/// one of the picks, is inherited.
fn mutate(ancestor: &Hash, fresh: &Hash, units: &[Unit], draws: &mut Draws) -> Hash {
    let mut pool: Vec<&Unit> = units.iter().collect();
    let picks = (1 + draws.below(MAX_MUTATED_UNITS)).min(pool.len() as u64);
    let mut child = *ancestor;
    for _ in 0..picks {
        let unit = pool.swap_remove(draws.below(pool.len() as u64) as usize);
        let op = if unit.is_seed() || draws.below(2) == 0 {
            UnitOp::Replace
        } else {
            let step = 1 + draws.below(MAX_NUDGE) as i8;
            UnitOp::Nudge(if draws.below(2) == 0 { step } else { -step })
        };
        child = child.with_unit(unit, op, fresh);
    }
    child
}

/// The resolved guidance state for one campaign invocation.
#[derive(Clone, Debug)]
pub(crate) struct GuidancePlan {
    seed_base: u64,
    plateau_window: u64,
    /// The units a child may mutate: the seed and every live knob claim.
    units: Vec<Unit>,
    ancestors: Vec<NoveltyEntry>,
    /// `hashes[i]` is the effective derivation input of `ancestors[i]`, resolved
    /// against that ancestor's own prefix.
    hashes: Vec<Hash>,
}

impl GuidancePlan {
    /// Resolve a plan from a persisted novelty log. Entries must be strictly
    /// increasing by generation (both stores validate that on load); any weight
    /// below 1 is lifted to 1 so a novel generation is never unselectable.
    ///
    /// The FIRST entry is dropped. A campaign's first generation is novel by
    /// construction — it opens the program's whole baseline (`main`, startup,
    /// every path the workload always takes), not a discovery — and weighting by
    /// raw novelty count therefore made it permanently dominate the pool.
    /// Measured before this exclusion: over a 60-generation guided run the log
    /// was `[[0, 88], [4, 13], [24, 1], [41, 40]]` and the bootstrap generation
    /// was chosen as the ancestor 34 times out of 42 exploits, so ~81% of the
    /// exploitation budget resampled around one arbitrary configuration —
    /// strictly worse than sampling independently. The pool holds only
    /// generations that found something the baseline did not.
    ///
    /// Dropping the first entry is prefix-stable, so the tear-safety argument in
    /// the module docs is unaffected: truncation only ever removes from the END of
    /// the log, so "the earliest entry" is the same entry at every generation.
    /// A campaign whose only novelty is that bootstrap generation therefore has an
    /// EMPTY pool and derives exactly like an unguided one — reported honestly as
    /// vacuous rather than dressed up as steering.
    pub(crate) fn new(
        seed_base: u64,
        plateau_window: u64,
        units: Vec<Unit>,
        log: &[NoveltyEntry],
    ) -> Self {
        let ancestors: Vec<NoveltyEntry> = log
            .iter()
            .skip(1)
            .map(|entry| NoveltyEntry {
                generation: entry.generation,
                weight: entry.weight.max(1),
            })
            .collect();
        // Forward pass: ancestor i is derived from ancestors strictly below it,
        // which — the log being strictly increasing — is exactly the prefix `..i`.
        let mut hashes: Vec<Hash> = Vec::with_capacity(ancestors.len());
        for index in 0..ancestors.len() {
            let (hash, _) = derive(
                seed_base,
                plateau_window,
                &units,
                ancestors[index].generation,
                &ancestors[..index],
                &hashes[..index],
            );
            hashes.push(hash);
        }
        Self {
            seed_base,
            plateau_window,
            units,
            ancestors,
            hashes,
        }
    }

    /// The derivation input for `generation`, plus why it was chosen.
    pub(crate) fn generation_hash(&self, generation: u64) -> (Hash, GuidanceDecision) {
        // Truncate below the generation being derived: this is the tear-safety
        // property described in the module docs.
        let cut = self
            .ancestors
            .partition_point(|entry| entry.generation < generation);
        derive(
            self.seed_base,
            self.plateau_window,
            &self.units,
            generation,
            &self.ancestors[..cut],
            &self.hashes[..cut],
        )
    }
}

fn derive(
    seed_base: u64,
    plateau_window: u64,
    units: &[Unit],
    generation: u64,
    ancestors: &[NoveltyEntry],
    ancestor_hashes: &[Hash],
) -> (Hash, GuidanceDecision) {
    debug_assert_eq!(ancestors.len(), ancestor_hashes.len());
    let base = base_generation_hash(seed_base, generation);
    let Some(last) = ancestors.last() else {
        return (base, GuidanceDecision::NoAncestors);
    };
    let drought = generation.saturating_sub(1).saturating_sub(last.generation);
    let mut draws = Draws::new(seed_base, generation);
    if draws.below(1000) >= exploit_permille(drought, plateau_window) {
        return (base, GuidanceDecision::Explore);
    }
    // Fitness-proportionate choice over the novelty weights: a generation that
    // opened many edges at once is a better thing to mutate than one that opened
    // a single edge, and every novel generation stays reachable.
    let total: u64 = ancestors
        .iter()
        .fold(0u64, |sum, entry| sum.saturating_add(entry.weight));
    let mut ticket = draws.below(total);
    let mut chosen = ancestors.len() - 1;
    for (index, entry) in ancestors.iter().enumerate() {
        if ticket < entry.weight {
            chosen = index;
            break;
        }
        ticket -= entry.weight;
    }
    (
        mutate(&ancestor_hashes[chosen], &base, units, &mut draws),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{CampaignSpec, FaultPlanes, mutation_units};

    fn log(entries: &[(u64, u64)]) -> Vec<NoveltyEntry> {
        entries
            .iter()
            .map(|(generation, weight)| NoveltyEntry {
                generation: *generation,
                weight: *weight,
            })
            .collect()
    }

    /// Units for a spec that reads many knobs: every fault plane, buggify, PCT
    /// and the yield stride.
    fn units() -> Vec<Unit> {
        mutation_units(&CampaignSpec {
            buggify: true,
            pct: true,
            yield_stride: true,
            faults: FaultPlanes::ALL,
            ..CampaignSpec::default()
        })
    }

    fn plan(seed_base: u64, entries: &[(u64, u64)]) -> GuidancePlan {
        GuidancePlan::new(seed_base, 200, units(), &log(entries))
    }

    #[test]
    fn with_no_ancestors_guided_derivation_is_the_unguided_one() {
        let plan = plan(0, &[]);
        for generation in 0..8 {
            assert_eq!(
                plan.generation_hash(generation),
                (
                    base_generation_hash(0, generation),
                    GuidanceDecision::NoAncestors
                )
            );
        }
    }

    /// The core of local mutation: an exploit child is its ancestor with one to
    /// three units changed, so it keeps the ancestor's seed (unless the seed is
    /// one of the changed units) and every other knob byte, the extension's
    /// crash and starvation draws included.
    #[test]
    fn an_exploit_child_is_its_ancestor_with_one_to_three_units_changed() {
        let units = units();
        let plan = plan(7, &[(0, 5), (3, 2), (6, 4)]);
        let (mut exploits, mut kept_seed) = (0, 0);
        for generation in 7..300 {
            let (child, decision) = plan.generation_hash(generation);
            let GuidanceDecision::Exploit { ancestor } = decision else {
                continue;
            };
            exploits += 1;
            let (parent, _) = plan.generation_hash(ancestor);
            let changed = child.differing_units(parent, &units);
            assert!(
                (1..=3).contains(&changed.len()),
                "generation {generation} changed {} units",
                changed.len()
            );
            assert!(child.agrees_outside(parent, &changed));
            if !changed.iter().any(|unit| unit.is_seed()) {
                assert_eq!(child.seed(), parent.seed());
                kept_seed += 1;
            }
        }
        assert!(exploits > 50, "too few exploits to judge: {exploits}");
        assert!(
            kept_seed * 2 > exploits,
            "most children must keep the seed: {kept_seed}/{exploits}"
        );
    }

    /// Mutation never touches a byte outside the offered units, so a spec that
    /// reads few knobs gets children that differ only in those knobs or the seed.
    #[test]
    fn mutation_offers_only_the_seed_and_knobs_the_spec_reads() {
        let narrow = mutation_units(&CampaignSpec {
            pct: true,
            ..CampaignSpec::default()
        });
        assert_eq!(narrow.len(), 2, "the seed and the PCT depth: {narrow:?}");
        assert!(narrow.iter().filter(|unit| unit.is_seed()).count() == 1);
        let plan = GuidancePlan::new(1, 200, narrow.clone(), &log(&[(0, 1), (2, 1)]));
        for generation in 3..100 {
            if let (child, GuidanceDecision::Exploit { ancestor }) =
                plan.generation_hash(generation)
            {
                let (parent, _) = plan.generation_hash(ancestor);
                assert!(child.agrees_outside(parent, &narrow.iter().collect::<Vec<_>>()));
            }
        }
    }

    #[test]
    fn prefix_determinism_survives_a_checkpoint_tear() {
        // A resumed campaign re-deriving generation N may see a log that already
        // holds N's own entry; it must derive what the original run derived.
        let untorn = plan(0, &[(0, 3), (4, 1)]);
        let torn = plan(0, &[(0, 3), (4, 1), (9, 2)]);
        for generation in 0..=9 {
            assert_eq!(
                untorn.generation_hash(generation),
                torn.generation_hash(generation)
            );
        }
        assert!((10..40).any(|g| untorn.generation_hash(g) != torn.generation_hash(g)));
    }

    #[test]
    fn the_bootstrap_generation_is_never_an_ancestor() {
        let plan = plan(0, &[(0, 88), (4, 13), (24, 1), (41, 40)]);
        let mut others = 0;
        for generation in 0..200 {
            if let (_, GuidanceDecision::Exploit { ancestor }) = plan.generation_hash(generation) {
                assert_ne!(ancestor, 0, "generation {generation} picked the bootstrap");
                others += 1;
            }
        }
        assert!(others > 0);
    }

    #[test]
    fn a_drought_broadens_exploration_to_a_floor() {
        let fresh = exploit_permille(0, 200);
        assert!(exploit_permille(100, 200) < fresh);
        assert_eq!(exploit_permille(10_000, 200), EXPLOIT_FLOOR_PERMILLE);
        assert_eq!(exploit_permille(0, 0), fresh);
    }

    /// A plan is a pure function of its inputs, and the novelty log is one of
    /// them: a different log steers a different stream.
    #[test]
    fn a_plan_is_a_pure_function_of_its_inputs() {
        let entries = log(&[(0, 2), (5, 4), (11, 1)]);
        let first = GuidancePlan::new(42, 50, units(), &entries);
        let second = GuidancePlan::new(42, 50, units(), &entries);
        for generation in 0..64 {
            assert_eq!(
                first.generation_hash(generation),
                second.generation_hash(generation),
                "generation {generation} must derive identically"
            );
        }
        let one = GuidancePlan::new(42, 50, units(), &log(&[(0, 2)]));
        let other = GuidancePlan::new(42, 50, units(), &log(&[(0, 2), (3, 9)]));
        assert!(
            (4..64).any(|g| one.generation_hash(g) != other.generation_hash(g)),
            "the novelty log must actually influence the stream"
        );
    }

    #[test]
    fn ancestors_are_chosen_proportionally_to_their_novelty() {
        // A heavily weighted ancestor must win most selections; an equal-weight
        // pair must split. This pins that the ticket walk reads weights at all.
        // The leading entry is the bootstrap generation and is excluded from the
        // pool, so the two competing ancestors come after it.
        let plan = GuidancePlan::new(3, 200, units(), &log(&[(0, 50), (1, 1), (2, 99)]));
        let mut heavy = 0;
        let mut light = 0;
        for generation in 3..400 {
            if let (_, GuidanceDecision::Exploit { ancestor }) = plan.generation_hash(generation) {
                if ancestor == 2 {
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
        // A weight below one is lifted, so every novel generation stays
        // selectable. Entry 0 is the excluded bootstrap; entry 1 weighs zero.
        let plan = GuidancePlan::new(1, 200, units(), &log(&[(0, 7), (1, 0)]));
        let reached = (2..64).any(|g| {
            matches!(
                plan.generation_hash(g),
                (_, GuidanceDecision::Exploit { ancestor: 1 })
            )
        });
        assert!(reached, "a zero-weight entry must still be selectable");
    }

    #[test]
    fn a_bootstrap_only_log_leaves_nothing_to_steer_and_reports_vacuous() {
        // The bootstrap generation is excluded from the pool, so a campaign whose
        // ONLY novelty was that first generation has no ancestors at all. It must
        // then derive exactly like an unguided campaign AND report itself vacuous —
        // never present resampling around the baseline as if it were steering.
        let plan = GuidancePlan::new(4, 200, units(), &log(&[(0, 88)]));
        let mut tally = GuidanceTally::default();
        for generation in 0..40 {
            let (hash, decision) = plan.generation_hash(generation);
            assert_eq!(
                hash,
                base_generation_hash(4, generation),
                "generation {generation} must derive exactly as unguided"
            );
            assert_eq!(decision, GuidanceDecision::NoAncestors);
            tally.record(decision);
        }
        assert!(
            tally.is_vacuous(),
            "a campaign that never steered must report vacuous: {tally:?}"
        );
        assert_eq!(tally.exploited, 0);
        assert_eq!(tally.no_ancestors, 40);
        // A tally is vacuous only when something was decided and nothing was exploited.
        {
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
}
