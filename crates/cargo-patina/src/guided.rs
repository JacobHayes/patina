//! Coverage-guided generation scheduling (`campaign --guided`).
//!
//! A guided generation's derivation material (its seed and every knob byte, see
//! `campaign/hash.rs`) is either the bare per-generation material (explore) or
//! a LOCAL mutation of the material of a corpus entry (exploit). The child keeps
//! its ancestor's seed and every knob except one to three mutated units, where a
//! unit is the seed or one knob the spec actually reads. Because seed AND every
//! knob are read out of that one material (`derive_flags`), steering it steers
//! the whole configuration without touching a knob derivation.
//!
//! # Corpus and energy
//!
//! The corpus is every generation that reached a coverage feature (an edge at
//! a hit-count bucket, see `coverage::hit_bucket`) first, except the bootstrap:
//! the first novel generation opens the program's whole baseline, not a
//! discovery. An entry's energy favours rare finds that have not been mined yet:
//! it is inversely proportional to how many generations have reached the
//! entry's rarest feature plus how many children it has already had. A fresh
//! entry whose feature nothing else reaches gets the most; an entry whose finds
//! became common, or which has been picked many times, fades.
//!
//! The exploit share adapts: it is the novelty rate of recent exploit children
//! relative to that of recent explore generations, clamped so neither arm ever
//! starves.
//!
//! The choices guidance makes (explore or exploit, which ancestor, which units,
//! how) come from their own keyed streams ([`Draws`]), never from the material:
//! reading them from knob bytes would correlate the decision with the knob
//! values it is choosing between.
//!
//! # Determinism
//!
//! A decision is a pure function of the seed base, the generation, and the
//! persisted store: the feature log (with per-feature hit counts) and the
//! decision log. Both are written with the coverage store, which may sit one
//! generation ahead of the campaign cursor after a checkpoint tear. A resumed
//! campaign therefore reuses a generation's RECORDED decision when the store
//! already holds one, and only decides afresh for a generation the store has
//! not seen, when the store holds exactly the generations below it. An
//! ancestor's material is re-derived from the decision log: the child of `a`
//! at `g` is `a`'s material mutated by `g`'s own mutation stream.

use crate::campaign::gen_byte::{Hash, Unit, UnitOp};
use crate::coverage::FeatureRecord;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Why a generation got the derivation input it did — reported so the mode can
/// be shown to have actually done something (an inert knob is a bug).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuidanceDecision {
    /// The corpus was empty, so there was nothing to steer toward. Identical
    /// to the unguided derivation, deliberately and visibly.
    NoAncestors,
    /// The exploration roll won: derive fresh, exactly as an unguided campaign.
    Explore,
    /// Mutate the derivation input of a corpus entry.
    Exploit { ancestor: u64 },
}

/// Exploit share bounds, in permille. Neither arm ever drops below a fifth of
/// the generations: exploration keeps finding what no mutation of the corpus
/// reaches, and exploitation keeps a productive corpus worth having.
const EXPLOIT_MIN_PERMILLE: u64 = 200;
const EXPLOIT_MAX_PERMILLE: u64 = 800;
/// How many recent steered generations the adaptive exploit share looks at.
const SHARE_WINDOW: usize = 100;
/// Energy numerator; an entry's energy is this over (rarity + picks).
const ENERGY_SCALE: u64 = 1 << 20;

/// The unguided derivation input: the pure per-generation hash every campaign has
/// always used. Guided mode starts from this and may replace it.
pub(crate) fn base_generation_hash(seed_base: u64, generation: u64) -> Hash {
    Hash::derive(seed_base, generation)
}

/// One keyed random stream of guidance: splitmix64 seeded from a hash keyed
/// apart from the generation material, so no selection ever reads a knob byte.
pub(crate) struct Draws(u64);

impl Draws {
    fn new(purpose: &[u8], seed_base: u64, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"patina-campaign-guidance/v2/");
        hasher.update(purpose);
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
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Most units a child mutates. One to three, AFL-havoc style: enough to step
/// off a plateau, few enough that the child stays near its ancestor.
const MAX_MUTATED_UNITS: u64 = 3;
/// Largest nudge step, in band-byte units.
const MAX_NUDGE: u64 = 16;

/// The child of `ancestor` at `generation`: its material with one to three
/// distinct units changed. A changed unit is replaced with the unguided
/// material's value, or, for a knob, half the time nudged a small step so
/// threshold-shaped behaviour can be approached gradually. Everything else,
/// the seed included unless the seed is one of the picks, is inherited.
///
/// Keyed on the generation alone (not on the selection draws before it), so
/// the decision log is enough to re-derive any ancestor's material.
fn mutate(ancestor: &Hash, seed_base: u64, generation: u64, units: &[Unit]) -> Hash {
    let fresh = base_generation_hash(seed_base, generation);
    let mut draws = Draws::new(b"mutate", seed_base, generation);
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
        child = child.with_unit(unit, op, &fresh);
    }
    child
}

/// A corpus entry as of the generation being decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    generation: u64,
    /// How many generations reached the entry's rarest feature (>= 1: the
    /// entry itself did).
    rarity: u64,
    /// How many generations so far exploited this entry.
    picks: u64,
}

impl Entry {
    fn energy(self) -> u64 {
        (ENERGY_SCALE / (self.rarity.max(1) + self.picks)).max(1)
    }
}

/// The guidance state for one campaign invocation: the persisted feature and
/// decision logs plus the spec's mutation units.
pub(crate) struct GuidancePlan<'a> {
    seed_base: u64,
    units: &'a [Unit],
    features: &'a [FeatureRecord],
    decisions: &'a [GuidanceDecision],
}

impl<'a> GuidancePlan<'a> {
    pub(crate) fn new(
        seed_base: u64,
        units: &'a [Unit],
        features: &'a [FeatureRecord],
        decisions: &'a [GuidanceDecision],
    ) -> Self {
        Self {
            seed_base,
            units,
            features,
            decisions,
        }
    }

    /// The derivation input for `generation`, plus why it was chosen: the
    /// recorded decision when the store already holds one (a resumed tear),
    /// else a fresh decision from the generations below it.
    pub(crate) fn generation_hash(&self, generation: u64) -> (Hash, GuidanceDecision) {
        let decision = match self.decisions.get(generation as usize) {
            Some(recorded) => *recorded,
            None => self.decide(generation),
        };
        (self.material(generation, decision), decision)
    }

    /// The material a generation ran with `decision`.
    fn material(&self, generation: u64, decision: GuidanceDecision) -> Hash {
        // Resolve the ancestor chain iteratively; every link is a strictly
        // smaller generation, so it terminates at an explored root.
        let mut chain = vec![generation];
        let mut link = decision;
        while let GuidanceDecision::Exploit { ancestor } = link {
            chain.push(ancestor);
            link = self.recorded(ancestor);
        }
        let root = chain.pop().expect("chain holds the generation");
        let mut material = base_generation_hash(self.seed_base, root);
        while let Some(child) = chain.pop() {
            material = mutate(&material, self.seed_base, child, self.units);
        }
        material
    }

    fn recorded(&self, generation: u64) -> GuidanceDecision {
        self.decisions
            .get(generation as usize)
            .copied()
            .unwrap_or(GuidanceDecision::NoAncestors)
    }

    /// The corpus as of `generation`: every novel generation below it except
    /// the bootstrap, with its rarity and pick count.
    fn corpus(&self, generation: u64) -> Vec<Entry> {
        let mut rarest: BTreeMap<u64, u64> = BTreeMap::new();
        for record in self.features {
            if record.generation >= generation {
                break;
            }
            let rarity = rarest.entry(record.generation).or_insert(u64::MAX);
            *rarity = (*rarity).min(record.hits);
        }
        // The bootstrap generation opens the baseline, not a discovery.
        let bootstrap = rarest.keys().next().copied();
        let mut picks: BTreeMap<u64, u64> = BTreeMap::new();
        for decision in &self.decisions[..self.decisions.len().min(generation as usize)] {
            if let GuidanceDecision::Exploit { ancestor } = decision {
                *picks.entry(*ancestor).or_default() += 1;
            }
        }
        rarest
            .into_iter()
            .filter(|(entry, _)| Some(*entry) != bootstrap)
            .map(|(entry, rarity)| Entry {
                generation: entry,
                rarity,
                picks: picks.get(&entry).copied().unwrap_or(0),
            })
            .collect()
    }

    /// The exploit share for `generation`, in permille: the recent novelty
    /// rate of exploit children over that of explore generations (each with a
    /// Laplace prior, so an untried arm reads as even), clamped.
    fn exploit_permille(&self, generation: u64) -> u64 {
        let novel = |g: u64| {
            let at = self
                .features
                .partition_point(|record| record.generation < g);
            self.features
                .get(at)
                .is_some_and(|record| record.generation == g)
        };
        let decided = &self.decisions[..self.decisions.len().min(generation as usize)];
        let (mut exploit, mut explore) = ([1u64, 2], [1u64, 2]);
        let recent = decided
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, decision)| **decision != GuidanceDecision::NoAncestors)
            .take(SHARE_WINDOW);
        for (g, decision) in recent {
            let arm = match decision {
                GuidanceDecision::Exploit { .. } => &mut exploit,
                _ => &mut explore,
            };
            arm[0] += u64::from(novel(g as u64));
            arm[1] += 1;
        }
        // rate = hits / trials, compared without division by cross-multiplying.
        let exploit_rate = exploit[0] * explore[1];
        let explore_rate = explore[0] * exploit[1];
        (1000 * exploit_rate / (exploit_rate + explore_rate))
            .clamp(EXPLOIT_MIN_PERMILLE, EXPLOIT_MAX_PERMILLE)
    }

    fn decide(&self, generation: u64) -> GuidanceDecision {
        let corpus = self.corpus(generation);
        if corpus.is_empty() {
            return GuidanceDecision::NoAncestors;
        }
        let mut draws = Draws::new(b"select", self.seed_base, generation);
        if draws.below(1000) >= self.exploit_permille(generation) {
            return GuidanceDecision::Explore;
        }
        let total: u64 = corpus.iter().map(|entry| entry.energy()).sum();
        let mut ticket = draws.below(total);
        for entry in &corpus {
            if ticket < entry.energy() {
                return GuidanceDecision::Exploit {
                    ancestor: entry.generation,
                };
            }
            ticket -= entry.energy();
        }
        unreachable!("the ticket is below the total energy")
    }
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

    /// Features as (generation first reached, generations that reached it).
    fn features(entries: &[(u64, u64)]) -> Vec<FeatureRecord> {
        entries
            .iter()
            .enumerate()
            .map(|(index, &(generation, hits))| FeatureRecord {
                generation,
                feature: index as u64,
                hits,
            })
            .collect()
    }

    /// Run a campaign's guidance forward from `features`, recording every
    /// decision as the driver does, and return the decision log.
    fn simulate(
        seed_base: u64,
        units: &[Unit],
        features: &[FeatureRecord],
        generations: u64,
    ) -> Vec<GuidanceDecision> {
        let mut decisions = Vec::new();
        for generation in 0..generations {
            let visible: Vec<FeatureRecord> = features
                .iter()
                .copied()
                .filter(|record| record.generation < generation)
                .collect();
            let plan = GuidancePlan::new(seed_base, units, &visible, &decisions);
            let (_, decision) = plan.generation_hash(generation);
            decisions.push(decision);
        }
        decisions
    }

    #[test]
    fn with_an_empty_corpus_guided_derivation_is_the_unguided_one() {
        let units = units();
        // Only the bootstrap generation is novel, so the corpus stays empty.
        let features = features(&[(0, 40), (0, 40)]);
        let mut decisions = Vec::new();
        for generation in 0..8 {
            let plan = GuidancePlan::new(0, &units, &features, &decisions);
            let (hash, decision) = plan.generation_hash(generation);
            assert_eq!(hash, base_generation_hash(0, generation));
            assert_eq!(decision, GuidanceDecision::NoAncestors);
            decisions.push(decision);
        }
    }

    /// The core of local mutation: an exploit child is its ancestor with one to
    /// three units changed, so it keeps the ancestor's seed (unless the seed is
    /// one of the changed units) and every other knob byte, the extension's
    /// crash draws included.
    #[test]
    fn an_exploit_child_is_its_ancestor_with_one_to_three_units_changed() {
        let units = units();
        let features = features(&[(0, 9), (3, 2), (6, 4)]);
        let decisions = simulate(7, &units, &features, 300);
        let plan = GuidancePlan::new(7, &units, &features, &decisions);
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
        let features = features(&[(0, 5), (2, 1)]);
        let decisions = simulate(1, &narrow, &features, 100);
        let plan = GuidancePlan::new(1, &narrow, &features, &decisions);
        let everything: Vec<&Unit> = narrow.iter().collect();
        for generation in 3..100 {
            if let (child, GuidanceDecision::Exploit { ancestor }) =
                plan.generation_hash(generation)
            {
                let (parent, _) = plan.generation_hash(ancestor);
                assert!(child.agrees_outside(parent, &everything));
            }
        }
    }

    /// A resumed campaign whose store is a generation ahead reuses the recorded
    /// decision, and one whose store is not derives the same decision afresh.
    #[test]
    fn a_recorded_decision_rederives_identically() {
        let units = units();
        let features = features(&[(0, 3), (4, 1), (9, 2)]);
        let decisions = simulate(5, &units, &features, 40);
        for generation in 0..40u64 {
            let visible: Vec<FeatureRecord> = features
                .iter()
                .copied()
                .filter(|record| record.generation < generation)
                .collect();
            let fresh = GuidancePlan::new(5, &units, &visible, &decisions[..generation as usize]);
            let torn = GuidancePlan::new(5, &units, &features, &decisions[..=generation as usize]);
            assert_eq!(
                fresh.generation_hash(generation),
                torn.generation_hash(generation),
                "generation {generation}"
            );
        }
        assert!(
            decisions
                .iter()
                .any(|decision| matches!(decision, GuidanceDecision::Exploit { .. })),
            "the fixture must steer for the check to mean anything"
        );
    }

    #[test]
    fn the_bootstrap_generation_is_never_an_ancestor() {
        let units = units();
        let features = features(&[(0, 88), (0, 88), (4, 13), (24, 1), (41, 40)]);
        let decisions = simulate(0, &units, &features, 200);
        assert!(decisions.contains(&GuidanceDecision::Exploit { ancestor: 4 }));
        assert!(!decisions.contains(&GuidanceDecision::Exploit { ancestor: 0 }));
    }

    /// Energy favours the entry whose find is rare: two entries found at the
    /// same time, one whose feature most generations since have reached and
    /// one whose feature nothing else has, split exploitation very unevenly.
    #[test]
    fn energy_favours_the_finder_of_a_rare_feature() {
        let units = units();
        // Bootstrap, then generations 1 and 2 each found one feature. Since
        // then generation 1's feature was reached 60 times, generation 2's
        // only by generation 2 itself.
        let features = features(&[(0, 64), (1, 60), (2, 1)]);
        let mut decisions = vec![GuidanceDecision::NoAncestors; 3];
        decisions.extend([GuidanceDecision::Explore; 61]);
        let (mut common, mut rare) = (0, 0);
        for generation in 64..400 {
            let plan = GuidancePlan::new(9, &units, &features, &decisions[..64]);
            match plan.decide(generation) {
                GuidanceDecision::Exploit { ancestor: 1 } => common += 1,
                GuidanceDecision::Exploit { ancestor: 2 } => rare += 1,
                _ => {}
            }
        }
        assert!(rare > 0, "the rare finder must be picked");
        assert!(
            rare > 10 * common.max(1),
            "rare finder picked {rare}x, common finder {common}x"
        );
    }

    /// Picks spend an entry's energy: once one entry has had many children, a
    /// fresh entry of equal rarity is preferred.
    #[test]
    fn picks_spend_energy() {
        let units = units();
        let features = features(&[(0, 9), (1, 1), (2, 1)]);
        let mut decisions = vec![GuidanceDecision::NoAncestors; 3];
        decisions.extend([GuidanceDecision::Exploit { ancestor: 1 }; 40]);
        let plan = GuidancePlan::new(3, &units, &features, &decisions);
        let corpus = plan.corpus(43);
        let energy = |generation| {
            corpus
                .iter()
                .find(|entry| entry.generation == generation)
                .unwrap()
                .energy()
        };
        assert!(energy(2) > 10 * energy(1));
    }

    /// The exploit share follows which arm has recently been finding novelty,
    /// within its bounds.
    #[test]
    fn the_exploit_share_follows_the_productive_arm() {
        let units = units();
        let explore_novel: Vec<(u64, u64)> = (0..60).map(|g| (g * 2 + 1, 1)).collect();
        let exploit_novel: Vec<(u64, u64)> = (0..60).map(|g| (g * 2 + 2, 1)).collect();
        // Odd generations explore, even ones exploit generation 1.
        let decisions: Vec<GuidanceDecision> = (0..121)
            .map(|g| match g {
                0 => GuidanceDecision::NoAncestors,
                g if g % 2 == 1 => GuidanceDecision::Explore,
                _ => GuidanceDecision::Exploit { ancestor: 1 },
            })
            .collect();
        let share = |novel: &[(u64, u64)]| {
            let mut entries = vec![(0, 9)];
            entries.extend_from_slice(novel);
            let features = features(&entries);
            GuidancePlan::new(0, &units, &features, &decisions).exploit_permille(121)
        };
        assert_eq!(share(&explore_novel), EXPLOIT_MIN_PERMILLE);
        assert_eq!(share(&exploit_novel), EXPLOIT_MAX_PERMILLE);
        let untried = GuidancePlan::new(0, &units, &[], &[]).exploit_permille(0);
        assert!((EXPLOIT_MIN_PERMILLE..=EXPLOIT_MAX_PERMILLE).contains(&untried));
    }

    #[test]
    fn a_bootstrap_only_campaign_reports_vacuous() {
        let mut tally = GuidanceTally::default();
        assert!(!tally.is_vacuous(), "an empty tally is not vacuous");
        tally.record(GuidanceDecision::NoAncestors);
        tally.record(GuidanceDecision::Explore);
        assert!(tally.is_vacuous(), "no exploit means the mode did nothing");
        tally.record(GuidanceDecision::Exploit { ancestor: 0 });
        assert!(!tally.is_vacuous());
    }
}
