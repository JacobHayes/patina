//! Candidate verdict caching, batching, and deterministic re-verification.

use crate::{FailureOracle, MinimizeError};
use patina_dst_trace::TraceBundle;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// One in this many cache hits is re-run against the real oracle, so a
/// nondeterministic oracle is surfaced rather than silently trusted.
const VERIFICATION_PERIOD: u64 = 16;

/// A verdict already observed for one candidate, plus how many times the cached
/// answer has been served, which paces the sampled re-verification.
#[derive(Clone, Copy, Debug)]
struct CachedVerdict {
    verdict: bool,
    hits: u64,
}

/// Remembers the oracle's verdict for each distinct candidate of one
/// minimization.
///
/// The first cache hit of a run is always re-verified and one in
/// [`VERIFICATION_PERIOD`] hits after that, so the soundness guard below can
/// never sit unused on a short run.
///
/// A reducer proposes the same candidate repeatedly - a sweep that re-tries a
/// position after an unrelated deletion, a confirmation pass that re-walks a
/// trace it has stopped changing, an up-front failure re-check shared by several
/// passes. Every such repeat is byte-for-byte the same input the oracle already
/// judged (measured at 15-19 % of all calls on real workq traces, 55-63 % inside
/// a confirmation round), so the verdict can be reused. Candidates are keyed by
/// the SHA-256 of [`TraceBundle::to_bytes`] - the exact canonical bytes a caller
/// hands its oracle - so two candidates share a verdict only when the oracle
/// cannot tell them apart.
///
/// # Soundness
///
/// Reuse is sound exactly as far as the oracle is a function of its candidate.
/// Rather than assume that, the memo re-runs a deterministic sample of its cache
/// hits and refuses the whole minimization with
/// [`MinimizeError::NondeterministicOracle`] if a re-run disagrees with the
/// cached verdict: a flaky oracle invalidates every result built on top of it,
/// so it is reported loudly instead of being averaged over. The sample is
/// derived from the candidate digest and the hit ordinal - never from a clock or
/// an RNG - so a repeated run re-verifies exactly the same hits and the search
/// stays reproducible.
#[derive(Debug)]
pub struct CandidateMemo {
    verdicts: HashMap<[u8; 32], CachedVerdict>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) verifications: u64,
    verification_period: u64,
}

impl Default for CandidateMemo {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateMemo {
    /// A fresh memo. Share one across the passes of a joint search (see the
    /// `*_with_memo` entry points) so a candidate two passes both propose is
    /// judged once.
    pub fn new() -> Self {
        Self::with_verification_period(VERIFICATION_PERIOD)
    }

    /// A memo that re-verifies one in `period` cache hits. `period` of 1
    /// verifies every hit, which the guard's own tests use to make the
    /// disagreement path fire deterministically.
    pub(super) fn with_verification_period(period: u64) -> Self {
        Self {
            verdicts: HashMap::new(),
            hits: 0,
            misses: 0,
            verifications: 0,
            verification_period: period.max(1),
        }
    }

    /// The verdict for `candidate`, from the cache when it has been judged
    /// before and from `oracle` otherwise.
    pub(super) fn decide<O: FailureOracle>(
        &mut self,
        candidate: &TraceBundle,
        oracle: &mut O,
    ) -> Result<bool, MinimizeError<O::Error>> {
        Ok(self.first_accepted(&[candidate], oracle)?.is_some())
    }

    /// Judge a window of candidates in scan order and return the position of the
    /// first one the oracle accepts, if any.
    ///
    /// Every candidate in the window is judged (or served from the cache), not
    /// just the ones up to the accept: the window is handed to the oracle in one
    /// [`FailureOracle::judge_batch`] call, so a concurrent oracle has already
    /// paid for the later verdicts and caching them is free. The *result* is
    /// still the first accept in scan order, which is what a serial scan would
    /// have returned, so widening the window changes throughput and never the
    /// answer.
    ///
    /// Two candidates in the SAME window that happen to be byte-identical are
    /// judged twice rather than deduplicated, because neither one's verdict
    /// exists yet when the window is planned. That costs a redundant oracle call
    /// on a trace with interchangeable decisions and changes nothing else: the
    /// verdicts agree for any oracle that is a function of its candidate, which
    /// is the assumption the whole cache rests on and which the sampled
    /// re-verification below polices.
    pub(super) fn first_accepted<O: FailureOracle>(
        &mut self,
        candidates: &[&TraceBundle],
        oracle: &mut O,
    ) -> Result<Option<usize>, MinimizeError<O::Error>> {
        // Plan every candidate against the cache BEFORE the oracle runs: a miss
        // must be judged, and a sampled hit must be re-judged so the soundness
        // guard fires on the same hits it would have sampled one at a time.
        let mut digests = Vec::with_capacity(candidates.len());
        let mut plans = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let digest: [u8; 32] =
                Sha256::digest(candidate.to_bytes().map_err(MinimizeError::Trace)?)
                    .as_slice()
                    .try_into()
                    .expect("SHA-256 produces 32 bytes");
            let plan = match self.verdicts.get(&digest).copied() {
                None => {
                    self.misses += 1;
                    CandidatePlan::Judge
                }
                Some(cached) => {
                    self.hits += 1;
                    let hits = cached.hits + 1;
                    self.verdicts.insert(
                        digest,
                        CachedVerdict {
                            verdict: cached.verdict,
                            hits,
                        },
                    );
                    // The first repeat of a run is always re-verified, so the
                    // guard runs at least once against any oracle that is asked
                    // the same question twice; after that the content-derived
                    // sample paces it.
                    if self.verifications > 0 && !self.verifies(&digest, hits) {
                        CandidatePlan::Cached(cached.verdict)
                    } else {
                        self.verifications += 1;
                        CandidatePlan::Verify(cached.verdict)
                    }
                }
            };
            digests.push(digest);
            plans.push(plan);
        }

        let pending: Vec<&TraceBundle> = plans
            .iter()
            .zip(candidates)
            .filter(|(plan, _)| !matches!(plan, CandidatePlan::Cached(_)))
            .map(|(_, candidate)| *candidate)
            .collect();
        let observed = if pending.is_empty() {
            Vec::new()
        } else {
            let verdicts = oracle
                .judge_batch(&pending)
                .map_err(MinimizeError::Oracle)?;
            if verdicts.len() != pending.len() {
                return Err(MinimizeError::OracleBatchArity {
                    asked: pending.len(),
                    answered: verdicts.len(),
                });
            }
            verdicts
        };

        let mut observed = observed.into_iter();
        let mut accepted = None;
        for (index, plan) in plans.into_iter().enumerate() {
            let verdict = match plan {
                CandidatePlan::Cached(verdict) => verdict,
                CandidatePlan::Judge => {
                    let verdict = observed
                        .next()
                        .expect("one verdict per candidate handed to the oracle");
                    self.verdicts
                        .insert(digests[index], CachedVerdict { verdict, hits: 0 });
                    verdict
                }
                CandidatePlan::Verify(cached) => {
                    let observed = observed
                        .next()
                        .expect("one verdict per candidate handed to the oracle");
                    if observed != cached {
                        return Err(MinimizeError::NondeterministicOracle {
                            digest: hex(&digests[index]),
                            cached,
                            observed,
                        });
                    }
                    observed
                }
            };
            if verdict && accepted.is_none() {
                accepted = Some(index);
            }
        }
        Ok(accepted)
    }

    /// Whether this hit is the sampled one. Both inputs are fixed by the search
    /// itself - the candidate's content and how often it has recurred - so the
    /// sample is identical on every repeat of the same minimization.
    fn verifies(&self, digest: &[u8; 32], hits: u64) -> bool {
        u64::from(digest[0]).wrapping_add(hits) % self.verification_period == 0
    }
}

/// What one candidate of a window needs before its verdict is known.
enum CandidatePlan {
    /// Never judged before: the oracle must see it.
    Judge,
    /// Judged before, and this repeat is not the sampled one.
    Cached(bool),
    /// Judged before, and this repeat is the sampled one: the oracle must see it
    /// again and agree.
    Verify(bool),
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Ask the oracle about one candidate through a caller-owned memo.
///
/// The reducers judge their input this way before shrinking it. It is public so
/// a caller can probe a candidate of its own — a pre-flight check, a guard
/// against an oracle that answers every candidate the same way — and have the
/// verdict cached for the search that follows rather than paid for twice.
pub fn judge_with_memo<O: FailureOracle>(
    candidate: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<bool, MinimizeError<O::Error>> {
    candidate.validate().map_err(MinimizeError::Trace)?;
    memo.decide(candidate, oracle)
}

#[cfg(test)]
mod tests;
