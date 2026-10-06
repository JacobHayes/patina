//! Candidate memo sampling and speculative-window soundness tests.

use super::*;
use crate::tests::{value_bundle, values};
use std::convert::Infallible;

#[test]
fn the_sampling_policy_is_content_derived_and_hits_its_advertised_rate() {
    let memo = CandidateMemo::new();
    let sampled = (0..=u8::MAX)
        .filter(|&byte| {
            let mut digest = [0u8; 32];
            digest[0] = byte;
            memo.verifies(&digest, 1)
        })
        .count();
    assert_eq!(
        sampled,
        256 / VERIFICATION_PERIOD as usize,
        "one hit in {VERIFICATION_PERIOD} must be re-verified"
    );
    // The same digest at successive hits moves in and out of the sample, so
    // a candidate that recurs often is re-verified repeatedly rather than
    // trusted forever, and one that never recurs costs nothing.
    let digest = [0u8; 32];
    assert!((1..=VERIFICATION_PERIOD).any(|hits| memo.verifies(&digest, hits)));
    let every = CandidateMemo::with_verification_period(1);
    assert!((1..=8).all(|hits| every.verifies(&digest, hits)));
}

#[test]
fn a_contradiction_after_the_accept_in_a_window_is_not_lost() {
    // The precise hazard batching introduces, arranged rather than hoped
    // for: the window's FIRST candidate is accepted and its SECOND is a
    // cache hit whose sampled re-run disagrees. The accept is the answer
    // the search wants, so an implementation that stopped reading verdicts
    // once it had one would return that accept and never see the
    // contradiction - laundering a flaky oracle exactly when the window is
    // wide. Every verdict in a window is resolved, so it aborts instead.
    let accepted = value_bundle(&[999, 1]);
    let contradicted = value_bundle(&[999, 2]);
    let mut memo = CandidateMemo::with_verification_period(1);
    // Seed the cache with an honest "still failing" verdict for the second
    // candidate, so the window below is a hit rather than a miss.
    let seeded = judge_with_memo(
        &contradicted,
        &mut |_: &TraceBundle| Ok::<_, Infallible>(true),
        &mut memo,
    )
    .unwrap();
    assert!(seeded, "the cache must be seeded with a positive verdict");

    struct AcceptFirstDenySecond;
    impl FailureOracle for AcceptFirstDenySecond {
        type Error = Infallible;

        fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Infallible> {
            // The first candidate still fails; the second now contradicts
            // the verdict its identical bytes already produced.
            Ok(values(candidate) == vec![999, 1])
        }

        fn batch_width(&self) -> usize {
            2
        }
    }

    let error = memo
        .first_accepted(&[&accepted, &contradicted], &mut AcceptFirstDenySecond)
        .unwrap_err();
    assert!(
        matches!(error, MinimizeError::NondeterministicOracle { .. }),
        "a contradiction behind an accept was lost: {error}"
    );
}
