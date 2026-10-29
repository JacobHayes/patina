//! The entropy-request fault (`--entropy-fail-permille`): it fails only the
//! requests a real random pool can fail, stops once a request shows the pool
//! ready, draws on its own stream, and replays from the trace alone.

use patina_dst_abi::ErrorCode;
use patina_dst_driver_api::EntropyFaultReport;
use patina_dst_runtime::{Context, EntropyWait, RuntimeConfig, RuntimeError};
use tempfile::tempdir;

/// Each request's bytes, or its error code, and the run's entropy fault report.
type EntropyRun = (Vec<Result<Vec<u8>, ErrorCode>>, Option<EntropyFaultReport>);

/// Run `requests` (length and wait kind) against one Context.
fn entropy_run(config: RuntimeConfig, requests: &[(usize, EntropyWait)]) -> EntropyRun {
    let mut context = Context::from_config(config).unwrap();
    let outcomes = requests
        .iter()
        .map(|&(len, wait)| {
            context
                .entropy_bytes(len, wait)
                .map_err(|error| match error {
                    RuntimeError::Effect(error) => error.code,
                    other => panic!("entropy request failed outside the effect boundary: {other}"),
                })
        })
        .collect();
    let report = context.entropy_fault_report();
    context.finish().unwrap();
    (outcomes, report)
}

/// One eligible request: a `GRND_NONBLOCK` read of a pool not yet known ready.
fn entropy_once(
    config: RuntimeConfig,
    len: usize,
) -> (Result<Vec<u8>, ErrorCode>, Option<EntropyFaultReport>) {
    let (mut outcomes, report) = entropy_run(config, &[(len, EntropyWait::FailIfUnready)]);
    (outcomes.remove(0), report)
}

#[test]
fn the_entropy_failure_knob_fires_and_is_reported() {
    // Control: without the knob the request resolves and nothing reports.
    let (bytes, report) = entropy_once(RuntimeConfig::seeded(1), 16);
    assert_eq!(bytes.unwrap().len(), 16);
    assert!(report.is_none(), "no entropy knob was live, so no report");

    // MUST fail: a certain failure rate turns an eligible request into EAGAIN,
    // and the report proves it was applied.
    let (failed, report) = entropy_once(
        RuntimeConfig::seeded(4).with_entropy_fail_permille(1000),
        16,
    );
    assert_eq!(failed, Err(ErrorCode::WouldBlock));
    let report = report.expect("a live knob reports");
    assert_eq!(report.requests, 1);
    assert_eq!(report.failures_injected, 1);
}

#[test]
fn entropy_requests_no_real_pool_fails_are_never_failed_nor_counted() {
    // A request that waits for the pool, or reads regardless of it, cannot fail
    // on a real system, so even a certain rate leaves it alone. With no
    // eligible request, the knob is undiagnosable: not vacuous.
    let (outcomes, report) = entropy_run(
        RuntimeConfig::seeded(4).with_entropy_fail_permille(1000),
        &[(16, EntropyWait::Never), (16, EntropyWait::UntilReady)],
    );
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    let report = report.expect("a live knob reports");
    assert_eq!(report.requests, 0);
    assert!(!report.fail_vacuity_diagnosable);
    assert!(!report.is_vacuous());
}

#[test]
fn a_pool_shown_ready_is_never_failed_again() {
    // A pool that has initialized stays initialized. A waiting request that
    // returns proves it ready, so a later nonblocking read cannot fail.
    // `Never` proves nothing: an unready pool serves it too.
    let (outcomes, report) = entropy_run(
        RuntimeConfig::seeded(4).with_entropy_fail_permille(1000),
        &[
            (16, EntropyWait::FailIfUnready),
            (16, EntropyWait::Never),
            (16, EntropyWait::FailIfUnready),
            (16, EntropyWait::UntilReady),
            (16, EntropyWait::FailIfUnready),
        ],
    );
    let failed: Vec<bool> = outcomes.iter().map(Result::is_err).collect();
    assert_eq!(failed, [true, false, true, false, false]);
    let report = report.expect("a live knob reports");
    assert_eq!((report.requests, report.failures_injected), (2, 2));

    // So is a nonblocking read the knob let through: once any read sees the
    // pool ready, no later read is eligible.
    let seed = (0..64)
        .find(|&seed| {
            let (outcomes, _) = entropy_run(
                RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
                &[(16, EntropyWait::FailIfUnready)],
            );
            outcomes[0].is_ok()
        })
        .expect("some seed in range must not fire at rate 500");
    let (outcomes, report) = entropy_run(
        RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
        &[(16, EntropyWait::FailIfUnready); 32],
    );
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    assert_eq!(report.expect("a live knob reports").requests, 1);
}

#[test]
fn arming_the_entropy_fault_knob_does_not_perturb_a_request_it_does_not_fire_on() {
    // The §1.2-style guarantee: the fault decision draws from its own
    // domain-separated stream, never from the entropy stream itself. Find a
    // seed where a live knob does not fire on the first request, then check the
    // returned bytes equal the knob-absent baseline for that SAME seed — a
    // shared decision stream would perturb them.
    let seed = (0..64)
        .find(|&seed| {
            let (_, report) = entropy_once(
                RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
                16,
            );
            report.expect("live knob").failures_injected == 0
        })
        .expect("some seed in range must not fire at rate 500");
    let baseline = entropy_once(RuntimeConfig::seeded(seed), 16).0.unwrap();
    let armed = entropy_once(
        RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
        16,
    )
    .0
    .unwrap();
    assert_eq!(baseline, armed);
}

#[test]
fn entropy_failure_replays_self_contained_without_re_supplying_the_flag() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("entropy.patina");
    let requests = [
        (16, EntropyWait::FailIfUnready),
        (8, EntropyWait::UntilReady),
        (16, EntropyWait::FailIfUnready),
    ];
    let (recorded, recorded_report) = entropy_run(
        RuntimeConfig::record(4, &path, "patina-test").with_entropy_fail_permille(1000),
        &requests,
    );
    assert_eq!(recorded[0], Err(ErrorCode::WouldBlock));
    assert_eq!(recorded_report.expect("report").failures_injected, 1);

    // Flag-free: no --entropy-fail-permille. The trace restores it.
    let (replayed, _) = entropy_run(RuntimeConfig::replay(&path, "patina-test"), &requests);
    assert_eq!(replayed, recorded);

    // A conflicting knob at replay fails closed rather than silently running a
    // different fault schedule.
    let conflicting = RuntimeConfig::replay(&path, "patina-test").with_entropy_fail_permille(1);
    assert!(Context::from_config(conflicting).is_err());
}

#[test]
fn a_branch_knows_the_pool_its_replayed_prefix_showed_ready() {
    // The pool's state comes from outcomes, not draws, so a branch that replays
    // a prefix and then goes live continues from the state the prefix reached.
    // Here the prefix's waiting read showed the pool ready, so the branch's
    // live nonblocking read cannot fail, even at a certain rate.
    let directory = tempdir().unwrap();
    let path = directory.path().join("entropy.patina");
    let prefix = [
        (16, EntropyWait::FailIfUnready),
        (8, EntropyWait::UntilReady),
    ];
    let (recorded, _) = entropy_run(
        RuntimeConfig::record(4, &path, "patina-test").with_entropy_fail_permille(1000),
        &prefix,
    );
    assert_eq!(recorded[0], Err(ErrorCode::WouldBlock));
    let (branched, _) = entropy_run(
        RuntimeConfig::branch(&path, "main", 2, "branch", 5, "patina-test"),
        &[
            (16, EntropyWait::FailIfUnready),
            (8, EntropyWait::UntilReady),
            (16, EntropyWait::FailIfUnready),
        ],
    );
    assert_eq!(branched[..2], recorded[..]);
    assert!(branched[2].is_ok(), "{branched:?}");
}

#[test]
fn a_replay_that_asks_with_another_wait_diverges() {
    // The wait decides what a request can answer and what it shows of the
    // pool, so it is part of the operation: a replay that asks differently,
    // even at the same length, fails closed instead of handing a waiting
    // request a recorded EAGAIN or a branch the wrong pool state.
    let directory = tempdir().unwrap();
    for (index, (recorded, replayed)) in [
        (EntropyWait::FailIfUnready, EntropyWait::UntilReady),
        (EntropyWait::Never, EntropyWait::UntilReady),
    ]
    .into_iter()
    .enumerate()
    {
        let path = directory.path().join(format!("entropy-{index}.patina"));
        entropy_run(
            RuntimeConfig::record(4, &path, "patina-test").with_entropy_fail_permille(1000),
            &[(16, recorded)],
        );
        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "patina-test")).unwrap();
        let diverged = replay.entropy_bytes(16, replayed);
        assert!(
            matches!(diverged, Err(RuntimeError::Trace(_))),
            "{recorded:?} recorded, {replayed:?} replayed: {diverged:?}"
        );
    }
}
