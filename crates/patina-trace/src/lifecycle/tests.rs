//! Tests for incarnation lifecycle markers, construction and validation.

use super::*;
use crate::MAIN_TIMELINE;
use crate::tests::operation;
use crate::{RunMetadata, TRACE_FORMAT_VERSION, Timeline, TraceBundle, TraceError, TraceEvent};
use patina_dst_abi::{Fd, Operation, Outcome};

#[test]
fn resolved_branch_lifecycle_state_is_validated() {
    let mut main_event = TraceEvent::new(0, operation(), Outcome::U64(10));
    main_event.order = 1;
    let mut branch_event = TraceEvent::new(1, operation(), Outcome::U64(20));
    branch_event.order = 3;
    branch_event.incarnation = 1;
    let bundle = TraceBundle {
        format_version: TRACE_FORMAT_VERSION,
        metadata: RunMetadata::new(7, "fingerprint", 0, "patina"),
        timelines: vec![
            Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle: vec![
                    LifecycleEvent {
                        order: 0,
                        kind: LifecycleEventKind::Start { incarnation: 0 },
                    },
                    LifecycleEvent {
                        order: 2,
                        kind: LifecycleEventKind::End { incarnation: 0 },
                    },
                ],
                decisions: vec![main_event],
            },
            Timeline {
                id: "branch-1".into(),
                parent: Some(MAIN_TIMELINE.into()),
                from_sequence: Some(1),
                branch_seed: Some(99),
                lifecycle: vec![
                    LifecycleEvent {
                        order: 2,
                        kind: LifecycleEventKind::Start { incarnation: 1 },
                    },
                    LifecycleEvent {
                        order: 4,
                        kind: LifecycleEventKind::End { incarnation: 1 },
                    },
                ],
                decisions: vec![branch_event],
            },
        ],
    };
    let error = bundle.validate().unwrap_err();
    assert!(
        matches!(&error, TraceError::Invalid(message) if message.contains("resolved timeline branch-1 starts incarnation 1 while another incarnation is active")),
        "unexpected error: {error}"
    );
}

#[test]
fn lifecycle_models_crash_restart_with_global_order() {
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let bundle = TraceBundle {
        format_version: TRACE_FORMAT_VERSION,
        metadata: RunMetadata::new(7, "fingerprint+crash-restart", 0, "patina"),
        timelines: vec![Timeline {
            id: MAIN_TIMELINE.into(),
            parent: None,
            from_sequence: None,
            branch_seed: None,
            lifecycle: vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 2,
                    kind: LifecycleEventKind::Crash {
                        incarnation: 0,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 3,
                    kind: LifecycleEventKind::Restart {
                        from_incarnation: 0,
                        to_incarnation: 1,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::Start { incarnation: 1 },
                },
                LifecycleEvent {
                    order: 6,
                    kind: LifecycleEventKind::End { incarnation: 1 },
                },
            ],
            decisions: vec![
                TraceEvent {
                    sequence: 0,
                    order: 1,
                    incarnation: 0,
                    operation: Operation::FsWrite {
                        fd: Fd(3),
                        bytes: b"trigger".to_vec(),
                    },
                    outcome: Outcome::Usize(7),
                },
                TraceEvent {
                    sequence: 1,
                    order: 5,
                    incarnation: 1,
                    operation: operation(),
                    outcome: Outcome::U64(11),
                },
            ],
        }],
    };
    bundle.validate().unwrap();
    let bytes = bundle.to_bytes().unwrap();
    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded, bundle);
    assert_eq!(
        reloaded.to_bytes().unwrap(),
        bytes,
        "v5 lifecycle encoding is canonical"
    );
}

#[test]
fn lifecycle_ordering_and_incarnation_mismatches_are_refused() {
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fingerprint", 0, "patina"),
        vec![TraceEvent::new(0, operation(), Outcome::U64(0))],
    );
    bundle.timelines[0].decisions[0].order = 0;
    let error = bundle.validate().unwrap_err();
    assert!(
        error.to_string().contains("reuses global order"),
        "duplicate lifecycle/operation order must be named: {error}"
    );

    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fingerprint", 0, "patina"),
        vec![TraceEvent::new(0, operation(), Outcome::U64(0))],
    );
    bundle.timelines[0].decisions[0].incarnation = 1;
    let error = bundle.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("declares incarnation 1, expected 0"),
        "incarnation/lifecycle mismatch must be named: {error}"
    );
}

#[test]
fn lifecycle_missing_crash_digest_mismatch_and_unended_states_are_refused() {
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let other = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let mut bundle = crash_restart_bundle(digest);
    bundle.timelines[0].lifecycle[1].kind = LifecycleEventKind::End { incarnation: 0 };
    let error = bundle.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Restart without a preceding Crash"),
        "missing crash must be named: {error}"
    );

    let mut bundle = crash_restart_bundle(digest);
    if let LifecycleEventKind::Restart {
        snapshot_digest, ..
    } = &mut bundle.timelines[0].lifecycle[2].kind
    {
        *snapshot_digest = other.into();
    }
    let error = bundle.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Restart does not match preceding Crash"),
        "digest mismatch must be named: {error}"
    );

    let mut bundle = crash_restart_bundle(digest);
    bundle.timelines[0].lifecycle.pop();
    let error = bundle.validate().unwrap_err();
    assert!(
        error.to_string().contains("lifecycle does not end cleanly"),
        "unended lifecycle must be named: {error}"
    );
}

fn crash_restart_bundle(digest: &str) -> TraceBundle {
    TraceBundle {
        format_version: TRACE_FORMAT_VERSION,
        metadata: RunMetadata::new(7, "fingerprint+crash-restart", 0, "patina"),
        timelines: vec![Timeline {
            id: MAIN_TIMELINE.into(),
            parent: None,
            from_sequence: None,
            branch_seed: None,
            lifecycle: vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 2,
                    kind: LifecycleEventKind::Crash {
                        incarnation: 0,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 3,
                    kind: LifecycleEventKind::Restart {
                        from_incarnation: 0,
                        to_incarnation: 1,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::Start { incarnation: 1 },
                },
                LifecycleEvent {
                    order: 6,
                    kind: LifecycleEventKind::End { incarnation: 1 },
                },
            ],
            decisions: vec![
                TraceEvent {
                    sequence: 0,
                    order: 1,
                    incarnation: 0,
                    operation: Operation::FsWrite {
                        fd: Fd(3),
                        bytes: b"trigger".to_vec(),
                    },
                    outcome: Outcome::Usize(7),
                },
                TraceEvent {
                    sequence: 1,
                    order: 5,
                    incarnation: 1,
                    operation: operation(),
                    outcome: Outcome::U64(11),
                },
            ],
        }],
    }
}
