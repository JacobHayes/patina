//! The one trace a crash-restart run leaves behind, and the per-incarnation
//! traces it is assembled from.
//!
//! Each incarnation of a crash-restart run is its own host process, and each
//! records (and replays) a linear trace of its own operations, stamped with
//! its incarnation and numbered from sequence 0. The supervisor joins those
//! into one bundle whose main timeline carries the lifecycle `Start(0)`,
//! incarnation 0's operations (ending with the one that fired the crash
//! selector), `Crash(0, digest)`, `Restart(0 -> 1, digest)`, `Start(1)`,
//! incarnation 1's operations, `End(1)`. In the joined timeline `sequence`
//! counts operations only, contiguously across both incarnations (incarnation
//! 1's first operation follows incarnation 0's last), while `order` also
//! gives each lifecycle marker a slot. Replay takes the bundle apart again and
//! hands each incarnation its own segment. The recovered filesystem itself is
//! not stored: replay re-derives it by replaying incarnation 0 to its crash
//! and checks it against the recorded digest.

use std::collections::BTreeSet;

use crate::{
    BuggifyConfigRecord, LifecycleEvent, LifecycleEventKind, MAIN_TIMELINE, RunMetadata,
    Sha256Digest, Timeline, TraceBundle, TraceError, TraceEvent,
};

/// A crash-restart run's trace taken apart at its crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashRestartSegments {
    /// Incarnation 0's own linear trace, ending with the operation that fired
    /// the crash selector.
    pub crashed: TraceBundle,
    /// Digest of the recovered filesystem snapshot incarnation 1 started from:
    /// the handoff's domain-separated snapshot digest
    /// ([`crate::VerifiedIncarnationHandoff::snapshot_digest`]).
    pub snapshot_digest: Sha256Digest,
    /// Incarnation 1's own linear trace, from its first operation to the end of
    /// the run.
    pub restarted: TraceBundle,
}

impl CrashRestartSegments {
    /// Assemble the run's single crash-restart trace.
    ///
    /// Both segments must be linear single-incarnation traces of the same run:
    /// their metadata agrees on everything except the buggify sites each
    /// incarnation happened to reach, which are merged.
    pub fn join(self) -> Result<TraceBundle, TraceError> {
        let crashed = incarnation_decisions(&self.crashed, 0)?;
        let restarted = incarnation_decisions(&self.restarted, 1)?;
        let metadata = merge_incarnation_metadata(self.crashed.metadata, self.restarted.metadata)?;
        let digest = self.snapshot_digest.to_string();

        let crashed_len = crashed.len() as u64;
        let crash_order = crashed_len + 1;
        let restart_start_order = crash_order + 2;
        let mut decisions = Vec::with_capacity(crashed.len() + restarted.len());
        for (index, event) in crashed.into_iter().enumerate() {
            let index = index as u64;
            decisions.push(TraceEvent {
                sequence: index,
                order: index + 1,
                incarnation: 0,
                operation: event.operation,
                outcome: event.outcome,
            });
        }
        let restarted_len = restarted.len() as u64;
        for (index, event) in restarted.into_iter().enumerate() {
            let index = index as u64;
            decisions.push(TraceEvent {
                sequence: crashed_len + index,
                order: restart_start_order + 1 + index,
                incarnation: 1,
                operation: event.operation,
                outcome: event.outcome,
            });
        }
        let lifecycle = vec![
            LifecycleEvent {
                order: 0,
                kind: LifecycleEventKind::Start { incarnation: 0 },
            },
            LifecycleEvent {
                order: crash_order,
                kind: LifecycleEventKind::Crash {
                    incarnation: 0,
                    snapshot_digest: digest.clone(),
                },
            },
            LifecycleEvent {
                order: crash_order + 1,
                kind: LifecycleEventKind::Restart {
                    from_incarnation: 0,
                    to_incarnation: 1,
                    snapshot_digest: digest,
                },
            },
            LifecycleEvent {
                order: restart_start_order,
                kind: LifecycleEventKind::Start { incarnation: 1 },
            },
            LifecycleEvent {
                order: restart_start_order + 1 + restarted_len,
                kind: LifecycleEventKind::End { incarnation: 1 },
            },
        ];
        let bundle = TraceBundle {
            format_version: self.crashed.format_version,
            metadata,
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle,
                decisions,
            }],
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

impl TraceBundle {
    /// Take a crash-restart trace apart into its two incarnations' own traces,
    /// or `None` for a trace that records no crash.
    ///
    /// A crash-restart trace has exactly one timeline whose lifecycle is
    /// `Start(0)`, `Crash(0)`, `Restart(0 -> 1)`, `Start(1)`, `End(1)`; any
    /// other lifecycle holding a crash is refused rather than guessed at.
    pub fn crash_restart_segments(&self) -> Result<Option<CrashRestartSegments>, TraceError> {
        let crashes = self
            .timelines
            .iter()
            .any(|timeline| timeline.lifecycle.iter().any(is_crash));
        if !crashes {
            return Ok(None);
        }
        let [main] = self.timelines.as_slice() else {
            return Err(TraceError::Invalid(
                "a crash-restart trace must hold exactly one timeline; branching a crash-restart \
                 run is not modeled"
                    .into(),
            ));
        };
        let digest = match main.lifecycle.as_slice() {
            [
                LifecycleEvent {
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                    ..
                },
                LifecycleEvent {
                    kind:
                        LifecycleEventKind::Crash {
                            incarnation: 0,
                            snapshot_digest,
                        },
                    ..
                },
                LifecycleEvent {
                    kind:
                        LifecycleEventKind::Restart {
                            from_incarnation: 0,
                            to_incarnation: 1,
                            ..
                        },
                    ..
                },
                LifecycleEvent {
                    kind: LifecycleEventKind::Start { incarnation: 1 },
                    ..
                },
                LifecycleEvent {
                    kind: LifecycleEventKind::End { incarnation: 1 },
                    ..
                },
            ] => Sha256Digest::parse(snapshot_digest)?,
            _ => {
                return Err(TraceError::Invalid(
                    "a crash-restart trace must record exactly Start(0), Crash(0), \
                     Restart(0 -> 1), Start(1), End(1)"
                        .into(),
                ));
            }
        };
        let segment = |incarnation: u64| {
            let decisions = main
                .decisions
                .iter()
                .filter(|event| event.incarnation == incarnation)
                .enumerate()
                .map(|(index, event)| {
                    TraceEvent::new(index as u64, event.operation.clone(), event.outcome.clone())
                })
                .collect();
            TraceBundle::linear(self.metadata.clone(), incarnation, decisions)
        };
        Ok(Some(CrashRestartSegments {
            crashed: segment(0),
            snapshot_digest: digest,
            restarted: segment(1),
        }))
    }
}

fn is_crash(marker: &LifecycleEvent) -> bool {
    matches!(marker.kind, LifecycleEventKind::Crash { .. })
}

/// The decisions of a segment that is `incarnation`'s own linear trace: one
/// unbranched timeline whose lifecycle is `Start(incarnation)`,
/// `End(incarnation)`.
fn incarnation_decisions(
    bundle: &TraceBundle,
    incarnation: u64,
) -> Result<Vec<TraceEvent>, TraceError> {
    bundle.validate()?;
    let [main] = bundle.timelines.as_slice() else {
        return Err(TraceError::Invalid(format!(
            "incarnation {incarnation}'s segment must be one linear timeline"
        )));
    };
    match main.lifecycle.as_slice() {
        [
            LifecycleEvent {
                kind: LifecycleEventKind::Start { incarnation: start },
                ..
            },
            LifecycleEvent {
                kind: LifecycleEventKind::End { incarnation: end },
                ..
            },
        ] if *start == incarnation && *end == incarnation => Ok(main.decisions.clone()),
        _ => Err(TraceError::Invalid(format!(
            "incarnation {incarnation}'s segment must be one linear timeline of that incarnation"
        ))),
    }
}

/// The metadata of the joined trace. Every incarnation runs the same
/// configuration from the same seed, so the two records must agree exactly;
/// only the buggify record differs, because it lists the sites and knobs each
/// incarnation reached, and the run reached the union.
fn merge_incarnation_metadata(
    mut crashed: RunMetadata,
    mut restarted: RunMetadata,
) -> Result<RunMetadata, TraceError> {
    let buggify = merge_buggify(crashed.buggify.take(), restarted.buggify.take())?;
    if crashed != restarted {
        return Err(TraceError::Invalid(
            "the crashed and restarted incarnations recorded different run metadata".into(),
        ));
    }
    crashed.buggify = buggify;
    Ok(crashed)
}

fn merge_buggify(
    crashed: Option<BuggifyConfigRecord>,
    restarted: Option<BuggifyConfigRecord>,
) -> Result<Option<BuggifyConfigRecord>, TraceError> {
    let (crashed, restarted) = match (crashed, restarted) {
        (None, None) => return Ok(None),
        (Some(crashed), Some(restarted)) => (crashed, restarted),
        _ => {
            return Err(TraceError::Invalid(
                "only one incarnation recorded a buggify configuration".into(),
            ));
        }
    };
    let config_differs = crashed.fire_permille != restarted.fire_permille
        || crashed.activation_permille != restarted.activation_permille
        || crashed.cutoff_nanos != restarted.cutoff_nanos
        || crashed.after_setup != restarted.after_setup;
    if config_differs {
        return Err(TraceError::Invalid(
            "the crashed and restarted incarnations recorded different buggify configurations"
                .into(),
        ));
    }
    let active_sites: BTreeSet<String> = crashed
        .active_sites
        .into_iter()
        .chain(restarted.active_sites)
        .collect();
    let mut knobs = crashed.knobs;
    for (label, value) in restarted.knobs {
        if *knobs.entry(label.clone()).or_insert(value) != value {
            return Err(TraceError::Invalid(format!(
                "the crashed and restarted incarnations realized different values for buggify \
                 knob {label:?}"
            )));
        }
    }
    Ok(Some(BuggifyConfigRecord {
        active_sites: active_sites.into_iter().collect(),
        knobs,
        ..crashed
    }))
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{Fd, Operation, Outcome};

    use super::*;

    const DIGEST: Sha256Digest = Sha256Digest([0xab; 32]);

    fn write(bytes: &[u8]) -> Operation {
        Operation::FsWrite {
            fd: Fd(3),
            bytes: bytes.to_vec(),
        }
    }

    fn segment(metadata: &RunMetadata, incarnation: u64, writes: &[&[u8]]) -> TraceBundle {
        let decisions = writes
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                TraceEvent::new(index as u64, write(bytes), Outcome::Usize(bytes.len()))
            })
            .collect();
        TraceBundle::linear(metadata.clone(), incarnation, decisions)
    }

    fn segments() -> CrashRestartSegments {
        let metadata = RunMetadata::new(7, "fingerprint");
        CrashRestartSegments {
            crashed: segment(&metadata, 0, &[b"before", b"trigger"]),
            snapshot_digest: DIGEST,
            restarted: segment(&metadata, 1, &[b"after"]),
        }
    }

    fn buggify(active_sites: &[&str], knobs: &[(&str, i64)]) -> BuggifyConfigRecord {
        BuggifyConfigRecord {
            fire_permille: 250,
            activation_permille: 250,
            cutoff_nanos: 300_000_000_000,
            after_setup: false,
            active_sites: active_sites.iter().map(|site| (*site).into()).collect(),
            knobs: knobs
                .iter()
                .map(|(label, value)| ((*label).into(), *value))
                .collect(),
        }
    }

    #[test]
    fn join_places_the_crash_between_the_two_incarnations() {
        let joined = segments().join().unwrap();
        let main = &joined.timelines[0];
        let digest = DIGEST.to_string();
        assert_eq!(
            main.lifecycle,
            vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 3,
                    kind: LifecycleEventKind::Crash {
                        incarnation: 0,
                        snapshot_digest: digest.clone(),
                    },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::Restart {
                        from_incarnation: 0,
                        to_incarnation: 1,
                        snapshot_digest: digest,
                    },
                },
                LifecycleEvent {
                    order: 5,
                    kind: LifecycleEventKind::Start { incarnation: 1 },
                },
                LifecycleEvent {
                    order: 7,
                    kind: LifecycleEventKind::End { incarnation: 1 },
                },
            ]
        );
        let placement: Vec<(u64, u64, u64)> = main
            .decisions
            .iter()
            .map(|event| (event.sequence, event.order, event.incarnation))
            .collect();
        assert_eq!(placement, vec![(0, 1, 0), (1, 2, 0), (2, 6, 1)]);
    }

    #[test]
    fn segments_of_a_joined_trace_are_the_segments_it_was_joined_from() {
        let original = segments();
        let joined = original.clone().join().unwrap();
        let reloaded = TraceBundle::from_slice(&joined.to_bytes().unwrap()).unwrap();
        assert_eq!(reloaded.crash_restart_segments().unwrap(), Some(original));
    }

    #[test]
    fn a_trace_without_a_crash_has_no_segments() {
        let metadata = RunMetadata::new(7, "fingerprint");
        let linear = segment(&metadata, 0, &[b"only"]);
        assert_eq!(linear.crash_restart_segments().unwrap(), None);
    }

    #[test]
    fn join_refuses_incarnations_with_different_metadata() {
        let mut parts = segments();
        parts.restarted.metadata.root_seed += 1;
        let error = parts.join().unwrap_err();
        assert!(
            error.to_string().contains("different run metadata"),
            "{error}"
        );
    }

    #[test]
    fn join_refuses_a_segment_that_already_crashed() {
        let mut parts = segments();
        parts.restarted = segments().join().unwrap();
        let error = parts.join().unwrap_err();
        assert!(error.to_string().contains("one linear timeline"), "{error}");
    }

    #[test]
    fn join_refuses_a_segment_of_the_wrong_incarnation() {
        let mut parts = segments();
        let metadata = parts.restarted.metadata.clone();
        parts.restarted = segment(&metadata, 0, &[b"after"]);
        let error = parts.join().unwrap_err();
        assert!(
            error.to_string().contains("incarnation 1's segment"),
            "{error}"
        );
    }

    #[test]
    fn join_merges_the_buggify_sites_each_incarnation_reached() {
        let mut parts = segments();
        parts.crashed.metadata.buggify = Some(buggify(&["b", "c"], &[("b", 4)]));
        parts.restarted.metadata.buggify = Some(buggify(&["a", "b"], &[("a", 1), ("b", 4)]));
        let joined = parts.join().unwrap();
        assert_eq!(
            joined.metadata.buggify,
            Some(buggify(&["a", "b", "c"], &[("a", 1), ("b", 4)]))
        );
    }

    #[test]
    fn join_refuses_a_buggify_knob_realized_differently_per_incarnation() {
        let mut parts = segments();
        parts.crashed.metadata.buggify = Some(buggify(&[], &[("b", 4)]));
        parts.restarted.metadata.buggify = Some(buggify(&[], &[("b", 5)]));
        let error = parts.join().unwrap_err();
        assert!(error.to_string().contains("knob \"b\""), "{error}");
    }

    #[test]
    fn segments_refuse_a_branched_crash_trace() {
        let mut joined = segments().join().unwrap();
        joined.timelines.push(Timeline {
            id: "branch".into(),
            parent: Some(MAIN_TIMELINE.into()),
            from_sequence: Some(1),
            branch_seed: Some(9),
            lifecycle: Vec::new(),
            decisions: Vec::new(),
        });
        let error = joined.crash_restart_segments().unwrap_err();
        assert!(
            error.to_string().contains("exactly one timeline"),
            "{error}"
        );
    }
}
