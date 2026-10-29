//! Incarnation lifecycle markers, construction and validation.

use std::collections::BTreeSet;

use patina_dst_abi::CrashKind;
use serde::{Deserialize, Serialize};

use crate::{Sha256Digest, Timeline, TraceError, TraceEvent};

/// One incarnation lifecycle marker in a timeline's global logical order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// Global order slot within this timeline. Operation events carry their own
    /// `order`; lifecycle and operation orders share one namespace and must be
    /// unique, so crash/restart boundaries can be placed between successful
    /// boundary operations without changing operation sequence numbers.
    pub order: u64,
    #[serde(flatten)]
    pub kind: LifecycleEventKind,
}

/// Lifecycle transitions for crash->fresh-incarnation traces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEventKind {
    Start {
        incarnation: u64,
    },
    Crash {
        incarnation: u64,
        /// What the crash took down, which decides the image the next
        /// incarnation booted from.
        crash_kind: CrashKind,
        snapshot_digest: String,
    },
    Restart {
        from_incarnation: u64,
        to_incarnation: u64,
        snapshot_digest: String,
    },
    End {
        incarnation: u64,
    },
}

pub(super) fn validate_timeline_lifecycle(timeline: &Timeline) -> Result<(), TraceError> {
    validate_lifecycle_events(
        &format!("timeline {}", timeline.id),
        &timeline.lifecycle,
        &timeline.decisions,
    )
}

/// What is wrong with a timeline's incarnation lifecycle. The validator's
/// refusals are distinct failures of one state machine, so a consumer (or a
/// test) can tell them apart without reading the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleViolation {
    TooShort,
    DuplicateOrder {
        order: u64,
    },
    OrderNotIncreasing {
        order: u64,
    },
    StartWhileActive {
        incarnation: u64,
    },
    StartDisagreesWithRestart {
        incarnation: u64,
        expected: u64,
    },
    StartWithoutRestart {
        incarnation: u64,
    },
    CrashInactive {
        incarnation: u64,
    },
    RestartWhileActive,
    RestartWithoutCrash,
    RestartMismatchesCrash,
    RestartNotForward,
    EndInactive {
        incarnation: u64,
    },
    NotEndedCleanly,
    OperationReusesOrder {
        sequence: u64,
        order: u64,
    },
    OperationOutsideIncarnation {
        sequence: u64,
        order: u64,
    },
    OperationIncarnationMismatch {
        sequence: u64,
        declared: u64,
        expected: u64,
    },
}

impl std::fmt::Display for LifecycleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "must record at least Start and End lifecycle events"),
            Self::DuplicateOrder { order } => write!(f, "has duplicate global order {order}"),
            Self::OrderNotIncreasing { order } => {
                write!(f, "lifecycle order {order} is not strictly increasing")
            }
            Self::StartWhileActive { incarnation } => write!(
                f,
                "starts incarnation {incarnation} while another incarnation is active"
            ),
            Self::StartDisagreesWithRestart {
                incarnation,
                expected,
            } => write!(
                f,
                "starts incarnation {incarnation} but restart expected {expected}"
            ),
            Self::StartWithoutRestart { incarnation } => {
                write!(f, "has Start({incarnation}) without a preceding Restart")
            }
            Self::CrashInactive { incarnation } => {
                write!(f, "crashes inactive incarnation {incarnation}")
            }
            Self::RestartWhileActive => {
                write!(f, "restarts while an incarnation is still active")
            }
            Self::RestartWithoutCrash => write!(f, "has Restart without a preceding Crash"),
            Self::RestartMismatchesCrash => {
                write!(f, "Restart does not match preceding Crash")
            }
            Self::RestartNotForward => {
                write!(f, "Restart target must be greater than source")
            }
            Self::EndInactive { incarnation } => {
                write!(f, "ends inactive incarnation {incarnation}")
            }
            Self::NotEndedCleanly => write!(f, "lifecycle does not end cleanly"),
            Self::OperationReusesOrder { sequence, order } => {
                write!(
                    f,
                    "operation sequence {sequence} reuses global order {order}"
                )
            }
            Self::OperationOutsideIncarnation { sequence, order } => write!(
                f,
                "operation sequence {sequence} at order {order} is outside any active incarnation"
            ),
            Self::OperationIncarnationMismatch {
                sequence,
                declared,
                expected,
            } => write!(
                f,
                "operation sequence {sequence} declares incarnation {declared}, expected {expected} from lifecycle"
            ),
        }
    }
}

fn lifecycle_error(label: &str, violation: LifecycleViolation) -> TraceError {
    TraceError::Lifecycle {
        label: label.to_owned(),
        violation,
    }
}

pub(super) fn validate_lifecycle_events(
    label: &str,
    lifecycle: &[LifecycleEvent],
    decisions: &[TraceEvent],
) -> Result<(), TraceError> {
    if lifecycle.len() < 2 {
        return Err(lifecycle_error(label, LifecycleViolation::TooShort));
    }

    let mut global_orders = BTreeSet::new();
    let mut active = None;
    let mut pending_restart_start = None;
    let mut last_crash: Option<(u64, &str)> = None;
    for (index, marker) in lifecycle.iter().enumerate() {
        if !global_orders.insert(marker.order) {
            return Err(lifecycle_error(
                label,
                LifecycleViolation::DuplicateOrder {
                    order: marker.order,
                },
            ));
        }
        if index > 0 && marker.order <= lifecycle[index - 1].order {
            return Err(lifecycle_error(
                label,
                LifecycleViolation::OrderNotIncreasing {
                    order: marker.order,
                },
            ));
        }
        match &marker.kind {
            LifecycleEventKind::Start { incarnation } => {
                if active.is_some() {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::StartWhileActive {
                            incarnation: *incarnation,
                        },
                    ));
                }
                if let Some(expected) = pending_restart_start.take() {
                    if *incarnation != expected {
                        return Err(lifecycle_error(
                            label,
                            LifecycleViolation::StartDisagreesWithRestart {
                                incarnation: *incarnation,
                                expected,
                            },
                        ));
                    }
                } else if index != 0 {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::StartWithoutRestart {
                            incarnation: *incarnation,
                        },
                    ));
                }
                active = Some(*incarnation);
            }
            LifecycleEventKind::Crash {
                incarnation,
                snapshot_digest,
                ..
            } => {
                Sha256Digest::parse(snapshot_digest)?;
                if active != Some(*incarnation) {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::CrashInactive {
                            incarnation: *incarnation,
                        },
                    ));
                }
                active = None;
                last_crash = Some((*incarnation, snapshot_digest.as_str()));
            }
            LifecycleEventKind::Restart {
                from_incarnation,
                to_incarnation,
                snapshot_digest,
            } => {
                Sha256Digest::parse(snapshot_digest)?;
                if active.is_some() {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::RestartWhileActive,
                    ));
                }
                let Some((crashed, crash_digest)) = last_crash.take() else {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::RestartWithoutCrash,
                    ));
                };
                if crashed != *from_incarnation || crash_digest != snapshot_digest {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::RestartMismatchesCrash,
                    ));
                }
                if to_incarnation <= from_incarnation {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::RestartNotForward,
                    ));
                }
                pending_restart_start = Some(*to_incarnation);
            }
            LifecycleEventKind::End { incarnation } => {
                if active != Some(*incarnation) {
                    return Err(lifecycle_error(
                        label,
                        LifecycleViolation::EndInactive {
                            incarnation: *incarnation,
                        },
                    ));
                }
                active = None;
            }
        }
    }
    if active.is_some() || pending_restart_start.is_some() || last_crash.is_some() {
        return Err(lifecycle_error(label, LifecycleViolation::NotEndedCleanly));
    }

    for event in decisions {
        if !global_orders.insert(event.order) {
            return Err(lifecycle_error(
                label,
                LifecycleViolation::OperationReusesOrder {
                    sequence: event.sequence,
                    order: event.order,
                },
            ));
        }
        let active_incarnation =
            active_incarnation_at_order(lifecycle, event.order).ok_or_else(|| {
                lifecycle_error(
                    label,
                    LifecycleViolation::OperationOutsideIncarnation {
                        sequence: event.sequence,
                        order: event.order,
                    },
                )
            })?;
        if event.incarnation != active_incarnation {
            return Err(lifecycle_error(
                label,
                LifecycleViolation::OperationIncarnationMismatch {
                    sequence: event.sequence,
                    declared: event.incarnation,
                    expected: active_incarnation,
                },
            ));
        }
    }
    Ok(())
}

pub(super) fn active_incarnation_at_order(lifecycle: &[LifecycleEvent], order: u64) -> Option<u64> {
    let mut active = None;
    let mut pending_restart_start = None;
    for marker in lifecycle {
        if marker.order >= order {
            break;
        }
        match marker.kind {
            LifecycleEventKind::Start { incarnation } => {
                if pending_restart_start.is_none_or(|expected| expected == incarnation) {
                    active = Some(incarnation);
                    pending_restart_start = None;
                }
            }
            LifecycleEventKind::Crash { .. } | LifecycleEventKind::End { .. } => {
                active = None;
            }
            LifecycleEventKind::Restart { to_incarnation, .. } => {
                pending_restart_start = Some(to_incarnation);
            }
        }
    }
    active
}

pub(super) fn linear_lifecycle_from_start_and_incarnation(
    start_order: u64,
    incarnation: u64,
    decisions: &[TraceEvent],
) -> Vec<LifecycleEvent> {
    let end_order = decisions
        .last()
        .map(|event| event.order.saturating_add(1))
        .unwrap_or(start_order.saturating_add(1));
    vec![
        LifecycleEvent {
            order: start_order,
            kind: LifecycleEventKind::Start { incarnation },
        },
        LifecycleEvent {
            order: end_order,
            kind: LifecycleEventKind::End { incarnation },
        },
    ]
}

#[cfg(test)]
mod tests;
