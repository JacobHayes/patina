//! Incarnation lifecycle markers, construction and validation.

use std::collections::BTreeSet;

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

pub(super) fn validate_lifecycle_events(
    label: &str,
    lifecycle: &[LifecycleEvent],
    decisions: &[TraceEvent],
) -> Result<(), TraceError> {
    if lifecycle.len() < 2 {
        return Err(TraceError::Invalid(format!(
            "{label} must record at least Start and End lifecycle events"
        )));
    }

    let mut global_orders = BTreeSet::new();
    let mut active = None;
    let mut pending_restart_start = None;
    let mut last_crash: Option<(u64, &str)> = None;
    for (index, marker) in lifecycle.iter().enumerate() {
        if !global_orders.insert(marker.order) {
            return Err(TraceError::Invalid(format!(
                "{label} has duplicate global order {}",
                marker.order
            )));
        }
        if index > 0 && marker.order <= lifecycle[index - 1].order {
            return Err(TraceError::Invalid(format!(
                "{label} lifecycle order {} is not strictly increasing",
                marker.order
            )));
        }
        match &marker.kind {
            LifecycleEventKind::Start { incarnation } => {
                if active.is_some() {
                    return Err(TraceError::Invalid(format!(
                        "{label} starts incarnation {incarnation} while another incarnation is active"
                    )));
                }
                if let Some(expected) = pending_restart_start.take() {
                    if *incarnation != expected {
                        return Err(TraceError::Invalid(format!(
                            "{label} starts incarnation {incarnation} but restart expected {expected}"
                        )));
                    }
                } else if index != 0 {
                    return Err(TraceError::Invalid(format!(
                        "{label} has Start({incarnation}) without a preceding Restart"
                    )));
                }
                active = Some(*incarnation);
            }
            LifecycleEventKind::Crash {
                incarnation,
                snapshot_digest,
            } => {
                Sha256Digest::parse(snapshot_digest)?;
                if active != Some(*incarnation) {
                    return Err(TraceError::Invalid(format!(
                        "{label} crashes inactive incarnation {incarnation}"
                    )));
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
                    return Err(TraceError::Invalid(format!(
                        "{label} restarts while an incarnation is still active"
                    )));
                }
                let Some((crashed, crash_digest)) = last_crash.take() else {
                    return Err(TraceError::Invalid(format!(
                        "{label} has Restart without a preceding Crash"
                    )));
                };
                if crashed != *from_incarnation || crash_digest != snapshot_digest {
                    return Err(TraceError::Invalid(format!(
                        "{label} Restart does not match preceding Crash"
                    )));
                }
                if to_incarnation <= from_incarnation {
                    return Err(TraceError::Invalid(format!(
                        "{label} Restart target must be greater than source"
                    )));
                }
                pending_restart_start = Some(*to_incarnation);
            }
            LifecycleEventKind::End { incarnation } => {
                if active != Some(*incarnation) {
                    return Err(TraceError::Invalid(format!(
                        "{label} ends inactive incarnation {incarnation}"
                    )));
                }
                active = None;
            }
        }
    }
    if active.is_some() || pending_restart_start.is_some() || last_crash.is_some() {
        return Err(TraceError::Invalid(format!(
            "{label} lifecycle does not end cleanly"
        )));
    }

    for event in decisions {
        if !global_orders.insert(event.order) {
            return Err(TraceError::Invalid(format!(
                "{label} operation sequence {} reuses global order {}",
                event.sequence, event.order
            )));
        }
        let active_incarnation =
            active_incarnation_at_order(lifecycle, event.order).ok_or_else(|| {
                TraceError::Invalid(format!(
                    "{label} operation sequence {} at order {} is outside any active incarnation",
                    event.sequence, event.order
                ))
            })?;
        if event.incarnation != active_incarnation {
            return Err(TraceError::Invalid(format!(
                "{label} operation sequence {} declares incarnation {}, expected {} from lifecycle",
                event.sequence, event.incarnation, active_incarnation
            )));
        }
    }
    Ok(())
}

fn active_incarnation_at_order(lifecycle: &[LifecycleEvent], order: u64) -> Option<u64> {
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
