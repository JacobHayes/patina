//! Filesystem crash selectors, accounting, and crash injection.

use crate::ENV_FS_CRASH_AT;

use crate::{Context, InjectedFsCrash, RuntimeError};
use patina_dst_abi::{EffectError, Operation};

use patina_dst_fs_mem::FsSnapshot;
use patina_dst_trace::HandoffConsumedState;
use std::fmt;

/// A boundary operation kind that a filesystem crash can be pinned to. The
/// runtime crashes immediately after the Nth matching operation completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashOp {
    Open,
    Write,
    Sync,
    Close,
}

impl fmt::Display for CrashOp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open => "open",
            Self::Write => "write",
            Self::Sync => "sync",
            Self::Close => "close",
        })
    }
}

/// Where a filesystem crash is injected: after the `ordinal`-th (1-based)
/// occurrence of `op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashPoint {
    pub op: CrashOp,
    pub ordinal: u64,
}

impl CrashPoint {
    /// Parse a `close:1`/`write:3`/`sync:2`/`open:1` crash point. A bare op
    /// name (`close`) means the first occurrence.
    pub fn parse(value: &str) -> Result<Self, RuntimeError> {
        let (op_text, ordinal) = match value.split_once(':') {
            Some((op_text, ordinal_text)) => {
                let ordinal = ordinal_text.parse::<u64>().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_FS_CRASH_AT} ordinal must be a positive integer: {value:?}"
                    ))
                })?;
                (op_text, ordinal)
            }
            None => (value, 1),
        };
        if ordinal == 0 {
            return Err(RuntimeError::Config(format!(
                "{ENV_FS_CRASH_AT} ordinal is 1-based and must be at least 1: {value:?}"
            )));
        }
        let op = match op_text {
            "open" => CrashOp::Open,
            "write" => CrashOp::Write,
            "sync" => CrashOp::Sync,
            "close" => CrashOp::Close,
            other => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_FS_CRASH_AT} op must be open, write, sync, or close; got {other:?}"
                )));
            }
        };
        Ok(Self { op, ordinal })
    }
}

/// The canonical `op:ordinal` spelling [`CrashPoint::parse`] reads back.
impl fmt::Display for CrashPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.op, self.ordinal)
    }
}

impl From<CrashPoint> for patina_dst_trace::CrashPointRecord {
    fn from(point: CrashPoint) -> Self {
        let op = match point.op {
            CrashOp::Open => patina_dst_trace::FaultCrashOp::Open,
            CrashOp::Write => patina_dst_trace::FaultCrashOp::Write,
            CrashOp::Sync => patina_dst_trace::FaultCrashOp::Sync,
            CrashOp::Close => patina_dst_trace::FaultCrashOp::Close,
        };
        Self {
            op,
            ordinal: point.ordinal,
        }
    }
}

impl From<patina_dst_trace::CrashPointRecord> for CrashPoint {
    fn from(record: patina_dst_trace::CrashPointRecord) -> Self {
        let op = match record.op {
            patina_dst_trace::FaultCrashOp::Open => CrashOp::Open,
            patina_dst_trace::FaultCrashOp::Write => CrashOp::Write,
            patina_dst_trace::FaultCrashOp::Sync => CrashOp::Sync,
            patina_dst_trace::FaultCrashOp::Close => CrashOp::Close,
        };
        Self {
            op,
            ordinal: record.ordinal,
        }
    }
}

/// Per-operation-kind occurrence counters used to fire a crash at the Nth
/// boundary op of a chosen kind.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrashCounts {
    pub open: u64,
    pub write: u64,
    pub sync: u64,
    pub close: u64,
}
impl Context {
    pub fn fs_crash(&mut self) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(Operation::FsCrash, |filesystem| filesystem.crash())
    }

    /// Fire the configured filesystem crash if the just-completed SUCCESSFUL
    /// boundary operation is the selected Nth occurrence. The triggering guest
    /// call must never return: reaching the selected point produces an internal
    /// incarnation-termination control carrying the recovered durable snapshot
    /// for the native shim/supervisor handoff. Manual [`Context::fs_crash`] keeps
    /// its explicit rollback-in-place semantics and does not route here.
    pub(super) fn maybe_inject_crash(&mut self, op: CrashOp) -> Result<(), RuntimeError> {
        if self.crash_fired {
            return Ok(());
        }
        let Some(point) = self.crash_at else {
            return Ok(());
        };
        let count = match op {
            CrashOp::Open => {
                self.crash_counts.open += 1;
                self.crash_counts.open
            }
            CrashOp::Write => {
                self.crash_counts.write += 1;
                self.crash_counts.write
            }
            CrashOp::Sync => {
                self.crash_counts.sync += 1;
                self.crash_counts.sync
            }
            CrashOp::Close => {
                self.crash_counts.close += 1;
                self.crash_counts.close
            }
        };
        if point.op != op || count != point.ordinal {
            return Ok(());
        }

        self.crash_fired = true;
        let snapshot_bytes = self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .crash_and_export_restart_snapshot()?;
        let snapshot = FsSnapshot::decode(&snapshot_bytes).map_err(|error| {
            RuntimeError::Config(format!(
                "filesystem driver exported an invalid crash-restart snapshot: {error}"
            ))
        })?;
        // The crash ends this incarnation's process without finalization, so its
        // recording (which ends with the triggering operation) is written now;
        // the supervisor joins it with the next incarnation's.
        self.flush_recording();
        Err(RuntimeError::InjectedFsCrash(Box::new(InjectedFsCrash {
            compatibility_fingerprint: self.execution_fingerprint().to_string(),
            from_incarnation: self.incarnation,
            to_incarnation: self.incarnation.saturating_add(1),
            selector: point.into(),
            consumed: HandoffConsumedState {
                operations: self.steps,
                lifecycle_order: self.steps,
            },
            snapshot,
        })))
    }
}

#[cfg(test)]
mod tests;
