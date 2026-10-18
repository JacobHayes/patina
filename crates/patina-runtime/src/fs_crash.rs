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

/// An embedder's channel for telling its supervisor that the selected crash
/// point was reached. [`Context::maybe_inject_crash`] calls it before anything
/// that carries the crash out (the export, the recording flush), so a
/// supervisor learns of the attempt even when one of those kills the process.
pub trait CrashAttemptSink: Send {
    fn attempting(&mut self, selector: CrashPoint);
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
    /// for the native shim/supervisor handoff, or [`RuntimeError::FsCrashFailed`]
    /// when the crash cannot be carried out. Manual [`Context::fs_crash`] keeps
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

        // The crash is spent whether or not it can be carried out: a failed
        // one ends the run as `FsCrashFailed`.
        self.crash_fired = true;
        if let Some(sink) = self.crash_attempt_sink.as_mut() {
            sink.attempting(point);
        }
        let snapshot = self.crash_restart_snapshot();
        // The crash, carried out or not, ends this incarnation's process
        // without finalization, so its recording (which ends with the
        // triggering operation) is written now: the supervisor joins it with
        // the next incarnation's, or keeps it as the failed crash's replay.
        self.flush_recording();
        let snapshot = snapshot.map_err(|reason| RuntimeError::FsCrashFailed {
            selector: point,
            reason,
        })?;
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

    /// Crash the filesystem and export the recovered durable image. The error
    /// is a bare reason, not an [`EffectError`], so no caller can hand it to
    /// the guest as an errno: [`Context::maybe_inject_crash`] makes it the
    /// run's [`RuntimeError::FsCrashFailed`].
    fn crash_restart_snapshot(&mut self) -> Result<FsSnapshot, String> {
        let bytes = self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem").to_string())?
            .crash_and_export_restart_snapshot()
            .map_err(|error| error.to_string())?;
        FsSnapshot::decode(&bytes).map_err(|error| {
            format!("filesystem driver exported an invalid crash-restart snapshot: {error}")
        })
    }
}

#[cfg(test)]
mod tests;
