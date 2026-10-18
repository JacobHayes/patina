//! Filesystem crash selectors, accounting, and crash injection.

use crate::ENV_FS_CRASH_AT;

use crate::{Context, InjectedFsCrash, RuntimeError};
use patina_dst_abi::{EffectError, Operation};

use patina_dst_fs_mem::FsSnapshot;
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain, incarnation_seed};
use patina_dst_trace::HandoffConsumedState;
use std::fmt;
use std::num::NonZeroU64;
use std::ops::RangeInclusive;

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

/// Which boot of a run a [`Context`] is. Every run boots once; a native
/// `--fs-crash-at` run boots again after its crash, from the recovered
/// filesystem, as a rebooted machine would.
///
/// Each boot draws its own seeded streams ([`Incarnation::stream_root`]) and
/// starts its monotonic clock at the run's boot origin again, while realtime
/// carries on from where the crashed boot left it, plus a seeded downtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Incarnation {
    /// Incarnation 0: the run's first boot, on its configured clock origins.
    #[default]
    First,
    /// A boot after a modeled crash.
    Restarted {
        /// The incarnation number, from 1.
        id: NonZeroU64,
        /// The realtime the crashed incarnation's clock had reached when it
        /// crashed: the handoff's `realtime_nanos`.
        previous_realtime_nanos: u64,
    },
}

/// The range of the seeded downtime between a modeled crash and the
/// restarted boot, in nanoseconds: one second to one minute, uniform.
pub const RESTART_DOWNTIME_NANOS: RangeInclusive<u64> = 1_000_000_000..=60_000_000_000;

impl Incarnation {
    /// The incarnation number: 0 for the first boot.
    pub const fn id(self) -> u64 {
        match self {
            Self::First => 0,
            Self::Restarted { id, .. } => id.get(),
        }
    }

    /// The root every seeded stream of this incarnation derives from: the
    /// run's seed for the first boot, and the run's seed keyed by the
    /// incarnation number for a restart ([`incarnation_seed`]).
    pub fn stream_root(self, run_seed: u64) -> u64 {
        incarnation_seed(run_seed, self.id())
    }

    /// The realtime epoch this incarnation's clock boots on. The first boot
    /// keeps the run's epoch. A restart boots at its predecessor's last
    /// realtime plus a downtime drawn from its own stream root, so its
    /// realtime starts strictly after every unperturbed realtime read of the
    /// crashed incarnation, while its monotonic clock starts again at
    /// `boot_origin_nanos`.
    pub(crate) fn realtime_epoch(
        self,
        run_epoch_nanos: u64,
        boot_origin_nanos: u64,
        stream_root: u64,
        clock_installed: bool,
    ) -> Result<u64, RuntimeError> {
        let Self::Restarted {
            previous_realtime_nanos,
            ..
        } = self
        else {
            return Ok(run_epoch_nanos);
        };
        if clock_installed {
            return Err(RuntimeError::Config(
                "a restarted incarnation carries realtime forward from the crashed one, which an \
                 installed clock cannot do; let the runtime build the clock"
                    .into(),
            ));
        }
        let shortest = *RESTART_DOWNTIME_NANOS.start();
        let span = RESTART_DOWNTIME_NANOS.end() - shortest + 1;
        let draw =
            SplitMix64::new(domain_seed(stream_root, fault_domain::RESTART_DOWNTIME)).next_u64();
        let downtime = shortest + draw % span;
        previous_realtime_nanos
            .checked_add(downtime)
            .and_then(|boot_realtime| boot_realtime.checked_sub(boot_origin_nanos))
            .ok_or_else(|| {
                RuntimeError::Config(format!(
                    "the crashed incarnation's realtime {previous_realtime_nanos} ns plus a \
                     {downtime} ns downtime gives no realtime epoch for a clock booting at \
                     uptime {boot_origin_nanos} ns"
                ))
            })
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
        let state = self.crash_restart_state();
        // The crash, carried out or not, ends this incarnation's process
        // without finalization, so its recording (which ends with the
        // triggering operation) is written now: the supervisor joins it with
        // the next incarnation's, or keeps it as the failed crash's replay.
        self.flush_recording();
        let (snapshot, realtime_nanos) = state.map_err(|reason| RuntimeError::FsCrashFailed {
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
            realtime_nanos,
            snapshot,
        })))
    }

    /// What the next incarnation boots from: the recovered durable image, and
    /// the realtime this incarnation's clock has reached. That realtime, read
    /// unrecorded like a filesystem timestamp, is at or after every
    /// unperturbed realtime read and every timestamp this clock stamped.
    fn crash_restart_state(&mut self) -> Result<(FsSnapshot, u64), String> {
        let snapshot = self.crash_restart_snapshot()?;
        let realtime_nanos = self.fs_time_unrecorded().map_err(|error| {
            format!("failed to read the crashed incarnation's realtime: {error}")
        })?;
        Ok((snapshot, realtime_nanos))
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
