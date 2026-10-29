//! Crash points: where a supervised run crashes, and what it hands over.
//!
//! A crash is a fault like any other: each crash point — a completed
//! operation with an effect a crash could cut short
//! ([`patina_dst_abi::Operation::is_crash_point`]) — draws from a seeded
//! stream whether the run crashes there (`--crash-permille`), and the first
//! hit crashes. A replay never draws: where its recording crashed is the
//! trace's own structure, the last operation of incarnation 0's segment, so
//! deleting other operations from a trace never moves the crash.

use crate::recording::Execution;
use crate::{Context, InjectedCrash, RuntimeError};
use patina_dst_abi::{CrashKind, Fd, Outcome};

use patina_dst_fs_mem::FsSnapshot;
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain, incarnation_seed};
use patina_dst_trace::HandoffConsumedState;
use std::num::NonZeroU64;
use std::ops::RangeInclusive;

/// Which boot of a run a [`Context`] is. Every run boots once; a native run
/// that crashes boots again after its crash, from the image the crash left,
/// as a restarted process or a rebooted machine would.
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

/// An embedder's channel for telling its supervisor that the run crashed.
/// [`Context::crash_after`] calls it before anything that carries the crash
/// out (the export, the recording flush), so a supervisor learns of the
/// attempt even when one of those kills the process.
pub trait CrashAttemptSink: Send {
    fn attempting(&mut self);

    /// The writes the embedder's page cache holds that no write-back has
    /// handed the filesystem yet, as `(descriptor, offset, bytes)`: a
    /// [`CrashKind::Process`] crash keeps them, as the kernel's page cache
    /// outlives the process.
    fn unwritten_stores(&mut self) -> Result<Vec<(Fd, u64, Vec<u8>)>, String> {
        Ok(Vec::new())
    }
}

/// Where an incarnation crashes, and what the crash takes down.
pub(crate) struct CrashArm {
    kind: CrashKind,
    trigger: CrashTrigger,
}

enum CrashTrigger {
    /// A live run: each completed crash point crashes with `permille`/1000
    /// odds, drawn from the run's crash-point stream.
    Draw { permille: u16, rng: SplitMix64 },
    /// A replay of the segment a recorded crash ended: the crash follows its
    /// last operation, whatever operation that is.
    SegmentEnd,
}

impl CrashArm {
    /// The crash a supervised first incarnation is armed with: a live run
    /// draws at each crash point, a replay crashes where its segment ends.
    /// `None` for a run with no crash to take: unsupervised, a restarted
    /// incarnation (a run crashes at most once), or a live run whose crash
    /// rate is zero, as swarm leaves a run that deselected the crash class.
    pub(crate) fn arm(
        supervised: bool,
        first: bool,
        replay: bool,
        permille: u16,
        kind: CrashKind,
        stream_root: u64,
    ) -> Option<Self> {
        if !supervised || !first {
            return None;
        }
        let trigger = if replay {
            CrashTrigger::SegmentEnd
        } else if permille == 0 {
            return None;
        } else {
            CrashTrigger::Draw {
                permille,
                rng: SplitMix64::new(domain_seed(stream_root, fault_domain::CRASH_POINT)),
            }
        };
        Some(Self { kind, trigger })
    }
}

impl Context {
    pub fn fs_crash(&mut self) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(patina_dst_abi::Operation::FsCrash, |filesystem| {
            filesystem.crash()
        })
    }

    /// Crash after the operation that just completed with `outcome`, when this
    /// incarnation's [`CrashArm`] says so: a live run at a successful crash
    /// point (`crash_point`) whose draw hits, a replay after the last
    /// operation of its segment. The triggering guest call never returns:
    /// the crash is an internal incarnation-termination control carrying the
    /// image the next incarnation boots from, for the native
    /// shim/supervisor handoff, or [`RuntimeError::CrashFailed`] when the
    /// crash cannot be carried out. Manual [`Context::fs_crash`] keeps its
    /// explicit rollback-in-place semantics and does not route here.
    pub(super) fn crash_after(
        &mut self,
        crash_point: bool,
        outcome: &Outcome,
    ) -> Result<(), RuntimeError> {
        let segment_ended = match &self.execution {
            Execution::Replay(replayer) => replayer.consumed() as usize == replayer.total(),
            _ => false,
        };
        let Some(arm) = self.crash.as_mut() else {
            return Ok(());
        };
        let fires = match &mut arm.trigger {
            CrashTrigger::Draw { permille, rng } => {
                crash_point
                    && !matches!(outcome, Outcome::Error(_))
                    && rng.next_u64() % 1000 < u64::from(*permille)
            }
            CrashTrigger::SegmentEnd => segment_ended,
        };
        if !fires {
            return Ok(());
        }
        let kind = arm.kind;
        // The crash is spent whether or not it can be carried out: a failed
        // one ends the run as `CrashFailed`.
        self.crash = None;
        if let Some(sink) = self.crash_attempt_sink.as_mut() {
            sink.attempting();
        }
        let state = self.crash_restart_state(kind);
        // The crash, carried out or not, ends this incarnation's process
        // without finalization, so its recording (which ends with the
        // triggering operation) is written now: the supervisor joins it with
        // the next incarnation's, or keeps it as the failed crash's replay.
        self.flush_recording();
        let (snapshot, realtime_nanos) =
            state.map_err(|reason| RuntimeError::CrashFailed { reason })?;
        Err(RuntimeError::InjectedCrash(Box::new(InjectedCrash {
            compatibility_fingerprint: self.execution_fingerprint().to_string(),
            from_incarnation: self.incarnation,
            to_incarnation: self.incarnation.saturating_add(1),
            kind,
            consumed: HandoffConsumedState {
                operations: self.steps,
                lifecycle_order: self.steps,
            },
            realtime_nanos,
            snapshot,
        })))
    }

    /// What the next incarnation boots from: the image a crash of `kind`
    /// leaves, and the realtime this incarnation's clock has reached. That
    /// realtime, read unrecorded like a filesystem timestamp, is at or after
    /// every unperturbed realtime read and every timestamp this clock stamped.
    fn crash_restart_state(&mut self, kind: CrashKind) -> Result<(FsSnapshot, u64), String> {
        let snapshot = self.crash_restart_snapshot(kind)?;
        let realtime_nanos = self.fs_time_unrecorded().map_err(|error| {
            format!("failed to read the crashed incarnation's realtime: {error}")
        })?;
        Ok((snapshot, realtime_nanos))
    }

    /// Export the image a crash of `kind` leaves. The error is a bare reason,
    /// not an [`EffectError`], so no caller can hand it to the guest as an
    /// errno: [`Context::crash_after`] makes it the run's
    /// [`RuntimeError::CrashFailed`].
    fn crash_restart_snapshot(&mut self, kind: CrashKind) -> Result<FsSnapshot, String> {
        if kind == CrashKind::Process {
            self.write_back_unwritten_stores()?;
        }
        let bytes = self
            .filesystem
            .crash_and_export_restart_snapshot(kind)
            .map_err(|error| error.to_string())?;
        FsSnapshot::decode(&bytes).map_err(|error| {
            format!("filesystem driver exported an invalid crash-restart snapshot: {error}")
        })
    }
}

impl Context {
    /// Hand the filesystem what the embedder's page cache holds unwritten,
    /// before a process crash exports the image. Unrecorded: the stores are a
    /// function of the guest's run, so a replay holds the same ones.
    fn write_back_unwritten_stores(&mut self) -> Result<(), String> {
        let Some(sink) = self.crash_attempt_sink.as_mut() else {
            return Ok(());
        };
        let stores = sink.unwritten_stores()?;
        if stores.is_empty() {
            return Ok(());
        }
        let clock = self.fs_clock().map_err(|error| error.to_string())?;
        let filesystem = self.filesystem.as_mut();
        for (fd, offset, bytes) in stores {
            filesystem
                .write_back_at(clock, fd, offset, &bytes)
                .map_err(|error| format!("failed to write back the page cache: {error}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
