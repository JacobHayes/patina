//! Crash points: where a supervised run crashes, and what it hands over.
//!
//! A crash is a fault like any other: each crash point — a completed
//! operation with an effect a crash could cut short
//! ([`patina_dst_abi::EffectClass::is_crash_point`]) — draws from a seeded
//! stream whether the machine goes down there (`--machine-crash-permille`),
//! else whether the process dies (`--process-crash-permille`), and the first
//! hit crashes. A replay never draws: where its recording crashed is the
//! trace's own structure, the last operation of incarnation 0's segment, so
//! deleting other operations from a trace never moves the crash.

use crate::recording::Execution;
use crate::{Context, InjectedCrash, RuntimeError};
use patina_dst_abi::{CrashKind, Fd};
use patina_dst_driver_api::{
    ClockFaultReport, DnsFaultReport, EntropyFaultReport, FsFaultOpKind, FsFaultTally, FsOpCounts,
    NetFaultTally,
};

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
pub(crate) enum CrashArm {
    /// A live run: at each completed crash point the machine goes down with
    /// `machine`/1000 odds, else the process dies with `process`/1000 odds,
    /// each drawn from the run's crash-point stream only when its rate is
    /// live. The first hit crashes.
    Draw {
        machine: u16,
        process: u16,
        rng: SplitMix64,
    },
    /// A replay of the segment a recorded crash ended: the crash, of the kind
    /// the recording's took, follows its last operation, whatever operation
    /// that is.
    SegmentEnd(CrashKind),
}

impl CrashArm {
    /// The crash a supervised first incarnation is armed with: a live run
    /// draws at each crash point, a replay crashes where its segment ends.
    /// `None` for a run with no crash to take: unsupervised, a restarted
    /// incarnation (a run crashes at most once), a live run whose crash rates
    /// are both zero, as swarm leaves a run that deselected the crash class,
    /// or a replay that was not told of a crash.
    pub(crate) fn arm(
        supervised: bool,
        first: bool,
        replay: Option<Option<CrashKind>>,
        crash: &crate::CrashFaultConfig,
        stream_root: u64,
    ) -> Option<Self> {
        if !supervised || !first {
            return None;
        }
        match replay {
            Some(kind) => kind.map(Self::SegmentEnd),
            None if crash.machine_permille == 0 && crash.process_permille == 0 => None,
            None => Some(Self::Draw {
                machine: crash.machine_permille,
                process: crash.process_permille,
                rng: SplitMix64::new(domain_seed(stream_root, fault_domain::CRASH_POINT)),
            }),
        }
    }
}

/// One seeded per-mille draw; a zero rate draws nothing, so a run with one
/// crash kind off consumes the stream exactly as if that kind did not exist.
fn hits(rng: &mut SplitMix64, permille: u16) -> bool {
    permille > 0 && rng.next_u64() % 1000 < u64::from(permille)
}

impl Context {
    pub fn fs_crash(&mut self) -> Result<(), RuntimeError> {
        let clock = self.fs_clock()?;
        self.filesystem_unit_undelayed(patina_dst_abi::Operation::FsCrash, |filesystem| {
            filesystem.crash(clock)
        })
    }

    /// Crash after the operation that just completed, when this incarnation's
    /// [`CrashArm`] says so: a live run at a crash point (`crash_point`,
    /// [`patina_dst_abi::EffectClass::is_crash_point`]) whose draw hits, a replay after the last
    /// operation of its segment. The triggering guest call never returns:
    /// the crash is an internal incarnation-termination control carrying the
    /// image the next incarnation boots from, for the native
    /// shim/supervisor handoff, or [`RuntimeError::CrashFailed`] when the
    /// crash cannot be carried out. Manual [`Context::fs_crash`] keeps its
    /// explicit rollback-in-place semantics and does not route here.
    pub(super) fn crash_after(&mut self, crash_point: bool) -> Result<(), RuntimeError> {
        let segment_ended = match &self.execution {
            Execution::Replay(replayer) => replayer.consumed() as usize == replayer.total(),
            _ => false,
        };
        let Some(arm) = self.crash.as_mut() else {
            return Ok(());
        };
        let fires = match arm {
            CrashArm::Draw { .. } if !crash_point => None,
            CrashArm::Draw {
                machine,
                process,
                rng,
            } => {
                if hits(rng, *machine) {
                    Some(CrashKind::Machine)
                } else if hits(rng, *process) {
                    Some(CrashKind::Process)
                } else {
                    None
                }
            }
            CrashArm::SegmentEnd(kind) => segment_ended.then_some(*kind),
        };
        let Some(kind) = fires else {
            return Ok(());
        };
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
            faults: self.fault_carry().encode(),
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
        let clock = self.fs_clock().map_err(|error| error.to_string())?;
        let bytes = self
            .filesystem
            .crash_and_export_restart_snapshot(clock, kind)
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

/// What a crashed incarnation's fault planes did, handed to the next
/// incarnation (through the handoff and the supervisor), which carries its
/// own counts on from it: the filesystem fault layer's tally and the
/// Context's filesystem-latency counts, the DNS, entropy and clock counts the
/// Context keeps, and the network driver's tally. Only counts travel; every
/// verdict (vacuity, missed targets) is judged afresh over the sums. Its text
/// form is a field of the handoff.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultCarry {
    fs: Option<FsFaultTally>,
    latency_eligible_ops: u64,
    latency_applied: u64,
    /// Counts only: the report's verdict flags are derived at the end.
    dns: DnsFaultReport,
    entropy: EntropyFaultReport,
    clock: ClockFaultReport,
    net: Option<NetFaultTally>,
}

/// The network tally's counts, in their text order.
fn net_words(tally: &NetFaultTally) -> [u64; 12] {
    [
        tally.send_ops,
        tally.datagram_send_ops,
        tally.delivery_ops,
        tally.drops_applied,
        tally.jitter_applied,
        tally.latency_applied,
        tally.duplicates_applied,
        tally.connect_ops,
        tally.connects_refused,
        tally.stream_ops,
        tally.resets_injected,
        tally.partition_blocks,
    ]
}

/// Comma-separated integers.
fn joined(words: &[u64]) -> String {
    words
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

impl FaultCarry {
    /// The text form: `fs=-`, or the tally's counts as comma-separated
    /// integers in a fixed order then `;landed=` and one `0`/`1` per target;
    /// then `;latency=<eligible>,<applied>`, `;dns=<resolutions>,<failures>,
    /// <delays>`, `;entropy=<requests>,<failures>`, `;clock=<reads>,<jumps>`
    /// and `;net=-` or the network tally's counts.
    pub fn encode(&self) -> String {
        let fs = match &self.fs {
            None => "-".to_owned(),
            Some(tally) => {
                let mut words = vec![tally.eligible_ops, tally.errors_injected];
                words.extend(FsFaultOpKind::ALL.map(|kind| tally.errors_by_op.get(kind)));
                words.push(tally.short_opportunities);
                words.push(tally.shorts_applied);
                words.extend(FsFaultOpKind::ALL.map(|kind| tally.shorts_by_op.get(kind)));
                let landed: String = tally
                    .targets_landed
                    .iter()
                    .map(|landed| if *landed { '1' } else { '0' })
                    .collect();
                format!("{};landed={landed}", joined(&words))
            }
        };
        let net = self
            .net
            .as_ref()
            .map_or_else(|| "-".to_owned(), |tally| joined(&net_words(tally)));
        format!(
            "fs={fs};latency={};dns={};entropy={};clock={};net={net}",
            joined(&[self.latency_eligible_ops, self.latency_applied]),
            joined(&[
                self.dns.resolutions,
                self.dns.failures_injected,
                self.dns.latency_applied
            ]),
            joined(&[self.entropy.requests, self.entropy.failures_injected]),
            joined(&[self.clock.reads, self.clock.jumps_applied]),
        )
    }

    /// Read [`FaultCarry::encode`]'s form; anything else is refused.
    pub fn decode(text: &str) -> Result<Self, String> {
        let malformed = || format!("malformed fault accounting {text:?}");
        let number = |word: &str| word.parse::<u64>().map_err(|_| malformed());
        let numbers = |words: &str, count: usize| -> Result<Vec<u64>, String> {
            let words = words
                .split(',')
                .map(number)
                .collect::<Result<Vec<_>, _>>()?;
            if words.len() == count {
                Ok(words)
            } else {
                Err(malformed())
            }
        };
        let rest = text.strip_prefix("fs=").ok_or_else(malformed)?;
        // The filesystem part holds a `;` of its own (`;landed=`), so the
        // fixed tail is split off from the right.
        let (fs, tail) = rest.rsplit_once(";latency=").ok_or_else(malformed)?;
        let mut fields = tail.split(';');
        let mut field = |key: &str| -> Result<&str, String> {
            let field = fields.next().ok_or_else(malformed)?;
            if key.is_empty() {
                return Ok(field);
            }
            field
                .strip_prefix(key)
                .and_then(|value| value.strip_prefix('='))
                .ok_or_else(malformed)
        };
        let latency = numbers(field("")?, 2)?;
        let dns = numbers(field("dns")?, 3)?;
        let entropy = numbers(field("entropy")?, 2)?;
        let clock = numbers(field("clock")?, 2)?;
        let net = match field("net")? {
            "-" => None,
            words => {
                let w = numbers(words, 12)?;
                Some(NetFaultTally {
                    send_ops: w[0],
                    datagram_send_ops: w[1],
                    delivery_ops: w[2],
                    drops_applied: w[3],
                    jitter_applied: w[4],
                    latency_applied: w[5],
                    duplicates_applied: w[6],
                    connect_ops: w[7],
                    connects_refused: w[8],
                    stream_ops: w[9],
                    resets_injected: w[10],
                    partition_blocks: w[11],
                })
            }
        };
        if fields.next().is_some() {
            return Err(malformed());
        }
        let fs = if fs == "-" {
            None
        } else {
            let (words, landed) = fs.split_once(";landed=").ok_or_else(malformed)?;
            let kinds = FsFaultOpKind::ALL.len();
            let words = numbers(words, 2 * kinds + 4)?;
            let counts = |words: &[u64]| {
                let mut counts = FsOpCounts::default();
                for (kind, count) in FsFaultOpKind::ALL.into_iter().zip(words) {
                    counts.add(kind, *count);
                }
                counts
            };
            let targets_landed = landed
                .chars()
                .map(|landed| match landed {
                    '0' => Ok(false),
                    '1' => Ok(true),
                    _ => Err(malformed()),
                })
                .collect::<Result<_, _>>()?;
            Some(FsFaultTally {
                eligible_ops: words[0],
                errors_injected: words[1],
                errors_by_op: counts(&words[2..2 + kinds]),
                short_opportunities: words[2 + kinds],
                shorts_applied: words[3 + kinds],
                shorts_by_op: counts(&words[4 + kinds..4 + 2 * kinds]),
                targets_landed,
            })
        };
        Ok(Self {
            fs,
            latency_eligible_ops: latency[0],
            latency_applied: latency[1],
            dns: DnsFaultReport {
                resolutions: dns[0],
                failures_injected: dns[1],
                latency_applied: dns[2],
                ..DnsFaultReport::default()
            },
            entropy: EntropyFaultReport {
                requests: entropy[0],
                failures_injected: entropy[1],
                ..EntropyFaultReport::default()
            },
            clock: ClockFaultReport {
                reads: clock[0],
                jumps_applied: clock[1],
                ..ClockFaultReport::default()
            },
            net,
        })
    }

    /// The fault layer's tally from the earlier incarnations.
    pub(crate) fn fs(&self) -> Option<&FsFaultTally> {
        self.fs.as_ref()
    }

    /// The Context's latency counts from the earlier incarnations: eligible
    /// operations and delays applied.
    pub(crate) fn latency(&self) -> (u64, u64) {
        (self.latency_eligible_ops, self.latency_applied)
    }

    /// The Context's DNS, entropy and clock counts from the earlier
    /// incarnations, to carry on from.
    pub(crate) fn context_reports(&self) -> (DnsFaultReport, EntropyFaultReport, ClockFaultReport) {
        (self.dns, self.entropy, self.clock)
    }

    /// The network driver's tally from the earlier incarnations.
    pub(crate) fn net(&self) -> Option<NetFaultTally> {
        self.net
    }
}

impl Context {
    /// This incarnation's fault accounting as the next one carries it on,
    /// what earlier incarnations handed this one included.
    fn fault_carry(&self) -> FaultCarry {
        FaultCarry {
            fs: self.filesystem.fault_tally(),
            latency_eligible_ops: self.fs_latency_eligible_ops,
            latency_applied: self.fs_latency_applied,
            dns: self.dns_report,
            entropy: self.entropy_report,
            clock: self.clock_report,
            net: self.network.fault_tally(),
        }
    }
}

#[cfg(test)]
mod fault_carry_tests {
    use super::*;

    #[test]
    fn a_fault_carry_round_trips_through_its_text() {
        let mut errors_by_op = FsOpCounts::default();
        errors_by_op.add(FsFaultOpKind::Open, 2);
        let mut shorts_by_op = FsOpCounts::default();
        shorts_by_op.add(FsFaultOpKind::Write, 5);
        let carry = FaultCarry {
            fs: Some(FsFaultTally {
                eligible_ops: 40,
                errors_injected: 2,
                errors_by_op,
                short_opportunities: 9,
                shorts_applied: 5,
                shorts_by_op,
                targets_landed: vec![true, false],
            }),
            latency_eligible_ops: 11,
            latency_applied: 7,
            dns: DnsFaultReport {
                resolutions: 6,
                failures_injected: 2,
                latency_applied: 3,
                ..DnsFaultReport::default()
            },
            entropy: EntropyFaultReport {
                requests: 8,
                failures_injected: 1,
                ..EntropyFaultReport::default()
            },
            clock: ClockFaultReport {
                reads: 30,
                jumps_applied: 4,
                ..ClockFaultReport::default()
            },
            net: Some(NetFaultTally {
                send_ops: 12,
                drops_applied: 3,
                partition_blocks: 1,
                ..NetFaultTally::default()
            }),
        };
        assert_eq!(FaultCarry::decode(&carry.encode()), Ok(carry.clone()));
        assert_eq!(
            FaultCarry::decode(&FaultCarry::default().encode()),
            Ok(FaultCarry::default())
        );
        // Truncated, a bad landed flag, a missing latency part, a plane
        // missing or short, a trailing field.
        let text = carry.encode();
        for bad in [
            text.replacen(",", ";", 1),
            text.replace("landed=10", "landed=12"),
            text.split(";latency=").next().unwrap().to_owned(),
            "fs=1,2;latency=0,0".to_owned(),
            text.split(";net=").next().unwrap().to_owned(),
            text.replace(";dns=6,2,3", ";dns=6,2"),
            format!("{text};extra=1"),
        ] {
            assert!(FaultCarry::decode(&bad).is_err(), "{bad}");
        }
    }
}
