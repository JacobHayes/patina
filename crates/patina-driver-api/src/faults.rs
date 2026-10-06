//! Fault-injection reports, operation counters, and vacuity thresholds.

/// Expected firings a rate-based fault class must have accumulated before a
/// zero-fire run is diagnosed as vacuous.
///
/// A rate knob that draws few times, or draws at a low rate, produces zero fires
/// as its ORDINARY sampling outcome, not as the silent-inertness signature the
/// diagnostic exists to catch. Diagnosing those runs turns the warning — and the
/// campaign class built on it — into noise that fires on healthy runs. Because
/// `P(zero fires) <= e^-expected` for any per-op rate, requiring five expected
/// firings keeps a spurious vacuity verdict under 1%.
pub const VACUITY_MIN_EXPECTED_FIRES: u64 = 5;

/// Whether a zero-fire outcome is anomalous enough to diagnose as vacuous, given
/// how many firing opportunities a rate knob actually saw at what rate. This is
/// the precondition behind every `*_vacuity_diagnosable` flag in
/// [`FsFaultReport`].
pub fn vacuity_is_diagnosable(opportunities: u64, permille: u16) -> bool {
    opportunities.saturating_mul(u64::from(permille)) >= VACUITY_MIN_EXPECTED_FIRES * 1000
}

/// Whether a zero-application verdict on an inclusive `MIN..MAX` nanosecond
/// range knob is anomalous rather than ordinary, judged the same rate-aware way
/// as [`vacuity_is_diagnosable`] judges a per-mille knob: the knob's chance of
/// drawing a NON-ZERO delay, over the eligible operations it actually saw, must
/// have expected at least [`VACUITY_MIN_EXPECTED_FIRES`] delays. A `0..0` range
/// (and any range whose draws are all zero) is inert by construction, not
/// vacuous, so it never diagnoses; a range with `MIN >= 1` delays every eligible
/// operation and reaches the threshold as soon as there are five of them.
///
/// Domain-neutral on purpose: every range knob shares this rule — filesystem
/// latency, DNS latency and network delivery jitter are judged here rather than
/// each domain growing its own copy of the arithmetic.
pub fn range_vacuity_is_diagnosable(opportunities: u64, (min, max): (u64, u64)) -> bool {
    if max == 0 {
        return false;
    }
    let span = max - min + 1;
    let nonzero = max - min.max(1) + 1;
    let permille = u16::try_from(nonzero.saturating_mul(1000) / span).unwrap_or(1000);
    vacuity_is_diagnosable(opportunities, permille)
}

/// Whether a zero-application verdict on a symmetric `[-hi, hi]` epoch-jump
/// range is anomalous rather than ordinary, judged the same rate-aware way as
/// [`range_vacuity_is_diagnosable`]: of the `2*hi + 1` values the draw can
/// land on, exactly one (zero) applies nothing, so the knob's chance of a
/// NON-ZERO draw over the eligible reads it actually saw must have expected
/// at least [`VACUITY_MIN_EXPECTED_FIRES`] applied jumps. `hi == 0` never
/// diagnoses: the knob draws nothing but zero, so it is inert by
/// construction, not vacuous. `u128` throughout so a `hi` near `u64::MAX`
/// cannot overflow the span computation.
pub fn epoch_jump_vacuity_is_diagnosable(reads: u64, hi: u64) -> bool {
    if hi == 0 {
        return false;
    }
    let span = 2u128 * u128::from(hi) + 1;
    let nonzero = 2u128 * u128::from(hi);
    let permille = u16::try_from(nonzero.saturating_mul(1000) / span).unwrap_or(1000);
    vacuity_is_diagnosable(reads, permille)
}

/// A fault-eligible filesystem operation, as the fault reports attribute effects
/// to it. It lives here rather than in the injecting wrapper because the report
/// crosses the driver boundary: the wrapper counts by kind and the runtime
/// renders by kind, and one enum keeps the two from drifting into different
/// spellings of the same operation.
///
/// Declaration order IS the report order — the breakdown must be a deterministic
/// function of the counts, never of a map's iteration order — so entries may be
/// added but existing ones should not be reshuffled without expecting the
/// rendered line to change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FsFaultOpKind {
    Open,
    Read,
    Write,
    ReadAt,
    WriteAt,
    Metadata,
    FdMetadata,
    CreateDirectory,
    MakeNode,
    RemoveFile,
    Sync,
    SetLen,
    SetTimes,
    SetTimesByPath,
    ReadDirectory,
    RemoveDirectory,
    Rename,
    Link,
    Symlink,
    ReadLink,
}

impl FsFaultOpKind {
    /// Every kind, in report order. The one place the set is enumerated: the
    /// counter array is sized from it and the breakdown is rendered by walking
    /// it, so a kind added to the enum reaches the report by adding one row
    /// here rather than by editing three parallel lists.
    pub const ALL: [FsFaultOpKind; 20] = [
        FsFaultOpKind::Open,
        FsFaultOpKind::Read,
        FsFaultOpKind::Write,
        FsFaultOpKind::ReadAt,
        FsFaultOpKind::WriteAt,
        FsFaultOpKind::Metadata,
        FsFaultOpKind::FdMetadata,
        FsFaultOpKind::CreateDirectory,
        FsFaultOpKind::MakeNode,
        FsFaultOpKind::RemoveFile,
        FsFaultOpKind::Sync,
        FsFaultOpKind::SetLen,
        FsFaultOpKind::SetTimes,
        FsFaultOpKind::SetTimesByPath,
        FsFaultOpKind::ReadDirectory,
        FsFaultOpKind::RemoveDirectory,
        FsFaultOpKind::Rename,
        FsFaultOpKind::Link,
        FsFaultOpKind::Symlink,
        FsFaultOpKind::ReadLink,
    ];

    /// The token the report and the injected-error message spell the operation
    /// with. Matches the `FsDriver` method name, so a breakdown row names the
    /// driver surface a reader can go look at.
    pub const fn name(self) -> &'static str {
        match self {
            FsFaultOpKind::Open => "open",
            FsFaultOpKind::Read => "read",
            FsFaultOpKind::Write => "write",
            FsFaultOpKind::ReadAt => "read_at",
            FsFaultOpKind::WriteAt => "write_at",
            FsFaultOpKind::Metadata => "metadata",
            FsFaultOpKind::FdMetadata => "fd_metadata",
            FsFaultOpKind::CreateDirectory => "create_directory",
            FsFaultOpKind::MakeNode => "make_node",
            FsFaultOpKind::RemoveFile => "remove_file",
            FsFaultOpKind::Sync => "sync",
            FsFaultOpKind::SetLen => "set_len",
            FsFaultOpKind::SetTimes => "set_times",
            FsFaultOpKind::SetTimesByPath => "set_times_by_path",
            FsFaultOpKind::ReadDirectory => "read_directory",
            FsFaultOpKind::RemoveDirectory => "remove_directory",
            FsFaultOpKind::Rename => "rename",
            FsFaultOpKind::Link => "link",
            FsFaultOpKind::Symlink => "symlink",
            FsFaultOpKind::ReadLink => "read_link",
        }
    }
}

/// Per-operation-kind counters for one fault class, dense over
/// [`FsFaultOpKind::ALL`] so accumulation and rendering are both
/// order-deterministic — the reason this is an array rather than a map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsOpCounts([u64; FsFaultOpKind::ALL.len()]);

/// The value an empty breakdown renders as. A sentinel rather than an empty
/// string keeps every field on the report line a non-empty `k=v` token, so a
/// whitespace-splitting reader cannot lose the key.
pub const EMPTY_OP_BREAKDOWN: &str = "-";

impl FsOpCounts {
    /// Attribute one effect of this class to `kind`.
    pub fn record(&mut self, kind: FsFaultOpKind) {
        self.0[kind as usize] += 1;
    }

    /// Effects attributed to `kind`.
    pub fn get(&self, kind: FsFaultOpKind) -> u64 {
        self.0[kind as usize]
    }

    /// Effects attributed across all kinds. Must equal the class's scalar
    /// counter on the same report — a breakdown that does not add up is a
    /// mis-attribution, not a rounding difference.
    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }

    /// Fold another report's counters in, per kind. Used when a fault-modeling
    /// driver is nested inside another and both attribute effects.
    pub fn merge(&mut self, other: &Self) {
        for (mine, theirs) in self.0.iter_mut().zip(other.0.iter()) {
            *mine += *theirs;
        }
    }

    /// The kinds that absorbed at least one effect, paired with their counts, in
    /// [`FsFaultOpKind::ALL`] order.
    pub fn nonzero(&self) -> impl Iterator<Item = (FsFaultOpKind, u64)> + '_ {
        FsFaultOpKind::ALL
            .into_iter()
            .filter_map(|kind| Some((kind, self.get(kind))).filter(|(_, count)| *count > 0))
    }
}

/// `open:3,read:12` in report order, or [`EMPTY_OP_BREAKDOWN`] when no effect
/// landed. This is the wire shape the fault report lines embed.
impl core::fmt::Display for FsOpCounts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut wrote = false;
        for (kind, count) in self.nonzero() {
            if wrote {
                f.write_str(",")?;
            }
            write!(f, "{}:{count}", kind.name())?;
            wrote = true;
        }
        if !wrote {
            f.write_str(EMPTY_OP_BREAKDOWN)?;
        }
        Ok(())
    }
}

/// End-of-run summary of filesystem fault-injection activity, for the
/// default-on vacuity diagnostic. It is deliberately per class: a run with both
/// error and short-I/O knobs enabled must not hide one inert class behind the
/// other class firing. The runtime folds this into `PATINA_FS_FAULT_REPORT` and
/// warns when a class that should have fired repeatedly applied zero effects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsFaultReport {
    /// Fault-eligible filesystem operations observed (all operations except the
    /// pure bookkeeping/administrative `close`, `dup`, `seek`, and `crash`).
    pub eligible_ops: u64,
    /// The error-injection knob was live over enough eligible operations that
    /// [`vacuity_is_diagnosable`] holds, so zero injected errors is anomalous.
    pub error_vacuity_diagnosable: bool,
    /// Operations failed by the fs-error injector.
    pub errors_injected: u64,
    /// Which operation kinds those injected errors landed on. Sums to
    /// `errors_injected`. A knob can be non-vacuous and still have exercised
    /// only one corner of the driver surface — errors that all landed on `open`
    /// leave every post-open failure path untested — and the scalar count alone
    /// cannot say so.
    pub errors_by_op: FsOpCounts,
    /// The short-I/O knob was live over enough truncatable read/write operations
    /// that [`vacuity_is_diagnosable`] holds, so zero shorts is anomalous.
    pub short_vacuity_diagnosable: bool,
    /// Read/write operations whose result was actually bound by an injected
    /// truncation. A truncation below a length the operation never reached
    /// anyway (a short read of a buffer the file never filled) is NOT counted:
    /// it perturbed nothing the guest could observe.
    pub shorts_applied: u64,
    /// Which operation kinds those applied truncations bound. Sums to
    /// `shorts_applied`, and only the four truncatable kinds (`read`, `write`,
    /// `read_at`, `write_at`) can appear. Shorts that all bound reads say
    /// nothing about the write path, which is the half a torn-record bug lives
    /// on.
    pub shorts_by_op: FsOpCounts,
    /// Reserved for the Context-side fs-latency knob; false in Wave B.
    pub latency_vacuity_diagnosable: bool,
    /// Reserved for Context-side fs latency applications; zero in Wave B.
    pub latency_applied: u64,
}

impl FsFaultReport {
    /// Whether any filesystem-fault class went vacuously inert: it was live over
    /// enough opportunities to be expected to fire repeatedly, yet applied zero
    /// effects.
    pub fn is_vacuous(&self) -> bool {
        (self.error_vacuity_diagnosable && self.errors_injected == 0)
            || (self.short_vacuity_diagnosable && self.shorts_applied == 0)
            || (self.latency_vacuity_diagnosable && self.latency_applied == 0)
    }
}

/// End-of-run summary of DNS fault-injection activity, for the default-on
/// vacuity diagnostic. Per class, exactly like [`FsFaultReport`]: a run with both
/// DNS knobs live must not hide one inert class behind the other firing.
///
/// Unlike the filesystem classes there is no driver here — resolution is a
/// `Context` operation against the run's host table — so the `Context` fills
/// every field. `resolutions` counts only FAULT-ELIGIBLE lookups: a name that is
/// not in the table is NXDOMAIN as semantics, at rate 1.0 and knob-free, and a
/// built-in (`localhost`, a numeric literal) is resolved locally. Counting those
/// would let a workload that never looks up a defined name report its DNS knobs
/// as having had opportunities they never had.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsFaultReport {
    /// Fault-eligible resolutions observed: lookups of names the host table
    /// defines.
    pub resolutions: u64,
    /// The failure knob was live over enough eligible resolutions that
    /// [`vacuity_is_diagnosable`] holds, so zero injected failures is anomalous.
    pub fail_vacuity_diagnosable: bool,
    /// Resolutions failed by the DNS fault injector.
    pub failures_injected: u64,
    /// The latency knob was live over enough eligible resolutions that
    /// [`vacuity_is_diagnosable`] holds.
    pub latency_vacuity_diagnosable: bool,
    /// Resolutions actually delayed by a non-zero seeded draw.
    pub latency_applied: u64,
}

impl DnsFaultReport {
    /// Whether any DNS-fault class went vacuously inert: live over enough
    /// opportunities to be expected to fire repeatedly, yet applied nothing.
    pub fn is_vacuous(&self) -> bool {
        (self.fail_vacuity_diagnosable && self.failures_injected == 0)
            || (self.latency_vacuity_diagnosable && self.latency_applied == 0)
    }
}

/// End-of-run summary of guest entropy-request fault-injection activity, for the
/// default-on vacuity diagnostic. A single class, unlike [`DnsFaultReport`]: the
/// entropy plane has only the one failure knob, no latency knob of its own.
///
/// Owned entirely by the `Context`: guest entropy is a single-site operation
/// (`Context::entropy_bytes`), so there is no driver to ask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntropyFaultReport {
    /// Fault-eligible entropy requests observed (every `entropy_bytes` call: the
    /// baseline nondeterminism source has no undefined-name-style exemption).
    pub requests: u64,
    /// The failure knob was live over enough eligible requests that
    /// [`vacuity_is_diagnosable`] holds, so zero injected failures is anomalous.
    pub fail_vacuity_diagnosable: bool,
    /// Requests failed by the entropy fault injector.
    pub failures_injected: u64,
}

impl EntropyFaultReport {
    /// Whether the entropy-fault class went vacuously inert: live over enough
    /// opportunities to be expected to fire repeatedly, yet applied nothing.
    pub fn is_vacuous(&self) -> bool {
        self.fail_vacuity_diagnosable && self.failures_injected == 0
    }
}

/// End-of-run summary of guest custom-operation fault-injection activity
/// (`--custom-op-fail-permille`), for the default-on vacuity diagnostic. A
/// single class, like [`EntropyFaultReport`].
///
/// Produced only when the knob is live, so every field describes an ARMED run —
/// which is what lets [`Self::is_vacuous`] judge zero opportunities harshly.
///
/// Owned entirely by the `Context`: a custom operation is announced through
/// `Context::custom_op_begin`, so there is no driver to ask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CustomOpFaultReport {
    /// Custom operations the guest declared fault-eligible and actually
    /// executed. A custom op that declares no failure shape is not counted: it
    /// is not an opportunity the knob passed up, it is an operation the guest
    /// never offered.
    pub eligible_ops: u64,
    /// The failure knob was live over enough eligible operations that
    /// [`vacuity_is_diagnosable`] holds, so zero injected failures is anomalous.
    pub fail_vacuity_diagnosable: bool,
    /// Operations failed by the custom-op fault injector.
    pub faults_injected: u64,
}

impl CustomOpFaultReport {
    /// Whether the custom-op fault class went vacuously inert.
    ///
    /// Stricter than every other plane, and deliberately: ZERO eligible
    /// operations is itself vacuous here. Elsewhere the opportunity denominator
    /// is a boundary the runtime models unconditionally — a run that did no
    /// filesystem I/O simply had no filesystem to fault — but a fault-eligible
    /// custom op exists only because the GUEST declared one. Arming this knob
    /// over a guest that declared none (or over a path that reached none) is a
    /// coverage claim with nothing behind it, and it is the exact shape a
    /// silently-inert custom-op campaign takes: green, and testing nothing.
    pub fn is_vacuous(&self) -> bool {
        self.eligible_ops == 0 || (self.fail_vacuity_diagnosable && self.faults_injected == 0)
    }
}

/// End-of-run summary of guest realtime-epoch fault-injection activity
/// (`--epoch-jump-nanos`), for the default-on vacuity diagnostic. A single
/// class, like [`EntropyFaultReport`]: the clock plane's only fault-injecting
/// knob is the epoch jump (sleep jitter has no vacuity counter of its own —
/// a delayed sleep is indistinguishable from a longer one).
///
/// Owned entirely by the `Context`: every realtime-epoch read is a single-site
/// operation (`Context::now(ClockKind::Realtime)`), so there is no driver to
/// ask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockFaultReport {
    /// Fault-eligible realtime-epoch reads observed (every `Context::now`
    /// call for `ClockKind::Realtime`, whether or not the knob was armed).
    pub reads: u64,
    /// The jump knob was live over enough eligible reads that
    /// [`epoch_jump_vacuity_is_diagnosable`] holds, so zero applied jumps is
    /// anomalous.
    pub jump_vacuity_diagnosable: bool,
    /// Reads whose returned value actually differed from the true virtual
    /// epoch. A zero draw, or a negative draw saturated away at epoch 0,
    /// applies nothing and is not counted.
    pub jumps_applied: u64,
}

impl ClockFaultReport {
    /// Whether the epoch-jump class went vacuously inert: live over enough
    /// opportunities to be expected to fire repeatedly, yet applied nothing.
    pub fn is_vacuous(&self) -> bool {
        self.jump_vacuity_diagnosable && self.jumps_applied == 0
    }
}

/// End-of-run summary of network fault-injection activity, for the default-on
/// vacuity diagnostic. Per class, exactly like [`FsFaultReport`] and
/// [`DnsFaultReport`]: a run with several network knobs live must not hide one
/// inert class behind another class firing, which is precisely what the earlier
/// merged `faults_applied` counter did — a run with drop and jitter both armed
/// reported "faults applied" from the drops alone while jitter was silently
/// inert on the exercised path.
///
/// Each class carries its own opportunity denominator: `send_ops` for the
/// per-datagram/segment knobs, `connect_ops` for connection establishment, and
/// `stream_ops` for established-stream data operations. A class is
/// `*_vacuity_diagnosable` only once its rate over the opportunities it actually
/// saw expected at least [`VACUITY_MIN_EXPECTED_FIRES`] firings, so a low rate
/// producing zero fires — its ORDINARY outcome — is never diagnosed.
///
/// The runtime folds these into the machine-readable `PATINA_NET_FAULT_REPORT`
/// line and raises a loud warning on vacuity — the analogue of the
/// vacuous-schedule diagnostic, catching the class where a fault knob is
/// silently inert on a code path (historically: TCP streams ignoring the
/// datagram-only knobs, and the TCP path ignoring the base link latency).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetFaultReport {
    /// Fault-eligible send operations observed: datagram `send`s that reached
    /// the fault-decision point plus TCP `tcp_send`s that enqueued bytes. The
    /// opportunity denominator for the drop, jitter, latency and duplication
    /// classes.
    pub send_ops: u64,
    /// The drop knob was live over enough sends to expect repeated firing.
    pub drop_vacuity_diagnosable: bool,
    /// Sends whose delivery was actually perturbed by a drop: a datagram lost,
    /// or a TCP segment delayed by a reliable-transport retransmit backoff.
    pub drops_applied: u64,
    /// The jitter knob was live over enough sends to expect repeated firing.
    pub jitter_vacuity_diagnosable: bool,
    /// Sends whose delivery time was actually pushed later by a non-zero jitter
    /// draw.
    pub jitter_applied: u64,
    /// The base link latency was set and enough sends occurred to expect it to
    /// have applied repeatedly.
    pub latency_vacuity_diagnosable: bool,
    /// Sends whose delivery time was actually pushed later by the base link
    /// latency. Zero here with the knob set is the defect-2 signature: a send
    /// path that ignores the configured latency entirely.
    pub latency_applied: u64,
    /// The duplication knob was live over enough sends to expect repeated firing.
    pub duplicate_vacuity_diagnosable: bool,
    /// Datagrams that were actually delivered twice.
    pub duplicates_applied: u64,
    /// Fault-eligible connection establishments: `tcp_connect` calls that
    /// reached the fault-decision point, i.e. that would otherwise have
    /// succeeded. A connect with no listener or a full backlog is refused by
    /// semantics and is never an opportunity.
    pub connect_ops: u64,
    /// The connect-refusal knob was live over enough connects to expect
    /// repeated firing.
    pub connect_refuse_vacuity_diagnosable: bool,
    /// Connections actually refused by the injector.
    pub connects_refused: u64,
    /// Fault-eligible established-stream data operations: sends that enqueued
    /// bytes and receives that returned data.
    pub stream_ops: u64,
    /// The reset knob was live over enough stream operations to expect repeated
    /// firing.
    pub reset_vacuity_diagnosable: bool,
    /// Streams actually torn down by an injected reset.
    pub resets_injected: u64,
    /// At least one partition was configured and enough sends/connects occurred
    /// that a partition matching real traffic should have blocked several.
    pub partition_vacuity_diagnosable: bool,
    /// Sends and connects actually blocked by a configured partition. Zero here
    /// with a partition configured is the operator-error signature: the
    /// partition names addresses this run never used, so it perturbed nothing.
    pub partition_blocks: u64,
}

impl NetFaultReport {
    /// Whether any network-fault class went vacuously inert: it was live over
    /// enough opportunities to be expected to fire repeatedly, yet applied zero
    /// effects. This is the silent-inertness bug signature, judged per class so
    /// one firing knob cannot vouch for another.
    pub fn is_vacuous(&self) -> bool {
        (self.drop_vacuity_diagnosable && self.drops_applied == 0)
            || (self.jitter_vacuity_diagnosable && self.jitter_applied == 0)
            || (self.latency_vacuity_diagnosable && self.latency_applied == 0)
            || (self.duplicate_vacuity_diagnosable && self.duplicates_applied == 0)
            || (self.connect_refuse_vacuity_diagnosable && self.connects_refused == 0)
            || (self.reset_vacuity_diagnosable && self.resets_injected == 0)
            || (self.partition_vacuity_diagnosable && self.partition_blocks == 0)
    }

    /// Whether this report describes any observed opportunity at all. A run
    /// whose network knobs never met traffic gave them no chance to fire, which
    /// is not the same as a knob being inert, so the diagnostic stays silent.
    pub fn had_opportunities(&self) -> bool {
        self.send_ops > 0 || self.connect_ops > 0 || self.stream_ops > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The breakdown's rendering is a function of the COUNTS, never of the order
    /// the effects arrived in — a report whose field text depends on arrival
    /// order would break byte-identical repeats of the same run. It also merges
    /// per kind, which is what keeps a nested fault-modeling driver's effects
    /// attributed rather than pooled.
    #[test]
    fn op_breakdown_renders_in_report_order_and_merges_per_kind() {
        assert_eq!(FsOpCounts::default().to_string(), EMPTY_OP_BREAKDOWN);
        assert_eq!(FsOpCounts::default().total(), 0);

        // Recorded out of report order; rendered in `FsFaultOpKind::ALL` order.
        let mut counts = FsOpCounts::default();
        counts.record(FsFaultOpKind::Sync);
        counts.record(FsFaultOpKind::Read);
        counts.record(FsFaultOpKind::Read);
        counts.record(FsFaultOpKind::Open);
        assert_eq!(counts.to_string(), "open:1,read:2,sync:1");
        assert_eq!(counts.total(), 4);

        // Arrival order cannot change the rendering.
        let mut reversed = FsOpCounts::default();
        reversed.record(FsFaultOpKind::Open);
        reversed.record(FsFaultOpKind::Read);
        reversed.record(FsFaultOpKind::Sync);
        reversed.record(FsFaultOpKind::Read);
        assert_eq!(reversed, counts);

        let mut nested = FsOpCounts::default();
        nested.record(FsFaultOpKind::Read);
        nested.record(FsFaultOpKind::WriteAt);
        counts.merge(&nested);
        assert_eq!(counts.to_string(), "open:1,read:3,write_at:1,sync:1");
        assert_eq!(counts.total(), 6);
        assert_eq!(counts.get(FsFaultOpKind::Read), 3);
        assert_eq!(counts.get(FsFaultOpKind::Write), 0);
    }
}
