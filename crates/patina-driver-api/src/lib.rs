//! Narrow data-plane interfaces implemented by deterministic drivers.
//!
//! Concrete drivers keep rich builders in their own crates. These traits only
//! describe effects required by the runtime boundary.

use patina_dst_abi::{
    ClockKind, Datagram, EffectError, Fd, FsDirectoryEntry, FsMetadata, OpenFlags, SeekWhence,
    SendReport, ShutdownHow, SocketId, TaskId, TcpAccepted,
};

pub type DriverResult<T> = Result<T, EffectError>;

pub trait FsDriver: Send {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd>;
    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>>;
    fn write(&mut self, fd: Fd, bytes: &[u8]) -> DriverResult<usize>;
    /// Positional read: read up to `max_len` bytes starting at `offset` WITHOUT
    /// disturbing the shared file cursor (the `pread`/`read_at` contract).
    ///
    /// The default composes `seek`(save)/`seek`(offset)/`read`/`seek`(restore)
    /// and runs entirely inside this one driver call. The runtime never
    /// interleaves a scheduler switch inside a single driver invocation, so the
    /// save/seek/read/restore sequence is atomic with respect to the
    /// deterministic scheduler even when multiple guest threads share the fd --
    /// which is exactly why positional I/O must reach the driver as ONE
    /// operation rather than being emulated with separate seek/read calls on the
    /// caller side. Drivers with native positional reads may override this.
    fn read_at(&mut self, fd: Fd, offset: u64, max_len: usize) -> DriverResult<Vec<u8>> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.read(fd, max_len);
        // Restore the cursor regardless of the read outcome, so a positional
        // read is a no-op on the file offset; the read result takes precedence.
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|bytes| restored.map(|_| bytes))
    }
    /// Positional write: write `bytes` starting at `offset` WITHOUT disturbing
    /// the shared file cursor (the `pwrite`/`write_at` contract). Atomic with
    /// respect to the scheduler for the same reason as [`FsDriver::read_at`];
    /// crash-consistency wrappers see the underlying `write`, so a positional
    /// write is journaled and crash-losable exactly like a cursor write.
    fn write_at(&mut self, fd: Fd, offset: u64, bytes: &[u8]) -> DriverResult<usize> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.write(fd, bytes);
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|written| restored.map(|_| written))
    }
    fn close(&mut self, fd: Fd) -> DriverResult<()>;
    fn seek(&mut self, _fd: Fd, _offset: i64, _whence: SeekWhence) -> DriverResult<u64> {
        Err(unsupported_filesystem_operation("seek"))
    }
    fn dup(&mut self, _fd: Fd) -> DriverResult<Fd> {
        Err(unsupported_filesystem_operation("dup"))
    }
    fn metadata(&mut self, _path: &str) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("metadata"))
    }
    fn fd_metadata(&mut self, _fd: Fd) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("descriptor metadata"))
    }
    fn create_directory(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("create directory"))
    }
    fn remove_file(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove file"))
    }
    fn sync(&mut self, _fd: Fd) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("sync"))
    }
    fn set_len(&mut self, _fd: Fd, _len: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set length"))
    }
    fn set_times(
        &mut self,
        _fd: Fd,
        _atime_nanos: Option<u64>,
        _mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times"))
    }
    fn set_times_by_path(
        &mut self,
        _path: &str,
        _atime_nanos: Option<u64>,
        _mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times by path"))
    }
    fn read_directory(&mut self, _path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        Err(unsupported_filesystem_operation("read directory"))
    }
    fn remove_directory(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove directory"))
    }
    fn rename(&mut self, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("rename"))
    }
    fn link(&mut self, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("link"))
    }
    fn symlink(&mut self, _target: &str, _link_path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("symlink"))
    }
    fn read_link(&mut self, _path: &str) -> DriverResult<String> {
        Err(unsupported_filesystem_operation("read link"))
    }
    fn crash(&mut self) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("crash"))
    }

    /// End-of-run filesystem fault-injection summary for the default-on vacuity
    /// diagnostic. A wrapper that models fs faults reports its counts; the
    /// default (a driver with no fault model) reports `None` and is never
    /// diagnosed as vacuous. Wrappers forward it so an inner fault-modeling
    /// driver remains visible.
    fn fault_report(&self) -> Option<FsFaultReport> {
        None
    }
}

fn unsupported_filesystem_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_dst_abi::ErrorCode::Denied,
        format!("filesystem driver does not support {operation}"),
    )
}

/// Resolve a guest path to the absolute, symlink-free *spelling* the
/// deterministic filesystems key their entries under: reject a relative or
/// NUL-bearing path, drop `.` and empty (`//`) components, and resolve `..`
/// lexically against the accumulated prefix (a `..` at the root stays at the
/// root, as it does on a real filesystem). This performs no I/O -- it is the
/// pure lexical half of `realpath`, shared here so the C-ABI shim and any driver
/// produce ONE canonical spelling rather than each risking a subtly different
/// one. The output is idempotent under the drivers' own entry normalization, so
/// a canonicalized path fed straight back into a driver operation names the
/// identical entry.
pub fn canonicalize_path(path: &str) -> DriverResult<String> {
    if !path.starts_with('/') {
        return Err(EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            format!("virtual filesystem path must be absolute: {path:?}"),
        ));
    }
    if path.contains('\0') {
        return Err(EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            "virtual filesystem path contains NUL",
        ));
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value),
        }
    }
    Ok(format!("/{}", components.join("/")))
}

/// The address a wildcard-bound listener would be keyed under for traffic dialed
/// at `address`, or `None` when the rule cannot apply.
///
/// The ONE wildcard-bind routing rule, shared by every layer that resolves a
/// virtual address to a socket: a listener bound to `0.0.0.0:PORT` receives
/// traffic addressed to any `IP:PORT` that has no exact-match binding. Exact
/// match always wins; this function only supplies the fallback key.
///
/// It lives here, beside [`canonicalize_path`], because two layers resolve
/// addresses independently — the network driver routes the packet and the native
/// shim wakes the receiving task from its own address-keyed table. A rule
/// implemented in only one of them delivers a datagram that nothing ever wakes
/// for, so both call this.
///
/// Addresses are opaque strings in the virtual network (tests and the explicit
/// API bind bare labels like `"server"`), so anything that is not a dotted-quad
/// `IP:PORT` yields `None` and keeps exact-match-only behavior. An address that
/// IS already the wildcard yields `None` too: it is its own exact match, and
/// returning it would invite a lookup loop.
pub fn wildcard_bind_key(address: &str) -> Option<String> {
    let (host, port) = address.rsplit_once(':')?;
    if host == WILDCARD_HOST {
        return None;
    }
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return None;
    }
    port.parse::<u16>().ok()?;
    Some(format!("{WILDCARD_HOST}:{port}"))
}

/// The dotted-quad spelling of `INADDR_ANY`, the host half of a wildcard bind.
pub const WILDCARD_HOST: &str = "0.0.0.0";

/// Convert an unsigned byte offset to the signed offset `seek` takes, rejecting
/// values past `i64::MAX` (unreachable for the in-memory filesystems but kept
/// sound rather than silently wrapping).
fn checked_offset(offset: u64) -> DriverResult<i64> {
    i64::try_from(offset).map_err(|_| {
        EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            format!("positional offset {offset} exceeds the addressable range"),
        )
    })
}

/// Level-triggered readiness of a virtual socket at a given virtual instant,
/// for a readiness reactor (`kqueue`/`kevent`). `read_eof`/`write_eof` carry the
/// `EV_EOF` conditions: the peer will send no more (`read_eof`) or will read no
/// more / the stream is torn down (`write_eof`). A pure inspection — no bytes
/// are consumed and no state changes — so a reactor may call it repeatedly while
/// gathering events without perturbing the run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetReadiness {
    pub readable: bool,
    pub writable: bool,
    pub read_eof: bool,
    pub write_eof: bool,
}

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
    /// The short-I/O knob was live over enough truncatable read/write operations
    /// that [`vacuity_is_diagnosable`] holds, so zero shorts is anomalous.
    pub short_vacuity_diagnosable: bool,
    /// Read/write operations whose result was actually bound by an injected
    /// truncation. A truncation below a length the operation never reached
    /// anyway (a short read of a buffer the file never filled) is NOT counted:
    /// it perturbed nothing the guest could observe.
    pub shorts_applied: u64,
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

fn unsupported_network_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_dst_abi::ErrorCode::Denied,
        format!("network driver does not support {operation}"),
    )
}

pub trait ClockDriver: Send {
    fn now(&mut self, clock: ClockKind) -> DriverResult<u64>;
    fn sleep_until(&mut self, clock: ClockKind, deadline_nanos: u64) -> DriverResult<()>;
}

pub trait EntropyDriver: Send {
    fn fill(&mut self, destination: &mut [u8]) -> DriverResult<()>;
}

/// End-of-run summary of an exploration scheduling policy (PCT priority-change
/// points, starvation intervals). Populated only during a live selection run
/// (`next()` decisions), so it reflects the record/seeded schedule; on replay the
/// recorded task selections are consumed through `select()` and `next()` is not
/// called, so a replay reports the inert default. The runtime folds these counts
/// into the machine-readable `PATINA_SCHEDULE_POLICY` diagnostic line and the
/// bug-depth annotation of a failing schedule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulePolicyReport {
    /// Whether the PCT (Probabilistic Concurrency Testing) policy was active.
    pub pct: bool,
    /// Configured PCT bug-depth `d` (number of priority bands; `d-1` change
    /// points).
    pub pct_depth: u32,
    /// Configured number of priority-change points (`d-1`).
    pub pct_change_points: u32,
    /// Number of priority-change points that were actually reached during the
    /// schedule (a live change point demoted a running task). This is the PCT
    /// contribution to the bug-depth estimate of a schedule.
    pub pct_change_points_hit: u32,
    /// Whether the starvation-interval policy was active.
    pub starvation: bool,
    /// Number of scheduling decisions where the starvation policy actually
    /// excluded at least one runnable task from selection.
    pub starve_events: u64,
    /// Number of scheduling decisions where honoring the starvation set would
    /// have left no schedulable task (every runnable task starved). The policy
    /// falls back to the full runnable set at those steps (liveness safety) and
    /// counts them here so a vacuous starvation configuration is diagnosed.
    pub starve_vacuous: u64,
    /// Total scheduling decisions (`next()` calls) observed under the policy.
    pub decisions: u64,
}

impl SchedulePolicyReport {
    /// Whether any exploration policy was active this run.
    pub fn is_active(&self) -> bool {
        self.pct || self.starvation
    }

    /// The bug-depth estimate for the realized schedule: the number of ordering
    /// decisions (priority-change points hit plus starvation exclusions) that
    /// were live in the schedule. A failure found under a schedule with a higher
    /// estimate exercised a deeper interleaving.
    pub fn bug_depth(&self) -> u64 {
        u64::from(self.pct_change_points_hit) + self.starve_events
    }
}

pub trait SchedulerDriver: Send {
    fn spawn(&mut self, label: &str) -> DriverResult<TaskId>;
    fn yield_task(&mut self, task: TaskId) -> DriverResult<()>;
    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()>;
    fn wake(&mut self, task: TaskId) -> DriverResult<()>;
    fn complete(&mut self, task: TaskId) -> DriverResult<()>;
    fn next(&mut self) -> DriverResult<Option<TaskId>>;
    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()>;
    /// End-of-run exploration-policy summary. The default scheduler policy
    /// (uniform random selection) reports `None`; PCT and starvation policies
    /// report their live counts. Read once at run finalization.
    fn policy_report(&self) -> Option<SchedulePolicyReport> {
        None
    }

    /// Whether the most recent scheduling decision deliberately withheld a
    /// runnable task from selection because of an active exploration policy — a
    /// starvation interval excluding a runnable task, or PCT priority ordering
    /// preferring a higher-priority task over an available strictly-lower-priority
    /// one. The liveness watchdog consults this so a *policy-explained*
    /// non-progress window (a deliberate starvation interval or a PCT priority
    /// deferral) is never misreported as a liveness violation: only genuine
    /// no-progress beyond policy-explained deferral trips the watchdog. The
    /// default (uniform-random) policy never defers, so it reports `false` and
    /// the watchdog is fully live for a plain run. Reflects the last `next()`
    /// decision; on replay `next()` is not called, so it reports `false`.
    fn liveness_deferring(&self) -> bool {
        false
    }
}

pub trait NetDriver: Send {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId>;
    fn validate_send(&self, socket: SocketId, to: &str) -> DriverResult<()>;
    fn send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<SendReport>;
    fn recv(&mut self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>>;
    /// The earliest future delivery time (`delivery_nanos > now_nanos`) among
    /// packets addressed to `socket`, or `None` when none are pending. A
    /// blocking receive uses this to park until virtual time reaches a
    /// deliverable packet under non-zero link latency. The default is
    /// conservative (`None`); drivers that model delivery timing override it,
    /// and wrappers must forward it so wrapped latency stays visible.
    fn next_delivery(&self, _socket: SocketId, _now_nanos: u64) -> DriverResult<Option<u64>> {
        Ok(None)
    }

    /// Bind a TCP listener at `address` with a pending-connection budget of
    /// `backlog` (values below 1 are treated as 1).
    fn tcp_listen(&mut self, _address: &str, _backlog: usize) -> DriverResult<SocketId> {
        Err(unsupported_network_operation("tcp listen"))
    }

    /// Pop the oldest established, not-yet-accepted connection, or `None` when
    /// nothing is pending at `now_nanos`.
    fn tcp_accept(
        &mut self,
        _listener: SocketId,
        _now_nanos: u64,
    ) -> DriverResult<Option<TcpAccepted>> {
        Err(unsupported_network_operation("tcp accept"))
    }

    /// Establish a connection from local `address` to the listener at `to`.
    /// Zero-latency drivers establish synchronously; `now_nanos` is the
    /// virtual send time of the handshake so a latency wrapper can delay it
    /// in a future revision.
    fn tcp_connect(
        &mut self,
        _address: &str,
        _to: &str,
        _now_nanos: u64,
    ) -> DriverResult<SocketId> {
        Err(unsupported_network_operation("tcp connect"))
    }

    /// Append up to `bytes.len()` bytes to the peer's receive buffer with
    /// delivery time `delivery_nanos` (callers pass "now"; wrappers may add
    /// latency). Returns the number of bytes accepted — `0` means the peer's
    /// buffer is full (would-block), never an error.
    fn tcp_send(
        &mut self,
        _socket: SocketId,
        _bytes: &[u8],
        _delivery_nanos: u64,
    ) -> DriverResult<usize> {
        Err(unsupported_network_operation("tcp send"))
    }

    /// Take up to `max_len` deliverable bytes. `None` = no data deliverable at
    /// `now_nanos` and the peer may still write (would-block); `Some(empty)` =
    /// end of stream; `Some(bytes)` = data (may cross segment boundaries).
    fn tcp_recv(
        &mut self,
        _socket: SocketId,
        _max_len: usize,
        _now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        Err(unsupported_network_operation("tcp recv"))
    }

    /// Close one or both directions of an established stream.
    fn tcp_shutdown(&mut self, _socket: SocketId, _how: ShutdownHow) -> DriverResult<()> {
        Err(unsupported_network_operation("tcp shutdown"))
    }

    /// Level-triggered readiness of `socket` at `now_nanos`, for a `kqueue`/
    /// `kevent` reactor. The conditions mirror the blocking `recv`/`send` paths
    /// exactly: `readable` iff a receive would return data or end-of-stream,
    /// `writable` iff a send would make progress or fail closed rather than
    /// would-block. A pure `&self` inspection that consumes nothing, so a
    /// reactor gathers events without recording a boundary observation. The
    /// default reports "not ready"; drivers that model byte buffers override it
    /// and wrappers forward it so wrapped latency stays visible.
    fn readiness(&self, _socket: SocketId, _now_nanos: u64) -> DriverResult<NetReadiness> {
        Ok(NetReadiness::default())
    }

    /// End-of-run network fault-injection summary for the default-on vacuity
    /// diagnostic. A driver that models faults reports its counts; the default
    /// (a driver with no fault model) reports `None` and is never diagnosed as
    /// vacuous. A pure `&self` inspection read once at run finalization.
    /// Wrappers forward it so a wrapped fault-modeling driver stays visible.
    fn fault_report(&self) -> Option<NetFaultReport> {
        None
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()>;
}
