//! Diagnostic report configuration and end-of-run report formatting.

use crate::buggify::BuggifyDiagnostics;
use crate::liveness::LivenessWatchdog;
use crate::schedule::ScheduleDiagnostics;
// A report cannot be declared without its control-plane spelling. The same
// rows generate the enum, ordered iteration, and public constants.
macro_rules! report_registry {
    ($($(#[$doc:meta])* $variant:ident => $env:ident = $name:literal;)+) => {
        $( $(#[$doc])* pub const $env: &str = $name; )+

        /// End-of-run diagnostic reports. Suppression affects presentation only,
        /// never fingerprints, recorded effects, or replay reconciliation.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Report { $( $(#[$doc])* $variant, )+ }

        impl Report {
            /// Every report, in declaration order. All families forward these
            /// same rows, so a report cannot skip their control-plane plumbing.
            pub const ALL: [Self; [$(stringify!($variant)),+].len()] = [$(Self::$variant),+];

            /// Joined spellings for the CLI environment registry.
            pub const ENV_NAMES: &'static str = {
                const JOINED: &str = concat!($($name, " / ",)+);
                JOINED.split_at(JOINED.len() - 3).0
            };

            /// The control-plane variable that suppresses this report.
            #[must_use]
            pub const fn env(self) -> &'static str {
                match self { $(Self::$variant => $env,)+ }
            }
        }
    };
}

report_registry! {
    /// Suppress the default-on end-of-run schedule diagnostic when set to a false-y
    /// value (`0`, `off`, `false`, `no`). The diagnostic is on by default.
    Schedule => ENV_SCHEDULE_REPORT = "PATINA_SCHEDULE_REPORT";
    /// Suppress the default-on end-of-run exploration-policy diagnostic
    /// (`PATINA_SCHEDULE_POLICY`) when set to a false-y value. On by default when a
    /// policy is active.
    SchedulePolicy => ENV_SCHEDULE_POLICY_REPORT = "PATINA_SCHEDULE_POLICY_REPORT";
    /// Suppress the default-on end-of-run swarm-selection diagnostic
    /// (`PATINA_SWARM_REPORT`) when set to a false-y value. On by default for every
    /// run that applied swarm selection.
    Swarm => ENV_SWARM_REPORT = "PATINA_SWARM_REPORT";
    /// Suppress the default-on end-of-run liveness-watchdog diagnostic
    /// (`PATINA_LIVENESS_REPORT`) when set to a false-y value.
    Liveness => ENV_LIVENESS_REPORT = "PATINA_LIVENESS_REPORT";
    /// Suppress the default-on end-of-run cooperative-SUT diagnostic when set to a
    /// false-y value (`0`, `off`, `false`, `no`). On by default when buggify is
    /// enabled.
    Sdk => ENV_SDK_REPORT = "PATINA_SDK_REPORT";
    /// Suppress the default-on end-of-run filesystem fault-injection diagnostic
    /// when set to a false-y value (`0`, `off`, `false`, `no`). The diagnostic is on
    /// by default when fs fault knobs had eligible traffic.
    FsFault => ENV_FS_FAULT_REPORT = "PATINA_FS_FAULT_REPORT";
    /// Suppress the default-on end-of-run DNS fault-injection diagnostic when set to
    /// a false-y value (`0`, `off`, `false`, `no`).
    DnsFault => ENV_DNS_FAULT_REPORT = "PATINA_DNS_FAULT_REPORT";
    /// Suppress the default-on end-of-run network fault-injection diagnostic when
    /// set to a false-y value (`0`, `off`, `false`, `no`). The diagnostic is on by
    /// default: it fires a loud warning when the net fault knobs could perturb
    /// delivery and fault-eligible traffic occurred, yet ZERO fault effects landed
    /// (the silent-inertness class — historically the inert TCP stream path).
    NetFault => ENV_NET_FAULT_REPORT = "PATINA_NET_FAULT_REPORT";
    /// Suppress the default-on end-of-run entropy fault-injection diagnostic when set
    /// to a false-y value (`0`, `off`, `false`, `no`).
    EntropyFault => ENV_ENTROPY_FAULT_REPORT = "PATINA_ENTROPY_FAULT_REPORT";
    /// Suppress the default-on end-of-run clock (realtime-epoch jump)
    /// fault-injection diagnostic when set to a false-y value (`0`, `off`, `false`,
    /// `no`).
    ClockFault => ENV_CLOCK_FAULT_REPORT = "PATINA_CLOCK_FAULT_REPORT";
    /// Suppress the default-on end-of-run custom-operation fault-injection
    /// diagnostic when set to a false-y value (`0`, `off`, `false`, `no`).
    CustomOpFault => ENV_CUSTOMOP_FAULT_REPORT = "PATINA_CUSTOMOP_FAULT_REPORT";
    /// Suppress the default-on native yield-point coverage diagnostic when set to a
    /// false-y value (`0`, `off`, `false`, `no`). The diagnostic is emitted by the
    /// native shim at the same finalization point as the runtime reports.
    Coverage => ENV_COVERAGE_REPORT = "PATINA_COVERAGE_REPORT";
    /// Suppress the default-on WASI depth diagnostic when set to a false-y value
    /// (`0`, `off`, `false`, `no`). WASI guests execute in-process, so the line is
    /// emitted by `cargo-patina` rather than by a shim, but the gate spelling matches
    /// [`ENV_COVERAGE_REPORT`] so both diagnostics are silenced the same way.
    Depth => ENV_DEPTH_REPORT = "PATINA_DEPTH_REPORT";
}

/// Which end-of-run diagnostic reports this run prints. Every report is on by
/// default; a false-y value (`0`, `off`, `false`, `no`) for a [`Report`]'s
/// variable turns that one off.
///
/// Resolved ONCE, at configuration time, from whatever control plane the family
/// supplies — the native shim's pre-scrub environment snapshot, the process
/// environment for the cargo family, the supervisor's environment for WASI.
/// Nothing consults the process environment at finalization: on native the
/// public `getenv` is interposed and the deterministic environment is long gone
/// by then, so a late read returns NULL and every knob reads as absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportConfig {
    enabled: [bool; Report::ALL.len()],
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            enabled: [true; Report::ALL.len()],
        }
    }
}

impl ReportConfig {
    /// Whether `report` prints.
    #[must_use]
    pub const fn enabled(&self, report: Report) -> bool {
        self.enabled[report as usize]
    }

    /// Turn one report on or off explicitly (the harness overlay path).
    pub const fn set(&mut self, report: Report, enabled: bool) {
        self.enabled[report as usize] = enabled;
    }

    /// Resolve every report knob through one control-plane accessor. An absent
    /// variable leaves the current setting; a false-y value suppresses; anything
    /// else (including an empty value) enables, so a pinned `=1` re-enables a
    /// report an ambient `=0` had suppressed.
    #[must_use]
    pub fn applied<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        for report in Report::ALL {
            if let Some(value) = get(report.env()) {
                self.set(report, !is_false_y(value.trim()));
            }
        }
        self
    }
}

/// The false-y spellings a default-ON knob accepts. Deliberately excludes the
/// empty string: `PATINA_SDK_REPORT=` asks for the default, which is on. The
/// default-OFF enable knobs ([`ENV_SWARM`], [`ENV_BUGGIFY_AFTER_SETUP`]) use the
/// opposite convention — a bare, valueless variable means off — so they keep
/// their own predicate rather than sharing this one.
fn is_false_y(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "off" | "false" | "no"
    )
}

/// Emit the default-on swarm-selection diagnostic for a run that applied swarm
/// fault-class masking. One machine-readable line, in the same shape as
/// `PATINA_SDK_REPORT`: the candidate/selected/deselected counts followed by one
/// `class=<token>|<0|1>` row per candidate in table order.
///
/// This is the uniform surface for every swarm-maskable class, so a consumer can
/// tell "this generation ran without fs error injection because swarm dropped it"
/// from "fs error injection was never requested" without re-deriving the mask.
/// A `vacuous=1` run (no candidate at all) also gets a loud warning, in the same
/// shape as the fs/net inert-knob warnings: `--swarm` with nothing to select from
/// explores exactly what a run without `--swarm` explores, so a clean result must
/// not read as swarm coverage. Suppressed by a false-y [`ENV_SWARM_REPORT`].
pub(super) fn emit_swarm_report(
    reports: ReportConfig,
    record: &patina_dst_trace::SwarmConfigRecord,
) {
    if !reports.enabled(Report::Swarm) {
        return;
    }
    eprintln!("{}", swarm_report_line(record));
    if record.is_vacuous() {
        eprintln!("{SWARM_VACUOUS_WARNING}");
    }
}

/// The `PATINA_SWARM_REPORT` line for a swarm draw. Pure, so the exact wire shape
/// the campaign classifier reads is unit-testable without capturing stderr.
pub(super) fn swarm_report_line(record: &patina_dst_trace::SwarmConfigRecord) -> String {
    let selected = record.selected_classes.len();
    let mut line = format!(
        "PATINA_SWARM_REPORT candidates={} selected={} deselected={} vacuous={}",
        record.candidate_classes.len(),
        selected,
        record.candidate_classes.len() - selected,
        u8::from(record.is_vacuous()),
    );
    for class in &record.candidate_classes {
        line.push_str(&format!(
            " class={class}|{}",
            u8::from(!record.deselected(class)),
        ));
    }
    line
}

/// The inert-`--swarm` warning. A constant so the runtime and the tests that pin
/// it (and the campaign/sweep classifiers that key on its leading phrase) cannot
/// drift apart.
const SWARM_VACUOUS_WARNING: &str = "PATINA WARNING: swarm fault-class selection inert — \
--swarm was requested but NO swarm-maskable fault class was enabled, so the draw had nothing to \
keep or drop and this run explored exactly the configuration it would have explored without \
--swarm. A clean result here does NOT mean fault-class subsets were tested. Enable the fault or \
buggify knobs the swarm should choose among, or drop --swarm.";

/// Emit the default-on liveness-watchdog diagnostic at a clean finish. Proves the
/// watchdog was armed and did not fire (a fired watchdog aborts before finish), so
/// "watchdog on, run OK" is demonstrably non-vacuous. Suppressed by a false-y
/// `PATINA_LIVENESS_REPORT`.
pub(super) fn emit_liveness_report(reports: ReportConfig, watchdog: &LivenessWatchdog) {
    if !reports.enabled(Report::Liveness) {
        return;
    }
    let mut line = format!(
        "PATINA_LIVENESS_REPORT armed={} fired={}",
        watchdog.arms.len(),
        u8::from(watchdog.fired),
    );
    for arm in &watchdog.arms {
        line.push_str(&format!(
            " {}=budget{}/armed{}/stall{}",
            arm.kind.as_str(),
            arm.budget_nanos,
            u8::from(arm.armed),
            arm.stall_ops,
        ));
    }
    eprintln!("{line}");
}

/// Emit the default-on schedule-exploration diagnostic to stderr for a
/// multithreaded run. Single-task runs (no concurrency to explore) stay silent.
/// The machine-readable `PATINA_SCHEDULE_REPORT` line lets a campaign tell a
/// genuinely-explored "all clean" from a vacuous one; a loud warning fires when
/// a spawned worker ran start-to-finish with zero scheduling boundaries.
pub(super) fn emit_schedule_report(reports: ReportConfig, diag: &ScheduleDiagnostics) {
    if !diag.had_concurrency() {
        return;
    }
    if !reports.enabled(Report::Schedule) {
        return;
    }
    let mut line = format!(
        "PATINA_SCHEDULE_REPORT tasks_spawned={} max_concurrent={} total_boundaries={} vacuous_threads={}",
        diag.tasks_spawned,
        diag.max_concurrent,
        diag.total_boundaries,
        diag.vacuous.len(),
    );
    for stat in &diag.tasks {
        line.push_str(&format!(
            " task{}={}y+{}p/life={}/cause={}",
            stat.task.0,
            stat.yields,
            stat.parks,
            stat.lifetime,
            stat.cause.as_str()
        ));
    }
    eprintln!("{line}");
    if !diag.vacuous.is_empty() {
        let ids = diag
            .vacuous
            .iter()
            .map(|task| task.0.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "PATINA WARNING: vacuous schedule exploration — {} spawned thread(s) (task id {ids}) ran \
to completion with no more scheduling boundaries than thread spawn/join alone incurs. Any loop in \
their body was atomics-only and thus invisible to the scheduler, so their internal interleavings \
are UNREACHABLE at any seed and a clean result here does NOT mean the concurrency was tested. \
Rebuild with `cargo patina build --coverage-points=N` (a scheduling point every N basic blocks, \
so the cost is 1/N of the dense mode) or `--yield-points` (a scheduling point at EVERY basic block) \
to make atomics-only race windows schedulable.",
            diag.vacuous.len(),
        );
    }
}

/// Emit the default-on DNS fault-injection diagnostic. Silent when no eligible
/// resolution happened at all — a workload that never looks up a defined name
/// gave the knobs no opportunity, which is not the same as a knob being inert.
/// Suppressed by a false-y [`ENV_DNS_FAULT_REPORT`].
pub(super) fn emit_dns_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::DnsFaultReport,
) {
    if report.resolutions == 0 {
        return;
    }
    if !reports.enabled(Report::DnsFault) {
        return;
    }
    eprintln!(
        "PATINA_DNS_FAULT_REPORT resolutions={} fail_vacuity_diagnosable={} failures_injected={} \
latency_vacuity_diagnosable={} latency_applied={} vacuous={}",
        report.resolutions,
        u8::from(report.fail_vacuity_diagnosable),
        report.failures_injected,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: DNS fault knobs inert — {} fault-eligible name resolution(s) \
occurred, enough that the configured rate should have fired an enabled DNS fault class several \
times over, yet it applied ZERO effects. A clean result here does NOT mean name-resolution \
failure was tested. Verify the guest resolves names the host table DEFINES — a lookup of an \
undefined name is NXDOMAIN by semantics and is never fault-eligible.",
            report.resolutions,
        );
    }
}

/// Emit the default-on entropy fault-injection diagnostic. Silent when the knob
/// was never live at all. Suppressed by a false-y [`ENV_ENTROPY_FAULT_REPORT`].
pub(super) fn emit_entropy_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::EntropyFaultReport,
) {
    if report.requests == 0 {
        return;
    }
    if !reports.enabled(Report::EntropyFault) {
        return;
    }
    eprintln!(
        "PATINA_ENTROPY_FAULT_REPORT requests={} fail_vacuity_diagnosable={} failures_injected={} vacuous={}",
        report.requests,
        u8::from(report.fail_vacuity_diagnosable),
        report.failures_injected,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: entropy fault knobs inert — {} fault-eligible entropy request(s) \
occurred, enough that the configured rate should have fired several times over, yet it applied \
ZERO effects.",
            report.requests,
        );
    }
}

/// Emit the default-on custom-operation fault-injection diagnostic. Silent when
/// the knob was never live. Suppressed by a false-y
/// [`ENV_CUSTOMOP_FAULT_REPORT`].
///
/// Unlike the other planes there is no zero-opportunity early return: a run that
/// armed this knob and reached NO fault-eligible custom op is precisely the
/// coverage lie the report exists to name.
pub(super) fn emit_customop_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::CustomOpFaultReport,
) {
    if !reports.enabled(Report::CustomOpFault) {
        return;
    }
    eprintln!(
        "PATINA_CUSTOMOP_FAULT_REPORT eligible_ops={} fail_vacuity_diagnosable={} \
faults_injected={} vacuous={}",
        report.eligible_ops,
        u8::from(report.fail_vacuity_diagnosable),
        report.faults_injected,
        u8::from(report.is_vacuous()),
    );
    if report.eligible_ops == 0 {
        eprintln!(
            "PATINA WARNING: custom-op fault knob inert — the run armed \
--custom-op-fail-permille and executed ZERO fault-eligible custom operations, so nothing could \
have been failed. A clean result here does NOT mean custom-op failure was tested. Verify the \
guest declares a failure shape on the operations it wraps (`custom_op_faultable`), and that the \
exercised path reaches them.",
        );
    } else if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: custom-op fault knob inert — {} fault-eligible custom operation(s) \
occurred, enough that the configured rate should have fired several times over, yet it applied \
ZERO faults.",
            report.eligible_ops,
        );
    }
}

/// Emit the default-on clock (epoch-jump) fault-injection diagnostic. Silent
/// when the knob was never live at all. Suppressed by a false-y
/// [`ENV_CLOCK_FAULT_REPORT`].
pub(super) fn emit_clock_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::ClockFaultReport,
) {
    if report.reads == 0 {
        return;
    }
    if !reports.enabled(Report::ClockFault) {
        return;
    }
    eprintln!(
        "PATINA_CLOCK_FAULT_REPORT reads={} jump_vacuity_diagnosable={} jumps_applied={} vacuous={}",
        report.reads,
        u8::from(report.jump_vacuity_diagnosable),
        report.jumps_applied,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: clock fault knobs inert — {} fault-eligible realtime-epoch read(s) \
occurred, enough that the configured jump range should have applied a non-zero offset several \
times over, yet it applied ZERO effects.",
            report.reads,
        );
    }
}

/// Emit the default-on filesystem fault-injection diagnostic to stderr. A driver
/// with no fault model reports `None` and stays silent, as does a live knob that
/// saw no fault-eligible traffic at all. Otherwise the machine-readable
/// `PATINA_FS_FAULT_REPORT` line lets a campaign tell a genuinely-perturbed run
/// from an inert one, and a loud warning fires when a class that was expected to
/// fire repeatedly (see `vacuity_is_diagnosable`) applied zero effects.
/// Suppressed by a false-y [`ENV_FS_FAULT_REPORT`].
pub(super) fn emit_fs_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::FsFaultReport,
) {
    if report.eligible_ops == 0 {
        return;
    }
    if !reports.enabled(Report::FsFault) {
        return;
    }
    eprintln!("{}", fs_fault_report_line(report));
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: filesystem fault knobs inert — {} fault-eligible filesystem op(s) \
occurred, enough that the configured rate should have fired an enabled fs fault class several \
times over, yet it applied ZERO effects. A clean result here does NOT mean every configured \
filesystem fault was tested. Verify the fs fault knobs reach the I/O path the workload uses — a \
short-I/O knob applies nothing to a guest whose reads never fill their buffer.",
            report.eligible_ops,
        );
    }
}

/// The `PATINA_FS_FAULT_REPORT` line for a filesystem fault summary. Pure, so the
/// exact wire shape the campaign classifier and the testbed scripts read is
/// unit-testable without capturing stderr.
///
/// Each rate class contributes its scalar count and, immediately after it, the
/// per-operation-kind breakdown of where those effects landed
/// (`errors_by_op=open:1,read:2`, or `-` when none did). The breakdown answers
/// the question the scalar cannot: a knob that fired plenty but only ever on
/// `open` left every post-open failure path untested, and that reads as healthy
/// coverage without it. `vacuous=` stays last, and every field stays a
/// whitespace-delimited `k=v` token, so the campaign classifier and the testbed
/// greps that read this line are unaffected.
pub(super) fn fs_fault_report_line(report: &patina_dst_driver_api::FsFaultReport) -> String {
    format!(
        "PATINA_FS_FAULT_REPORT eligible_ops={} error_vacuity_diagnosable={} errors_injected={} \
errors_by_op={} short_vacuity_diagnosable={} shorts_applied={} shorts_by_op={} \
latency_vacuity_diagnosable={} latency_applied={} vacuous={}",
        report.eligible_ops,
        u8::from(report.error_vacuity_diagnosable),
        report.errors_injected,
        report.errors_by_op,
        u8::from(report.short_vacuity_diagnosable),
        report.shorts_applied,
        report.shorts_by_op,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.is_vacuous()),
    )
}

/// Emit the default-on network fault-injection diagnostic to stderr. A driver
/// with no fault model reports `None` and stays silent; a driver whose knobs
/// cannot perturb anything (`could_apply == false`) is also silent. When the
/// knobs could perturb delivery, the machine-readable `PATINA_NET_FAULT_REPORT`
/// line lets a campaign tell a genuinely-perturbed run from an inert one, and a
/// loud warning fires when fault-eligible traffic occurred yet ZERO fault
/// effects landed — the silent-inertness class (historically: the SimNet TCP
/// stream path ignoring the datagram-only fault knobs). Suppressed by a false-y
/// [`ENV_NET_FAULT_REPORT`].
pub(super) fn emit_net_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::NetFaultReport,
) {
    if !report.had_opportunities() {
        return;
    }
    if !reports.enabled(Report::NetFault) {
        return;
    }
    eprintln!(
        "PATINA_NET_FAULT_REPORT send_ops={} drop_vacuity_diagnosable={} drops_applied={} \
jitter_vacuity_diagnosable={} jitter_applied={} latency_vacuity_diagnosable={} latency_applied={} \
duplicate_vacuity_diagnosable={} duplicates_applied={} connect_ops={} \
connect_refuse_vacuity_diagnosable={} connects_refused={} stream_ops={} \
reset_vacuity_diagnosable={} resets_injected={} partition_vacuity_diagnosable={} \
partition_blocks={} vacuous={}",
        report.send_ops,
        u8::from(report.drop_vacuity_diagnosable),
        report.drops_applied,
        u8::from(report.jitter_vacuity_diagnosable),
        report.jitter_applied,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.duplicate_vacuity_diagnosable),
        report.duplicates_applied,
        report.connect_ops,
        u8::from(report.connect_refuse_vacuity_diagnosable),
        report.connects_refused,
        report.stream_ops,
        u8::from(report.reset_vacuity_diagnosable),
        report.resets_injected,
        u8::from(report.partition_vacuity_diagnosable),
        report.partition_blocks,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: net fault knobs inert — fault-eligible network traffic occurred \
({} send(s), {} connect(s), {} stream op(s)), enough that an enabled net fault class should have \
fired several times over, yet that class applied ZERO effects. The configured network fault is \
SILENTLY INERT on the code path this run exercised (historically the SimNet TCP stream path \
ignored the datagram-only fault knobs), so a clean result here does NOT mean the faults were \
tested. Verify the knob reaches the path the workload uses — and, for a partition, that it names \
addresses this run actually connects between.",
            report.send_ops, report.connect_ops, report.stream_ops,
        );
    }
}

/// Emit the machine-readable `PATINA_SCHEDULE_POLICY` line for a run that used an
/// exploration scheduling policy (PCT / starvation). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a sweep parses it to annotate a found failure with a
/// bug-depth estimate and to detect a vacuous starvation configuration. Suppressed
/// by a false-y [`ENV_SCHEDULE_POLICY_REPORT`].
pub(super) fn emit_schedule_policy_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::SchedulePolicyReport,
) {
    if !report.is_active() {
        return;
    }
    if !reports.enabled(Report::SchedulePolicy) {
        return;
    }
    eprintln!(
        "PATINA_SCHEDULE_POLICY pct={} pct_depth={} pct_change_points={} pct_change_points_hit={} \
starvation={} starve_events={} starve_vacuous={} decisions={} bug_depth={}",
        u8::from(report.pct),
        report.pct_depth,
        report.pct_change_points,
        report.pct_change_points_hit,
        u8::from(report.starvation),
        report.starve_events,
        report.starve_vacuous,
        report.decisions,
        report.bug_depth(),
    );
    if report.starve_vacuous > 0 {
        eprintln!(
            "PATINA WARNING: vacuous starvation configuration — {} scheduling decision(s) would have \
starved every runnable task and were forced to schedule anyway to preserve liveness. A starvation \
configuration that routinely starves the only runnable task is testing nothing; narrow the starved \
subset or the interval window.",
            report.starve_vacuous,
        );
    }
}

/// Emit the machine-readable `PATINA_SDK_REPORT` line for a run that registered
/// any cooperative-SUT sites (or enabled buggify). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a campaign parses it to accumulate per-site coverage
/// across generations. Suppressed by a false-y [`ENV_SDK_REPORT`]. Link-time
/// declarations use `declared_site=<label>|<kind>|@<file:line>` and do not imply
/// evaluation. Per-evaluated-site token is
/// `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->|@<file:line>`.
pub(super) fn emit_sdk_report(reports: ReportConfig, diag: &BuggifyDiagnostics) {
    if !diag.enabled && diag.sites_registered == 0 && diag.declared_sites.is_empty() {
        return;
    }
    if !reports.enabled(Report::Sdk) {
        return;
    }
    let mut line = format!(
        "PATINA_SDK_REPORT enabled={} swarm_deselected={} fire_permille={} activation_permille={} \
cutoff_nanos={} cutoff_reached={} sites_declared={} sites_registered={} sites_activated={} \
total_firings={} cutoff_suppressed={} after_setup={} setup_complete={}",
        u8::from(diag.enabled),
        u8::from(diag.swarm_deselected),
        diag.fire_permille,
        diag.activation_permille,
        diag.cutoff_nanos,
        u8::from(diag.cutoff_reached),
        diag.declared_sites.len(),
        diag.sites_registered,
        diag.sites_activated,
        diag.total_firings,
        diag.cutoff_suppressed,
        u8::from(diag.after_setup),
        u8::from(diag.setup_complete),
    );
    for site in &diag.declared_sites {
        line.push_str(&format!(
            " declared_site={}|{}|@{}",
            site.label,
            site.kind.as_str(),
            site.site,
        ));
    }
    for site in &diag.sites {
        let knob = site
            .knob
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        line.push_str(&format!(
            " site={}|{}|a{}|e{}|f{}|r{}|s{}|v{}|k{}|@{}",
            site.label,
            site.kind.as_str(),
            u8::from(site.active),
            site.evals,
            site.fires,
            u8::from(site.reachable),
            u8::from(site.sometimes_satisfied),
            u8::from(site.always_violated),
            knob,
            site.site,
        ));
    }
    eprintln!("{line}");
}

#[cfg(test)]
mod tests {
    use crate::Context;
    use crate::config::RuntimeConfig;
    use crate::reports::{Report, ReportConfig, fs_fault_report_line};
    use patina_dst_abi::{FsClock, OpenFlags};

    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn fs_latency_vacuity_is_rate_aware_and_bites_on_an_inert_knob() {
        use patina_dst_driver_api::FsFaultReport;

        // FIRES: a knob that delays every eligible op, over twenty of them,
        // that applied ZERO delays. That is the shape a filesystem path
        // bypassing the Context latency choke point produces — the class this
        // detector exists for — and it must be reported as vacuous.
        assert!(patina_dst_driver_api::range_vacuity_is_diagnosable(
            20,
            (1_000, 1_000)
        ));
        let bypassed = FsFaultReport {
            eligible_ops: 20,
            latency_vacuity_diagnosable: true,
            latency_applied: 0,
            ..FsFaultReport::default()
        };
        assert!(bypassed.is_vacuous());

        // DOES NOT FIRE below the expected-firings floor: four eligible ops are
        // too few to call zero delays anomalous.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            4,
            (1_000, 1_000)
        ));

        // DOES NOT FIRE for a range whose every draw is zero: that knob is inert
        // by construction, not inert on the code path.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            1_000_000,
            (0, 0)
        ));

        // Rate-aware in between: `0..9` delays nine draws in ten, so it takes six
        // eligible ops to expect five delays.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            5,
            (0, 9)
        ));
        assert!(patina_dst_driver_api::range_vacuity_is_diagnosable(
            6,
            (0, 9)
        ));
    }

    /// The report must name WHICH operation kinds absorbed the injected effects.
    /// A bare `errors_injected=7` cannot distinguish a run that failed seven
    /// `open`s from one that failed seven `sync`s, and those are different
    /// coverage: a durability bug reachable only through a failing `sync` stays
    /// untested while the report reads identically. Same for short I/O — shorts
    /// that all landed on reads say nothing about the write path.
    #[test]
    fn fs_fault_report_line_attributes_effects_to_operation_kinds() {
        use patina_dst_driver_api::FsDriver;
        use patina_dst_fs_mem::MemFs;
        use patina_dst_wrapper_fault::FaultFs;
        let readable_write = OpenFlags {
            read: true,
            ..OpenFlags::create_truncate_write()
        };
        let mut inner = MemFs::new();
        let fd = inner.open(FsClock::EPOCH, "/file", readable_write).unwrap();
        inner.write(FsClock::EPOCH, fd, b"abcdef").unwrap();

        // Every eligible operation fails, so the breakdown is exactly the
        // operations performed, in the report's fixed order rather than the
        // call order.
        let mut fs = FaultFs::new(inner, 1).error_permille(1000);
        assert!(fs.sync(fd).is_err());
        assert!(fs.metadata("/file").is_err());
        assert!(fs.open(FsClock::EPOCH, "/other", readable_write).is_err());
        assert!(fs.read(FsClock::EPOCH, fd, 4).is_err());
        assert!(fs.read(FsClock::EPOCH, fd, 4).is_err());
        let report = fs.fault_report().unwrap();
        assert_eq!(report.errors_injected, 5);
        let line = fs_fault_report_line(&report);
        assert!(
            line.contains(" errors_by_op=open:1,read:2,metadata:1,sync:1 "),
            "error breakdown must name the op kinds in the fixed report order:\n{line}"
        );
        assert!(
            line.contains(" shorts_by_op=- "),
            "an unfired class renders as the empty-breakdown sentinel:\n{line}"
        );

        // The short class attributes independently: a truncation counts against
        // the op kind whose result it bound.
        let mut inner = MemFs::new();
        let fd = inner.open(FsClock::EPOCH, "/file", readable_write).unwrap();
        inner.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        assert!(fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap() < 6);
        assert!(fs.read_at(FsClock::EPOCH, fd, 0, 6).unwrap().len() < 6);
        let report = fs.fault_report().unwrap();
        assert_eq!(report.shorts_applied, 2);
        let line = fs_fault_report_line(&report);
        assert!(
            line.contains(" shorts_by_op=write:1,read_at:1 "),
            "short breakdown must name the op kinds it bound:\n{line}"
        );
        assert!(
            line.contains(" errors_by_op=- "),
            "the error class stayed off and must not borrow the short class's ops:\n{line}"
        );
    }

    /// Absent knobs leave every report on; only the documented false-y spellings
    /// suppress; an explicit truthy value re-enables what an ambient `0` had
    /// suppressed (the pin a campaign puts on its children).
    #[test]
    fn report_config_parses_the_documented_spellings() {
        assert!(ReportConfig::default().enabled(Report::Schedule));
        for value in ["0", "off", "FALSE", " no "] {
            let config = ReportConfig::default()
                .applied(|name| (name == Report::Schedule.env()).then(|| value.to_string()));
            assert!(!config.enabled(Report::Schedule), "{value:?} must suppress");
            assert!(
                config.enabled(Report::Swarm),
                "{value:?} must not touch a sibling report"
            );
        }
        for value in ["1", "", "yes", "on"] {
            let config = ReportConfig::default()
                .applied(|_| Some("0".to_string()))
                .applied(|name| (name == Report::Sdk.env()).then(|| value.to_string()));
            assert!(config.enabled(Report::Sdk), "{value:?} must re-enable");
            assert!(!config.enabled(Report::Swarm));
        }
    }

    // Report suppression is presentation, not run semantics: two recordings of the
    // same workload — one with every report on, one with every report off — must
    // produce byte-identical traces. That property is what keeps the knobs out of
    // the fingerprint and out of everything replay reconciles, so a quietly
    // recorded trace still replays against a loud one and back.
    #[test]
    fn report_suppression_does_not_reach_a_recorded_byte() {
        let directory = tempdir().unwrap();
        let record = |name: &str, reports: ReportConfig| {
            let trace = directory.path().join(name);
            let config = RuntimeConfig::record(11, &trace, "reports-v1").with_reports(reports);
            let mut context = Context::from_config(config).unwrap();
            context.write_file("/data", b"payload").unwrap();
            assert_eq!(context.read_file("/data").unwrap(), b"payload");
            context.finish().unwrap();
            fs::read(&trace).unwrap()
        };

        let mut silent = ReportConfig::default();
        for report in Report::ALL {
            silent.set(report, false);
        }
        assert_eq!(
            record("loud.patina", ReportConfig::default()),
            record("quiet.patina", silent),
            "a suppression preference must not change a recorded byte"
        );
    }
}
