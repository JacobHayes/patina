//! Diagnostic report configuration and end-of-run report formatting.

use crate::buggify::BuggifyDiagnostics;
use crate::liveness::LivenessWatchdog;
use crate::schedule::ScheduleDiagnostics;
use std::sync::OnceLock;

/// Where the runtime's own diagnostic text goes: std's stderr, unless an
/// embedder installed a writer ([`set_diagnostic_writer`]).
static DIAGNOSTIC_WRITER: OnceLock<fn(&[u8])> = OnceLock::new();

/// Send every diagnostic the runtime prints (the end-of-run reports, its
/// markers and `PATINA_INFRA` lines) through `writer` for the rest of the
/// process instead of std's stderr. The native shim installs one because std's
/// stderr is a lock the guest shares: a guest thread parked while holding it
/// would otherwise stop the run's finalization. Answers false, changing
/// nothing, when a writer is already installed.
pub fn set_diagnostic_writer(writer: fn(&[u8])) -> bool {
    DIAGNOSTIC_WRITER.set(writer).is_ok()
}

/// Write `text` through the installed diagnostic writer, else std's stderr.
pub(crate) fn write_diagnostic(text: std::fmt::Arguments<'_>) {
    match DIAGNOSTIC_WRITER.get() {
        Some(writer) => writer(std::fmt::format(text).as_bytes()),
        None => {
            let _ = std::io::Write::write_fmt(&mut std::io::stderr(), text);
        }
    }
}

/// `eprintln!` through [`write_diagnostic`].
macro_rules! diagnostic {
    ($($argument:tt)*) => {
        $crate::reports::write_diagnostic(format_args!("{}\n", format_args!($($argument)*)))
    };
}
pub(crate) use diagnostic;

/// Where the end-of-run reports and their warnings go when an embedder keeps
/// them apart from the run's result ([`set_report_writer`]).
static REPORT_WRITER: OnceLock<fn(&[u8])> = OnceLock::new();

/// Send the end-of-run reports and their warnings through `writer` instead of
/// the diagnostic writer. They describe how the run went, not what it found:
/// a verdict, a violation marker or a `PATINA_INFRA` line still goes through
/// [`set_diagnostic_writer`]'s writer beside the guest's output. Answers false,
/// changing nothing, when a writer is already installed.
pub fn set_report_writer(writer: fn(&[u8])) -> bool {
    REPORT_WRITER.set(writer).is_ok()
}

/// Write `text` through the installed report writer, else as a diagnostic.
pub(crate) fn write_report(text: std::fmt::Arguments<'_>) {
    match REPORT_WRITER.get() {
        Some(writer) => writer(std::fmt::format(text).as_bytes()),
        None => write_diagnostic(text),
    }
}

/// `eprintln!` through [`write_report`].
macro_rules! report {
    ($($argument:tt)*) => {
        $crate::reports::write_report(format_args!("{}\n", format_args!($($argument)*)))
    };
}
// The per-plane fault reports' line names, which a fault knob's metadata names.
pub(crate) const FS_FAULT_REPORT: &str = "PATINA_FS_FAULT_REPORT";
pub(crate) const DNS_FAULT_REPORT: &str = "PATINA_DNS_FAULT_REPORT";
pub(crate) const NET_FAULT_REPORT: &str = "PATINA_NET_FAULT_REPORT";
pub(crate) const ENTROPY_FAULT_REPORT: &str = "PATINA_ENTROPY_FAULT_REPORT";
pub(crate) const CLOCK_FAULT_REPORT: &str = "PATINA_CLOCK_FAULT_REPORT";

/// Emit the default-on swarm-selection diagnostic for a run that applied swarm
/// fault-class masking. One line, in the same shape as
/// `PATINA_SDK_REPORT`: the candidate/selected/deselected counts followed by one
/// `class=<token>|<0|1>` row per candidate in table order.
///
/// This is the uniform surface for every swarm-maskable class, so a consumer can
/// tell "this generation ran without fs error injection because swarm dropped it"
/// from "fs error injection was never requested" without re-deriving the mask.
/// A `vacuous=1` run (no candidate at all) also gets a loud warning, in the same
/// shape as the fs/net inert-knob warnings: `--swarm` with nothing to select from
/// explores exactly what a run without `--swarm` explores, so a clean result must
/// not read as swarm coverage.
pub(super) fn emit_swarm_report(record: &patina_dst_trace::SwarmConfigRecord) {
    report!("{}", swarm_report_line(record));
    if record.is_vacuous() {
        report!("{SWARM_VACUOUS_WARNING}");
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
/// "watchdog on, run OK" is demonstrably non-vacuous.
pub(super) fn emit_liveness_report(watchdog: &LivenessWatchdog) {
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
    report!("{line}");
}

/// Emit the default-on schedule-exploration diagnostic to stderr for a
/// multithreaded run. Single-task runs (no concurrency to explore) stay silent.
/// The `PATINA_SCHEDULE_REPORT` line lets a reader tell a
/// genuinely-explored "all clean" from a vacuous one; a loud warning fires when
/// a spawned worker ran start-to-finish with zero scheduling boundaries.
pub(super) fn emit_schedule_report(diag: &ScheduleDiagnostics) {
    if !diag.had_concurrency() {
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
    report!("{line}");
    if !diag.vacuous.is_empty() {
        let ids = diag
            .vacuous
            .iter()
            .map(|task| task.0.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        report!(
            "PATINA WARNING: vacuous schedule exploration — {} spawned thread(s) (task id {ids}) ran \
to completion with no more scheduling boundaries than thread spawn/join alone incurs. Any loop in \
their body was atomics-only and thus invisible to the scheduler, so their internal interleavings \
are UNREACHABLE at any seed and a clean result here does NOT mean the concurrency was tested. \
Build with `patina build --instrument` and run with `--yield-stride N` (a scheduling point \
every N edges a thread executes; 1 is every edge) to make atomics-only race windows schedulable.",
            diag.vacuous.len(),
        );
    }
}

/// Emit the default-on DNS fault-injection diagnostic. Silent when no eligible
/// resolution happened at all — a workload that never looks up a defined name
/// gave the knobs no opportunity, which is not the same as a knob being inert.
///
pub(super) fn emit_dns_fault_report(report: &patina_dst_driver_api::DnsFaultReport) {
    if report.resolutions == 0 {
        return;
    }
    report!(
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
        report!(
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
/// was never live or the run made no fault-eligible request, as on a platform
/// whose entropy APIs cannot fail.
pub(super) fn emit_entropy_fault_report(report: &patina_dst_driver_api::EntropyFaultReport) {
    if report.requests == 0 {
        return;
    }
    report!(
        "PATINA_ENTROPY_FAULT_REPORT requests={} fail_vacuity_diagnosable={} failures_injected={} vacuous={}",
        report.requests,
        u8::from(report.fail_vacuity_diagnosable),
        report.failures_injected,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        report!(
            "PATINA WARNING: entropy fault knobs inert — {} fault-eligible entropy request(s) \
occurred (GRND_NONBLOCK reads before the random pool was known ready), enough that the configured \
rate should have fired several times over, yet it applied ZERO effects.",
            report.requests,
        );
    }
}

/// Emit the default-on clock (epoch-jump) fault-injection diagnostic. Silent
/// when the knob was never live at all.
pub(super) fn emit_clock_fault_report(report: &patina_dst_driver_api::ClockFaultReport) {
    if report.reads == 0 {
        return;
    }
    report!(
        "PATINA_CLOCK_FAULT_REPORT reads={} jump_vacuity_diagnosable={} jumps_applied={} vacuous={}",
        report.reads,
        u8::from(report.jump_vacuity_diagnosable),
        report.jumps_applied,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        report!(
            "PATINA WARNING: clock fault knobs inert — {} fault-eligible realtime-epoch read(s) \
occurred, enough that the configured jump range should have applied a non-zero offset several \
times over, yet it applied ZERO effects.",
            report.reads,
        );
    }
}

/// Emit the default-on filesystem fault-injection diagnostic to stderr. A driver
/// with no fault model reports `None` and stays silent, as does a live knob that
/// saw no fault-eligible traffic at all. Otherwise the
/// `PATINA_FS_FAULT_REPORT` line lets a reader tell a genuinely-perturbed run
/// from an inert one, and a loud warning fires when a class that was expected to
/// fire repeatedly (see `vacuity_is_diagnosable`) applied zero effects.
///
pub(super) fn emit_fs_fault_report(report: &patina_dst_driver_api::FsFaultReport) {
    if report.eligible_ops == 0 && report.targets_missed == 0 {
        return;
    }
    report!("{}", fs_fault_report_line(report));
    if report.targets_missed != 0 {
        report!(
            "PATINA WARNING: {} --fs-error-at target(s) never landed — the run made fewer \
operations of the kind than the ordinal, or another target took the same operation, so the fault \
it names was not tested.",
            report.targets_missed,
        );
    } else if report.is_vacuous() {
        report!(
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
errors_by_op={} targets_missed={} short_vacuity_diagnosable={} shorts_applied={} shorts_by_op={} \
latency_vacuity_diagnosable={} latency_applied={} vacuous={}",
        report.eligible_ops,
        u8::from(report.error_vacuity_diagnosable),
        report.errors_injected,
        report.errors_by_op,
        report.targets_missed,
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
/// knobs could perturb delivery, the `PATINA_NET_FAULT_REPORT`
/// line lets a reader tell a genuinely-perturbed run from an inert one, and a
/// loud warning fires when fault-eligible traffic occurred yet ZERO fault
/// effects landed — the silent-inertness class (historically: the SimNet TCP
/// stream path ignoring the datagram-only fault knobs).
pub(super) fn emit_net_fault_report(report: &patina_dst_driver_api::NetFaultReport) {
    if !report.had_opportunities() {
        return;
    }
    report!(
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
        report!(
            "PATINA WARNING: net fault knobs inert — fault-eligible network traffic occurred \
({} send(s), {} connect(s), {} stream op(s)), enough that an enabled net fault class should have \
fired several times over, yet that class applied ZERO effects. The configured network fault is \
SILENTLY INERT on the code path this run exercised (historically the SimNet TCP stream path \
ignored the datagram-only fault knobs), so a clean result here does NOT mean the faults were \
tested. Verify the knob reaches the path the workload uses — and, for a partition, that it names \
addresses this run actually connects between.",
            report.send_ops,
            report.connect_ops,
            report.stream_ops,
        );
    }
}

/// Emit the human `PATINA_SCHEDULE_POLICY` line for a run that used an
/// exploration scheduling policy (PCT). The machine copy, bug-depth estimate
/// included, is the facts document's `schedule_policy`.
pub(super) fn emit_schedule_policy_report(report: &crate::scheduler::SchedulePolicyReport) {
    if !report.is_active() {
        return;
    }
    report!(
        "PATINA_SCHEDULE_POLICY pct={} pct_depth={} pct_change_points={} pct_change_points_hit={} \
decisions={} bug_depth={}",
        u8::from(report.pct),
        report.pct_depth,
        report.pct_change_points,
        report.pct_change_points_hit,
        report.decisions,
        report.bug_depth(),
    );
}

/// Emit the human `PATINA_SDK_REPORT` line ([`sdk_report_line`]).
///
pub(super) fn emit_sdk_report(diag: &BuggifyDiagnostics) {
    if let Some(line) = sdk_report_line(diag) {
        report!("{line}");
    }
}

/// The human `PATINA_SDK_REPORT` line for a run that declared or registered any
/// cooperative-SUT sites (or enabled buggify); `None` otherwise. Link-time
/// declarations read `declared_site=<label>|<kind>|@<file:line>` and do not
/// imply evaluation; an evaluated site reads
/// `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->|@<file:line>`.
/// The machine copy is the facts document's `sdk`.
pub(crate) fn sdk_report_line(diag: &BuggifyDiagnostics) -> Option<String> {
    if !diag.enabled && diag.sites_registered == 0 && diag.declared_sites.is_empty() {
        return None;
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
    Some(line)
}

#[cfg(test)]
mod tests {
    use crate::reports::fs_fault_report_line;
    use patina_dst_abi::{FsClock, OpenFlags};

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

        // DOES NOT FIRE below the expected-firings floor: one eligible op fewer
        // than the floor is too few to call zero delays anomalous.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            patina_dst_driver_api::CERTAIN_VACUITY_MIN_OPPORTUNITIES - 1,
            (1_000, 1_000)
        ));

        // DOES NOT FIRE for a range whose every draw is zero: that knob is inert
        // by construction, not inert on the code path.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            1_000_000,
            (0, 0)
        ));

        // Rate-aware in between: `0..9` delays nine draws in ten, so it takes
        // the floor's worth of delays divided by nine tenths, rounded up.
        let ops = (patina_dst_driver_api::VACUITY_MIN_EXPECTED_FIRES * 10).div_ceil(9);
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            ops - 1,
            (0, 9)
        ));
        assert!(patina_dst_driver_api::range_vacuity_is_diagnosable(
            ops,
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
}
