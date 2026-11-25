//! Self-profiling for Patina (launcher, sandbox, supervisor, `patina batch`, and optional
//! compile-time `#[cfg(feature = "profile")]` inner-loop counters from `patina-rt`).
//!
//! Coarse phase profiling is always compiled and gated by `PATINA_PROFILE` / `PATINA_PROFILE_OUT`:
//! - Unset (default): a single cached relaxed atomic load (<50 ns / run), zero allocations,
//!   zero changes to stdout, stderr, `result.json`, `boundary.log`, or deterministic digests.
//! - `PATINA_PROFILE=1` (or `stderr` / `true`): prints a human-readable phase waterfall on stderr
//!   and attaches a `"timing"` object to `result.json` (and `patina batch` NDJSON lines).
//! - `PATINA_PROFILE=json`: prints the `"timing"` JSON object on stderr (and attaches it to
//!   `result.json` / batch NDJSON).
//! - `PATINA_PROFILE_OUT=<path>`: writes Chrome Trace Event Format JSON (`traceEvents` + summary
//!   `metadata`) directly openable in `chrome://tracing` and Perfetto UI.
//!
//! When Patina is built with `--features profile`, `patina-rt` and the supervisor also populate
//! `proto::profile::ProfileTab` in shared `Ctl` memory, adding per-syscall, supervisor IPC,
//! compute-point, load-time plan, and boundary-log breakdowns to the waterfall, JSON, and trace.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Output mode selected by `PATINA_PROFILE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Stderr,
    Json,
}

/// Cached profiling configuration parsed once per process.
#[derive(Clone, Debug)]
pub struct ProfileConfig {
    pub mode: Mode,
    pub out_path: Option<PathBuf>,
}

impl ProfileConfig {
    pub fn is_enabled(&self) -> bool {
        self.mode != Mode::Off || self.out_path.is_some()
    }
}

/// 0 = uninitialized, 1 = disabled, 2 = enabled.
static FAST_STATE: AtomicU8 = AtomicU8::new(0);
static CONFIG: OnceLock<ProfileConfig> = OnceLock::new();

fn parse_env() -> ProfileConfig {
    let mode = match std::env::var("PATINA_PROFILE") {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" => Mode::Off,
            "json" => Mode::Json,
            _ => Mode::Stderr,
        },
        Err(_) => Mode::Off,
    };
    let out_path = std::env::var_os("PATINA_PROFILE_OUT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    ProfileConfig { mode, out_path }
}

/// Read the cached profiling configuration (initializes on first call).
pub fn config() -> &'static ProfileConfig {
    CONFIG.get_or_init(|| {
        let cfg = parse_env();
        FAST_STATE.store(if cfg.is_enabled() { 2 } else { 1 }, Ordering::Relaxed);
        cfg
    })
}

/// Fast-path check for whether profiling is enabled.
/// After first initialization this is a single relaxed atomic load (<5 ns).
#[inline]
pub fn enabled() -> bool {
    match FAST_STATE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => config().is_enabled(),
    }
}

/// Capture host `CLOCK_MONOTONIC` ns when profiling is enabled; returns 0 with zero syscalls when
/// disabled.
#[inline]
pub fn stamp() -> u64 {
    if enabled() {
        crate::launch::mono_ns()
    } else {
        0
    }
}

/// A named phase span in host `CLOCK_MONOTONIC` nanoseconds.
#[derive(Clone, Debug)]
pub struct Span {
    pub name: &'static str,
    pub cat: &'static str,
    pub start_ns: u64,
    pub end_ns: u64,
}

impl Span {
    pub fn new(name: &'static str, cat: &'static str, start_ns: u64, end_ns: u64) -> Span {
        Span {
            name,
            cat,
            start_ns,
            end_ns: end_ns.max(start_ns),
        }
    }

    pub fn dur_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }
}

/// Snapshot of fine-grained `patina-rt` and supervisor inner-loop counters (`--features profile`).
#[derive(Clone, Debug, Default)]
pub struct RtProfileSnapshot {
    pub sigsys_count: u64,
    pub sigsys_ns: u64,
    pub fault_count: u64,
    pub fault_ns: u64,
    pub sup_ipc_count: u64,
    pub sup_ipc_ns: u64,
    pub compute_enter_count: u64,
    pub compute_enter_ns: u64,
    pub compute_exit_count: u64,
    pub compute_exit_ns: u64,
    pub compute_point_count: u64,
    pub compute_point_ns: u64,
    pub plan_on_map_count: u64,
    pub plan_on_map_ns: u64,
    pub plan_trap_count: u64,
    pub plan_trap_ns: u64,
    pub plan_entry_count: u64,
    pub plan_entry_ns: u64,
    pub log_trap_count: u64,
    pub log_trap_ns: u64,
    pub log_append_count: u64,
    pub log_append_ns: u64,
    /// Non-zero per-syscall totals: `(name, count, ns)`.
    pub syscalls: Vec<(String, u64, u64)>,
    /// Non-zero per-supervisor-op totals: `(name, count, ns)`.
    pub sup_ops: Vec<(String, u64, u64)>,
}

impl RtProfileSnapshot {
    /// Read a snapshot from the mapped control region when built with `--features profile`.
    #[cfg(feature = "profile")]
    pub fn read_from_ctl(ctl_ptr: *mut u8) -> RtProfileSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let t = unsafe { proto::profile::ProfileTab::at(ctl_ptr) };
        let mut syscalls = Vec::new();
        for slot in 0..proto::profile::PROFILE_SYSCALL_SLOTS {
            let count = t.syscalls_count[slot].load(Relaxed);
            if count > 0 {
                let ns = t.syscalls_ns[slot].load(Relaxed);
                syscalls.push((proto::profile::syscall_name(slot).to_string(), count, ns));
            }
        }
        let mut sup_ops = Vec::new();
        for op in 0..proto::profile::PROFILE_OP_SLOTS {
            let count = t.sup_op_count[op].load(Relaxed);
            if count > 0 {
                let ns = t.sup_op_ns[op].load(Relaxed);
                sup_ops.push((proto::profile::op_name(op).to_string(), count, ns));
            }
        }
        RtProfileSnapshot {
            sigsys_count: t.sigsys_count.load(Relaxed),
            sigsys_ns: t.sigsys_ns.load(Relaxed),
            fault_count: t.fault_count.load(Relaxed),
            fault_ns: t.fault_ns.load(Relaxed),
            sup_ipc_count: t.sup_ipc_count.load(Relaxed),
            sup_ipc_ns: t.sup_ipc_ns.load(Relaxed),
            compute_enter_count: t.compute_enter_count.load(Relaxed),
            compute_enter_ns: t.compute_enter_ns.load(Relaxed),
            compute_exit_count: t.compute_exit_count.load(Relaxed),
            compute_exit_ns: t.compute_exit_ns.load(Relaxed),
            compute_point_count: t.compute_point_count.load(Relaxed),
            compute_point_ns: t.compute_point_ns.load(Relaxed),
            plan_on_map_count: t.plan_on_map_count.load(Relaxed),
            plan_on_map_ns: t.plan_on_map_ns.load(Relaxed),
            plan_trap_count: t.plan_trap_count.load(Relaxed),
            plan_trap_ns: t.plan_trap_ns.load(Relaxed),
            plan_entry_count: t.plan_entry_count.load(Relaxed),
            plan_entry_ns: t.plan_entry_ns.load(Relaxed),
            log_trap_count: t.log_trap_count.load(Relaxed),
            log_trap_ns: t.log_trap_ns.load(Relaxed),
            log_append_count: t.log_append_count.load(Relaxed),
            log_append_ns: t.log_append_ns.load(Relaxed),
            syscalls,
            sup_ops,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sigsys_count == 0
            && self.fault_count == 0
            && self.sup_ipc_count == 0
            && self.syscalls.is_empty()
            && self.sup_ops.is_empty()
    }

    /// Accumulate another snapshot (e.g. across multiple boots or batch jobs).
    pub fn add(&mut self, other: &RtProfileSnapshot) {
        self.sigsys_count += other.sigsys_count;
        self.sigsys_ns += other.sigsys_ns;
        self.fault_count += other.fault_count;
        self.fault_ns += other.fault_ns;
        self.sup_ipc_count += other.sup_ipc_count;
        self.sup_ipc_ns += other.sup_ipc_ns;
        self.compute_enter_count += other.compute_enter_count;
        self.compute_enter_ns += other.compute_enter_ns;
        self.compute_exit_count += other.compute_exit_count;
        self.compute_exit_ns += other.compute_exit_ns;
        self.compute_point_count += other.compute_point_count;
        self.compute_point_ns += other.compute_point_ns;
        self.plan_on_map_count += other.plan_on_map_count;
        self.plan_on_map_ns += other.plan_on_map_ns;
        self.plan_trap_count += other.plan_trap_count;
        self.plan_trap_ns += other.plan_trap_ns;
        self.plan_entry_count += other.plan_entry_count;
        self.plan_entry_ns += other.plan_entry_ns;
        self.log_trap_count += other.log_trap_count;
        self.log_trap_ns += other.log_trap_ns;
        self.log_append_count += other.log_append_count;
        self.log_append_ns += other.log_append_ns;
        merge_named(&mut self.syscalls, &other.syscalls);
        merge_named(&mut self.sup_ops, &other.sup_ops);
    }

    pub fn to_json(&self) -> Value {
        let mut by_time = self.syscalls.clone();
        by_time.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));
        let top_syscalls: Vec<Value> = by_time
            .iter()
            .take(20)
            .map(|(name, count, ns)| {
                json!({
                    "name": name,
                    "count": count,
                    "ms": ns_to_ms(*ns),
                    "avg_us": avg_us(*ns, *count),
                })
            })
            .collect();

        let mut ops_by_time = self.sup_ops.clone();
        ops_by_time.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));
        let top_ops: Vec<Value> = ops_by_time
            .iter()
            .take(15)
            .map(|(name, count, ns)| {
                json!({
                    "op": name,
                    "count": count,
                    "ms": ns_to_ms(*ns),
                    "avg_us": avg_us(*ns, *count),
                })
            })
            .collect();

        let metric = |count: u64, ns: u64| {
            json!({
                "count": count,
                "ms": ns_to_ms(ns),
                "avg_us": avg_us(ns, count),
            })
        };

        json!({
            "sigsys": metric(self.sigsys_count, self.sigsys_ns),
            "fault": metric(self.fault_count, self.fault_ns),
            "sup_ipc": metric(self.sup_ipc_count, self.sup_ipc_ns),
            "compute": {
                "enter": metric(self.compute_enter_count, self.compute_enter_ns),
                "exit": metric(self.compute_exit_count, self.compute_exit_ns),
                "point": metric(self.compute_point_count, self.compute_point_ns),
            },
            "plans": {
                "on_map": metric(self.plan_on_map_count, self.plan_on_map_ns),
                "trap": metric(self.plan_trap_count, self.plan_trap_ns),
                "entry": metric(self.plan_entry_count, self.plan_entry_ns),
            },
            "log": {
                "trap": metric(self.log_trap_count, self.log_trap_ns),
                "append": metric(self.log_append_count, self.log_append_ns),
            },
            "top_syscalls": top_syscalls,
            "top_sup_ops": top_ops,
        })
    }

    pub fn format_section(&self, out: &mut String) {
        let _ = writeln!(out, "  inner-loop (patina-rt --features profile):");
        let row = |out: &mut String, label: &str, count: u64, ns: u64| {
            if count > 0 {
                let _ = writeln!(
                    out,
                    "    {:<24} {:>8} calls  {:>8.3} ms  ({:>6.2} us/call)",
                    label,
                    count,
                    ns_to_ms(ns),
                    avg_us(ns, count)
                );
            }
        };
        row(out, "sigsys (total)", self.sigsys_count, self.sigsys_ns);
        row(out, "fault (total)", self.fault_count, self.fault_ns);
        row(
            out,
            "sup_ipc (rt->sup)",
            self.sup_ipc_count,
            self.sup_ipc_ns,
        );
        row(
            out,
            "compute::enter",
            self.compute_enter_count,
            self.compute_enter_ns,
        );
        row(
            out,
            "compute::exit",
            self.compute_exit_count,
            self.compute_exit_ns,
        );
        row(
            out,
            "compute::point",
            self.compute_point_count,
            self.compute_point_ns,
        );
        row(
            out,
            "plans::on_map",
            self.plan_on_map_count,
            self.plan_on_map_ns,
        );
        row(out, "plans::trap", self.plan_trap_count, self.plan_trap_ns);
        row(
            out,
            "plans::entry",
            self.plan_entry_count,
            self.plan_entry_ns,
        );
        row(out, "log::trap", self.log_trap_count, self.log_trap_ns);
        row(
            out,
            "log::append",
            self.log_append_count,
            self.log_append_ns,
        );

        if !self.syscalls.is_empty() {
            let mut by_time = self.syscalls.clone();
            by_time.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));
            let _ = writeln!(out, "  top syscalls (by host time):");
            for (name, count, ns) in by_time.iter().take(10) {
                let _ = writeln!(
                    out,
                    "    {:<24} {:>8} calls  {:>8.3} ms  ({:>6.2} us/call)",
                    name,
                    count,
                    ns_to_ms(*ns),
                    avg_us(*ns, *count)
                );
            }
        }
        if !self.sup_ops.is_empty() {
            let mut ops = self.sup_ops.clone();
            ops.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));
            let _ = writeln!(out, "  top supervisor ops (server side):");
            for (name, count, ns) in ops.iter().take(8) {
                let _ = writeln!(
                    out,
                    "    {:<24} {:>8} calls  {:>8.3} ms  ({:>6.2} us/call)",
                    name,
                    count,
                    ns_to_ms(*ns),
                    avg_us(*ns, *count)
                );
            }
        }
    }
}

fn merge_named(dst: &mut Vec<(String, u64, u64)>, src: &[(String, u64, u64)]) {
    for (name, count, ns) in src {
        if let Some(e) = dst.iter_mut().find(|x| x.0 == *name) {
            e.1 += *count;
            e.2 += *ns;
        } else {
            dst.push((name.clone(), *count, *ns));
        }
    }
}

/// Coarse host-monotonic timestamps for a single boot (`launch::run_boot`).
#[derive(Clone, Debug, Default)]
pub struct BootTiming {
    pub boot: u64,
    pub t_boot_start: u64,
    pub t_files_ready: u64,
    pub t_spec_ready: u64,
    pub t_spawn: u64,
    pub t_sandbox_pid1: u64,
    pub t_sandbox_setup: u64,
    pub t_sup_start: u64,
    pub t_copied: u64,
    pub t_first_hello: u64,
    pub t_main_exit: u64,
    pub t_finish: u64,
    pub t_exported: u64,
    pub t_verdict: u64,
    pub t_waited: u64,
    pub t_stdio_done: u64,
    pub t_boot_done: u64,
    pub traps: u64,
    pub switches: u64,
    pub rt: Option<RtProfileSnapshot>,
}

impl BootTiming {
    /// Decompose the boot into ordered, non-overlapping critical-path phase spans.
    pub fn phases(&self) -> Vec<Span> {
        let mut spans = Vec::with_capacity(14);
        if self.t_boot_start == 0 || self.t_boot_done == 0 {
            return spans;
        }
        let mut cursor = self.t_boot_start;
        let waited = self.t_waited;
        let push = |spans: &mut Vec<Span>,
                    cursor: &mut u64,
                    name: &'static str,
                    cat: &'static str,
                    end: u64| {
            if end >= *cursor && end > 0 {
                spans.push(Span::new(name, cat, *cursor, end));
                *cursor = end;
            }
        };

        push(
            &mut spans,
            &mut cursor,
            "boot_files_and_ctl",
            "launcher",
            self.t_files_ready,
        );
        push(
            &mut spans,
            &mut cursor,
            "layout_and_spec",
            "launcher",
            self.t_spec_ready,
        );
        push(
            &mut spans,
            &mut cursor,
            "sandbox_spawn_prep",
            "launcher",
            self.t_spawn,
        );

        // Inside the sandbox: keeper -> PID 1 -> mounts -> supervisor -> guest -> teardown.
        // Guard against boots that aborted early (missing internal marks).
        if self.t_sandbox_pid1 >= cursor && self.t_sandbox_pid1 <= waited {
            push(
                &mut spans,
                &mut cursor,
                "keeper_to_pid1",
                "sandbox",
                self.t_sandbox_pid1,
            );
        }
        if self.t_sandbox_setup >= cursor && self.t_sandbox_setup <= waited {
            push(
                &mut spans,
                &mut cursor,
                "sandbox_mount_setup",
                "sandbox",
                self.t_sandbox_setup,
            );
        }
        if self.t_sup_start >= cursor && self.t_sup_start <= waited {
            push(
                &mut spans,
                &mut cursor,
                "sup_startup",
                "supervisor",
                self.t_sup_start,
            );
        }
        if self.t_copied >= cursor && self.t_copied <= waited {
            push(
                &mut spans,
                &mut cursor,
                "sup_init_and_copy",
                "supervisor",
                self.t_copied,
            );
        }
        if self.t_first_hello >= cursor && self.t_first_hello <= waited {
            push(
                &mut spans,
                &mut cursor,
                "guest_boot_to_hello",
                "guest",
                self.t_first_hello,
            );
        }
        let guest_end = if self.t_main_exit >= cursor && self.t_main_exit <= waited {
            self.t_main_exit
        } else if self.t_finish >= cursor && self.t_finish <= waited {
            self.t_finish
        } else {
            0
        };
        if guest_end > 0 {
            push(&mut spans, &mut cursor, "guest_exec", "guest", guest_end);
        }
        if self.t_exported >= cursor && self.t_exported <= waited {
            push(
                &mut spans,
                &mut cursor,
                "sup_teardown_export",
                "supervisor",
                self.t_exported,
            );
        }
        if self.t_verdict >= cursor && self.t_verdict <= waited {
            push(
                &mut spans,
                &mut cursor,
                "sandbox_verdict_wait",
                "launcher",
                self.t_verdict,
            );
        }
        push(
            &mut spans,
            &mut cursor,
            "sandbox_exit_reap",
            "launcher",
            waited,
        );
        push(
            &mut spans,
            &mut cursor,
            "stdio_and_log_flush",
            "launcher",
            self.t_stdio_done,
        );
        push(
            &mut spans,
            &mut cursor,
            "ctl_read_and_unmap",
            "launcher",
            self.t_boot_done,
        );

        spans
    }

    pub fn total_ns(&self) -> u64 {
        self.t_boot_done.saturating_sub(self.t_boot_start)
    }

    pub fn to_json(&self) -> Value {
        let phases: Vec<Value> = self
            .phases()
            .into_iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "cat": s.cat,
                    "ms": ns_to_ms(s.dur_ns()),
                })
            })
            .collect();
        let mut obj = json!({
            "boot": self.boot,
            "total_ms": ns_to_ms(self.total_ns()),
            "traps": self.traps,
            "switches": self.switches,
            "phases": phases,
        });
        if let Some(rt) = &self.rt {
            if !rt.is_empty() {
                obj["rt"] = rt.to_json();
            }
        }
        obj
    }
}

/// Complete profile for a `patina run` invocation.
#[derive(Clone, Debug, Default)]
pub struct RunProfile {
    pub seed: u64,
    pub outcome: String,
    pub traps: u64,
    pub switches: u64,
    pub t_start_ns: u64,
    pub t_end_ns: u64,
    pub pre_spans: Vec<Span>,
    pub boots: Vec<BootTiming>,
    pub post_spans: Vec<Span>,
}

impl RunProfile {
    pub fn total_ns(&self) -> u64 {
        self.t_end_ns.saturating_sub(self.t_start_ns)
    }

    pub fn aggregated_rt(&self) -> Option<RtProfileSnapshot> {
        let mut acc = RtProfileSnapshot::default();
        let mut any = false;
        for b in &self.boots {
            if let Some(rt) = &b.rt {
                if !rt.is_empty() {
                    acc.add(rt);
                    any = true;
                }
            }
        }
        any.then_some(acc)
    }

    /// Flat list of all phases (pre + boots + post) for waterfall and JSON summary.
    pub fn all_spans(&self) -> Vec<Span> {
        let mut all = Vec::new();
        all.extend(self.pre_spans.iter().cloned());
        for b in &self.boots {
            all.extend(b.phases());
        }
        all.extend(self.post_spans.iter().cloned());
        all
    }

    /// Structured `"timing"` JSON object (embedded in `result.json` when `PATINA_PROFILE` is on,
    /// and printed to stderr when `PATINA_PROFILE=json`).
    pub fn to_timing_json(&self) -> Value {
        let total_ns = self.total_ns().max(1);
        let phases: Vec<Value> = self
            .all_spans()
            .into_iter()
            .map(|s| {
                let dur = s.dur_ns();
                json!({
                    "name": s.name,
                    "cat": s.cat,
                    "ms": ns_to_ms(dur),
                    "pct": round1(dur as f64 * 100.0 / total_ns as f64),
                })
            })
            .collect();
        let boots: Vec<Value> = self.boots.iter().map(BootTiming::to_json).collect();
        let mut obj = json!({
            "total_ms": ns_to_ms(self.total_ns()),
            "seed": self.seed,
            "outcome": self.outcome,
            "traps": self.traps,
            "switches": self.switches,
            "phases": phases,
            "boots": boots,
        });
        if let Some(rt) = self.aggregated_rt() {
            obj["rt"] = rt.to_json();
        }
        obj
    }

    /// Crisp human-readable phase waterfall for stderr.
    pub fn format_waterfall(&self) -> String {
        let total_ns = self.total_ns().max(1);
        let mut out = String::new();
        let _ = writeln!(
            out,
            "patina-profile: run seed={} outcome={} total={:.3} ms (boots={} traps={} switches={})",
            self.seed,
            self.outcome,
            ns_to_ms(self.total_ns()),
            self.boots.len(),
            self.traps,
            self.switches
        );
        let _ = writeln!(out, "  {:<26} {:>9} {:>7}  category", "phase", "ms", "%");
        let mut accounted = 0u64;
        for s in self.all_spans() {
            let dur = s.dur_ns();
            accounted += dur;
            let pct = dur as f64 * 100.0 / total_ns as f64;
            let _ = writeln!(
                out,
                "  {:<26} {:>9.3} {:>6.1}%  {}",
                s.name,
                ns_to_ms(dur),
                pct,
                s.cat
            );
        }
        let other = self.total_ns().saturating_sub(accounted);
        if other > 100_000 {
            let pct = other as f64 * 100.0 / total_ns as f64;
            let _ = writeln!(
                out,
                "  {:<26} {:>9.3} {:>6.1}%  other",
                "untracked",
                ns_to_ms(other),
                pct
            );
        }
        if let Some(rt) = self.aggregated_rt() {
            rt.format_section(&mut out);
        }
        out
    }

    /// Write Chrome Trace Event Format JSON (`chrome://tracing`, Perfetto UI).
    pub fn write_chrome_trace(&self, path: &Path) -> Result<(), String> {
        let pid = std::process::id();
        let origin = self.t_start_ns;
        let mut events: Vec<Value> = vec![json!({
            "name": "thread_name",
            "ph": "M",
            "pid": pid,
            "tid": 0,
            "args": { "name": "patina-run" }
        })];
        for s in &self.pre_spans {
            events.push(trace_event(s, pid, 0, origin, None));
        }
        for b in &self.boots {
            events.push(json!({
                "name": format!("boot-{}", b.boot),
                "cat": "boot",
                "ph": "X",
                "ts": us_since(b.t_boot_start, origin),
                "dur": ns_to_us(b.total_ns()),
                "pid": pid,
                "tid": 0,
                "args": { "boot": b.boot, "traps": b.traps, "switches": b.switches },
            }));
            for s in b.phases() {
                events.push(trace_event(&s, pid, 0, origin, Some(b.boot)));
            }
        }
        for s in &self.post_spans {
            events.push(trace_event(s, pid, 0, origin, None));
        }
        let doc = json!({
            "displayTimeUnit": "ms",
            "traceEvents": events,
            "metadata": self.to_timing_json(),
        });
        write_trace_file(path, &doc)
    }

    /// Emit according to `PATINA_PROFILE` and `PATINA_PROFILE_OUT`.
    pub fn emit(&self) {
        let cfg = config();
        match cfg.mode {
            Mode::Off => {}
            Mode::Stderr => eprint!("{}", self.format_waterfall()),
            Mode::Json => {
                if let Ok(s) = serde_json::to_string(&self.to_timing_json()) {
                    eprintln!("{s}");
                }
            }
        }
        if let Some(path) = &cfg.out_path {
            if let Err(e) = self.write_chrome_trace(path) {
                eprintln!("patina-profile: {e}");
            }
        }
    }
}

/// Per-job timing record collected inside `patina batch`.
#[derive(Clone, Debug)]
pub struct BatchJobTiming {
    pub id: u64,
    pub seed: u64,
    pub worker_idx: usize,
    pub cpu: usize,
    pub outcome: String,
    pub traps: u64,
    pub switches: u64,
    pub t_start_ns: u64,
    pub t_end_ns: u64,
    pub boots: Vec<BootTiming>,
}

impl BatchJobTiming {
    pub fn total_ns(&self) -> u64 {
        self.t_end_ns.saturating_sub(self.t_start_ns)
    }

    pub fn to_timing_json(&self) -> Value {
        let boots: Vec<Value> = self.boots.iter().map(BootTiming::to_json).collect();
        let mut obj = json!({
            "total_ms": ns_to_ms(self.total_ns()),
            "worker": self.worker_idx,
            "cpu": self.cpu,
            "traps": self.traps,
            "switches": self.switches,
            "boots": boots,
        });
        let mut acc = RtProfileSnapshot::default();
        let mut any = false;
        for b in &self.boots {
            if let Some(rt) = &b.rt {
                if !rt.is_empty() {
                    acc.add(rt);
                    any = true;
                }
            }
        }
        if any {
            obj["rt"] = acc.to_json();
        }
        obj
    }
}

/// Whole-session profile for `patina batch`.
pub struct BatchProfile {
    pub t_start_ns: u64,
    pub jobs_configured: usize,
    pub startup_spans: Vec<Span>,
    pub jobs: Mutex<Vec<BatchJobTiming>>,
}

impl BatchProfile {
    pub fn new(t_start_ns: u64) -> BatchProfile {
        BatchProfile {
            t_start_ns,
            jobs_configured: 0,
            startup_spans: Vec::new(),
            jobs: Mutex::new(Vec::new()),
        }
    }

    pub fn push_startup(&mut self, name: &'static str, cat: &'static str, start_ns: u64) {
        let end_ns = stamp();
        if start_ns > 0 && end_ns >= start_ns {
            self.startup_spans
                .push(Span::new(name, cat, start_ns, end_ns));
        }
    }

    pub fn record_job(&self, job: BatchJobTiming) {
        self.jobs.lock().unwrap().push(job);
    }

    pub fn to_summary_json(&self, t_end_ns: u64) -> Value {
        let total_ns = t_end_ns.saturating_sub(self.t_start_ns);
        let jobs = self.jobs.lock().unwrap();
        let count = jobs.len();
        let mut durs: Vec<u64> = jobs.iter().map(BatchJobTiming::total_ns).collect();
        durs.sort_unstable();
        let mean_ms = if count > 0 {
            ns_to_ms(durs.iter().sum::<u64>() / count as u64)
        } else {
            0.0
        };
        let p50_ms = percentile_ns(&durs, 50).map(ns_to_ms).unwrap_or(0.0);
        let p95_ms = percentile_ns(&durs, 95).map(ns_to_ms).unwrap_or(0.0);
        let throughput = if total_ns > 0 {
            round1(count as f64 / (total_ns as f64 / 1e9))
        } else {
            0.0
        };

        let startup: Vec<Value> = self
            .startup_spans
            .iter()
            .map(|s| json!({"name": s.name, "cat": s.cat, "ms": ns_to_ms(s.dur_ns())}))
            .collect();

        // Aggregate mean phase durations across all boots of all jobs.
        let mut phase_order: Vec<&'static str> = Vec::new();
        let mut phase_totals: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
        let mut acc_rt = RtProfileSnapshot::default();
        let mut any_rt = false;
        let mut total_traps = 0u64;
        let mut total_switches = 0u64;
        for j in jobs.iter() {
            total_traps += j.traps;
            total_switches += j.switches;
            for b in &j.boots {
                for s in b.phases() {
                    if !phase_totals.contains_key(s.name) {
                        phase_order.push(s.name);
                    }
                    let e = phase_totals.entry(s.name).or_insert((0, 0));
                    e.0 += s.dur_ns();
                    e.1 += 1;
                }
                if let Some(rt) = &b.rt {
                    if !rt.is_empty() {
                        acc_rt.add(rt);
                        any_rt = true;
                    }
                }
            }
        }
        let avg_phases: Vec<Value> = phase_order
            .into_iter()
            .filter_map(|name| {
                let (sum_ns, n) = phase_totals.get(name).copied()?;
                Some(json!({
                    "name": name,
                    "mean_ms": ns_to_ms(sum_ns / n.max(1)),
                    "total_ms": ns_to_ms(sum_ns),
                    "count": n,
                }))
            })
            .collect();

        let mut obj = json!({
            "mode": "batch",
            "total_ms": ns_to_ms(total_ns),
            "workers": self.jobs_configured,
            "jobs": count,
            "jobs_per_sec": throughput,
            "job_mean_ms": mean_ms,
            "job_p50_ms": p50_ms,
            "job_p95_ms": p95_ms,
            "traps": total_traps,
            "switches": total_switches,
            "startup": startup,
            "boot_phases": avg_phases,
        });
        if any_rt {
            obj["rt"] = acc_rt.to_json();
        }
        obj
    }

    pub fn format_summary(&self, t_end_ns: u64) -> String {
        let total_ns = t_end_ns.saturating_sub(self.t_start_ns);
        let jobs = self.jobs.lock().unwrap();
        let count = jobs.len();
        let mut durs: Vec<u64> = jobs.iter().map(BatchJobTiming::total_ns).collect();
        durs.sort_unstable();
        let mean_ms = if count > 0 {
            ns_to_ms(durs.iter().sum::<u64>() / count as u64)
        } else {
            0.0
        };
        let p50_ms = percentile_ns(&durs, 50).map(ns_to_ms).unwrap_or(0.0);
        let p95_ms = percentile_ns(&durs, 95).map(ns_to_ms).unwrap_or(0.0);
        let throughput = if total_ns > 0 {
            count as f64 / (total_ns as f64 / 1e9)
        } else {
            0.0
        };

        let mut out = String::new();
        let _ = writeln!(
            out,
            "patina-profile: batch workers={} jobs={} total={:.3} ms ({:.1} jobs/s, mean={:.3} ms, p50={:.3} ms, p95={:.3} ms)",
            self.jobs_configured,
            count,
            ns_to_ms(total_ns),
            throughput,
            mean_ms,
            p50_ms,
            p95_ms,
        );
        if !self.startup_spans.is_empty() {
            let _ = writeln!(out, "  startup:");
            for s in &self.startup_spans {
                let _ = writeln!(
                    out,
                    "    {:<24} {:>9.3} ms  ({})",
                    s.name,
                    ns_to_ms(s.dur_ns()),
                    s.cat
                );
            }
        }
        let mut phase_order: Vec<&'static str> = Vec::new();
        let mut phase_totals: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
        let mut acc_rt = RtProfileSnapshot::default();
        let mut any_rt = false;
        let mut total_boot_ns = 0u64;
        for j in jobs.iter() {
            for b in &j.boots {
                total_boot_ns += b.total_ns();
                for s in b.phases() {
                    if !phase_totals.contains_key(s.name) {
                        phase_order.push(s.name);
                    }
                    let e = phase_totals.entry(s.name).or_insert((0, 0));
                    e.0 += s.dur_ns();
                    e.1 += 1;
                }
                if let Some(rt) = &b.rt {
                    if !rt.is_empty() {
                        acc_rt.add(rt);
                        any_rt = true;
                    }
                }
            }
        }
        if !phase_order.is_empty() {
            let denom = total_boot_ns.max(1) as f64;
            let _ = writeln!(
                out,
                "  boot phases (mean across jobs): {:<12} {:>9} {:>7}",
                "", "mean ms", "%"
            );
            for name in phase_order {
                if let Some(&(sum_ns, n)) = phase_totals.get(name) {
                    let pct = sum_ns as f64 * 100.0 / denom;
                    let _ = writeln!(
                        out,
                        "    {:<24} {:>9.3} ms {:>6.1}%",
                        name,
                        ns_to_ms(sum_ns / n.max(1)),
                        pct
                    );
                }
            }
        }
        if any_rt {
            acc_rt.format_section(&mut out);
        }
        out
    }

    pub fn write_chrome_trace(&self, path: &Path, t_end_ns: u64) -> Result<(), String> {
        let pid = std::process::id();
        let origin = self.t_start_ns;
        let mut events: Vec<Value> = vec![json!({
            "name": "thread_name",
            "ph": "M",
            "pid": pid,
            "tid": 0,
            "args": { "name": "batch-main" }
        })];
        for w in 0..self.jobs_configured {
            events.push(json!({
                "name": "thread_name",
                "ph": "M",
                "pid": pid,
                "tid": w + 1,
                "args": { "name": format!("worker-{w}") }
            }));
        }
        for s in &self.startup_spans {
            events.push(trace_event(s, pid, 0, origin, None));
        }
        {
            let jobs = self.jobs.lock().unwrap();
            for j in jobs.iter() {
                let tid = j.worker_idx + 1;
                events.push(json!({
                    "name": format!("job-{} (seed {})", j.id, j.seed),
                    "cat": "batch_job",
                    "ph": "X",
                    "ts": us_since(j.t_start_ns, origin),
                    "dur": ns_to_us(j.total_ns()),
                    "pid": pid,
                    "tid": tid,
                    "args": {
                        "id": j.id,
                        "seed": j.seed,
                        "cpu": j.cpu,
                        "outcome": j.outcome,
                        "traps": j.traps,
                        "switches": j.switches,
                    },
                }));
                for b in &j.boots {
                    for s in b.phases() {
                        events.push(trace_event(&s, pid, tid, origin, Some(b.boot)));
                    }
                }
            }
        }
        let doc = json!({
            "displayTimeUnit": "ms",
            "traceEvents": events,
            "metadata": self.to_summary_json(t_end_ns),
        });
        write_trace_file(path, &doc)
    }

    pub fn emit(&self, t_end_ns: u64) {
        let cfg = config();
        match cfg.mode {
            Mode::Off => {}
            Mode::Stderr => eprint!("{}", self.format_summary(t_end_ns)),
            Mode::Json => {
                if let Ok(s) = serde_json::to_string(&self.to_summary_json(t_end_ns)) {
                    eprintln!("{s}");
                }
            }
        }
        if let Some(path) = &cfg.out_path {
            if let Err(e) = self.write_chrome_trace(path, t_end_ns) {
                eprintln!("patina-profile: {e}");
            }
        }
    }
}

fn trace_event(s: &Span, pid: u32, tid: usize, origin: u64, boot: Option<u64>) -> Value {
    let mut ev = json!({
        "name": s.name,
        "cat": s.cat,
        "ph": "X",
        "ts": us_since(s.start_ns, origin),
        "dur": ns_to_us(s.dur_ns()),
        "pid": pid,
        "tid": tid,
    });
    if let Some(b) = boot {
        ev["args"] = json!({ "boot": b });
    }
    ev
}

fn write_trace_file(path: &Path, doc: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut s = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    s.push('\n');
    std::fs::write(path, s).map_err(|e| format!("write {}: {e}", path.display()))
}

fn ns_to_ms(ns: u64) -> f64 {
    (ns as f64 / 1_000.0).round() / 1_000.0
}

fn ns_to_us(ns: u64) -> f64 {
    (ns as f64 / 10.0).round() / 100.0
}

fn us_since(ts: u64, origin: u64) -> f64 {
    ns_to_us(ts.saturating_sub(origin))
}

fn avg_us(ns: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        ((ns as f64 / count as f64) / 10.0).round() / 100.0
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn percentile_ns(sorted: &[u64], pct: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    Some(sorted[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_timing_phases_are_non_overlapping_and_sum_to_total() {
        let bt = BootTiming {
            boot: 1,
            t_boot_start: 1_000_000,
            t_files_ready: 1_500_000,
            t_spec_ready: 1_800_000,
            t_spawn: 2_000_000,
            t_sandbox_pid1: 4_000_000,
            t_sandbox_setup: 8_000_000,
            t_sup_start: 8_200_000,
            t_copied: 9_000_000,
            t_first_hello: 11_000_000,
            t_main_exit: 15_000_000,
            t_finish: 15_050_000,
            t_exported: 15_500_000,
            t_verdict: 15_700_000,
            t_waited: 16_000_000,
            t_stdio_done: 16_300_000,
            t_boot_done: 16_500_000,
            traps: 120,
            switches: 12,
            rt: None,
        };
        let phases = bt.phases();
        assert_eq!(phases.len(), 14);
        let sum: u64 = phases.iter().map(Span::dur_ns).sum();
        assert_eq!(sum, bt.total_ns());
        for w in phases.windows(2) {
            assert_eq!(w[0].end_ns, w[1].start_ns);
        }
    }

    #[test]
    fn boot_timing_handles_early_abort_cleanly() {
        let bt = BootTiming {
            boot: 1,
            t_boot_start: 1_000_000,
            t_files_ready: 1_200_000,
            t_spec_ready: 1_400_000,
            t_spawn: 1_500_000,
            t_sandbox_pid1: 0,
            t_sandbox_setup: 0,
            t_sup_start: 0,
            t_copied: 0,
            t_first_hello: 0,
            t_main_exit: 0,
            t_finish: 0,
            t_exported: 0,
            t_verdict: 5_000_000,
            t_waited: 5_500_000,
            t_stdio_done: 5_700_000,
            t_boot_done: 6_000_000,
            traps: 0,
            switches: 0,
            rt: None,
        };
        let phases = bt.phases();
        let sum: u64 = phases.iter().map(Span::dur_ns).sum();
        assert_eq!(sum, bt.total_ns());
    }

    #[test]
    fn rt_snapshot_merges_and_formats() {
        let mut a = RtProfileSnapshot {
            sigsys_count: 100,
            sigsys_ns: 2_000_000,
            sup_ipc_count: 10,
            sup_ipc_ns: 500_000,
            syscalls: vec![
                ("read".into(), 60, 1_200_000),
                ("write".into(), 40, 800_000),
            ],
            sup_ops: vec![("Yield".into(), 8, 400_000)],
            ..Default::default()
        };
        let b = RtProfileSnapshot {
            sigsys_count: 50,
            sigsys_ns: 1_000_000,
            sup_ipc_count: 5,
            sup_ipc_ns: 250_000,
            syscalls: vec![("read".into(), 20, 400_000), ("openat".into(), 30, 600_000)],
            sup_ops: vec![("Yield".into(), 2, 100_000), ("Hello".into(), 1, 50_000)],
            ..Default::default()
        };
        a.add(&b);
        assert_eq!(a.sigsys_count, 150);
        assert_eq!(a.syscalls.len(), 3);
        let j = a.to_json();
        assert_eq!(j["sigsys"]["count"], 150);
        assert_eq!(j["top_syscalls"][0]["name"], "read");
        assert_eq!(j["top_syscalls"][0]["count"], 80);
        let mut s = String::new();
        a.format_section(&mut s);
        assert!(s.contains("sigsys (total)"));
        assert!(s.contains("read"));
        assert!(s.contains("Yield"));
    }

    #[test]
    fn run_profile_waterfall_and_chrome_trace() {
        let rp = RunProfile {
            seed: 42,
            outcome: "ok".into(),
            traps: 55,
            switches: 3,
            t_start_ns: 10_000_000,
            t_end_ns: 25_000_000,
            pre_spans: vec![
                Span::new("cli_config_resolve", "cli", 10_000_000, 10_500_000),
                Span::new("preflight", "launcher", 10_500_000, 11_000_000),
            ],
            boots: vec![BootTiming {
                boot: 1,
                t_boot_start: 11_000_000,
                t_files_ready: 12_000_000,
                t_spec_ready: 12_500_000,
                t_spawn: 13_000_000,
                t_sandbox_pid1: 15_000_000,
                t_sandbox_setup: 18_000_000,
                t_sup_start: 18_200_000,
                t_copied: 19_000_000,
                t_first_hello: 20_000_000,
                t_main_exit: 22_000_000,
                t_finish: 22_100_000,
                t_exported: 22_500_000,
                t_verdict: 22_700_000,
                t_waited: 23_000_000,
                t_stdio_done: 23_500_000,
                t_boot_done: 24_000_000,
                traps: 55,
                switches: 3,
                rt: None,
            }],
            post_spans: vec![Span::new(
                "result_write_and_check",
                "launcher",
                24_000_000,
                25_000_000,
            )],
        };
        let wf = rp.format_waterfall();
        assert!(wf.contains("patina-profile: run seed=42"));
        assert!(wf.contains("sandbox_mount_setup"));
        assert!(wf.contains("guest_exec"));

        let tmp =
            std::env::temp_dir().join(format!("patina-prof-unit-{}.json", std::process::id()));
        rp.write_chrome_trace(&tmp).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&tmp).unwrap()).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(v["traceEvents"].as_array().unwrap().len() >= 10);
        assert_eq!(v["metadata"]["seed"], 42);
    }
}
