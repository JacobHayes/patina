//! `patina profile PATH [--format summary|json|trace|folded|html] [--out FILE] [--serve [ADDR]]`:
//! Deterministic Guest Profiling Suite for single runs and sweeps/campaigns.
//!
//! - **4-Bucket Attribution**: strictly separates (1) Guest User Compute, (2) Logical I/O &
//!   Syscall Work, (3) Modeled Virtual Latency (with p50/p95/p99 tail distributions), and
//!   (4) Patina Runtime Tax so slow intercepts never masquerade as slow guest code.
//! - **Deterministic CPU Flamegraphs**: decodes `boot-*/cpu_profile.bin` (captured via
//!   `--profile-cpu`), strictly filters `[RT_BASE, RT_REGION_END)`, symbolizes against guest ELF
//!   `.symtab`/`.dynsym`, and emits standard folded stacks (`main;parse;hash 42000`).
//! - **Memory & Virtual Tail-Latency Attribution**: tracks `mmap`/`munmap`/`mremap`/`brk` peak and
//!   delta timelines plus virtual latency percentiles per operation category.
//! - **Perfetto / Chrome Trace Event JSON** (`--format trace`) with thread lanes, syscalls,
//!   futex/fsync/net/sleep ops, preempts, injected faults, CPU samples, and memory counter tracks.
//! - **Interactive HTML Dashboard** (`--format html` / `--serve [ADDR]`): self-contained zero-CDN
//!   dashboard for both single runs and sweep/campaign directories, plus a zero-dependency local
//!   HTTP server via `std::net::TcpListener`.

use crate::cli::{Args, Res};
use crate::durability::check::boots;
use crate::log::{Cut, Str};
use crate::result::read_json;
use proto::ctl::Op;
use proto::guest_profile::{HEADER_LEN, KIND_IMAGE, KIND_SAMPLE, MAGIC, VERSION};
use proto::layout::{RT_BASE, RT_REGION_END};
use proto::rec::{Rec, RecKind, REC_SIZE, STR_PATH, STR_RESOLVED};
use proto::table::name as syscall_name;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub const PROFILE_SCHEMA: &str = "patina.profile/v1";
const DEFAULT_SERVE_ADDR: &str = "127.0.0.1:8080";
const MAX_TIMELINE_EVENTS_HTML: usize = 5_000;
const MAX_MEM_POINTS_HTML: usize = 600;
const MAX_TRACE_EVENTS: usize = 250_000;

fn single_path<'a>(args: &'a Args, usage: &str) -> Res<&'a Path> {
    let [p] = args.positional.as_slice() else {
        return Err(usage.into());
    };
    let path = Path::new(p.as_str());
    if !path.exists() {
        return Err(format!("{}: no such file or directory", path.display()));
    }
    Ok(path)
}

fn write_output(args: &Args, output: &str) -> Res<ExitCode> {
    if let Some(out_path) = args.last("--out") {
        let p = Path::new(out_path);
        if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(p, output.as_bytes()).map_err(|e| format!("write {}: {e}", p.display()))?;
        eprintln!("wrote {}", p.display());
    } else {
        let mut out = std::io::stdout().lock();
        if let Err(e) = out.write_all(output.as_bytes()) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(format!("stdout: {e}"));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Entry point for `patina inspect profile PATH [--format text|json] [--out FILE]`.
pub fn inspect_profile(args: &Args) -> Res<ExitCode> {
    let path = single_path(
        args,
        "usage: patina inspect profile PATH [--format text|json] [--out FILE]",
    )?;
    let target = load_target(path)?;
    let output = match (&target, args.json()) {
        (ProfileTarget::Run(run), false) => format_run_summary(run),
        (ProfileTarget::Run(run), true) => serde_json::to_string_pretty(run).unwrap() + "\n",
        (ProfileTarget::Sweep(sweep), false) => format_sweep_summary(sweep),
        (ProfileTarget::Sweep(sweep), true) => serde_json::to_string_pretty(sweep).unwrap() + "\n",
    };
    write_output(args, &output)
}

/// Entry point for `patina inspect serve [--addr ADDR] PATH`.
pub fn inspect_serve(args: &Args) -> Res<ExitCode> {
    let path = single_path(args, "usage: patina inspect serve [--addr ADDR] PATH")?;
    let target = load_target(path)?;
    let addr = args.last("--addr").unwrap_or(DEFAULT_SERVE_ADDR);
    serve(&target, addr)?;
    Ok(ExitCode::SUCCESS)
}

/// Entry point for `patina inspect html [--out FILE] PATH`.
pub fn inspect_html(args: &Args) -> Res<ExitCode> {
    let path = single_path(args, "usage: patina inspect html [--out FILE] PATH")?;
    let target = load_target(path)?;
    let output = match &target {
        ProfileTarget::Run(run) => {
            let profile_json = serde_json::to_string(run).unwrap();
            let trace_json = serde_json::to_string(&build_perfetto_trace(run)).unwrap();
            crate::profile_html::render_run_html(&profile_json, &trace_json)
        }
        ProfileTarget::Sweep(sweep) => {
            let sweep_json = serde_json::to_string(sweep).unwrap();
            crate::profile_html::render_sweep_html(&sweep_json)
        }
    };
    write_output(args, &output)
}

/// Entry point for `patina inspect trace [--out FILE] RUNDIR`.
pub fn inspect_trace(args: &Args) -> Res<ExitCode> {
    let path = single_path(args, "usage: patina inspect trace [--out FILE] RUNDIR")?;
    let target = load_target(path)?;
    let ProfileTarget::Run(run) = target else {
        return Err(
            "inspect trace requires a single run directory (use inspect html or inspect serve for a sweep)"
                .into(),
        );
    };
    let output = serde_json::to_string(&build_perfetto_trace(&run)).unwrap() + "\n";
    write_output(args, &output)
}

/// Entry point for `patina inspect folded [--out FILE] RUNDIR`.
pub fn inspect_folded(args: &Args) -> Res<ExitCode> {
    let path = single_path(args, "usage: patina inspect folded [--out FILE] RUNDIR")?;
    let target = load_target(path)?;
    let ProfileTarget::Run(run) = target else {
        return Err(
            "inspect folded requires a single run directory with --profile-cpu (use inspect html or inspect serve for a sweep)"
                .into(),
        );
    };
    let output = format_folded(&run)?;
    write_output(args, &output)
}

/// Auto-detected profile target: a single run directory or a sweep/campaign directory.
pub enum ProfileTarget {
    Run(Box<RunProfile>),
    Sweep(Box<SweepProfile>),
}

/// Auto-detect whether `path` is a single run directory or a sweep/campaign directory and load it.
pub fn load_target(path: &Path) -> Res<ProfileTarget> {
    if is_run_dir(path) {
        return Ok(ProfileTarget::Run(Box::new(profile_run(path)?)));
    }
    if path.is_dir()
        && (path.join("report.json").is_file()
            || path.join("sweep.json").is_file()
            || !crate::report::collect(&[path.to_path_buf()])
                .unwrap_or_default()
                .is_empty())
    {
        return Ok(ProfileTarget::Sweep(Box::new(profile_sweep(path)?)));
    }
    Err(format!(
        "{}: not a patina run directory (no run.json/result.json/boot-1) or sweep directory (no report.json/runs)",
        path.display()
    ))
}

fn is_run_dir(path: &Path) -> bool {
    path.is_dir()
        && (path.join("run.json").is_file()
            || path.join("result.json").is_file()
            || path.join("boot-1").is_dir())
}

// ============================================================================
// Single-Run Profile Data Structures
// ============================================================================

#[derive(Clone, Debug, Serialize)]
pub struct RunProfile {
    pub schema: &'static str,
    pub kind: &'static str,
    pub dir: String,
    pub program: String,
    pub seed: u64,
    pub outcome: String,
    pub stop: String,
    pub digest: String,
    pub boots: u64,
    pub virtual_duration_ns: u64,
    pub wall_ms: u64,
    pub guest_compute: GuestComputeBucket,
    pub logical_io: LogicalIoBucket,
    pub virtual_latency: VirtualLatencyBucket,
    pub patina_tax: PatinaTaxBucket,
    pub memory: MemoryAttribution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageSummary>,
    pub threads: Vec<ThreadInfo>,
    pub timeline_events: Vec<TimelineEvent>,
    #[serde(skip)]
    pub trace_events: Vec<TraceRawEvent>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GuestComputeBucket {
    pub compute_events: u64,
    pub compute_charge_ns: u64,
    pub compute_switches: u64,
    pub deadline_stops: u64,
    pub spin_yields: u64,
    pub pause_points: u64,
    pub virtual_share_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_profile: Option<CpuProfileSummary>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CpuProfileSummary {
    pub interval: u64,
    pub total_samples: u64,
    pub total_weight: u64,
    pub rt_frames_filtered: u64,
    pub images_loaded: usize,
    pub top_functions: Vec<FunctionSample>,
    pub folded_stacks: Vec<FoldedStack>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionSample {
    pub name: String,
    pub module: String,
    pub self_weight: u64,
    pub total_weight: u64,
    pub self_pct: f64,
    pub total_pct: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FoldedStack {
    pub stack: String,
    pub weight: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LogicalIoBucket {
    pub total_syscalls: u64,
    pub syscall_errors: u64,
    pub read_ops: u64,
    pub read_bytes: u64,
    pub write_ops: u64,
    pub write_bytes: u64,
    pub fsync_ops: u64,
    pub futex_wait_ops: u64,
    pub futex_wake_ops: u64,
    pub futex_total_ops: u64,
    pub net_send_ops: u64,
    pub net_recv_ops: u64,
    pub net_connect_ops: u64,
    pub net_accept_ops: u64,
    pub net_bytes_tx: u64,
    pub net_bytes_rx: u64,
    pub alloc_ops: u64,
    pub faults_injected: u64,
    pub faults_by_class: BTreeMap<String, u64>,
    pub top_syscalls: Vec<SyscallRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyscallRow {
    pub name: String,
    pub category: String,
    pub count: u64,
    pub errors: u64,
    pub bytes: u64,
    pub total_vtime_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VirtualLatencyBucket {
    pub total_ns: u64,
    pub compute_ns: u64,
    pub io_ns: u64,
    pub fsync_ns: u64,
    pub futex_ns: u64,
    pub net_ns: u64,
    pub wait_sleep_ns: u64,
    pub memory_ns: u64,
    pub fault_ns: u64,
    pub other_ns: u64,
    pub distributions: BTreeMap<String, LatencyDist>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LatencyDist {
    pub count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PatinaTaxBucket {
    pub wall_ms: u64,
    pub traps: u64,
    pub switches: u64,
    pub traps_per_sec: f64,
    pub virtual_to_wall_ratio: f64,
    pub plans_loaded: u64,
    pub rewrite_points: u64,
    pub rewrite_images: u64,
    pub boundary_records: u64,
    pub boundary_log_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MemoryAttribution {
    pub mmap_count: u64,
    pub munmap_count: u64,
    pub mremap_count: u64,
    pub brk_count: u64,
    pub total_allocated_bytes: u64,
    pub total_freed_bytes: u64,
    pub peak_mapped_bytes: u64,
    pub final_mapped_bytes: u64,
    pub timeline: Vec<MemPoint>,
    pub top_allocations: Vec<AllocEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemPoint {
    pub t_us: f64,
    pub mapped_bytes: u64,
    pub delta: i64,
    pub op: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AllocEvent {
    pub t_us: f64,
    pub boot: usize,
    pub slot: u16,
    pub op: String,
    pub bytes: u64,
    pub addr: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CoverageSummary {
    pub edges_hit: u64,
    pub total_hits: u64,
    pub map_size: usize,
    pub density_pct: f64,
    pub unique_hashes: usize,
    pub sample_hashes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreadInfo {
    pub boot: usize,
    pub slot: u16,
    pub label: String,
    pub events: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TimelineEvent {
    pub boot: usize,
    pub slot: u16,
    pub seq: u64,
    pub ts_us: f64,
    pub dur_us: f64,
    pub cat: String,
    pub name: String,
    pub ret: i64,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TraceRawEvent {
    pub ph: &'static str,
    pub pid: usize,
    pub tid: u32,
    pub ts_us: f64,
    pub dur_us: f64,
    pub cat: &'static str,
    pub name: String,
    pub args: Value,
}

// ============================================================================
// Sweep / Campaign Profile Data Structures
// ============================================================================

#[derive(Clone, Debug, Serialize)]
pub struct SweepProfile {
    pub schema: &'static str,
    pub kind: &'static str,
    pub dir: String,
    pub total_runs: usize,
    pub unique_seeds: usize,
    pub findings: usize,
    pub vacuous: bool,
    pub outcomes: BTreeMap<String, usize>,
    pub groups: Vec<SweepGroup>,
    pub runs: Vec<SweepRunRow>,
    pub summary_stats: SweepStats,
}

#[derive(Clone, Debug, Serialize)]
pub struct SweepGroup {
    pub index: usize,
    pub signature: String,
    pub outcome: String,
    pub stop: String,
    pub count: usize,
    pub known: Option<String>,
    pub case: Option<String>,
    pub seeds: Vec<u64>,
    pub example: Option<String>,
    pub faults_every: Vec<String>,
    pub faults_none: Vec<String>,
    pub rerun: String,
    pub replay_command: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SweepRunRow {
    pub seed: u64,
    pub case: Option<String>,
    pub outcome: String,
    pub stop: String,
    pub signature: String,
    pub wall_ms: u64,
    pub virtual_ms: f64,
    pub traps: u64,
    pub switches: u64,
    pub compute_events: u64,
    pub faults_injected: u64,
    pub edges_hit: Option<u64>,
    pub dir: String,
    pub replay_command: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SweepStats {
    pub total_wall_ms: u64,
    pub mean_wall_ms: f64,
    pub p50_wall_ms: u64,
    pub p95_wall_ms: u64,
    pub max_wall_ms: u64,
    pub total_traps: u64,
    pub total_faults_injected: u64,
    pub max_edges_hit: u64,
}

// ============================================================================
// Single-Run Profiler Implementation
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyscallCat {
    Fsync,
    ReadWrite,
    Futex,
    Net,
    SleepTimer,
    Memory,
    Other,
}

impl SyscallCat {
    fn as_str(self) -> &'static str {
        match self {
            SyscallCat::Fsync => "fsync",
            SyscallCat::ReadWrite => "io",
            SyscallCat::Futex => "futex",
            SyscallCat::Net => "net",
            SyscallCat::SleepTimer => "sleep",
            SyscallCat::Memory => "memory",
            SyscallCat::Other => "other",
        }
    }

    fn dist_key(self) -> Option<&'static str> {
        match self {
            SyscallCat::Fsync => Some("fsync"),
            SyscallCat::ReadWrite => Some("read_write"),
            SyscallCat::Futex => Some("futex"),
            SyscallCat::Net => Some("net"),
            SyscallCat::SleepTimer => Some("sleep_timer"),
            SyscallCat::Memory => Some("memory"),
            SyscallCat::Other => None,
        }
    }
}

fn classify_syscall(name: &str) -> SyscallCat {
    match name {
        "fsync" | "fdatasync" | "sync" | "syncfs" | "sync_file_range" => SyscallCat::Fsync,
        "read" | "write" | "pread64" | "pwrite64" | "readv" | "writev" | "preadv" | "pwritev"
        | "preadv2" | "pwritev2" | "open" | "openat" | "openat2" | "close" | "stat" | "fstat"
        | "lstat" | "newfstatat" | "statx" | "getdents" | "getdents64" | "lseek" | "ftruncate"
        | "truncate" | "rename" | "renameat" | "renameat2" | "unlink" | "unlinkat"
        | "fallocate" | "copy_file_range" | "sendfile" | "splice" => SyscallCat::ReadWrite,
        "futex" | "futex_waitv" => SyscallCat::Futex,
        "socket" | "socketpair" | "bind" | "listen" | "accept" | "accept4" | "connect"
        | "sendto" | "recvfrom" | "sendmsg" | "recvmsg" | "sendmmsg" | "recvmmsg" | "shutdown"
        | "getsockname" | "getpeername" | "setsockopt" | "getsockopt" => SyscallCat::Net,
        "nanosleep" | "clock_nanosleep" | "poll" | "ppoll" | "select" | "pselect6"
        | "epoll_wait" | "epoll_pwait" | "epoll_pwait2" | "sched_yield" | "pause" => {
            SyscallCat::SleepTimer
        }
        "mmap" | "munmap" | "mremap" | "brk" | "mprotect" | "madvise" => SyscallCat::Memory,
        _ => SyscallCat::Other,
    }
}

#[derive(Default)]
struct SyscallAccum {
    cat: &'static str,
    count: u64,
    errors: u64,
    bytes: u64,
    total_vtime_ns: u64,
    latencies_ns: Vec<u64>,
}

/// Analyze a single Patina run directory into a structured `RunProfile`.
pub fn profile_run(dir: &Path) -> Res<RunProfile> {
    let run_json = read_json(&dir.join("run.json")).unwrap_or(Value::Null);
    let result_json = read_json(&dir.join("result.json")).unwrap_or(Value::Null);

    let seed = result_json["seed"]
        .as_u64()
        .or_else(|| run_json["seed"].as_u64())
        .unwrap_or(0);
    let outcome = result_json["outcome"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let stop = result_json["stop"].as_str().unwrap_or("").to_string();
    let digest = result_json["digest"].as_str().unwrap_or("").to_string();
    let wall_ms = result_json["wall_ms"].as_u64().unwrap_or(0);
    let program = run_json["config"]["cmd"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty())
        .or_else(|| run_json["program"]["guest"].as_str().map(str::to_string))
        .unwrap_or_else(|| dir.display().to_string());

    let boot_dirs = boots(dir);
    let boots_count = result_json["boots"]
        .as_u64()
        .unwrap_or(boot_dirs.len().max(1) as u64);

    let mut syscalls: BTreeMap<String, SyscallAccum> = BTreeMap::new();
    let mut dist_samples: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let mut thread_counts: BTreeMap<(usize, u16), u64> = BTreeMap::new();
    let mut logical = LogicalIoBucket::default();
    let mut vlat = VirtualLatencyBucket::default();
    let mut mem = MemoryAttribution::default();
    let mut trace_events: Vec<TraceRawEvent> = Vec::new();
    let mut all_timeline: Vec<TimelineEvent> = Vec::new();
    let mut all_mem_points: Vec<MemPoint> = Vec::new();
    let mut all_allocs: Vec<AllocEvent> = Vec::new();

    let mut first_vclock: Option<u64> = None;
    let mut last_vclock: u64 = 0;
    let mut total_records: u64 = 0;
    let mut total_log_bytes: u64 = 0;
    let mut log_compute_switches: u64 = 0;
    let mut log_deadline_stops: u64 = 0;
    let mut log_spin_yields: u64 = 0;

    // Track per-(boot, addr) active mmap sizes and per-(boot, slot) brk watermark.
    let mut active_mmaps: HashMap<(usize, u64), u64> = HashMap::new();
    let mut current_brk: HashMap<usize, u64> = HashMap::new();
    let mut current_mapped: u64 = 0;

    for (boot_idx, bdir) in boot_dirs.iter().enumerate() {
        let boot_num = boot_idx + 1;
        let log_path = bdir.join("boundary.log");
        if let Ok(md) = std::fs::metadata(&log_path) {
            total_log_bytes += md.len();
        }
        let recs = load_boot_records(bdir)?;
        total_records += recs.len() as u64;

        let mut prev_vclock: Option<u64> = None;
        let mut slot_wait_start: HashMap<u16, u64> = HashMap::new();
        let mut slot_fault_delay: HashMap<u16, bool> = HashMap::new();
        let mut last_wait_kind: u8 = 0; // 0=other, 1=sleep, 2=futex, 3=io, 4=fault_delay
        let mut i = 0usize;

        while i < recs.len() {
            let r = recs[i];
            i += 1;

            let v0 = *first_vclock.get_or_insert(r.vclock_ns);
            if r.vclock_ns > last_vclock {
                last_vclock = r.vclock_ns;
            }
            let dt = match prev_vclock {
                Some(p) => r.vclock_ns.saturating_sub(p),
                None => 0,
            };
            let cur_vclock = prev_vclock.map_or(r.vclock_ns, |p| p.max(r.vclock_ns));
            prev_vclock = Some(cur_vclock);

            // Consume any immediately following Str/Name records attached to the same (seq, slot).
            let mut attached_path: Option<String> = None;
            while i < recs.len() {
                let next = recs[i];
                if next.kind == RecKind::Str as u8 && next.seq == r.seq && next.slot == r.slot {
                    let mut st = Str::start(&next);
                    i += 1;
                    while i < recs.len() {
                        if let Some(s) = st.as_mut() {
                            if s.push(&recs[i]) {
                                i += 1;
                                continue;
                            }
                        }
                        break;
                    }
                    if let Some(s) = st {
                        if s.whole() && (s.which == STR_RESOLVED || s.which == STR_PATH) {
                            let txt = String::from_utf8_lossy(&s.bytes).into_owned();
                            if s.which == STR_RESOLVED || attached_path.is_none() {
                                attached_path = Some(txt);
                            }
                        }
                    }
                    continue;
                }
                if next.kind == RecKind::Name as u8 && next.seq == r.seq {
                    let (b, n, _) = next.name_bytes();
                    attached_path = Some(String::from_utf8_lossy(&b[..n]).into_owned());
                    i += 1;
                    continue;
                }
                break;
            }

            let ts_us = cur_vclock.saturating_sub(v0) as f64 / 1000.0;
            let kind = RecKind::from_u8(r.kind);

            match kind {
                Some(RecKind::Trap) => {
                    *thread_counts.entry((boot_num, r.slot)).or_default() += 1;
                    let sname = syscall_name(r.nr as u64);
                    let cat = classify_syscall(sname);
                    logical.total_syscalls += 1;
                    let is_err = r.ret < 0;
                    if is_err {
                        logical.syscall_errors += 1;
                    }

                    // Duration of this syscall: if the slot parked during this syscall, measure
                    // full wait-to-completion virtual latency using cur_vclock (monotonic max
                    // across any idle jump that occurred while blocked).
                    let _ = slot_fault_delay.remove(&r.slot);
                    let wait_dur = slot_wait_start
                        .remove(&r.slot)
                        .map(|t0| cur_vclock.saturating_sub(t0))
                        .unwrap_or(0);
                    let op_dur_ns = wait_dur.max(dt);

                    // Byte volume & operation counters.
                    let mut op_bytes: u64 = 0;
                    match sname {
                        "read" | "pread64" | "readv" | "preadv" | "preadv2" => {
                            logical.read_ops += 1;
                            if r.ret > 0 {
                                op_bytes = r.ret as u64;
                                logical.read_bytes += op_bytes;
                            }
                        }
                        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => {
                            logical.write_ops += 1;
                            if r.ret > 0 {
                                op_bytes = r.ret as u64;
                                logical.write_bytes += op_bytes;
                            }
                        }
                        "fsync" | "fdatasync" | "sync" | "syncfs" | "sync_file_range" => {
                            logical.fsync_ops += 1;
                        }
                        "futex" | "futex_waitv" => {
                            logical.futex_total_ops += 1;
                            let op = r.args[1] & 0x7f;
                            if matches!(op, 0 | 9 | 11) {
                                // FUTEX_WAIT / FUTEX_WAIT_BITSET / FUTEX_WAIT_REQUEUE_PI
                                logical.futex_wait_ops += 1;
                            } else if matches!(op, 1 | 3 | 4 | 5 | 10 | 12) {
                                // FUTEX_WAKE / REQUEUE / CMP_REQUEUE / WAKE_OP / WAKE_BITSET
                                logical.futex_wake_ops += 1;
                            }
                        }
                        "sendto" | "sendmsg" | "sendmmsg" => {
                            logical.net_send_ops += 1;
                            if r.ret > 0 {
                                op_bytes = r.ret as u64;
                                logical.net_bytes_tx += op_bytes;
                            }
                        }
                        "recvfrom" | "recvmsg" | "recvmmsg" => {
                            logical.net_recv_ops += 1;
                            if r.ret > 0 {
                                op_bytes = r.ret as u64;
                                logical.net_bytes_rx += op_bytes;
                            }
                        }
                        "connect" => logical.net_connect_ops += 1,
                        "accept" | "accept4" => logical.net_accept_ops += 1,
                        "mmap" => {
                            logical.alloc_ops += 1;
                            mem.mmap_count += 1;
                            if r.ret > 0 {
                                let len = r.args[1];
                                let addr = r.ret as u64;
                                op_bytes = len;
                                mem.total_allocated_bytes += len;
                                if let Some(prev) = active_mmaps.insert((boot_num, addr), len) {
                                    current_mapped = current_mapped.saturating_sub(prev);
                                }
                                current_mapped = current_mapped.saturating_add(len);
                                mem.peak_mapped_bytes = mem.peak_mapped_bytes.max(current_mapped);
                                all_mem_points.push(MemPoint {
                                    t_us: ts_us,
                                    mapped_bytes: current_mapped,
                                    delta: len as i64,
                                    op: "mmap".into(),
                                });
                                all_allocs.push(AllocEvent {
                                    t_us: ts_us,
                                    boot: boot_num,
                                    slot: r.slot,
                                    op: "mmap".into(),
                                    bytes: len,
                                    addr: format!("{addr:#x}"),
                                });
                                if trace_events.len() < MAX_TRACE_EVENTS {
                                    trace_events.push(TraceRawEvent {
                                        ph: "C",
                                        pid: boot_num,
                                        tid: 0,
                                        ts_us,
                                        dur_us: 0.0,
                                        cat: "memory",
                                        name: "guest_memory_bytes".into(),
                                        args: json!({"mapped_bytes": current_mapped}),
                                    });
                                }
                            }
                        }
                        "munmap" => {
                            logical.alloc_ops += 1;
                            mem.munmap_count += 1;
                            if r.ret == 0 {
                                let addr = r.args[0];
                                let len = r.args[1];
                                op_bytes = len;
                                let removed = active_mmaps.remove(&(boot_num, addr)).unwrap_or(len);
                                let freed = removed.min(current_mapped);
                                mem.total_freed_bytes += freed;
                                current_mapped = current_mapped.saturating_sub(freed);
                                all_mem_points.push(MemPoint {
                                    t_us: ts_us,
                                    mapped_bytes: current_mapped,
                                    delta: -(freed as i64),
                                    op: "munmap".into(),
                                });
                                if trace_events.len() < MAX_TRACE_EVENTS {
                                    trace_events.push(TraceRawEvent {
                                        ph: "C",
                                        pid: boot_num,
                                        tid: 0,
                                        ts_us,
                                        dur_us: 0.0,
                                        cat: "memory",
                                        name: "guest_memory_bytes".into(),
                                        args: json!({"mapped_bytes": current_mapped}),
                                    });
                                }
                            }
                        }
                        "mremap" => {
                            logical.alloc_ops += 1;
                            mem.mremap_count += 1;
                            if r.ret > 0 {
                                let old_addr = r.args[0];
                                let old_size = active_mmaps
                                    .remove(&(boot_num, old_addr))
                                    .unwrap_or(r.args[1]);
                                let new_size = r.args[2];
                                let new_addr = r.ret as u64;
                                op_bytes = new_size;
                                active_mmaps.insert((boot_num, new_addr), new_size);
                                let delta = new_size as i64 - old_size as i64;
                                if delta >= 0 {
                                    mem.total_allocated_bytes += delta as u64;
                                    current_mapped = current_mapped.saturating_add(delta as u64);
                                } else {
                                    let d = (-delta) as u64;
                                    mem.total_freed_bytes += d;
                                    current_mapped = current_mapped.saturating_sub(d);
                                }
                                mem.peak_mapped_bytes = mem.peak_mapped_bytes.max(current_mapped);
                                all_mem_points.push(MemPoint {
                                    t_us: ts_us,
                                    mapped_bytes: current_mapped,
                                    delta,
                                    op: "mremap".into(),
                                });
                                if delta > 0 {
                                    all_allocs.push(AllocEvent {
                                        t_us: ts_us,
                                        boot: boot_num,
                                        slot: r.slot,
                                        op: "mremap".into(),
                                        bytes: delta as u64,
                                        addr: format!("{new_addr:#x}"),
                                    });
                                }
                                if trace_events.len() < MAX_TRACE_EVENTS {
                                    trace_events.push(TraceRawEvent {
                                        ph: "C",
                                        pid: boot_num,
                                        tid: 0,
                                        ts_us,
                                        dur_us: 0.0,
                                        cat: "memory",
                                        name: "guest_memory_bytes".into(),
                                        args: json!({"mapped_bytes": current_mapped}),
                                    });
                                }
                            }
                        }
                        "brk" => {
                            logical.alloc_ops += 1;
                            mem.brk_count += 1;
                            if r.ret > 0 {
                                let new_brk = r.ret as u64;
                                let prev = *current_brk.entry(boot_num).or_insert(new_brk);
                                if new_brk != prev {
                                    let delta = new_brk as i64 - prev as i64;
                                    current_brk.insert(boot_num, new_brk);
                                    if delta > 0 {
                                        op_bytes = delta as u64;
                                        mem.total_allocated_bytes += op_bytes;
                                        current_mapped = current_mapped.saturating_add(op_bytes);
                                        all_allocs.push(AllocEvent {
                                            t_us: ts_us,
                                            boot: boot_num,
                                            slot: r.slot,
                                            op: "brk".into(),
                                            bytes: op_bytes,
                                            addr: format!("{new_brk:#x}"),
                                        });
                                    } else {
                                        let d = (-delta) as u64;
                                        mem.total_freed_bytes += d;
                                        current_mapped = current_mapped.saturating_sub(d);
                                    }
                                    mem.peak_mapped_bytes =
                                        mem.peak_mapped_bytes.max(current_mapped);
                                    all_mem_points.push(MemPoint {
                                        t_us: ts_us,
                                        mapped_bytes: current_mapped,
                                        delta,
                                        op: "brk".into(),
                                    });
                                    if trace_events.len() < MAX_TRACE_EVENTS {
                                        trace_events.push(TraceRawEvent {
                                            ph: "C",
                                            pid: boot_num,
                                            tid: 0,
                                            ts_us,
                                            dur_us: 0.0,
                                            cat: "memory",
                                            name: "guest_memory_bytes".into(),
                                            args: json!({"mapped_bytes": current_mapped}),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    // Modeled virtual latency bucket attribution (incremental dt sums to total_ns).
                    match cat {
                        SyscallCat::Fsync => vlat.fsync_ns += dt,
                        SyscallCat::ReadWrite => vlat.io_ns += dt,
                        SyscallCat::Futex => vlat.futex_ns += dt,
                        SyscallCat::Net => vlat.net_ns += dt,
                        SyscallCat::SleepTimer => vlat.wait_sleep_ns += dt,
                        SyscallCat::Memory => vlat.memory_ns += dt,
                        SyscallCat::Other => vlat.other_ns += dt,
                    }

                    if let Some(dk) = cat.dist_key() {
                        dist_samples.entry(dk).or_default().push(op_dur_ns);
                    }

                    let entry = syscalls
                        .entry(sname.to_string())
                        .or_insert_with(|| SyscallAccum {
                            cat: cat.as_str(),
                            ..Default::default()
                        });
                    entry.count += 1;
                    if is_err {
                        entry.errors += 1;
                    }
                    entry.bytes += op_bytes;
                    entry.total_vtime_ns += op_dur_ns;
                    entry.latencies_ns.push(op_dur_ns);

                    let start_us = (ts_us - op_dur_ns as f64 / 1000.0).max(0.0);
                    let dur_us = (op_dur_ns as f64 / 1000.0).max(0.1);
                    if trace_events.len() < MAX_TRACE_EVENTS {
                        let mut a = json!({"seq": r.seq, "ret": r.ret});
                        if op_bytes > 0 {
                            a["bytes"] = json!(op_bytes);
                        }
                        if let Some(p) = &attached_path {
                            a["path"] = json!(p);
                        }
                        trace_events.push(TraceRawEvent {
                            ph: "X",
                            pid: boot_num,
                            tid: r.slot as u32 + 1,
                            ts_us: start_us,
                            dur_us,
                            cat: cat.as_str(),
                            name: sname.to_string(),
                            args: a,
                        });
                    }
                    all_timeline.push(TimelineEvent {
                        boot: boot_num,
                        slot: r.slot,
                        seq: r.seq,
                        ts_us: start_us,
                        dur_us,
                        cat: cat.as_str().to_string(),
                        name: sname.to_string(),
                        ret: r.ret,
                        bytes: op_bytes,
                        detail: attached_path,
                    });
                }
                Some(RecKind::Preempt) => {
                    *thread_counts.entry((boot_num, r.slot)).or_default() += 1;
                    vlat.compute_ns += dt;
                    let ev_name = match r.nr {
                        2 => {
                            log_spin_yields += 1;
                            "spin_point"
                        }
                        proto::compute::PREEMPT_NR => match r.args[2] & 0xffff_ffff {
                            proto::compute::REASON_DEADLINE => {
                                log_deadline_stops += 1;
                                "compute_deadline"
                            }
                            proto::compute::REASON_REFILL => "compute_refill",
                            _ => {
                                log_compute_switches += 1;
                                "compute_switch"
                            }
                        },
                        _ => "preempt",
                    };
                    if trace_events.len() < MAX_TRACE_EVENTS {
                        trace_events.push(TraceRawEvent {
                            ph: "i",
                            pid: boot_num,
                            tid: r.slot as u32 + 1,
                            ts_us,
                            dur_us: 0.0,
                            cat: "compute",
                            name: ev_name.to_string(),
                            args: json!({"seq": r.seq, "pc": format!("{:#x}", r.args[0])}),
                        });
                    }
                    all_timeline.push(TimelineEvent {
                        boot: boot_num,
                        slot: r.slot,
                        seq: r.seq,
                        ts_us,
                        dur_us: (dt as f64 / 1000.0).max(0.5),
                        cat: "compute".into(),
                        name: ev_name.into(),
                        ret: 0,
                        bytes: 0,
                        detail: Some(format!("pc={:#x}", r.args[0])),
                    });
                }
                Some(RecKind::Injected) => {
                    *thread_counts.entry((boot_num, r.slot)).or_default() += 1;
                    vlat.fault_ns += dt;
                    logical.faults_injected += 1;
                    let class_name = match r.args[0] {
                        proto::faults::INJ_ERROR => "fs-error".to_string(),
                        proto::faults::INJ_SHORT => "fs-short".to_string(),
                        proto::faults::INJ_DELAY => {
                            slot_fault_delay.insert(r.slot, true);
                            "fs-delay".to_string()
                        }
                        proto::faults::INJ_FSYNC_EIO | proto::faults::INJ_FSYNC_REPORT => {
                            "fsync-error".to_string()
                        }
                        proto::faults::INJ_MEM_LIMIT => "mem-limit".to_string(),
                        proto::faults::INJ_PATH_SWAP => "path-swap".to_string(),
                        other => format!("fault-{other}"),
                    };
                    *logical
                        .faults_by_class
                        .entry(class_name.clone())
                        .or_default() += 1;
                    let sname = syscall_name(r.nr as u64);
                    let detail = match &attached_path {
                        Some(p) => format!("{class_name} on {sname} ({p})"),
                        None => format!("{class_name} on {sname}"),
                    };
                    if trace_events.len() < MAX_TRACE_EVENTS {
                        trace_events.push(TraceRawEvent {
                            ph: "i",
                            pid: boot_num,
                            tid: r.slot as u32 + 1,
                            ts_us,
                            dur_us: 0.0,
                            cat: "fault",
                            name: format!("fault:{class_name}"),
                            args: json!({
                                "seq": r.seq,
                                "syscall": sname,
                                "value": r.args[2],
                                "path": attached_path,
                            }),
                        });
                    }
                    all_timeline.push(TimelineEvent {
                        boot: boot_num,
                        slot: r.slot,
                        seq: r.seq,
                        ts_us,
                        dur_us: (dt as f64 / 1000.0).max(1.0),
                        cat: "fault".into(),
                        name: format!("fault:{class_name}"),
                        ret: r.ret,
                        bytes: 0,
                        detail: Some(detail),
                    });
                }
                Some(RecKind::SupDecision) => {
                    if r.nr == proto::ctl::DEC_IDLE_JUMP {
                        match last_wait_kind {
                            1 => vlat.wait_sleep_ns += dt,
                            2 => vlat.futex_ns += dt,
                            3 => vlat.io_ns += dt,
                            4 => vlat.fault_ns += dt,
                            _ => vlat.wait_sleep_ns += dt,
                        }
                    } else {
                        match Op::from_u32(r.nr) {
                            Some(Op::Sleep) => {
                                if slot_fault_delay.remove(&r.slot).unwrap_or(false) {
                                    vlat.fault_ns += dt;
                                    last_wait_kind = 4;
                                } else {
                                    vlat.wait_sleep_ns += dt;
                                    last_wait_kind = 1;
                                }
                                slot_wait_start.entry(r.slot).or_insert(r.vclock_ns);
                            }
                            Some(Op::FutexWait) => {
                                vlat.futex_ns += dt;
                                last_wait_kind = 2;
                                slot_wait_start.entry(r.slot).or_insert(r.vclock_ns);
                            }
                            Some(Op::FutexWake | Op::FutexRequeue) => {
                                vlat.futex_ns += dt;
                            }
                            Some(Op::Park) => {
                                vlat.io_ns += dt;
                                last_wait_kind = 3;
                                slot_wait_start.entry(r.slot).or_insert(r.vclock_ns);
                            }
                            Some(Op::WaitPark) => {
                                vlat.wait_sleep_ns += dt;
                                last_wait_kind = 1;
                                slot_wait_start.entry(r.slot).or_insert(r.vclock_ns);
                            }
                            _ => {
                                vlat.other_ns += dt;
                            }
                        }
                    }
                }
                Some(RecKind::SignalDelivery) => {
                    vlat.other_ns += dt;
                    if trace_events.len() < MAX_TRACE_EVENTS {
                        trace_events.push(TraceRawEvent {
                            ph: "i",
                            pid: boot_num,
                            tid: r.slot as u32 + 1,
                            ts_us,
                            dur_us: 0.0,
                            cat: "signal",
                            name: format!("sig {}", r.nr),
                            args: json!({"seq": r.seq, "signal": r.nr}),
                        });
                    }
                }
                Some(RecKind::CrashPoint) => {
                    vlat.fault_ns += dt;
                    if trace_events.len() < MAX_TRACE_EVENTS {
                        trace_events.push(TraceRawEvent {
                            ph: "i",
                            pid: boot_num,
                            tid: r.slot as u32 + 1,
                            ts_us,
                            dur_us: 0.0,
                            cat: "fault",
                            name: "crash_point".into(),
                            args: json!({"seq": r.seq}),
                        });
                    }
                }
                _ => {
                    vlat.other_ns += dt;
                }
            }
        }
    }

    let virtual_duration_ns = match first_vclock {
        Some(v0) => last_vclock.saturating_sub(v0),
        None => 0,
    };

    // Bucket 1: Guest User Compute.
    let compute_events = result_json["compute"]["events"].as_u64().unwrap_or(0);
    let charge_per_event = result_json["compute"]["charge_ns"]
        .as_u64()
        .unwrap_or(proto::compute::CHARGE_NS);
    let compute_charge_ns = compute_events.saturating_mul(charge_per_event);
    let compute_switches = result_json["compute"]["switches"]
        .as_u64()
        .unwrap_or(log_compute_switches);
    let deadline_stops = result_json["compute"]["deadline_stops"]
        .as_u64()
        .unwrap_or(log_deadline_stops);
    let spin_yields = result_json["counters"]["sched"]["spin_yields"]
        .as_u64()
        .unwrap_or(log_spin_yields);
    let pause_points = result_json["sched"]["pause_points"].as_u64().unwrap_or(0);

    // If result.json had fault counts (e.g., when boundary.log was pruned), backfill faults_injected.
    if logical.faults_injected == 0 {
        if let Some(inj) = result_json["faults"]["injected"].as_u64() {
            logical.faults_injected = inj;
        }
        if let Some(counts) = result_json["faults"]["counts"].as_object() {
            for (k, v) in counts {
                let n = v["injected"].as_u64().unwrap_or(0);
                if n > 0 {
                    logical.faults_by_class.insert(k.clone(), n);
                }
            }
        }
    }

    // Reconcile compute_ns in virtual_latency with exact compute_charge_ns when logs only record
    // traps/switches while compute charge accrued between traps.
    if compute_charge_ns > vlat.compute_ns && virtual_duration_ns > 0 {
        let extra = compute_charge_ns.min(virtual_duration_ns) - vlat.compute_ns;
        vlat.compute_ns += extra;
        // Trim proportionally from other_ns / io_ns so total stays bounded by virtual_duration_ns.
        let trim_other = extra.min(vlat.other_ns);
        vlat.other_ns -= trim_other;
        let rem = extra - trim_other;
        let trim_io = rem.min(vlat.io_ns);
        vlat.io_ns -= trim_io;
    }
    vlat.total_ns = virtual_duration_ns.max(
        vlat.compute_ns
            + vlat.io_ns
            + vlat.fsync_ns
            + vlat.futex_ns
            + vlat.net_ns
            + vlat.wait_sleep_ns
            + vlat.memory_ns
            + vlat.fault_ns
            + vlat.other_ns,
    );

    let virtual_share_pct = if vlat.total_ns > 0 {
        (vlat.compute_ns as f64 / vlat.total_ns as f64) * 100.0
    } else {
        0.0
    };

    // Latency distributions (p50/p95/p99/max) per category.
    for (cat_name, mut samples) in dist_samples {
        if samples.is_empty() {
            continue;
        }
        vlat.distributions
            .insert(cat_name.to_string(), compute_dist(&mut samples));
    }

    // Top syscalls table sorted by total_vtime_ns desc, then count desc, then name.
    let mut top_syscalls: Vec<SyscallRow> = syscalls
        .into_iter()
        .map(|(name, mut acc)| {
            let dist = compute_dist(&mut acc.latencies_ns);
            SyscallRow {
                name,
                category: acc.cat.to_string(),
                count: acc.count,
                errors: acc.errors,
                bytes: acc.bytes,
                total_vtime_ns: acc.total_vtime_ns,
                p50_ns: dist.p50_ns,
                p95_ns: dist.p95_ns,
                p99_ns: dist.p99_ns,
                max_ns: dist.max_ns,
            }
        })
        .collect();
    top_syscalls.sort_by(|a, b| {
        b.total_vtime_ns
            .cmp(&a.total_vtime_ns)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.name.cmp(&b.name))
    });
    logical.top_syscalls = top_syscalls;

    // Decode & symbolize deterministic CPU profile sidecars (boot-*/cpu_profile.bin) if present.
    let interval = run_json["config"]["profile-cpu-interval"]
        .as_u64()
        .unwrap_or(0);
    let cpu_profile = load_cpu_profiles(
        dir,
        &boot_dirs,
        &run_json,
        interval,
        first_vclock.unwrap_or(0),
        &mut trace_events,
    )?;

    let guest_compute = GuestComputeBucket {
        compute_events,
        compute_charge_ns,
        compute_switches,
        deadline_stops,
        spin_yields,
        pause_points,
        virtual_share_pct,
        cpu_profile,
    };

    // Bucket 4: Patina Runtime Tax.
    let traps = result_json["sched"]["traps"]
        .as_u64()
        .unwrap_or(logical.total_syscalls);
    let switches = result_json["sched"]["switches"].as_u64().unwrap_or(0);
    let wall_secs = (wall_ms as f64) / 1000.0;
    let traps_per_sec = if wall_secs > 0.0 {
        traps as f64 / wall_secs
    } else {
        0.0
    };
    let virtual_to_wall_ratio = if wall_ms > 0 {
        (virtual_duration_ns as f64 / 1_000_000.0) / wall_ms as f64
    } else {
        0.0
    };
    let plans_loaded = result_json["rewrite"]["plans"].as_u64().unwrap_or(0);
    let rewrite_points = result_json["rewrite"]["points"].as_u64().unwrap_or(0);
    let rewrite_images = result_json["rewrite"]["images"]
        .as_array()
        .map_or(0, |a| a.len() as u64);

    let patina_tax = PatinaTaxBucket {
        wall_ms,
        traps,
        switches,
        traps_per_sec,
        virtual_to_wall_ratio,
        plans_loaded,
        rewrite_points,
        rewrite_images,
        boundary_records: total_records,
        boundary_log_bytes: total_log_bytes,
    };

    // Memory attribution finalization.
    mem.final_mapped_bytes = current_mapped;
    mem.timeline = downsample_mem_points(all_mem_points, MAX_MEM_POINTS_HTML);
    all_allocs.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.t_us.total_cmp(&b.t_us))
    });
    all_allocs.truncate(20);
    mem.top_allocations = all_allocs;

    // Edge coverage from result.json if present.
    let coverage = result_json["coverage"].as_object().map(|cov| {
        let edges_hit = cov.get("edges_hit").and_then(|v| v.as_u64()).unwrap_or(0);
        let total_hits = cov.get("total_hits").and_then(|v| v.as_u64()).unwrap_or(0);
        let hashes: Vec<String> = cov
            .get("edge_hashes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|h| format!("{h:016x}")))
                    .collect()
            })
            .unwrap_or_default();
        let unique_hashes = hashes.len();
        let sample_hashes = hashes.into_iter().take(32).collect();
        let map_size = proto::plan::COVERAGE_SIZE;
        CoverageSummary {
            edges_hit,
            total_hits,
            map_size: map_size as usize,
            density_pct: (edges_hit as f64 / map_size as f64) * 100.0,
            unique_hashes,
            sample_hashes,
        }
    });

    // Thread metadata.
    let threads: Vec<ThreadInfo> = thread_counts
        .into_iter()
        .map(|((boot, slot), events)| ThreadInfo {
            boot,
            slot,
            label: format!("boot-{boot} / slot-{slot}"),
            events,
        })
        .collect();

    // Downsample HTML timeline events deterministically while preserving faults & slow ops.
    let timeline_events = downsample_timeline(all_timeline, MAX_TIMELINE_EVENTS_HTML);

    Ok(RunProfile {
        schema: PROFILE_SCHEMA,
        kind: "run",
        dir: dir.display().to_string(),
        program,
        seed,
        outcome,
        stop,
        digest,
        boots: boots_count,
        virtual_duration_ns,
        wall_ms,
        guest_compute,
        logical_io: logical,
        virtual_latency: vlat,
        patina_tax,
        memory: mem,
        coverage,
        threads,
        timeline_events,
        trace_events,
    })
}

/// Load all boundary records of a boot, supporting both uncut and sweep-cut logs.
fn load_boot_records(bdir: &Path) -> Res<Vec<Rec>> {
    let log = bdir.join("boundary.log");
    if !log.is_file() {
        return Ok(vec![]);
    }
    let mut recs = read_rec_file(&log)?;
    if bdir.join("boundary.cut").is_file() {
        let tail = bdir.join("boundary.tail");
        if tail.is_file() {
            recs.extend(read_rec_file(&tail)?);
        }
        // Keep clippy happy that `Cut` is referenced if needed; validate cut file cleanly.
        let _ = read_json(&bdir.join("boundary.cut"))
            .ok()
            .and_then(|v| serde_json::from_value::<Cut>(v).ok());
    }
    Ok(recs)
}

fn read_rec_file(path: &Path) -> Res<Vec<Rec>> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (chunks, _) = bytes.as_chunks::<REC_SIZE>();
    let mut out = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        out.push(Rec::from_bytes(chunk));
    }
    Ok(out)
}

/// Compute exact deterministic percentiles (p50, p95, p99, min, max) over `samples`.
pub fn compute_dist(samples: &mut [u64]) -> LatencyDist {
    if samples.is_empty() {
        return LatencyDist::default();
    }
    samples.sort_unstable();
    let n = samples.len();
    let total_ns: u64 = samples.iter().copied().sum();
    let pct = |p: usize| -> u64 {
        let idx = ((n - 1) * p) / 100;
        samples[idx]
    };
    LatencyDist {
        count: n as u64,
        total_ns,
        min_ns: samples[0],
        p50_ns: pct(50),
        p95_ns: pct(95),
        p99_ns: pct(99),
        max_ns: samples[n - 1],
    }
}

fn downsample_mem_points(pts: Vec<MemPoint>, cap: usize) -> Vec<MemPoint> {
    if pts.len() <= cap || cap < 2 {
        return pts;
    }
    let mut out = Vec::with_capacity(cap);
    let step = (pts.len() - 1) as f64 / (cap - 1) as f64;
    for i in 0..cap {
        let idx = ((i as f64 * step).round() as usize).min(pts.len() - 1);
        out.push(pts[idx].clone());
    }
    out
}

fn downsample_timeline(events: Vec<TimelineEvent>, cap: usize) -> Vec<TimelineEvent> {
    if events.len() <= cap || cap < 2 {
        return events;
    }
    // Always preserve faults, then stride uniformly across the rest.
    let mut out = Vec::with_capacity(cap);
    let step = (events.len() - 1) as f64 / (cap - 1) as f64;
    let mut picked = vec![false; events.len()];
    for (idx, ev) in events.iter().enumerate() {
        if ev.cat == "fault" && out.len() < cap / 4 {
            picked[idx] = true;
            out.push(ev.clone());
        }
    }
    let rem = cap.saturating_sub(out.len());
    if rem > 0 {
        for i in 0..rem {
            let idx = ((i as f64 * step).round() as usize).min(events.len() - 1);
            if !picked[idx] {
                picked[idx] = true;
                out.push(events[idx].clone());
            }
        }
    }
    out.sort_by(|a, b| a.ts_us.total_cmp(&b.ts_us).then_with(|| a.seq.cmp(&b.seq)));
    out
}

// ============================================================================
// Deterministic CPU Profile Decoder & ELF Symbolizer
// ============================================================================

type SymbolTable = Vec<(u64, u64, String)>;
type CachedElf = (Option<SymbolTable>, Option<Vec<u8>>);

struct MappedImage {
    pid: u32,
    start: u64,
    end: u64,
    bias: u64,
    module: String,
    symbols: SymbolTable,
}

struct SymbolCache {
    by_host: HashMap<PathBuf, CachedElf>,
    program_guest: Option<String>,
    program_host: Option<PathBuf>,
    machine_progs: Vec<(String, PathBuf)>,
    mounts: Vec<(String, PathBuf)>,
}

impl SymbolCache {
    fn from_run_json(run_json: &Value) -> Self {
        let program_guest = run_json["program"]["guest"].as_str().map(str::to_string);
        let program_host = run_json["program"]["host"].as_str().map(PathBuf::from);
        let mut machine_progs = Vec::new();
        if let Some(arr) = run_json["machine_programs"].as_array() {
            for m in arr {
                if let (Some(g), Some(h)) = (m["guest"].as_str(), m["host"].as_str()) {
                    machine_progs.push((g.to_string(), PathBuf::from(h)));
                }
            }
        }
        let mut mounts = Vec::new();
        if let Some(arr) = run_json["config"]["mounts"].as_array() {
            for m in arr {
                if let (Some(src), Some(dst)) = (m["src"].as_str(), m["dst"].as_str()) {
                    mounts.push((dst.to_string(), PathBuf::from(src)));
                }
            }
        }
        Self {
            by_host: HashMap::new(),
            program_guest,
            program_host,
            machine_progs,
            mounts,
        }
    }

    fn resolve_host(&self, guest_path: &str) -> Option<PathBuf> {
        if self.program_guest.as_deref() == Some(guest_path) {
            if let Some(h) = &self.program_host {
                if h.is_file() {
                    return Some(h.clone());
                }
            }
        }
        for (g, h) in &self.machine_progs {
            if g == guest_path && h.is_file() {
                return Some(h.clone());
            }
        }
        for (dst, src) in &self.mounts {
            if let Some(rest) = guest_path.strip_prefix(&format!("{dst}/")) {
                let candidate = src.join(rest);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        let direct = Path::new(guest_path);
        if direct.is_file() {
            return Some(direct.to_path_buf());
        }
        // Handle /lib -> /usr/lib and /lib64 -> /usr/lib64 symlinks on merged-usr hosts.
        for (prefix, repl) in [("/lib/", "/usr/lib/"), ("/lib64/", "/usr/lib64/")] {
            if let Some(rest) = guest_path.strip_prefix(prefix) {
                let c = Path::new(repl).join(rest);
                if c.is_file() {
                    return Some(c);
                }
            }
        }
        None
    }

    fn load_elf_info(
        &mut self,
        guest_path: &str,
        start: u64,
        raw_bias: u64,
        file_off: u64,
    ) -> (u64, Vec<(u64, u64, String)>) {
        let Some(host) = self.resolve_host(guest_path) else {
            let bias = if raw_bias == u64::MAX {
                start
            } else {
                raw_bias
            };
            return (bias, Vec::new());
        };
        let entry = self.by_host.entry(host.clone()).or_insert_with(|| {
            let bytes = std::fs::read(&host).ok();
            let syms = bytes
                .as_deref()
                .and_then(|b| crate::rewrite::elf::Elf::parse(b).ok())
                .map(|elf| elf.symbols());
            (syms, bytes)
        });
        let effective_bias = if raw_bias == u64::MAX {
            entry
                .1
                .as_deref()
                .and_then(|b| crate::rewrite::elf::Elf::parse(b).ok())
                .and_then(|elf| elf.vaddr_at_offset(file_off))
                .map(|vaddr| start.wrapping_sub(vaddr))
                .unwrap_or(start)
        } else {
            raw_bias
        };
        let syms = entry.0.clone().unwrap_or_default();
        (effective_bias, syms)
    }
}

fn symbolize_pc(images: &[MappedImage], pid: u32, pc: u64) -> (String, String) {
    // Prefer an image belonging to the exact pid (latest mapping wins for exec/dlopen),
    // then fall back to any image containing pc (e.g. forked child inheriting parent mappings).
    let img = images
        .iter()
        .rev()
        .find(|m| m.pid == pid && pc >= m.start && pc < m.end)
        .or_else(|| images.iter().rev().find(|m| pc >= m.start && pc < m.end));

    let Some(img) = img else {
        return (format!("[unknown {pc:#x}]"), "unknown".into());
    };
    let vaddr = pc.wrapping_sub(img.bias);
    if !img.symbols.is_empty() {
        let idx = img.symbols.partition_point(|(addr, _, _)| *addr <= vaddr);
        if idx > 0 {
            let (saddr, ssize, ref sname) = img.symbols[idx - 1];
            let within = if ssize > 0 {
                vaddr < saddr.saturating_add(ssize)
            } else {
                vaddr.saturating_sub(saddr) < 64 * 1024
            };
            if within {
                return (clean_symbol(sname), img.module.clone());
            }
        }
    }
    (format!("{}+{vaddr:#x}", img.module), img.module.clone())
}

/// Clean symbol names for folded flamegraphs (never contain `;` or newlines).
fn clean_symbol(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ';' | '\n' | '\r' => '_',
            _ => c,
        })
        .collect()
}

fn load_cpu_profiles(
    _run_dir: &Path,
    boot_dirs: &[PathBuf],
    run_json: &Value,
    interval: u64,
    first_vclock: u64,
    trace_events: &mut Vec<TraceRawEvent>,
) -> Res<Option<CpuProfileSummary>> {
    let mut found_any = false;
    let mut cache = SymbolCache::from_run_json(run_json);
    let mut folded: BTreeMap<String, u64> = BTreeMap::new();
    let mut func_self: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut func_total: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut total_samples: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut rt_frames_filtered: u64 = 0;
    let mut images_loaded: usize = 0;

    for (boot_idx, bdir) in boot_dirs.iter().enumerate() {
        let path = bdir.join("cpu_profile.bin");
        if !path.is_file() {
            continue;
        }
        found_any = true;
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if data.len() < HEADER_LEN {
            continue;
        }
        if data[..8] != MAGIC {
            return Err(format!("{}: invalid cpu_profile.bin magic", path.display()));
        }
        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(format!(
                "{}: unsupported cpu_profile.bin version {version}",
                path.display()
            ));
        }

        let mut images: Vec<MappedImage> = Vec::new();
        let mut off = HEADER_LEN;
        let boot_num = boot_idx + 1;

        while off + 4 <= data.len() {
            let kind = data[off];
            let payload_len =
                u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + payload_len > data.len() {
                break;
            }
            let p = &data[off..off + payload_len];
            off += payload_len;

            match kind {
                KIND_IMAGE if p.len() >= 42 => {
                    let pid = u32::from_le_bytes(p[0..4].try_into().unwrap());
                    let start = u64::from_le_bytes(p[8..16].try_into().unwrap());
                    let end = u64::from_le_bytes(p[16..24].try_into().unwrap());
                    let raw_bias = u64::from_le_bytes(p[24..32].try_into().unwrap());
                    let file_off = u64::from_le_bytes(p[32..40].try_into().unwrap());
                    let plen = u16::from_le_bytes(p[40..42].try_into().unwrap()) as usize;
                    if 42 + plen > p.len() {
                        continue;
                    }
                    let guest_path = String::from_utf8_lossy(&p[42..42 + plen]).into_owned();
                    let module = Path::new(&guest_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&guest_path)
                        .to_string();
                    let (bias, symbols) =
                        cache.load_elf_info(&guest_path, start, raw_bias, file_off);
                    images.push(MappedImage {
                        pid,
                        start,
                        end,
                        bias,
                        module,
                        symbols,
                    });
                    images_loaded += 1;
                }
                KIND_SAMPLE if p.len() >= 36 => {
                    let vclock_ns = u64::from_le_bytes(p[0..8].try_into().unwrap());
                    let seq = u64::from_le_bytes(p[8..16].try_into().unwrap());
                    let weight = u64::from_le_bytes(p[16..24].try_into().unwrap()).max(1);
                    let pid = u32::from_le_bytes(p[24..28].try_into().unwrap());
                    let slot = u16::from_le_bytes(p[32..34].try_into().unwrap());
                    let depth = u16::from_le_bytes(p[34..36].try_into().unwrap()) as usize;
                    if 36 + 8 * depth > p.len() {
                        continue;
                    }

                    let mut resolved: Vec<(String, String)> = Vec::with_capacity(depth);
                    for i in 0..depth {
                        let o = 36 + 8 * i;
                        let pc = u64::from_le_bytes(p[o..o + 8].try_into().unwrap());
                        if pc == 0 {
                            continue;
                        }
                        if (RT_BASE..RT_REGION_END).contains(&pc) {
                            rt_frames_filtered += 1;
                            continue;
                        }
                        // Return addresses (frame > 0) point one instruction past the call site.
                        let lookup_pc = if i > 0 { pc.saturating_sub(1) } else { pc };
                        resolved.push(symbolize_pc(&images, pid, lookup_pc));
                    }

                    if resolved.is_empty() {
                        continue;
                    }

                    total_samples += 1;
                    total_weight += weight;

                    // Leaf frame (index 0) gets self_weight.
                    *func_self.entry(resolved[0].clone()).or_default() += weight;
                    // Every distinct function in the stack gets total_weight (inclusive, no double count on recursion).
                    let mut seen_in_stack: Vec<&(String, String)> = Vec::new();
                    for f in &resolved {
                        if !seen_in_stack.contains(&f) {
                            seen_in_stack.push(f);
                            *func_total.entry(f.clone()).or_default() += weight;
                        }
                    }

                    // Folded stack is root-to-leaf (outermost -> innermost).
                    let stack_str: String = resolved
                        .iter()
                        .rev()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(";");
                    *folded.entry(stack_str.clone()).or_default() += weight;

                    if trace_events.len() < MAX_TRACE_EVENTS {
                        let ts_us = vclock_ns.saturating_sub(first_vclock) as f64 / 1000.0;
                        trace_events.push(TraceRawEvent {
                            ph: "i",
                            pid: boot_num,
                            tid: slot as u32 + 1,
                            ts_us,
                            dur_us: 0.0,
                            cat: "cpu_sample",
                            name: resolved[0].0.clone(),
                            args: json!({
                                "seq": seq,
                                "weight": weight,
                                "stack": stack_str,
                            }),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    if !found_any {
        return Ok(None);
    }

    let mut top_functions: Vec<FunctionSample> = func_total
        .into_iter()
        .map(|((name, module), total_w)| {
            let self_w = func_self
                .get(&(name.clone(), module.clone()))
                .copied()
                .unwrap_or(0);
            let denom = total_weight.max(1) as f64;
            FunctionSample {
                name,
                module,
                self_weight: self_w,
                total_weight: total_w,
                self_pct: (self_w as f64 / denom) * 100.0,
                total_pct: (total_w as f64 / denom) * 100.0,
            }
        })
        .collect();
    top_functions.sort_by(|a, b| {
        b.self_weight
            .cmp(&a.self_weight)
            .then_with(|| b.total_weight.cmp(&a.total_weight))
            .then_with(|| a.name.cmp(&b.name))
    });
    top_functions.truncate(50);

    let folded_stacks: Vec<FoldedStack> = folded
        .into_iter()
        .map(|(stack, weight)| FoldedStack { stack, weight })
        .collect();

    Ok(Some(CpuProfileSummary {
        interval,
        total_samples,
        total_weight,
        rt_frames_filtered,
        images_loaded,
        top_functions,
        folded_stacks,
    }))
}

// ============================================================================
// Perfetto / Chrome Trace Event JSON Builder
// ============================================================================

pub fn build_perfetto_trace(run: &RunProfile) -> Value {
    let mut events: Vec<Value> = Vec::with_capacity(run.trace_events.len() + run.threads.len() + 8);

    // Process metadata per boot.
    let max_boot = run.boots.max(1) as usize;
    for b in 1..=max_boot {
        events.push(json!({
            "name": "process_name",
            "ph": "M",
            "pid": b,
            "tid": 0,
            "args": {"name": format!("patina boot-{b} (seed {})", run.seed)}
        }));
    }
    for t in &run.threads {
        events.push(json!({
            "name": "thread_name",
            "ph": "M",
            "pid": t.boot,
            "tid": t.slot as u32 + 1,
            "args": {"name": format!("guest-slot-{}", t.slot)}
        }));
    }

    for ev in &run.trace_events {
        let mut obj = json!({
            "name": ev.name,
            "cat": ev.cat,
            "ph": ev.ph,
            "ts": ev.ts_us,
            "pid": ev.pid,
            "tid": ev.tid,
            "args": ev.args,
        });
        if ev.ph == "X" {
            obj["dur"] = json!(ev.dur_us);
        } else if ev.ph == "i" {
            obj["s"] = json!("t");
        }
        events.push(obj);
    }

    json!({
        "traceEvents": events,
        "displayTimeUnit": "ms",
        "otherData": {
            "generator": "patina inspect",
            "schema": PROFILE_SCHEMA,
            "seed": run.seed,
            "digest": run.digest,
            "outcome": run.outcome,
        }
    })
}

// ============================================================================
// Sweep / Campaign Profiler Implementation
// ============================================================================

pub fn profile_sweep(dir: &Path) -> Res<SweepProfile> {
    let runs = crate::report::collect(&[dir.to_path_buf()])?;
    let report_val = if let Ok(v) = read_json(&dir.join("report.json")) {
        v
    } else {
        crate::report::build(&runs, &[], None, None, "patina inspect summary").0
    };

    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    if let Some(obj) = report_val["outcomes"].as_object() {
        for (k, v) in obj {
            outcomes.insert(k.clone(), v.as_u64().unwrap_or(0) as usize);
        }
    }

    let mut groups = Vec::new();
    if let Some(arr) = report_val["groups"].as_array() {
        for (idx, g) in arr.iter().enumerate() {
            let seeds: Vec<u64> = g["seeds"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_u64())
                .collect();
            let faults_every: Vec<String> = g["faults"]["every"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            let faults_none: Vec<String> = g["faults"]["none"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            groups.push(SweepGroup {
                index: idx + 1,
                signature: g["signature"].as_str().unwrap_or("?").to_string(),
                outcome: g["outcome"].as_str().unwrap_or("?").to_string(),
                stop: g["stop"].as_str().unwrap_or("").to_string(),
                count: g["count"].as_u64().unwrap_or(0) as usize,
                known: g["known"].as_str().map(str::to_string),
                case: g["case"].as_str().map(str::to_string),
                seeds,
                example: g["example"].as_str().map(str::to_string),
                faults_every,
                faults_none,
                rerun: g["rerun"].as_str().unwrap_or("").to_string(),
                replay_command: g["replay_command"].as_str().unwrap_or("").to_string(),
            });
        }
    }

    let mut run_rows = Vec::with_capacity(runs.len());
    let mut wall_samples = Vec::with_capacity(runs.len());
    let mut total_wall_ms = 0u64;
    let mut total_traps = 0u64;
    let mut total_faults_injected = 0u64;
    let mut max_edges_hit = 0u64;

    for r in &runs {
        let outcome = r.result["outcome"].as_str().unwrap_or("?").to_string();
        let stop = r.result["stop"].as_str().unwrap_or("").to_string();
        let signature = crate::report::signature_of(&r.result);
        let wall_ms = r.result["wall_ms"].as_u64().unwrap_or(0);
        let traps = r.result["sched"]["traps"].as_u64().unwrap_or(0);
        let switches = r.result["sched"]["switches"].as_u64().unwrap_or(0);
        let compute_events = r.result["compute"]["events"].as_u64().unwrap_or(0);
        let faults_injected = r.result["faults"]["injected"].as_u64().unwrap_or(0);
        let edges_hit = r.result["coverage"]["edges_hit"].as_u64();
        let virtual_ms = quick_virtual_duration_ms(&r.dir, traps, compute_events);

        total_wall_ms += wall_ms;
        total_traps += traps;
        total_faults_injected += faults_injected;
        if let Some(e) = edges_hit {
            max_edges_hit = max_edges_hit.max(e);
        }
        wall_samples.push(wall_ms);

        run_rows.push(SweepRunRow {
            seed: r.seed,
            case: r.case.clone(),
            outcome,
            stop,
            signature,
            wall_ms,
            virtual_ms,
            traps,
            switches,
            compute_events,
            faults_injected,
            edges_hit,
            dir: r.dir.display().to_string(),
            replay_command: format!(
                "patina replay {}",
                crate::report::quote(&r.dir.display().to_string())
            ),
        });
    }

    let dist = compute_dist(&mut wall_samples);
    let mean_wall_ms = if !run_rows.is_empty() {
        total_wall_ms as f64 / run_rows.len() as f64
    } else {
        0.0
    };

    let total_runs = report_val["runs"].as_u64().unwrap_or(run_rows.len() as u64) as usize;
    let unique_seeds = report_val["seeds"].as_u64().unwrap_or(0) as usize;
    let findings = report_val["findings"].as_u64().unwrap_or(0) as usize;
    let vacuous = report_val["vacuous"].as_bool().unwrap_or(false);

    Ok(SweepProfile {
        schema: PROFILE_SCHEMA,
        kind: "sweep",
        dir: dir.display().to_string(),
        total_runs,
        unique_seeds,
        findings,
        vacuous,
        outcomes,
        groups,
        runs: run_rows,
        summary_stats: SweepStats {
            total_wall_ms,
            mean_wall_ms,
            p50_wall_ms: dist.p50_ns,
            p95_wall_ms: dist.p95_ns,
            max_wall_ms: dist.max_ns,
            total_traps,
            total_faults_injected,
            max_edges_hit,
        },
    })
}

/// Read only the first and last `Rec` of a run's boundary logs (O(1) seeks) to get virtual duration
/// quickly across hundreds of sweep runs, falling back to estimated trap+compute time if pruned.
fn quick_virtual_duration_ms(run_dir: &Path, traps: u64, compute_events: u64) -> f64 {
    use std::io::{Seek, SeekFrom};
    let bdirs = boots(run_dir);
    let mut first: Option<u64> = None;
    let mut last: Option<u64> = None;
    let mut buf = [0u8; REC_SIZE];

    for bdir in &bdirs {
        let log = bdir.join("boundary.log");
        if let Ok(mut f) = File::open(&log) {
            if f.read_exact(&mut buf).is_ok() {
                let r = Rec::from_bytes(&buf);
                first.get_or_insert(r.vclock_ns);
                last = Some(r.vclock_ns);
            }
            let tail_path = if bdir.join("boundary.tail").is_file() {
                bdir.join("boundary.tail")
            } else {
                log
            };
            if let Ok(mut tf) = File::open(&tail_path) {
                if let Ok(len) = tf.metadata().map(|m| m.len()) {
                    let n = len / REC_SIZE as u64;
                    if n > 0
                        && tf.seek(SeekFrom::Start((n - 1) * REC_SIZE as u64)).is_ok()
                        && tf.read_exact(&mut buf).is_ok()
                    {
                        last = Some(Rec::from_bytes(&buf).vclock_ns);
                    }
                }
            }
        }
    }
    if let (Some(a), Some(b)) = (first, last) {
        return b.saturating_sub(a) as f64 / 1_000_000.0;
    }
    let est_ns =
        traps.saturating_mul(1_000) + compute_events.saturating_mul(proto::compute::CHARGE_NS);
    est_ns as f64 / 1_000_000.0
}

// ============================================================================
// Text & Folded Formatters
// ============================================================================

pub fn format_folded(run: &RunProfile) -> Res<String> {
    let Some(cpu) = &run.guest_compute.cpu_profile else {
        return Err(format!(
            "{}: no cpu_profile.bin found (run with `--profile-cpu` or `patina replay {} --profile-cpu`)",
            run.dir, run.dir
        ));
    };
    let mut s = String::new();
    for line in &cpu.folded_stacks {
        s.push_str(&format!("{} {}\n", line.stack, line.weight));
    }
    Ok(s)
}

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.3} s", ns as f64 / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.2} ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1} us", ns as f64 / 1e3)
    } else {
        format!("{ns} ns")
    }
}

pub fn format_run_summary(r: &RunProfile) -> String {
    let mut s = String::new();
    s.push_str(&format!("Patina Deterministic Guest Profile ({})\n", r.dir));
    s.push_str(&format!(
        "  program: {}  seed: {}  outcome: {} ({})  boots: {}  digest: {}\n",
        r.program, r.seed, r.outcome, r.stop, r.boots, r.digest
    ));
    s.push_str(&format!(
        "  virtual duration: {}   wall time: {} ms   virtual/wall: {:.2}x\n\n",
        fmt_ns(r.virtual_duration_ns),
        r.wall_ms,
        r.patina_tax.virtual_to_wall_ratio
    ));

    // Bucket 1
    s.push_str("1. Guest User Compute\n");
    s.push_str(&format!(
        "   compute events: {}   virtual compute: {} ({:.1}% of vtime)\n",
        r.guest_compute.compute_events,
        fmt_ns(r.virtual_latency.compute_ns),
        r.guest_compute.virtual_share_pct
    ));
    s.push_str(&format!(
        "   compute switches: {}   deadline stops: {}   spin yields: {}   pause points: {}\n",
        r.guest_compute.compute_switches,
        r.guest_compute.deadline_stops,
        r.guest_compute.spin_yields,
        r.guest_compute.pause_points
    ));
    if let Some(cpu) = &r.guest_compute.cpu_profile {
        s.push_str(&format!(
            "   CPU profile: {} deterministic samples (weight {}, interval {}, rt frames filtered: {})\n",
            cpu.total_samples, cpu.total_weight, cpu.interval, cpu.rt_frames_filtered
        ));
        for f in cpu.top_functions.iter().take(8) {
            s.push_str(&format!(
                "     {:>6.1}% self  {:>6.1}% total  {} [{}]\n",
                f.self_pct, f.total_pct, f.name, f.module
            ));
        }
    }
    s.push('\n');

    // Bucket 2
    s.push_str("2. Logical I/O & Syscall Work\n");
    s.push_str(&format!(
        "   syscalls: {} (errors: {})   read: {} ops ({})   write: {} ops ({})\n",
        r.logical_io.total_syscalls,
        r.logical_io.syscall_errors,
        r.logical_io.read_ops,
        crate::report::bytes(r.logical_io.read_bytes),
        r.logical_io.write_ops,
        crate::report::bytes(r.logical_io.write_bytes),
    ));
    s.push_str(&format!(
        "   fsync: {}   futex: {} (wait {}, wake {})   net: tx {} ({}) / rx {} ({}) / conn {}\n",
        r.logical_io.fsync_ops,
        r.logical_io.futex_total_ops,
        r.logical_io.futex_wait_ops,
        r.logical_io.futex_wake_ops,
        r.logical_io.net_send_ops,
        crate::report::bytes(r.logical_io.net_bytes_tx),
        r.logical_io.net_recv_ops,
        crate::report::bytes(r.logical_io.net_bytes_rx),
        r.logical_io.net_connect_ops,
    ));
    s.push_str(&format!(
        "   alloc ops: {}   faults injected: {}\n",
        r.logical_io.alloc_ops, r.logical_io.faults_injected
    ));
    if !r.logical_io.top_syscalls.is_empty() {
        s.push_str("   top syscalls (by virtual time):\n");
        for sc in r.logical_io.top_syscalls.iter().take(8) {
            s.push_str(&format!(
                "     {:<16} {:>7} calls  {:>10} vtime  p50={:<9} p99={:<9} bytes={}\n",
                sc.name,
                sc.count,
                fmt_ns(sc.total_vtime_ns),
                fmt_ns(sc.p50_ns),
                fmt_ns(sc.p99_ns),
                crate::report::bytes(sc.bytes),
            ));
        }
    }
    s.push('\n');

    // Bucket 3
    s.push_str("3. Modeled Virtual Latency\n");
    let tot = r.virtual_latency.total_ns.max(1) as f64;
    let pct = |v: u64| (v as f64 / tot) * 100.0;
    s.push_str(&format!(
        "   compute: {:<10} ({:>4.1}%)   io: {:<10} ({:>4.1}%)   fsync: {:<10} ({:>4.1}%)\n",
        fmt_ns(r.virtual_latency.compute_ns),
        pct(r.virtual_latency.compute_ns),
        fmt_ns(r.virtual_latency.io_ns),
        pct(r.virtual_latency.io_ns),
        fmt_ns(r.virtual_latency.fsync_ns),
        pct(r.virtual_latency.fsync_ns),
    ));
    s.push_str(&format!(
        "   futex:   {:<10} ({:>4.1}%)   net:{:<10} ({:>4.1}%)   sleep: {:<10} ({:>4.1}%)\n",
        fmt_ns(r.virtual_latency.futex_ns),
        pct(r.virtual_latency.futex_ns),
        fmt_ns(r.virtual_latency.net_ns),
        pct(r.virtual_latency.net_ns),
        fmt_ns(r.virtual_latency.wait_sleep_ns),
        pct(r.virtual_latency.wait_sleep_ns),
    ));
    s.push_str(&format!(
        "   memory:  {:<10} ({:>4.1}%)   flt:{:<10} ({:>4.1}%)   other: {:<10} ({:>4.1}%)\n",
        fmt_ns(r.virtual_latency.memory_ns),
        pct(r.virtual_latency.memory_ns),
        fmt_ns(r.virtual_latency.fault_ns),
        pct(r.virtual_latency.fault_ns),
        fmt_ns(r.virtual_latency.other_ns),
        pct(r.virtual_latency.other_ns),
    ));
    if !r.virtual_latency.distributions.is_empty() {
        s.push_str("   virtual tail latency:\n");
        for (cat, d) in &r.virtual_latency.distributions {
            s.push_str(&format!(
                "     {:<12} n={:<6} p50={:<10} p95={:<10} p99={:<10} max={}\n",
                cat,
                d.count,
                fmt_ns(d.p50_ns),
                fmt_ns(d.p95_ns),
                fmt_ns(d.p99_ns),
                fmt_ns(d.max_ns),
            ));
        }
    }
    s.push('\n');

    // Bucket 4
    s.push_str("4. Patina Runtime Tax (isolated from guest work)\n");
    s.push_str(&format!(
        "   wall time: {} ms   traps: {} ({:.0} traps/s)   switches: {}\n",
        r.patina_tax.wall_ms, r.patina_tax.traps, r.patina_tax.traps_per_sec, r.patina_tax.switches
    ));
    s.push_str(&format!(
        "   plans loaded: {}   rewrite points: {}   images: {}   boundary log: {} ({} records)\n\n",
        r.patina_tax.plans_loaded,
        r.patina_tax.rewrite_points,
        r.patina_tax.rewrite_images,
        crate::report::bytes(r.patina_tax.boundary_log_bytes),
        r.patina_tax.boundary_records
    ));

    // Memory
    s.push_str("Memory Attribution (mmap / munmap / mremap / brk)\n");
    s.push_str(&format!(
        "   peak mapped: {}   final mapped: {}   allocated: {}   freed: {}\n",
        crate::report::bytes(r.memory.peak_mapped_bytes),
        crate::report::bytes(r.memory.final_mapped_bytes),
        crate::report::bytes(r.memory.total_allocated_bytes),
        crate::report::bytes(r.memory.total_freed_bytes),
    ));
    s.push_str(&format!(
        "   ops: mmap={} munmap={} mremap={} brk={}\n",
        r.memory.mmap_count, r.memory.munmap_count, r.memory.mremap_count, r.memory.brk_count
    ));

    // Coverage
    if let Some(cov) = &r.coverage {
        s.push_str(&format!(
            "\nEdge Coverage\n   edges hit: {} / {} ({:.2}%)   total hits: {}   unique hashes: {}\n",
            cov.edges_hit, cov.map_size, cov.density_pct, cov.total_hits, cov.unique_hashes
        ));
    }

    s
}

pub fn format_sweep_summary(sw: &SweepProfile) -> String {
    let mut s = String::new();
    s.push_str(&format!("Patina Sweep / Campaign Profile ({})\n", sw.dir));
    s.push_str(&format!(
        "  runs: {}   seeds: {}   findings: {}   groups: {}   vacuous: {}\n",
        sw.total_runs,
        sw.unique_seeds,
        sw.findings,
        sw.groups.len(),
        sw.vacuous
    ));
    let outcomes: Vec<String> = sw
        .outcomes
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    s.push_str(&format!("  outcomes: {}\n", outcomes.join("  ")));
    s.push_str(&format!(
        "  wall_ms: mean={:.1} p50={} p95={} max={}   total traps={}   faults injected={}\n",
        sw.summary_stats.mean_wall_ms,
        sw.summary_stats.p50_wall_ms,
        sw.summary_stats.p95_wall_ms,
        sw.summary_stats.max_wall_ms,
        sw.summary_stats.total_traps,
        sw.summary_stats.total_faults_injected,
    ));
    if !sw.groups.is_empty() {
        s.push_str("\nFinding Groups:\n");
        for g in &sw.groups {
            s.push_str(&format!(
                "  #{:<2} [{}] {} ({} runs)\n      replay: {}\n",
                g.index, g.outcome, g.signature, g.count, g.replay_command
            ));
        }
    }
    s
}

// ============================================================================
// Zero-Dependency Local HTTP Server (`--serve [ADDR]`)
// ============================================================================

pub struct PreparedPayload {
    pub html: String,
    pub profile_json: String,
    pub trace_json: Option<String>,
}

impl PreparedPayload {
    pub fn from_target(target: &ProfileTarget) -> Self {
        match target {
            ProfileTarget::Run(run) => {
                let profile_json = serde_json::to_string_pretty(run).unwrap();
                let trace_json = serde_json::to_string(&build_perfetto_trace(run)).unwrap();
                let html = crate::profile_html::render_run_html(&profile_json, &trace_json);
                Self {
                    html,
                    profile_json,
                    trace_json: Some(trace_json),
                }
            }
            ProfileTarget::Sweep(sweep) => {
                let profile_json = serde_json::to_string_pretty(sweep).unwrap();
                let html = crate::profile_html::render_sweep_html(&profile_json);
                Self {
                    html,
                    profile_json,
                    trace_json: None,
                }
            }
        }
    }
}

/// Bind `TcpListener` on `addr` and return `(listener, local_addr)`.
pub fn bind_server(addr: &str) -> Res<(TcpListener, SocketAddr)> {
    let listener =
        TcpListener::bind(addr).map_err(|e| format!("--addr {addr}: bind failed: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("--addr {addr}: local_addr: {e}"))?;
    Ok((listener, local))
}

/// Serve one HTTP connection against `payload`.
pub fn handle_http_connection(mut stream: TcpStream, payload: &PreparedPayload) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut reader = BufReader::new(&stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() || req_line.is_empty() {
        return;
    }
    // Drain request headers.
    let mut hdr = String::new();
    while reader.read_line(&mut hdr).is_ok() {
        if hdr == "\r\n" || hdr == "\n" || hdr.is_empty() {
            break;
        }
        hdr.clear();
    }

    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        let _ = write_http_response(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n",
            method == "HEAD",
        );
        return;
    }

    match path {
        "/" | "/index.html" => {
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                payload.html.as_bytes(),
                method == "HEAD",
            );
        }
        "/profile.json" => {
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                payload.profile_json.as_bytes(),
                method == "HEAD",
            );
        }
        "/trace.json" => match &payload.trace_json {
            Some(t) => {
                let _ = write_http_response(
                    &mut stream,
                    "200 OK",
                    "application/json; charset=utf-8",
                    t.as_bytes(),
                    method == "HEAD",
                );
            }
            None => {
                let _ = write_http_response(
                    &mut stream,
                    "404 Not Found",
                    "application/json; charset=utf-8",
                    br#"{"error":"trace.json is only available for single runs"}"#,
                    method == "HEAD",
                );
            }
        },
        _ => {
            let _ = write_http_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found\n",
                method == "HEAD",
            );
        }
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn serve(target: &ProfileTarget, addr: &str) -> Res<()> {
    let payload = PreparedPayload::from_target(target);
    let (listener, local) = bind_server(addr)?;
    eprintln!("patina inspect serve: listening on http://{local}/");
    eprintln!("  dashboard:     http://{local}/");
    eprintln!("  profile JSON:  http://{local}/profile.json");
    if payload.trace_json.is_some() {
        eprintln!("  Perfetto JSON: http://{local}/trace.json");
    }
    for stream in listener.incoming().flatten() {
        handle_http_connection(stream, &payload);
    }
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn percentiles_are_exact_and_deterministic() {
        let mut v: Vec<u64> = (1..=100).rev().collect();
        let d = compute_dist(&mut v);
        assert_eq!(d.count, 100);
        assert_eq!(d.min_ns, 1);
        assert_eq!(d.max_ns, 100);
        assert_eq!(d.p50_ns, 50);
        assert_eq!(d.p95_ns, 95);
        assert_eq!(d.p99_ns, 99);
        assert_eq!(d.total_ns, 5050);
    }

    #[test]
    fn cpu_profile_decoder_filters_rt_frames_and_builds_folded_stacks() {
        let dir = std::env::temp_dir().join(format!("patina-prof-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let b1 = dir.join("boot-1");
        std::fs::create_dir_all(&b1).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(&proto::guest_profile::encode_header(62));
        let mut rec = [0u8; proto::guest_profile::MAX_RECORD_BYTES];
        let n = proto::guest_profile::encode_image(
            &mut rec,
            100,
            0x40_0000,
            0x41_0000,
            0x40_0000,
            0,
            b"/guest/demo",
        );
        blob.extend_from_slice(&rec[..n]);
        // Sample includes one RT frame in [RT_BASE, RT_REGION_END) that MUST be filtered out.
        let pcs = [0x40_1200u64, RT_BASE + 0x1234, 0x40_1050];
        let m =
            proto::guest_profile::encode_sample(&mut rec, 1_000_000, 5, 1000, 100, 100, 0, &pcs);
        blob.extend_from_slice(&rec[..m]);
        std::fs::write(b1.join("cpu_profile.bin"), &blob).unwrap();

        let mut trace_events = Vec::new();
        let cpu = load_cpu_profiles(&dir, &[b1], &Value::Null, 1000, 0, &mut trace_events)
            .unwrap()
            .expect("cpu profile present");
        assert_eq!(cpu.total_samples, 1);
        assert_eq!(cpu.total_weight, 1000);
        assert_eq!(cpu.rt_frames_filtered, 1);
        assert_eq!(cpu.folded_stacks.len(), 1);
        assert!(
            !cpu.folded_stacks[0].stack.contains("7fff"),
            "RT address leaked: {}",
            cpu.folded_stacks[0].stack
        );
        assert!(cpu.folded_stacks[0].stack.contains("demo+"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_server_serves_html_profile_and_trace_on_ephemeral_port() {
        let dir = std::env::temp_dir().join(format!("patina-prof-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let b1 = dir.join("boot-1");
        std::fs::create_dir_all(&b1).unwrap();
        std::fs::write(
            dir.join("result.json"),
            r#"{"outcome":"ok","stop":"exit","seed":7,"digest":"abcd","boots":1,"wall_ms":12,"sched":{"traps":2,"switches":1},"compute":{"events":500,"switches":1,"deadline_stops":0,"charge_ns":100}}"#,
        )
        .unwrap();
        std::fs::write(b1.join("boundary.log"), b"").unwrap();

        let target = load_target(&dir).unwrap();
        let payload = Arc::new(PreparedPayload::from_target(&target));
        let (listener, addr) = bind_server("127.0.0.1:0").unwrap();

        let p2 = Arc::clone(&payload);
        let h = std::thread::spawn(move || {
            for _ in 0..4 {
                let (s, _) = listener.accept().unwrap();
                handle_http_connection(s, &p2);
            }
        });

        let get = |path: &str| -> String {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            resp
        };

        let html_resp = get("/");
        assert!(html_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(html_resp.contains("text/html"));
        assert!(html_resp.contains("<!DOCTYPE html>"));

        let json_resp = get("/profile.json");
        assert!(json_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(json_resp.contains("application/json"));
        let body = json_resp.split("\r\n\r\n").nth(1).unwrap();
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["schema"], PROFILE_SCHEMA);
        assert_eq!(v["seed"], 7);

        let trace_resp = get("/trace.json");
        assert!(trace_resp.starts_with("HTTP/1.1 200 OK"));
        let tbody = trace_resp.split("\r\n\r\n").nth(1).unwrap();
        let tv: Value = serde_json::from_str(tbody).unwrap();
        assert!(tv["traceEvents"].is_array());

        let missing_resp = get("/nope");
        assert!(missing_resp.starts_with("HTTP/1.1 404 Not Found"));

        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_profile_and_html_render_cleanly() {
        let dir = std::env::temp_dir().join(format!("patina-prof-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let r1 = dir.join("seed-1");
        let r2 = dir.join("seed-2");
        std::fs::create_dir_all(&r1).unwrap();
        std::fs::create_dir_all(&r2).unwrap();
        std::fs::write(
            r1.join("result.json"),
            r#"{"outcome":"ok","stop":"exit","seed":1,"digest":"1111","boots":1,"wall_ms":10,"sched":{"traps":5,"switches":1},"faults":{"injected":0,"counts":{}}}"#,
        )
        .unwrap();
        std::fs::write(
            r2.join("result.json"),
            r#"{"outcome":"failure","stop":"exit","seed":2,"digest":"2222","boots":1,"wall_ms":25,"signature":"failure: exit 1","sched":{"traps":9,"switches":2},"faults":{"injected":2,"counts":{"fs-error":{"injected":2,"eligible":4}}}}"#,
        )
        .unwrap();

        let target = load_target(&dir).unwrap();
        let ProfileTarget::Sweep(sw) = target else {
            panic!("expected sweep target");
        };
        assert_eq!(sw.total_runs, 2);
        assert_eq!(sw.findings, 1);
        assert_eq!(sw.groups.len(), 1);
        let html = crate::profile_html::render_sweep_html(&serde_json::to_string(&*sw).unwrap());
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("failure: exit 1"));
        assert!(!html.contains("https://cdn"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
