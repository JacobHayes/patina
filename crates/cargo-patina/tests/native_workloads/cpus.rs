//! The virtual machine's CPU count (`--cpus`) as workloads read it: every
//! count surface, and allocators reading their CPU.

use super::*;

#[cfg(target_os = "linux")]
const CPU_COUNTS: [&str; 5] = ["parallelism", "online", "configured", "early", "affinity"];
#[cfg(target_os = "linux")]
const CPU_KEYS: [&str; 8] = [
    "parallelism",
    "online",
    "configured",
    "early",
    "affinity",
    "thread_cpus",
    "proc_cpuinfo",
    "sys_cpu_online",
];
#[cfg(target_os = "macos")]
const CPU_COUNTS: [&str; 8] = [
    "parallelism",
    "online",
    "configured",
    "early",
    "ncpu",
    "activecpu",
    "logicalcpu",
    "physicalcpu",
];
#[cfg(target_os = "macos")]
const CPU_KEYS: [&str; 8] = CPU_COUNTS;

/// Every CPU count the probe read is the run's, and its threads ran on more
/// than one CPU exactly when the machine has more than one.
fn assert_cpu_count(out: &[u8], cpus: u32) {
    let fields = assert_fields(out, "NATIVE_CPU_RESULT ", &CPU_KEYS);
    for key in CPU_COUNTS {
        assert_eq!(fields[key], cpus.to_string(), "{key}: {}", text(out));
    }
    if cfg!(target_os = "linux") {
        let spread: u32 = fields["thread_cpus"].parse().unwrap();
        assert_eq!(spread > 1, cpus > 1, "{}", text(out));
        // Patina serves no CPU files: a reader falls back to the affinity mask.
        assert_eq!(fields["proc_cpuinfo"], "false");
        assert_eq!(fields["sys_cpu_online"], "false");
    }
}

/// Every guest-visible CPU count agrees with the run's `--cpus`: std's
/// `available_parallelism`, `sysconf`'s online and configured counts (also as
/// a constructor read them before Patina's startup ran), and the
/// platform's own (Linux's affinity mask and each thread's CPU, through glibc
/// and the raw syscalls; macOS's `hw.*cpu` sysctls). The count is recorded,
/// a flag-free replay restores it, a matching `--cpus` replays, and a
/// different one is refused by name. The flag's range is the parser's
/// (`registry_value_grammars_match_the_parsers`).
#[test]
fn every_cpu_count_surface_agrees_with_the_run() {
    let g = Guest::assert_build("cpu_probe.rs");
    g.assert_audit_clean();
    let default = run_seeded(&g, 1, &[]);
    assert_cpu_count(&default, patina_dst_abi::DEFAULT_CPUS);
    let one = run_seeded(&g, 1, &["--cpus", "1"]);
    assert_cpu_count(&one, 1);
    let (three, trace) = g.assert_recorded(1, &["--cpus", "3"]);
    assert_cpu_count(&three.stdout, 3);
    assert_eq!(
        patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .metadata
            .cpus,
        3
    );
    let replay = |count: &str| g.command("replay", &[trace.to_str().unwrap(), "--cpus", count]);
    assert_eq!(assert_success(replay("3")).stdout, three.stdout);
    assert_refused(replay("4"), &["--cpus"]);
}

/// A global allocator that reads its CPU and the CPU count on every
/// allocation, as a per-CPU arena allocator does, runs threads: the runtime
/// allocates through it while holding its own state, and every CPU surface
/// the allocator reads answers without that state's lock. Armed from a
/// constructor that runs before Patina's, its first read lands in Patina's
/// startup capturing the control plane, and is the run's count. The CPUs it
/// saw are the run's, repeatably and through a replay.
#[test]
fn an_allocator_reading_its_cpu_runs_threads() {
    let g = Guest::assert_build("cpu_allocator_probe.rs");
    let cpus = 3u32;
    let count = cpus.to_string();
    let flags = ["--cpus", count.as_str()];
    let out = g.assert_run_success(1, &flags).stdout;
    let fields = assert_fields(
        &out,
        "NATIVE_CPU_ALLOC_RESULT ",
        &["total", "read", "cpus_seen", "online"],
    );
    assert_eq!(fields["read"], "1", "{}", text(&out));
    assert_eq!(fields["online"], count, "{}", text(&out));
    let seen: u32 = fields["cpus_seen"].parse().unwrap();
    // Linux threads start round robin over the CPUs; macOS has no per-thread
    // CPU query, so the probe reads none.
    let expected = if cfg!(target_os = "linux") { cpus } else { 1 };
    assert_eq!(seen, expected, "{}", text(&out));
}

/// An allocator that makes system calls on every allocation, as the
/// program's `#[global_allocator]` and its C `malloc`, runs threads and lists
/// a directory. The runtime reaches its C entry points from inside calls of
/// its own: a new thread's TLS while it creates the host thread, holding its
/// state, and a directory stream. Each call the allocator makes there
/// (`syscall(SYS_getcpu)`; while listing, `getrusage`, a failing `getrusage`
/// whose errno it reads, `sched_getaffinity`; and, where syscall-user-dispatch
/// traps it, a raw `getcpu`) nests in the runtime's call, which carries on as
/// the runtime's once the allocator returns. The CPUs it saw are the run's,
/// repeatably and through a replay.
#[cfg(target_os = "linux")]
#[test]
fn an_allocator_making_system_calls_runs_threads() {
    let mut bins = vec!["syscall_allocator"];
    if kernel_supports(KernelFeature::Sud) {
        bins.push("syscall_allocator_raw");
    }
    for bin in bins {
        let g = Guest::assert_build_with("syscall-allocator", &["--bin", bin]);
        let cpus = 3u32;
        let count = cpus.to_string();
        let flags = ["--cpus", count.as_str()];
        let out = g.assert_run_success(1, &flags).stdout;
        let fields = assert_fields(
            &out,
            "NATIVE_SYSCALL_ALLOC_RESULT ",
            &["total", "asked", "cpus_seen", "read_state", "listed"],
        );
        for key in ["asked", "read_state", "listed"] {
            assert_eq!(fields[key], "1", "{bin} {key}: {}", text(&out));
        }
        assert_eq!(fields["cpus_seen"], count, "{bin}: {}", text(&out));
    }
}
