//! ABI-door and scheduler integration pins. Unlike the Linux host-oracle
//! probes these also execute on macOS and Linux arm64, and pin virtual time.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
#[cfg(target_os = "linux")]
#[path = "native_abi/sysv_ipc.rs"]
mod sysv_ipc;
#[path = "native_abi/variadic.rs"]
mod variadic;
use common::native::*;

/// Class pairing: runtime boot-origin translation invariance; exercises the
/// public ABI clocks, uptime, coarse truncation and absolute timer deadlines.
#[test]
fn guest_clock_origins_and_uptime_are_coherent() {
    let g = assert_build_c_guest("boot_origin.c", CLink::PosixShim);
    let out = assert_standalone_success(&g.binary, &[], &[]).stdout;
    let fields = assert_fields(&out, "BOOT_ORIGIN ", &["start", "realtime", "cpu"]);
    // The defaults, and the few calls charged since the guest started.
    let soon_after = |value: &str, origin: u64| {
        let value: u64 = value.parse().unwrap();
        assert!(
            (origin..origin + 100_000).contains(&value),
            "{value} {origin}"
        );
        value
    };
    let start = soon_after(
        fields["start"],
        patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS,
    );
    soon_after(
        fields["realtime"],
        start + patina_dst_runtime::DEFAULT_REALTIME_EPOCH_NANOS,
    );
    soon_after(fields["cpu"], patina_dst_abi::STARTUP_CPU_NANOS);
}

/// The prefixed C ABI over the crash checkpoint: a seed decides the guest's
/// entropy and virtual time, and the environment protocol records and replays
/// without a seed.
#[test]
fn prefixed_c_abi_preserves_crash_checkpoint_and_replays() {
    let g = assert_build_c_guest("probe.c", CLink::Shim);
    let result = |seed: &str| {
        let out = assert_standalone_success(&g.binary, &[seed], &[]).stdout;
        assert_fields(
            &out,
            "NATIVE_SHIM_RESULT ",
            &["seed", "random", "before", "after", "contents"],
        )
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect::<std::collections::BTreeMap<_, _>>()
    };
    let fields = result("123");
    assert_eq!(fields["seed"], "123");
    assert_lower_hex(&fields["random"], 32);
    // The default origin and a 5 ms sleep, each with the calls charged
    // before it.
    let before: u64 = fields["before"].parse().unwrap();
    let origin = patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS;
    assert!((origin..origin + 100_000).contains(&before), "{before}");
    let slept = fields["after"].parse::<u64>().unwrap() - before;
    assert!((5_000_000..5_100_000).contains(&slept), "{slept}");
    assert_eq!(fields["contents"], "stable");
    assert_ne!(
        fields["random"],
        result("124")["random"],
        "entropy must vary, not just the printed seed"
    );

    let trace = g.dir.path().join("env.patina");
    let env = [
        ("PATINA_RT_MODE", "record"),
        ("PATINA_RT_SEED", "123"),
        ("PATINA_RT_TRACE", trace.to_str().unwrap()),
        ("PATINA_RT_FINGERPRINT", "c-abi-v1"),
    ];
    let record = assert_standalone_success(&g.binary, &["env"], &env).stdout;
    let replay_env = [
        ("PATINA_RT_MODE", "replay"),
        ("PATINA_RT_TRACE", trace.to_str().unwrap()),
        ("PATINA_RT_FINGERPRINT", "c-abi-v1"),
    ];
    assert_eq!(
        record,
        assert_standalone_success(&g.binary, &["env"], &replay_env).stdout
    );
}

/// The direct POSIX ABI (file I/O, the descriptor table, the `*at` family,
/// `realpath` and the environment) answers from the deterministic kernel; the
/// host's canaries never reach the guest.
#[test]
fn posix_descriptors_paths_and_environment_are_virtualized() {
    let g = assert_build_c_guest("posix_probe.c", CLink::PosixShim);
    assert_standalone_success(
        &g.binary,
        &[],
        &[
            ("HOST_CANARY", "must-not-leak"),
            ("PATINA_HOST_CANARY", "must-not-leak"),
        ],
    );
}

#[test]
fn libc_at_calls_are_interposed_and_replayable() {
    let g = Guest::assert_build("at_family_probe.rs");
    let audit = g.assert_audit_clean();
    for symbol in ["symlinkat", "readlinkat"] {
        assert!(!text(&audit.stdout).contains(symbol));
    }
    g.assert_no_imports(&["symlinkat", "readlinkat"]);
    assert_eq!(
        text(&g.assert_run_success(1, &[]).stdout),
        "NATIVE_LIBC_AT_RESULT link=target.txt read=pointed-at abs=/state/target.txt\n"
    );
}

/// Pipes and a socketpair through the scheduler: a blocked reader woken by a
/// writer thread, duplex transfer, endpoint aliases (EOF and EPIPE, without
/// SIGPIPE, only at the last alias) and non-blocking reads.
#[test]
fn pipes_and_socketpairs_wake_alias_and_refuse_to_block() {
    let g = Guest::assert_build("pipe_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_run_success(1, &[]).stdout),
        "NATIVE_PIPE_RESULT got=ping-pong\n\
         NATIVE_SOCKETPAIR_RESULT reply=PING\n\
         NATIVE_PIPE_DUP_RESULT ok=true eof=true epipe=true\n\
         NATIVE_PIPE_NONBLOCK_RESULT ok=true\n"
    );
}

/// Read interest registered, from another thread, in a socket that is already
/// readable wakes the task parked in the reactor (`kevent` on macOS,
/// `epoll_wait` on Linux), which delivers it, as the native run does. Class
/// pairing: the scheduler's deadlock refusal, which a parked reactor that
/// missed the registration reaches.
#[test]
fn a_registration_wakes_a_parked_reactor() {
    let g = Guest::assert_build("reactor_register_probe.rs");
    let expected = native_stdout("reactor_register_probe.rs");
    assert_exact_line(&expected, "NATIVE_REACTOR_REGISTER_RESULT woke_ready=true");
    g.assert_audit_clean();
    assert_eq!(text(&g.assert_run_success(1, &[]).stdout), text(&expected));
}

/// A shared file mapping is a view of the page cache the crash model
/// judges: a store through it is what a read returns, an in-process crash
/// rolls the file AND the mapping back to the durable image, and
/// `msync(MS_SYNC)` makes a store survive the next crash.
#[test]
fn shared_file_mappings_follow_the_crash_model() {
    let g = assert_build_c_guest("mmap_crash_probe.c", CLink::PosixShim);
    let out = assert_standalone_success(&g.binary, &[], &[]).stdout;
    assert_eq!(text(&out), "NATIVE_MMAP_CRASH_RESULT contents=synced!\n");
}

/// Run one `mem_probe.c` mode, with the host's `RLIMIT_MEMLOCK` at zero
/// (every lock answer the guest sees must be the virtual kernel's) and, when
/// given, its `RLIMIT_NOFILE` (soft and hard) at `descriptors`.
fn mem_probe(g: &Guest, mode: &str, descriptors: Option<libc::rlim_t>) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(&g.binary);
    command.env_clear().arg(mode);
    // SAFETY: async-signal-safe calls on the forked child's own limits.
    unsafe {
        command.pre_exec(move || {
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &none) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(count) = descriptors {
                let limit = libc::rlimit {
                    rlim_cur: count,
                    rlim_max: count,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        })
    };
    common::output_with_deadline(&mut command, std::time::Duration::from_secs(20))
        .expect("mem probe exceeded 20s")
}

/// The virtual kernel's memory answers (`mem_probe.c`), one mode each:
///
/// - `mprotect`: a shared view that may not write (a read-only file; on Linux
///   a `SHM_RDONLY` attachment too) refuses `PROT_WRITE`; a private copy of
///   the same file takes it; an unmapped page below such a view is `ENOMEM`.
/// - `msync-*`: `msync` makes durable what the kernel synchronizes: over a
///   hole, the views on both sides of it before the call answers `ENOMEM`; on
///   macOS, a call asked neither only to start (`MS_ASYNC`) nor to dispose of
///   the pages (`MS_DEACTIVATE`), whatever `MS_SYNC` says.
/// - `wronly` (macOS): a write-only descriptor maps without access, private or
///   shared, and `mprotect` then exposes the file's bytes.
/// - `limits` (Linux): `RLIMIT_MEMLOCK` is the virtual 8 MiB whatever the
///   host's is, lowers but never rises again, and judges `mlock`.
/// - `huge` (Linux): zero hugetlb pages, one answer across `mmap`, `shmget`
///   and `memfd`.
/// - `thp` (Linux): transparent huge pages are off: one touch makes one page
///   resident.
/// - `populate` (Linux): `mlock` populates what it locks, and a page no fault
///   reaches (no access, past a file's end) is `ENOMEM`.
///
/// A touch past the end of a mapped file is `SIGBUS`. On Linux a call the shim
/// refuses by name answers `ENOSYS`, through libc's wrapper and the raw
/// syscall alike, and each mapped file holds a host memfd: past the host's
/// descriptor limit the shim stops by name instead of answering `EMFILE`.
#[test]
fn memory_calls_answer_from_the_virtual_kernel() {
    use std::os::unix::process::ExitStatusExt;
    let g = assert_build_c_guest("mem_probe.c", CLink::PosixShim);
    let modes: &[&str] = if cfg!(target_os = "macos") {
        &[
            "mprotect",
            "msync-hole",
            "msync-default",
            "msync-deactivate",
            "wronly",
        ]
    } else {
        &[
            "mprotect",
            "msync-hole",
            "limits",
            "huge",
            "thp",
            "populate",
        ]
    };
    let failed: Vec<String> = modes
        .iter()
        .map(|mode| (mode, mem_probe(&g, mode, None)))
        .filter(|(mode, output)| {
            !output.status.success()
                || text(&output.stdout) != format!("NATIVE_MEM_RESULT {mode}=ok\n")
        })
        .map(|(mode, output)| format!("{mode}: {output:?}"))
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
    let output = mem_probe(&g, "sigbus", None);
    assert_eq!(output.status.signal(), Some(libc::SIGBUS), "{output:?}");
    if cfg!(target_os = "linux") {
        let output = mem_probe(&g, "refusals", None);
        assert!(output.status.success(), "{output:?}");
        let stdout = text(&output.stdout);
        let answers: std::collections::BTreeMap<&str, &str> = stdout
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let enosys = format!("errno {}", libc::ENOSYS);
        for call in [
            "mlockall-current",
            "mlockall-current-raw",
            "msgctl-info",
            "msgctl-info-raw",
            "semctl-info",
            "semctl-info-raw",
            "shmctl-info",
            "shmctl-info-raw",
        ] {
            assert_eq!(
                answers.get(call).copied(),
                Some(enosys.as_str()),
                "{call}: {stdout}{}",
                text(&output.stderr)
            );
        }
        let output = mem_probe(&g, "descriptors", Some(64));
        assert!(!output.status.success(), "{output:?}");
        assert!(
            text(&output.stderr).contains("the host refused a memfd for guest memory"),
            "{output:?}"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Readiness through the scheduler: an edge-triggered epoll waiter woken
    /// by a writer thread, its latch and re-fire; an eventfd write waking a
    /// parked epoll_wait, its counter and semaphore modes; and an epoll
    /// timeout advancing exactly its virtual duration.
    #[test]
    fn epoll_and_eventfd_wake_latch_and_time_out_exactly() {
        let g = Guest::assert_build("epoll_probe.rs");
        g.assert_audit_clean();
        assert_eq!(
            text(&g.assert_run_success(1, &[]).stdout),
            "NATIVE_EPOLL_RESULT latched=0 refired=1\n\
             NATIVE_EVENTFD_RESULT woke=1 refired=1 sem_ok=true\n\
             NATIVE_EPOLL_TIMEOUT timeout_ms=50\n"
        );
    }

    /// A C guest's `pthread_exit` runs the cleanup handler
    /// `pthread_cleanup_push` registered (the setjmp form C compiles to, which
    /// glibc's unwind longjmps into and continues from), and the join answers
    /// its value; a pending cancel does not act at the join of a thread that
    /// has ended ("cancel-join"), which waits for nothing under glibc either.
    ///
    /// Where glibc ends a thread and the model cannot follow, the run stops
    /// by name instead of aborting in the unwinder or running on: a
    /// `pthread_exit` or an acting cancel inside a guest signal handler
    /// (the unwind would cross the shim's Rust delivery frames), and a
    /// pending cancel at a cancellation point the model does not act at (a
    /// `write` that does not block; a self-join, where glibc waits instead of
    /// answering `EDEADLK`).
    #[test]
    fn c_thread_endings_run_cleanup_or_stop_by_name() {
        let g = assert_build_c_guest("pthread_exit_probe.c", CLink::PosixShim);
        for (mode, expected) in [
            (
                &[][..],
                "NATIVE_PTHREAD_EXIT cleanup=7\nNATIVE_PTHREAD_EXIT value=42\n",
            ),
            (&["cancel-join"][..], "NATIVE_PTHREAD_EXIT value=0\n"),
        ] {
            let (output, _) = g.record_standalone(mode);
            assert!(output.status.success(), "{mode:?}: {output:?}");
            assert_eq!(text(&output.stdout), expected, "{mode:?}");
        }
        for (mode, diagnostic) in [
            ("handler", &["signal handler"][..]),
            ("cancel-handler", &["signal handler"][..]),
            ("cancel-write", &["cancellation", "write"][..]),
            ("cancel-self-join", &["cancellation", "pthread_join"][..]),
        ] {
            g.assert_internal_fatal(&[mode], diagnostic);
        }
    }

    /// What glibc runs on a thread after its task completed (a `pthread_key`
    /// destructor here, the allocator's thread shutdown, the host exit) runs
    /// beside no task: a thread that takes the baton next starts only once
    /// that teardown is over. The main thread counts its yields until the
    /// destructor publishes, which a teardown left to the host makes the
    /// host's count: seeded, recorded and replayed runs then differ.
    #[test]
    fn a_finished_threads_teardown_runs_beside_no_task() {
        let g = assert_build_c_guest("thread_teardown_probe.c", CLink::PosixShim);
        for seed in 1..=3 {
            let out = g.assert_run_success(seed, &[]).stdout;
            assert_fields(&out, "NATIVE_THREAD_TEARDOWN ", &["yields"]);
        }
    }

    /// An interest whose registered number was closed while a `dup` keeps
    /// its socket open still watches the socket, as the host kernel's does:
    /// a segment in flight ends a bounded wait at its delivery, not the
    /// timeout, and wakes a wait with none. Class pairing: every source a
    /// fan-in park watches resolves through `resolve_source`, the one
    /// resolution `fd_poll` reads readiness through.
    #[test]
    fn an_epoll_interest_outlives_its_registered_number() {
        let g = Guest::assert_build("epoll_alias_probe.rs");
        g.assert_audit_clean();
        let delivered = "NATIVE_EPOLL_ALIAS_RESULT bounded=1 unbounded=1";
        assert_exact_line(&native_stdout("epoll_alias_probe.rs"), delivered);
        let latency = ["--net-latency-nanos", "2000000"];
        let out = g.assert_run_success(1, &latency).stdout;
        assert_exact_line(&out, delivered);
        let fields = assert_fields(&out, "NATIVE_EPOLL_ALIAS_ELAPSED ", &["bounded_us"]);
        // The 2 ms hop, plus the calls charged around it.
        let waited: u64 = fields["bounded_us"].parse().unwrap();
        assert!((2_000..2_100).contains(&waited), "{}", text(&out));
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    #[test]
    fn kqueue_reports_fields_and_wakes_reader() {
        let g = Guest::assert_build("kqueue_probe.rs");
        g.assert_audit_clean();
        // EV_CLEAR: an arrival fires once, nothing more fires until the next;
        // a pipe writer waits for PIPE_BUF of room; EV_DISPATCH stays quiet.
        assert_eq!(
            text(&g.assert_run_success(1, &[]).stdout),
            "NATIVE_KQUEUE_RESULT got=ping\n\
             NATIVE_KQUEUE_CLEAR socket=[1, 0, 1, 0] pipe=[1, 0, 1, 0]\n\
             NATIVE_KQUEUE_MODES write=[1, 0, 1] dispatch=[1, 0]\n"
        );
    }

    #[test]
    fn kqueue_user_events_wake_and_timeout_exactly() {
        let g = Guest::assert_build("kqueue_user_probe.rs");
        g.assert_audit_clean();
        assert_eq!(
            text(&g.assert_run_success(1, &[]).stdout),
            "NATIVE_KQUEUE_USER_TIMEOUT user_ok=true timeout_ms=50\n"
        );
    }

    #[test]
    fn clock_nsec_matches_clock_gettime() {
        let g = Guest::assert_build("clock_nsec_probe.rs");
        g.assert_audit_clean();
        let out = g.assert_run_success(1, &[]).stdout;
        let fields = assert_fields(&out, "CLOCK_NSEC_RESULT ", &["mono_ns", "real_ns"]);
        for value in fields.values() {
            assert!(
                value.bytes().all(|b| b.is_ascii_digit()),
                "nanosecond value: {value}"
            );
            value.parse::<u64>().expect("u64 nanoseconds");
        }
    }
}

/// The C streams at the edges of a run (`stdio_lifecycle_probe.c`): the end of
/// `main`, the first write, and a run patina refuses. Class pairing: the
/// fd/stdio and proc/exit conformance scenarios hold the streams' buffering to
/// the host; these hold what the scheduler and the refusal paths do to them.
mod stdio_lifecycle {
    use super::*;

    fn seeded(binary: &std::path::Path, case: &str, seed: u64) -> std::process::Output {
        let seed = seed.to_string();
        standalone_output(
            binary,
            &[case],
            &[("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", &seed)],
        )
    }

    /// Only the root task runs after `main`: an atexit handler's `printf`
    /// must not wait on the stream lock a parked printing thread holds (that
    /// wait is a scheduling operation past the end of `main`, a refusal), and
    /// the environment's lock (glibc's `envlock`) is released the same way:
    /// an atexit `setenv` beside a parked `setenv` loop. Each seed schedules
    /// the threads differently. Choosing stdout's buffer asks fstat about the
    /// descriptor: the answer for the capture leaves errno as the host's pipe
    /// does.
    #[test]
    fn the_end_of_main_takes_no_scheduler_lock_and_the_first_write_keeps_errno() {
        let g = assert_build_c_guest("stdio_lifecycle_probe.c", CLink::PosixShim);
        for seed in 1..=8 {
            let output = assert_success(seeded(&g.binary, "teardown", seed));
            let stdout = text(&output.stdout);
            assert!(
                stdout.contains("main 49\n") && stdout.ends_with("atexit handler says bye\n"),
                "seed {seed}: {stdout}"
            );
            let output = assert_success(seeded(&g.binary, "env-teardown", seed));
            assert_eq!(
                text(&output.stdout),
                "atexit handler set bye\n",
                "seed {seed}"
            );
        }
        let native = assert_build_c_guest("stdio_lifecycle_probe.c", CLink::Unlinked);
        let native = assert_success(standalone_output(&native.binary, &["errno"], &[]));
        let patina = assert_success(seeded(&g.binary, "errno", 1));
        assert_eq!(text(&patina.stdout), text(&native.stdout));
    }

    /// A refusal ends the run by the private abort, which glibc's exit flush
    /// never sees: the output the guest buffered before it still reaches the
    /// capture, through a scheduler refusal (a relocked normal mutex; Linux:
    /// Darwin's static mutexes are error-checking, so the relock is EDEADLK
    /// there) and the trap-class refusal (`trap_fatal`: a zoneinfo file
    /// `localtime_r` would read). A failed C `assert()` is glibc's: the same
    /// message on stderr, the buffered stdout lost, death by SIGABRT, and (a
    /// guest abort) a finalized trace. glibc's own hook wrote through its
    /// `stderr`, which in a guest is the shim's sentinel, and died of SIGSEGV.
    #[cfg(target_os = "linux")]
    #[test]
    fn refusals_keep_the_buffered_output_and_a_failed_assert_is_glibcs() {
        use std::os::unix::process::ExitStatusExt;
        let g = assert_build_c_guest("stdio_lifecycle_probe.c", CLink::PosixShim);
        for case in ["deadlock", "zoneinfo"] {
            let output = seeded(&g.binary, case, 1);
            assert_eq!(
                output.status.signal(),
                Some(6),
                "{case}: {}",
                text(&output.stderr)
            );
            assert!(!output.stderr.is_empty(), "a refusal names itself");
            assert_eq!(text(&output.stdout), "progress before the refusal\n");
        }
        let native = assert_build_c_guest("stdio_lifecycle_probe.c", CLink::Unlinked);
        let native = standalone_output(&native.binary, &["assert"], &[]);
        let patina = seeded(&g.binary, "assert", 1);
        assert_eq!(native.status.signal(), Some(6), "{}", text(&native.stderr));
        assert_eq!(patina.status.signal(), Some(6), "{}", text(&patina.stderr));
        assert_eq!(text(&patina.stderr), text(&native.stderr));
        assert_eq!(text(&patina.stdout), text(&native.stdout));
        let (recorded, trace) = g.record_standalone(&["assert"]);
        assert_eq!(
            recorded.status.signal(),
            Some(6),
            "{}",
            text(&recorded.stderr)
        );
        patina_dst_trace::TraceBundle::load(&trace).expect("a failed assert finalizes its trace");
    }

    /// glibc's standard-stream calls, each case reporting what reached a pipe
    /// after every call, natively and under patina alike (Linux: the rules
    /// are glibc's), called (-O0) and, for the entry points, inlined (-O2):
    ///
    /// - `modes` (`stdio_modes_probe.c`): the buffering modes (`setvbuf`,
    ///   `setbuf`, `setlinebuf`, line buffering, `ferror`/`clearerr`,
    ///   `flockfile`);
    /// - `chars` (`stdio_chars_probe.c`): the character and positioning calls
    ///   a C++ runtime makes (`putc`, `getc`, `fread`, `ungetc`, `fileno`,
    ///   `fseeko64`, `ftello64`), on a pipe and on a regular file;
    /// - the default case (`stdio_entry_probe.c`): every character entry
    ///   point beside putc/getc (the `_unlocked` and `_IO_` spellings,
    ///   `fgetc`, the `__overflow`/`__uflow` slow paths of the inline bodies),
    ///   glibc's internal lock spellings and `fclose`.
    ///
    /// `getchar` (glibc's own stdin), `freopen` of a standard stream and any
    /// other `FILE*` stop by name.
    #[cfg(target_os = "linux")]
    #[test]
    fn standard_stream_calls_match_the_host() {
        use std::os::unix::process::ExitStatusExt;
        let modes = guest_source("stdio_modes_probe.c");
        let chars = guest_source("stdio_chars_probe.c");
        for opt in ["-O0", "-O2"] {
            let flags = [opt, modes.to_str().unwrap(), chars.to_str().unwrap()];
            let build = |link| assert_build_c_guest_with_flags("stdio_entry_probe.c", link, &flags);
            let native = build(CLink::Unlinked);
            let g = build(CLink::PosixShim);
            // The mode and character reports are of calls; only the entry
            // points have inline bodies to compare.
            let cases: &[&str] = if opt == "-O0" {
                &["", "modes", "chars"]
            } else {
                &[""]
            };
            for &case in cases {
                let host = assert_success(standalone_output(&native.binary, &[case], &[]));
                let patina = assert_success(seeded(&g.binary, case, 1));
                assert!(!host.stdout.is_empty(), "{opt} {case}");
                assert_eq!(text(&patina.stdout), text(&host.stdout), "{opt} {case}");
            }
            if opt == "-O0" {
                for (case, stop) in [
                    ("getchar", "getchar reads glibc's own stdin"),
                    ("freopen", "freopen of a standard stream"),
                    ("foreign", "not the shim's stdout or stderr: fputc"),
                ] {
                    let stopped = seeded(&g.binary, case, 1);
                    let stderr = text(&stopped.stderr);
                    assert_eq!(stopped.status.signal(), Some(6), "{case}: {stderr}");
                    assert!(stderr.contains(stop), "{case}: {stderr}");
                }
            }
        }
    }

    /// libstdc++ binds `stdout` and `stderr` to the shim's streams, so every
    /// call it makes on them must be the shim's: `std::endl` and `put` (putc),
    /// `tellp` (fseeko64/ftello64) give the host's output, after the C++
    /// runtime's own constructor ran (before Patina's runtime is installed)
    /// through interposed calls. `cin` reads glibc's own `stdin`, which the
    /// shim does not model: a named stop, never a host read.
    #[cfg(target_os = "linux")]
    #[test]
    fn cxx_standard_streams_match_the_host() {
        use std::os::unix::process::ExitStatusExt;
        let native = tempfile::tempdir().unwrap();
        let host = native.path().join("cxx-guest");
        assert_success(
            std::process::Command::new(std::env::var("CXX").unwrap_or_else(|_| "c++".into()))
                .args(["-std=c++17", "-Wall", "-Wextra", "-Werror"])
                .arg(guest_source("cxx_stdio_probe.cc"))
                .arg("-o")
                .arg(&host)
                .output()
                .unwrap(),
        );
        let native = assert_success(standalone_output(&host, &[""], &[]));
        let g = assert_build_cxx_guest("cxx_stdio_probe.cc");
        let patina = assert_success(seeded(&g.binary, "", 1));
        assert!(text(&native.stdout).contains("CXX_STDIO_ENDL"));
        assert_eq!(text(&patina.stdout), text(&native.stdout));
        assert_eq!(text(&patina.stderr), text(&native.stderr));
        let cin = seeded(&g.binary, "cin", 1);
        assert_eq!(cin.status.signal(), Some(6), "{}", text(&cin.stderr));
        let refusal = text(&cin.stderr);
        assert!(refusal.contains("getc"), "{refusal}");
    }
}

/// Class pairing: timer imports must be refused and their registry rows must
/// match compiled definitions (syscall_registry); raw/libc share one model.
#[cfg(target_os = "linux")]
#[test]
fn libc_timers_follow_virtual_time_and_replay() {
    let g = assert_build_c_guest_with_flags(
        "signals/libc_timers.c",
        CLink::PosixShim,
        &["-Wl,--gc-sections"],
    );
    g.assert_audit_clean();
    g.assert_no_imports(&["setitimer", "getitimer", "alarm", "timer_", "timerfd_"]);
    assert_eq!(g.assert_run_success(7, &[]).stdout, b"LIBC_TIMERS_OK\n");
    g.assert_internal_fatal(&["thread"], &["SIGEV_THREAD callbacks are not modeled"]);
}

/// Class pairing: named timer import refusal; Darwin has no scheduled signal
/// model, so even direct execution must never fall through to libSystem.
#[cfg(target_os = "macos")]
#[test]
fn darwin_interval_timer_doors_refuse_by_name() {
    let g = assert_build_c_guest("signals/libc_timers.c", CLink::PosixShim);
    for name in ["setitimer", "getitimer", "alarm", "ualarm"] {
        g.assert_internal_fatal(&[name], &[&format!("Darwin {name} is not modeled")]);
    }
}
