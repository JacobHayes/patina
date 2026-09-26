//! ABI-door and scheduler integration pins. Unlike the Linux host-oracle
//! probes these also execute on macOS and Linux arm64, and pin virtual time.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

#[test]
fn prefixed_c_abi_preserves_crash_checkpoint() {
    let g = assert_build_c_guest("probe.c", CLink::Shim);
    let first = assert_standalone_success(&g.binary, &["123"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["123"], &[]).stdout
    );
    let fields = assert_fields(
        &first,
        "NATIVE_SHIM_RESULT ",
        &["seed", "random", "before", "after", "contents"],
    );
    assert_eq!(fields["seed"], "123");
    assert_lower_hex(fields["random"], 32);
    assert_eq!(fields["before"], "0");
    assert_eq!(fields["after"], "5000000");
    assert_eq!(fields["contents"], "stable");
    let other = assert_standalone_success(&g.binary, &["124"], &[]).stdout;
    let other = assert_fields(
        &other,
        "NATIVE_SHIM_RESULT ",
        &["seed", "random", "before", "after", "contents"],
    );
    assert_ne!(
        fields["random"], other["random"],
        "entropy must vary, not just the printed seed"
    );
}

#[test]
fn prefixed_c_env_protocol_records_and_replays_without_seed() {
    let g = assert_build_c_guest("probe.c", CLink::Shim);
    let trace = g.dir.path().join("env.patina");
    let env = [
        ("PATINA_MODE", "record"),
        ("PATINA_SEED", "123"),
        ("PATINA_TRACE", trace.to_str().unwrap()),
        ("PATINA_FINGERPRINT", "c-abi-v1"),
    ];
    let record = assert_standalone_success(&g.binary, &["env"], &env).stdout;
    let replay_env = [
        ("PATINA_MODE", "replay"),
        ("PATINA_TRACE", trace.to_str().unwrap()),
        ("PATINA_FINGERPRINT", "c-abi-v1"),
    ];
    assert_eq!(
        record,
        assert_standalone_success(&g.binary, &["env"], &replay_env).stdout
    );
}

#[test]
fn posix_descriptors_and_environment_are_virtualized() {
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
fn posix_at_paths_resolve_relative_to_directory_fds() {
    let g = assert_build_c_guest("openat_probe.c", CLink::PosixShim);
    let first = assert_standalone_success(&g.binary, &["5"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["5"], &[]).stdout
    );
    assert_eq!(
        text(&first),
        "NATIVE_OPENAT_RESULT seed=5 contents=openat\n"
    );
}

#[test]
fn realpath_buffer_conventions_agree() {
    let g = assert_build_c_guest("realpath_probe.c", CLink::PosixShim);
    let first = assert_standalone_success(&g.binary, &["5"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["5"], &[]).stdout
    );
    assert_eq!(
        text(&first),
        "NATIVE_REALPATH_RESULT seed=5 canonical=/root/fragments\n"
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
        text(&g.assert_seeded_record_replay_identity(1, &[])),
        "NATIVE_LIBC_AT_RESULT link=target.txt read=pointed-at abs=/state/target.txt\n"
    );
}

#[test]
fn std_file_clone_shares_cursor() {
    let g = Guest::assert_build("dup_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_seeded_record_replay_identity(3, &[])),
        "NATIVE_DUP_RESULT head=abc rest=def mid=bc\n"
    );
}

fn assert_repeated_output(g: &Guest, seeds: &[u64], expected: &str) {
    assert!(!seeds.is_empty(), "at least one seed must be checked");
    g.assert_audit_clean();
    for &seed in seeds {
        assert_eq!(text(&g.assert_seed_repeatability(seed, 2, &[])), expected);
    }
}

#[test]
fn pipe_reader_is_woken_by_writer_thread() {
    let g = Guest::assert_build("pipe_probe.rs");
    let expected = "NATIVE_PIPE_RESULT got=ping-pong\n";
    assert_repeated_output(&g, &[1, 2], expected);
    g.assert_record_replay_identity(1, &[], expected.as_bytes());
}

#[test]
fn socketpair_transfers_in_both_directions() {
    let g = Guest::assert_build("socketpair_probe.rs");
    let expected = "NATIVE_SOCKETPAIR_RESULT reply=PING\n";
    assert_repeated_output(&g, &[1, 2], expected);
    g.assert_record_replay_identity(1, &[], expected.as_bytes());
}

#[test]
fn closed_pipe_returns_epipe_without_sigpipe() {
    let g = Guest::assert_build("pipe_epipe_probe.rs");
    assert_repeated_output(&g, &[1], "NATIVE_PIPE_EPIPE_RESULT epipe=true eof=true\n");
}

#[test]
fn nonblocking_pipes_return_eagain() {
    let g = Guest::assert_build("pipe_nonblock_probe.rs");
    assert_repeated_output(&g, &[1], "NATIVE_PIPE_NONBLOCK_RESULT ok=true\n");
}

#[test]
fn pipe_aliases_keep_channels_alive() {
    let g = Guest::assert_build("pipe_dup_probe.rs");
    assert_repeated_output(
        &g,
        &[1],
        "NATIVE_PIPE_DUP_RESULT ok=true eof=true epipe=true\n",
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    #[test]
    fn epoll_wakes_readers_and_refires_edges() {
        let g = Guest::assert_build("epoll_probe.rs");
        let expected = "NATIVE_EPOLL_RESULT latched=0 refired=1\n";
        assert_repeated_output(&g, &[1, 2], expected);
        g.assert_record_replay_identity(1, &[], expected.as_bytes());
    }

    #[test]
    fn eventfd_writer_wakes_epoll_waiter() {
        let g = Guest::assert_build("eventfd_probe.rs");
        assert_repeated_output(
            &g,
            &[1],
            "NATIVE_EVENTFD_RESULT woke=1 refired=1 sem_ok=true\n",
        );
    }

    /// A shared file mapping is a view of the page cache the crash model
    /// judges: a store through it is what a read returns, an in-process crash
    /// rolls the file AND the mapping back to the durable image, and
    /// `msync(MS_SYNC)` makes a store survive the next crash.
    #[test]
    fn shared_file_mappings_follow_the_crash_model() {
        let g = assert_build_c_guest("mmap_crash_probe.c", CLink::PosixShim);
        let first = assert_standalone_success(&g.binary, &[], &[]).stdout;
        assert_eq!(first, assert_standalone_success(&g.binary, &[], &[]).stdout);
        assert_eq!(text(&first), "NATIVE_MMAP_CRASH_RESULT contents=synced!\n");
    }

    /// Run one `mem_probe.c` mode, with the host's `RLIMIT_MEMLOCK` at zero:
    /// every lock answer the guest sees must be the virtual kernel's.
    fn mem_probe(mode: &str) -> std::process::Output {
        mem_probe_with(mode, None)
    }

    /// `mem_probe`, with the host's `RLIMIT_NOFILE` (soft and hard) at
    /// `descriptors` when given.
    fn mem_probe_with(mode: &str, descriptors: Option<libc::rlim_t>) -> std::process::Output {
        use std::os::unix::process::CommandExt;
        let g = assert_build_c_guest("mem_probe.c", CLink::PosixShim);
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

    fn assert_mem_probe(mode: &str) {
        let output = mem_probe(mode);
        assert!(output.status.success(), "{mode}: {output:?}");
        assert_eq!(
            text(&output.stdout),
            format!("NATIVE_MEM_RESULT {mode}=ok\n")
        );
    }

    /// `RLIMIT_MEMLOCK` is the virtual 8 MiB whatever the host's is, lowers
    /// but never rises again, and judges `mlock`.
    #[test]
    fn memlock_limit_is_virtual() {
        assert_mem_probe("limits");
    }

    /// A shared view that may not write (a read-only file, `SHM_RDONLY`)
    /// refuses `PROT_WRITE`; a private copy of the same file takes it.
    #[test]
    fn mprotect_refuses_write_on_read_only_shared_views() {
        assert_mem_probe("mprotect");
    }

    /// Zero hugetlb pages, one answer across `mmap`, `shmget` and `memfd`.
    #[test]
    fn hugetlb_has_no_configured_pages() {
        assert_mem_probe("huge");
    }

    /// Transparent huge pages are off: one touch makes one page resident.
    #[test]
    fn transparent_huge_pages_are_disabled() {
        assert_mem_probe("thp");
    }

    /// A touch past the end of a mapped file is `SIGBUS`.
    #[test]
    fn touching_past_end_of_file_raises_sigbus() {
        use std::os::unix::process::ExitStatusExt;
        let output = mem_probe("sigbus");
        assert_eq!(output.status.signal(), Some(libc::SIGBUS), "{output:?}");
    }

    /// `mlock` populates what it locks, and a page no fault reaches (no
    /// access, past a file's end) is `ENOMEM`.
    #[test]
    fn mlock_answers_what_populating_found() {
        assert_mem_probe("populate");
    }

    /// Each mapped file holds a host memfd; past the host's descriptor limit
    /// the shim stops by name instead of answering the guest `EMFILE`.
    #[test]
    fn host_descriptor_exhaustion_is_a_named_fatal() {
        let output = mem_probe_with("descriptors", Some(64));
        assert!(!output.status.success(), "{output:?}");
        assert!(
            text(&output.stderr).contains("the host refused a memfd for guest memory"),
            "{output:?}"
        );
    }

    #[test]
    fn epoll_timeout_advances_exact_virtual_time() {
        let g = Guest::assert_build("epoll_timeout_probe.rs");
        assert_repeated_output(&g, &[1], "NATIVE_EPOLL_TIMEOUT timeout_ms=50\n");
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    #[test]
    fn kqueue_reports_fields_and_wakes_reader() {
        let g = Guest::assert_build("kqueue_probe.rs");
        let expected = "NATIVE_KQUEUE_RESULT got=ping\n";
        assert_repeated_output(&g, &[1, 2], expected);
        g.assert_record_replay_identity(1, &[], expected.as_bytes());
    }

    #[test]
    fn kqueue_user_events_wake_and_timeout_exactly() {
        let g = Guest::assert_build("kqueue_user_probe.rs");
        assert_repeated_output(
            &g,
            &[1],
            "NATIVE_KQUEUE_USER_TIMEOUT user_ok=true timeout_ms=50\n",
        );
    }

    #[test]
    fn clock_nsec_matches_clock_gettime() {
        let g = Guest::assert_build("clock_nsec_probe.rs");
        g.assert_audit_clean();
        let out = g.assert_seed_repeatability(1, 2, &[]);
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

    fn guest(link: CLink) -> Guest {
        assert_build_c_guest("stdio_lifecycle_probe.c", link)
    }

    fn seeded(binary: &std::path::Path, case: &str, seed: u64) -> std::process::Output {
        let seed = seed.to_string();
        standalone_output(
            binary,
            &[case],
            &[("PATINA_MODE", "seeded"), ("PATINA_SEED", &seed)],
        )
    }

    /// Only the root task runs after `main`: an atexit handler's `printf` must
    /// not wait on the stream lock a parked printing thread holds (that wait
    /// is a scheduling operation past the end of `main`, a refusal).
    #[test]
    fn stdio_after_main_takes_no_scheduler_lock() {
        let g = guest(CLink::PosixShim);
        for seed in 1..=8 {
            let output = assert_success(seeded(&g.binary, "teardown", seed));
            let stdout = text(&output.stdout);
            assert!(
                stdout.contains("main 49\n") && stdout.ends_with("atexit handler says bye\n"),
                "seed {seed}: {stdout}"
            );
        }
    }

    /// The environment's lock (glibc's `envlock`) is released the same way:
    /// an atexit `setenv` beside a parked `setenv` loop.
    #[test]
    fn setenv_after_main_takes_no_scheduler_lock() {
        let g = guest(CLink::PosixShim);
        for seed in 1..=8 {
            let output = assert_success(seeded(&g.binary, "env-teardown", seed));
            assert_eq!(
                text(&output.stdout),
                "atexit handler set bye\n",
                "seed {seed}"
            );
        }
    }

    /// Choosing stdout's buffer asks fstat about the descriptor; the answer
    /// for the capture must not leave an errno the host's pipe would not.
    #[test]
    fn the_first_write_leaves_errno_alone() {
        let native = assert_success(standalone_output(
            &guest(CLink::Unlinked).binary,
            &["errno"],
            &[],
        ));
        let patina = assert_success(seeded(&guest(CLink::PosixShim).binary, "errno", 1));
        assert_eq!(text(&patina.stdout), text(&native.stdout));
    }

    /// A refusal ends the run by the private abort, which glibc's exit flush
    /// never sees: the output the guest buffered before it still reaches the
    /// capture (Linux: Darwin's static mutexes are error-checking, so the
    /// relock is EDEADLK there, not a refusal).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refusal_keeps_the_buffered_output() {
        assert_refusal_keeps_output("deadlock");
    }

    /// The same through the trap-class refusal (`trap_fatal`): a zoneinfo file
    /// `localtime_r` would read.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_trap_refusal_keeps_the_buffered_output() {
        assert_refusal_keeps_output("zoneinfo");
    }

    /// A failed C `assert()` is glibc's: the same message on stderr, the
    /// buffered stdout lost, death by SIGABRT, and (a guest abort) a finalized
    /// trace. glibc's own hook wrote through its `stderr`, which in a guest is
    /// the shim's sentinel, and died of SIGSEGV.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_assert_is_glibcs_abort() {
        use std::os::unix::process::ExitStatusExt;
        let native = standalone_output(&guest(CLink::Unlinked).binary, &["assert"], &[]);
        let g = guest(CLink::PosixShim);
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

    /// glibc's buffering modes (`setvbuf`, `setbuf`, `setlinebuf`, line
    /// buffering, `ferror`/`clearerr`, `flockfile`) observed on a pipe after
    /// every call: the same report natively and under patina. Linux: the
    /// rules are glibc's.
    #[cfg(target_os = "linux")]
    #[test]
    fn buffering_modes_match_the_host() {
        let source = "stdio_modes_probe.c";
        let native = assert_success(standalone_output(
            &assert_build_c_guest(source, CLink::Unlinked).binary,
            &[],
            &[],
        ));
        let g = assert_build_c_guest(source, CLink::PosixShim);
        let patina = assert_success(seeded(&g.binary, "", 1));
        assert!(!native.stdout.is_empty());
        assert_eq!(text(&patina.stdout), text(&native.stdout));
    }

    #[cfg(target_os = "linux")]
    fn assert_refusal_keeps_output(case: &str) {
        use std::os::unix::process::ExitStatusExt;
        let g = guest(CLink::PosixShim);
        let output = seeded(&g.binary, case, 1);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        assert!(!output.stderr.is_empty(), "a refusal names itself");
        assert_eq!(text(&output.stdout), "progress before the refusal\n");
    }
}
