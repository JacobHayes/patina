//! Real C/raw doors paired with the signals state/wait and fatal-policy detectors.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

#[cfg(target_os = "linux")]
fn assert_interruptible_wait(case: &str) {
    let g = assert_build_c_guest("signals/blocking_readiness.c", CLink::PosixShim);
    let output = assert_standalone_success(
        &g.binary,
        &[case],
        &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")],
    );
    assert_eq!(output.stdout, b"NATIVE_SIGNAL_READINESS_OK\n");
}

#[cfg(target_os = "linux")]
#[test]
fn libc_poll_is_eintr_even_with_sa_restart() {
    assert_interruptible_wait("poll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_ppoll_restores_mask_and_preserves_timeout_on_eintr() {
    assert_interruptible_wait("ppoll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_select_writes_remaining_timeout_on_eintr() {
    assert_interruptible_wait("select");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_pselect_restores_mask_and_preserves_timeout_on_eintr() {
    assert_interruptible_wait("pselect");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_epoll_pwait_restores_mask_on_eintr() {
    assert_interruptible_wait("epoll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_sleep_returns_remaining_seconds_on_signal() {
    assert_interruptible_wait("sleep");
}

/// A guest's own SIGSEGV handler gets each SIGSEGV the kernel would give it —
/// a stack overflow on its alternate stack, an access fault, both left by
/// `siglongjmp`, a raised one with the sender's code and `SA_RESETHAND`, a
/// fault whose edited context resumes — in the kernel's frame order among
/// other pending signals (whose frames, built beneath its own, are lost with
/// it when it leaves by `siglongjmp`, and run the action they were dequeued
/// with when it changes theirs), while the timestamp-counter trap keeps the host
/// disposition, so the guest prints what it prints natively; so do handlers
/// on alternate stacks with room for one delivery and little more, and
/// alarms whose handlers run between counter reads. A fault or a raise the
/// handler blocks takes the default action as natively (never a second run
/// of the handler), as does a fault inside another fault signal's handler
/// whose `sa_mask` blocks SIGSEGV; on an ordinary stack, where the shim cannot
/// tell a nested fault from a `siglongjmp`'d handler, it stops by name.
#[cfg(target_os = "linux")]
#[test]
fn a_guest_segv_handler_gets_what_the_kernel_would_give_it() {
    use std::os::unix::process::ExitStatusExt;
    let native = assert_build_c_guest("signals/segv_routing.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/segv_routing.c", CLink::PosixShim);
    let env = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")];
    for case in [
        "overflow",
        "raise",
        "resume",
        "order-shared",
        "order-mask",
        "order-escape",
        "order-reset",
        "nodefer-std",
        "nodefer-rt",
        "autodisarm-high",
        "front-small",
        "front-segv-small",
        "front-autodisarm-small",
        "front-segv-autodisarm-small",
        "alarm",
        "alarm-small",
        #[cfg(target_arch = "x86_64")]
        "kernel-gp",
    ] {
        let oracle = assert_standalone_success(&native.binary, &[case], &[]);
        let output = assert_standalone_success(&patina.binary, &[case], &env);
        assert_eq!(text(&output.stdout), text(&oracle.stdout), "{case}");
    }
    // Natively the next frame's handler starts under an upper handler's
    // edited saved mask; the shim cannot carry the mask over and stops by
    // name.
    assert_standalone_success(&native.binary, &["nodefer-edit"], &[]);
    let output = standalone_output(&patina.binary, &["nodefer-edit"], &env);
    assert_eq!(output.status.signal(), Some(6), "{output:?}");
    assert!(text(&output.stderr).contains("saved mask"), "{output:?}");
    let trap = cfg!(target_arch = "x86_64") && kernel_supports(KernelFeature::Tsc);
    for case in ["nested", "nested-stack", "reraise", "masked-fault"] {
        let oracle = standalone_output(&native.binary, &[case], &[]);
        let output = standalone_output(&patina.binary, &[case], &env);
        assert_eq!(oracle.status.signal(), Some(11), "{case}: {oracle:?}");
        let stopped = case == "nested-stack" && trap;
        let expected = if stopped { 6 } else { 11 };
        assert_eq!(output.status.signal(), Some(expected), "{case}: {output:?}");
        // Without the counter trap the host blocks SIGSEGV inside the
        // handler and the kernel kills the nested fault with no handler at
        // all; the captured output is on the host already.
        assert_eq!(text(&output.stdout), text(&oracle.stdout), "{case}");
    }
}

/// A delivery's cost to the stack its handler runs on. Natively that is the
/// kernel's signal frame, whose size is the host CPU's (its extended state);
/// under the shim the kernel's frame is private, and a delivery takes the
/// same few bytes on every host and every route: a raised signal, a fault
/// the front handler routes, a SIGSEGV (the counter trap's route on x86_64).
/// The small-stack fixtures size their stacks from this measurement, never
/// from auxv. CI keeps the native measurement and the CPU's flags.
#[cfg(target_os = "linux")]
#[test]
fn a_delivery_costs_the_guest_stack_a_fixed_few_bytes() {
    use std::io::Write;
    for source in ["signals/segv_routing.c", "signals/counter_small.c"] {
        let fixture = std::fs::read_to_string(guest_source(source)).unwrap();
        assert!(
            !fixture.contains("getauxval("),
            "auxv must not size {source}"
        );
    }
    let native = assert_build_c_guest("signals/segv_routing.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/segv_routing.c", CLink::PosixShim);
    let env = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")];
    let costs = |binary: &std::path::Path, env: &[(&str, &str)]| -> Vec<usize> {
        let output = assert_standalone_success(binary, &["route-cost"], env);
        let line = text(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("ROUTE_COST "))
            .expect("route cost measurement")
            .to_owned();
        let delivery = assert_standalone_success(binary, &["frame-size"], env);
        let calibrated = text(&delivery.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("DELIVERY_STACK_BYTES "))
            .and_then(|rest| rest.split_whitespace().next())
            .expect("delivery calibration")
            .parse()
            .unwrap();
        line.split_whitespace()
            .map(|field| field.split_once('=').unwrap().1.parse().unwrap())
            .chain([calibrated])
            .collect()
    };
    let oracle = costs(&native.binary, &[]);
    let shim = costs(&patina.binary, &env);
    assert!(
        oracle.iter().all(|cost| (512..128 * 1024).contains(cost)),
        "vacuous native measurement: {oracle:?}"
    );
    assert!(
        shim.windows(2).all(|pair| pair[0] == pair[1]) && shim[0] <= 64,
        "a delivery under the shim takes more than its slot and return address, or not the \
         same on every route: {shim:?} (native {oracle:?})"
    );
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();
    let flags = cpuinfo
        .lines()
        .find(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| matches!(key.trim(), "flags" | "Features"))
        })
        .expect("CPU feature flags");
    let measurement = format!(
        "delivery stack bytes ({arch}): native {oracle:?}, shim {shim:?}\nsignal calibration CPU {flags}",
        arch = std::env::consts::ARCH,
    );
    eprintln!("{measurement}");
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "{measurement}\n"
        )
        .unwrap();
    }
}

/// A runtime with small thread stacks runs its code on stacks of a few KiB,
/// makes raw syscalls there, and runs its handlers on alternate stacks whose
/// bounds it checks; a coroutine runtime switches stacks inside handlers. A
/// handler that code on a 2 KiB stack sends itself a signal for runs inside
/// the alternate stack it registered, is told so by `sigaltstack` and its
/// `uc_stack` (an `SS_AUTODISARM` one disabled, and registered again at its
/// return), nests a second handler there, and makes syscalls and libc calls
/// from both, writing nothing to the small stack; handlers that leave by
/// `siglongjmp`, thousands of times, leave the shim's private stack usable; a
/// handler that swapcontexts to a coroutine making syscalls on a stack of its
/// own (a mapping, or a local array of a frame above the handler), from a
/// plain or `SS_AUTODISARM` alternate stack or a thread's own stack, nested in
/// another handler or taking one inside the coroutine, returns intact; and a thread-local destructor's syscall after its
/// thread's handler left by `siglongjmp` is answered; handlers return out of
/// order across coroutines, nest by `siglongjmp` into an outer handler, and
/// suspend eight deep. The guest prints what
/// it prints natively, through the raw syscall trap (x86_64) and through
/// libc's `syscall(2)` (every arch).
#[cfg(target_os = "linux")]
#[test]
fn handlers_run_on_the_stacks_they_ask_for() {
    let native = assert_build_c_guest("signals/small_stack.c", CLink::Unlinked);
    let env = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "3")];
    let cases = [
        "altstack",
        "autodisarm",
        "escape",
        "exit-escape",
        // Coroutine stacks mapped, and carved from a frame above the handler.
        "swap-ma--",
        "swap-md--",
        "swap-mdn-",
        "swap-mo-t",
        "swap-la--",
        "swap-ld--",
        "swap-lds-",
        "swap-lo--",
        "swap-lon-",
        "swap-los-",
        "swap-la-t",
        "swap-ldst",
        "swap-lo-t",
        "swap-lont",
        "swap-lost",
        // Handlers that return out of order, suspended at once, or left by
        // `siglongjmp` into an outer handler or from shallower points.
        "interleave",
        "interleave-alt",
        "outer",
        "outer-alt",
        "chain-8",
        "shallower-60",
    ];
    // The raw door needs syscall-user-dispatch; libc's is every arch's.
    let raw = cfg!(target_arch = "x86_64")
        .then(|| sud_c_guest("signals/small_stack.c"))
        .flatten();
    let libc = assert_build_c_guest("signals/small_stack.c", CLink::PosixShim);
    let runs = raw
        .iter()
        .flat_map(|g| cases.map(|case| (&g.binary, case.to_owned())))
        .chain(cases.map(|case| (&libc.binary, format!("{case}-libc"))));
    for (binary, case) in runs {
        let oracle = assert_standalone_success(&native.binary, &[&case], &[]);
        let output = assert_standalone_success(binary, &[&case], &env);
        assert_eq!(text(&output.stdout), text(&oracle.stdout), "{case}");
    }
    // Past what the shim tracks the run stops by name where natively it runs
    // on: 70 handlers suspended at once, and 70 left by `siglongjmp` from
    // ever shallower points, which nothing proves left (`frames.rs`).
    for case in ["chain-70", "shallower-70"] {
        use std::os::unix::process::ExitStatusExt;
        assert_standalone_success(&native.binary, &[case], &[]);
        let output = standalone_output(&libc.binary, &[&format!("{case}-libc")], &env);
        assert_eq!(output.status.signal(), Some(6), "{case}: {output:?}");
        assert!(
            text(&output.stderr).contains("not modeled"),
            "{case}: {output:?}"
        );
    }
}

/// A synchronous signal an instruction raises (SIGBUS, SIGFPE, SIGILL,
/// SIGTRAP) meets the action the kernel would give it: after a delivery
/// batch's handler leaves by `siglongjmp` from a frame that ran the action
/// its dequeue captured, the next genuine one runs the guest's current
/// action, under that action's mask, so the guest prints what it prints
/// natively.
#[cfg(target_os = "linux")]
#[test]
fn synchronous_signals_meet_the_action_the_kernel_would_give_them() {
    let native = assert_build_c_guest("signals/fault_routing.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/fault_routing.c", CLink::PosixShim);
    let env = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")];
    let oracle = assert_standalone_success(&native.binary, &["swap-escape"], &[]);
    let output = assert_standalone_success(&patina.binary, &["swap-escape"], &env);
    assert_eq!(text(&output.stdout), text(&oracle.stdout));
}

/// A genuine fault that takes the default action (SIGBUS, SIGFPE, SIGILL,
/// SIGTRAP) ends the run by that signal with what the guest wrote to its
/// descriptors before it on the host, and what C `stdout` still buffered
/// lost, exactly as natively: also on a thread that blocks every signal,
/// whose fault the kernel takes with no handler, so no shim code runs.
#[cfg(target_os = "linux")]
#[test]
fn a_fault_death_keeps_what_the_guest_wrote_before_it() {
    use std::os::unix::process::ExitStatusExt;
    let native = assert_build_c_guest("signals/fault_routing.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/fault_routing.c", CLink::PosixShim);
    let env = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")];
    let cases: &[&str] = if cfg!(target_arch = "x86_64") {
        &["die-bus", "die-trap", "die-fpe", "die-int3", "die-blocked"]
    } else {
        &["die-bus", "die-trap", "die-blocked"]
    };
    for case in cases {
        let oracle = standalone_output(&native.binary, &[case], &[]);
        let output = standalone_output(&patina.binary, &[case], &env);
        assert!(
            oracle.status.signal().is_some(),
            "native {case}: {oracle:?}"
        );
        assert_eq!(
            output.status.signal(),
            oracle.status.signal(),
            "{case}: {output:?}"
        );
        assert_eq!(text(&output.stdout), text(&oracle.stdout), "{case}");
        assert!(
            text(&output.stderr).contains(text(&oracle.stderr)),
            "{case}: {output:?}"
        );
    }
}

/// A handler that adds the containment signals to its frame's saved mask
/// gets them blocked natively when it returns, and the guest runs on; so does
/// one whose action's `sa_mask` blocks them while it runs. Under patina the
/// return must leave them unblocked (whichever restorer ran), and so must the
/// handler's own run, so the next raw syscall and timestamp-counter read are
/// still answered and the guest prints what it prints natively.
#[cfg(target_os = "linux")]
#[test]
fn a_handler_frame_cannot_block_the_containment_signals() {
    let native = assert_build_c_guest("signals/frame_mask.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/frame_mask.c", CLink::PosixShim);
    let cases: &[&str] = if cfg!(target_arch = "x86_64") {
        &["libc", "sa-mask", "raw", "raw-libc"]
    } else {
        &["libc", "sa-mask"]
    };
    for case in cases {
        let oracle = assert_standalone_success(&native.binary, &[case], &[]);
        assert_eq!(oracle.stdout, b"FRAME_MASK_OK\n", "native {case}");
        let output = standalone_output(
            &patina.binary,
            &[case],
            &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")],
        );
        assert!(
            output.status.success(),
            "{case}: {:?}\n{}",
            output.status,
            text(&output.stderr)
        );
        assert_eq!(output.stdout, oracle.stdout, "{case}");
    }
}

/// A thread's exit walks the robust list it registered (the virtual kernel's
/// `exit_robust_list`): its own futex word gains `FUTEX_OWNER_DIED` and keeps
/// its waiters bit, another thread's is left alone. Natively the host kernel
/// does the same, so the guest's assertions hold on both.
#[cfg(target_os = "linux")]
#[test]
fn a_thread_exit_walks_its_robust_list() {
    let g = assert_build_c_guest("signals/thread_registrations.c", CLink::PosixShim);
    let output = assert_standalone_success(
        &g.binary,
        &["robust-exit"],
        &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")],
    );
    assert_eq!(output.stdout, b"ROBUST_EXIT_OK\n");
}

/// The exit walk wakes a dead owner's futexes as the kernel does, by their
/// shared key: a `FUTEX_WAIT` waiter on an owned word wakes and sees
/// `FUTEX_OWNER_DIED`, a waiter on the pending operation's zero word wakes,
/// and a `FUTEX_WAIT_PRIVATE` waiter stays parked until woken privately.
#[cfg(target_os = "linux")]
#[test]
fn a_dead_owners_walk_wakes_only_shared_waiters() {
    let g = assert_build_c_guest("signals/thread_registrations.c", CLink::PosixShim);
    for seed in ["7", "8"] {
        let output = assert_standalone_success(
            &g.binary,
            &["robust-wake"],
            &[("PATINA_MODE", "seeded"), ("PATINA_SEED", seed)],
        );
        assert_eq!(
            text(&output.stdout),
            "shared woken=1 owner_died=1 waiters=1\n\
             pending woken=1\n\
             private left waiting=1 owner_died=1\n",
            "seed {seed}"
        );
    }
}

/// The exit walk runs where the kernel's does, after the thread's
/// thread-local destructors: one that releases its thread's robust lock
/// still finds it held, as it does natively.
#[cfg(target_os = "linux")]
#[test]
fn thread_local_destructors_run_before_the_exit_walk() {
    let native = assert_build_c_guest("signals/thread_registrations.c", CLink::Unlinked);
    let patina = assert_build_c_guest("signals/thread_registrations.c", CLink::PosixShim);
    let oracle = assert_standalone_success(&native.binary, &["robust-dtor"], &[]);
    assert_eq!(
        text(&oracle.stdout),
        "destructor found its lock held=1, released=1\n"
    );
    let output = assert_standalone_success(
        &patina.binary,
        &["robust-dtor"],
        &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")],
    );
    assert_eq!(text(&output.stdout), text(&oracle.stdout));
}

/// A thread just created has taken over its registrations before
/// `pthread_create` returns: `get_robust_list` of it names glibc's head for
/// it, on every seed and every run, where it once answered whichever state
/// the host had scheduled the new thread to.
#[cfg(target_os = "linux")]
#[test]
fn a_new_threads_robust_head_is_known_when_create_returns() {
    let g = assert_build_c_guest("signals/thread_registrations.c", CLink::PosixShim);
    let expected = (0..4)
        .map(|i| format!("thread {i}: result=0 glibc_head=1 own_view=1\n"))
        .collect::<String>();
    for seed in 1..=8u64 {
        for _ in 0..3 {
            let output = assert_standalone_success(
                &g.binary,
                &["robust-new"],
                &[
                    ("PATINA_MODE", "seeded"),
                    ("PATINA_SEED", &seed.to_string()),
                ],
            );
            assert_eq!(text(&output.stdout), expected, "seed {seed}");
        }
    }
}

/// glibc's rseq registration of every thread is taken off the host and kept
/// virtually: the area stays registered (a second registration is `EBUSY`)
/// and names the one virtual CPU, and the host never writes it. The host
/// kernel rewrites a registered area's CPU fields at every signal delivery,
/// so a sentinel that survives a handled signal proves no host registration
/// is left, deterministically. Patina only: natively the host's registration
/// overwrites the sentinel, by design.
#[cfg(target_os = "linux")]
#[test]
fn rseq_areas_are_never_written_by_the_host() {
    let g = assert_build_c_guest("signals/thread_registrations.c", CLink::PosixShim);
    for seed in ["7", "8"] {
        let output = assert_standalone_success(
            &g.binary,
            &["rseq-sentinel"],
            &[("PATINA_MODE", "seeded"), ("PATINA_SEED", seed)],
        );
        assert_eq!(
            text(&output.stdout),
            "main virtual_cpu=1 start_kept=1 id_kept=1\n\
             thread virtual_cpu=1 start_kept=1 id_kept=1\n\
             thread virtual_cpu=1 start_kept=1 id_kept=1\n",
            "seed {seed}"
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod raw {
    use super::*;
    use patina_dst_trace::TraceBundle;
    use std::os::unix::process::ExitStatusExt;

    fn assert_state(case: &str) {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        let (output, trace) = g.record_standalone(&[case]);
        assert_success(output);
        TraceBundle::load(&trace).expect("successful state probe finalizes its trace");
    }

    #[test]
    fn prctl_libc_and_raw_share_one_state() {
        assert_state("prctl");
    }
    #[test]
    fn libc_tgkill_and_tkill_deliver_registered_handler() {
        assert_state("handler");
    }
    #[test]
    fn libc_and_raw_masks_keep_the_traps_armed() {
        assert_state("masks");
    }
    #[test]
    fn nested_raw_handler_cannot_undo_outer_unblock() {
        assert_state("nested-unblock");
    }
    #[test]
    fn sigwait_retries_after_unrelated_handler() {
        assert_state("sigwait");
    }
    #[test]
    fn libc_sigsuspend_handler_sees_safe_temporary_mask() {
        assert_state("suspend-libc");
    }
    #[test]
    fn raw_sigsuspend_handler_sees_safe_temporary_mask() {
        assert_state("suspend-raw");
    }

    #[test]
    fn guest_abort_finalizes_trace_before_host_abort() {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        let (output, trace) = g.record_standalone(&["guest-abort"]);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        TraceBundle::load(&trace).expect("guest abort finalizes its trace");
    }

    /// glibc's `_FORTIFY_SOURCE` file failures are guest aborts, as `abort`
    /// is: glibc's exact diagnostic on stderr, SIGABRT, a finalized trace.
    /// Every `_chk` past its buffer is `__chk_fail`; every `__open*_2` that
    /// needs a mode is `__fortify_fail` naming its call (glibc io/open_2.c,
    /// open64_2.c, openat_2.c, openat64_2.c).
    #[test]
    fn fortify_failures_are_guest_aborts() {
        const OVERFLOW: &str = "*** buffer overflow detected ***: terminated";
        const CASES: [(&str, &str); 9] = [
            ("__read_chk", OVERFLOW),
            ("__pread_chk", OVERFLOW),
            ("__pread64_chk", OVERFLOW),
            ("__readlink_chk", OVERFLOW),
            ("__readlinkat_chk", OVERFLOW),
            (
                "__open_2",
                "*** invalid open call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__open64_2",
                "*** invalid open64 call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__openat_2",
                "*** invalid openat call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__openat64_2",
                "*** invalid openat64 call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
        ];
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        for (symbol, diagnostic) in CASES {
            let (output, trace) = g.record_standalone(&[&format!("fortify-{symbol}")]);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.signal(), Some(6), "{symbol}: {stderr}");
            assert!(
                stderr.lines().any(|line| line == diagnostic),
                "{symbol}: no {diagnostic:?} line in {stderr}"
            );
            TraceBundle::load(&trace)
                .unwrap_or_else(|error| panic!("{symbol}: the abort left no trace: {error}"));
        }
    }

    fn assert_internal_fatal(case: &str, diagnostic: &str) {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        g.assert_internal_fatal(&[case], &[diagnostic]);
    }
    #[test]
    fn internal_c_trap_leaves_trace_incomplete() {
        assert_internal_fatal("internal-c", "process spawn reached under patina: fork");
    }
    #[test]
    fn internal_raw_trap_leaves_trace_incomplete() {
        assert_internal_fatal("internal-rust", "SUD trapped syscall number 999999");
    }
    /// An internal stop is the shim's own abort, never a delivery: a
    /// guest's SIGABRT handler (a runtime's, whose raw syscalls would trap
    /// back into the stopping shim) does not run, and the run ends by
    /// SIGABRT with the named stop.
    #[test]
    fn an_internal_stop_never_runs_a_guest_abort_handler() {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        let (output, _) = g.record_standalone(&["internal-guest-abort-handler"]);
        g.assert_internal_fatal(
            &["internal-guest-abort-handler"],
            &["SUD trapped syscall number 999999"],
        );
        assert!(
            !text(&output.stderr).contains("handler ran"),
            "{}",
            text(&output.stderr)
        );
    }
    #[test]
    fn context_locked_refusal_never_reenters_the_scheduler() {
        assert_internal_fatal("internal-context-active", "no custom operation open");
    }

    #[test]
    fn nested_custom_op_fatal_leaves_trace_incomplete() {
        assert_internal_fatal("internal-context", "may not nest or be left unclosed");
    }
}

// Class pairing: internal Rust panic and guest abort must use different fatal
// vehicles. Fault injection is confined to a scratch copy of the real shim;
// the production export and its real ownership guard are both exercised.
#[test]
fn internal_rust_panic_never_finalizes_an_invalid_trace() {
    use patina_dst_trace::TraceBundle;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::Command;
    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    for strategy in ["unwind", "abort"] {
        let dir = tempfile::tempdir().unwrap();
        let workspace = common::native_workspace();
        let shim = dir.path().join("crates/patina-native-shim");
        copy_tree(&workspace.join("crates/patina-native-shim"), &shim);
        let mut manifest = std::fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
        let members = manifest.find("members = [").unwrap();
        let end = members + manifest[members..].find(']').unwrap() + 1;
        manifest.replace_range(members..end, "members = [\"crates/patina-native-shim\"]");
        // Dependencies retain their declared paths; only the shim is copied/mutated.
        manifest = manifest.replace(
            "path = \"crates/",
            &format!("path = \"{}/crates/", workspace.display()),
        );
        std::fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
        std::fs::copy(workspace.join("Cargo.lock"), dir.path().join("Cargo.lock")).unwrap();
        let source = shim.join("src/lib.rs");
        let source_text = std::fs::read_to_string(&source).unwrap();
        let anchor = "pub unsafe extern \"C\" fn patina_clock_now(clock_id: u32, nanos: *mut u64) -> c_int {\n    let _panic_scope = crate::panic_boundary::PanicScope::enter();";
        assert_eq!(
            source_text.matches(anchor).count(),
            1,
            "one production ABI guard injection site"
        );
        // A valid argument singles out the explicit query, not startup's clock reads.
        let planted = format!(
            "{anchor}\n    if clock_id == 1 {{ panic!(\"planted internal Rust panic\"); }}"
        );
        std::fs::write(source, source_text.replace(anchor, &planted)).unwrap();
        let target = dir.path().join("build");
        let built = assert_success(
            Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args([
                    "rustc",
                    "--lib",
                    "--offline",
                    "--message-format=json",
                    "-p",
                    "patina-dst-native-shim",
                    "--manifest-path",
                ])
                .arg(dir.path().join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .args(["--", "-C", &format!("panic={strategy}")])
                .output()
                .unwrap(),
        );
        // Cargo can redirect intermediates separately from target-dir. Consume
        // its artifact messages rather than guessing where dependency rlibs live.
        let dependency_dirs: std::collections::BTreeSet<std::path::PathBuf> = text(&built.stdout)
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("Cargo artifact JSON")
            })
            .filter(|message| message["reason"] == "compiler-artifact")
            .flat_map(|message| {
                message["filenames"]
                    .as_array()
                    .expect("artifact filenames")
                    .iter()
                    .filter_map(|name| {
                        let path = Path::new(name.as_str().expect("artifact path"));
                        (path.extension().is_some_and(|ext| ext == "rlib"))
                            .then(|| path.parent().unwrap().to_owned())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !dependency_dirs.is_empty(),
            "non-vacuous dependency artifacts"
        );
        let binary = dir.path().join("panic-guest");
        let posix = common::compile_posix_object(dir.path());
        let mut cc = common::c_compiler();
        cc.arg("-I")
            .arg(shim.join("include"))
            .arg(guest_source("signals/internal_panic.c"))
            .arg(posix)
            .arg(target.join("debug/libpatina_dst_native_shim.a"));
        if cfg!(target_os = "linux") {
            cc.arg("-Wl,--wrap=dlsym");
        }
        assert_success(cc.arg("-o").arg(&binary).output().unwrap());
        let guest = Guest { dir, binary };
        let (output, trace) = guest.record_standalone(&[]);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        assert!(
            text(&output.stderr).contains("planted internal Rust panic"),
            "{}",
            text(&output.stderr)
        );
        if let Ok(bundle) = TraceBundle::load(&trace) {
            bundle
                .validate()
                .expect("RED control: the pre-hook trace is complete and valid");
            panic!(
                "internal Rust panic finalized a complete valid trace ({} timelines)",
                bundle.timelines.len()
            );
        }
        // Replacing the hook cannot turn an internal unwind into guest abort.
        let vehicle = guest.dir.path().join("guest_panic.rs");
        let code = std::fs::read_to_string(guest_source("signals/guest_panic.rs")).unwrap();
        std::fs::write(
            &vehicle,
            format!("extern crate patina_dst_native_shim;\n{code}").replace("//!", "//"),
        )
        .unwrap();
        let binary = guest.dir.path().join("replacement-hook-guest");
        // Native libraries precede the compiler/system runtimes. A late
        // link-arg object can leave libc or outlined atomic helpers unresolved.
        let posix_archive = guest.dir.path().join("libpatina_test_posix.a");
        assert_success(
            Command::new("ar")
                .arg("crs")
                .arg(&posix_archive)
                .arg(guest.dir.path().join("patina_posix.o"))
                .output()
                .unwrap(),
        );
        let mut rustc = Command::new("rustc");
        rustc
            .arg("--edition=2024")
            .args(["-C", &format!("panic={strategy}")])
            .arg(&vehicle)
            .arg("--extern")
            .arg(format!(
                "patina_dst_native_shim={}",
                target
                    .join("debug/libpatina_dst_native_shim.rlib")
                    .display()
            ))
            .arg("-L")
            .arg(format!("native={}", guest.dir.path().display()))
            .args(["-l", "static=patina_test_posix"])
            .arg("-o")
            .arg(&binary);
        for directory in dependency_dirs {
            rustc
                .arg("-L")
                .arg(format!("dependency={}", directory.display()));
        }
        if cfg!(target_os = "linux") {
            rustc.args(["-C", "link-arg=-Wl,--wrap=dlsym"]);
        }
        assert_success(rustc.output().unwrap());
        let replacement = Guest {
            dir: guest.dir,
            binary,
        };
        let diagnostics: &[&str] = if strategy == "unwind" {
            &["patina native shim panic: unwinding an owned boundary"]
        } else if cfg!(target_os = "linux") {
            &["patina native shim panic: aborting an owned boundary"]
        } else {
            // Darwin has no guest abort interposer. With a replaced hook and
            // panic=abort, libc aborts directly: signal + incomplete trace are
            // the contract, not the Linux interposer's diagnostic.
            &[]
        };
        replacement.assert_internal_fatal(&["replace-internal"], diagnostics);
    }
}

#[test]
fn guest_panics_remain_catchable_in_main_and_callbacks() {
    let guest = Guest::assert_build("signals/guest_panic.rs");
    for mode in ["prior", "replace"] {
        let (output, trace) = guest.record_standalone(&[mode]);
        let output = assert_success(output);
        assert_exact_line(
            &output.stdout,
            if cfg!(target_os = "linux") {
                "GUEST_PANICS_CAUGHT=4"
            } else {
                "GUEST_PANICS_CAUGHT=2"
            },
        );
        patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .validate()
            .unwrap();
    }
}

/// Self-signal libc doors must bind to the platform model, record generation,
/// deliver to the caller (including workers), and permit modeled handler work.
#[test]
fn self_raise_is_modeled_and_replayable() {
    // Paired audit detector: the Rust compute-watchdog guest retains raise and
    // must pass the source-first CLI audit without allowances. C ABI fixtures
    // intentionally link a whole std staticlib, so run their behavior directly.
    let guest = assert_build_c_guest("signals/self_raise.c", CLink::PosixShim);
    guest.assert_no_imports(&["raise"]);
    let (first, path) = guest.record_standalone(&[]);
    let first = assert_success(first);
    assert_exact_line(&first.stdout, "SELF_RAISE_OK");
    let bytes = std::fs::read(&path).unwrap();
    let (second, _) = guest.record_standalone(&[]);
    assert_eq!(first.stdout, assert_success(second).stdout);
    assert_eq!(bytes, std::fs::read(&path).unwrap(), "record identity");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", "exec 3<\"$1\"; shift; exec \"$@\"", "native-boundary"])
        .arg(&path)
        .arg(&guest.binary)
        .envs([
            ("PATINA_MODE", "replay"),
            ("PATINA_TRACE_FD", "3"),
            ("PATINA_FINGERPRINT", "native-boundary"),
        ]);
    let replay = common::output_with_deadline(&mut command, std::time::Duration::from_secs(20))
        .expect("self-signal replay exceeded 20s");
    assert_eq!(first.stdout, assert_success(replay).stdout);
    let trace = patina_dst_trace::TraceBundle::load(&path).unwrap();
    let generated: Vec<_> = trace.timelines[0]
        .decisions
        .iter()
        .filter_map(|event| {
            if let patina_dst_abi::Operation::SignalGenerated { sig, target, .. } = event.operation
            {
                Some((sig, target))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        generated.len(),
        8,
        "record every delivered and ignored generation"
    );
    assert!(generated.iter().any(
        |(_, target)| *target == patina_dst_abi::SignalTarget::Task(patina_dst_abi::TaskId(2))
    ));
    use std::os::unix::process::ExitStatusExt;
    let (output, trace) = guest.record_standalone(&["default"]);
    assert_eq!(output.status.signal(), Some(libc::SIGTERM), "{output:?}");
    assert_exact_line(&output.stdout, "default");
    patina_dst_trace::TraceBundle::load(trace)
        .unwrap()
        .validate()
        .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn self_raise_refuses_unmodeled_delivery_before_calling_a_handler() {
    let guest = assert_build_c_guest("signals/self_raise.c", CLink::PosixShim);
    for (mode, message) in [
        ("reserved", "SIGSYS is reserved for containment"),
        ("stop", "Darwin default signal stop is not modeled"),
        (
            "info",
            "Darwin self-signal SA_SIGINFO delivery is not modeled",
        ),
        (
            "deferred",
            "Darwin deferred self-signal delivery is not modeled",
        ),
    ] {
        guest.assert_internal_fatal(&[mode], &[message]);
    }
}

// Class pairing: Linux interruption cases above plus the shared process/time
// adapters. This deliberately requires no raw-syscall or signal-delivery support.
#[test]
fn portable_process_answers_and_uninterrupted_sleep_replay() {
    let guest = assert_build_c_guest("signals/process_sleep.c", CLink::PosixShim);
    let (first, trace) = guest.record_standalone(&[]);
    assert_exact_line(&assert_success(first).stdout, "PROCESS_SLEEP_OK");
    let bytes = std::fs::read(&trace).unwrap();
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
    let (second, _) = guest.record_standalone(&[]);
    assert_exact_line(&assert_success(second).stdout, "PROCESS_SLEEP_OK");
    assert_eq!(bytes, std::fs::read(&trace).unwrap(), "record identity");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", "exec 3<\"$1\"; shift; exec \"$@\"", "native-boundary"])
        .arg(&trace)
        .arg(&guest.binary)
        .envs([
            ("PATINA_MODE", "replay"),
            ("PATINA_TRACE_FD", "3"),
            ("PATINA_FINGERPRINT", "native-boundary"),
        ]);
    let replay = common::output_with_deadline(&mut command, std::time::Duration::from_secs(20))
        .expect("standalone replay exceeded 20s");
    assert_exact_line(&assert_success(replay).stdout, "PROCESS_SLEEP_OK");
}
