//! Class-level pairing: frozen signals-family lifecycle conformance and trace
//! obligations. All mutations use the same ABI entries as the two guest doors.
use super::*;

const SIGPIPE: i32 = 13;
const SIGABRT: i32 = 6;
const SIGSTOP: i32 = 19;
const SIGTSTP: i32 = 20;
const SIGTTIN: i32 = 21;
const SIGTTOU: i32 = 22;
const MSG_NOSIGNAL: i32 = 0x4000;
const EPIPE: i32 = 32;

static HANDLER_TASK: AtomicUsize = AtomicUsize::new(0);
extern "C" fn task_handler(_: i32) {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    HANDLER_TASK.store(current_task().0 as usize, Ordering::SeqCst);
}
fn install_task_handler(sig: i32, flags: u64) -> Action {
    super::install_handler(sig, task_handler, flags, 0)
}
#[test]
fn broken_pipe_generates_sigpipe_before_epipe() {
    isolated(|| {
        let me = current_task();
        install_task_handler(SIGPIPE, 0);
        let [rd, wr] = pipe();
        assert_eq!(crate::patina_close(rd), 0);
        assert_eq!(
            unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
            -1
        );
        assert_eq!(crate::patina_errno(), EPIPE);
        assert_eq!(
            HANDLERS.load(Ordering::SeqCst),
            1,
            "delivery precedes EPIPE"
        );
        assert_eq!(HANDLER_TASK.load(Ordering::SeqCst), me.0 as usize);
        let ignore = Action {
            handler: SIG_IGN,
            ..Action::default()
        };
        assert_eq!(
            unsafe { patina_signal_action(SIGPIPE, &ignore, std::ptr::null_mut(), SIGSET_BYTES) },
            0
        );
        assert_eq!(
            unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
            -1
        );
        assert_eq!(crate::patina_errno(), EPIPE);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        assert_eq!(
            lock_state().signals.tasks[&me].private.mask(),
            0,
            "ignored generation is dropped"
        );
        // The production generation entry asserts SPIN_DEPTH == 0: either
        // broken-pipe call aborts if pipe_write holds its runtime lock here.
        assert_eq!(
            signal_ops(&operations()),
            vec![(SIGPIPE as u8, SignalTarget::Task(me)); 2]
        );
    });
}

#[test]
fn msg_nosignal_suppresses_sigpipe() {
    isolated(|| {
        install_task_handler(SIGPIPE, 0);
        let me = current_task();
        use crate::thread::net::abi::{AF_UNIX, SOCK_STREAM};
        use crate::thread::net::{patina_sock_sendto, patina_sock_socketpair};
        let mut fds = [-1i32; 2];
        assert_eq!(
            patina_sock_socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr() as usize),
            0
        );
        assert_eq!(crate::patina_close(fds[1]), 0);
        for (flags, count) in [(MSG_NOSIGNAL, 0), (0, 1)] {
            // The SUD sendto row and C send both reach this entry.
            assert_eq!(
                patina_sock_sendto(fds[0], b"x".as_ptr() as usize, 1, flags, 0, 0),
                -i64::from(EPIPE)
            );
            assert_eq!(HANDLERS.load(Ordering::SeqCst), count);
        }
        assert_eq!(
            signal_ops(&operations()),
            vec![(SIGPIPE as u8, SignalTarget::Task(me))]
        );
    });
}

#[test]
fn resethand_preserves_flags_mask_and_restorer_after_delivery() {
    isolated(|| {
        let mut action = install_task_handler(SIGUSR2, SA_RESETHAND);
        action.mask = bit(SIGUSR1 as u8);
        assert_eq!(
            unsafe { patina_signal_action(SIGUSR2, &action, std::ptr::null_mut(), SIGSET_BYTES) },
            0
        );
        generate(SIGUSR2);
        deliver();
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        let mut old = Action::default();
        assert_eq!(
            unsafe { patina_signal_action(SIGUSR2, std::ptr::null(), &mut old, SIGSET_BYTES) },
            0
        );
        assert_eq!(
            old,
            Action {
                handler: SIG_DFL,
                ..action
            }
        );
    });
}

#[test]
fn sigstop_to_self_is_a_named_trap() {
    use std::os::unix::process::ExitStatusExt;
    if let Ok(signal) = std::env::var("PATINA_STOP_TEST") {
        isolated(|| {
            generate(signal.parse().unwrap());
            deliver();
            panic!("default stop returned");
        });
        return;
    }
    for sig in [SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU] {
        let child = reexec(&test_name(), &[("PATINA_STOP_TEST", &sig.to_string())]);
        assert_eq!(child.status.signal(), Some(SIGABRT));
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(stderr.contains(concat!(
            "patina native shim fatal: ",
            "default Stop-class signal would stop the only virtual process"
        )));
    }
    isolated(|| {
        for sig in [SIGTSTP, SIGTTIN, SIGTTOU] {
            install_task_handler(sig, 0);
            generate(sig);
            deliver();
        }
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 3);
        assert_eq!(
            HANDLER_TASK.load(Ordering::SeqCst),
            current_task().0 as usize
        );
    });
}

#[test]
fn thread_directed_signal_targets_only_that_task() {
    isolated(|| {
        install_task_handler(SIGUSR1, 0);
        let me = current_task();
        let [rd, _wr] = pipe();
        let target = spawn(move || {
            let mut byte = 0u8;
            for _ in 0..2 {
                assert_eq!(
                    unsafe { crate::patina_read(rd, (&mut byte as *mut u8).cast(), 1) },
                    -1
                );
                assert_eq!(crate::patina_errno(), EINTR);
                assert_eq!(
                    HANDLER_TASK.load(Ordering::SeqCst),
                    current_task().0 as usize
                );
            }
        });
        let task = task_of(target);
        for (index, row) in ["tgkill", "tkill"].iter().enumerate() {
            delay();
            assert!(parked_class(task).is_some());
            let tid = tid_of(task) as u64;
            let args = if *row == "tgkill" {
                [
                    u64::from(crate::registry::IDENTITY_PID),
                    tid,
                    SIGUSR1 as u64,
                ]
            } else {
                [tid, SIGUSR1 as u64, 0]
            };
            assert_eq!(
                unsafe {
                    crate::sud::patina_sud_dispatch(
                        syscall_number(row),
                        args[0],
                        args[1],
                        args[2],
                        0,
                        0,
                        0,
                        0,
                    )
                },
                0
            );
            assert_eq!(
                HANDLERS.load(Ordering::SeqCst),
                index,
                "caller did not run handler"
            );
            let state = lock_state();
            assert_eq!(
                state.signals.tasks[&task].private.mask(),
                bit(SIGUSR1 as u8)
            );
            assert_eq!(state.signals.tasks[&me].private.mask(), 0);
            assert!(!state.signals.interrupted.contains_key(&me));
            assert!(state.signals.interrupted.contains_key(&task));
            assert!(!state.signals.blocked.contains_key(&task));
        }
        join(target);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 2);
        let ops = operations();
        assert_eq!(
            signal_ops(&ops),
            vec![(SIGUSR1 as u8, SignalTarget::Task(task)); 2]
        );
        for (i, op) in ops.iter().enumerate() {
            if matches!(op, Operation::SignalGenerated { .. }) {
                assert!(matches!(ops[i + 1], Operation::TaskWake { task: woken } if woken == task));
                assert!(!matches!(ops[i + 2], Operation::TaskWake { .. }));
            }
        }
    });
}

#[test]
fn pending_for_a_blocking_task_is_invisible_to_another_tasks_sigpending() {
    isolated(|| {
        install_task_handler(SIGUSR1, 0);
        set_mask(SIG_BLOCK, bit(SIGUSR1 as u8));
        let [rd, wr] = pipe();
        let target = spawn(move || {
            let mut byte = 0u8;
            assert_eq!(
                unsafe { crate::patina_read(rd, (&mut byte as *mut u8).cast(), 1) },
                1
            );
            assert_eq!(query_pending(), bit(SIGUSR1 as u8));
            assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
            set_mask(SIG_UNBLOCK, bit(SIGUSR1 as u8));
            deliver();
            assert_eq!(query_pending(), 0);
            assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
            assert_eq!(
                HANDLER_TASK.load(Ordering::SeqCst),
                current_task().0 as usize
            );
        });
        let task = task_of(target);
        delay();
        assert_eq!(
            unsafe {
                generate_signal(
                    GenerationTarget::Thread {
                        tgid: Some(crate::registry::IDENTITY_PID as i32),
                        tid: tid_of(task),
                    },
                    SIGUSR1,
                    GenerationInfo::Thread,
                )
            },
            0
        );
        assert_eq!(
            query_pending(),
            0,
            "the caller also blocks SIGUSR1 but cannot see another private queue"
        );
        assert!(parked_class(task).is_some());
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
        // A third task likewise cannot see the target's private pending set.
        let observer = spawn(|| assert_eq!(query_pending(), 0));
        join(observer);
        assert_eq!(
            unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
            1
        );
        join(target);
        set_mask(SIG_SETMASK, 0);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn set_tid_address_is_cleared_and_woken_at_thread_finish() {
    isolated(|| {
        use std::sync::Arc;
        use std::sync::atomic::AtomicI32;
        let word = Arc::new(AtomicI32::new(123));
        let own_word = AtomicI32::new(456);
        let me = current_task();
        assert_eq!(
            unsafe { patina_set_tid_address(own_word.as_ptr()) },
            i64::from(tid_of(me))
        );
        let child_word = word.clone();
        let worker = spawn(move || {
            let tid = unsafe { patina_set_tid_address(child_word.as_ptr()) };
            assert_eq!(tid, i64::from(tid_of(current_task())));
            delay();
            assert!(
                lock_state().futexes[&(child_word.as_ptr() as usize)]
                    .iter()
                    .any(|waiter| waiter.task == me)
            );
        });
        let task = task_of(worker);
        assert_eq!(patina_futex_wait(word.as_ptr() as usize, 123), 0);
        assert_eq!(word.load(Ordering::SeqCst), 0);
        assert_eq!(
            own_word.load(Ordering::SeqCst),
            456,
            "thread_finish clears only that task's word"
        );
        join(worker);
        assert!(!lock_state().signals.tasks.contains_key(&task));
        let ops = operations();
        let completed = ops
            .iter()
            .position(|op| matches!(op, Operation::TaskComplete { task: t } if *t == task))
            .unwrap();
        assert!(
            ops[..completed]
                .iter()
                .any(|op| matches!(op, Operation::TaskWake { task } if *task == me))
        );
    });
}

#[test]
fn raw_exit_from_main_keeps_the_process_alive() {
    const ATEXIT_STATUS: i32 = 99;
    const WORKER_STATUS: i32 = 37;
    if let Ok(mode) = std::env::var("PATINA_EXIT_TEST") {
        unsafe extern "C" {
            fn atexit(callback: extern "C" fn()) -> i32;
        }
        extern "C" fn on_exit() {
            host(SYS_EXIT_GROUP, [ATEXIT_STATUS as u64, 0, 0, 0, 0, 0]);
        }
        assert_eq!(unsafe { atexit(on_exit) }, 0);
        if mode == "control" {
            unsafe { (crate::hostapi::get().host_exit)(0) }
        }
        let config = patina_dst_runtime::RuntimeConfig::record(
            1,
            std::env::var("PATINA_EXIT_TRACE").unwrap(),
            "raw-exit-unit",
        );
        assert_eq!(crate::install(crate::Context::from_config(config)), 0);
        let main = activate();
        if mode == "return" {
            extern "C" fn return_nonzero(_: *mut c_void) -> *mut c_void {
                assert!(!lock_state().signals.tasks.contains_key(&TaskId(1)));
                WORKER_STATUS as *mut c_void
            }
            let mut worker = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    patina_thread_create(
                        &mut worker,
                        std::ptr::null(),
                        Some(return_nonzero),
                        std::ptr::null_mut(),
                    )
                },
                0
            );
        } else {
            let raw_worker = mode == "raw-worker-exit";
            spawn(move || {
                assert!(
                    !lock_state().signals.tasks.contains_key(&main),
                    "main completed, not merely parked"
                );
                unsafe {
                    crate::sud::patina_sud_dispatch(
                        syscall_number(if raw_worker { "exit" } else { "exit_group" }),
                        WORKER_STATUS as u64,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    );
                }
            });
        }
        unsafe {
            crate::sud::patina_sud_dispatch(syscall_number("exit"), 12, 0, 0, 0, 0, 0, 0);
        }
        panic!("raw exit returned");
    }
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("main-exit.patina");
    for (mode, expected) in [
        ("control", ATEXIT_STATUS),
        ("main", WORKER_STATUS),
        ("return", 0),
        ("raw-worker-exit", WORKER_STATUS),
    ] {
        if trace.exists() {
            std::fs::remove_file(&trace).unwrap();
        }
        let child = reexec(
            &test_name(),
            &[
                ("PATINA_EXIT_TEST", mode),
                ("PATINA_EXIT_TRACE", trace.to_str().unwrap()),
            ],
        );
        assert_eq!(
            child.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
    }
    let bundle = TraceBundle::load(&trace).unwrap();
    assert!(
        bundle.timelines[0]
            .decisions
            .iter()
            .any(|event| matches!(event.operation, Operation::TaskComplete { task: TaskId(1) }))
    );
}

#[test]
fn generation_validates_typed_targets_before_recording() {
    isolated(|| {
        // The tree: init (1) and the guest (2), whose main thread is 2.
        const INIT: i32 = crate::registry::INIT_PID as i32;
        const GUEST: i32 = crate::registry::IDENTITY_PID as i32;
        let mut info = Info::new(SIGUSR1 as u8, SI_QUEUE);
        let process = |pid| GenerationTarget::Process { pid };
        let thread = |tgid, tid| GenerationTarget::Thread { tgid, tid };
        for (target, sig, expected) in [
            (process(GUEST), -1, EINVAL),
            (process(GUEST), 65, EINVAL),
            (process(3), 0, ESRCH),
            (process(-3), 0, ESRCH),
            // Every process but init and the caller: none.
            (process(-1), 0, ESRCH),
            (thread(None, 0), 0, EINVAL),
            (thread(None, -1), 0, EINVAL),
            (thread(None, 999), 0, ESRCH),
            (thread(Some(0), GUEST), 0, EINVAL),
            (thread(Some(-1), GUEST), 0, EINVAL),
            (thread(Some(3), GUEST), 0, ESRCH),
            (thread(Some(INIT), GUEST), 0, ESRCH),
            (thread(Some(GUEST), INIT), 0, ESRCH),
            (thread(Some(GUEST), 0), 0, EINVAL),
            (thread(Some(GUEST), 999), 0, ESRCH),
        ] {
            assert_eq!(
                unsafe { generate_signal(target, sig, GenerationInfo::Thread) },
                -i64::from(expected)
            );
        }
        for target in [process(GUEST), thread(Some(GUEST), GUEST)] {
            assert_eq!(
                unsafe {
                    generate_signal(target, SIGUSR1, GenerationInfo::Queued(std::ptr::null()))
                },
                -i64::from(EFAULT)
            );
        }
        // A forged kernel or tkill code only to the caller's own thread id.
        for (pid, code, expected) in [
            (3, SI_QUEUE, ESRCH),
            (3, SI_USER, EPERM),
            (3, SI_TKILL, EPERM),
            (INIT, SI_USER, EPERM),
            (INIT, SI_QUEUE, 0),
        ] {
            info.words[1] = code as u32 as u64;
            for target in [process(pid), thread(Some(pid), pid)] {
                assert_eq!(
                    unsafe { generate_signal(target, SIGUSR1, GenerationInfo::Queued(&info)) },
                    -i64::from(expected)
                );
            }
        }
        // Existence probes, and a real signal to init, which takes nothing.
        for (target, sig) in [
            (process(0), 0),
            (process(GUEST), 0),
            (process(-GUEST), 0),
            (thread(None, GUEST), 0),
            (thread(Some(GUEST), GUEST), 0),
            (process(INIT), 0),
            (process(INIT), SIGUSR1),
            (thread(None, INIT), SIGUSR1),
            (thread(Some(INIT), INIT), SIGUSR1),
        ] {
            assert_eq!(
                unsafe { generate_signal(target, sig, GenerationInfo::User) },
                0
            );
        }
        assert!(signal_ops(&operations()).is_empty());
    });
}

#[test]
fn detached_handles_live_until_completion_then_are_removed() {
    isolated(|| {
        let worker = spawn(|| {
            delay();
        });
        assert_eq!(unsafe { patina_thread_detach(worker) }, 0);
        assert_eq!(patina_pthread_kill(worker as usize, 0), 0);
        assert_eq!(unsafe { patina_thread_detach(worker) }, EINVAL);
        assert_eq!(
            unsafe { patina_thread_join(worker, std::ptr::null_mut()) },
            EINVAL
        );
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
        assert_eq!(crate::patina_sleep_until(CLOCK_MONOTONIC, now + 100), 0);
        assert_eq!(patina_pthread_kill(worker as usize, 0), ESRCH);
        assert_eq!(
            unsafe { patina_thread_join(worker, std::ptr::null_mut()) },
            ESRCH
        );
    });
}

/// `setpgid(0, …)` names the caller's process by its leader's pid, so a
/// thread other than the main one moves the whole process (`sys.c`
/// `setpgid`: `task_pid_vnr(group_leader)`), while naming that thread's own
/// id is `EINVAL` (not a thread-group leader).
#[test]
fn setpgid_of_zero_from_a_non_main_thread_names_the_process() {
    isolated(|| {
        let worker = spawn(|| {
            let me = crate::thread::current_tid();
            assert_ne!(me, crate::registry::IDENTITY_PID as i32);
            assert_eq!(crate::identity::setpgid(0, 0), 0);
            assert_eq!(crate::identity::setpgid(me, 0), -i64::from(EINVAL));
            assert_eq!(crate::identity::setpgid(0, 77), -i64::from(EPERM));
            assert_eq!(crate::identity::setpgid(0, 1), 0);
            assert_eq!(crate::identity::getpgid(0), 1);
        });
        join(worker);
    });
}
