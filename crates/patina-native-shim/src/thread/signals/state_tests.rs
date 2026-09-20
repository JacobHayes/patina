//! Signal state class detectors: the production state, syscall entries, and frame transport.
use super::*;
use std::cell::RefCell;
const ENOMEM: i32 = 12;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum HostCall {
    Mask(u64),
    Queue(u8),
}
thread_local! {
    static HOST_CALL_COUNT: Cell<Option<usize>> = const { Cell::new(None) };
    static HOST_CALLS: RefCell<Option<Vec<HostCall>>> = const { RefCell::new(None) };
}
pub(in crate::thread::signals) fn observe_host_call(nr: i64, args: [u64; 6]) {
    HOST_CALL_COUNT.with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
    HOST_CALLS.with(|calls| {
        let mut calls = calls.borrow_mut();
        let Some(calls) = calls.as_mut() else {
            return;
        };
        match nr {
            SYS_RT_SIGPROCMASK if args[0] == SIG_SETMASK as u64 && args[1] != 0 => {
                calls.push(HostCall::Mask(unsafe { *(args[1] as *const u64) }))
            }
            SYS_RT_TGSIGQUEUEINFO => calls.push(HostCall::Queue(args[2] as u8)),
            _ => {}
        }
    });
}
fn capture_transport(body: impl FnOnce()) -> Vec<HostCall> {
    HOST_CALLS.with(|calls| *calls.borrow_mut() = Some(Vec::new()));
    body();
    HOST_CALLS.with(|calls| calls.borrow_mut().take().unwrap())
}
fn query_action(sig: i32) -> Action {
    let mut action = Action::default();
    assert_eq!(
        unsafe { patina_signal_action(sig, std::ptr::null(), &mut action, SIGSET_BYTES) },
        0
    );
    action
}
fn query_stack() -> Stack {
    let mut stack = Stack::default();
    assert_eq!(
        unsafe { patina_signal_altstack(std::ptr::null(), &mut stack) },
        0
    );
    stack
}
fn stack_for(bytes: &mut [u8]) -> Stack {
    Stack {
        base: bytes.as_mut_ptr() as usize,
        flags: 0,
        size: bytes.len(),
    }
}
fn set_stack(stack: &Stack) {
    assert_eq!(
        unsafe { patina_signal_altstack(stack, std::ptr::null_mut()) },
        0
    );
}
fn directed(task: TaskId, sig: i32) {
    assert_eq!(
        unsafe {
            generate_signal(
                GenerationTarget::Thread {
                    tgid: Some(1),
                    tid: task.0 as i32,
                },
                sig,
                GenerationInfo::Thread,
            )
        },
        0
    );
}

#[test]
fn signal_state_is_per_task() {
    isolated(|| {
        action(false);
        let main = current_task();
        let mut main_bytes = vec![0u8; 64 * 1024];
        let main_stack = stack_for(&mut main_bytes);
        set_stack(&main_stack);
        let worker = spawn(move || {
            let mut bytes = vec![0u8; 64 * 1024];
            let stack = stack_for(&mut bytes);
            set_stack(&stack);
            set_mask(SIG_BLOCK, bit(SIGUSR1));
            directed(current_task(), SIGUSR1);
            assert_eq!(query_pending(), bit(SIGUSR1));
            let state = lock_state();
            assert_eq!(state.signals.mask(main), 0);
            assert_eq!(state.signals.tasks[&main].private.mask(), 0);
            assert_eq!(state.signals.shared.mask(), 0);
            drop(state);
            assert_eq!(query_stack(), stack);
            set_stack(&Stack::default());
        });
        join(worker);
        assert_eq!(query_pending(), 0);
        assert_eq!(query_stack(), main_stack);
        set_stack(&Stack::default());
    });
}

#[test]
fn mask_is_inherited_at_spawn() {
    isolated(|| {
        action(false);
        set_mask(SIG_BLOCK, bit(SIGUSR1));
        directed(current_task(), SIGUSR1);
        let mut bytes = vec![0u8; 64 * 1024];
        set_stack(&stack_for(&mut bytes));
        let worker = spawn(|| {
            assert_eq!(read_mask() & bit(SIGUSR1), bit(SIGUSR1));
            assert_eq!(
                lock_state().signals.mask(current_task()) & bit(SIGUSR1),
                bit(SIGUSR1)
            );
            assert_eq!(query_pending(), 0);
            assert_eq!(query_stack().flags, SS_DISABLE);
            assert!(
                lock_state().signals.tasks[&current_task()]
                    .private
                    .0
                    .is_empty()
            );
        });
        join(worker);
        set_stack(&Stack::default());
        set_mask(SIG_UNBLOCK, bit(SIGUSR1));
        deliver();
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn same_task_kill_delivers_at_syscall_return() {
    isolated(|| {
        action(false);
        let sent = capture_transport(|| generate(SIGUSR1));
        assert!(sent.is_empty(), "generation must never issue a host signal");
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
        // The generation-only assertion above proves transport is separate.
        // Drive the real dispatch tail now, not a hand-called delivery hook.
        assert_eq!(
            unsafe {
                crate::sud::patina_sud_dispatch(
                    syscall_number("kill"),
                    1,
                    SIGUSR1 as u64,
                    0,
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
            1,
            "standard pending instances coalesce"
        );
        let ops = operations();
        assert_eq!(
            signal_ops(&ops),
            vec![(SIGUSR1 as u8, SignalTarget::Process); 2]
        );
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Operation::TaskWake { .. }))
        );
    });
}

#[test]
fn unmask_delivers_pending_before_return() {
    isolated(|| {
        action(false);
        for (index, how) in [SIG_UNBLOCK, SIG_SETMASK].into_iter().enumerate() {
            set_mask(SIG_BLOCK, bit(SIGUSR1));
            generate(SIGUSR1);
            patina_signal_deliver();
            assert_eq!(HANDLERS.load(Ordering::SeqCst), index);
            assert_eq!(query_pending(), bit(SIGUSR1));
            let mask = if how == SIG_UNBLOCK { bit(SIGUSR1) } else { 0 };
            let mut old = 0;
            let rc = unsafe {
                crate::sud::patina_sud_dispatch(
                    syscall_number("rt_sigprocmask"),
                    how as u64,
                    &mask as *const _ as u64,
                    &mut old as *mut _ as u64,
                    8,
                    0,
                    0,
                    0,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(old, bit(SIGUSR1));
            assert_eq!(HANDLERS.load(Ordering::SeqCst), index + 1);
            assert_eq!(query_pending(), 0);
        }
    });
}

#[test]
fn stacked_delivery_releases_frames_with_one_host_unblock() {
    isolated(|| {
        install_handler(SIGUSR1, handler, 0, 0);
        install_handler(SIGUSR2, handler, 0, 0);
        set_mask(SIG_BLOCK, bit(SIGUSR1) | bit(SIGUSR2));
        generate(SIGUSR2);
        generate(SIGUSR1);
        set_mask(SIG_UNBLOCK, bit(SIGUSR1) | bit(SIGUSR2));
        let calls = capture_transport(|| patina_signal_deliver());
        assert_eq!(
            calls,
            vec![
                HostCall::Mask(host_mask(u64::MAX)),
                HostCall::Queue(SIGUSR1 as u8),
                HostCall::Queue(SIGUSR2 as u8),
                HostCall::Mask(0)
            ]
        );
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn raw_rt_sigaction_installs_and_reports_oldact() {
    isolated(|| {
        let original = install_handler(SIGUSR1, handler, SA_RESTART, bit(SIGUSR2));
        // Paired with fixture_preserves_native_restorer_validity: a restorer
        // pointer is meaningful only when the native action marks it valid.
        if original.flags & SA_RESTORER != 0 {
            assert_ne!(original.restorer, 0);
        }
        #[cfg(target_arch = "x86_64")]
        assert_ne!(original.flags & SA_RESTORER, 0);
        set_mask(SIG_BLOCK, bit(SIGUSR1));
        generate(SIGUSR1);
        directed(current_task(), SIGUSR1);
        let ignore = Action {
            handler: SIG_IGN,
            flags: original.flags & SA_RESTORER,
            restorer: original.restorer,
            mask: bit(SIGUSR2),
        };
        let mut old = Action::default();
        assert_eq!(
            unsafe {
                crate::sud::patina_sud_dispatch(
                    syscall_number("rt_sigaction"),
                    SIGUSR1 as u64,
                    &ignore as *const _ as u64,
                    &mut old as *mut _ as u64,
                    8,
                    0,
                    0,
                    0,
                )
            },
            0
        );
        assert_eq!(old, original);
        assert_eq!(query_action(SIGUSR1), ignore);
        assert_eq!(
            query_pending(),
            0,
            "installing ignore flushes private and shared queues"
        );
    });
}

static ON_STACK: AtomicUsize = AtomicUsize::new(0);
extern "C" fn stack_handler(_: i32) {
    let old = query_stack();
    let local = 0u8;
    let sp = &local as *const _ as usize;
    assert!(sp >= old.base && sp < old.base + old.size);
    assert_ne!(old.flags & SS_ONSTACK, 0);
    assert_eq!(
        unsafe { patina_signal_altstack(&Stack::default(), std::ptr::null_mut()) },
        -i64::from(EPERM)
    );
    ON_STACK.fetch_add(1, Ordering::SeqCst);
}
#[test]
fn sigaltstack_is_per_task_and_forwarded() {
    isolated(|| {
        install_handler(SIGUSR1, stack_handler, SA_ONSTACK, 0);
        let original = query_stack();
        let mut bytes = vec![0u8; 64 * 1024];
        let stack = stack_for(&mut bytes);
        let mut old = Stack::default();
        assert_eq!(unsafe { patina_signal_altstack(&stack, &mut old) }, 0);
        assert_eq!(old, original);
        assert_eq!(query_stack(), stack);
        let mut host_stack = Stack::default();
        assert_eq!(
            host(
                SYS_SIGALTSTACK,
                [0, &mut host_stack as *mut _ as u64, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(host_stack, stack);
        let too_small = Stack { size: 1, ..stack };
        assert_eq!(
            unsafe { patina_signal_altstack(&too_small, std::ptr::null_mut()) },
            -i64::from(ENOMEM)
        );
        let invalid = Stack {
            flags: 123,
            ..stack
        };
        assert_eq!(
            unsafe { patina_signal_altstack(&invalid, std::ptr::null_mut()) },
            -i64::from(EINVAL)
        );
        let worker = spawn(|| assert_eq!(query_stack().flags, SS_DISABLE));
        join(worker);
        generate(SIGUSR1);
        deliver();
        assert_eq!(ON_STACK.load(Ordering::SeqCst), 1);
        set_stack(&original);
    });
}

#[test]
fn dequeue_private_before_shared_lowest_first_fifo() {
    isolated(|| {
        let set = bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGRTMIN);
        set_mask(SIG_BLOCK, set);
        generate(SIGUSR2);
        generate(SIGUSR1);
        generate(SIGUSR1);
        for value in [21u64, 22] {
            let mut info = Info::new(SIGRTMIN as u8, SI_QUEUE);
            info.words[3] = value;
            assert_eq!(
                unsafe {
                    generate_signal(
                        GenerationTarget::Thread {
                            tgid: Some(1),
                            tid: current_task().0 as i32,
                        },
                        SIGRTMIN,
                        GenerationInfo::Queued(&info),
                    )
                },
                0
            );
        }
        for (sig, value) in [(SIGRTMIN, 21), (SIGRTMIN, 22), (SIGUSR1, 0), (SIGUSR2, 0)] {
            let mut info = Info::new(0, 0);
            assert_eq!(
                unsafe {
                    patina_signal_wait(
                        &set,
                        &mut info,
                        &Timespec { sec: 0, nsec: 0 },
                        SIGSET_BYTES,
                        WaitMode::Dequeue,
                    )
                },
                i64::from(sig)
            );
            assert_eq!(info.value(), value);
        }
        assert_eq!(query_pending(), 0, "standard instances coalesce");
    });
}

#[test]
fn generation_never_takes_the_runtime_lock_twice() {
    if std::env::var("PATINA_SIGNAL_REFUSAL").as_deref() == Ok("locked") {
        isolated(|| {
            let _state = lock_state();
            generate(SIGUSR1);
        });
        return;
    }
    if std::env::var("PATINA_SIGNAL_UNIT_CHILD").as_deref() != Ok(test_name().as_str()) {
        let output = reexec(&test_name(), &[("PATINA_SIGNAL_REFUSAL", "locked")]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("signal generation under the runtime lock")
        );
    }
    isolated(|| {
        let ignore = Action {
            handler: SIG_IGN,
            ..Action::default()
        };
        assert_eq!(
            unsafe { patina_signal_action(SIGPIPE, &ignore, std::ptr::null_mut(), SIGSET_BYTES) },
            0
        );
        let [rd, wr] = pipe();
        crate::patina_close(rd);
        assert_eq!(
            unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
            -1
        );
        assert_eq!(crate::patina_errno(), crate::EPIPE);
        assert!(
            signal_ops(&operations())
                .iter()
                .any(|(sig, target)| *sig == SIGPIPE as u8
                    && matches!(target, SignalTarget::Task(_)))
        );
    });
}

#[test]
fn reserved_signals_are_stripped_from_every_host_mask() {
    if let Ok(mode) = std::env::var("PATINA_SIGNAL_REFUSAL") {
        isolated(|| {
            crate::PATINA_TSC_ARMED.store(1, Ordering::Relaxed);
            let sig = if mode == "sys" { SIGSYS } else { SIGSEGV };
            let action = Action {
                handler: handler as *const () as usize,
                ..Action::default()
            };
            unsafe {
                patina_signal_action(i32::from(sig), &action, std::ptr::null_mut(), SIGSET_BYTES);
            }
        });
        return;
    }
    if std::env::var("PATINA_SIGNAL_UNIT_CHILD").as_deref() != Ok(test_name().as_str()) {
        for mode in ["sys", "segv"] {
            let output = reexec(&test_name(), &[("PATINA_SIGNAL_REFUSAL", mode)]);
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("reserved signal registration")
            );
        }
    }
    isolated(|| {
        crate::PATINA_TSC_ARMED.store(1, Ordering::Relaxed);
        let reserved = bit(SIGSYS) | bit(SIGSEGV);
        action(false);
        let calls = capture_transport(|| {
            set_mask(SIG_SETMASK, u64::MAX);
            assert_eq!(read_mask() & reserved, 0);
            let worker = spawn(move || assert_eq!(read_mask() & reserved, 0));
            join(worker);
            generate(SIGUSR1);
            set_mask(SIG_UNBLOCK, bit(SIGUSR1));
            deliver();
            let worker = spawn(|| {
                delay();
                generate(SIGUSR1);
            });
            let temporary = reserved;
            assert_eq!(
                unsafe {
                    patina_signal_wait(
                        &temporary,
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        SIGSET_BYTES,
                        WaitMode::Suspend,
                    )
                },
                -i64::from(EINTR)
            );
            join(worker);
        });
        assert!(
            calls
                .iter()
                .filter_map(|call| match call {
                    HostCall::Mask(mask) => Some(mask),
                    _ => None,
                })
                .all(|mask| mask & reserved == 0)
        );
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 2);
        set_mask(SIG_SETMASK, 0);
    });
}

#[test]
fn no_pending_syscall_tail_and_unchanged_frame_issue_no_host_calls() {
    isolated(|| {
        // Clear any initialization fixup, then count *all* host calls, not only
        // writes observed by the stacked-transport assertion.
        let mut mask = 0u64;
        let mut stack = Stack::default();
        unsafe {
            patina_signal_frame(&mut mask, &mut stack);
        }
        HOST_CALL_COUNT.with(|count| count.set(Some(0)));
        assert_eq!(
            unsafe {
                crate::sud::patina_sud_dispatch(syscall_number("getpid"), 0, 0, 0, 0, 0, 0, 0)
            },
            1
        );
        unsafe {
            patina_signal_frame(&mut mask, &mut stack);
        }
        assert_eq!(HOST_CALL_COUNT.with(|count| count.replace(None)), Some(0));
        set_mask(SIG_BLOCK, bit(SIGUSR1));
        HOST_CALL_COUNT.with(|count| count.set(Some(0)));
        unsafe {
            patina_signal_frame(&mut mask, &mut stack);
        }
        assert_eq!(mask & bit(SIGUSR1), bit(SIGUSR1));
        assert_eq!(HOST_CALL_COUNT.with(|count| count.replace(None)), Some(1));
    });
}

// Class pairing: dirty-frame ownership across nested kernel handler boundaries.
#[test]
fn nested_signal_frame_preserves_outer_mask_and_stack_fixups() {
    extern "C" fn nested_frame(_: i32) {
        let mut mask = u64::MAX;
        let mut stack = Stack::default();
        unsafe {
            patina_signal_frame(&mut mask, &mut stack);
        }
        assert_ne!(mask, u64::MAX, "inner frame consumed the dirty mask");
        HANDLERS.fetch_add(1, Ordering::SeqCst);
    }
    isolated(|| {
        install_handler(SIGUSR1, nested_frame, 0, 0);
        let mut storage = vec![0u8; 65536];
        let stack = Stack {
            base: storage.as_mut_ptr() as usize,
            flags: 0,
            size: storage.len(),
        };
        assert_eq!(
            unsafe { patina_signal_altstack(&stack, std::ptr::null_mut()) },
            0
        );
        set_mask(SIG_BLOCK, bit(SIGUSR1));
        generate(SIGUSR1);
        set_mask(SIG_UNBLOCK, bit(SIGUSR1));
        deliver();
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        let mut outer_mask = u64::MAX;
        let mut outer_stack = Stack::default();
        unsafe {
            patina_signal_frame(&mut outer_mask, &mut outer_stack);
        }
        assert_eq!(
            (outer_mask, outer_stack),
            (read_mask(), stack),
            "outer mask and stack dirty bits survived inner fixup"
        );
        assert_eq!(
            unsafe { patina_signal_altstack(&Stack::default(), std::ptr::null_mut()) },
            0
        );
    });
}

#[test]
fn fatal_batch_never_releases_a_handler_after_finalization() {
    use std::os::unix::process::ExitStatusExt;
    const SIGTERM: i32 = 15;
    extern "C" fn forbidden_handler(_: i32) {
        host(SYS_EXIT_GROUP, [99, 0, 0, 0, 0, 0]);
    }
    if let Ok(path) = std::env::var("PATINA_FATAL_TRACE") {
        let config = patina_dst_runtime::RuntimeConfig::record(1, path, "fatal-batch");
        assert_eq!(crate::install(crate::Context::from_config(config)), 0);
        activate();
        install_handler(SIGUSR1, forbidden_handler, 0, 0);
        set_mask(SIG_SETMASK, bit(SIGUSR1) | bit(SIGTERM));
        generate(SIGUSR1);
        generate(SIGTERM);
        set_mask(SIG_SETMASK, 0);
        deliver();
        panic!("fatal batch returned");
    }
    let path = trace_path();
    let output = reexec(
        &test_name(),
        &[("PATINA_FATAL_TRACE", path.to_str().unwrap())],
    );
    assert_eq!(output.status.signal(), Some(SIGTERM));
    let trace = TraceBundle::load(&path).unwrap();
    trace.validate().unwrap();
    assert_eq!(
        trace.timelines[0]
            .decisions
            .iter()
            .filter(|event| matches!(event.operation, Operation::SignalGenerated { .. }))
            .count(),
        2
    );
    std::fs::remove_file(path).unwrap();
}

static DEFERRED_FD: AtomicUsize = AtomicUsize::new(0);
extern "C" fn observes_deferred_signal(_: i32) {
    assert_eq!(query_pending(), bit(SIGUSR2));
    let fd = DEFERRED_FD.load(Ordering::SeqCst) as i32;
    if fd != 0 {
        let mut record = [0u8; 128];
        assert_eq!(
            unsafe { crate::patina_read(fd, record.as_mut_ptr().cast(), record.len()) },
            128
        );
        assert_eq!(
            u32::from_ne_bytes(record[..4].try_into().unwrap()),
            SIGUSR2 as u32
        );
        assert_eq!(query_pending(), 0);
    }
    HANDLERS.fetch_add(1, Ordering::SeqCst);
}
#[test]
fn action_mask_deferred_pending_remains_visible_and_consumable() {
    isolated(|| {
        install_handler(SIGUSR1, observes_deferred_signal, 0, bit(SIGUSR2));
        install_handler(SIGUSR2, handler, 0, 0);
        for consume in [false, true] {
            HANDLERS.store(0, Ordering::SeqCst);
            let fd = unsafe { fd::patina_signalfd(-1, &bit(SIGUSR2), SIGSET_BYTES, SFD_NONBLOCK) };
            assert!(fd >= 0);
            DEFERRED_FD.store(if consume { fd as usize } else { 0 }, Ordering::SeqCst);
            set_mask(SIG_SETMASK, bit(SIGUSR1) | bit(SIGUSR2));
            generate(SIGUSR2);
            generate(SIGUSR1);
            set_mask(SIG_SETMASK, 0);
            deliver();
            assert_eq!(HANDLERS.load(Ordering::SeqCst), if consume { 1 } else { 2 });
            assert_eq!(crate::patina_close(fd as i32), 0);
        }
    });
}

#[test]
fn startup_queries_do_not_install_the_scheduler() {
    let name = test_name();
    if std::env::var("PATINA_SIGNAL_UNIT_CHILD").as_deref() != Ok(&name) {
        let output = reexec(&name, &[]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(crate::slot().lock().is_none());
    assert!(!crate::BOUNDARY_SEEN.load(Ordering::Relaxed));
    install_handler(SIGUSR1, handler, 0, 0);
    let mut previous = Action::default();
    assert_eq!(
        unsafe { patina_signal_action(SIGUSR1, std::ptr::null(), &mut previous, SIGSET_BYTES) },
        0
    );
    assert_eq!(previous.handler, handler as *const () as usize);
    let mut stack = Stack::default();
    assert_eq!(
        unsafe { patina_signal_altstack(std::ptr::null(), &mut stack) },
        0
    );
    let mut fds = [0, 1, 2].map(|fd| readiness::PollFd {
        fd,
        events: 0,
        revents: -1,
    });
    const POLLNVAL: i16 = 0x020;
    assert!(
        unsafe {
            readiness::patina_poll(
                fds.as_mut_ptr(),
                fds.len(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        } >= 0
    );
    assert!(fds.iter().all(|fd| fd.revents & POLLNVAL == 0));
    assert!(crate::slot().lock().is_none());
    assert!(!lock_state().active);
    assert!(!crate::BOUNDARY_SEEN.load(Ordering::Relaxed));
}
