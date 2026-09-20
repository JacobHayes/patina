//! Class-level pairing: frozen signals-family obligations and its six host
//! conformance probes. These tests drive the real baton, queues and kernel frames.
use super::*;
use patina_dst_abi::Operation;
use patina_dst_trace::TraceBundle;
use std::sync::atomic::{AtomicUsize, Ordering};

// The production C link supplies --wrap=dlsym. Plain Rust unit binaries do
// not; give their host-alias resolver the same real dlsym vehicle explicitly.
#[unsafe(no_mangle)]
unsafe extern "C" fn __real_dlsym(
    handle: *mut c_void,
    symbol: *const std::ffi::c_char,
) -> *mut c_void {
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const std::ffi::c_char) -> *mut c_void;
    }
    unsafe { dlsym(handle, symbol) }
}

pub(in crate::thread) static HANDLERS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn handler(_: i32) {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
}

/// Every child (including expected-fatal children) must announce exactly one
/// selected libtest test. `isolated` also requires one passed test; lifecycle
/// tests instead check their deliberate process exit status (including zero).
fn reexec(name: &str, env: &[(&str, &str)]) -> std::process::Output {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env("PATINA_SIGNAL_UNIT_CHILD", name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "{name} timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| line == "running 1 test"),
        "reexec did not select exactly one test: {name}: {stdout}"
    );
    output
}
fn test_name() -> String {
    std::thread::current()
        .name()
        .expect("named libtest thread")
        .to_owned()
}
pub(in crate::thread) fn isolated(body: impl FnOnce()) {
    // Derive from libtest, rather than trusting a duplicated string literal.
    let name = test_name();
    if std::env::var("PATINA_SIGNAL_UNIT_CHILD").as_deref() != Ok(&name) {
        let output = reexec(&name, &[]);
        assert!(
            output.status.success(),
            "status {}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "isolated child must complete exactly one test"
        );
        return;
    }
    let config = patina_dst_runtime::RuntimeConfig::record(1, trace_path(), "signal-unit");
    assert_eq!(crate::install(crate::Context::from_config(config)), 0);
    activate();
    body();
    if crate::slot().lock().is_some() {
        assert_eq!(crate::patina_shutdown(), 0);
    }
    let path = trace_path();
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
}
pub(in crate::thread) fn syscall_number(name: &str) -> i64 {
    crate::registry::syscall(name)
        .unwrap()
        .nr
        .for_arch(crate::registry::Arch::host())
        .unwrap() as i64
}
pub(in crate::thread) fn trace_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("patina-signal-unit-{}.patina", std::process::id()))
}
pub(in crate::thread) fn operations() -> Vec<Operation> {
    assert_eq!(crate::patina_shutdown(), 0);
    let path = trace_path();
    let bundle = TraceBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    bundle.timelines[0]
        .decisions
        .iter()
        .map(|event| event.operation.clone())
        .collect()
}
pub(in crate::thread) const SIGUSR1: i32 = 10;
pub(in crate::thread) const SIGUSR2: i32 = 12;
const SIGRTMIN: i32 = 34;
pub(in crate::thread) const SA_RESTORER: u64 = 0x0400_0000;
pub(in crate::thread) const SA_ONSTACK: u64 = 0x0800_0000;
const SS_ONSTACK: i32 = 1;

pub(in crate::thread) fn install_handler(
    sig: i32,
    handler: extern "C" fn(i32),
    flags: u64,
    mask: u64,
) -> Action {
    let mut action = native_handler_action(sig, handler);
    action.flags = (action.flags & SA_RESTORER) | flags;
    action.mask = mask;
    assert_eq!(
        unsafe { patina_signal_action(sig, &action, std::ptr::null_mut(), SIGSET_BYTES) },
        0
    );
    action
}

fn native_handler_action(sig: i32, handler: extern "C" fn(i32)) -> Action {
    // No C interposers are linked into the unit binary. Query the native kernel
    // action, including the flag that says whether its restorer slot is valid.
    unsafe extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
    }
    unsafe {
        signal(sig, handler as *const () as usize);
    }
    let mut action = Action::default();
    assert_eq!(
        host(
            SYS_RT_SIGACTION,
            [
                sig as u64,
                0,
                &mut action as *mut _ as u64,
                SIGSET_BYTES as u64,
                0,
                0
            ]
        ),
        0
    );
    action
}

// Class detector for native-to-fixture ABI drift: compare restorer validity
// against libc's kernel action, then actually return through the handler frame.
#[test]
fn fixture_preserves_native_restorer_validity() {
    isolated(|| {
        let native = native_handler_action(SIGUSR1, handler);
        let installed = install_handler(SIGUSR1, handler, SA_RESTART, 0);
        assert_eq!(installed.flags & SA_RESTORER, native.flags & SA_RESTORER);
        if native.flags & SA_RESTORER != 0 {
            assert_ne!(native.restorer, 0);
            assert_eq!(installed.restorer, native.restorer);
        }
        generate(SIGUSR1);
        patina_signal_deliver();
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    });
}

pub(in crate::thread) fn action(restart: bool) {
    install_handler(SIGUSR1, handler, if restart { SA_RESTART } else { 0 }, 0);
}
pub(in crate::thread) fn set_mask(how: i32, mask: u64) {
    assert_eq!(
        unsafe { patina_signal_mask(how, &mask, std::ptr::null_mut(), SIGSET_BYTES) },
        0
    );
}
pub(in crate::thread) fn query_pending() -> u64 {
    let mut mask = 0u64;
    assert_eq!(
        unsafe { patina_signal_pending((&mut mask as *mut u64).cast(), SIGSET_BYTES) },
        0
    );
    mask
}
pub(in crate::thread) fn spawn(body: impl FnOnce() + Send + 'static) -> *mut c_void {
    extern "C" fn start(arg: *mut c_void) -> *mut c_void {
        let body = unsafe { Box::from_raw(arg.cast::<Box<dyn FnOnce() + Send>>()) };
        body();
        std::ptr::null_mut()
    }
    let body: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(body));
    let mut thread = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            patina_thread_create(
                &mut thread,
                std::ptr::null(),
                Some(start),
                Box::into_raw(body).cast(),
            )
        },
        0
    );
    thread
}
fn task_of(thread: *mut c_void) -> TaskId {
    lock_state().handles[&(thread as usize)]
}
pub(in crate::thread) fn join(thread: *mut c_void) {
    assert_eq!(
        unsafe { patina_thread_join(thread, std::ptr::null_mut()) },
        0
    );
}
pub(in crate::thread) fn generate(sig: i32) {
    assert_eq!(
        unsafe {
            generate_signal(
                GenerationTarget::Process { pid: 1 },
                sig,
                GenerationInfo::User,
            )
        },
        0
    );
}
pub(in crate::thread) fn pipe() -> [i32; 2] {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { patina_pipe(fds.as_mut_ptr(), fds.as_mut_ptr().add(1), 0, 0) },
        0
    );
    fds
}
pub(in crate::thread) fn delay() {
    delay_for(10);
}
fn delay_for(nanos: u64) {
    let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
    assert_eq!(crate::patina_sleep_until(CLOCK_MONOTONIC, now + nanos), 0);
}
pub(in crate::thread) fn parked_class(task: TaskId) -> Option<BlockClass> {
    lock_state()
        .signals
        .blocked
        .get(&task)
        .map(|blocked| blocked.class)
}
fn signal_ops(ops: &[Operation]) -> Vec<(u8, SignalTarget)> {
    ops.iter()
        .filter_map(|op| match op {
            Operation::SignalGenerated { sig, target, .. } => Some((*sig, *target)),
            _ => None,
        })
        .collect()
}
fn wakes_after(ops: &[Operation], index: usize) -> Vec<TaskId> {
    ops[index + 1..]
        .iter()
        .take_while(|op| matches!(op, Operation::TaskWake { .. }))
        .filter_map(|op| match op {
            Operation::TaskWake { task } => Some(*task),
            _ => None,
        })
        .collect()
}

pub(in crate::thread) fn after_others_park(task: TaskId) -> BlockClass {
    delay();
    parked_class(task).expect("target must actually be parked before generation")
}
pub(in crate::thread) fn on_any_waiter_list(task: TaskId) -> bool {
    let state = lock_state();
    state.net.pipe_channels.values().any(|channel| {
        channel.recv_waiters.contains(&task)
            || channel.send_waiters.contains(&task)
            || channel.open_waiters.contains(&task)
    }) || state
        .table
        .mutexes
        .values()
        .any(|entry| entry.waiters.iter().any(|waiting| *waiting == task))
        || state
            .table
            .conds
            .values()
            .any(|entry| entry.waiters.iter().any(|(waiting, _)| *waiting == task))
        || state.table.rwlocks.values().any(|entry| {
            entry.read_waiters.iter().any(|waiting| *waiting == task)
                || entry.write_waiters.iter().any(|waiting| *waiting == task)
        })
        || state
            .table
            .threads
            .values()
            .any(|entry| entry.joiner == Some(task))
        || state.net.sockets.values().any(|socket| {
            socket.recv_waiters.contains(&task) || socket.send_waiters.contains(&task)
        })
        || state.futexes.values().any(|queue| queue.contains(&task))
        || state
            .net
            .eventfds
            .values()
            .any(|fd| fd.read_waiters.contains(&task))
        || state
            .signals
            .signalfds
            .values()
            .any(|fd| fd.waiters.contains(&task))
}
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed))]
struct Event {
    events: u32,
    data: u64,
}
const EPOLLIN: u32 = 1;
const EPOLL_CTL_ADD: i32 = 1;
const CLOCK_MONOTONIC: u32 = 1;
const TIMER_ABSTIME: u64 = 1;

fn pipe_read_case(restart: bool) {
    action(restart);
    let [rd, wr] = pipe();
    let me = current_task();
    let helper = spawn(move || {
        assert_eq!(after_others_park(me), BlockClass::Io);
        generate(SIGUSR1);
        assert_eq!(
            HANDLERS.load(Ordering::SeqCst),
            0,
            "generation runs no handler"
        );
        deliver();
        assert_eq!(
            HANDLERS.load(Ordering::SeqCst),
            0,
            "the helper cannot steal shared delivery"
        );
        if restart {
            delay();
            assert_eq!(
                parked_class(me),
                Some(BlockClass::Io),
                "restarted read re-parked"
            );
            assert_eq!(
                unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
                1
            );
        }
    });
    let mut byte = 0u8;
    let rc = unsafe { crate::patina_read(rd, (&mut byte as *mut u8).cast(), 1) };
    if restart {
        assert_eq!(rc, 1);
        assert_eq!(byte, b'x');
    } else {
        assert_eq!(rc, -1);
        assert_eq!(crate::patina_errno(), EINTR);
    }
    assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    assert_eq!(parked_class(me), None);
    join(helper);
    let ops = operations();
    assert_eq!(
        ops.iter()
            .filter(
                |op| matches!(op, Operation::SignalGenerated { sig, .. } if *sig == SIGUSR1 as u8)
            )
            .count(),
        1
    );
}
#[test]
fn sa_restart_restarts_pipe_read() {
    isolated(|| pipe_read_case(true));
}
#[test]
fn no_sa_restart_pipe_read_is_eintr() {
    isolated(|| pipe_read_case(false));
}

#[test]
fn process_directed_signal_picks_the_leader_when_unblocked_else_lowest_unblocked() {
    isolated(|| {
        let blocked = bit(SIGUSR1);
        for helper_sender in [false, true] {
            for (main_mask, a_mask, b_mask, selected) in [
                (0, 0, 0, Some(0)),
                (blocked, 0, 0, Some(1)),
                (blocked, blocked, 0, Some(2)),
                (blocked, blocked, blocked, None),
            ] {
                action(false);
                let [a_rd, a_wr] = pipe();
                let [b_rd, b_wr] = pipe();
                set_mask(SIG_SETMASK, a_mask);
                let a = spawn(move || {
                    let mut byte = 0u8;
                    let rc = unsafe { crate::patina_read(a_rd, (&mut byte as *mut u8).cast(), 1) };
                    if selected == Some(1) {
                        assert_eq!(rc, -1);
                        assert_eq!(crate::patina_errno(), EINTR);
                    } else {
                        assert_eq!(rc, 1);
                    }
                });
                set_mask(SIG_SETMASK, b_mask);
                let b = spawn(move || {
                    let mut byte = 0u8;
                    let rc = unsafe { crate::patina_read(b_rd, (&mut byte as *mut u8).cast(), 1) };
                    if selected == Some(2) {
                        assert_eq!(rc, -1);
                        assert_eq!(crate::patina_errno(), EINTR);
                    } else {
                        assert_eq!(rc, 1);
                    }
                });
                set_mask(SIG_SETMASK, main_mask);
                delay();
                let tasks = [current_task(), task_of(a), task_of(b)];
                assert_eq!(parked_class(tasks[1]), Some(BlockClass::Io));
                assert_eq!(parked_class(tasks[2]), Some(BlockClass::Io));
                let emit = move || {
                    generate(SIGUSR1); // actual production generation on the actual caller
                    let state = lock_state();
                    assert_eq!(
                        state.signals.target(SIGUSR1 as u8, SignalTarget::Process),
                        selected.map(|i| tasks[i])
                    );
                    assert_eq!(state.signals.shared.mask(), blocked);
                    for index in [1, 2] {
                        assert_eq!(
                            state.signals.interrupted.contains_key(&tasks[index]),
                            selected == Some(index)
                        );
                    }
                    drop(state);
                    // Clear the queued instance before scheduling, so this test
                    // isolates selection from the separately tested frame delivery.
                    let ignore = Action {
                        handler: SIG_IGN,
                        ..Action::default()
                    };
                    assert_eq!(
                        unsafe {
                            patina_signal_action(
                                SIGUSR1,
                                &ignore,
                                std::ptr::null_mut(),
                                SIGSET_BYTES,
                            )
                        },
                        0
                    );
                };
                if helper_sender {
                    let sender = spawn(move || {
                        set_mask(SIG_SETMASK, blocked);
                        emit();
                    });
                    join(sender);
                } else {
                    emit();
                }
                for fd in [a_wr, b_wr] {
                    assert_eq!(
                        unsafe { crate::patina_write(fd, b"x".as_ptr().cast(), 1) },
                        1
                    );
                }
                join(a);
                join(b);
                for fd in [a_rd, a_wr, b_rd, b_wr] {
                    assert_eq!(crate::patina_close(fd), 0);
                }
            }
        }
        assert_eq!(
            signal_ops(&operations()),
            vec![(SIGUSR1 as u8, SignalTarget::Process); 8]
        );
    });
}

#[test]
fn generation_wakes_only_the_chosen_parked_task() {
    isolated(|| {
        action(false);
        let me = current_task();
        let [rd, wr] = pipe();
        let [other_rd, other_wr] = pipe();
        let other = spawn(move || {
            set_mask(SIG_BLOCK, bit(SIGUSR1));
            let mut byte = 0u8;
            assert_eq!(
                unsafe { crate::patina_read(other_rd, (&mut byte as *mut u8).cast(), 1) },
                1
            );
        });
        let worker = task_of(other);
        let helper = spawn(move || {
            delay();
            {
                let state = lock_state();
                assert!(state.signals.blocked.contains_key(&me));
                assert!(state.signals.blocked.contains_key(&worker));
            }
            generate(SIGUSR1);
            {
                let state = lock_state();
                assert!(!state.signals.blocked.contains_key(&me));
                assert!(state.signals.blocked.contains_key(&worker));
                assert!(
                    state
                        .net
                        .pipe_channels
                        .values()
                        .any(|ch| ch.recv_waiters.contains(&worker))
                );
                assert!(
                    !state
                        .net
                        .pipe_channels
                        .values()
                        .any(|ch| ch.recv_waiters.contains(&me))
                );
            }
            delay();
            assert_eq!(
                unsafe { crate::patina_write(other_wr, b"x".as_ptr().cast(), 1) },
                1
            );
        });
        let mut byte = 0u8;
        assert_eq!(
            unsafe { crate::patina_read(rd, (&mut byte as *mut u8).cast(), 1) },
            -1
        );
        assert_eq!(crate::patina_errno(), EINTR);
        join(helper);
        join(other);
        crate::patina_close(wr);
        let ops = operations();
        let generated = ops
            .iter()
            .position(|op| matches!(op, Operation::SignalGenerated { .. }))
            .unwrap();
        assert_eq!(wakes_after(&ops, generated), vec![me]);
    });
}

#[test]
fn nanosleep_interrupted_reports_remaining_and_never_restarts() {
    isolated(|| {
        action(true);
        // The C-facing ABI and the raw SUD adapter both pass real rem buffers.
        for raw in [false, true] {
            let me = current_task();
            let helper = spawn(move || {
                assert_eq!(after_others_park(me), BlockClass::Sleep);
                generate(SIGUSR1);
            });
            let now = with_context_raw(|c| c.now(ClockKind::Monotonic)).unwrap();
            let req = Timespec { sec: 0, nsec: 100 };
            let mut rem = [99i64; 2];
            let rc = if raw {
                unsafe {
                    crate::sud::patina_sud_dispatch(
                        syscall_number("nanosleep"),
                        &req as *const _ as u64,
                        rem.as_mut_ptr() as u64,
                        0,
                        0,
                        0,
                        0,
                        0,
                    )
                }
            } else {
                let rc = unsafe {
                    crate::patina_sleep_until_remaining(
                        CLOCK_MONOTONIC,
                        now + 100,
                        rem.as_mut_ptr(),
                    )
                };
                assert_eq!(rc, -1);
                -i64::from(crate::patina_errno())
            };
            assert_eq!(rc, -i64::from(EINTR));
            assert_eq!(rem, [0, 90]);
            join(helper);
        }
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn absolute_clock_nanosleep_leaves_rem_untouched() {
    isolated(|| {
        action(true);
        let me = current_task();
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::Sleep);
            generate(SIGUSR1);
        });
        let req = Timespec { sec: 0, nsec: 100 };
        let mut rem = [123i64, 456];
        let rc = unsafe {
            crate::sud::patina_sud_dispatch(
                syscall_number("clock_nanosleep"),
                u64::from(CLOCK_MONOTONIC),
                TIMER_ABSTIME,
                &req as *const _ as u64,
                rem.as_mut_ptr() as u64,
                0,
                0,
                0,
            )
        };
        assert_eq!(rc, -i64::from(EINTR));
        assert_eq!(rem, [123, 456]);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        join(helper);
    });
}

#[test]
fn epoll_wait_is_eintr_even_with_sa_restart() {
    isolated(|| {
        action(true);
        let [rd, _wr] = pipe();
        let ep = epoll::patina_epoll_create1(0);
        let interest = Event {
            events: EPOLLIN,
            data: 7,
        };
        assert_eq!(
            unsafe {
                epoll::patina_epoll_ctl(ep, EPOLL_CTL_ADD, rd, (&interest as *const Event).cast())
            },
            0
        );
        let me = current_task();
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::Readiness);
            generate(SIGUSR1);
            let state = lock_state();
            assert!(
                !state
                    .net
                    .pipe_channels
                    .values()
                    .any(|ch| ch.recv_waiters.contains(&me))
            );
        });
        let mut events = [0u64; 4];
        assert_eq!(
            unsafe { epoll::patina_epoll_wait(ep, events.as_mut_ptr().cast(), 1, -1) },
            -1
        );
        assert_eq!(crate::patina_errno(), EINTR);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        assert_eq!(parked_class(me), None);
        join(helper);
    });
}

#[test]
fn timed_futex_wait_is_eintr_under_a_handler() {
    isolated(|| {
        let word = Box::into_raw(Box::new(0u32)) as usize;
        for (timed, restart) in [(true, true), (true, false), (false, true), (false, false)] {
            action(restart);
            let me = current_task();
            let helper = spawn(move || {
                assert_eq!(
                    after_others_park(me),
                    if timed {
                        BlockClass::TimedFutex
                    } else {
                        BlockClass::Futex
                    }
                );
                let now = with_context_raw(|c| c.now(ClockKind::Monotonic)).unwrap();
                generate(SIGUSR1);
                if !timed && restart {
                    assert_eq!(crate::patina_sleep_until(CLOCK_MONOTONIC, now + 20), 0);
                    assert_eq!(patina_futex_wake(word, 1), 1);
                }
            });
            let rc = if timed {
                patina_futex_wait_timed(word, 0, CLOCK_MONOTONIC, 0, 100)
            } else {
                patina_futex_wait(word, 0)
            };
            if !timed && restart {
                assert_eq!(rc, 0);
            } else {
                assert_eq!(rc, -1);
                assert_eq!(crate::patina_errno(), EINTR);
            }
            assert!(
                lock_state()
                    .futexes
                    .get(&word)
                    .is_none_or(VecDeque::is_empty)
            );
            join(helper);
        }
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 4);
        unsafe {
            drop(Box::from_raw(word as *mut u32));
        }
    });
}

#[test]
fn interrupted_waiter_is_unlinked_before_wake() {
    isolated(|| {
        action(false);
        let me = current_task();
        for class in [
            BlockClass::Io,
            BlockClass::Futex,
            BlockClass::Readiness,
            BlockClass::Sleep,
        ] {
            let pipe = matches!(class, BlockClass::Io | BlockClass::Readiness).then(pipe);
            let word = (class == BlockClass::Futex).then(|| Box::into_raw(Box::new(0u32)) as usize);
            let ep = (class == BlockClass::Readiness).then(|| {
                let ep = epoll::patina_epoll_create1(0);
                let interest = Event {
                    events: EPOLLIN,
                    data: 7,
                };
                assert_eq!(
                    unsafe {
                        epoll::patina_epoll_ctl(
                            ep,
                            EPOLL_CTL_ADD,
                            pipe.unwrap()[0],
                            (&interest as *const Event).cast(),
                        )
                    },
                    0
                );
                ep
            });
            let helper = spawn(move || {
                assert_eq!(after_others_park(me), class);
                generate(SIGUSR1);
                assert_eq!(parked_class(me), None);
                assert!(!on_any_waiter_list(me));
                if let Some(word) = word {
                    assert_eq!(
                        patina_futex_wake(word, 1),
                        0,
                        "the later primitive wake cannot find the interrupted task"
                    );
                }
                if let Some([_, wr]) = pipe {
                    assert_eq!(
                        unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
                        1
                    );
                }
            });
            let mut buf = [0u64; 4];
            let rc = match class {
                BlockClass::Io => unsafe {
                    crate::patina_read(pipe.unwrap()[0], buf.as_mut_ptr().cast(), 1) as i32
                },
                BlockClass::Futex => patina_futex_wait(word.unwrap(), 0),
                BlockClass::Readiness => unsafe {
                    epoll::patina_epoll_wait(ep.unwrap(), buf.as_mut_ptr().cast(), 1, -1)
                },
                BlockClass::Sleep => {
                    let now = with_context_raw(|c| c.now(ClockKind::Monotonic)).unwrap();
                    crate::patina_sleep_until(CLOCK_MONOTONIC, now + 100)
                }
                _ => unreachable!(),
            };
            assert_eq!(rc, -1);
            assert_eq!(crate::patina_errno(), EINTR);
            join(helper);
            // An interrupted timer cannot cause the next deadlock rescue to
            // select this task before its new, later deadline.
            let now = with_context_raw(|c| c.now(ClockKind::Monotonic)).unwrap();
            assert_eq!(crate::patina_sleep_until(CLOCK_MONOTONIC, now + 200), 0);
            assert_eq!(
                with_context_raw(|c| c.now(ClockKind::Monotonic)).unwrap(),
                now + 200
            );
            if let Some(word) = word {
                unsafe {
                    drop(Box::from_raw(word as *mut u32));
                }
            }
            if let Some(ep) = ep {
                assert_eq!(crate::patina_close(ep), 0);
            }
            if let Some([rd, wr]) = pipe {
                assert_eq!(crate::patina_close(rd), 0);
                assert_eq!(crate::patina_close(wr), 0);
            }
        }
        let ops = operations();
        for (index, op) in ops.iter().enumerate() {
            if matches!(op, Operation::SignalGenerated { .. }) {
                assert_eq!(wakes_after(&ops, index), vec![me]);
            }
        }
    });
}

#[test]
fn sigsuspend_parks_until_an_unblocked_signal() {
    isolated(|| {
        action(true);
        let me = current_task();
        set_mask(SIG_SETMASK, bit(SIGUSR1));
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::SigSuspend);
            generate(SIGUSR2);
            {
                let state = lock_state();
                assert!(state.signals.blocked.contains_key(&me));
                assert_eq!(state.signals.pending(me), bit(SIGUSR2));
            }
            generate(SIGUSR1);
        });
        assert_eq!(
            unsafe {
                patina_signal_wait(
                    &bit(SIGUSR2),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    SIGSET_BYTES,
                    WaitMode::Suspend,
                )
            },
            -i64::from(EINTR)
        );
        assert_eq!(read_mask(), bit(SIGUSR1));
        assert_eq!(lock_state().signals.mask(me), bit(SIGUSR1));
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        // Consume the temporarily blocked SIGUSR2 before restoring an empty mask.
        let zero = Timespec { sec: 0, nsec: 0 };
        assert_eq!(
            unsafe {
                patina_signal_wait(
                    &bit(SIGUSR2),
                    std::ptr::null_mut(),
                    &zero,
                    SIGSET_BYTES,
                    WaitMode::Dequeue,
                )
            },
            i64::from(SIGUSR2)
        );
        join(helper);
        set_mask(SIG_SETMASK, 0);
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::Pause);
            generate(SIGUSR1);
        });
        assert_eq!(
            unsafe {
                patina_signal_wait(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    SIGSET_BYTES,
                    WaitMode::Pause,
                )
            },
            -i64::from(EINTR)
        );
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 2);
        join(helper);
        set_mask(SIG_SETMASK, bit(SIGUSR2));
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::SigWait);
            generate(SIGUSR2);
        });
        let mut info = Info { words: [0; 16] };
        assert_eq!(
            unsafe {
                patina_signal_wait(
                    &bit(SIGUSR2),
                    &mut info,
                    std::ptr::null(),
                    SIGSET_BYTES,
                    WaitMode::Dequeue,
                )
            },
            i64::from(SIGUSR2)
        );
        assert_eq!(info.code(), SI_USER);
        assert_eq!(
            HANDLERS.load(Ordering::SeqCst),
            2,
            "sigwait dequeues without a handler"
        );
        join(helper);
    });
}

#[test]
fn signalfd_readable_iff_matching_pending() {
    isolated(|| {
        action(true);
        let me = current_task();
        set_mask(SIG_SETMASK, bit(SIGUSR1) | bit(SIGUSR2));
        let sfd = unsafe { fd::patina_signalfd(-1, &bit(SIGUSR1), SIGSET_BYTES, 0) } as i32;
        assert!(sfd >= 0);
        let ready = || fd_readiness(&lock_state(), sfd, None).readable;
        assert!(!ready());
        generate(SIGUSR2);
        assert!(!ready());
        generate(SIGUSR1);
        assert!(ready());
        let mut record = [0u8; 128];
        assert_eq!(
            unsafe { crate::patina_read(sfd, record.as_mut_ptr().cast(), record.len()) },
            128
        );
        assert_eq!(
            u32::from_ne_bytes(record[0..4].try_into().unwrap()),
            SIGUSR1 as u32
        );
        assert_eq!(u32::from_ne_bytes(record[12..16].try_into().unwrap()), 1);
        assert!(!ready());
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::SignalfdRead);
            generate(SIGUSR1);
        });
        assert_eq!(
            unsafe { crate::patina_read(sfd, record.as_mut_ptr().cast(), record.len()) },
            128
        );
        assert!(!ready());
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
        join(helper);
        let replacement = spawn(move || {
            delay();
            assert_eq!(parked_class(me), Some(BlockClass::SignalfdRead));
            assert_eq!(
                unsafe { fd::patina_signalfd(sfd, &bit(SIGUSR2), SIGSET_BYTES, 0) },
                i64::from(sfd)
            );
            assert_eq!(parked_class(me), None);
            assert!(lock_state().signals.interrupted.is_empty());
        });
        assert_eq!(
            unsafe { crate::patina_read(sfd, record.as_mut_ptr().cast(), record.len()) },
            128
        );
        assert_eq!(
            u32::from_ne_bytes(record[..4].try_into().unwrap()),
            SIGUSR2 as u32
        );
        assert!(!ready());
        join(replacement);
        assert_eq!(crate::patina_close(sfd), 0);
        assert!(lock_state().signals.signalfds.is_empty());
        let ops = operations();
        let generated = ops
            .iter()
            .rposition(|op| matches!(op, Operation::SignalGenerated { .. }))
            .unwrap();
        assert_eq!(
            wakes_after(&ops, generated),
            vec![me],
            "the chosen signalfd reader is also on its fd queue, but is woken only once"
        );
    });
}

#[test]
fn signalfd_watchers_wake_once_only_for_visible_pending() {
    isolated(|| {
        action(false);
        set_mask(SIG_SETMASK, bit(SIGUSR1) | bit(SIGUSR2));
        let sfd = unsafe { fd::patina_signalfd(-1, &bit(SIGUSR1), SIGSET_BYTES, 0) } as i32;
        let other_sfd = unsafe { fd::patina_signalfd(-1, &bit(SIGUSR2), SIGSET_BYTES, 0) } as i32;
        fn watch(fd: i32) {
            // Duplicate subscriptions must not double-wake a task.
            let mut fds = [readiness::PollFd {
                fd,
                events: readiness::POLLIN,
                revents: 0,
            }; 2];
            assert_eq!(
                unsafe {
                    readiness::patina_poll(
                        fds.as_mut_ptr(),
                        2,
                        -1,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                    )
                },
                2
            );
            assert!(fds.iter().all(|fd| fd.revents == readiness::POLLIN));
        }
        let a = spawn(move || {
            watch(sfd);
            let mut record = [0u8; 128];
            assert_eq!(
                unsafe { crate::patina_read(sfd, record.as_mut_ptr().cast(), 128) },
                128
            );
            watch(sfd);
        });
        let b = spawn(move || watch(sfd));
        let c = spawn(move || watch(other_sfd));
        let ids = [task_of(a), task_of(b), task_of(c)];
        delay();
        assert!(ids.iter().all(|task| parked_class(*task).is_some()));
        assert_eq!(
            unsafe {
                generate_signal(
                    GenerationTarget::Thread {
                        tgid: Some(1),
                        tid: ids[0].0 as i32,
                    },
                    SIGUSR1,
                    GenerationInfo::Thread,
                )
            },
            0
        );
        {
            let state = lock_state();
            assert!(!state.signals.blocked.contains_key(&ids[0]));
            assert!(state.signals.blocked.contains_key(&ids[1]));
            assert!(state.signals.blocked.contains_key(&ids[2]));
            assert_eq!(state.signals.pending(ids[1]), 0);
            assert!(state.signals.interrupted.is_empty());
        }
        delay();
        assert!(ids.iter().all(|task| parked_class(*task).is_some()));
        generate(SIGUSR1);
        {
            let state = lock_state();
            assert!(!state.signals.blocked.contains_key(&ids[0]));
            assert!(!state.signals.blocked.contains_key(&ids[1]));
            assert!(state.signals.blocked.contains_key(&ids[2]));
            assert!(state.signals.interrupted.is_empty());
            assert!(
                state
                    .signals
                    .signalfds
                    .values()
                    .all(|fd| !fd.waiters.contains(&ids[0]) && !fd.waiters.contains(&ids[1]))
            );
        }
        join(a);
        join(b);
        generate(SIGUSR2);
        join(c);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 0);
        let ops = operations();
        let generations: Vec<_> = ops
            .iter()
            .enumerate()
            .filter_map(|(i, op)| matches!(op, Operation::SignalGenerated { .. }).then_some(i))
            .collect();
        assert_eq!(generations.len(), 3);
        assert_eq!(wakes_after(&ops, generations[0]), vec![ids[0]]);
        assert_eq!(wakes_after(&ops, generations[1]), vec![ids[0], ids[1]]);
        assert_eq!(wakes_after(&ops, generations[2]), vec![ids[2]]);
    });
}

#[test]
fn reexec_rejects_an_empty_filter_and_a_planted_failure() {
    const PLANT: &str = "PATINA_REEXEC_PLANT";
    if std::env::var_os(PLANT).is_some() {
        isolated(|| panic!("planted reexec failure"));
        return;
    }
    isolated(|| {
        assert!(std::panic::catch_unwind(|| reexec("no::such::signal::test", &[])).is_err());
        let failed = reexec(&test_name(), &[(PLANT, "1")]);
        assert!(!failed.status.success());
        assert!(String::from_utf8_lossy(&failed.stderr).contains("planted reexec failure"));
    });
}

#[test]
fn zero_time_signal_wait_returns_eagain_before_unrelated_delivery() {
    isolated(|| {
        action(false);
        generate(SIGUSR1);
        let timeout = Timespec { sec: 0, nsec: 0 };
        let set = bit(SIGUSR2);
        let rc = unsafe {
            crate::sud::patina_sud_dispatch(
                syscall_number("rt_sigtimedwait"),
                &set as *const _ as u64,
                0,
                &timeout as *const _ as u64,
                SIGSET_BYTES as u64,
                0,
                0,
                0,
            )
        };
        assert_eq!(rc, -i64::from(EAGAIN));
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn sleep_remaining_is_snapshotted_before_handler_time() {
    extern "C" fn advancing_handler(_: i32) {
        delay_for(20);
    }
    isolated(|| {
        install_handler(SIGUSR1, advancing_handler, 0, 0);
        let me = current_task();
        let helper = spawn(move || {
            assert_eq!(after_others_park(me), BlockClass::Sleep);
            generate(SIGUSR1);
        });
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
        let mut remaining = [0i64; 2];
        assert_eq!(
            unsafe {
                crate::patina_sleep_until_remaining(
                    CLOCK_MONOTONIC,
                    now + 100,
                    remaining.as_mut_ptr(),
                )
            },
            -1
        );
        assert_eq!(crate::patina_errno(), EINTR);
        assert_eq!(remaining, [0, 90]);
        assert_eq!(
            with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap(),
            now + 30
        );
        join(helper);
    });
}

#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
#[path = "state_tests.rs"]
mod state_tests;
pub(super) use state_tests::observe_host_call;

#[path = "sync_wait_tests.rs"]
mod sync_wait_tests;
