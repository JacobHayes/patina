//! thread/main_exit — a raw `exit` (the thread row, not `exit_group`) from
//! the main thread ends only that thread: the process lives while another
//! thread runs, that thread records events after the main thread is gone,
//! a row it issues copies its pointers as before (the process's memory is
//! the running thread's), `process_vm_readv` of the process named by that
//! thread's id copies while the exited leader's pid is `ESRCH` (`mm_access`
//! finds no memory behind it), and its `exit_group` sets the process exit
//! status (kernel/exit.c do_exit vs do_group_exit; man 2 exit). procfs
//! keeps the process: `/proc/self/status` describes the exited leader as
//! a zombie (`Z (zombie)`, under the name it set, with no `Umask`: it has
//! no `fs` left) still
//! counted among the threads, and `/proc/self/task` lists it beside the
//! running thread, its `stat` in state `Z` with `PF_EXITING` among its
//! flags.

use crate::catalog::{DEFAULTS, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub fn run(p: &Probe) {
    static MAIN_LEAVING: AtomicBool = AtomicBool::new(false);
    static WORKER_PROBE: AtomicPtr<Probe> = AtomicPtr::new(std::ptr::null_mut());
    // Published before the spawn, so the worker never reads it unset. The main
    // thread leaves by a raw exit that never returns, so the probe its frame
    // owns stays mapped for the worker.
    WORKER_PROBE.store(p as *const Probe as *mut Probe, Ordering::SeqCst);
    let worker = std::thread::Builder::new()
        .spawn(move || {
            let p: &'static Probe =
                unsafe { &*(WORKER_PROBE.load(Ordering::SeqCst) as *const Probe) };
            while !MAIN_LEAVING.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            std::thread::sleep(std::time::Duration::from_millis(40));
            p.check("the worker runs after the main thread's raw exit", true);
            procfs_after_leader(p);
            let mut blocked = u64::MAX;
            p.check(
                "and a row copies its pointer out",
                p.call_observed(
                    Syscall::N_rt_sigprocmask,
                    [
                        libc::SIG_BLOCK as i64,
                        0,
                        &mut blocked as *mut u64 as i64,
                        8,
                        0,
                        0,
                    ],
                ) == 0
                    && blocked != u64::MAX,
            );
            let source = 0x5au8;
            let mut target = 0u8;
            let local = libc::iovec {
                iov_base: (&raw mut target).cast(),
                iov_len: 1,
            };
            let remote = libc::iovec {
                iov_base: (&raw const source).cast_mut().cast(),
                iov_len: 1,
            };
            let read_by = |pid: i64| {
                p.call_observed(
                    Syscall::N_process_vm_readv,
                    [
                        pid,
                        &raw const local as i64,
                        1,
                        &raw const remote as i64,
                        1,
                        0,
                    ],
                )
            };
            let me = p.call_unrecorded(Syscall::N_gettid, [0; 6]);
            p.check(
                "process_vm_readv of the process by the running thread's id copies",
                read_by(me) == 1 && target == source,
            );
            let leader = p.call_unrecorded(Syscall::N_getpid, [0; 6]);
            p.check(
                "and by the exited leader's pid is ESRCH",
                read_by(leader) == neg(libc::ESRCH),
            );
            p.mark("worker_done", &[]);
            p.exit_group(0);
        })
        .expect("spawn");
    drop(worker);
    p.check(
        "the main thread is the thread group leader",
        p.gettid() == p.getpid(),
    );
    // SAFETY: a NUL-terminated name.
    unsafe { libc::prctl(libc::PR_SET_NAME, c"leader".as_ptr()) };
    MAIN_LEAVING.store(true, Ordering::SeqCst);
    p.exit_thread(0);
}

/// `PF_EXITING` (include/linux/sched.h).
const PF_EXITING: u64 = 0x4;

/// What procfs shows of the process once its leader has exited, read by
/// the thread still running.
fn procfs_after_leader(p: &Probe) {
    let status = || std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let keyed = |text: &str, key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(":\t"))
            .map(str::to_owned)
    };
    // The kernel marks the leader a zombie as its exit ends.
    p.rec.quiet(|| {
        crate::signals::wait_until(std::time::Duration::from_millis(1), || {
            keyed(&status(), "State").as_deref() == Some("Z (zombie)")
        })
    });
    let text = status();
    p.check(
        "/proc/self/status describes the exited leader as a zombie",
        keyed(&text, "State").as_deref() == Some("Z (zombie)"),
    );
    p.check(
        "under the name it set",
        keyed(&text, "Name").as_deref() == Some("leader"),
    );
    p.check(
        "with no umask, among two threads",
        keyed(&text, "Umask").is_none() && keyed(&text, "Threads").as_deref() == Some("2"),
    );
    let leader = p.call_unrecorded(Syscall::N_getpid, [0; 6]);
    let me = p.call_unrecorded(Syscall::N_gettid, [0; 6]);
    let mut tids: Vec<i64> = std::fs::read_dir("/proc/self/task")
        .map(|dir| {
            dir.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    tids.sort_unstable();
    p.check(
        "/proc/self/task lists the exited leader and the running thread",
        tids == [leader.min(me), leader.max(me)],
    );
    let stat =
        std::fs::read_to_string(format!("/proc/self/task/{leader}/stat")).unwrap_or_default();
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map_or(Vec::new(), |(_, rest)| rest.split_whitespace().collect());
    p.check(
        "the leader's task stat is in state Z, exiting",
        fields.first() == Some(&"Z")
            && fields
                .get(6)
                .and_then(|flags| flags.parse::<u64>().ok())
                .is_some_and(|flags| flags & PF_EXITING != 0),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/main_exit",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_exit,
        Syscall::N_exit_group,
        Syscall::N_rt_sigprocmask,
        Syscall::N_process_vm_readv,
    ],
    trace: Some(TraceFacts {
        generations: &[],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
