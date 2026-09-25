//! thread/robust_list — the robust-futex list head the kernel walks when a
//! thread exits (kernel/futex/syscalls.c `set_robust_list`,
//! `get_robust_list`), as 6.8 answers it:
//!
//! * `set_robust_list` takes exactly a `struct robust_list_head` (24 bytes;
//!   any other length is `EINVAL`) and replaces the caller's head;
//! * `get_robust_list` of the caller (pid 0, or its own tid) reports the
//!   head glibc registered for the thread at its start: an empty list (its
//!   `next` points at the head itself), glibc's `futex_offset` and no
//!   operation pending, and a length of 24; a second thread's head is its
//!   own, empty too; a pid no process has is `ESRCH`, and a NULL length
//!   pointer `EFAULT`;
//! * a head the caller sets is what it then reads back, and restoring
//!   glibc's head restores the report.
//!
//! glibc wraps neither row, so the scenario runs through the kernel
//! vehicles.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::observe::{Id, Norm};
use crate::probe::{NO_SUCH_PID, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `struct robust_list_head`.
#[repr(C)]
struct Head {
    next: usize,
    futex_offset: i64,
    list_op_pending: usize,
}

const HEAD_BYTES: i64 = std::mem::size_of::<Head>() as i64;

/// What `get_robust_list` reported: the head's address and the length.
struct Report {
    result: i64,
    head: usize,
    len: usize,
}

impl Report {
    /// The head it names, read through the pointer (an empty list's `next`
    /// is the head itself).
    fn read(&self) -> Option<&Head> {
        // SAFETY: a head the kernel reports is a live thread's registered
        // `robust_list_head`: glibc's in the thread's descriptor, or one
        // this scenario owns.
        (self.result == 0 && self.head != 0).then(|| unsafe { &*(self.head as *const Head) })
    }
}

/// `get_robust_list(pid)`; the event records the length and the head's
/// shape, never its address.
fn get(p: &Probe, pid: i64, what: &str, with_len: bool) -> Report {
    let mut head = 0usize;
    let mut len = 0usize;
    let len_ptr = if with_len {
        &mut len as *mut usize as i64
    } else {
        0
    };
    let result = p.call_unrecorded(
        Syscall::N_get_robust_list,
        [pid, &mut head as *mut usize as i64, len_ptr, 0, 0, 0],
    );
    let report = Report { result, head, len };
    let shape = report.read();
    p.rec
        .event(Syscall::N_get_robust_list.name(), result)
        .arg("pid", pid)
        .norm("args.pid", Norm::Identity(Id::Process))
        .arg("of", what)
        .arg("len_ptr", with_len)
        .field("len", report.len)
        .field("empty", shape.is_some_and(|h| h.next == report.head))
        .field("futex_offset", shape.map_or(0, |h| h.futex_offset))
        .field("op_pending", shape.is_some_and(|h| h.list_op_pending != 0))
        .emit();
    report
}

/// Puts glibc's head back (unrecorded) if dropped before the scenario's own
/// restore.
struct RestoreHead<'a> {
    p: &'a Probe,
    head: usize,
}

impl Drop for RestoreHead<'_> {
    fn drop(&mut self) {
        self.p.call_unrecorded(
            Syscall::N_set_robust_list,
            [self.head as i64, HEAD_BYTES, 0, 0, 0, 0],
        );
    }
}

fn set(p: &Probe, head: usize, len: i64, what: &str) -> i64 {
    p.observed(
        Syscall::N_set_robust_list,
        [head as i64, len, 0, 0, 0, 0],
        &[("head", what.into()), ("len", len.into())],
    )
}

pub fn run(p: &Probe) {
    let mut mine = Head {
        next: 0,
        futex_offset: -8,
        list_op_pending: 0,
    };
    mine.next = &mine as *const Head as usize;
    let mine_at = &mine as *const Head as usize;
    p.check(
        "set_robust_list of any length but a head's is EINVAL",
        set(p, mine_at, 0, "own") == neg(EINVAL),
    );

    let glibc = get(p, 0, "self", true);
    p.check(
        "the caller's head is glibc's: an empty list, nothing pending, 24 bytes",
        glibc.result == 0
            && glibc.len == HEAD_BYTES as usize
            && glibc
                .read()
                .is_some_and(|h| h.next == glibc.head && h.list_op_pending == 0),
    );
    let tid = p.gettid();
    let by_tid = get(p, tid, "own-tid", true);
    p.check(
        "the caller's own tid names the same head",
        by_tid.result == 0 && by_tid.head == glibc.head,
    );
    let (helper, helper_empty) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                p.rec.quiet(|| {
                    let mut head = 0usize;
                    let mut len = 0usize;
                    let r = p.call_unrecorded(
                        Syscall::N_get_robust_list,
                        [
                            0,
                            &mut head as *mut usize as i64,
                            &mut len as *mut usize as i64,
                            0,
                            0,
                            0,
                        ],
                    );
                    let report = Report {
                        result: r,
                        head,
                        len,
                    };
                    // Read while the thread (and so its head) lives.
                    let empty = report.read().is_some_and(|h| h.next == report.head);
                    (report, empty)
                })
            })
            .join()
            .expect("the helper thread")
    });
    p.mark(
        "helper_robust_list",
        &[
            ("result", helper.result.into()),
            ("len", helper.len.into()),
            ("own_head", (helper.head != glibc.head).into()),
            ("empty", helper_empty.into()),
        ],
    );
    p.check(
        "a second thread's head is its own, and empty",
        helper.result == 0 && helper.head != glibc.head && helper_empty,
    );
    p.check(
        "a pid no process has is ESRCH",
        get(p, i64::from(NO_SUCH_PID), "no-such-pid", true).result == neg(ESRCH),
    );
    p.check(
        "a NULL length pointer is EFAULT",
        get(p, 0, "self", false).result == neg(EFAULT),
    );

    p.check(
        "set_robust_list of a head answers 0",
        set(p, mine_at, HEAD_BYTES, "own") == 0,
    );
    // Should a check stop the probe before the restore below, glibc's head
    // goes back anyway: the kernel walks the registered head at thread exit.
    let restore = RestoreHead {
        p,
        head: glibc.head,
    };
    let own = get(p, 0, "self", true);
    p.check(
        "the head set is the head reported",
        own.result == 0 && own.head == mine_at && own.read().is_some_and(|h| h.futex_offset == -8),
    );
    p.check(
        "restoring glibc's head answers 0",
        set(p, glibc.head, HEAD_BYTES, "glibc") == 0,
    );
    std::mem::forget(restore);
    let restored = get(p, 0, "self", true);
    p.check(
        "and restores the report",
        restored.result == 0 && restored.head == glibc.head,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/robust_list",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_set_robust_list, Syscall::N_get_robust_list],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: Vehicle::KERNEL,
            what: "set_robust_list is SoftDeny(ENOSYS) in the registry, a kernel without robust futexes, though every thread's glibc registration reaches the host kernel (ld.so's before SUD arms, a managed thread's from the host pthread_create): 6.8 has them and judges the length",
            failure: Failure::Differs(&[
                Difference::field(0, "set_robust_list", "errno", Observed::Str("ENOSYS")),
                Difference::check(1, "set_robust_list of any length but a head's is EINVAL"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: Vehicle::KERNEL,
            what: "get_robust_list is Trap(unmodeled) in the registry (the signals arc models it on the scheduler), so the SUD dispatcher aborts at the first get_robust_list",
            failure: Failure::Stops {
                events: 2,
                ending: Ending::Signal(libc::SIGABRT),
                diagnostic: "patina: SUD trapped unsupported syscall get_robust_list (nr",
            },
        },
    ],
    ..DEFAULTS
};
