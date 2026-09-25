//! ipc/mqueue — POSIX message queues within one process and its threads
//! (man 7 mq_overview, man 3 mq_open/mq_send/mq_receive/mq_notify/
//! mq_getattr; ipc/mqueue.c), through the kernel rows glibc's `mq_*` use
//! (the name without its leading slash):
//!
//! * a queue is created with the attributes asked (`mq_getsetattr` reports
//!   `mq_maxmsg`, `mq_msgsize`, `mq_curmsgs`, `mq_flags`); `O_CREAT|O_EXCL`
//!   on an existing name is `EEXIST`, opening a name nobody created
//!   `ENOENT`, a name with a slash `EACCES`, a zero `mq_maxmsg` or
//!   `mq_msgsize` `EINVAL`;
//! * messages come out highest priority first, first in first out within a
//!   priority; a message longer than `mq_msgsize` is `EMSGSIZE`, a buffer
//!   shorter than it too, a priority from `MQ_PRIO_MAX` up `EINVAL`;
//! * with `O_NONBLOCK` a full queue refuses a send and an empty one a
//!   receive with `EAGAIN`; `mq_getsetattr` changes only `O_NONBLOCK`
//!   (another flag is `EINVAL`);
//!   without it a receive waits until its deadline (`ETIMEDOUT`) — one that
//!   has already passed included — and a blocked receive completes when
//!   another thread sends; an invalid deadline is `EINVAL` whether or not
//!   the call would wait (ipc/mqueue.c `prepare_timeout` judges it first);
//! * `mq_notify`: one registration per queue (a second is `EBUSY`), removed
//!   with NULL, re-registered after; `SIGEV_SIGNAL` with an invalid signal is
//!   `EINVAL`; a message arriving on an empty queue sends the signal and
//!   consumes the registration;
//! * `mq_unlink` removes the name (a second one is `ENOENT`) while an open
//!   descriptor keeps working.
//!
//! The queue's name is derived from the run directory; it is unlinked on
//! every path.

use super::owned::Owned;
use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::owned;
use crate::probe::{Deadline, Notify, Probe, neg};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// The queue's attributes (the need's detection creates the same shape).
const MAXMSG: i64 = 4;
const MSGSIZE: i64 = 16;
/// `MQ_PRIO_MAX`.
const PRIO_MAX: u32 = 32768;
/// A signal number past `_NSIG` (64 on every Linux architecture).
const NO_SUCH_SIGNAL: i32 = 65;

pub fn run(p: &Probe) {
    let dir = p.dir();
    let name = owned::mq_name(std::path::Path::new(&dir));

    let fd = p.mq_open(
        &name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0o600,
        Some((MAXMSG, MSGSIZE)),
    );
    p.require("create the queue", fd >= 0);
    let queue = Owned::mqueue(&name);
    let (r, attr) = p.mq_getsetattr(fd, None);
    p.check(
        "it has the attributes asked, empty and blocking",
        r == 0
            && attr.mq_maxmsg == MAXMSG
            && attr.mq_msgsize == MSGSIZE
            && attr.mq_curmsgs == 0
            && attr.mq_flags == 0,
    );
    p.check(
        "O_CREAT|O_EXCL on its name is EEXIST",
        i64::from(p.mq_open(&name, O_RDWR | O_CREAT | O_EXCL, 0o600, None)) == neg(EEXIST),
    );
    p.check(
        "a name nobody created is ENOENT",
        i64::from(p.mq_open(&format!("{name}-none"), O_RDWR, 0, None)) == neg(ENOENT),
    );
    p.check(
        "a name with a slash is EACCES",
        i64::from(p.mq_open(&format!("{name}/sub"), O_RDWR | O_CREAT, 0o600, None)) == neg(EACCES),
    );
    p.check(
        "a zero mq_maxmsg is EINVAL",
        i64::from(p.mq_open(
            &format!("{name}-zero"),
            O_RDWR | O_CREAT,
            0o600,
            Some((0, MSGSIZE)),
        )) == neg(EINVAL),
    );
    p.check(
        "a zero mq_msgsize is EINVAL",
        i64::from(p.mq_open(
            &format!("{name}-zero"),
            O_RDWR | O_CREAT,
            0o600,
            Some((MAXMSG, 0)),
        )) == neg(EINVAL),
    );

    // ---- order and sizes ----
    for (data, prio) in [
        (&b"low"[..], 1),
        (b"high-1", 5),
        (b"mid", 3),
        (b"high-2", 5),
    ] {
        p.check(
            "send",
            p.mq_timedsend(fd, data, prio, Deadline::Forever) == 0,
        );
    }
    let (r, attr) = p.mq_getsetattr(fd, None);
    p.check("four messages queued", r == 0 && attr.mq_curmsgs == 4);
    p.check(
        "a message longer than mq_msgsize is EMSGSIZE",
        p.mq_timedsend(fd, &[b'x'; 17], 1, Deadline::Epoch) == neg(EMSGSIZE),
    );
    p.check(
        "a priority from MQ_PRIO_MAX up is EINVAL",
        p.mq_timedsend(fd, b"x", PRIO_MAX, Deadline::Epoch) == neg(EINVAL),
    );
    p.check(
        "a buffer shorter than mq_msgsize is EMSGSIZE",
        p.mq_timedreceive(fd, MSGSIZE as usize - 1, Deadline::Forever)
            .0
            == neg(EMSGSIZE),
    );
    let mut order = Vec::new();
    for _ in 0..4 {
        let (r, data, prio) = p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Forever);
        if r >= 0 {
            order.push((String::from_utf8_lossy(&data).into_owned(), prio));
        }
    }
    p.check(
        "highest priority first, first in first out within one",
        order
            == [
                ("high-1".to_string(), 5),
                ("high-2".to_string(), 5),
                ("mid".to_string(), 3),
                ("low".to_string(), 1),
            ],
    );

    // ---- blocking and O_NONBLOCK ----
    p.check(
        "a receive on an empty queue waits until its deadline",
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::After(10_000_000))
            .0
            == neg(ETIMEDOUT),
    );
    p.check(
        "a deadline already passed times out at once",
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Epoch).0 == neg(ETIMEDOUT),
    );
    p.check(
        "an invalid deadline is EINVAL",
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::BadNsec).0 == neg(EINVAL),
    );
    let (r, previous) = p.mq_getsetattr(fd, Some(i64::from(O_NONBLOCK)));
    p.check(
        "mq_getsetattr sets O_NONBLOCK, answering the old flags",
        r == 0 && previous.mq_flags == 0,
    );
    p.check(
        "an empty queue refuses a receive with EAGAIN",
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Forever).0 == neg(EAGAIN),
    );
    for _ in 0..MAXMSG {
        p.check("fill", p.mq_timedsend(fd, b"f", 0, Deadline::Forever) == 0);
    }
    p.check(
        "a full queue refuses a send with EAGAIN",
        p.mq_timedsend(fd, b"f", 0, Deadline::Forever) == neg(EAGAIN),
    );
    p.check(
        "an invalid deadline is EINVAL even when the call need not wait",
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::BadNsec).0 == neg(EINVAL),
    );
    p.check(
        "a flag other than O_NONBLOCK is EINVAL",
        p.mq_getsetattr(fd, Some(i64::from(O_NONBLOCK | O_APPEND)))
            .0
            == neg(EINVAL),
    );
    let (r, attr) = p.mq_getsetattr(fd, Some(0));
    p.check(
        "clearing O_NONBLOCK answers the flags it had, the queue still full",
        r == 0 && attr.mq_flags == i64::from(O_NONBLOCK) && attr.mq_curmsgs == MAXMSG,
    );
    for _ in 0..MAXMSG {
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Forever);
    }
    // ---- notification ----
    p.check("register SIGEV_NONE", p.mq_notify(fd, Notify::Quiet) == 0);
    p.check(
        "a second registration is EBUSY",
        p.mq_notify(fd, Notify::Quiet) == neg(EBUSY),
    );
    p.check("remove it", p.mq_notify(fd, Notify::Remove) == 0);
    p.check(
        "an invalid signal is EINVAL",
        p.mq_notify(fd, Notify::Signal(NO_SUCH_SIGNAL)) == neg(EINVAL),
    );
    let usr1 = support::one_set(SIGUSR1);
    let mut old = support::empty_set();
    p.check(
        "block SIGUSR1",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), Some(&mut old), 8) == 0,
    );
    p.check(
        "register SIGEV_SIGNAL SIGUSR1",
        p.mq_notify(fd, Notify::Signal(SIGUSR1)) == 0,
    );
    p.check(
        "a message arrives",
        p.mq_timedsend(fd, b"n", 0, Deadline::Forever) == 0,
    );
    let mut pending = support::empty_set();
    p.check(
        "SIGUSR1 is pending",
        p.rt_sigpending(&mut pending, 8) == 0 && support::has(&pending, SIGUSR1),
    );
    // SAFETY: a zeroed siginfo is a valid out-buffer.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    p.check(
        "its si_code is SI_MESGQ",
        p.rt_sigtimedwait(&usr1, Some(&mut info), Some(0), 8) == i64::from(SIGUSR1)
            && info.si_code == SI_MESGQ,
    );
    p.check(
        "the notification consumed the registration",
        p.mq_notify(fd, Notify::Quiet) == 0 && p.mq_notify(fd, Notify::Remove) == 0,
    );
    p.check(
        "restore the mask",
        p.rt_sigprocmask(SIG_SETMASK, Some(&old), None, 8) == 0,
    );

    // ---- unlink ----
    let unlinked = p.mq_unlink(&name);
    p.check("mq_unlink removes the name", unlinked == 0);
    queue.removed(unlinked);
    p.check(
        "a second mq_unlink is ENOENT",
        p.mq_unlink(&name) == neg(ENOENT),
    );
    let (r, data, _) = p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Forever);
    p.check("the open descriptor keeps working", r == 1 && data == b"n");
    // Last, once no signal is due: the helper thread starts with SIGUSR1
    // unblocked, and a process-directed notification could pick it.
    let received = std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec
                .quiet(|| p.mq_timedsend(fd, b"late", 2, Deadline::Forever));
        });
        p.mq_timedreceive(fd, MSGSIZE as usize, Deadline::Forever)
    });
    p.check(
        "a blocked receive completes when another thread sends",
        received.0 == 4 && received.1 == b"late" && received.2 == 2,
    );

    p.check("close it", p.close(fd) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "ipc/mqueue",
    run,
    covers: &[
        Syscall::N_mq_open,
        Syscall::N_mq_unlink,
        Syscall::N_mq_timedsend,
        Syscall::N_mq_timedreceive,
        Syscall::N_mq_notify,
        Syscall::N_mq_getsetattr,
    ],
    vehicles: Vehicle::KERNEL,
    needs: &[Need::PosixMqueue],
    ..DEFAULTS
};
