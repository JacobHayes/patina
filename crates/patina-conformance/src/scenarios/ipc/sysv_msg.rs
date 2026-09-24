//! ipc/sysv_msg — System V message queues within one process and its
//! threads (man 2 msgget, msgsnd, msgrcv, msgctl; ipc/msg.c):
//!
//! * `IPC_STAT` counts the messages and bytes queued and names the last
//!   sender and receiver; `IPC_SET` lowers `msg_qbytes`, after which a send
//!   that does not fit is `EAGAIN` under `IPC_NOWAIT`;
//! * `msgrcv` selects by type: 0 takes the first message, a positive type
//!   the first of that type, a negative one the first of the lowest type not
//!   above its magnitude, `MSG_EXCEPT` the first of any other type; an empty
//!   selection with `IPC_NOWAIT` is `ENOMSG`;
//! * a message longer than the buffer is `E2BIG` and stays queued;
//!   `MSG_NOERROR` truncates it and consumes it;
//! * a blocked receive completes when another thread sends;
//! * a type of 0 or below, a size past any `msgmax`, and an unknown command
//!   are `EINVAL`; a NULL message is `EFAULT` whatever its size (the type is
//!   read first);
//! * a key names one queue: `EEXIST` for `IPC_CREAT|IPC_EXCL` on a taken
//!   key, `ENOENT` for a key nobody took; once removed its id is `EINVAL`.
//!
//! The helper thread's calls are unrecorded (their timing is the host's);
//! what they cause is. Keys are `ftok(3)` of the run directory; every queue
//! is removed on every path.
//!
//! The keyed queue comes first, while nothing private exists: a run killed
//! there leaves only what the harness sweeps by key (`crate::owned`).

use super::owned::Owned;
use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::owned;
use crate::probe::{Key, MsgArg, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// Past any `msgmax` a host can configure (it is an `int`).
const HUGE: usize = 1 << 40;
/// A command `msgctl` does not define (the IPC commands end at 20,
/// `SEM_STAT_ANY`).
const UNKNOWN_CMD: i32 = 99;
/// The queue's byte limit after `IPC_SET`.
const QBYTES: u64 = 8;

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;

    // ---- a keyed queue ----
    let key = p.owned_key(owned::MSG_PROJECT, "ftok(run,'M')");
    let kid = p.msgget(key, IPC_CREAT | IPC_EXCL | 0o600);
    p.require("create the keyed queue", kid >= 0);
    let keyed = Owned::sysv(Syscall::N_msgctl, kid);
    p.check(
        "IPC_CREAT|IPC_EXCL on a taken key is EEXIST",
        i64::from(p.msgget(key, IPC_CREAT | IPC_EXCL | 0o600)) == neg(EEXIST),
    );
    p.check("the key names the queue", p.msgget(key, 0) == kid);
    let removed = p.msgctl(kid, IPC_RMID, MsgArg::None).0;
    p.check("IPC_RMID", removed == 0);
    keyed.removed(removed);
    p.check(
        "a key nobody took is ENOENT",
        i64::from(p.msgget(key, 0)) == neg(ENOENT),
    );

    // ---- a private queue ----
    let id = p.msgget(Key::PRIVATE, IPC_CREAT | 0o600);
    p.require("create a private queue", id >= 0);
    let queue = Owned::sysv(Syscall::N_msgctl, id);
    let (r, ds) = p.msgctl(id, IPC_STAT, MsgArg::Stat);
    p.check(
        "a new queue is empty and never used",
        r == 0
            && ds.is_some_and(|ds| {
                ds.msg_qnum == 0
                    && ds.__msg_cbytes == 0
                    && ds.msg_lspid == 0
                    && ds.msg_lrpid == 0
                    && ds.msg_stime == 0
                    && u32::from(ds.msg_perm.mode) & 0o777 == 0o600
            }),
    );
    for (mtype, text) in [(1, &b"a"[..]), (2, b"bb"), (3, b"ccc"), (1, b"dddd")] {
        p.check("send a message", p.msgsnd(id, mtype, text, IPC_NOWAIT) == 0);
    }
    let (r, ds) = p.msgctl(id, IPC_STAT, MsgArg::Stat);
    p.check(
        "IPC_STAT counts the messages and bytes, names the sender",
        r == 0
            && ds.is_some_and(|ds| {
                ds.msg_qnum == 4
                    && ds.__msg_cbytes == 10
                    && ds.msg_lspid == pid
                    && ds.msg_stime != 0
            }),
    );

    // ---- selection ----
    let (_, got) = p.msgrcv(id, 16, 3, IPC_NOWAIT);
    p.check(
        "a positive type takes the first of that type",
        got.is_some_and(|(mtype, text)| mtype == 3 && text == b"ccc"),
    );
    let (_, got) = p.msgrcv(id, 16, -2, IPC_NOWAIT);
    p.check(
        "a negative type takes the lowest type not above it",
        got.is_some_and(|(mtype, text)| mtype == 1 && text == b"a"),
    );
    let (_, got) = p.msgrcv(id, 16, 1, IPC_NOWAIT | MSG_EXCEPT);
    p.check(
        "MSG_EXCEPT takes the first of any other type",
        got.is_some_and(|(mtype, text)| mtype == 2 && text == b"bb"),
    );
    p.check(
        "an empty selection with IPC_NOWAIT is ENOMSG",
        p.msgrcv(id, 16, 5, IPC_NOWAIT).0 == neg(ENOMSG),
    );
    p.check(
        "a message longer than the buffer is E2BIG",
        p.msgrcv(id, 2, 0, IPC_NOWAIT).0 == neg(E2BIG),
    );
    let (r, got) = p.msgrcv(id, 2, 0, IPC_NOWAIT | MSG_NOERROR);
    p.check(
        "and stays queued; MSG_NOERROR truncates it",
        r == 2 && got.is_some_and(|(mtype, text)| mtype == 1 && text == b"dd"),
    );
    p.check(
        "and consumes it",
        p.msgrcv(id, 16, 0, IPC_NOWAIT).0 == neg(ENOMSG),
    );
    let (r, ds) = p.msgctl(id, IPC_STAT, MsgArg::Stat);
    p.check(
        "IPC_STAT: empty again, this process received last",
        r == 0
            && ds.is_some_and(|ds| {
                ds.msg_qnum == 0 && ds.__msg_cbytes == 0 && ds.msg_lrpid == pid && ds.msg_rtime != 0
            }),
    );

    // ---- a full queue, a blocked receive ----
    p.check(
        "IPC_SET lowers msg_qbytes",
        p.msgctl(
            id,
            IPC_SET,
            MsgArg::Set {
                mode: 0o600,
                qbytes: QBYTES,
            },
        )
        .0 == 0,
    );
    let (r, ds) = p.msgctl(id, IPC_STAT, MsgArg::Stat);
    p.check(
        "IPC_STAT shows it",
        r == 0 && ds.is_some_and(|ds| ds.msg_qbytes == QBYTES),
    );
    p.check(
        "a message that fills the queue",
        p.msgsnd(id, 7, b"12345678", IPC_NOWAIT) == 0,
    );
    p.check(
        "a send that does not fit is EAGAIN under IPC_NOWAIT",
        p.msgsnd(id, 7, b"9", IPC_NOWAIT) == neg(EAGAIN),
    );
    p.msgrcv(id, 16, 7, IPC_NOWAIT);
    let received = std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec.quiet(|| p.msgsnd(id, 9, b"late", 0));
        });
        p.msgrcv(id, 16, 9, 0)
    });
    p.check(
        "a blocked receive completes when another thread sends",
        received.0 == 4
            && received
                .1
                .is_some_and(|(mtype, text)| mtype == 9 && text == b"late"),
    );

    // ---- refusals ----
    p.check(
        "type 0 is EINVAL",
        p.msgsnd(id, 0, b"x", IPC_NOWAIT) == neg(EINVAL),
    );
    p.check(
        "a negative type is EINVAL",
        p.msgsnd(id, -1, b"x", IPC_NOWAIT) == neg(EINVAL),
    );
    p.check(
        "a size past msgmax is EINVAL",
        p.msgsnd_declared(id, Some((1, b"x")), HUGE, IPC_NOWAIT) == neg(EINVAL),
    );
    p.check(
        "a NULL message is EFAULT, its type read before the size is judged",
        p.msgsnd_declared(id, None, HUGE, IPC_NOWAIT) == neg(EFAULT),
    );
    p.check(
        "an unknown command is EINVAL",
        p.msgctl(id, UNKNOWN_CMD, MsgArg::None).0 == neg(EINVAL),
    );

    // ---- removal ----
    let removed = p.msgctl(id, IPC_RMID, MsgArg::None).0;
    p.check("IPC_RMID of the private queue", removed == 0);
    queue.removed(removed);
    p.check(
        "a removed id is EINVAL",
        p.msgsnd(id, 1, b"x", IPC_NOWAIT) == neg(EINVAL)
            && p.msgctl(id, IPC_STAT, MsgArg::Stat).0 == neg(EINVAL),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "ipc/sysv_msg",
    run,
    covers: &[
        Syscall::N_msgget,
        Syscall::N_msgsnd,
        Syscall::N_msgrcv,
        Syscall::N_msgctl,
    ],
    symbols: &["syscall", "getpid"],
    needs: &[Need::SysvMsg],
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::ALL,
        what: "msgget is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no msgget wrapper)",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall msgget (nr",
        },
    }],
    ..DEFAULTS
};
