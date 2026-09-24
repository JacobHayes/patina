//! ipc/sysv_sem — System V semaphores within one process and its threads
//! (man 2 semget, semop, semtimedop, semctl; ipc/sem.c):
//!
//! * a new set's values are 0; `SETVAL`/`SETALL` and `GETVAL`/`GETALL`;
//!   `GETPID` names the last process to operate; `GETNCNT`/`GETZCNT` count
//!   the waiters; `IPC_STAT` reports the set size and mode, `IPC_SET` changes
//!   the mode; a value past `SEMVMX` (32767) is `ERANGE`, a negative one
//!   too; an unknown command is `EINVAL`;
//! * `semop` applies its operations atomically, all or none: a decrement
//!   below 0 or a wait-for-zero on a nonzero value with `IPC_NOWAIT` is
//!   `EAGAIN` and changes nothing; an increment past `SEMVMX` is `ERANGE`; a
//!   semaphore number past the set is `EFBIG`; no operation is `EINVAL`, more
//!   than `SEMOPM` `E2BIG`;
//! * `semtimedop` blocks until its timeout, then `EAGAIN`; an invalid
//!   timeout is `EINVAL` even for an operation that need not wait; a blocked
//!   decrement completes when another thread increments;
//! * removing a set wakes a thread blocked on it with `EIDRM`; later
//!   operations on the id are `EINVAL`;
//! * a key names one set: `EEXIST` for `IPC_CREAT|IPC_EXCL` on a taken key,
//!   `EINVAL` for more semaphores than the set has, `ENOENT` for a key
//!   nobody took; creating a set of 0 semaphores is `EINVAL`.
//!
//! The helper thread's calls are unrecorded (their timing is the host's);
//! what they cause is. Keys are `ftok(3)` of the run directory; every set is
//! removed on every path.
//!
//! The keyed set comes first, while nothing private exists: a run killed
//! there leaves only what the harness sweeps by key (`crate::owned`).

use super::owned::Owned;
use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::owned;
use crate::probe::{Key, Probe, SemArg, Window, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

/// `SEMVMX`: the largest semaphore value.
const SEMVMX: i32 = 32767;
/// Far past any host's `SEMOPM` (32 by default, 500 on most distributions).
const TOO_MANY_OPS: usize = 1 << 20;
const NOWAIT: i16 = IPC_NOWAIT as i16;
/// A command `semctl` does not define (the IPC commands end at 20,
/// `SEM_STAT_ANY`).
const UNKNOWN_CMD: i32 = 99;
/// How long the helper thread waits for the main thread to block.
const BLOCK_DEADLINE: Duration = Duration::from_secs(10);

/// Wait (unrecorded) until `id`'s semaphore `num` has a waiter of `cmd`
/// (`GETNCNT`/`GETZCNT`), or the deadline passes.
fn await_waiter(p: &Probe, id: i32, num: i32, cmd: i32) -> bool {
    let deadline = Instant::now() + BLOCK_DEADLINE;
    while Instant::now() < deadline {
        let count = p.call_unrecorded(
            Syscall::N_semctl,
            [id as i64, num as i64, cmd as i64, 0, 0, 0],
        );
        if count > 0 {
            return true;
        }
        if count < 0 {
            return false;
        }
        std::thread::yield_now();
    }
    false
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;

    // ---- keys ----
    let key = p.owned_key(owned::SEM_PROJECT, "ftok(run,'E')");
    let kid = p.semget(key, 2, IPC_CREAT | IPC_EXCL | 0o600);
    p.require("create the keyed set", kid >= 0);
    let keyed = Owned::sysv(Syscall::N_semctl, kid);
    p.check(
        "IPC_CREAT|IPC_EXCL on a taken key is EEXIST",
        i64::from(p.semget(key, 2, IPC_CREAT | IPC_EXCL | 0o600)) == neg(EEXIST),
    );
    p.check("the key names the set", p.semget(key, 0, 0) == kid);
    p.check(
        "more semaphores than the set has is EINVAL",
        i64::from(p.semget(key, 3, 0)) == neg(EINVAL),
    );
    let removed = p.semctl(kid, 0, IPC_RMID, &SemArg::None).0;
    p.check("IPC_RMID", removed == 0);
    keyed.removed(removed);
    p.check(
        "a key nobody took is ENOENT",
        i64::from(p.semget(key, 0, 0)) == neg(ENOENT),
    );
    // ---- values ----
    let from = p.realtime_seconds();
    let id = p.semget(Key::PRIVATE, 3, IPC_CREAT | 0o600);
    p.require("create a set of three", id >= 0);
    let set = Owned::sysv(Syscall::N_semctl, id);
    let (r, values) = p.semctl(id, 0, GETALL, &SemArg::GetAll(3));
    p.check("a new set's values are 0", r == 0 && values == [0, 0, 0]);
    p.check("SETVAL", p.semctl(id, 1, SETVAL, &SemArg::Val(5)).0 == 0);
    p.check(
        "GETVAL reads it",
        p.semctl(id, 1, GETVAL, &SemArg::None).0 == 5,
    );
    p.check(
        "SETALL",
        p.semctl(id, 0, SETALL, &SemArg::SetAll(vec![1, 2, 3])).0 == 0,
    );
    let (r, values) = p.semctl(id, 0, GETALL, &SemArg::GetAll(3));
    p.check("GETALL reads them", r == 0 && values == [1, 2, 3]);
    p.check(
        "a value past SEMVMX is ERANGE",
        p.semctl(id, 0, SETVAL, &SemArg::Val(SEMVMX + 1)).0 == neg(ERANGE),
    );
    p.check(
        "a negative value is ERANGE",
        p.semctl(id, 0, SETVAL, &SemArg::Val(-1)).0 == neg(ERANGE),
    );
    p.check(
        "an unknown command is EINVAL",
        p.semctl(id, 0, UNKNOWN_CMD, &SemArg::None).0 == neg(EINVAL),
    );
    // Creation and every SETVAL/SETALL since stamp `sem_ctime`.
    let changed = Window {
        from,
        to: p.realtime_seconds(),
    };
    let (r, ds) = p.semctl_stat(id);
    p.check(
        "IPC_STAT: three semaphores, the mode, never operated on, changed since creation",
        r == 0
            && ds.is_some_and(|ds| {
                ds.sem_nsems == 3
                    && u32::from(ds.sem_perm.mode) & 0o777 == 0o600
                    && ds.sem_otime == 0
                    && changed.holds(ds.sem_ctime)
            }),
    );
    p.check(
        "IPC_SET changes the mode",
        p.semctl(id, 0, IPC_SET, &SemArg::SetMode(0o640)).0 == 0,
    );
    let (r, ds) = p.semctl_stat(id);
    p.check(
        "IPC_STAT shows it",
        r == 0 && ds.is_some_and(|ds| u32::from(ds.sem_perm.mode) & 0o777 == 0o640),
    );

    // ---- semop ----
    let (applied, operated) = p.stamped(|| p.semop(id, &[(0, 1, 0), (1, -2, 0)], None));
    p.check("decrements and increments apply together", applied == 0);
    let (r, values) = p.semctl(id, 0, GETALL, &SemArg::GetAll(3));
    p.check("to every semaphore", r == 0 && values == [2, 0, 3]);
    let (r, ds) = p.semctl_stat(id);
    p.check(
        "IPC_STAT: stamped at the operation",
        r == 0 && ds.is_some_and(|ds| operated.holds(ds.sem_otime)),
    );
    p.check(
        "GETPID names this process",
        p.semctl(id, 0, GETPID, &SemArg::None).0 == i64::from(pid),
    );
    p.check(
        "a decrement below 0 with IPC_NOWAIT is EAGAIN",
        p.semop(id, &[(0, -1, NOWAIT), (1, -1, NOWAIT)], None) == neg(EAGAIN),
    );
    p.check(
        "wait-for-zero on a nonzero value with IPC_NOWAIT is EAGAIN",
        p.semop(id, &[(2, 0, NOWAIT)], None) == neg(EAGAIN),
    );
    let (r, values) = p.semctl(id, 0, GETALL, &SemArg::GetAll(3));
    p.check(
        "a failed semop changes nothing",
        r == 0 && values == [2, 0, 3],
    );
    p.check(
        "wait-for-zero on a zero value succeeds at once",
        p.semop(id, &[(1, 0, 0)], None) == 0,
    );
    p.check(
        "an increment past SEMVMX is ERANGE",
        p.semop(id, &[(0, SEMVMX as i16, 0)], None) == neg(ERANGE),
    );
    p.check(
        "a semaphore number past the set is EFBIG",
        p.semop(id, &[(3, 1, 0)], None) == neg(EFBIG),
    );
    p.check(
        "no operation is EINVAL",
        p.semop(id, &[], Some(0)) == neg(EINVAL),
    );
    p.check(
        "more operations than SEMOPM is E2BIG",
        p.semop(id, &[], Some(TOO_MANY_OPS)) == neg(E2BIG),
    );

    // ---- timeouts and waiters ----
    p.check(
        "semtimedop blocks until its timeout, then EAGAIN",
        p.semtimedop(id, &[(1, -1, 0)], Some((0, 10_000_000))) == neg(EAGAIN),
    );
    p.check(
        "an invalid timeout is EINVAL, judged before the operation",
        p.semtimedop(id, &[(0, -1, 0)], Some((0, 1_000_000_000))) == neg(EINVAL),
    );
    p.check(
        "a timeout that need not be waited",
        p.semtimedop(id, &[(0, -1, 0)], Some((0, 10_000_000))) == 0,
    );
    let (r, values) = p.semctl(id, 0, GETALL, &SemArg::GetAll(3));
    p.check("was not", r == 0 && values == [1, 0, 3]);
    let waiters = AtomicI64::new(-1);
    let woken = std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec.quiet(|| {
                if await_waiter(p, id, 1, GETNCNT) {
                    waiters.store(
                        p.call_unrecorded(
                            Syscall::N_semctl,
                            [id as i64, 1, GETNCNT as i64, 0, 0, 0],
                        ),
                        Ordering::SeqCst,
                    );
                    let ops = [sembuf {
                        sem_num: 1,
                        sem_op: 1,
                        sem_flg: 0,
                    }];
                    p.call_unrecorded(
                        Syscall::N_semop,
                        [id as i64, ops.as_ptr() as i64, 1, 0, 0, 0],
                    );
                }
            });
        });
        p.semop(id, &[(1, -1, 0)], None)
    });
    p.check(
        "a blocked decrement completes when another thread increments",
        woken == 0,
    );
    p.check(
        "GETNCNT counted the blocked thread",
        waiters.load(Ordering::SeqCst) == 1,
    );
    p.check(
        "GETNCNT is 0 again",
        p.semctl(id, 1, GETNCNT, &SemArg::None).0 == 0,
    );
    p.check(
        "GETZCNT is 0",
        p.semctl(id, 2, GETZCNT, &SemArg::None).0 == 0,
    );
    let removed = AtomicI64::new(-1);
    let idrm = std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec.quiet(|| {
                if await_waiter(p, id, 2, GETZCNT) {
                    removed.store(
                        p.call_unrecorded(
                            Syscall::N_semctl,
                            [id as i64, 0, IPC_RMID as i64, 0, 0, 0],
                        ),
                        Ordering::SeqCst,
                    );
                }
            });
        });
        p.semop(id, &[(2, 0, 0)], None)
    });
    set.removed(removed.load(Ordering::SeqCst));
    p.check(
        "removing the set wakes its waiter with EIDRM",
        removed.load(Ordering::SeqCst) == 0 && idrm == neg(EIDRM),
    );
    p.check(
        "a removed id is EINVAL",
        p.semop(id, &[(0, 1, 0)], None) == neg(EINVAL)
            && p.semctl(id, 0, GETVAL, &SemArg::None).0 == neg(EINVAL),
    );

    p.check(
        "a set of 0 semaphores is EINVAL",
        i64::from(p.semget(Key::PRIVATE, 0, IPC_CREAT | 0o600)) == neg(EINVAL),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "ipc/sysv_sem",
    run,
    covers: &[
        Syscall::N_semget,
        Syscall::N_semop,
        Syscall::N_semtimedop,
        Syscall::N_semctl,
    ],
    symbols: &["syscall", "getpid"],
    needs: &[Need::SysvSem],
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::ALL,
        what: "semget is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no semget wrapper)",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall semget (nr",
        },
    }],
    ..DEFAULTS
};
