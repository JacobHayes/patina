//! ipc/sysv_shm — System V shared memory within one process (man 2 shmget,
//! shmat, shmdt, shmctl; ipc/shm.c):
//!
//! * a segment is exactly the size asked (`shm_segsz`) and zero-filled;
//!   size 0 is `EINVAL`; `IPC_STAT` reports the mode, the creator, the
//!   attach count, the last attacher and which times are set;
//! * two attachments are two views of the same bytes; `SHM_RDONLY` attaches
//!   read-only; a misaligned address without `SHM_RND` is `EINVAL`; an
//!   attachment can be placed at a chosen free address; `shmdt` of an
//!   address that is not an attachment is `EINVAL`;
//! * `IPC_SET` changes the mode; an unknown command is `EINVAL`;
//! * a key names one segment: `IPC_CREAT|IPC_EXCL` on a taken key is
//!   `EEXIST`, a larger size than the segment's `EINVAL`, a key nobody took
//!   `ENOENT`;
//! * `IPC_RMID` of an attached segment marks it `SHM_DEST` and frees its key
//!   at once (the key is then `ENOENT`, `IPC_STAT` shows it private), the
//!   bytes live on, Linux still lets it be attached, and the last detach
//!   destroys it (its id is then `EINVAL`).
//!
//! Keys are `ftok(3)` of the run directory; every segment is removed on
//! every path.
//!
//! The keyed segment comes first, while nothing private exists: a run killed
//! there leaves only what the harness sweeps by key (`crate::owned`).

use super::owned::Owned;
use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::owned;
use crate::probe::{At, Key, Probe, ShmArg, neg, page_size, perm_mode};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `SHM_DEST` (uapi/linux/shm.h): marked for destruction.
const SHM_DEST: u32 = 0o1000;
/// A command `shmctl` does not define (the IPC commands end at 20,
/// `SEM_STAT_ANY`).
const UNKNOWN_CMD: i32 = 99;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let pid = p.getpid() as i32;
    let size = page + 1;

    // ---- a keyed segment ----
    let key = p.owned_key(owned::SHM_PROJECT, "ftok(run,'S')");
    let kid = p.shmget(key, page, IPC_CREAT | IPC_EXCL | 0o600);
    p.require("create the keyed segment", kid >= 0);
    let keyed = Owned::sysv(Syscall::N_shmctl, kid);
    p.check(
        "IPC_CREAT|IPC_EXCL on a taken key is EEXIST",
        i64::from(p.shmget(key, page, IPC_CREAT | IPC_EXCL | 0o600)) == neg(EEXIST),
    );
    p.check("the key names the segment", p.shmget(key, 0, 0) == kid);
    p.check(
        "a size past the segment's is EINVAL",
        i64::from(p.shmget(key, 2 * page, 0)) == neg(EINVAL),
    );
    let (r, k) = p.shmat("k", kid, page, &null, 0);
    p.require("attach the keyed segment", r >= 0);
    let k = k.unwrap();
    k.fill(0, b"kept");
    let removed = p.shmctl(kid, IPC_RMID, ShmArg::None).0;
    p.check("IPC_RMID of an attached segment succeeds", removed == 0);
    let (r, ds) = p.shmctl(kid, IPC_STAT, ShmArg::Stat);
    p.check(
        "it is marked SHM_DEST, its key gone, still attached",
        r == 0
            && ds.is_some_and(|ds| {
                perm_mode(&ds.shm_perm) & SHM_DEST == SHM_DEST
                    && ds.shm_perm.__key == IPC_PRIVATE
                    && ds.shm_nattch == 1
            }),
    );
    p.check(
        "its key names nothing",
        i64::from(p.shmget(key, 0, 0)) == neg(ENOENT),
    );
    p.check("its bytes live on", k.bytes(0, 4) == b"kept");
    let (r, again) = p.shmat("a", kid, page, &null, 0);
    p.check(
        "Linux still attaches a segment marked for destruction",
        r >= 0 && again.is_some_and(|again| again.bytes(0, 4) == b"kept"),
    );
    if let Some(again) = again {
        p.check("detach that", p.shmdt(&again.at(0)) == 0);
    }
    p.check("the last detach", p.shmdt(&k.at(0)) == 0);
    let gone = p.shmctl(kid, IPC_STAT, ShmArg::Stat).0;
    p.check("destroys it: its id is EINVAL", gone == neg(EINVAL));
    keyed.removed(if gone == neg(EINVAL) { 0 } else { removed });
    p.check(
        "a key nobody took is ENOENT",
        i64::from(p.shmget(key, 0, 0)) == neg(ENOENT),
    );

    // ---- a private segment ----
    let (id, created) = p.stamped(|| p.shmget(Key::PRIVATE, size, IPC_CREAT | 0o600));
    p.require("create a private segment", id >= 0);
    let private = Owned::sysv(Syscall::N_shmctl, id);
    let (r, ds) = p.shmctl(id, IPC_STAT, ShmArg::Stat);
    p.check(
        "IPC_STAT: the size asked, the mode, never attached or detached, changed at creation",
        r == 0
            && ds.is_some_and(|ds| {
                ds.shm_segsz == size
                    && perm_mode(&ds.shm_perm) & 0o777 == 0o600
                    && ds.shm_nattch == 0
                    && ds.shm_cpid == pid
                    && ds.shm_lpid == 0
                    && ds.shm_atime == 0
                    && ds.shm_dtime == 0
                    && created.holds(ds.shm_ctime)
            }),
    );
    let (r, x) = p.shmat("x", id, size, &null, 0);
    p.require("attach it", r >= 0);
    let x = x.unwrap();
    p.check("a new segment is zero-filled", x.zeroed(0, size));
    let ((r, y), attached) = p.stamped(|| p.shmat("y", id, size, &null, 0));
    p.require("attach it again", r >= 0);
    let y = y.unwrap();
    x.fill(0, b"shared");
    y.store(size - 1, b'!');
    p.check(
        "two attachments are two views of the same bytes",
        x.base != y.base && y.bytes(0, 6) == b"shared" && x.load(size - 1) == b'!',
    );
    let (r, ds) = p.shmctl(id, IPC_STAT, ShmArg::Stat);
    p.check(
        "IPC_STAT: two attachments, this process attached last, at the last attach",
        r == 0
            && ds.is_some_and(|ds| {
                ds.shm_nattch == 2
                    && ds.shm_lpid == pid
                    && attached.holds(ds.shm_atime)
                    && ds.shm_dtime == 0
            }),
    );
    let (r, reader) = p.shmat("r", id, size, &null, SHM_RDONLY);
    p.check(
        "SHM_RDONLY attaches a read-only view",
        r >= 0 && reader.is_some_and(|reader| reader.bytes(0, 6) == b"shared"),
    );
    if let Some(reader) = reader {
        p.check("detach it", p.shmdt(&reader.at(0)) == 0);
    }
    p.check(
        "a misaligned address without SHM_RND is EINVAL",
        p.shmat("-", id, size, &y.at(1), 0).0 == neg(EINVAL),
    );
    p.check(
        "shmdt of an address inside an attachment is EINVAL",
        p.shmdt(&y.at(1)) == neg(EINVAL),
    );
    let (detached, dropped) = p.stamped(|| p.shmdt(&y.at(0)));
    p.check("detach the second view", detached == 0);
    let (r, placed) = p.shmat("z", id, size, &y.at(0), 0);
    p.check(
        "an attachment lands on a chosen free address",
        r >= 0 && placed.is_some_and(|placed| placed.base == y.base && placed.load(0) == b's'),
    );
    p.check(
        "shmdt of an address that is not an attachment is EINVAL",
        p.shmdt(&x.at(page)) == neg(EINVAL),
    );
    let (r, ds) = p.shmctl(id, IPC_STAT, ShmArg::Stat);
    p.check(
        "IPC_STAT: stamped at the last detach",
        r == 0 && ds.is_some_and(|ds| ds.shm_nattch == 2 && dropped.holds(ds.shm_dtime)),
    );
    p.check(
        "IPC_SET changes the mode",
        p.shmctl(id, IPC_SET, ShmArg::SetMode(0o640)).0 == 0,
    );
    let (r, ds) = p.shmctl(id, IPC_STAT, ShmArg::Stat);
    p.check(
        "IPC_STAT shows it",
        r == 0 && ds.is_some_and(|ds| perm_mode(&ds.shm_perm) & 0o777 == 0o640),
    );
    p.check(
        "an unknown command is EINVAL",
        p.shmctl(id, UNKNOWN_CMD, ShmArg::None).0 == neg(EINVAL),
    );
    p.check(
        "size 0 is EINVAL",
        i64::from(p.shmget(Key::PRIVATE, 0, IPC_CREAT | 0o600)) == neg(EINVAL),
    );

    // ---- removal of the private segment ----
    let removed = p.shmctl(id, IPC_RMID, ShmArg::None).0;
    p.check("IPC_RMID of the private segment", removed == 0);
    p.check("detach the first view", p.shmdt(&x.at(0)) == 0);
    p.check("detach the placed view", p.shmdt(&y.at(0)) == 0);
    let gone = p.shmctl(id, IPC_STAT, ShmArg::Stat).0;
    p.check("it is destroyed", gone == neg(EINVAL));
    private.removed(if gone == neg(EINVAL) { 0 } else { removed });
    p.check(
        "IPC_RMID of a destroyed id is EINVAL",
        p.shmctl(id, IPC_RMID, ShmArg::None).0 == neg(EINVAL),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "ipc/sysv_shm",
    run,
    covers: &[
        Syscall::N_shmget,
        Syscall::N_shmat,
        Syscall::N_shmdt,
        Syscall::N_shmctl,
    ],
    symbols: &["syscall", "getpid"],
    needs: &[Need::SysvShm],
    ..DEFAULTS
};
