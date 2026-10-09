//! System V IPC — shared memory, semaphores, message queues — for the one
//! virtual process and its threads: cross-process IPC with single-process
//! semantics, the kernel's (ipc/shm.c, ipc/sem.c, ipc/msg.c, ipc/util.c)
//! refusals in the kernel's order, one IPC namespace per run.
//!
//! Each kind has its own id space, allocated as `ipc_idr_alloc` does (a
//! cyclic index with a sequence number that moves when the index wraps), so a
//! removed id is `EINVAL` from then on. The virtual kernel's limits are its
//! declared configuration's (`registry::KERNEL_CONFIG`: `kernel.shmmni`,
//! `kernel.sem`, `kernel.msgmax`, …); the one identity owns every object it
//! creates, so a permission check reads the owner triad. Times are the
//! virtual realtime clock's seconds, pids the virtual process's.
//!
//! A segment's pages are a shared anonymous object the shim holds, and an
//! attachment is a view of it (`crate::mem`): the address-space rows keep the
//! attachments in step with `munmap`/`mremap`, and a segment's `shm_nattch` is
//! its view count. A task that has to wait (a semaphore operation, a full or
//! empty message queue) parks on the object's queue through the scheduler; the
//! task that makes its operation possible completes it for it, as the
//! kernel's `update_queue` and `pipelined_send` do, and `IPC_RMID` wakes every
//! waiter with `EIDRM`. A wait is never restarted after a signal handler runs
//! (`EINTR`, man 7 signal).
//!
//! POSIX message queues (ipc/mqueue.c) live in the same namespace: a queue is
//! named without its leading slash (the kernel row's spelling), its
//! descriptors are `FdKind::MessageQueue` descriptions (close-on-exec, with
//! the access mode and `O_NONBLOCK` of the open), and it lives until it is
//! unlinked and its last description is closed. Messages leave highest
//! priority first; a receiver or sender that has to wait parks on the
//! scheduler until the absolute `CLOCK_REALTIME` deadline, and is restarted
//! after a `SA_RESTART` handler. `mq_notify` registers the process once; a
//! message arriving on an empty queue with no receiver waiting sends its
//! signal (`SI_MESGQ`) through the signal model and consumes the
//! registration.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::mem::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::registry::KERNEL_CONFIG;
use crate::{E2BIG, EEXIST, EFAULT, EFBIG, EINTR, ENOENT, ERANGE};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i32 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
/// The commands a kernel answers with namespace-wide tables (`IPC_INFO`,
/// `SHM_INFO`, `*_STAT`, `*_STAT_ANY`) or page locking (`SHM_LOCK`,
/// `SHM_UNLOCK`): named refusals, not wrong answers.
const IPC_INFO: i32 = 3;
const SHM_LOCK: i32 = 11;
const SHM_UNLOCK: i32 = 12;
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;
const SHM_STAT_ANY: i32 = 15;
const SEM_STAT: i32 = 18;
const SEM_INFO: i32 = 19;
const SEM_STAT_ANY: i32 = 20;
const MSG_STAT: i32 = 11;
const MSG_INFO: i32 = 12;
const MSG_STAT_ANY: i32 = 13;
const DENY_TABLES: &str = "patina: System V IPC namespace tables (IPC_INFO, *_INFO, *_STAT, \
    *_STAT_ANY) and SHM_LOCK/SHM_UNLOCK are not modeled; failing closed\n";

const S_IRWXUGO: u32 = 0o777;
const S_IRUGO: u32 = 0o444;
const S_IWUGO: u32 = 0o222;
const S_IXUGO: u32 = 0o111;

/// `IPCMNI_SHIFT`: an id is `seq << 15 | index`.
const IPCMNI_SHIFT: u32 = 15;
const IPCMNI: i32 = 1 << IPCMNI_SHIFT;
/// `ipc_min_cycle` (`RADIX_TREE_MAP_SIZE`): the least window ids cycle in.
const IPC_MIN_CYCLE: i32 = 64;
/// `ipcid_seq_max()`.
const SEQ_MAX: i32 = i32::MAX >> IPCMNI_SHIFT;

const SHMMNI: i32 = KERNEL_CONFIG.shmmni;
const SHMMAX: usize = KERNEL_CONFIG.shmmax as usize;
const SHM_HUGETLB: i32 = 0o4000;
const SHM_HUGE_SHIFT: i32 = 26;
const SHM_HUGE_MASK: u32 = 0x3f;
const SHM_RDONLY: i32 = 0o10000;
const SHM_RND: i32 = 0o20000;
const SHM_REMAP: i32 = 0o40000;
const SHM_EXEC: i32 = 0o100000;
/// `shm_perm.mode`'s "marked for destruction" bit.
const SHM_DEST: u32 = 0o1000;
/// `SHMLBA`: the page, on both architectures.
const SHMLBA: usize = crate::mem::PAGE;

const SEMMNI: i32 = KERNEL_CONFIG.semmni;
const SEMMSL: i32 = KERNEL_CONFIG.semmsl;
const SEMOPM: usize = KERNEL_CONFIG.semopm as usize;
const SEMVMX: i32 = 32767;
const SEMAEM: i32 = SEMVMX;
const SEM_UNDO: i16 = 0x1000;
const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;

const MSGMNI: i32 = KERNEL_CONFIG.msgmni;
const MSGMAX: usize = KERNEL_CONFIG.msgmax as usize;
const MSGMNB: usize = KERNEL_CONFIG.msgmnb as usize;
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;
const MSG_COPY: i32 = 0o40000;

const EIDRM: c_int = 43;
const ENOMSG: c_int = 42;
const EACCES: c_int = 13;
const ENOSPC: c_int = 28;
const ENOSYS: c_int = crate::ENOSYS;
const EAGAIN: c_int = EWOULDBLOCK;

fn fail(errno: c_int) -> i64 {
    -i64::from(errno)
}

/// `struct ipc64_perm` (asm-generic/ipcbuf.h). `mode` is a `u32` on arm64
/// and a `u16` plus padding on x86_64; both little-endian layouts agree.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct IpcPerm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    seq: u16,
    pad: u16,
    pad2: u32,
    unused: [u64; 2],
}

/// `struct shmid64_ds` (asm-generic/shmbuf.h, 64-bit).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ShmidDs {
    perm: IpcPerm,
    segsz: u64,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: i32,
    lpid: i32,
    nattch: u64,
    unused: [u64; 2],
}

/// `struct semid64_ds`: x86_64 pads each time (arch/x86 sembuf.h).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SemidDs {
    perm: IpcPerm,
    otime: i64,
    otime_pad: u64,
    ctime: i64,
    ctime_pad: u64,
    nsems: u64,
    unused: [u64; 2],
}

/// `struct semid64_ds` (asm-generic/sembuf.h, 64-bit).
#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SemidDs {
    perm: IpcPerm,
    otime: i64,
    ctime: i64,
    nsems: u64,
    unused: [u64; 2],
}

/// `struct msqid64_ds` (64-bit).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MsqidDs {
    perm: IpcPerm,
    stime: i64,
    rtime: i64,
    ctime: i64,
    cbytes: u64,
    qnum: u64,
    qbytes: u64,
    lspid: i32,
    lrpid: i32,
    unused: [u64; 2],
}

/// `struct sembuf`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sembuf {
    num: u16,
    op: i16,
    flg: i16,
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::Sembuf {
        num: u16,
        op: i16,
        flg: i16,
    });
    crate::plain!(super::IpcPerm {
        key: i32,
        uid: u32,
        gid: u32,
        cuid: u32,
        cgid: u32,
        mode: u32,
        seq: u16,
        pad: u16,
        pad2: u32,
        unused: [u64; 2],
    });
    crate::plain!(super::ShmidDs {
        perm: super::IpcPerm,
        segsz: u64,
        atime: i64,
        dtime: i64,
        ctime: i64,
        cpid: i32,
        lpid: i32,
        nattch: u64,
        unused: [u64; 2],
    });
    #[cfg(target_arch = "x86_64")]
    crate::plain!(super::SemidDs {
        perm: super::IpcPerm,
        otime: i64,
        otime_pad: u64,
        ctime: i64,
        ctime_pad: u64,
        nsems: u64,
        unused: [u64; 2],
    });
    #[cfg(not(target_arch = "x86_64"))]
    crate::plain!(super::SemidDs {
        perm: super::IpcPerm,
        otime: i64,
        ctime: i64,
        nsems: u64,
        unused: [u64; 2],
    });
    crate::plain!(super::MsqidDs {
        perm: super::IpcPerm,
        stime: i64,
        rtime: i64,
        ctime: i64,
        cbytes: u64,
        qnum: u64,
        qbytes: u64,
        lspid: i32,
        lrpid: i32,
        unused: [u64; 2],
    });
}

/// An object's `kern_ipc_perm`: its key, owner, mode (with the kind's status
/// bits, such as `SHM_DEST`) and sequence number.
#[derive(Clone, Copy)]
struct Perm {
    key: i32,
    uid: u32,
    gid: u32,
    mode: u32,
    seq: u16,
}

impl Perm {
    fn new(key: i32, flags: i32) -> Self {
        Perm {
            key,
            uid: crate::identity::credential().uid,
            gid: crate::identity::credential().gid,
            mode: flags as u32 & S_IRWXUGO,
            seq: 0,
        }
    }

    /// `ipcperms`: the one identity created every object, so it is judged by
    /// the owner triad.
    fn allows(&self, requested: u32) -> bool {
        let requested = (requested >> 6) | (requested >> 3) | requested;
        let granted = self.mode >> 6;
        requested & !granted & 0o7 == 0
    }

    fn stat(&self) -> IpcPerm {
        IpcPerm {
            key: self.key,
            uid: self.uid,
            gid: self.gid,
            cuid: crate::identity::credential().uid,
            cgid: crate::identity::credential().gid,
            mode: self.mode,
            seq: self.seq,
            ..IpcPerm::default()
        }
    }

    /// `ipc_update_perm`: the owner and the permission bits, `EINVAL` for an
    /// id that names nobody (`-1`).
    fn update(&mut self, from: &IpcPerm) -> Result<(), c_int> {
        if from.uid == u32::MAX || from.gid == u32::MAX {
            return Err(EINVAL);
        }
        self.uid = from.uid;
        self.gid = from.gid;
        self.mode = (self.mode & !S_IRWXUGO) | (from.mode & S_IRWXUGO);
        Ok(())
    }
}

/// One kind's objects, keyed by index, allocated as `ipc_idr_alloc` does.
struct Space<T> {
    objects: BTreeMap<i32, (Perm, T)>,
    seq: i32,
    last: i32,
    limit: i32,
}

impl<T> Space<T> {
    const fn new(limit: i32) -> Self {
        Space {
            objects: BTreeMap::new(),
            seq: 0,
            last: -1,
            limit,
        }
    }

    fn id(perm: &Perm, index: i32) -> i32 {
        (i32::from(perm.seq) << IPCMNI_SHIFT) + index
    }

    /// The id of the object `key` names.
    fn keyed(&self, key: i32) -> Option<i32> {
        self.objects
            .iter()
            .find(|(_, (perm, _))| perm.key == key)
            .map(|(index, (perm, _))| Self::id(perm, *index))
    }

    /// `ipc_obtain_object_check`: `EINVAL` for an id no live object has.
    fn get(&self, id: i32) -> Result<&(Perm, T), c_int> {
        if id < 0 {
            return Err(EINVAL);
        }
        self.objects
            .get(&(id % IPCMNI))
            .filter(|(perm, _)| Self::id(perm, id % IPCMNI) == id)
            .ok_or(EINVAL)
    }

    fn get_mut(&mut self, id: i32) -> Result<&mut (Perm, T), c_int> {
        if id < 0 {
            return Err(EINVAL);
        }
        self.objects
            .get_mut(&(id % IPCMNI))
            .filter(|(perm, _)| Self::id(perm, id % IPCMNI) == id)
            .ok_or(EINVAL)
    }

    fn remove(&mut self, id: i32) -> Option<(Perm, T)> {
        self.get(id).ok()?;
        self.objects.remove(&(id % IPCMNI))
    }

    /// `ipc_addid`/`ipc_idr_alloc`: the next free index after the last one
    /// handed out, cycling within `max(3/2 × in use, 64)` (`ipc_min_cycle`,
    /// capped at the kind's limit), with the sequence moved on a wrap;
    /// `ENOSPC` at the limit.
    fn add(&mut self, mut perm: Perm, value: T) -> Result<i32, c_int> {
        let in_use = self.objects.len() as i32;
        if in_use >= self.limit {
            return Err(ENOSPC);
        }
        let window = (in_use * 3 / 2).max(IPC_MIN_CYCLE).min(self.limit);
        let free = |index: &i32| !self.objects.contains_key(index);
        let index = (self.last + 1..window)
            .find(free)
            .or_else(|| (0..window).find(free))
            .ok_or(ENOSPC)?;
        if index <= self.last {
            self.seq += 1;
            if self.seq >= SEQ_MAX {
                self.seq = 0;
            }
        }
        self.last = index;
        perm.seq = self.seq as u16;
        let id = Self::id(&perm, index);
        self.objects.insert(index, (perm, value));
        Ok(id)
    }
}

/// The virtual realtime clock's seconds.
fn now() -> i64 {
    with_context_raw(|context| context.fs_time_unrecorded())
        .map(|nanos| (nanos / 1_000_000_000) as i64)
        .unwrap_or(0)
}

/// The caller's pid, which the IPC objects record as their last user.
fn pid() -> i32 {
    crate::patina_pid()
}

/// Where a task waits on an IPC object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::thread) enum IpcWait {
    Sem(i32),
    MsgSend(i32),
    MsgRecv(i32),
    /// A blocked `mq_timedsend`/`mq_timedreceive` on a message queue.
    MqSend(u64),
    MqRecv(u64),
    /// A readiness reactor watching a message queue.
    MqWritable(u64),
    MqReadable(u64),
}

struct Segment {
    /// The segment's pages.
    pages: crate::mem::Segment,
    size: usize,
    atime: i64,
    dtime: i64,
    ctime: i64,
    lpid: i32,
}

struct SemSet {
    /// Each semaphore's value and the last process to operate on it.
    sems: Vec<(i32, i32)>,
    /// The process's `SEM_UNDO` adjustments.
    adjust: Vec<i32>,
    /// Whether the process holds an undo entry for the set: a `SEM_UNDO`
    /// operation got past the set's lookup (`find_alloc_undo`).
    undo: bool,
    otime: i64,
    ctime: i64,
    /// Blocked operations, oldest first.
    pending: WaitQueue<VecDeque<SemWaiter>>,
}

struct SemWaiter {
    task: TaskId,
    ops: Vec<Sembuf>,
    /// The operation that could not proceed (`q->blocking`), what
    /// `GETNCNT`/`GETZCNT` count.
    blocking: usize,
    alter: bool,
}

struct Message {
    mtype: i64,
    text: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Search {
    Any,
    Equal,
    NotEqual,
    LessEqual,
}

impl Search {
    fn test(self, mtype: i64, wanted: i64) -> bool {
        match self {
            Search::Any => true,
            Search::Equal => mtype == wanted,
            Search::NotEqual => mtype != wanted,
            Search::LessEqual => mtype <= wanted,
        }
    }
}

struct Receiver {
    task: TaskId,
    wanted: i64,
    mode: Search,
    max: usize,
}

struct MsgQueue {
    messages: VecDeque<Message>,
    cbytes: usize,
    qbytes: usize,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: i32,
    lrpid: i32,
    receivers: WaitQueue<VecDeque<Receiver>>,
    senders: WaitQueue<VecDeque<TaskId>>,
}

impl MsgQueue {
    /// `msg_fits_inqueue`.
    fn fits(&self, size: usize) -> bool {
        size + self.cbytes <= self.qbytes && self.messages.len() < self.qbytes
    }

    /// `find_msg`: the first message the search selects; for `LessEqual` the
    /// first of the lowest type not above `wanted`.
    fn find(&self, wanted: i64, mode: Search) -> Option<usize> {
        let mut found: Option<usize> = None;
        let mut bound = wanted;
        for (index, message) in self.messages.iter().enumerate() {
            if mode.test(message.mtype, bound) {
                found = Some(index);
                if mode != Search::LessEqual || message.mtype == 1 {
                    break;
                }
                bound = message.mtype - 1;
            }
        }
        found
    }
}

/// What a waker decided for a parked task.
enum Outcome {
    /// The semaphore operation completed, or the wait ended with an errno.
    Done(i64),
    /// A message handed straight to a waiting receiver.
    Message(Message),
}

/// The run's IPC namespace.
pub(in crate::thread) struct Ipc {
    shm: Space<Segment>,
    sem: Space<SemSet>,
    msg: Space<MsgQueue>,
    outcomes: BTreeMap<TaskId, Outcome>,
    /// POSIX message queues by name, and every queue (named or unlinked but
    /// still open) by id.
    mq_names: BTreeMap<Vec<u8>, u64>,
    mqueues: BTreeMap<u64, Mqueue>,
    /// Open queue descriptions, by the handle their descriptor names.
    mq_opens: BTreeMap<u64, MqOpen>,
    next_mq: u64,
    /// The bytes the queues hold against `RLIMIT_MSGQUEUE`.
    mq_bytes: u64,
}

impl Default for Ipc {
    fn default() -> Self {
        Ipc {
            shm: Space::new(SHMMNI),
            sem: Space::new(SEMMNI),
            msg: Space::new(MSGMNI),
            outcomes: BTreeMap::new(),
            mq_names: BTreeMap::new(),
            mqueues: BTreeMap::new(),
            mq_opens: BTreeMap::new(),
            next_mq: 1,
            mq_bytes: 0,
        }
    }
}

impl Ipc {
    /// Unlink `task` from the wait queue `wait` names (its wait ended some
    /// other way: a signal, a timeout).
    pub(in crate::thread) fn unwait(&mut self, wait: IpcWait, task: TaskId) {
        match wait {
            IpcWait::Sem(id) => {
                if let Ok((_, set)) = self.sem.get_mut(id) {
                    set.pending.retain(|waiter| waiter.task != task);
                }
            }
            IpcWait::MsgSend(id) => {
                if let Ok((_, queue)) = self.msg.get_mut(id) {
                    queue.senders.retain(|waiter| *waiter != task);
                }
            }
            IpcWait::MsgRecv(id) => {
                if let Ok((_, queue)) = self.msg.get_mut(id) {
                    queue.receivers.retain(|waiter| waiter.task != task);
                }
            }
            IpcWait::MqSend(queue) => {
                if let Some(queue) = self.mqueues.get_mut(&queue) {
                    queue.senders.retain(|sender| sender.task != task);
                }
            }
            IpcWait::MqRecv(queue) => {
                if let Some(queue) = self.mqueues.get_mut(&queue) {
                    queue.receivers.retain(|waiter| *waiter != task);
                }
            }
            IpcWait::MqWritable(queue) => {
                if let Some(queue) = self.mqueues.get_mut(&queue) {
                    queue.writable_watchers.retain(|waiter| *waiter != task);
                }
            }
            IpcWait::MqReadable(queue) => {
                if let Some(queue) = self.mqueues.get_mut(&queue) {
                    queue.readable_watchers.retain(|waiter| *waiter != task);
                }
            }
        }
    }
}

/// Park `me` on the IPC wait `loc` (until `deadline` on its clock, if any)
/// and settle how the wait ended: the outcome a waker left (`Ok(Some)`), a
/// wait to retry after a restartable handler or an ordinary wake (`Ok(None)`),
/// or the errno — `timeout` when the deadline passed, `EINTR` after a handler
/// that does not restart the call.
fn wait_on(
    state: StateGuard,
    me: TaskId,
    reason: &'static str,
    wait: Wait,
    loc: IpcWait,
    deadline: Option<(ClockKind, u64)>,
    timeout: c_int,
) -> Result<Option<Outcome>, i64> {
    let mut state = state;
    let step = match deadline {
        None => state.block(me, reason, wait),
        Some((clock, at)) => state.block_timed(me, reason, wait, clock, at),
    };
    match step {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return Err(fail(c_int::from(error.into_posix()))),
    }
    let resumed = signals::resume();
    let mut state = lock_state();
    if let Some(outcome) = state.ipc.outcomes.remove(&me) {
        return Ok(Some(outcome));
    }
    state.ipc.unwait(loc, me);
    if state.timed_out.remove(&me) {
        return Err(fail(timeout));
    }
    if resumed == signals::Resumed::Eintr {
        return Err(fail(EINTR));
    }
    Ok(None)
}

/// `IPC_RMID` of an object tasks wait on: each wakes to `EIDRM`.
fn removed(mut state: StateGuard, woken: Vec<TaskId>) -> i64 {
    for task in &woken {
        state.ipc.outcomes.insert(*task, Outcome::Done(fail(EIDRM)));
    }
    drop(state);
    wake_all(woken);
    0
}

/// `IPC_STAT`'s copy to the caller: `EFAULT` for NULL, else 0.
///
/// # Safety
/// `buf` must be NULL or valid for a `T` write.
unsafe fn copy_out<T: crate::plain::Plain>(buf: *mut T, stat: T) -> i64 {
    if buf.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { crate::plain::store(buf, stat) };
    0
}

/// `ipcget`: the object `key` names, or a new one. `create` builds it; `check`
/// is the kind's `more_checks` on an existing one.
fn get_or_create<T>(
    space: &mut Space<T>,
    key: i32,
    flags: i32,
    check: impl FnOnce(&T) -> Result<(), c_int>,
    create: impl FnOnce() -> Result<T, c_int>,
) -> Result<i32, c_int> {
    if key == IPC_PRIVATE {
        return space.add(Perm::new(key, flags), create()?);
    }
    match space.keyed(key) {
        None if flags & IPC_CREAT == 0 => Err(ENOENT),
        None => space.add(Perm::new(key, flags), create()?),
        Some(_) if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 => Err(EEXIST),
        Some(id) => {
            let (perm, object) = space.get(id)?;
            check(object)?;
            if !perm.allows(flags as u32 & S_IRWXUGO) {
                return Err(EACCES);
            }
            Ok(id)
        }
    }
}

fn answer(result: Result<i32, c_int>) -> i64 {
    match result {
        Ok(value) => i64::from(value),
        Err(errno) => fail(errno),
    }
}

/// Take the boundary's scheduling point, as every system call does.
fn boundary() -> Result<(), c_int> {
    sched_point()
}

mod messages;
mod mqueue;
mod semaphores;
mod shared_memory;

#[cfg(test)]
mod tests;

pub(crate) use messages::{msgctl, msgget, msgrcv, msgsnd};
use mqueue::{MqOpen, Mqueue};
pub(crate) use mqueue::{
    mq_close, mq_getsetattr, mq_mode, mq_notify, mq_open, mq_read, mq_seek, mq_timedreceive,
    mq_timedsend, mq_unlink, mq_unread,
};
pub(in crate::thread) use mqueue::{mq_event_seqs, mq_readiness, mq_watch};
#[cfg(test)]
use semaphores::Refused;
pub(crate) use semaphores::{exit_sem, semctl, semget, semtimedop};
#[cfg(test)]
use semaphores::{perform, update_queue};
pub(crate) use shared_memory::{shm_detached, shmat, shmctl, shmdt, shmget};
