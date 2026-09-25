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

use super::*;
use crate::mem::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::registry::{IDENTITY_PID, KERNEL_CONFIG};
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
    unused: [u64; 2],
}

/// `struct shmid64_ds` (asm-generic/shmbuf.h, 64-bit).
#[repr(C)]
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
pub(crate) struct SemidDs {
    perm: IpcPerm,
    otime: i64,
    ctime: i64,
    nsems: u64,
    unused: [u64; 2],
}

/// `struct msqid64_ds` (64-bit).
#[repr(C)]
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sembuf {
    num: u16,
    op: i16,
    flg: i16,
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

const PID: i32 = IDENTITY_PID as i32;

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
    pending: VecDeque<SemWaiter>,
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
    receivers: VecDeque<Receiver>,
    senders: VecDeque<TaskId>,
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
    state: SpinGuard<'static, ThreadRuntime>,
    me: TaskId,
    reason: &'static str,
    class: BlockClass,
    loc: IpcWait,
    deadline: Option<(ClockKind, u64)>,
    timeout: c_int,
) -> Result<Option<Outcome>, i64> {
    let mut state = state;
    let wait = Wait::new(class, vec![WaiterLoc::Ipc(loc)]);
    let step = match deadline {
        None => state.block(me, reason, wait),
        Some((clock, at)) => state.block_timed(me, reason, wait, clock, at),
    };
    match step {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return Err(fail(error.into_posix())),
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
fn removed(mut state: SpinGuard<'static, ThreadRuntime>, woken: Vec<TaskId>) -> i64 {
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
unsafe fn copy_out<T>(buf: *mut T, stat: T) -> i64 {
    if buf.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { buf.write(stat) };
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

// ---------------------------------------------------------------- shared memory

/// `shmget(2)`.
pub(crate) fn shmget(key: i32, size: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.shm,
        key,
        flags,
        |segment| {
            if segment.size < size {
                Err(EINVAL)
            } else {
                Ok(())
            }
        },
        || {
            if !(1..=SHMMAX).contains(&size) {
                return Err(EINVAL);
            }
            if flags & SHM_HUGETLB != 0 {
                // `newseg`: a pool the machine has, then `hugetlb_file_setup`,
                // which lets only `CAP_IPC_LOCK` or the `hugetlb_shm_group`
                // back a segment with huge pages — not the one identity.
                let sizelog = (flags >> SHM_HUGE_SHIFT) as u32 & SHM_HUGE_MASK;
                if crate::mem::huge_page_size(sizelog).is_none() {
                    return Err(EINVAL);
                }
                return Err(crate::EPERM);
            }
            let pages = crate::mem::Segment::new(size);
            Ok(Segment {
                pages,
                size,
                atime: 0,
                dtime: 0,
                ctime: now(),
                lpid: 0,
            })
        },
    );
    answer(result)
}

/// `shmat(2)`: the attachment's address, or `-errno`.
pub(crate) fn shmat(id: i32, addr: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 {
        return fail(EINVAL);
    }
    let mut addr = addr;
    if addr != 0 {
        if addr % SHMLBA != 0 {
            if flags & SHM_RND == 0 {
                return fail(EINVAL);
            }
            addr -= addr % SHMLBA;
            if addr == 0 && flags & SHM_REMAP != 0 {
                return fail(EINVAL);
            }
        }
    } else if flags & SHM_REMAP != 0 {
        return fail(EINVAL);
    }
    let (mut prot, mut access) = if flags & SHM_RDONLY != 0 {
        (PROT_READ, S_IRUGO)
    } else {
        (PROT_READ | PROT_WRITE, S_IRUGO | S_IWUGO)
    };
    if flags & SHM_EXEC != 0 {
        prot |= PROT_EXEC;
        access |= S_IXUGO;
    }
    let (fd, size) = {
        let state = lock_state();
        let (perm, segment) = match state.ipc.shm.get(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(access) {
            return fail(EACCES);
        }
        (segment.pages.fd(), segment.size)
    };
    let fixed = (addr != 0).then_some(addr);
    let attached = crate::mem::attach(id, fd, size, fixed, flags & SHM_REMAP != 0, prot);
    if attached >= 0 {
        let mut state = lock_state();
        if let Ok((_, segment)) = state.ipc.shm.get_mut(id) {
            segment.atime = now();
            segment.lpid = PID;
        }
    }
    attached
}

/// `shmdt(2)`.
pub(crate) fn shmdt(addr: usize) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if addr % crate::mem::PAGE != 0 {
        return fail(EINVAL);
    }
    let size_of = |id: i32| {
        lock_state()
            .ipc
            .shm
            .get(id)
            .ok()
            .map(|(_, segment)| segment.size)
    };
    match crate::mem::detach(addr, size_of) {
        Ok(_) => 0,
        Err(errno) => fail(errno),
    }
}

/// A view of segment `id` went away (`shm_close`): stamp the detach, and
/// destroy a segment marked for destruction once nothing attaches it.
pub(crate) fn shm_detached(id: i32) {
    let mut state = lock_state();
    let Ok((perm, segment)) = state.ipc.shm.get_mut(id) else {
        return;
    };
    segment.dtime = now();
    segment.lpid = PID;
    if perm.mode & SHM_DEST != 0 && crate::mem::attachments(id) == 0 {
        destroy_segment(&mut state, id);
    }
}

fn destroy_segment(state: &mut ThreadRuntime, id: i32) {
    // The segment's pages go with it.
    state.ipc.shm.remove(id);
}

/// `shmctl(2)`.
///
/// # Safety
/// `buf` must be NULL or valid for the command's `shmid_ds`.
pub(crate) unsafe fn shmctl(id: i32, cmd: i32, buf: *mut ShmidDs) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if cmd < 0 || id < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | SHM_INFO | SHM_STAT | SHM_STAT_ANY | SHM_LOCK | SHM_UNLOCK => {
            i64::from(crate::deny(DENY_TABLES))
        }
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, segment) = match state.ipc.shm.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                ShmidDs {
                    perm: perm.stat(),
                    segsz: segment.size as u64,
                    atime: segment.atime,
                    dtime: segment.dtime,
                    ctime: segment.ctime,
                    cpid: PID,
                    lpid: segment.lpid,
                    nattch: crate::mem::attachments(id) as u64,
                    unused: [0; 2],
                }
            };
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        IPC_SET | IPC_RMID => {
            let from = if cmd == IPC_SET {
                if buf.is_null() {
                    return fail(EFAULT);
                }
                // SAFETY: per this function's contract.
                Some(unsafe { (*buf).perm })
            } else {
                None
            };
            let mut state = lock_state();
            let (perm, segment) = match state.ipc.shm.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            match from {
                Some(from) => {
                    if let Err(errno) = perm.update(&from) {
                        return fail(errno);
                    }
                    segment.ctime = now();
                }
                None => {
                    // `do_shm_rmid`: the key goes at once; the segment lives
                    // while anything attaches it.
                    perm.key = IPC_PRIVATE;
                    perm.mode |= SHM_DEST;
                    if crate::mem::attachments(id) == 0 {
                        destroy_segment(&mut state, id);
                    }
                }
            }
            0
        }
        _ => fail(EINVAL),
    }
}

// ---------------------------------------------------------------- semaphores

/// `semget(2)`.
pub(crate) fn semget(key: i32, nsems: i32, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if !(0..=SEMMSL).contains(&nsems) {
        return fail(EINVAL);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.sem,
        key,
        flags,
        |set| {
            if (nsems as usize) > set.sems.len() {
                Err(EINVAL)
            } else {
                Ok(())
            }
        },
        || {
            if nsems == 0 {
                return Err(EINVAL);
            }
            Ok(SemSet {
                sems: vec![(0, 0); nsems as usize],
                adjust: vec![0; nsems as usize],
                undo: false,
                otime: 0,
                ctime: now(),
                pending: VecDeque::new(),
            })
        },
    );
    answer(result)
}

/// Why an operation vector did not complete.
enum Refused {
    /// Operation `index` has to wait.
    Block(usize),
    /// `-errno`: `EAGAIN` for `IPC_NOWAIT`, `ERANGE` past a limit.
    Errno(c_int),
}

/// `perform_atomic_semop_slow`: apply `ops` in order, all or none.
fn perform(set: &mut SemSet, ops: &[Sembuf]) -> Result<(), Refused> {
    let mut values: Vec<i32> = set.sems.iter().map(|(value, _)| *value).collect();
    let mut adjust = set.adjust.clone();
    for (index, op) in ops.iter().enumerate() {
        let num = op.num as usize;
        let current = values[num];
        if op.op == 0 && current != 0 {
            return Err(if op.flg & IPC_NOWAIT as i16 != 0 {
                Refused::Errno(EAGAIN)
            } else {
                Refused::Block(index)
            });
        }
        let result = current + i32::from(op.op);
        if result < 0 {
            return Err(if op.flg & IPC_NOWAIT as i16 != 0 {
                Refused::Errno(EAGAIN)
            } else {
                Refused::Block(index)
            });
        }
        if result > SEMVMX {
            return Err(Refused::Errno(ERANGE));
        }
        if op.flg & SEM_UNDO != 0 {
            let undo = adjust[num] - i32::from(op.op);
            if !(-SEMAEM - 1..=SEMAEM).contains(&undo) {
                return Err(Refused::Errno(ERANGE));
            }
            adjust[num] = undo;
        }
        values[num] = result;
    }
    for op in ops {
        set.sems[op.num as usize] = (values[op.num as usize], PID);
    }
    set.adjust = adjust;
    Ok(())
}

/// `update_queue`: complete every blocked operation the values now allow,
/// oldest first, rescanning after one that altered them. Answers the tasks to
/// wake.
fn update_queue(set: &mut SemSet, outcomes: &mut BTreeMap<TaskId, Outcome>) -> Vec<TaskId> {
    let mut woken = Vec::new();
    let mut index = 0;
    while index < set.pending.len() {
        let ops = set.pending[index].ops.clone();
        match perform(set, &ops) {
            Ok(()) => {
                let waiter = set.pending.remove(index).expect("indexed above");
                outcomes.insert(waiter.task, Outcome::Done(0));
                woken.push(waiter.task);
                set.otime = now();
                if waiter.alter {
                    index = 0;
                    continue;
                }
            }
            Err(Refused::Block(blocking)) => {
                set.pending[index].blocking = blocking;
                index += 1;
            }
            Err(Refused::Errno(errno)) => {
                let waiter = set.pending.remove(index).expect("indexed above");
                outcomes.insert(waiter.task, Outcome::Done(fail(errno)));
                woken.push(waiter.task);
            }
        }
    }
    woken
}

/// `semop(2)`/`semtimedop(2)`, `timeout` relative.
///
/// # Safety
/// `sops` must be NULL or readable for `nsops` entries; `timeout` NULL or a
/// readable timespec.
pub(crate) unsafe fn semtimedop(
    id: i32,
    sops: *const Sembuf,
    nsops: usize,
    timeout: *const signals::Timespec,
) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if nsops < 1 || id < 0 {
        return fail(EINVAL);
    }
    if nsops > SEMOPM {
        return fail(E2BIG);
    }
    if sops.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    let ops: Vec<Sembuf> = unsafe { std::slice::from_raw_parts(sops, nsops) }.to_vec();
    let relative = if timeout.is_null() {
        None
    } else {
        // SAFETY: per this function's contract.
        let timeout = unsafe { &*timeout };
        if timeout.sec < 0 || !(0..1_000_000_000).contains(&timeout.nsec) {
            return fail(EINVAL);
        }
        Some(
            (timeout.sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(timeout.nsec as u64),
        )
    };
    let max = ops.iter().map(|op| op.num).max().unwrap_or(0) as usize;
    let alter = ops.iter().any(|op| op.op != 0);
    let undos = ops.iter().any(|op| op.flg & SEM_UNDO != 0);
    let me = current_task();
    let mut deadline = None;
    loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let Ipc { sem, outcomes, .. } = &mut state.ipc;
        let (perm, set) = match sem.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if undos {
            set.undo = true;
        }
        if max >= set.sems.len() {
            return fail(EFBIG);
        }
        if !perm.allows(if alter { S_IWUGO } else { S_IRUGO }) {
            return fail(EACCES);
        }
        let blocking = match perform(set, &ops) {
            Ok(()) => {
                set.otime = now();
                let woken = if alter {
                    update_queue(set, outcomes)
                } else {
                    Vec::new()
                };
                drop(state);
                wake_all(woken);
                return 0;
            }
            Err(Refused::Errno(errno)) => return fail(errno),
            Err(Refused::Block(blocking)) => blocking,
        };
        set.pending.push_back(SemWaiter {
            task: me,
            ops: ops.clone(),
            blocking,
            alter,
        });
        let timed = match (relative, deadline) {
            (None, _) => None,
            (Some(_), Some(at)) => Some((ClockKind::Monotonic, at)),
            (Some(relative), None) => {
                match with_context_raw(|context| context.now(ClockKind::Monotonic)) {
                    Ok(now) => Some((
                        ClockKind::Monotonic,
                        *deadline.insert(now.saturating_add(relative)),
                    )),
                    Err(errno) => return fail(errno),
                }
            }
        };
        let loc = IpcWait::Sem(id);
        match wait_on(state, me, "semop", BlockClass::Ipc, loc, timed, EAGAIN) {
            Ok(Some(Outcome::Done(result))) => return result,
            Ok(_) => {}
            Err(result) => return result,
        }
    }
}

/// `exit_sem` for a process whose only thread drops its undo list
/// (`unshare(CLONE_SYSVSEM)`): each set it holds an undo entry for gets the
/// adjustments applied — a semaphore kept within `0..=SEMVMX`, its last
/// process the caller where one moved it — and the entry dropped; then the
/// set's waiters are rescanned and its `sem_otime` moves (`do_smart_update`
/// with `otime` forced).
pub(crate) fn exit_sem() {
    let mut state = lock_state();
    let Ipc { sem, outcomes, .. } = &mut state.ipc;
    let mut woken = Vec::new();
    for (_, set) in sem.objects.values_mut() {
        if !set.undo {
            continue;
        }
        set.undo = false;
        for (slot, adjust) in set.sems.iter_mut().zip(set.adjust.iter_mut()) {
            if *adjust != 0 {
                *slot = ((slot.0 + *adjust).clamp(0, SEMVMX), PID);
                *adjust = 0;
            }
        }
        woken.extend(update_queue(set, outcomes));
        set.otime = now();
    }
    drop(state);
    wake_all(woken);
}

/// `semctl(2)`; `arg` is the fourth argument's register (`union semun`).
///
/// # Safety
/// For `IPC_STAT`/`IPC_SET`/`GETALL`/`SETALL`, `arg` must point to the
/// command's buffer.
pub(crate) unsafe fn semctl(id: i32, num: i32, cmd: i32, arg: usize) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | SEM_INFO | SEM_STAT | SEM_STAT_ANY => i64::from(crate::deny(DENY_TABLES)),
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, set) = match state.ipc.sem.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                sem_stat(perm, set)
            };
            let buf = arg as *mut SemidDs;
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        GETALL | GETVAL | GETPID | GETNCNT | GETZCNT | SETALL => {
            // SAFETY: forwarded from this function's contract.
            unsafe { sem_values(id, num, cmd, arg) }
        }
        SETVAL => {
            let value = arg as i32;
            if !(0..=SEMVMX).contains(&value) {
                return fail(ERANGE);
            }
            let mut state = lock_state();
            let Ipc { sem, outcomes, .. } = &mut state.ipc;
            let (perm, set) = match sem.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            if num < 0 || num as usize >= set.sems.len() {
                return fail(EINVAL);
            }
            if !perm.allows(S_IWUGO) {
                return fail(EACCES);
            }
            set.sems[num as usize] = (value, PID);
            set.adjust[num as usize] = 0;
            set.ctime = now();
            let woken = update_queue(set, outcomes);
            drop(state);
            wake_all(woken);
            0
        }
        IPC_SET | IPC_RMID => {
            let from = if cmd == IPC_SET {
                let buf = arg as *const SemidDs;
                if buf.is_null() {
                    return fail(EFAULT);
                }
                // SAFETY: per this function's contract.
                Some(unsafe { (*buf).perm })
            } else {
                None
            };
            let mut state = lock_state();
            match from {
                Some(from) => {
                    let (perm, set) = match state.ipc.sem.get_mut(id) {
                        Ok(found) => found,
                        Err(errno) => return fail(errno),
                    };
                    if let Err(errno) = perm.update(&from) {
                        return fail(errno);
                    }
                    set.ctime = now();
                    0
                }
                None => {
                    // `freeary`: every waiter wakes with EIDRM.
                    let Some((_, set)) = state.ipc.sem.remove(id) else {
                        return fail(EINVAL);
                    };
                    let woken = set.pending.iter().map(|waiter| waiter.task).collect();
                    removed(state, woken)
                }
            }
        }
        _ => fail(EINVAL),
    }
}

fn sem_stat(perm: &Perm, set: &SemSet) -> SemidDs {
    #[cfg(target_arch = "x86_64")]
    {
        SemidDs {
            perm: perm.stat(),
            otime: set.otime,
            otime_pad: 0,
            ctime: set.ctime,
            ctime_pad: 0,
            nsems: set.sems.len() as u64,
            unused: [0; 2],
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        SemidDs {
            perm: perm.stat(),
            otime: set.otime,
            ctime: set.ctime,
            nsems: set.sems.len() as u64,
            unused: [0; 2],
        }
    }
}

/// `semctl_main`: the value commands.
///
/// # Safety
/// For `GETALL`/`SETALL`, `arg` must point to one `u16` per semaphore.
unsafe fn sem_values(id: i32, num: i32, cmd: i32, arg: usize) -> i64 {
    let mut state = lock_state();
    let Ipc { sem, outcomes, .. } = &mut state.ipc;
    let (perm, set) = match sem.get_mut(id) {
        Ok(found) => found,
        Err(errno) => return fail(errno),
    };
    if !perm.allows(if cmd == SETALL { S_IWUGO } else { S_IRUGO }) {
        return fail(EACCES);
    }
    let count = set.sems.len();
    match cmd {
        GETALL => {
            let out = arg as *mut u16;
            if out.is_null() {
                return fail(EFAULT);
            }
            for (index, (value, _)) in set.sems.iter().enumerate() {
                // SAFETY: per this function's contract.
                unsafe { out.add(index).write(*value as u16) };
            }
            return 0;
        }
        SETALL => {
            let from = arg as *const u16;
            if from.is_null() {
                return fail(EFAULT);
            }
            // SAFETY: per this function's contract.
            let values: Vec<u16> = unsafe { std::slice::from_raw_parts(from, count) }.to_vec();
            if values.iter().any(|value| i32::from(*value) > SEMVMX) {
                return fail(ERANGE);
            }
            for (slot, value) in set.sems.iter_mut().zip(values) {
                *slot = (i32::from(value), PID);
            }
            set.adjust.iter_mut().for_each(|adjust| *adjust = 0);
            set.ctime = now();
            let woken = update_queue(set, outcomes);
            drop(state);
            wake_all(woken);
            return 0;
        }
        _ => {}
    }
    if num < 0 || num as usize >= count {
        return fail(EINVAL);
    }
    let num = num as usize;
    let counted = |zero: bool| {
        set.pending
            .iter()
            .filter(|waiter| {
                let op = waiter.ops[waiter.blocking];
                op.num as usize == num && if zero { op.op == 0 } else { op.op < 0 }
            })
            .count() as i64
    };
    match cmd {
        GETVAL => i64::from(set.sems[num].0),
        GETPID => i64::from(set.sems[num].1),
        GETNCNT => counted(false),
        GETZCNT => counted(true),
        _ => unreachable!("the value commands are matched above"),
    }
}

// ---------------------------------------------------------------- message queues

/// `msgget(2)`.
pub(crate) fn msgget(key: i32, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.msg,
        key,
        flags,
        |_| Ok(()),
        || {
            Ok(MsgQueue {
                messages: VecDeque::new(),
                cbytes: 0,
                qbytes: MSGMNB,
                stime: 0,
                rtime: 0,
                ctime: now(),
                lspid: 0,
                lrpid: 0,
                receivers: VecDeque::new(),
                senders: VecDeque::new(),
            })
        },
    );
    answer(result)
}

/// `msgsnd(2)`.
///
/// # Safety
/// `msgp` must be NULL or point to a `long` type followed by `size` bytes.
pub(crate) unsafe fn msgsnd(id: i32, msgp: *const u8, size: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    // The type is read before anything is judged.
    if msgp.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    let mtype = unsafe { msgp.cast::<i64>().read_unaligned() };
    if size > MSGMAX || (size as isize) < 0 || id < 0 {
        return fail(EINVAL);
    }
    if mtype < 1 {
        return fail(EINVAL);
    }
    // SAFETY: per this function's contract.
    let text = unsafe { std::slice::from_raw_parts(msgp.add(8), size) }.to_vec();
    let me = current_task();
    let mut message = Some(Message { mtype, text });
    loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let Ipc { msg, outcomes, .. } = &mut state.ipc;
        let (perm, queue) = match msg.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(S_IWUGO) {
            return fail(EACCES);
        }
        if queue.fits(size) {
            queue.lspid = PID;
            queue.stime = now();
            let sent = message.take().expect("sent once");
            let woken = deliver_message(queue, outcomes, sent);
            drop(state);
            wake_all(woken);
            return 0;
        }
        if flags & IPC_NOWAIT != 0 {
            return fail(EAGAIN);
        }
        queue.senders.push_back(me);
        let loc = IpcWait::MsgSend(id);
        match wait_on(state, me, "msgsnd", BlockClass::Ipc, loc, None, EAGAIN) {
            Ok(Some(Outcome::Done(result))) => return result,
            Ok(_) => {}
            Err(result) => return result,
        }
    }
}

/// `pipelined_send`, else enqueue: hand `message` to the first waiting
/// receiver it suits (one too small for it is woken with `E2BIG`), or append
/// it. Answers the tasks to wake.
fn deliver_message(
    queue: &mut MsgQueue,
    outcomes: &mut BTreeMap<TaskId, Outcome>,
    message: Message,
) -> Vec<TaskId> {
    let mut woken = Vec::new();
    let mut index = 0;
    while index < queue.receivers.len() {
        let receiver = &queue.receivers[index];
        if !receiver.mode.test(message.mtype, receiver.wanted) {
            index += 1;
            continue;
        }
        let receiver = queue.receivers.remove(index).expect("indexed above");
        woken.push(receiver.task);
        if receiver.max < message.text.len() {
            outcomes.insert(receiver.task, Outcome::Done(fail(E2BIG)));
            continue;
        }
        queue.lrpid = PID;
        queue.rtime = now();
        outcomes.insert(receiver.task, Outcome::Message(message));
        return woken;
    }
    queue.cbytes += message.text.len();
    queue.messages.push_back(message);
    woken
}

/// Wake every sender waiting for room (`ss_wakeup`): each re-judges.
fn wake_senders(queue: &mut MsgQueue) -> Vec<TaskId> {
    queue.senders.drain(..).collect()
}

/// `msgrcv(2)`: the text length, or `-errno`.
///
/// # Safety
/// `msgp` must be writable for a `long` type followed by `size` bytes.
pub(crate) unsafe fn msgrcv(id: i32, msgp: *mut u8, size: usize, mtype: i64, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 || (size as isize) < 0 {
        return fail(EINVAL);
    }
    if flags & MSG_COPY != 0 {
        if flags & MSG_EXCEPT != 0 || flags & IPC_NOWAIT == 0 {
            return fail(EINVAL);
        }
        // A kernel without CONFIG_CHECKPOINT_RESTORE.
        return fail(ENOSYS);
    }
    let (wanted, mode) = if mtype == 0 {
        (0, Search::Any)
    } else if mtype < 0 {
        (
            if mtype == i64::MIN { i64::MAX } else { -mtype },
            Search::LessEqual,
        )
    } else if flags & MSG_EXCEPT != 0 {
        (mtype, Search::NotEqual)
    } else {
        (mtype, Search::Equal)
    };
    let me = current_task();
    let message = loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let (perm, queue) = match state.ipc.msg.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(S_IRUGO) {
            return fail(EACCES);
        }
        if let Some(index) = queue.find(wanted, mode) {
            if size < queue.messages[index].text.len() && flags & MSG_NOERROR == 0 {
                return fail(E2BIG);
            }
            let message = queue.messages.remove(index).expect("found above");
            queue.cbytes -= message.text.len();
            queue.rtime = now();
            queue.lrpid = PID;
            let woken = wake_senders(queue);
            drop(state);
            wake_all(woken);
            break message;
        }
        if flags & IPC_NOWAIT != 0 {
            return fail(ENOMSG);
        }
        queue.receivers.push_back(Receiver {
            task: me,
            wanted,
            mode,
            max: if flags & MSG_NOERROR != 0 {
                i32::MAX as usize
            } else {
                size
            },
        });
        let loc = IpcWait::MsgRecv(id);
        match wait_on(state, me, "msgrcv", BlockClass::Ipc, loc, None, EAGAIN) {
            Ok(Some(Outcome::Message(message))) => break message,
            Ok(Some(Outcome::Done(result))) | Err(result) => return result,
            Ok(None) => {}
        }
    };
    let copied = size.min(message.text.len());
    // SAFETY: per this function's contract.
    unsafe {
        msgp.cast::<i64>().write_unaligned(message.mtype);
        msgp.add(8)
            .copy_from_nonoverlapping(message.text.as_ptr(), copied);
    }
    copied as i64
}

/// `msgctl(2)`.
///
/// # Safety
/// `buf` must be NULL or valid for the command's `msqid_ds`.
pub(crate) unsafe fn msgctl(id: i32, cmd: i32, buf: *mut MsqidDs) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 || cmd < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | MSG_INFO | MSG_STAT | MSG_STAT_ANY => i64::from(crate::deny(DENY_TABLES)),
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, queue) = match state.ipc.msg.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                MsqidDs {
                    perm: perm.stat(),
                    stime: queue.stime,
                    rtime: queue.rtime,
                    ctime: queue.ctime,
                    cbytes: queue.cbytes as u64,
                    qnum: queue.messages.len() as u64,
                    qbytes: queue.qbytes as u64,
                    lspid: queue.lspid,
                    lrpid: queue.lrpid,
                    unused: [0; 2],
                }
            };
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        IPC_SET => {
            if buf.is_null() {
                return fail(EFAULT);
            }
            // SAFETY: per this function's contract.
            let (from, qbytes) = unsafe { ((*buf).perm, (*buf).qbytes) };
            let mut state = lock_state();
            let (perm, queue) = match state.ipc.msg.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            // Raising the limit past `msgmnb` needs CAP_SYS_RESOURCE.
            if qbytes > MSGMNB as u64 {
                return fail(EPERM);
            }
            if let Err(errno) = perm.update(&from) {
                return fail(errno);
            }
            queue.qbytes = qbytes as usize;
            queue.ctime = now();
            // Receivers re-judge the permissions, senders the room.
            let mut woken: Vec<TaskId> = queue.receivers.drain(..).map(|r| r.task).collect();
            woken.extend(wake_senders(queue));
            drop(state);
            wake_all(woken);
            0
        }
        IPC_RMID => {
            let mut state = lock_state();
            let Some((_, queue)) = state.ipc.msg.remove(id) else {
                return fail(EINVAL);
            };
            let woken = queue
                .receivers
                .iter()
                .map(|receiver| receiver.task)
                .chain(queue.senders.iter().copied())
                .collect();
            removed(state, woken)
        }
        _ => fail(EINVAL),
    }
}

// ---------------------------------------------------------------- POSIX message queues

/// `DFLT_QUEUESMAX`, `DFLT_MSG`/`DFLT_MSGMAX`, `DFLT_MSGSIZE`/`DFLT_MSGSIZEMAX`.
const MQ_QUEUES_MAX: usize = 256;
const MQ_MSG_DEFAULT: i64 = 10;
const MQ_MSG_MAX: i64 = 10;
const MQ_MSGSIZE_DEFAULT: i64 = 8192;
const MQ_MSGSIZE_MAX: i64 = 8192;
const MQ_PRIO_MAX: u32 = 32768;
/// `sizeof(struct msg_msg)` and `sizeof(struct posix_msg_tree_node)`, what a
/// queue is charged per possible message besides its bytes.
const MSG_MSG_SIZE: u64 = 48;
const TREE_NODE_SIZE: u64 = 48;
const NAME_MAX: usize = 255;
const PATH_MAX: usize = 4096;
const O_ACCMODE: i32 = 3;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_NONBLOCK_KERNEL: i32 = 0o4000;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
/// `SI_MESGQ`: a message arrived on an empty queue.
const SI_MESGQ: i32 = -3;
/// `_NSIG`.
const NSIG: i32 = 64;
const EMSGSIZE: c_int = 90;
const EBADF: c_int = crate::EBADF;
const EMFILE: c_int = 24;
const ENAMETOOLONG: c_int = crate::ENAMETOOLONG;
const ENOTSOCK: c_int = crate::ENOTSOCK;
const ENXIO: c_int = crate::ENXIO;

/// `struct mq_attr`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MqAttr {
    flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    reserved: [i64; 4],
}

/// `struct sigevent`: the members `mq_notify` reads.
#[repr(C)]
pub(crate) struct SigEvent {
    value: u64,
    signo: i32,
    notify: i32,
    rest: [i32; 12],
}

struct MqSender {
    task: TaskId,
    prio: u32,
    data: Vec<u8>,
}

struct Mqueue {
    maxmsg: usize,
    msgsize: usize,
    mode: u32,
    /// Messages, highest priority first, oldest first within a priority.
    messages: VecDeque<(u32, Vec<u8>)>,
    /// Bytes queued (`qsize`).
    qsize: usize,
    named: bool,
    opens: usize,
    /// The registration: `(sigev_notify, sigev_signo, sigev_value)`.
    notify: Option<(i32, i32, u64)>,
    receivers: VecDeque<TaskId>,
    senders: VecDeque<MqSender>,
    readable_watchers: VecDeque<TaskId>,
    writable_watchers: VecDeque<TaskId>,
    /// Arrival and departure counts: the epoll edge sequences.
    arrivals: u64,
    departures: u64,
    /// What the queue is charged against `RLIMIT_MSGQUEUE`.
    charge: u64,
}

impl Mqueue {
    fn insert(&mut self, prio: u32, data: Vec<u8>) {
        let at = self
            .messages
            .iter()
            .position(|(queued, _)| *queued < prio)
            .unwrap_or(self.messages.len());
        self.qsize += data.len();
        self.messages.insert(at, (prio, data));
        self.arrivals += 1;
    }

    fn attr(&self, flags: i64) -> MqAttr {
        MqAttr {
            flags,
            maxmsg: self.maxmsg as i64,
            msgsize: self.msgsize as i64,
            curmsgs: self.messages.len() as i64,
            reserved: [0; 4],
        }
    }
}

/// An open queue description: its queue and its read position (a queue
/// descriptor reads its status line).
struct MqOpen {
    queue: u64,
    position: usize,
}

/// `getname` then `lookup_one_len` on the queue root: the name's bytes, or
/// the errno.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated string.
unsafe fn mq_name(name: *const c_char) -> Result<Vec<u8>, c_int> {
    if name.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: per this function's contract.
    let bytes = unsafe { std::ffi::CStr::from_ptr(name) }
        .to_bytes()
        .to_vec();
    if bytes.is_empty() {
        return Err(ENOENT);
    }
    if bytes.len() >= PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(EACCES);
    }
    if bytes.len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok(bytes)
}

/// The queue and status of the open queue description a descriptor names:
/// `EBADF` for anything else.
fn mq_entry(fd: c_int) -> Result<(u64, u32), c_int> {
    let resolved = super::class_entry(fd)?;
    if resolved.kind != FdKind::MessageQueue {
        return Err(EBADF);
    }
    Ok((resolved.handle, resolved.status))
}

/// A realtime deadline (`prepare_timeout`): `EINVAL` for an invalid one.
///
/// # Safety
/// `timeout` must be NULL or a readable timespec.
unsafe fn mq_deadline(timeout: *const signals::Timespec) -> Result<Option<u64>, c_int> {
    if timeout.is_null() {
        return Ok(None);
    }
    // SAFETY: per this function's contract.
    let timeout = unsafe { &*timeout };
    if timeout.sec < 0 || !(0..1_000_000_000).contains(&timeout.nsec) {
        return Err(EINVAL);
    }
    Ok(Some(
        (timeout.sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(timeout.nsec as u64),
    ))
}

/// `mq_open(2)`: a new descriptor, or `-errno`.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated string, `attr` NULL or a readable
/// `mq_attr`.
pub(crate) unsafe fn mq_open(
    name: *const c_char,
    oflag: i32,
    mode: u32,
    attr: *const MqAttr,
) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let requested = if attr.is_null() {
        None
    } else {
        // SAFETY: per this function's contract.
        Some(unsafe { *attr })
    };
    // SAFETY: per this function's contract.
    let name = match unsafe { mq_name(name) } {
        Ok(name) => name,
        Err(errno) => return fail(errno),
    };
    let mut state = lock_state();
    let ipc = &mut state.ipc;
    let queue = match ipc.mq_names.get(&name) {
        Some(&queue) => {
            if oflag & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return fail(EEXIST);
            }
            if oflag & O_ACCMODE == O_ACCMODE {
                return fail(EINVAL);
            }
            let wanted = match oflag & O_ACCMODE {
                0 => 0o4,
                O_WRONLY => 0o2,
                _ => 0o6,
            };
            if (ipc.mqueues[&queue].mode >> 6) & wanted != wanted {
                return fail(EACCES);
            }
            queue
        }
        None => {
            if oflag & O_CREAT == 0 {
                return fail(ENOENT);
            }
            if ipc.mqueues.len() >= MQ_QUEUES_MAX {
                return fail(ENOSPC);
            }
            let (maxmsg, msgsize) = requested
                .map_or((MQ_MSG_DEFAULT, MQ_MSGSIZE_DEFAULT), |attr| {
                    (attr.maxmsg, attr.msgsize)
                });
            if maxmsg <= 0 || msgsize <= 0 || maxmsg > MQ_MSG_MAX || msgsize > MQ_MSGSIZE_MAX {
                return fail(EINVAL);
            }
            let charge = (maxmsg as u64) * (msgsize as u64)
                + (maxmsg as u64) * MSG_MSG_SIZE
                + (maxmsg as u64).min(u64::from(MQ_PRIO_MAX)) * TREE_NODE_SIZE;
            if ipc.mq_bytes + charge > crate::limits::soft(crate::limits::RLIMIT_MSGQUEUE) {
                return fail(EMFILE);
            }
            ipc.mq_bytes += charge;
            let queue = ipc.next_mq;
            ipc.next_mq += 1;
            ipc.mqueues.insert(
                queue,
                Mqueue {
                    maxmsg: maxmsg as usize,
                    msgsize: msgsize as usize,
                    mode: mode & !crate::paths::umask() & S_IRWXUGO,
                    messages: VecDeque::new(),
                    qsize: 0,
                    named: true,
                    opens: 0,
                    notify: None,
                    receivers: VecDeque::new(),
                    senders: VecDeque::new(),
                    readable_watchers: VecDeque::new(),
                    writable_watchers: VecDeque::new(),
                    arrivals: 0,
                    departures: 0,
                    charge,
                },
            );
            ipc.mq_names.insert(name.clone(), queue);
            queue
        }
    };
    let handle = ipc.next_mq;
    ipc.next_mq += 1;
    ipc.mq_opens.insert(handle, MqOpen { queue, position: 0 });
    ipc.mqueues.get_mut(&queue).expect("opened above").opens += 1;
    drop(state);
    let access = match oflag & O_ACCMODE {
        0 => O_READ,
        O_WRONLY => O_WRITE,
        _ => O_READ | O_WRITE,
    };
    let status = access
        | if oflag & O_NONBLOCK_KERNEL != 0 {
            O_NONBLOCK
        } else {
            0
        };
    // A queue descriptor is always close-on-exec.
    match crate::install_fd(FdKind::MessageQueue, handle, status, true) {
        Ok(fd) => i64::from(fd),
        Err(errno) => {
            mq_close(handle);
            fail(errno)
        }
    }
}

/// The last reference to an open queue description went.
pub(crate) fn mq_close(handle: u64) {
    let mut state = lock_state();
    let ipc = &mut state.ipc;
    let Some(open) = ipc.mq_opens.remove(&handle) else {
        return;
    };
    let Some(queue) = ipc.mqueues.get_mut(&open.queue) else {
        return;
    };
    queue.opens -= 1;
    // `mqueue_flush_file`: the owner's close drops its registration.
    queue.notify = None;
    if !queue.named && queue.opens == 0 {
        let queue = ipc.mqueues.remove(&open.queue).expect("found above");
        ipc.mq_bytes -= queue.charge;
    }
}

/// `mq_unlink(2)`.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated string.
pub(crate) unsafe fn mq_unlink(name: *const c_char) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    // SAFETY: per this function's contract.
    let name = match unsafe { mq_name(name) } {
        Ok(name) => name,
        Err(errno) => return fail(errno),
    };
    let mut state = lock_state();
    let ipc = &mut state.ipc;
    let Some(queue) = ipc.mq_names.remove(&name) else {
        return fail(ENOENT);
    };
    let unused = {
        let queue = ipc.mqueues.get_mut(&queue).expect("a named queue exists");
        queue.named = false;
        queue.opens == 0
    };
    if unused {
        let queue = ipc.mqueues.remove(&queue).expect("found above");
        ipc.mq_bytes -= queue.charge;
    }
    0
}

/// Whether the realtime clock has reached `deadline`.
fn passed(deadline: Option<u64>) -> Result<bool, c_int> {
    match deadline {
        None => Ok(false),
        Some(at) => {
            with_context_raw(|context| context.now(ClockKind::Realtime)).map(|now| now >= at)
        }
    }
}

/// `mq_timedsend(2)`.
///
/// # Safety
/// `data` must be readable for `len` bytes; `timeout` NULL or a readable
/// timespec.
pub(crate) unsafe fn mq_timedsend(
    fd: c_int,
    data: *const u8,
    len: usize,
    prio: u32,
    timeout: *const signals::Timespec,
) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    // SAFETY: per this function's contract.
    let deadline = match unsafe { mq_deadline(timeout) } {
        Ok(deadline) => deadline,
        Err(errno) => return fail(errno),
    };
    if prio >= MQ_PRIO_MAX {
        return fail(EINVAL);
    }
    let me = current_task();
    loop {
        let (handle, status) = match mq_entry(fd) {
            Ok(entry) => entry,
            Err(errno) => return fail(errno),
        };
        if status & O_WRITE == 0 {
            return fail(EBADF);
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let Some(queue_id) = state.ipc.mq_opens.get(&handle).map(|open| open.queue) else {
            return fail(EBADF);
        };
        let ipc = &mut state.ipc;
        let queue = ipc
            .mqueues
            .get_mut(&queue_id)
            .expect("an open queue exists");
        if len > queue.msgsize {
            return fail(EMSGSIZE);
        }
        if data.is_null() && len > 0 {
            return fail(EFAULT);
        }
        // SAFETY: per this function's contract.
        let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        if queue.messages.len() < queue.maxmsg {
            let mut woken: Vec<TaskId> = queue.readable_watchers.drain(..).collect();
            let mut notify = None;
            if let Some(receiver) = queue.receivers.pop_front() {
                // `pipelined_send`: the waiting receiver takes it directly.
                queue.arrivals += 1;
                ipc.outcomes.insert(
                    receiver,
                    Outcome::Message(Message {
                        mtype: i64::from(prio),
                        text: bytes,
                    }),
                );
                woken.push(receiver);
            } else {
                queue.insert(prio, bytes);
                if queue.messages.len() == 1 {
                    notify = queue.notify.take();
                }
            }
            drop(state);
            wake_all(woken);
            if let Some((SIGEV_SIGNAL, signo, value)) = notify {
                notify_signal(signo, value);
            }
            return 0;
        }
        if status & O_NONBLOCK != 0 {
            return fail(EAGAIN);
        }
        match passed(deadline) {
            Ok(true) => return fail(ETIMEDOUT),
            Ok(false) => {}
            Err(errno) => return fail(errno),
        }
        queue.senders.push_back(MqSender {
            task: me,
            prio,
            data: bytes,
        });
        let loc = IpcWait::MqSend(queue_id);
        let timed = deadline.map(|at| (ClockKind::Realtime, at));
        match wait_on(
            state,
            me,
            "mq_timedsend",
            BlockClass::Io,
            loc,
            timed,
            ETIMEDOUT,
        ) {
            Ok(Some(Outcome::Done(result))) => return result,
            Ok(_) => {}
            Err(result) => return result,
        }
    }
}

/// Send the `SIGEV_SIGNAL` notification: process-directed, `SI_MESGQ`, the
/// sender's pid and uid and the registered value.
fn notify_signal(signo: i32, value: u64) {
    if signo == 0 {
        return;
    }
    let info = signals::Info {
        words: [
            signo as u64,
            u64::from(SI_MESGQ as u32),
            u64::from(IDENTITY_PID) | (u64::from(crate::identity::credential().uid) << 32),
            value,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    };
    // SAFETY: `info` is a whole kernel-layout siginfo that outlives the call.
    unsafe {
        signals::generate_signal(
            signals::GenerationTarget::Process { pid: PID },
            signo,
            signals::GenerationInfo::Queued(&info),
        );
    }
}

/// `mq_timedreceive(2)`: the message's length, or `-errno`.
///
/// # Safety
/// `data` must be writable for `len` bytes; `prio` NULL or writable;
/// `timeout` NULL or a readable timespec.
pub(crate) unsafe fn mq_timedreceive(
    fd: c_int,
    data: *mut u8,
    len: usize,
    prio: *mut u32,
    timeout: *const signals::Timespec,
) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    // SAFETY: per this function's contract.
    let deadline = match unsafe { mq_deadline(timeout) } {
        Ok(deadline) => deadline,
        Err(errno) => return fail(errno),
    };
    let me = current_task();
    let (priority, message) = loop {
        let (handle, status) = match mq_entry(fd) {
            Ok(entry) => entry,
            Err(errno) => return fail(errno),
        };
        if status & O_READ == 0 {
            return fail(EBADF);
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let Some(queue_id) = state.ipc.mq_opens.get(&handle).map(|open| open.queue) else {
            return fail(EBADF);
        };
        let ipc = &mut state.ipc;
        let queue = ipc
            .mqueues
            .get_mut(&queue_id)
            .expect("an open queue exists");
        if len < queue.msgsize {
            return fail(EMSGSIZE);
        }
        if let Some((priority, message)) = queue.messages.pop_front() {
            queue.qsize -= message.len();
            queue.departures += 1;
            let mut woken: Vec<TaskId> = queue.writable_watchers.drain(..).collect();
            // `pipelined_receive`: a waiting sender's message takes the room.
            if let Some(sender) = queue.senders.pop_front() {
                queue.insert(sender.prio, sender.data);
                woken.extend(queue.readable_watchers.drain(..));
                ipc.outcomes.insert(sender.task, Outcome::Done(0));
                woken.push(sender.task);
            }
            drop(state);
            wake_all(woken);
            break (priority, message);
        }
        if status & O_NONBLOCK != 0 {
            return fail(EAGAIN);
        }
        match passed(deadline) {
            Ok(true) => return fail(ETIMEDOUT),
            Ok(false) => {}
            Err(errno) => return fail(errno),
        }
        queue.receivers.push_back(me);
        let loc = IpcWait::MqRecv(queue_id);
        let timed = deadline.map(|at| (ClockKind::Realtime, at));
        match wait_on(
            state,
            me,
            "mq_timedreceive",
            BlockClass::Io,
            loc,
            timed,
            ETIMEDOUT,
        ) {
            Ok(Some(Outcome::Message(message))) => break (message.mtype as u32, message.text),
            Ok(Some(Outcome::Done(result))) | Err(result) => return result,
            Ok(None) => {}
        }
    };
    if data.is_null() && !message.is_empty() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe {
        if !prio.is_null() {
            prio.write(priority);
        }
        data.copy_from_nonoverlapping(message.as_ptr(), message.len());
    }
    message.len() as i64
}

/// `mq_notify(2)`.
///
/// # Safety
/// `event` must be NULL or a readable `sigevent`.
pub(crate) unsafe fn mq_notify(fd: c_int, event: *const SigEvent) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let registration = if event.is_null() {
        None
    } else {
        // SAFETY: per this function's contract.
        let event = unsafe { &*event };
        match event.notify {
            SIGEV_NONE | SIGEV_SIGNAL => {}
            SIGEV_THREAD => {
                // The registration names a netlink socket; the virtual
                // network has none, so the descriptor is judged as the
                // kernel judges any other.
                if event.value == 0 {
                    return fail(EFAULT);
                }
                return fail(match super::class_entry(event.signo) {
                    Err(_) => EBADF,
                    Ok(resolved) if resolved.kind == FdKind::Socket => EINVAL,
                    Ok(_) => ENOTSOCK,
                });
            }
            _ => return fail(EINVAL),
        }
        if event.notify == SIGEV_SIGNAL && !(0..=NSIG).contains(&event.signo) {
            return fail(EINVAL);
        }
        Some((event.notify, event.signo, event.value))
    };
    let (handle, _) = match mq_entry(fd) {
        Ok(entry) => entry,
        Err(errno) => return fail(errno),
    };
    let mut state = lock_state();
    let ipc = &mut state.ipc;
    let Some(queue) = ipc
        .mq_opens
        .get(&handle)
        .and_then(|open| ipc.mqueues.get_mut(&open.queue))
    else {
        return fail(EBADF);
    };
    match registration {
        None => {
            queue.notify = None;
            0
        }
        Some(_) if queue.notify.is_some() => fail(EBUSY),
        Some(registration) => {
            queue.notify = Some(registration);
            0
        }
    }
}

/// `mq_getsetattr(2)`.
///
/// # Safety
/// `new` must be NULL or a readable `mq_attr`, `old` NULL or writable.
pub(crate) unsafe fn mq_getsetattr(fd: c_int, new: *const MqAttr, old: *mut MqAttr) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let new_flags = if new.is_null() {
        None
    } else {
        // SAFETY: per this function's contract.
        let flags = unsafe { (*new).flags };
        if flags & !i64::from(O_NONBLOCK_KERNEL) != 0 {
            return fail(EINVAL);
        }
        Some(flags)
    };
    let (handle, status) = match mq_entry(fd) {
        Ok(entry) => entry,
        Err(errno) => return fail(errno),
    };
    let attr = {
        let state = lock_state();
        let Some(queue) = state
            .ipc
            .mq_opens
            .get(&handle)
            .and_then(|open| state.ipc.mqueues.get(&open.queue))
        else {
            return fail(EBADF);
        };
        queue.attr(if status & O_NONBLOCK != 0 {
            i64::from(O_NONBLOCK_KERNEL)
        } else {
            0
        })
    };
    if let Some(flags) = new_flags {
        let nonblocking = flags & i64::from(O_NONBLOCK_KERNEL) != 0;
        if let Err(errno) = super::super::fd_table().lock().set_status(
            fd,
            O_NONBLOCK,
            if nonblocking { O_NONBLOCK } else { 0 },
        ) {
            return fail(errno);
        }
    }
    if !old.is_null() {
        // SAFETY: per this function's contract.
        unsafe { old.write(attr) };
    }
    0
}

/// `FILENT_SIZE`: an mqueue inode's size, the room its status line has.
const FILENT_SIZE: usize = 80;

/// The status line an mqueue file reads (`mqueue_read_file`).
fn status_line(queue: &Mqueue) -> String {
    let (notify, signo) = match queue.notify {
        Some((kind, signo, _)) => (kind, if kind == SIGEV_SIGNAL { signo } else { 0 }),
        None => (0, 0),
    };
    let owner = if queue.notify.is_some() { PID } else { 0 };
    format!(
        "QSIZE:{:<10} NOTIFY:{notify:<5} SIGNO:{signo:<5} NOTIFY_PID:{owner:<6}\n",
        queue.qsize
    )
}

/// `read(2)` of a queue descriptor — or `pread(2)` at `at` — its status line
/// from the description's position (`simple_read_from_buffer`). A read moves
/// the position; a positional read does not.
///
/// # Safety
/// `destination` must be writable for `len` bytes.
pub(crate) unsafe fn mq_read(
    handle: u64,
    destination: *mut c_void,
    len: usize,
    at: Option<u64>,
) -> isize {
    let mut state = lock_state();
    let ipc = &mut state.ipc;
    let Some(open) = ipc.mq_opens.get_mut(&handle) else {
        return super::super::fail(EBADF) as isize;
    };
    let line = status_line(&ipc.mqueues[&open.queue]);
    let position = at.map_or(open.position, |at| {
        usize::try_from(at).unwrap_or(usize::MAX)
    });
    let from = position.min(line.len());
    let count = len.min(line.len() - from);
    // SAFETY: per this function's contract.
    unsafe {
        destination
            .cast::<u8>()
            .copy_from_nonoverlapping(line.as_ptr().add(from), count)
    };
    if at.is_none() {
        open.position += count;
    }
    count as isize
}

/// `lseek(2)` of a queue descriptor (`default_llseek` over an inode of
/// `FILENT_SIZE` bytes): the new position, or the errno.
pub(crate) fn mq_seek(handle: u64, offset: i64, whence: u32) -> Result<i64, c_int> {
    let mut state = lock_state();
    let open = state.ipc.mq_opens.get_mut(&handle).ok_or(EBADF)?;
    let size = FILENT_SIZE as i64;
    let target = match whence {
        0 => Some(offset),
        1 => (open.position as i64).checked_add(offset),
        2 => size.checked_add(offset),
        // SEEK_DATA: the whole file is data; SEEK_HOLE: the hole is its end.
        3 if offset >= size => return Err(ENXIO),
        3 => Some(offset),
        4 if offset >= size => return Err(ENXIO),
        4 => Some(size),
        _ => return Err(EINVAL),
    };
    match target {
        Some(target) if target >= 0 => {
            open.position = target as usize;
            Ok(target)
        }
        _ => Err(EINVAL),
    }
}

/// `FIONREAD` on a queue descriptor: the inode's size less the position.
pub(crate) fn mq_unread(handle: u64) -> Option<i32> {
    let state = lock_state();
    let open = state.ipc.mq_opens.get(&handle)?;
    Some(FILENT_SIZE as i32 - i32::try_from(open.position).unwrap_or(i32::MAX))
}

/// The permission bits of the queue a descriptor names.
pub(crate) fn mq_mode(handle: u64) -> Option<u32> {
    let state = lock_state();
    let open = state.ipc.mq_opens.get(&handle)?;
    state.ipc.mqueues.get(&open.queue).map(|queue| queue.mode)
}

/// Level-triggered readiness of a queue (`mqueue_poll_file`): readable with a
/// message queued, writable with room.
pub(in crate::thread) fn mq_readiness(state: &ThreadRuntime, handle: u64) -> (bool, bool) {
    state
        .ipc
        .mq_opens
        .get(&handle)
        .and_then(|open| state.ipc.mqueues.get(&open.queue))
        .map_or((false, false), |queue| {
            (
                !queue.messages.is_empty(),
                queue.messages.len() < queue.maxmsg,
            )
        })
}

/// The arrival and departure counts of a queue: its epoll edge sequences.
pub(in crate::thread) fn mq_event_seqs(state: &ThreadRuntime, handle: u64) -> (u64, u64) {
    state
        .ipc
        .mq_opens
        .get(&handle)
        .and_then(|open| state.ipc.mqueues.get(&open.queue))
        .map_or((0, 0), |queue| (queue.arrivals, queue.departures))
}

/// Register a readiness reactor's task on a queue's readable or writable
/// watchers.
pub(in crate::thread) fn mq_watch(
    state: &mut ThreadRuntime,
    handle: u64,
    me: TaskId,
    readable: bool,
) -> Option<WaiterLoc> {
    let queue_id = state.ipc.mq_opens.get(&handle)?.queue;
    let queue = state.ipc.mqueues.get_mut(&queue_id)?;
    if readable {
        queue.readable_watchers.push_back(me);
        Some(WaiterLoc::Ipc(IpcWait::MqReadable(queue_id)))
    } else {
        queue.writable_watchers.push_back(me);
        Some(WaiterLoc::Ipc(IpcWait::MqWritable(queue_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perm() -> Perm {
        Perm::new(IPC_PRIVATE, 0o600)
    }

    #[test]
    fn ids_advance_cyclically_and_a_removed_id_stays_invalid() {
        let mut space: Space<()> = Space::new(3);
        let first = space.add(perm(), ()).unwrap();
        let second = space.add(perm(), ()).unwrap();
        assert_eq!((first, second), (0, 1));
        assert!(space.remove(first).is_some());
        // The next index after the last one handed out, not the freed one.
        assert_eq!(space.add(perm(), ()).unwrap(), 2);
        // Wrapping reuses index 0 under the next sequence number.
        assert_eq!(space.add(perm(), ()).unwrap(), IPCMNI);
        assert_eq!(space.add(perm(), ()), Err(ENOSPC));
        assert_eq!(space.get(first).err(), Some(EINVAL));
        assert!(space.get(IPCMNI).is_ok());
    }

    #[test]
    fn ids_cycle_within_the_window_in_use_sets() {
        let mut space: Space<()> = Space::new(SEMMNI);
        for expected in 0..IPC_MIN_CYCLE {
            let id = space.add(perm(), ()).unwrap();
            assert_eq!(id, expected);
            space.remove(id).unwrap();
        }
        // Few objects in use: the index wraps at 64, not at the limit.
        assert_eq!(space.add(perm(), ()).unwrap(), IPCMNI);
    }

    fn set(values: &[i32]) -> SemSet {
        SemSet {
            sems: values.iter().map(|value| (*value, 0)).collect(),
            adjust: vec![0; values.len()],
            undo: false,
            otime: 0,
            ctime: 0,
            pending: VecDeque::new(),
        }
    }

    fn op(num: u16, op: i16, flg: i16) -> Sembuf {
        Sembuf { num, op, flg }
    }

    #[test]
    fn semaphore_operations_apply_all_or_none_in_order() {
        let mut sems = set(&[1, 0]);
        // The second operation blocks, so the first is not applied.
        assert!(matches!(
            perform(&mut sems, &[op(0, -1, 0), op(1, -1, 0)]),
            Err(Refused::Block(1))
        ));
        assert_eq!(sems.sems[0].0, 1);
        assert!(matches!(
            perform(&mut sems, &[op(1, -1, IPC_NOWAIT as i16)]),
            Err(Refused::Errno(EAGAIN))
        ));
        // Operations on one semaphore apply in sequence.
        assert!(perform(&mut sems, &[op(1, 2, 0), op(1, -1, 0)]).is_ok());
        assert_eq!(sems.sems[1], (1, PID));
        assert!(matches!(
            perform(&mut sems, &[op(0, SEMVMX as i16, 0)]),
            Err(Refused::Errno(ERANGE))
        ));
        assert!(matches!(
            perform(&mut sems, &[op(1, 0, 0)]),
            Err(Refused::Block(0))
        ));
    }

    #[test]
    fn a_blocked_operation_is_completed_by_the_one_that_allows_it() {
        let mut sems = set(&[0]);
        sems.pending.push_back(SemWaiter {
            task: TaskId(7),
            ops: vec![op(0, -1, 0)],
            blocking: 0,
            alter: true,
        });
        let mut outcomes = BTreeMap::new();
        assert!(update_queue(&mut sems, &mut outcomes).is_empty());
        sems.sems[0].0 = 1;
        assert_eq!(update_queue(&mut sems, &mut outcomes), vec![TaskId(7)]);
        assert!(matches!(outcomes.get(&TaskId(7)), Some(Outcome::Done(0))));
        assert_eq!(sems.sems[0].0, 0);
        assert!(sems.pending.is_empty());
    }

    #[test]
    fn a_receive_selects_by_type_as_find_msg_does() {
        let mut queue = MsgQueue {
            messages: VecDeque::new(),
            cbytes: 0,
            qbytes: MSGMNB,
            stime: 0,
            rtime: 0,
            ctime: 0,
            lspid: 0,
            lrpid: 0,
            receivers: VecDeque::new(),
            senders: VecDeque::new(),
        };
        for mtype in [3, 2, 1, 2] {
            queue.messages.push_back(Message {
                mtype,
                text: Vec::new(),
            });
        }
        assert_eq!(queue.find(0, Search::Any), Some(0));
        assert_eq!(queue.find(2, Search::Equal), Some(1));
        assert_eq!(queue.find(3, Search::NotEqual), Some(1));
        // The first of the lowest type not above 2.
        assert_eq!(queue.find(2, Search::LessEqual), Some(2));
        assert_eq!(queue.find(5, Search::Equal), None);
        assert!(queue.fits(MSGMNB));
        assert!(!queue.fits(MSGMNB + 1));
    }
}
