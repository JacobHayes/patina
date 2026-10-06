//! POSIX message-queue state and operations.

use super::*;

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
pub(super) const NAME_MAX: usize = 255;
pub(super) const PATH_MAX: usize = 4096;
pub(super) const O_ACCMODE: i32 = 3;
pub(super) const O_WRONLY: i32 = 1;
pub(super) const O_CREAT: i32 = 0o100;
pub(super) const O_EXCL: i32 = 0o200;
const O_NONBLOCK_KERNEL: i32 = 0o4000;
pub(super) const SIGEV_SIGNAL: i32 = 0;
pub(super) const SIGEV_NONE: i32 = 1;
pub(super) const SIGEV_THREAD: i32 = 2;
/// `SI_MESGQ`: a message arrived on an empty queue.
const SI_MESGQ: i32 = -3;
/// `_NSIG`.
const NSIG: i32 = 64;
pub(super) const EMSGSIZE: c_int = 90;
pub(super) const EBADF: c_int = crate::EBADF;
pub(super) const EMFILE: c_int = 24;
pub(super) const ENAMETOOLONG: c_int = crate::ENAMETOOLONG;
pub(super) const ENOTSOCK: c_int = crate::ENOTSOCK;
pub(super) const ENXIO: c_int = crate::ENXIO;

/// `struct mq_attr`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MqAttr {
    pub(super) flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    pub(super) reserved: [i64; 4],
}

/// `struct sigevent`: the members `mq_notify` reads.
#[repr(C)]
pub(crate) struct SigEvent {
    pub(super) value: u64,
    pub(super) signo: i32,
    pub(super) notify: i32,
    pub(super) rest: [i32; 12],
}

pub(super) struct MqSender {
    pub(super) task: TaskId,
    prio: u32,
    pub(super) data: Vec<u8>,
}

pub(super) struct Mqueue {
    maxmsg: usize,
    msgsize: usize,
    pub(super) mode: u32,
    /// Messages, highest priority first, oldest first within a priority.
    pub(super) messages: VecDeque<(u32, Vec<u8>)>,
    /// Bytes queued (`qsize`).
    qsize: usize,
    pub(super) named: bool,
    opens: usize,
    /// The registration: `(sigev_notify, sigev_signo, sigev_value)`.
    pub(super) notify: Option<(i32, i32, u64)>,
    pub(super) receivers: VecDeque<TaskId>,
    pub(super) senders: VecDeque<MqSender>,
    pub(super) readable_watchers: VecDeque<TaskId>,
    pub(super) writable_watchers: VecDeque<TaskId>,
    /// Arrival and departure counts: the epoll edge sequences.
    pub(super) arrivals: u64,
    departures: u64,
    /// What the queue is charged against `RLIMIT_MSGQUEUE`.
    pub(super) charge: u64,
}

impl Mqueue {
    pub(super) fn insert(&mut self, prio: u32, data: Vec<u8>) {
        let at = self
            .messages
            .iter()
            .position(|(queued, _)| *queued < prio)
            .unwrap_or(self.messages.len());
        self.qsize += data.len();
        self.messages.insert(at, (prio, data));
        self.arrivals += 1;
    }

    pub(super) fn attr(&self, flags: i64) -> MqAttr {
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
pub(super) struct MqOpen {
    pub(super) queue: u64,
    pub(super) position: usize,
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

/// A realtime deadline (`prepare_timeout`): copied in (`EFAULT`), then
/// `EINVAL` for an invalid one.
fn mq_deadline(timeout: *const signals::Timespec) -> Result<Option<u64>, c_int> {
    if timeout.is_null() {
        return Ok(None);
    }
    let Ok(timeout) = crate::uaccess::read::<signals::Timespec>(timeout as usize) else {
        return Err(EFAULT);
    };
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
pub(super) fn passed(deadline: Option<u64>) -> Result<bool, c_int> {
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
    let deadline = match mq_deadline(timeout) {
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
    let deadline = match mq_deadline(timeout) {
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
