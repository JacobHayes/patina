//! Shared descriptor-readiness reactor state and waiter registration.

use super::*;

// ------------------------------------------------------------------
// kqueue / kevent readiness reactor (macOS). A deterministic in-process
// model of the BSD readiness multiplexer that mio (and therefore tokio)
// builds its IO driver on. A `kqueue` is a description in the descriptor
// table; `kevent`/`kevent64` register EVFILT_READ/WRITE interest over the
// virtual pipe and socket fds, an EVFILT_USER self-wakeup
// (mio's `Waker`), and EVFILT_TIMER against the virtual clock, then gather
// ready events — parking on the scheduler baton with multi-fd fan-in when
// nothing is ready. Readiness for a pipe fd is pure in-shim channel state;
// readiness for a SimNet socket fd is the runtime's UNRECORDED
// `net_readiness` (a deterministic function of the recorded send/recv history
// and the virtual clock). Like the mutex words and the pipe channels, the
// registry itself is deterministic GIVEN the recorded schedule, so it carries
// NO trace events of its own; only the scheduler parks/wakes are recorded.
//
// Event delivery is edge-triggered (mio always registers with EV_CLEAR): a
// READ/WRITE knote fires on the not-ready -> ready transition and, registered
// with EV_CLEAR, on every arrival in its direction since its last delivery,
// as the kernel activates a knote on each append (a reader that drained the
// bytes before the next scan saw them still gets the next arrival's event);
// an EV_CLEAR pipe writer waits for a whole `PIPE_BUF` of room. A level
// condition (e.g. a peer-closed EV_EOF that stays set) fires exactly once
// rather than busy-looping the reactor. Returned events are ordered by `(ident, filter)` — the `BTreeMap` key order — so the
// gathered slice is a pure function of the registry and the schedule.
/// The C-facing kqueue event, matching `struct patina_kevent` in the header
/// (a platform-neutral projection of the macOS `struct kevent` the C layer
/// marshals to and from). Field order and padding match the header exactly.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PatinaKevent {
    pub(super) ident: u64,
    pub(super) filter: i16,
    pub(super) flags: u16,
    pub(super) fflags: u32,
    pub(super) data: i64,
    pub(super) udata: usize,
}

#[cfg(target_os = "macos")]
const _: () = {
    assert!(size_of::<PatinaKevent>() == size_of::<libc::kevent>());
    assert!(
        core::mem::offset_of!(PatinaKevent, ident) == core::mem::offset_of!(libc::kevent, ident)
    );
    assert!(
        core::mem::offset_of!(PatinaKevent, filter) == core::mem::offset_of!(libc::kevent, filter)
    );
    assert!(
        core::mem::offset_of!(PatinaKevent, flags) == core::mem::offset_of!(libc::kevent, flags)
    );
    assert!(
        core::mem::offset_of!(PatinaKevent, fflags) == core::mem::offset_of!(libc::kevent, fflags)
    );
    assert!(core::mem::offset_of!(PatinaKevent, data) == core::mem::offset_of!(libc::kevent, data));
    assert!(
        core::mem::offset_of!(PatinaKevent, udata) == core::mem::offset_of!(libc::kevent, udata)
    );
};

/// A descriptor's kernel poll mask (`EPOLL*` bits, [`net::abi`]'s
/// `POLL*`) and its per-direction arrival sequences, for the readiness
/// reactors: what the object's poll function answers now, computed
/// without consuming anything or recording a boundary op. `desc`, when
/// given, is the description an interest was registered against, which is
/// what is polled even if the number now names another one (the kernel's
/// `(fd, struct file)` interest key). `None` for a number that names
/// nothing.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(super) fn fd_poll(
    state: &ThreadRuntime,
    fd: c_int,
    desc: Option<DescId>,
) -> Option<(u32, (u64, u64))> {
    let (kind, handle, _) = resolve_source(fd, desc)?;
    Some(poll_description(state, kind, handle))
}

/// The kind, class handle and status flags of what a readiness source names:
/// the retained description `desc` when given, else what the number `fd`
/// names now. `None` for either naming nothing.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
fn resolve_source(fd: c_int, desc: Option<DescId>) -> Option<(FdKind, u64, u32)> {
    let table = super::fd_table().lock();
    match desc {
        Some(desc) => {
            let description = table.description(desc)?;
            Some((description.kind, description.handle, description.status))
        }
        None => {
            let resolved = table.resolve(fd)?;
            Some((resolved.kind, resolved.handle, resolved.status))
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
fn poll_description(state: &ThreadRuntime, kind: FdKind, handle: u64) -> (u32, (u64, u64)) {
    use net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    match kind {
        FdKind::Pipe => pipe_poll(state, handle as c_int),
        FdKind::Socket => net::socket_poll(state, handle).unwrap_or((POLLERR | POLLHUP, (0, 0))),
        #[cfg(target_os = "linux")]
        FdKind::SignalFd => {
            let readable = signals::fd::readable(state, handle, current_task());
            let arrivals = state
                .signals
                .signalfds
                .get(&handle)
                .map_or(0, |fd| fd.arrivals);
            (
                if readable { POLLIN | POLLRDNORM } else { 0 },
                (arrivals, 0),
            )
        }
        // `eventfd_poll`: readable while the count is nonzero; a write
        // that would overflow fails closed instead of parking, so it is
        // always writable.
        #[cfg(target_os = "linux")]
        FdKind::EventFd => {
            state
                .net
                .eventfds
                .get(&(handle as c_int))
                .map_or((POLLERR | POLLHUP, (0, 0)), |efd| {
                    let readable = if efd.value > 0 {
                        POLLIN | POLLRDNORM
                    } else {
                        0
                    };
                    (readable | POLLOUT | POLLWRNORM, (efd.write_events, 0))
                })
        }
        // Standard input is an empty pipe whose writer is gone: hung up
        // (`pipe_poll`).
        FdKind::Stdin => (POLLHUP, (0, 0)),
        // The captured streams' pipes always have room: the supervisor
        // drains them.
        FdKind::Stdout | FdKind::Stderr => (POLLOUT | POLLWRNORM, (0, 0)),
        // `/dev/random`'s `random_poll`, the one memory device poll: readable
        // (and only that) once the pool is ready, which the model's pool is
        // by every `/dev/random` read (`memdev::read`). A pool not yet known
        // ready, which only the entropy fault leaves after a nonblocking
        // `getrandom`, still polls readable here.
        FdKind::MemDevice
            if matches!(
                crate::memdev::MemDevice::of_handle(handle),
                crate::memdev::MemDevice::Random
            ) =>
        {
            (POLLIN | POLLRDNORM, (0, 0))
        }
        // `DEFAULT_POLLMASK`: files and devices are always ready (and
        // cannot be registered with epoll at all: `EPERM` at
        // `epoll_ctl`).
        FdKind::File | FdKind::Dir | FdKind::OPath | FdKind::MemDevice => {
            (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, (0, 0))
        }
        // An nsfs inode has no poll method either, nor has a procfs node
        // (`proc_reg_poll` answers the default for a file without one).
        #[cfg(target_os = "linux")]
        FdKind::Namespace | FdKind::NamespacePath | FdKind::Proc | FdKind::ProcDir => {
            (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, (0, 0))
        }
        // `timerfd_poll`: readable while an expiration is unread; every
        // firing is an arrival.
        #[cfg(target_os = "linux")]
        FdKind::TimerFd => {
            let (readable, fires) = timers::timerfd_poll(state, handle);
            (if readable { POLLIN | POLLRDNORM } else { 0 }, (fires, 0))
        }
        // `inotify_poll`: readable while an event is queued; every queued
        // event is an arrival.
        #[cfg(target_os = "linux")]
        FdKind::Inotify => {
            let (readable, arrivals) = inotify::poll(state, handle);
            (
                if readable { POLLIN | POLLRDNORM } else { 0 },
                (arrivals, 0),
            )
        }
        #[cfg(target_os = "linux")]
        FdKind::Epoll => (0, (0, 0)),
        // `pidfd_poll`: readable once the process's thread group has
        // exited, which a process never sees of itself or of init.
        #[cfg(target_os = "linux")]
        FdKind::Pidfd => (0, (0, 0)),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => (0, (0, 0)),
    }
}

/// `pipe_poll`: the read side is readable while bytes are queued and hung
/// up once no writer is left; the write side is writable while there is
/// room and in error once no reader is left.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
fn pipe_poll(state: &ThreadRuntime, fd: c_int) -> (u32, (u64, u64)) {
    use net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    let Some(end) = state.net.pipe_ends.get(&fd) else {
        return (POLLERR | POLLHUP, (0, 0));
    };
    let read = end
        .read_channel
        .and_then(|id| state.net.pipe_channels.get(&id));
    let write = end
        .write_channel
        .and_then(|id| state.net.pipe_channels.get(&id));
    let mut mask = 0;
    if let Some(channel) = read {
        if !channel.buffer.is_empty() {
            mask |= POLLIN | POLLRDNORM;
        }
        if channel.write_closed() {
            mask |= POLLHUP;
        }
    }
    if let Some(channel) = write {
        if channel.buffer.len() < channel.capacity {
            mask |= POLLOUT | POLLWRNORM;
        }
        if channel.read_closed() {
            mask |= POLLERR;
        }
    }
    let seqs = (
        read.map_or(0, |channel| channel.read_events),
        write.map_or(0, |channel| channel.write_events),
    );
    (mask, seqs)
}

/// One source a readiness fan-in park watches: direction `dir` on what guest
/// number `fd` names, or, for an interest that retains the description it was
/// registered against (epoll's `(fd, struct file)` key), on `desc` whatever
/// the number names now, as [`fd_poll`] reads it.
#[cfg(any(target_os = "linux", patina_posix_exports))]
#[derive(Clone, Copy)]
pub(super) struct Watched {
    pub(super) dir: ReadyDir,
    pub(super) fd: c_int,
    pub(super) desc: Option<DescId>,
}

/// A readiness direction to watch on a virtual descriptor. Deliberately
/// reactor-neutral (not an `EVFILT_*`/`EPOLL*` value): the OS-agnostic fan-in
/// core below is shared by the kqueue (macOS) and epoll (Linux) frontends.
#[cfg(any(target_os = "linux", patina_posix_exports))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadyDir {
    Read,
    Write,
}

/// Where a task parked on a readiness fan-in enqueued itself, so it can be
/// unlinked on resume regardless of which source woke it. Reactor-neutral: a
/// kqueue or epoll frontend both watch the same virtual pipe/socket queues.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy)]
pub(super) enum WaiterLoc {
    PipeOpen(u64),
    Futex(usize),
    Mutex(usize),
    RwRead(usize),
    RwWrite(usize),
    Cond(usize, usize),
    Join(TaskId),
    PipeRecv(u64),
    PipeSend(u64),
    SockRecv(c_int),
    SockSend(c_int),
    /// Linux: parked on an eventfd's readable queue (an eventfd is always
    /// writable, so there is no write-direction queue).
    #[cfg(target_os = "linux")]
    EventFdRecv(c_int),
    #[cfg(target_os = "linux")]
    SignalFdRecv(u64),
    /// Linux: parked on a System V IPC object's wait queue.
    #[cfg(target_os = "linux")]
    Ipc(ipc::IpcWait),
    /// Linux: parked on a timer descriptor's readers.
    #[cfg(target_os = "linux")]
    TimerFdRecv(u64),
    /// Parked in `F_SETLKW` on a record or OFD lock.
    RecordLock,
    /// Linux: parked on an inotify instance's readers.
    #[cfg(target_os = "linux")]
    InotifyRecv(u64),
    /// macOS: parked in `kevent` on a kqueue, woken by an `EVFILT_USER`
    /// trigger or a registration change.
    #[cfg(all(target_os = "macos", patina_posix_exports))]
    KqueueWait(u64),
    /// Linux: parked in `epoll_wait` on an epoll instance, woken by a
    /// registration change.
    #[cfg(target_os = "linux")]
    EpollWait(u64),
    /// macOS: parked on a libdispatch semaphore, which the waiter decremented
    /// on entry. Unlinking it (only an expiry does) restores that count.
    #[cfg(target_os = "macos")]
    Dispatch(usize),
}

impl WaiterLoc {
    /// Whether a wait parked here answers its expiry as a timeout
    /// (`ETIMEDOUT`): a condition, futex, IPC or dispatch-semaphore wait.
    pub(super) fn times_out(&self) -> bool {
        match self {
            WaiterLoc::Cond(..) | WaiterLoc::Futex(..) => true,
            #[cfg(target_os = "linux")]
            WaiterLoc::Ipc(..) => true,
            #[cfg(target_os = "macos")]
            WaiterLoc::Dispatch(..) => true,
            _ => false,
        }
    }
}

/// Register `me` on the waiter queue of every watched `(direction, fd)`
/// source, returning the locations to unlink on resume. This is the reusable
/// multi-fd fan-in primitive a readiness reactor parks on: the frontend
/// supplies the watched set (guest numbers) from its OWN registry, so no
/// reactor-specific keying (kqueue `(ident, filter)`, epoll interest masks)
/// leaks into the shared core. The readiness sources — pipe channels and
/// SimNet socket queues — and the readiness predicate [`fd_readiness`] are
/// equally neutral. A number that names nothing waitable (closed, or a
/// kind that is always ready) registers no waiter: its readiness is
/// already decided.
///
/// A waiter queue only hears other tasks' calls. A socket's next in-flight
/// segment becomes readable when virtual time reaches its delivery, with no
/// call to wake anyone, so the registration also carries the earliest such
/// delivery among the watched sockets, and the park ends there
/// ([`ReadinessWait::bounded`]).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(super) fn register_readiness_waiters(
    state: &mut ThreadRuntime,
    me: TaskId,
    watched: &[Watched],
) -> ReadinessWait {
    let mut wait = Wait::new(BlockClass::Readiness, Vec::new());
    let mut next_arrival: Option<u64> = None;
    for &Watched {
        dir,
        fd: guest_fd,
        desc,
    } in watched
    {
        let Some((kind, handle, _)) = resolve_source(guest_fd, desc) else {
            continue;
        };
        let fd = handle as c_int;
        // Eventfd (Linux): only the readable direction has a queue; a write
        // watch needs no waiter because an eventfd is always writable.
        #[cfg(target_os = "linux")]
        if kind == FdKind::SignalFd {
            if dir == ReadyDir::Read
                && let Some(fd) = state.signals.signalfds.get_mut(&handle)
            {
                wait.enqueue(&mut fd.waiters, me, WaiterLoc::SignalFdRecv(handle));
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if kind == FdKind::TimerFd {
            if dir == ReadyDir::Read {
                timers::timerfd_watch(state, handle, me, &mut wait);
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if kind == FdKind::Inotify {
            if dir == ReadyDir::Read {
                inotify::watch(state, handle, me, &mut wait);
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if kind == FdKind::EventFd {
            if dir == ReadyDir::Read
                && let Some(efd) = state.net.eventfds.get_mut(&fd)
            {
                wait.enqueue(&mut efd.read_waiters, me, WaiterLoc::EventFdRecv(fd));
            }
            continue;
        }
        if kind == FdKind::Pipe {
            let Some(end) = state.net.pipe_ends.get(&fd) else {
                continue;
            };
            let channel = match dir {
                ReadyDir::Read => end.read_channel,
                ReadyDir::Write => end.write_channel,
            };
            if let Some(channel) = channel
                && let Some(ch) = state.net.pipe_channels.get_mut(&channel)
            {
                match dir {
                    ReadyDir::Read => {
                        wait.enqueue(&mut ch.recv_waiters, me, WaiterLoc::PipeRecv(channel));
                    }
                    ReadyDir::Write => {
                        wait.enqueue(&mut ch.send_waiters, me, WaiterLoc::PipeSend(channel));
                    }
                }
            }
        } else if kind == FdKind::Socket {
            if dir == ReadyDir::Read {
                let arrival = net::socket_next_arrival(state, fd).unwrap_or_else(|errno| {
                    fatal(&format!(
                        "a readiness park could not read when socket {guest_fd}'s next \
                         delivery arrives (errno {errno}); failing closed"
                    ))
                });
                next_arrival = earliest(next_arrival, arrival);
            }
            let Some(socket) = state.net.sockets.table.get_mut(&fd) else {
                continue;
            };
            match dir {
                ReadyDir::Read => {
                    wait.enqueue(&mut socket.recv_waiters, me, WaiterLoc::SockRecv(fd));
                }
                ReadyDir::Write => {
                    wait.enqueue(&mut socket.send_waiters, me, WaiterLoc::SockSend(fd));
                }
            }
        }
    }
    ReadinessWait { wait, next_arrival }
}

/// A readiness fan-in registration ([`register_readiness_waiters`]): the
/// waiter queues it joined and the earliest delivery in flight to a watched
/// socket.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(super) struct ReadinessWait {
    wait: Wait,
    next_arrival: Option<u64>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
impl ReadinessWait {
    /// The wait to park on and the deadline it parks until: the caller's own
    /// `deadline` (its timeout, a reactor timer) or the next delivery to a
    /// watched socket, whichever comes first. A park that ends at a delivery
    /// is no timeout; the caller rescans and finds the socket ready.
    pub(super) fn bounded(self, deadline: Option<u64>) -> (Wait, Option<u64>) {
        (self.wait, earliest(deadline, self.next_arrival))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(any(target_os = "linux", patina_posix_exports))]
fn earliest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Unlink `me` from every queue [`register_readiness_waiters`] enqueued it on,
/// so a later wake of that queue never targets an already-resumed task.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn unregister_waiters(state: &mut ThreadRuntime, me: TaskId, locs: &[WaiterLoc]) {
    let remove = |queue: &mut WaitQueue<VecDeque<TaskId>>| {
        if let Some(index) = queue.iter().position(|task| *task == me) {
            queue.remove(index);
        }
    };
    for loc in locs {
        match *loc {
            WaiterLoc::PipeOpen(channel) => {
                if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                    remove(&mut ch.open_waiters);
                }
            }
            WaiterLoc::Futex(address) => {
                if let Some(queue) = state.futexes.get_mut(&address) {
                    if let Some(index) = queue.iter().position(|waiter| waiter.task == me) {
                        queue.remove(index);
                    }
                    if queue.is_empty() {
                        state.futexes.remove(&address);
                    }
                }
            }
            WaiterLoc::Mutex(key) => {
                if let Some(entry) = state.table.mutexes.get_mut(&key)
                    && let Some(index) = entry.waiters.iter().position(|task| *task == me)
                {
                    entry.waiters.remove(index);
                }
            }
            WaiterLoc::RwRead(key) | WaiterLoc::RwWrite(key) => {
                if let Some(entry) = state.table.rwlocks.get_mut(&key) {
                    let queue = if matches!(loc, WaiterLoc::RwRead(_)) {
                        &mut entry.read_waiters
                    } else {
                        &mut entry.write_waiters
                    };
                    if let Some(index) = queue.iter().position(|task| *task == me) {
                        queue.remove(index);
                    }
                }
            }
            WaiterLoc::Cond(cond, mutex) => {
                if let Some(entry) = state.table.conds.get_mut(&cond)
                    && let Some(index) = entry.waiters.iter().position(|(task, _)| *task == me)
                {
                    entry.waiters.remove(index);
                }
                unregister_waiters(state, me, &[WaiterLoc::Mutex(mutex)]);
            }
            WaiterLoc::Join(target) => {
                if let Some(entry) = state.table.threads.get_mut(&target)
                    && *entry.joiner == Some(me)
                {
                    entry.joiner.take();
                }
            }
            WaiterLoc::PipeRecv(channel) => {
                if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                    remove(&mut ch.recv_waiters);
                }
            }
            WaiterLoc::PipeSend(channel) => {
                if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                    remove(&mut ch.send_waiters);
                }
            }
            WaiterLoc::SockRecv(fd) => {
                if let Some(socket) = state.net.sockets.table.get_mut(&fd) {
                    remove(&mut socket.recv_waiters);
                }
            }
            WaiterLoc::SockSend(fd) => {
                if let Some(socket) = state.net.sockets.table.get_mut(&fd) {
                    remove(&mut socket.send_waiters);
                }
            }
            #[cfg(target_os = "linux")]
            WaiterLoc::SignalFdRecv(handle) => {
                if let Some(fd) = state.signals.signalfds.get_mut(&handle) {
                    remove(&mut fd.waiters);
                }
            }
            #[cfg(target_os = "linux")]
            WaiterLoc::EventFdRecv(fd) => {
                if let Some(efd) = state.net.eventfds.get_mut(&fd) {
                    remove(&mut efd.read_waiters);
                }
            }
            #[cfg(target_os = "linux")]
            WaiterLoc::Ipc(wait) => state.ipc.unwait(wait, me),
            #[cfg(target_os = "linux")]
            WaiterLoc::TimerFdRecv(handle) => timers::timerfd_unwatch(state, handle, me),
            WaiterLoc::RecordLock => locks::unwait(state, me),
            #[cfg(target_os = "linux")]
            WaiterLoc::InotifyRecv(handle) => inotify::unwatch(state, handle, me),
            #[cfg(all(target_os = "macos", patina_posix_exports))]
            WaiterLoc::KqueueWait(id) => kqueue::unwait(state, id, me),
            #[cfg(target_os = "linux")]
            WaiterLoc::EpollWait(id) => epoll::unwait(state, id, me),
            #[cfg(target_os = "macos")]
            WaiterLoc::Dispatch(key) => {
                if let Some(sem) = state.dispatch.get_mut(&key)
                    && let Some(index) = sem.waiters.iter().position(|task| *task == me)
                {
                    sem.waiters.remove(index);
                    // Keep a negative count equal to the live waiter total.
                    sem.count += 1;
                }
            }
        }
    }
}

// ------------------------------------------------------------------
// epoll readiness reactor (Linux) — the mirror of `mod kqueue` above over
// the same OS-agnostic readiness core (`fd_poll`,
// `register_readiness_waiters`). An epoll instance is a description in the
// descriptor table; `epoll_ctl` keeps one interest per watched fd (epoll
// semantics) over every pollable descriptor kind; `epoll_wait` gathers
// ready events — parking on the scheduler baton with multi-fd fan-in when
// nothing is ready, bounded by the millisecond timeout on the virtual
// clock and the next delivery in flight to a watched socket, and woken by a
// registration change as well as by its sources. mio's `Waker` analogue
// needs no epoll-specific wake path: it is an ordinary watched eventfd
// whose write drains the shared read-waiter queue.
//
// Delivery follows fs/eventpoll.c: a ready list (`ep->rdllist`) that an
// interest joins at the tail when its source wakes it, from which
// `epoll_wait` delivers each item's poll mask read through its events,
// re-queuing a level-triggered item at the tail and dropping an
// edge-triggered one until its next wakeup. The model observes wakeups
// through each source's per-direction ARRIVAL SEQUENCES (a datagram, a
// write, an eventfd add — every arrival is a wakeup, as `ep_poll_callback`
// sees it) and through watched conditions rising (a hang-up, an error,
// room to write). Everything here is deterministic GIVEN the recorded
// schedule and carries NO trace events; only the scheduler parks/wakes are
// recorded.
