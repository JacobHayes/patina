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
// READ/WRITE knote fires on the not-ready -> ready transition and re-arms once
// readiness drops, so a level condition (e.g. a peer-closed EV_EOF that stays
// set) fires exactly once rather than busy-looping the reactor. Returned
// events are ordered by `(ident, filter)` — the `BTreeMap` key order — so the
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

/// A descriptor's kernel poll mask (`EPOLL*` bits, [`net::abi`]'s
/// `POLL*`) and its per-direction arrival sequences, for the readiness
/// reactors: what the object's poll function answers now, computed
/// without consuming anything or recording a boundary op. `desc`, when
/// given, is the description an interest was registered against, which is
/// what is polled even if the number now names another one (the kernel's
/// `(fd, struct file)` interest key). `None` for a number that names
/// nothing.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn fd_poll(
    state: &ThreadRuntime,
    fd: c_int,
    desc: Option<DescId>,
) -> Option<(u32, (u64, u64))> {
    let (kind, handle, status) = match desc {
        Some(desc) => {
            let table = super::fd_table().lock();
            let description = table.description(desc)?;
            (description.kind, description.handle, description.status)
        }
        None => {
            let resolved = super::fd_table().lock().resolve(fd)?;
            (resolved.kind, resolved.handle, resolved.status)
        }
    };
    Some(poll_description(state, kind, handle, status))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn poll_description(
    state: &ThreadRuntime,
    kind: FdKind,
    handle: u64,
    // The description's status flags: a userfaultfd's poll reads its
    // `O_NONBLOCK`.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] status: u32,
) -> (u32, (u64, u64)) {
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
        // Standard input is at end of file.
        FdKind::Stdin => (POLLIN | POLLRDNORM | POLLHUP, (0, 0)),
        // The captured streams always accept bytes.
        FdKind::Stdout | FdKind::Stderr => (POLLOUT | POLLWRNORM, (0, 0)),
        // `DEFAULT_POLLMASK`: files and devices are always ready (and
        // cannot be registered with epoll at all: `EPERM` at
        // `epoll_ctl`).
        FdKind::File | FdKind::Dir | FdKind::OPath | FdKind::Urandom => {
            (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, (0, 0))
        }
        // An nsfs inode has no poll method either.
        #[cfg(target_os = "linux")]
        FdKind::Namespace | FdKind::NamespacePath => {
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
        // A ruleset has no poll method: `DEFAULT_POLLMASK`, and `EPERM`
        // at `epoll_ctl`, as for a file.
        #[cfg(target_os = "linux")]
        FdKind::LandlockRuleset => (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, (0, 0)),
        #[cfg(target_os = "linux")]
        FdKind::Userfaultfd => (
            crate::mem::userfaultfd::poll(handle, status & super::O_NONBLOCK != 0),
            (0, 0),
        ),
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => {
            let (readable, writable) = ipc::mq_readiness(state, handle);
            let mut mask = 0;
            if readable {
                mask |= POLLIN | POLLRDNORM;
            }
            if writable {
                mask |= POLLOUT | POLLWRNORM;
            }
            (mask, ipc::mq_event_seqs(state, handle))
        }
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster => pty::poll(state, pty::Side::Master, handle as u32),
        #[cfg(target_os = "linux")]
        FdKind::PtySlave => pty::poll(state, pty::Side::Slave, handle as u32),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => (0, (0, 0)),
    }
}

/// `pipe_poll`: the read side is readable while bytes are queued and hung
/// up once no writer is left; the write side is writable while there is
/// room and in error once no reader is left.
#[cfg(any(target_os = "macos", target_os = "linux"))]
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
    #[cfg(target_os = "linux")]
    let seqs = (
        read.map_or(0, |channel| channel.read_events),
        write.map_or(0, |channel| channel.write_events),
    );
    #[cfg(target_os = "macos")]
    let seqs = (0, 0);
    (mask, seqs)
}

/// A readiness direction to watch on a virtual descriptor. Deliberately
/// reactor-neutral (not an `EVFILT_*`/`EPOLL*` value): the OS-agnostic fan-in
/// core below is shared by the kqueue (macOS) and epoll (Linux) frontends.
#[cfg(any(target_os = "macos", target_os = "linux"))]
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
    /// Linux: parked on a pseudoterminal side's readers.
    #[cfg(target_os = "linux")]
    Pty(u32, pty::Side),
    /// Parked in `F_SETLKW` on a record or OFD lock.
    RecordLock,
    /// Linux: parked on an inotify instance's readers.
    #[cfg(target_os = "linux")]
    InotifyRecv(u64),
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn register_readiness_waiters(
    state: &mut ThreadRuntime,
    me: TaskId,
    watched: &[(ReadyDir, c_int)],
) -> Vec<WaiterLoc> {
    let mut locs = Vec::new();
    for &(dir, guest_fd) in watched {
        let Some(resolved) = super::fd_table().lock().resolve(guest_fd) else {
            continue;
        };
        let fd = resolved.handle as c_int;
        // Eventfd (Linux): only the readable direction has a queue; a write
        // watch needs no waiter because an eventfd is always writable.
        #[cfg(target_os = "linux")]
        if resolved.kind == FdKind::SignalFd {
            if dir == ReadyDir::Read
                && let Some(fd) = state.signals.signalfds.get_mut(&resolved.handle)
            {
                fd.waiters.push_back(me);
                locs.push(WaiterLoc::SignalFdRecv(resolved.handle));
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if resolved.kind == FdKind::MessageQueue {
            if let Some(loc) = ipc::mq_watch(state, resolved.handle, me, dir == ReadyDir::Read) {
                locs.push(loc);
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if resolved.kind == FdKind::TimerFd {
            if dir == ReadyDir::Read {
                locs.extend(timers::timerfd_watch(state, resolved.handle, me));
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        if resolved.kind == FdKind::Inotify {
            if dir == ReadyDir::Read {
                locs.extend(inotify::watch(state, resolved.handle, me));
            }
            continue;
        }
        #[cfg(target_os = "linux")]
        // One queue per side: a pair wakes its writers too (an
        // edge-triggered interest in output waits for that).
        if let Some(side) = pty::Side::of(resolved.kind) {
            locs.extend(pty::watch(state, side, resolved.handle as u32, me));
            continue;
        }
        #[cfg(target_os = "linux")]
        if resolved.kind == FdKind::EventFd {
            if dir == ReadyDir::Read
                && let Some(efd) = state.net.eventfds.get_mut(&fd)
            {
                efd.read_waiters.push_back(me);
                locs.push(WaiterLoc::EventFdRecv(fd));
            }
            continue;
        }
        if resolved.kind == FdKind::Pipe {
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
                        ch.recv_waiters.push_back(me);
                        locs.push(WaiterLoc::PipeRecv(channel));
                    }
                    ReadyDir::Write => {
                        ch.send_waiters.push_back(me);
                        locs.push(WaiterLoc::PipeSend(channel));
                    }
                }
            }
        } else if resolved.kind == FdKind::Socket {
            let Some(socket) = state.net.sockets.table.get_mut(&fd) else {
                continue;
            };
            match dir {
                ReadyDir::Read => {
                    socket.recv_waiters.push_back(me);
                    locs.push(WaiterLoc::SockRecv(fd));
                }
                ReadyDir::Write => {
                    socket.send_waiters.push_back(me);
                    locs.push(WaiterLoc::SockSend(fd));
                }
            }
        }
    }
    locs
}

/// Unlink `me` from every queue [`register_readiness_waiters`] enqueued it on,
/// so a later wake of that queue never targets an already-resumed task.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn unregister_waiters(state: &mut ThreadRuntime, me: TaskId, locs: &[WaiterLoc]) {
    let remove = |queue: &mut VecDeque<TaskId>| {
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
                    && entry.joiner == Some(me)
                {
                    entry.joiner = None;
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
            #[cfg(target_os = "linux")]
            WaiterLoc::Pty(index, side) => pty::unwatch(state, index, side, me),
            WaiterLoc::RecordLock => locks::unwait(state, me),
            #[cfg(target_os = "linux")]
            WaiterLoc::InotifyRecv(handle) => inotify::unwatch(state, handle, me),
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
// clock. mio's `Waker` analogue needs no epoll-specific wake path: it is an
// ordinary watched eventfd whose write drains the shared read-waiter
// queue.
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
