//! Deterministic anonymous pipes and FIFO channels.

use super::*;

// ------------------------------------------------------------------
// In-process pipe. Both endpoints of a `pipe`/`pipe2` (or of a FIFO) live
// inside this one guest process (the common case: an async
// runtime's IO-driver / signal self-pipe wakeup), so there is no cross-
// address-space escape — they are modeled as deterministic in-memory byte
// channels whose reads/writes are scheduler-visible, reusing the SAME baton /
// waiter machinery the virtual sockets use (block / switch_and_park / wake).
// Being pure in-process memory that only ever mutates while the acting task
// holds the baton, the transfer is deterministic GIVEN the schedule — exactly
// like the futex / mutex words — so it carries NO trace events of its own: the
// recorded scheduler steps already pin every interleaving, so record and
// flag-free replay converge on that. No host call is ever made.

/// A bounded, directed byte channel: writer endpoints feed it, reader
/// endpoints drain it. A `pipe` (or a FIFO) is a single channel.
pub(crate) struct PipeChannel {
    pub(crate) buffer: VecDeque<u8>,
    pub(crate) capacity: usize,
    /// Number of live fds referencing the READ side (one per reader endpoint,
    /// plus one per `dup`/`F_DUPFD` of one). The reader side is "closed" —
    /// `read_closed`, further writes get `EPIPE` — only when this hits 0.
    pub(crate) read_refs: usize,
    /// Number of live fds referencing the WRITE side. The writer side is
    /// "closed" — `write_closed`, drained reads return EOF — only at 0.
    pub(crate) write_refs: usize,
    /// Tasks parked in a blocking read, waiting for bytes to arrive.
    pub(in crate::thread) recv_waiters: WaitQueue<VecDeque<TaskId>>,
    /// Tasks parked in a blocking write, waiting for buffer space.
    pub(in crate::thread) send_waiters: WaitQueue<VecDeque<TaskId>>,
    /// Tasks parked in a blocking FIFO `open`, waiting for the opposite-end
    /// opener to arrive. One queue for both directions, as the kernel keeps
    /// one wait queue per pipe: a woken task re-checks its own condition.
    /// Always empty for an anonymous pipe, whose two ends exist at birth.
    pub(in crate::thread) open_waiters: WaitQueue<VecDeque<TaskId>>,
    /// How many times this channel has been opened for reading / for
    /// writing — Linux's `r_counter`/`w_counter`. A blocking open waits for
    /// the PARTNER COUNTER to move, not for the partner to still be there,
    /// so a writer that opens and closes again still releases a reader
    /// parked in `open(O_RDONLY)`.
    pub(crate) read_opens: u64,
    pub(crate) write_opens: u64,
    /// The deterministic-filesystem inode this channel belongs to when it
    /// backs a FIFO, so the last close can drop the inode → channel binding
    /// (a later `open` of the same FIFO then starts from an empty pipe,
    /// exactly as it does on a kernel that frees the pipe with its last fd).
    /// `None` for an anonymous `pipe` channel.
    pub(crate) fifo_ino: Option<u64>,
    /// Read-direction arrival sequence: bumped on every event that could
    /// newly satisfy a reader (bytes written, writer close). The epoll
    /// frontend's EPOLLET latch compares sequences so an edge re-fires per
    /// arrival — the kernel's semantics — even when readiness never dropped
    /// (a partially drained buffer). Linux-only: the kqueue frontend's
    /// EV_CLEAR latch re-arms only on a readiness drop.
    #[cfg(target_os = "linux")]
    pub(crate) read_events: u64,
    /// Write-direction sequence: bumped on space creation / reader close.
    #[cfg(target_os = "linux")]
    pub(crate) write_events: u64,
}

/// Real pipes carry a fixed-capacity kernel buffer (Linux's default is 64 KiB);
/// match it so a writer that outruns its reader parks on a full buffer exactly
/// as it would on the host, rather than buffering without bound.
const PIPE_CAPACITY: usize = 64 * 1024;
/// `PIPE_BUF`: the largest write a pipe takes whole or not at all.
#[cfg(target_os = "linux")]
pub(crate) const PIPE_BUF: usize = 4096;
#[cfg(target_os = "macos")]
pub(crate) const PIPE_BUF: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipeRead {
    Read(usize),
    Eof,
    WouldBlock,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipeWrite {
    Wrote(usize),
    BrokenPipe,
    WouldBlock,
}

impl PipeChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            capacity,
            // Every channel is created with exactly one reader endpoint and
            // one writer endpoint; `dup` raises the matching side later.
            read_refs: 1,
            write_refs: 1,
            recv_waiters: WaitQueue::new(),
            send_waiters: WaitQueue::new(),
            open_waiters: WaitQueue::new(),
            read_opens: 1,
            write_opens: 1,
            fifo_ino: None,
            #[cfg(target_os = "linux")]
            read_events: 0,
            #[cfg(target_os = "linux")]
            write_events: 0,
        }
    }

    /// The channel behind a FIFO inode. Unlike an anonymous pipe it is born
    /// with NO ends: every `open` of the FIFO adds one, and the rendezvous
    /// rules below decide when an open may proceed.
    pub(crate) fn new_fifo(capacity: usize, ino: u64) -> Self {
        Self {
            read_refs: 0,
            write_refs: 0,
            read_opens: 0,
            write_opens: 0,
            fifo_ino: Some(ino),
            ..Self::new(capacity)
        }
    }

    /// Every reader fd of this channel has closed: further writes get
    /// `EPIPE`. Derived from the reference count rather than latched,
    /// because a FIFO's reader side comes BACK when it is opened again.
    pub(crate) fn read_closed(&self) -> bool {
        self.read_refs == 0
    }

    /// Every writer fd has closed: drained reads return EOF. Derived for the
    /// same reason.
    pub(crate) fn write_closed(&self) -> bool {
        self.write_refs == 0
    }

    /// Pull up to `dst.len()` bytes. `WouldBlock` only when the buffer is empty
    /// and the writer is still open; drained + writer-closed is `Eof`.
    pub(crate) fn try_read(&mut self, dst: &mut [u8]) -> PipeRead {
        if !self.buffer.is_empty() {
            let count = dst.len().min(self.buffer.len());
            for (slot, byte) in dst[..count].iter_mut().zip(self.buffer.drain(..count)) {
                *slot = byte;
            }
            #[cfg(target_os = "linux")]
            {
                self.write_events = self.write_events.wrapping_add(1);
            }
            PipeRead::Read(count)
        } else if self.write_closed() {
            PipeRead::Eof
        } else {
            PipeRead::WouldBlock
        }
    }

    /// Push as many of `src`'s bytes as fit — all of them or none when
    /// there are at most `PIPE_BUF` (`pipe_write`'s atomic write).
    /// `WouldBlock` when they do not fit and the reader is open (the caller
    /// parks); a closed reader is `BrokenPipe` (the caller generates SIGPIPE
    /// before returning EPIPE).
    pub(crate) fn try_write(&mut self, src: &[u8]) -> PipeWrite {
        if self.read_closed() {
            return PipeWrite::BrokenPipe;
        }
        let space = self.capacity - self.buffer.len();
        if space == 0 || (src.len() <= PIPE_BUF && space < src.len()) {
            return PipeWrite::WouldBlock;
        }
        let count = src.len().min(space);
        self.buffer.extend(&src[..count]);
        #[cfg(target_os = "linux")]
        {
            self.read_events = self.read_events.wrapping_add(1);
        }
        PipeWrite::Wrote(count)
    }
}

/// One end of a pipe or FIFO. `read_channel`/`write_channel` name the
/// directed [`PipeChannel`]s this endpoint may drain / feed: a pipe end
/// holds one of them, a FIFO opened read-write both sides of its one.
pub(crate) struct PipeEnd {
    pub(crate) read_channel: Option<u64>,
    pub(crate) write_channel: Option<u64>,
    /// Set when this endpoint came from opening a FIFO rather than from
    /// `pipe`: the NODE it is open on. It is all the descriptor
    /// needs, because `fstat` asks the filesystem about that node — the
    /// node's own reference (taken at the first open, dropped with the last
    /// endpoint) is what keeps it answerable even after the last name for it
    /// is unlinked.
    fifo_ino: Option<u64>,
    /// The pipefs node an anonymous pipe end is on
    /// (`net.pipe_inodes`); `None` for a FIFO end, whose node is
    /// `fifo_ino`'s.
    inode: Option<u64>,
}

/// The node behind an anonymous pipe (both ends share one, on pipefs) or a
/// socket (each its own, on sockfs): what `fstat` reports, what
/// `fchmod` changes, and what the filesystem-level answers (`fstatfs`,
/// `syncfs`) are about. It holds no bytes — those are the channel's.
pub(crate) struct PipeInode {
    socket: bool,
    /// Permission bits: `0o600` for a pipe, `0o777` for a socket, as the
    /// kernel creates them; `fchmod` changes them.
    mode: u32,
    atime_nanos: u64,
    mtime_nanos: u64,
    ctime_nanos: u64,
    /// Endpoints naming this node; it is freed with the last.
    pub(crate) ends: usize,
}

/// The next number of the kernel's one counter of pseudo-filesystem
/// inodes (`get_next_ino`), which pipefs and sockfs nodes and a secure
/// anonymous inode (a userfaultfd's) all draw from.
#[cfg(target_os = "linux")]
pub(crate) fn next_inode_number() -> u64 {
    let mut state = lock_state();
    let ino = state.net.next_pipe_ino;
    state.net.next_pipe_ino = ino.wrapping_add(1);
    ino
}

/// Mint a pipefs/sockfs node stamped with the filesystem clock's now.
pub(super) fn mint_pipe_inode(
    state: &mut ThreadRuntime,
    socket: bool,
    now: u64,
    ends: usize,
) -> u64 {
    let ino = state.net.next_pipe_ino;
    state.net.next_pipe_ino = ino.wrapping_add(1);
    state.net.pipe_inodes.insert(
        ino,
        PipeInode {
            socket,
            mode: if socket { 0o777 } else { 0o600 },
            atime_nanos: now,
            mtime_nanos: now,
            ctime_nanos: now,
            ends,
        },
    );
    ino
}

/// The instant a new pipefs/sockfs node is stamped with: the time the
/// deterministic filesystem stamps its own entries with (0 before a runtime
/// is installed, which only a unit test reaches).
pub(crate) fn pipe_inode_time() -> u64 {
    super::fs_time_unrecorded()
}

/// The pipefs/sockfs node behind `fd` when it is an anonymous pipe end
/// or a socket.
fn anon_inode(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
    let resolved = class_entry(fd).ok()?;
    let handle = resolved.handle as c_int;
    match resolved.kind {
        FdKind::Pipe => state.net.pipe_ends.get(&handle)?.inode,
        FdKind::Socket => state
            .net
            .sockets
            .table
            .get(&handle)
            .map(|socket| socket.inode),
        _ => None,
    }
}

/// The pipefs/sockfs node behind `fd`, if it is an anonymous pipe end or
/// a socket: its metadata as `fstat` reports it.
pub(crate) fn pipe_inode_metadata(fd: c_int) -> Option<super::PatinaMetadata> {
    let state = lock_state();
    let ino = anon_inode(&state, fd)?;
    let inode = state.net.pipe_inodes.get(&ino)?;
    Some(super::PatinaMetadata {
        kind: if inode.socket {
            super::PATINA_ENTRY_SOCKET
        } else {
            super::PATINA_ENTRY_FIFO
        },
        mode: inode.mode,
        nlink: 1,
        fs: if inode.socket {
            super::PATINA_FS_SOCKFS
        } else {
            super::PATINA_FS_PIPEFS
        },
        rdev_major: 0,
        rdev_minor: 0,
        length: 0,
        blocks: 0,
        ino,
        atime: super::PatinaTimestamp::from_nanos(i128::from(inode.atime_nanos)),
        mtime: super::PatinaTimestamp::from_nanos(i128::from(inode.mtime_nanos)),
        ctime: super::PatinaTimestamp::from_nanos(i128::from(inode.ctime_nanos)),
        btime: super::PatinaTimestamp::default(),
    })
}

/// `fchmod` on an anonymous pipe end or a socket: the node's permission
/// bits change and its `ctime` moves. `None` for any other descriptor.
pub(crate) fn pipe_inode_set_mode(fd: c_int, mode: u32) -> Option<()> {
    let now = pipe_inode_time();
    let mut state = lock_state();
    let ino = anon_inode(&state, fd)?;
    let inode = state.net.pipe_inodes.get_mut(&ino)?;
    inode.mode = mode & 0o7777;
    inode.ctime_nanos = now;
    Some(())
}

/// Which filesystem a pipe-kind descriptor is on: a FIFO end is on the
/// deterministic volume, an anonymous pipe on pipefs. `None` for a number
/// that is not a pipe end.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_filesystem(fd: c_int) -> Option<u32> {
    let (end, _) = pipe_entry(fd).ok()?;
    let state = lock_state();
    let end = state.net.pipe_ends.get(&end)?;
    Some(match end.inode {
        None => super::PATINA_FS_VOLUME,
        Some(_) => super::PATINA_FS_PIPEFS,
    })
}

fn drain_channel_recv_waiters(state: &mut ThreadRuntime, channel: u64) -> Vec<TaskId> {
    state
        .net
        .pipe_channels
        .get_mut(&channel)
        .map(|channel| channel.recv_waiters.drain().collect())
        .unwrap_or_default()
}

fn drain_channel_send_waiters(state: &mut ThreadRuntime, channel: u64) -> Vec<TaskId> {
    state
        .net
        .pipe_channels
        .get_mut(&channel)
        .map(|channel| channel.send_waiters.drain().collect())
        .unwrap_or_default()
}

#[unsafe(no_mangle)]
/// Create a simplex pipe: `read_fd_out` is the read end, `write_fd_out` the
/// write end, both non-blocking when `nonblocking != 0` and close-on-exec
/// when `cloexec != 0`. The ends and the backing channel come from the class
/// handle / channel counters and the two guest numbers from the descriptor
/// table, so their numbering is a pure function of the schedule. Activates
/// the thread subsystem so a later blocking read/write can park via the baton.
///
/// # Safety
/// `read_fd_out`/`write_fd_out` must be writable.
pub unsafe extern "C" fn patina_pipe(
    read_fd_out: *mut c_int,
    write_fd_out: *mut c_int,
    nonblocking: c_int,
    cloexec: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if read_fd_out.is_null() || write_fd_out.is_null() {
        return super::fail(EINVAL);
    }
    let now = pipe_inode_time();
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return super::fail(c_int::from(error.into_posix()));
    }
    if let Err(errno) = super::fd_table().lock().ensure_free(2) {
        return super::fail(errno);
    }
    let inode = mint_pipe_inode(&mut state, false, now, 2);
    let channel = state.net.next_channel;
    state.net.next_channel = state.net.next_channel.wrapping_add(1);
    state
        .net
        .pipe_channels
        .insert(channel, PipeChannel::new(PIPE_CAPACITY));
    let read_end = next_handle(&mut state);
    let write_end = next_handle(&mut state);
    state.net.pipe_ends.insert(
        read_end,
        PipeEnd {
            read_channel: Some(channel),
            write_channel: None,
            fifo_ino: None,
            inode: Some(inode),
        },
    );
    state.net.pipe_ends.insert(
        write_end,
        PipeEnd {
            read_channel: None,
            write_channel: Some(channel),
            fifo_ino: None,
            inode: Some(inode),
        },
    );
    let nonblock = if nonblocking != 0 { O_NONBLOCK } else { 0 };
    // SAFETY: the out-pointers were checked non-null above.
    unsafe {
        bind_pipe_pair(
            &mut state,
            (read_end, O_READ | nonblock),
            (write_end, O_WRITE | nonblock),
            cloexec != 0,
            read_fd_out,
            write_fd_out,
        )
    }
}

/// Bind two freshly minted pipe ends to guest numbers, atomically. A full
/// table (`EMFILE`) releases both ends — through the ordinary close path,
/// so the channel is reclaimed — and creates nothing.
///
/// # Safety
/// `first_out`/`second_out` must be writable.
unsafe fn bind_pipe_pair(
    state: &mut ThreadRuntime,
    first: (c_int, u32),
    second: (c_int, u32),
    cloexec: bool,
    first_out: *mut c_int,
    second_out: *mut c_int,
) -> c_int {
    let bound = super::fd_table().lock().install_pair(
        FdKind::Pipe,
        (first.0 as u64, first.1),
        (second.0 as u64, second.1),
        cloexec,
    );
    match bound {
        Ok((a, b)) => {
            // SAFETY: per this function's contract.
            unsafe {
                first_out.write(a);
                second_out.write(b);
            }
            super::set_errno(0);
            0
        }
        Err(errno) => {
            // The fresh ends were never installed in the descriptor table.
            // Remove them under this existing ThreadRuntime guard; the normal
            // close helper would reacquire the same non-recursive lock.
            let first_end = state.net.pipe_ends.remove(&(first.0 as c_int));
            let second_end = state.net.pipe_ends.remove(&(second.0 as c_int));
            if let Some(channel) = first_end
                .as_ref()
                .and_then(|end| end.read_channel.or(end.write_channel))
                .or_else(|| {
                    second_end
                        .as_ref()
                        .and_then(|end| end.read_channel.or(end.write_channel))
                })
            {
                state.net.pipe_channels.remove(&channel);
            }
            if let Some(ino) = first_end
                .as_ref()
                .and_then(|end| end.inode)
                .or_else(|| second_end.as_ref().and_then(|end| end.inode))
            {
                state.net.pipe_inodes.remove(&ino);
            }
            super::fail(errno)
        }
    }
}

// ------------------------------------------------------------------
// Named pipes (FIFOs). A FIFO is a filesystem NAME (created by `mkfifo`,
// stat-able, renameable, unlinkable — all of that is deterministic
// filesystem state) whose BYTES are not filesystem state at all: they live
// in a pipe, exactly like an anonymous one's. So the entry lives in the
// driver and the transfer reuses the machinery above — one `PipeChannel`
// per open FIFO inode, the same waiter deques, the same `try_read`/
// `try_write`, the same EOF/`EPIPE` rules — instead of a second pipe model.
//
// What a FIFO adds is the rendezvous at OPEN, and it is modeled the way the
// kernel models it (`fs/pipe.c:fifo_open`): an open registers its end and
// bumps that side's open counter, wakes anything parked on the pipe, and
// then — unless it is `O_NONBLOCK` or `O_RDWR` — waits for the PARTNER
// counter to move. Waiting on the counter rather than on "a partner is
// currently there" is what makes a writer that opens and closes again still
// release a reader parked in `open(O_RDONLY)`.

/// Open the FIFO whose deterministic-filesystem inode is `ino`, returning a
/// virtual pipe-endpoint fd or -1 with `patina_errno` set.
///
/// The caller has already asked the filesystem about the entry, so
/// existence, path resolution, and the permission decision are settled
/// before this runs.
///
/// The first open of a FIFO takes a REFERENCE on its node, and the last
/// close of the channel drops it. That reference is the whole of the FIFO's
/// inode lifetime: a kernel keeps an inode alive while any descriptor holds
/// it, and these descriptors are the ones the filesystem itself has no
/// handle for — so without it, unlinking the last name would pull the node
/// out from under a perfectly live endpoint and `fstat` would answer for a
/// node nobody can name.
///
/// Blocking is a deterministic park through the same baton the pipe reads
/// and writes use, so under the cooperative scheduler another task's
/// `open(O_WRONLY)` is what wakes a reader parked here — and a FIFO nobody
/// ever opens for writing surfaces as the runtime's deadlock report rather
/// than a hung process.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(crate) fn fifo_open(
    ino: u64,
    path: &str,
    read: bool,
    write: bool,
    nonblocking: bool,
    status: u32,
    cloexec: bool,
) -> c_int {
    let me = current_task();
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return super::fail(c_int::from(error.into_posix()));
    }
    let existing = state.net.fifo_channels.get(&ino).copied();
    // `O_WRONLY|O_NONBLOCK` with no reader is `ENXIO`, and it is decided
    // BEFORE any bookkeeping: the call never becomes a writer, so it must
    // not leave a channel or an open count behind. No channel at all is the
    // same answer as a channel with no readers.
    if write && !read && nonblocking {
        let has_reader = existing
            .and_then(|channel| state.net.pipe_channels.get(&channel))
            .is_some_and(|channel| channel.read_refs > 0);
        if !has_reader {
            return super::fail(super::ENXIO);
        }
    }
    let opened_channel = existing.is_none();
    let channel_id = match existing {
        Some(channel) => channel,
        None => {
            let channel = state.net.next_channel;
            state.net.next_channel = state.net.next_channel.wrapping_add(1);
            state
                .net
                .pipe_channels
                .insert(channel, PipeChannel::new_fifo(PIPE_CAPACITY, ino));
            state.net.fifo_channels.insert(ino, channel);
            channel
        }
    };
    let channel = state
        .net
        .pipe_channels
        .get_mut(&channel_id)
        .expect("the channel was just resolved or created");
    if read {
        channel.read_refs += 1;
        channel.read_opens = channel.read_opens.wrapping_add(1);
    }
    if write {
        channel.write_refs += 1;
        channel.write_opens = channel.write_opens.wrapping_add(1);
    }
    // `O_RDWR` on a FIFO is its own partner, so it never waits — Linux
    // leaves this undefined and implements it exactly this way.
    let wait = if read && write {
        None
    } else if read {
        (channel.write_refs == 0 && !nonblocking).then_some((true, channel.write_opens))
    } else {
        // The non-blocking case already returned `ENXIO` above.
        (channel.read_refs == 0).then_some((false, channel.read_opens))
    };
    let woken: Vec<TaskId> = channel.open_waiters.drain().collect();
    let end = next_handle(&mut state);
    state.net.pipe_ends.insert(
        end,
        PipeEnd {
            read_channel: read.then_some(channel_id),
            write_channel: write.then_some(channel_id),
            fifo_ino: Some(ino),
            inode: None,
        },
    );
    // The guest number is reserved BEFORE the rendezvous, as the kernel's
    // `do_sys_openat2` takes its slot before the blocking `fifo_open` — so a
    // second open on another thread while this one waits numbers after it.
    let fd = match super::install_fd(FdKind::Pipe, end as u64, status, cloexec) {
        Ok(fd) => fd,
        Err(errno) => {
            drop(state);
            let _ = pipe_close_locked(end as u64);
            wake_all(woken);
            return super::fail(errno);
        }
    };
    drop(state);
    // The open holds the name it was opened through from here, before
    // any wait (`fifo_open` runs with the dentry held), so a rename or
    // unlink while it waits moves or unhashes that name.
    #[cfg(target_os = "linux")]
    crate::fsnotify::fifo_bound(end as u64, ino, path);
    // An open that fails lets its name go without a close event, then
    // closes through the ordinary path.
    let abandon = || {
        #[cfg(target_os = "linux")]
        crate::fsnotify::fifo_abandoned(end as u64);
        super::patina_close(fd);
    };
    // The channel is the node's one reference: taken when it comes into
    // existence, dropped when it is reclaimed. Outside the state lock, like
    // every other runtime call from this module.
    if opened_channel
        && let Err(errno) = super::with_context(|context| context.fs_retain_inode(ino))
    {
        abandon();
        wake_all(woken);
        return super::fail(errno);
    }
    wake_all(woken);

    if let Some((for_writer, seen)) = wait {
        loop {
            let mut state = lock_state();
            let Some(channel) = state.net.pipe_channels.get_mut(&channel_id) else {
                // Unreachable: this open holds a reference on the channel.
                break;
            };
            let satisfied = if for_writer {
                channel.write_refs > 0 || channel.write_opens != seen
            } else {
                channel.read_refs > 0 || channel.read_opens != seen
            };
            if satisfied {
                break;
            }
            let mut wait = Wait::new(BlockClass::Io, vec![]);
            wait.enqueue(
                &mut channel.open_waiters,
                me,
                WaiterLoc::PipeOpen(channel_id),
            );
            let reason = if for_writer {
                "fifo-open-read"
            } else {
                "fifo-open-write"
            };
            let step = state.block(me, reason, wait);
            match step {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => drop(state),
                Err(error) => {
                    let errno = c_int::from(error.into_posix());
                    drop(state);
                    // The descriptor never came into existence, so release
                    // the number and the end this open registered — through
                    // the ordinary close path, so the partner's EOF/`EPIPE`
                    // bookkeeping and the channel reclamation are the usual
                    // ones.
                    abandon();
                    return super::fail(errno);
                }
            }
            lock_state().timed_out.remove(&me);
            #[cfg(target_os = "linux")]
            if signals::resume() == signals::Resumed::Eintr {
                abandon();
                return super::fail(super::EINTR);
            }
        }
    }
    #[cfg(target_os = "linux")]
    crate::fsnotify::fifo_opened(end as u64);
    super::set_errno(0);
    fd
}

/// The bytes a pipe end's `FIONREAD` reports: what is queued
/// in the channel it reads (a pipe's write end, the pipe's one channel).
pub(crate) fn pipe_queued(handle: u64) -> Option<usize> {
    let state = lock_state();
    let end = state.net.pipe_ends.get(&(handle as c_int))?;
    let channel = end.read_channel.or(end.write_channel)?;
    state
        .net
        .pipe_channels
        .get(&channel)
        .map(|channel| channel.buffer.len())
}

/// What `fstat` should report for `fd` when it is a FIFO descriptor.
pub(crate) fn fifo_ino(fd: c_int) -> Option<u64> {
    let (end, _) = pipe_entry(fd).ok()?;
    fifo_end_ino(end as u64)
}

/// The FIFO node a pipe end (by its handle) was opened through, if any.
pub(crate) fn fifo_end_ino(end: u64) -> Option<u64> {
    lock_state()
        .net
        .pipe_ends
        .get(&(end as c_int))
        .and_then(|end| end.fifo_ino)
}

/// # Safety
/// `buf` must be writable for `len` bytes when nonzero.
pub(crate) unsafe fn pipe_read(
    handle: u64,
    nonblocking: bool,
    buf: *mut c_void,
    len: usize,
) -> isize {
    let fd = handle as c_int;
    if let Err(errno) = sched_point() {
        return super::fail(errno) as isize;
    }
    if len != 0 && buf.is_null() {
        return super::fail(EINVAL) as isize;
    }
    if len == 0 {
        return 0;
    }
    let me = current_task();
    loop {
        let mut state = lock_state();
        let channel = match state.net.pipe_ends.get(&fd) {
            // A read on the write-only end of a simplex pipe is EBADF (the end
            // is O_WRONLY), matching the kernel.
            Some(end) => match end.read_channel {
                Some(channel) => channel,
                None => return super::fail(super::EBADF) as isize,
            },
            None => return super::fail(super::EBADF) as isize,
        };
        // Reborrowed each iteration; only one `&mut` to the caller's buffer is
        // ever live (the previous is dropped when the iteration ends).
        let dst = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
        let outcome = state
            .net
            .pipe_channels
            .get_mut(&channel)
            .map(|channel| channel.try_read(dst))
            // A live endpoint always references a live channel.
            .unwrap_or(PipeRead::Eof);
        match outcome {
            PipeRead::Read(count) => {
                let waiters = drain_channel_send_waiters(&mut state, channel);
                drop(state);
                wake_all(waiters);
                return isize::try_from(count).unwrap_or(isize::MAX);
            }
            PipeRead::Eof => return 0,
            PipeRead::WouldBlock => {
                if nonblocking {
                    return super::fail(EWOULDBLOCK) as isize;
                }
                let mut wait = Wait::new(BlockClass::Io, vec![]);
                if let Some(queued) = state.net.pipe_channels.get_mut(&channel) {
                    wait.enqueue(&mut queued.recv_waiters, me, WaiterLoc::PipeRecv(channel));
                }
                let step = state.block(me, "pipe-read", wait);
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => return super::fail(c_int::from(error.into_posix())) as isize,
                }
                lock_state().timed_out.remove(&me);
                #[cfg(target_os = "linux")]
                if signals::resume() == signals::Resumed::Eintr {
                    return super::fail(super::EINTR) as isize;
                }
            }
        }
    }
}

/// # Safety
/// `buf` must be readable for `len` bytes when nonzero.
pub(crate) unsafe fn pipe_write(
    handle: u64,
    nonblocking: bool,
    buf: *const c_void,
    len: usize,
    nosignal: bool,
) -> isize {
    let fd = handle as c_int;
    if let Err(errno) = sched_point() {
        return super::fail(errno) as isize;
    }
    if len != 0 && buf.is_null() {
        return super::fail(EINVAL) as isize;
    }
    if len == 0 {
        return 0;
    }
    let src = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) };
    let me = current_task();
    // A blocking write returns once every byte is in (a signal or a
    // vanished reader ends it early with what went in); a nonblocking one
    // returns what fit.
    let mut written = 0;
    loop {
        let mut state = lock_state();
        let channel = match state.net.pipe_ends.get(&fd) {
            // A write on the read-only end of a simplex pipe is EBADF.
            Some(end) => match end.write_channel {
                Some(channel) => channel,
                None => return super::fail(super::EBADF) as isize,
            },
            None => return super::fail(super::EBADF) as isize,
        };
        let outcome = state
            .net
            .pipe_channels
            .get_mut(&channel)
            .map(|channel| channel.try_write(&src[written..]))
            .unwrap_or(PipeWrite::BrokenPipe);
        match outcome {
            PipeWrite::Wrote(count) => {
                written += count;
                let waiters = drain_channel_recv_waiters(&mut state, channel);
                drop(state);
                wake_all(waiters);
                if written == len || nonblocking {
                    return isize::try_from(written).unwrap_or(isize::MAX);
                }
            }
            PipeWrite::BrokenPipe => {
                drop(state);
                if !nosignal {
                    broken_pipe_signal();
                }
                if written > 0 {
                    return isize::try_from(written).unwrap_or(isize::MAX);
                }
                return super::fail(super::EPIPE) as isize;
            }
            PipeWrite::WouldBlock => {
                if nonblocking {
                    return super::fail(EWOULDBLOCK) as isize;
                }
                let mut wait = Wait::new(BlockClass::Io, vec![]);
                if let Some(queued) = state.net.pipe_channels.get_mut(&channel) {
                    wait.enqueue(&mut queued.send_waiters, me, WaiterLoc::PipeSend(channel));
                }
                let step = state.block(me, "pipe-write", wait);
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => return super::fail(c_int::from(error.into_posix())) as isize,
                }
                lock_state().timed_out.remove(&me);
                // `pipe_write`: a write a handler interrupts answers what it
                // wrote; only one that wrote nothing fails or restarts.
                #[cfg(target_os = "linux")]
                match signals::resume() {
                    signals::Resumed::Normal => {}
                    _ if written > 0 => return isize::try_from(written).unwrap_or(isize::MAX),
                    signals::Resumed::Eintr => return super::fail(super::EINTR) as isize,
                    signals::Resumed::Restart => {}
                }
            }
        }
    }
}

pub(crate) fn broken_pipe_signal() {
    #[cfg(target_os = "linux")]
    {
        // The channel lock must be released before the shared generation entry.
        let rc = unsafe {
            signals::generate_signal(
                signals::GenerationTarget::Thread {
                    tgid: Some(crate::patina_pid()),
                    tid: tid_of(current_task()),
                },
                signals::SIGPIPE,
                signals::GenerationInfo::User,
            )
        };
        if rc != 0 {
            fatal("SIGPIPE generation failed");
        }
        signals::deliver();
    }
}

// ------------------------------------------------------------------
// Splicing (`splice`, `tee`, `vmsplice`, and `sendfile`/`copy` into a
// pipe): the kernel moves bytes between a pipe and a file, or between two
// pipes, without a user copy. Here they are the SAME channel buffers the
// reads and writes above use, under the same baton park, so a splice is
// observable exactly as the equivalent read and write would be.

/// The pipe an endpoint belongs to — the one channel of an anonymous pipe
/// or a FIFO.
#[cfg(target_os = "linux")]
pub(crate) fn splice_pipe(handle: u64) -> Option<u64> {
    let state = lock_state();
    let end = state.net.pipe_ends.get(&(handle as c_int))?;
    end.read_channel.or(end.write_channel)
}

/// What a splice waits for on one pipe.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum PipeWant {
    /// Bytes to read, or the last writer gone.
    Data(u64),
    /// Room to write, or the last reader gone.
    Space(u64),
}

/// Park until every `want` is met — the ordinary pipe park, on each
/// channel's queue — or answer at once under `nonblocking` (`EAGAIN`).
/// A write side whose readers are all gone is `EPIPE`, raised as `SIGPIPE`
/// first. `Ok(false)` when a read side is empty with no writer left: there
/// is nothing to wait for.
#[cfg(target_os = "linux")]
fn pipe_await(wants: &[PipeWant], nonblocking: bool) -> Result<bool, c_int> {
    let me = current_task();
    loop {
        let mut state = lock_state();
        let mut locs = Vec::new();
        for want in wants {
            match *want {
                PipeWant::Data(channel) => {
                    let Some(ch) = state.net.pipe_channels.get(&channel) else {
                        return Ok(false);
                    };
                    if ch.buffer.is_empty() {
                        if ch.write_closed() {
                            return Ok(false);
                        }
                        locs.push(WaiterLoc::PipeRecv(channel));
                    }
                }
                PipeWant::Space(channel) => {
                    let Some(ch) = state.net.pipe_channels.get(&channel) else {
                        return Err(super::EPIPE);
                    };
                    if ch.read_closed() {
                        drop(state);
                        broken_pipe_signal();
                        return Err(super::EPIPE);
                    }
                    if ch.buffer.len() >= ch.capacity {
                        locs.push(WaiterLoc::PipeSend(channel));
                    }
                }
            }
        }
        if locs.is_empty() {
            return Ok(true);
        }
        if nonblocking {
            return Err(EWOULDBLOCK);
        }
        let mut wait = Wait::new(BlockClass::Io, vec![]);
        for loc in &locs {
            match *loc {
                WaiterLoc::PipeRecv(channel) => {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        wait.enqueue(&mut ch.recv_waiters, me, *loc);
                    }
                }
                WaiterLoc::PipeSend(channel) => {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        wait.enqueue(&mut ch.send_waiters, me, *loc);
                    }
                }
                _ => {}
            }
        }
        let step = state.block(me, "pipe-splice", wait);
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return Err(c_int::from(error.into_posix())),
        }
        let mut state = lock_state();
        state.timed_out.remove(&me);
        unregister_waiters(&mut state, me, &locs);
        drop(state);
        #[cfg(target_os = "linux")]
        if signals::resume() == signals::Resumed::Eintr {
            return Err(super::EINTR);
        }
    }
}

/// Wait until the pipe `handle` reads from has bytes (`Ok(0)`: none will
/// come, its last writer is gone).
#[cfg(target_os = "linux")]
pub(crate) fn pipe_await_data(handle: u64, nonblocking: bool) -> Result<usize, c_int> {
    sched_point()?;
    let channel = splice_pipe(handle).ok_or(super::EINVAL)?;
    if !pipe_await(&[PipeWant::Data(channel)], nonblocking)? {
        return Ok(0);
    }
    Ok(lock_state()
        .net
        .pipe_channels
        .get(&channel)
        .map_or(0, |channel| channel.buffer.len()))
}

/// Wait until the pipe `handle` writes to has room: the free bytes.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_await_space(handle: u64, nonblocking: bool) -> Result<usize, c_int> {
    sched_point()?;
    let channel = splice_pipe(handle).ok_or(super::EINVAL)?;
    pipe_await(&[PipeWant::Space(channel)], nonblocking)?;
    Ok(lock_state()
        .net
        .pipe_channels
        .get(&channel)
        .map_or(0, |channel| {
            channel.capacity.saturating_sub(channel.buffer.len())
        }))
}

/// Drain up to `max` bytes from the pipe `handle` belongs to, waking its
/// writers. Never waits.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_take(handle: u64, max: usize) -> Vec<u8> {
    let Some(channel) = splice_pipe(handle) else {
        return Vec::new();
    };
    let mut state = lock_state();
    let Some(ch) = state.net.pipe_channels.get_mut(&channel) else {
        return Vec::new();
    };
    let count = max.min(ch.buffer.len());
    let bytes: Vec<u8> = ch.buffer.drain(..count).collect();
    if !bytes.is_empty() {
        #[cfg(target_os = "linux")]
        {
            ch.write_events = ch.write_events.wrapping_add(1);
        }
    }
    let waiters = drain_channel_send_waiters(&mut state, channel);
    drop(state);
    wake_all(waiters);
    bytes
}

/// Put bytes a splice took back at the head of the pipe, ahead of anything
/// written since: the part of a transfer its destination did not accept.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_untake(handle: u64, bytes: &[u8]) {
    let Some(channel) = splice_pipe(handle) else {
        return;
    };
    let mut state = lock_state();
    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
        for byte in bytes.iter().rev() {
            ch.buffer.push_front(*byte);
        }
    }
}

/// Push as many of `bytes` as fit into the pipe `handle` belongs to,
/// waking its readers. Never waits.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_put(handle: u64, bytes: &[u8]) -> usize {
    let Some(channel) = splice_pipe(handle) else {
        return 0;
    };
    let mut state = lock_state();
    let written = match state
        .net
        .pipe_channels
        .get_mut(&channel)
        .map(|ch| ch.try_write(bytes))
    {
        Some(PipeWrite::Wrote(count)) => count,
        _ => 0,
    };
    let waiters = drain_channel_recv_waiters(&mut state, channel);
    drop(state);
    wake_all(waiters);
    written
}

/// `splice` between two pipes (`consume`) or `tee` (`!consume`): wait for
/// input and for room, then move — or copy — up to `len` bytes in one step.
/// `Ok(0)` when the input is empty with no writer left.
#[cfg(target_os = "linux")]
pub(crate) fn pipe_to_pipe(
    input: u64,
    output: u64,
    len: usize,
    nonblocking: bool,
    consume: bool,
) -> Result<usize, c_int> {
    sched_point()?;
    let (Some(from), Some(to)) = (splice_pipe(input), splice_pipe(output)) else {
        return Err(super::EINVAL);
    };
    if !pipe_await(&[PipeWant::Data(from), PipeWant::Space(to)], nonblocking)? {
        return Ok(0);
    }
    let mut state = lock_state();
    let available = state
        .net
        .pipe_channels
        .get(&from)
        .map_or(0, |ch| ch.buffer.len());
    let room = state
        .net
        .pipe_channels
        .get(&to)
        .map_or(0, |ch| ch.capacity.saturating_sub(ch.buffer.len()));
    let count = len.min(available).min(room);
    let bytes: Vec<u8> = match state.net.pipe_channels.get_mut(&from) {
        Some(ch) if consume => {
            #[cfg(target_os = "linux")]
            {
                ch.write_events = ch.write_events.wrapping_add(1);
            }
            ch.buffer.drain(..count).collect()
        }
        Some(ch) => ch.buffer.iter().take(count).copied().collect(),
        None => Vec::new(),
    };
    if let Some(ch) = state.net.pipe_channels.get_mut(&to) {
        ch.try_write(&bytes);
    }
    let mut waiters = drain_channel_recv_waiters(&mut state, to);
    if consume {
        waiters.extend(drain_channel_send_waiters(&mut state, from));
    }
    drop(state);
    wake_all(waiters);
    Ok(count)
}

/// Free a pipe endpoint whose description's last reference went
/// (the universal `patina_close` path). A channel SIDE closes — waking the
/// peer with EPIPE (readers gone) or EOF (writers gone) — only on the LAST
/// endpoint of that side; a dup'd number never reaches here until it is the
/// last one.
pub(crate) fn pipe_close(handle: u64) -> Result<(), c_int> {
    pipe_close_locked(handle)
}

fn pipe_close_locked(handle: u64) -> Result<(), c_int> {
    let fd = handle as c_int;
    let mut state = lock_state();
    let Some(end) = state.net.pipe_ends.remove(&fd) else {
        return Err(super::EBADF);
    };
    if let Some(ino) = end.inode
        && let Some(inode) = state.net.pipe_inodes.get_mut(&ino)
    {
        inode.ends -= 1;
        if inode.ends == 0 {
            state.net.pipe_inodes.remove(&ino);
        }
    }
    let mut waiters = Vec::new();
    let mut released_ino = None;
    // Dropping a READER reference: writers get EPIPE only once the last one
    // goes, and only then are blocked writers woken to observe it.
    if let Some(channel) = end.read_channel
        && let Some(channel) = state.net.pipe_channels.get_mut(&channel)
    {
        channel.read_refs -= 1;
        if channel.read_refs == 0 {
            #[cfg(target_os = "linux")]
            {
                channel.write_events = channel.write_events.wrapping_add(1);
            }
            waiters.extend(channel.send_waiters.drain());
        }
    }
    // Dropping a WRITER reference: readers see EOF (once drained) only after
    // the last writer closes, and only then are blocked readers woken.
    if let Some(channel) = end.write_channel
        && let Some(channel) = state.net.pipe_channels.get_mut(&channel)
    {
        channel.write_refs -= 1;
        if channel.write_refs == 0 {
            #[cfg(target_os = "linux")]
            {
                channel.read_events = channel.read_events.wrapping_add(1);
            }
            waiters.extend(channel.recv_waiters.drain());
        }
    }
    // Reclaim any channel with no references left on either side. Channel ids
    // come from a monotonic counter and are never reused, so no stale entry
    // can survive.
    for channel in [end.read_channel, end.write_channel].into_iter().flatten() {
        let drained = state
            .net
            .pipe_channels
            .get(&channel)
            .is_some_and(|channel| channel.read_refs == 0 && channel.write_refs == 0);
        if drained {
            let reclaimed = state.net.pipe_channels.remove(&channel);
            // A FIFO channel is the pipe BEHIND a name, not the name: with
            // its last fd gone the buffered bytes go too, and the next
            // `open` of the same FIFO mints a fresh empty channel. Exactly
            // what a kernel does when a pipe's last reference drops.
            if let Some(ino) = reclaimed.and_then(|channel| channel.fifo_ino) {
                state.net.fifo_channels.remove(&ino);
                released_ino = Some(ino);
            }
        }
    }
    drop(state);
    // The last endpoint on a FIFO's channel drops the node's reference; if
    // its last name went first, that is where the node is finally freed.
    if let Some(ino) = released_ino
        && let Err(errno) = super::with_context(|context| context.fs_release_inode(ino))
    {
        wake_all(waiters);
        return Err(errno);
    }
    wake_all(waiters);
    Ok(())
}

/// The largest pipe buffer an unprivileged `F_SETPIPE_SZ` may ask for
/// (`fs.pipe-max-size`).
const PIPE_MAX_SIZE: usize = crate::registry::KERNEL_CONFIG.pipe_max_size as usize;
const PIPE_PAGE: usize = 4096;

/// The channel a pipe endpoint's `F_GETPIPE_SZ`/`F_SETPIPE_SZ` act on: the
/// pipe's one channel.
fn pipe_size_channel(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
    let end = state.net.pipe_ends.get(&fd)?;
    end.write_channel.or(end.read_channel)
}

#[unsafe(no_mangle)]
/// `fcntl(F_GETPIPE_SZ)`: the endpoint's buffer capacity; `EINVAL` for a
/// description that is not a pipe end.
pub extern "C" fn patina_pipe_size(guest_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let end = match class_entry(guest_fd) {
        Ok(resolved) if resolved.kind == FdKind::Pipe => resolved.handle as c_int,
        Ok(_) => return super::fail(EINVAL),
        Err(errno) => return super::fail(errno),
    };
    let state = lock_state();
    let capacity = pipe_size_channel(&state, end)
        .and_then(|channel| state.net.pipe_channels.get(&channel))
        .map(|channel| channel.capacity);
    match capacity {
        Some(capacity) => {
            super::set_errno(0);
            c_int::try_from(capacity).unwrap_or_else(|_| super::fail(super::EOVERFLOW))
        }
        None => super::fail(super::EBADF),
    }
}

#[unsafe(no_mangle)]
/// `fcntl(F_SETPIPE_SZ)`: resize the buffer the way `fs/pipe.c:round_pipe_size`
/// does — at least one page, rounded up to a power of two, at most the
/// unprivileged maximum (`EPERM` above it) — and refuse (`EBUSY`) to shrink
/// below the bytes currently buffered. Returns the new capacity.
pub extern "C" fn patina_pipe_set_size(guest_fd: c_int, size: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let end = match class_entry(guest_fd) {
        Ok(resolved) if resolved.kind == FdKind::Pipe => resolved.handle as c_int,
        Ok(_) => return super::fail(EINVAL),
        Err(errno) => return super::fail(errno),
    };
    let Ok(requested) = usize::try_from(size) else {
        return super::fail(EINVAL);
    };
    if requested == 0 {
        return super::fail(EINVAL);
    }
    let rounded = requested.max(PIPE_PAGE).next_power_of_two();
    if rounded > PIPE_MAX_SIZE {
        return super::fail(EPERM);
    }
    let mut state = lock_state();
    let Some(channel) = pipe_size_channel(&state, end)
        .and_then(|channel| state.net.pipe_channels.get_mut(&channel))
    else {
        return super::fail(super::EBADF);
    };
    if channel.buffer.len() > rounded {
        return super::fail(EBUSY);
    }
    channel.capacity = rounded;
    super::set_errno(0);
    c_int::try_from(rounded).unwrap_or_else(|_| super::fail(super::EOVERFLOW))
}
