//! Sockets: the one socket layer behind both doors.
//!
//! Every socket syscall has one kernel-shaped entry here (`patina_sock_*`: the
//! raw arguments, guest pointers as addresses, `-errno` on failure) that the C
//! interposers and the SUD rows both call, so the two doors cannot disagree.
//! An entry resolves the descriptor (`EBADF`, `ENOTSOCK`), copies its
//! arguments in the way `net/socket.c` does (`move_addr_to_kernel`, the
//! message header, the iovecs, the control messages; `EFAULT` for what cannot
//! be read, never a fault in the shim), and hands the family the request:
//!
//! * `AF_INET`/`AF_INET6` ([`inet`]): TCP and UDP whose traffic is SimNet's,
//!   through recorded runtime operations; the socket layer the kernel keeps
//!   above the wire — the bind table and its conflicts, connection state,
//!   pending errors, options — lives here, deterministic given the schedule.
//! * `AF_UNIX` ([`unix`]): stream, datagram and sequenced-packet sockets of
//!   the one process, their bytes, descriptors and credentials queued here;
//!   path names are socket nodes in the deterministic filesystem, abstract
//!   names a namespace of their own. A `socketpair` is two of them.
//! * `AF_NETLINK` ([`netlink`], Linux): `NETLINK_ROUTE`, answered from the
//!   virtual interface table.
//!
//! What a socket reports to `poll`/`epoll`/`select` is its kernel poll mask
//! ([`socket_poll`]), computed the way the family's poll function computes
//! it, plus an arrival count for edge-triggered interest. Nothing here reads
//! host network state.

use super::*;

pub(crate) mod abi;
mod addr;
pub(crate) mod iface;
mod inet;
#[cfg(target_os = "linux")]
mod ipctl;
mod msg;
#[cfg(target_os = "linux")]
mod netlink;
mod opts;
mod unix;

use crate::fdtable::DescId;
use crate::registry::IDENTITY_PID;
use crate::uaccess;
use abi::*;

/// `MAX_RW_COUNT`: the most one transfer moves.
const MAX_RW_COUNT: usize = i32::MAX as usize & !4095;

/// `SOCK_MAX`: one past the highest socket type.
const SOCK_MAX: i32 = 11;

/// The credentials a message or a connection carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Creds {
    pub(crate) pid: i32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl Creds {
    /// The one virtual process's.
    pub(crate) const PROCESS: Creds = Creds {
        pid: IDENTITY_PID as i32,
        uid: crate::caller().uid,
        gid: crate::caller().gid,
    };
    /// `cred_to_ucred` with no peer: pid 0 and the overflow ids.
    pub(crate) const NONE: Creds = Creds {
        pid: 0,
        uid: 65534,
        gid: 65534,
    };

    #[cfg(target_os = "linux")]
    pub(crate) fn bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&self.pid.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.uid.to_ne_bytes());
        bytes[8..].copy_from_slice(&self.gid.to_ne_bytes());
        bytes
    }
}

/// One socket (the kernel's `struct socket` and `struct sock` together).
pub(crate) struct Socket {
    pub(crate) family: i32,
    pub(crate) ty: i32,
    pub(crate) protocol: i32,
    pub(crate) opts: opts::Options,
    /// `sk_shutdown`: [`RCV_SHUTDOWN`], [`SEND_SHUTDOWN`].
    pub(crate) shutdown: u8,
    /// `sk_err`: the pending error `SO_ERROR` and the next call report.
    pub(crate) error: c_int,
    pub(crate) proto: Proto,
    pub(crate) recv_waiters: VecDeque<TaskId>,
    pub(crate) send_waiters: VecDeque<TaskId>,
    /// Write-space arrivals: bumped whenever a receive frees room this
    /// socket's sends go into (`sk_write_space`), the write-direction edge an
    /// edge-triggered `EPOLLOUT` interest fires on.
    pub(crate) write_space: u64,
    /// The sockfs node `fstat` reports (`NetState::pipe_inodes`).
    pub(crate) inode: u64,
}

pub(crate) enum Proto {
    Inet(inet::Inet),
    Unix(unix::Unix),
    #[cfg(target_os = "linux")]
    Netlink(netlink::Netlink),
}

impl Socket {
    fn new(family: i32, ty: i32, protocol: i32, proto: Proto, inode: u64) -> Socket {
        Socket {
            family,
            ty,
            protocol,
            opts: opts::Options::new(family, ty),
            shutdown: 0,
            error: 0,
            proto,
            recv_waiters: VecDeque::new(),
            send_waiters: VecDeque::new(),
            write_space: 0,
            inode,
        }
    }

    /// `sock_error`: take the pending error.
    pub(crate) fn take_error(&mut self) -> Option<c_int> {
        (self.error != 0).then(|| std::mem::replace(&mut self.error, 0))
    }
}

/// Every socket of the process and the families' namespaces.
#[derive(Default)]
pub(crate) struct Sockets {
    pub(crate) table: BTreeMap<c_int, Socket>,
    inet: inet::Tables,
    unix: unix::Names,
    #[cfg(target_os = "linux")]
    netlink: netlink::Ports,
}

/// A message on its way out: the gathered bytes, the destination the caller
/// named (the raw address), and what it carries beside the bytes.
pub(crate) struct Outgoing {
    pub(crate) data: Payload,
    pub(crate) to: Option<Vec<u8>>,
    /// Open file descriptions in flight (`SCM_RIGHTS`), each holding a
    /// reference until it is received or dropped.
    pub(crate) rights: Vec<DescId>,
    /// Credentials the sender stated (`SCM_CREDENTIALS`).
    pub(crate) creds: Option<Creds>,
    /// `MSG_*`, with `MSG_DONTWAIT` for a non-blocking description.
    pub(crate) flags: c_int,
    /// Control messages at the protocol's levels (`IP_TOS`, `IP_PKTINFO`,
    /// `UDP_SEGMENT`, …), for a datagram socket.
    pub(crate) protocol: Vec<msg::ProtocolCmsg>,
}

/// The bytes a send carries, still in the guest's memory. A protocol copies
/// them in as it takes them — a record whole once its size is judged, a
/// stream a piece at a time as room appears — as the kernel's
/// `copy_from_iter` does, so no byte is copied (or allocated for) before the
/// send is judged, and a stream that meets an unreadable page mid-way has
/// sent what came before it.
pub(crate) struct Payload {
    segments: Vec<(usize, usize)>,
    len: usize,
}

/// The most a stream send copies in at a time.
pub(crate) const STREAM_CHUNK: usize = 64 * 1024;

impl Payload {
    /// One guest buffer (`send`, `write`), at most `MAX_RW_COUNT` of it.
    pub(crate) fn contiguous(base: usize, len: usize) -> Payload {
        Payload::gathered(vec![(base, len)])
    }

    /// Guest segments in order (`sendmsg`'s iovec), at most `MAX_RW_COUNT`
    /// bytes of them.
    pub(crate) fn gathered(segments: Vec<(usize, usize)>) -> Payload {
        let mut len = 0usize;
        let mut taken = Vec::with_capacity(segments.len());
        for (base, seg) in segments {
            let take = seg.min(MAX_RW_COUNT - len);
            if take > 0 {
                taken.push((base, take));
                len += take;
            }
        }
        Payload {
            segments: taken,
            len,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `count` bytes from offset `at`.
    pub(crate) fn read(&self, at: usize, count: usize) -> Result<Vec<u8>, c_int> {
        let count = count.min(self.len.saturating_sub(at));
        let mut ranges = Vec::new();
        let (mut skip, mut left) = (at, count);
        for &(base, len) in &self.segments {
            if left == 0 {
                break;
            }
            if skip >= len {
                skip -= len;
                continue;
            }
            let take = (len - skip).min(left);
            ranges.push((base + skip, take));
            skip = 0;
            left -= take;
        }
        let mut bytes = vec![0u8; count];
        uaccess::read_gather(&ranges, &mut bytes)?;
        Ok(bytes)
    }

    /// Every byte.
    pub(crate) fn read_all(&self) -> Result<Vec<u8>, c_int> {
        self.read(0, self.len)
    }
}

impl Outgoing {
    fn plain(data: Payload, to: Option<Vec<u8>>, flags: c_int) -> Outgoing {
        Outgoing {
            data,
            to,
            rights: Vec::new(),
            creds: None,
            flags,
            protocol: Vec::new(),
        }
    }
}

/// What a receive asks for.
#[derive(Clone, Copy)]
pub(crate) struct Want {
    /// The bytes the caller's buffers hold.
    pub(crate) capacity: usize,
    /// `MSG_*`, with `MSG_DONTWAIT` for a non-blocking description.
    pub(crate) flags: c_int,
}

/// What a receive delivered.
#[derive(Default)]
pub(crate) struct Incoming {
    /// The bytes copied to the caller (at most the capacity).
    pub(crate) data: Vec<u8>,
    /// The call's answer: the bytes delivered, or a datagram's whole length
    /// under `MSG_TRUNC`.
    pub(crate) len: usize,
    /// The source's address as the kernel reports it (`msg_namelen` its
    /// length; empty for none), when the family names one.
    pub(crate) from: Option<Vec<u8>>,
    /// `msg_flags`.
    pub(crate) flags: c_int,
    pub(crate) rights: Vec<DescId>,
    /// Credentials to report (`SO_PASSCRED`).
    pub(crate) creds: Option<Creds>,
    /// Protocol-level ancillary data to report, in the order the kernel
    /// puts it (`IP_PKTINFO`, `IP_TOS`, `IPV6_PKTINFO`, `IPV6_TCLASS`).
    pub(crate) control: Vec<msg::ProtocolCmsg>,
}

/// Which of a socket's queues a waiting task parks on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Recv,
    Send,
}

fn errno_result(result: Result<i64, c_int>) -> i64 {
    match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno),
    }
}

/// The unrecorded virtual now: a function of the recorded sleeps, so a
/// deadline built on it reproduces on replay.
pub(crate) fn now() -> Result<u64, c_int> {
    with_context_raw(|context| context.monotonic_now_unrecorded())
}

/// Park the calling task on `handle`'s `dir` queue until something wakes it,
/// the virtual-clock `deadline` passes, or a signal interrupts it (`EINTR`).
/// The caller decided to wait while holding `state`.
pub(super) fn park(
    mut state: SpinGuard<'_, ThreadRuntime>,
    handle: c_int,
    dir: Dir,
    deadline: Option<u64>,
    reason: &'static str,
) -> Result<(), c_int> {
    let me = current_task();
    let Some(socket) = state.net.sockets.table.get_mut(&handle) else {
        return Err(crate::EBADF);
    };
    let loc = match dir {
        Dir::Recv => {
            socket.recv_waiters.push_back(me);
            WaiterLoc::SockRecv(handle)
        }
        Dir::Send => {
            socket.send_waiters.push_back(me);
            WaiterLoc::SockSend(handle)
        }
    };
    let wait = Wait::new(BlockClass::Io, vec![loc]);
    let step = match deadline {
        Some(deadline) => state.block_timed(me, reason, wait, ClockKind::Monotonic, deadline),
        None => state.block(me, reason, wait),
    };
    match step {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return Err(error.into_posix()),
    }
    {
        let mut state = lock_state();
        unregister_waiters(&mut state, me, &[loc]);
        state.timed_out.remove(&me);
    }
    #[cfg(target_os = "linux")]
    if signals::resume() == signals::Resumed::Eintr {
        return Err(crate::EINTR);
    }
    Ok(())
}

/// A receive freed room for `writer`'s sends: a write-space arrival, and its
/// send waiters to wake once the state lock is dropped.
pub(super) fn room_freed(state: &mut ThreadRuntime, writer: c_int) -> Vec<TaskId> {
    match state.net.sockets.table.get_mut(&writer) {
        Some(socket) => {
            socket.write_space = socket.write_space.wrapping_add(1);
            socket.send_waiters.drain(..).collect()
        }
        None => Vec::new(),
    }
}

/// Take `handle`'s `dir` waiters for waking once the state lock is dropped.
pub(super) fn waiters(state: &mut ThreadRuntime, handle: c_int, dir: Dir) -> Vec<TaskId> {
    state
        .net
        .sockets
        .table
        .get_mut(&handle)
        .map(|socket| match dir {
            Dir::Recv => socket.recv_waiters.drain(..).collect(),
            Dir::Send => socket.send_waiters.drain(..).collect(),
        })
        .unwrap_or_default()
}

/// A deadline `timeout` nanoseconds (the socket's `SO_RCVTIMEO` or
/// `SO_SNDTIMEO`) from now, or `None` for no timeout.
pub(crate) fn deadline(timeout: Option<u64>) -> Result<Option<u64>, c_int> {
    match timeout {
        Some(timeout) => Ok(Some(now()?.saturating_add(timeout))),
        None => Ok(None),
    }
}

/// Whether a waited-for `deadline` has passed.
pub(crate) fn expired(deadline: Option<u64>) -> Result<bool, c_int> {
    match deadline {
        Some(deadline) => Ok(now()? >= deadline),
        None => Ok(false),
    }
}

/// Mint a socket's sockfs node, stamped with the filesystem clock's now.
fn mint_inode(state: &mut ThreadRuntime) -> u64 {
    mint_pipe_inode(state, true, pipe_inode_time(), 1)
}

/// Free a socket's sockfs node.
fn drop_inode(state: &mut ThreadRuntime, ino: u64) {
    if let Some(inode) = state.net.pipe_inodes.get_mut(&ino) {
        inode.ends -= 1;
        if inode.ends == 0 {
            state.net.pipe_inodes.remove(&ino);
        }
    }
}

/// Bind a new socket to the lowest free guest number. A full table
/// (`EMFILE`) takes the socket back out, so a failure creates nothing.
fn install(
    state: &mut ThreadRuntime,
    handle: c_int,
    nonblocking: bool,
    cloexec: bool,
) -> Result<c_int, c_int> {
    let status = O_READ | O_WRITE | if nonblocking { O_NONBLOCK } else { 0 };
    match crate::install_fd(FdKind::Socket, handle as u64, status, cloexec) {
        Ok(fd) => Ok(fd),
        Err(errno) => {
            if let Some(socket) = state.net.sockets.table.remove(&handle) {
                drop_inode(state, socket.inode);
            }
            Err(errno)
        }
    }
}

/// `SOCK_NONBLOCK`/`SOCK_CLOEXEC` split off a type or `accept4` flags.
#[cfg(target_os = "linux")]
fn creation_flags(flags: c_int) -> Result<(bool, bool), c_int> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    Ok((flags & SOCK_NONBLOCK != 0, flags & SOCK_CLOEXEC != 0))
}

/// Darwin's socket types carry no creation flags.
#[cfg(target_os = "macos")]
fn creation_flags(flags: c_int) -> Result<(bool, bool), c_int> {
    if flags != 0 {
        return Err(EINVAL);
    }
    Ok((false, false))
}

/// Create a socket of `family`/`ty`/`protocol` in the table (no number yet):
/// the family's `create` refusals, in `__sock_create`'s order.
fn create(state: &mut ThreadRuntime, family: i32, ty: i32, protocol: i32) -> Result<c_int, c_int> {
    if !(0..AF_MAX).contains(&family) {
        return Err(EAFNOSUPPORT);
    }
    if !(0..SOCK_MAX).contains(&ty) {
        return Err(EINVAL);
    }
    let (ty, protocol, proto) = match family {
        AF_INET | AF_INET6 => inet::create(family == AF_INET6, ty, protocol)?,
        AF_UNIX => unix::create(ty, protocol)?,
        #[cfg(target_os = "linux")]
        AF_NETLINK => netlink::create(ty, protocol)?,
        // `packet_create`: CAP_NET_RAW before anything else.
        #[cfg(target_os = "linux")]
        AF_PACKET => return Err(crate::EPERM),
        _ => return Err(EAFNOSUPPORT),
    };
    state.ensure_active().map_err(ThreadError::into_posix)?;
    let handle = next_handle(state);
    let inode = mint_inode(state);
    state
        .net
        .sockets
        .table
        .insert(handle, Socket::new(family, ty, protocol, proto, inode));
    Ok(handle)
}

/// `socket(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_socket(family: c_int, ty: c_int, protocol: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (nonblocking, cloexec) = creation_flags(ty & !SOCK_TYPE_MASK)?;
        let mut state = lock_state();
        let handle = create(&mut state, family, ty & SOCK_TYPE_MASK, protocol)?;
        install(&mut state, handle, nonblocking, cloexec).map(i64::from)
    })())
}

/// `socketpair(2)`: the numbers are written to `sv` before the pair exists,
/// as `__sys_socketpair` does (a bad `sv` is `EFAULT` whatever the family).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_socketpair(
    family: c_int,
    ty: c_int,
    protocol: c_int,
    sv: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (nonblocking, cloexec) = creation_flags(ty & !SOCK_TYPE_MASK)?;
        let ty = ty & SOCK_TYPE_MASK;
        let mut state = lock_state();
        // The kernel reserves both numbers and writes them first; the table
        // allocates lowest-free, so they are the two it is about to hand out.
        let (first, second) = crate::fd_table().lock().next_free_pair()?;
        uaccess::write(sv, &[first, second])?;
        let a = create(&mut state, family, ty, protocol)?;
        let b = match create(&mut state, family, ty, protocol) {
            Ok(b) => b,
            Err(errno) => {
                close_unbound(&mut state, a);
                return Err(errno);
            }
        };
        if family != AF_UNIX {
            // Only AF_UNIX implements `socketpair`; the rest answer
            // `sock_no_socketpair`.
            close_unbound(&mut state, a);
            close_unbound(&mut state, b);
            return Err(EOPNOTSUPP);
        }
        unix::pair(&mut state, a, b);
        let status = O_READ | O_WRITE | if nonblocking { O_NONBLOCK } else { 0 };
        let installed = crate::fd_table().lock().install_pair(
            FdKind::Socket,
            (a as u64, status),
            (b as u64, status),
            cloexec,
        );
        match installed {
            Ok(_) => Ok(0),
            Err(errno) => {
                close_unbound(&mut state, a);
                close_unbound(&mut state, b);
                Err(errno)
            }
        }
    })())
}

/// Drop a socket no number was bound to.
fn close_unbound(state: &mut ThreadRuntime, handle: c_int) {
    if let Some(socket) = state.net.sockets.table.remove(&handle) {
        drop_inode(state, socket.inode);
        let _ = close_socket(state, handle, socket);
    }
}

/// A guest number's socket handle and its `O_NONBLOCK`.
fn lookup(fd: c_int) -> Result<(c_int, bool), c_int> {
    socket_entry(fd)
}

/// The family of the socket `handle`.
fn family_of(handle: c_int) -> Result<Family, c_int> {
    let state = lock_state();
    let socket = state.net.sockets.table.get(&handle).ok_or(crate::EBADF)?;
    Ok(match socket.proto {
        Proto::Inet(_) => Family::Inet,
        Proto::Unix(_) => Family::Unix,
        #[cfg(target_os = "linux")]
        Proto::Netlink(_) => Family::Netlink,
    })
}

/// A socket's family, for dispatch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Inet,
    Unix,
    #[cfg(target_os = "linux")]
    Netlink,
}

/// `bind(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_bind(fd: c_int, addr: usize, len: i64) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, _) = lookup(fd)?;
        let address = addr::copy_in(addr, len)?;
        match family_of(handle)? {
            Family::Inet => inet::bind(handle, &address),
            Family::Unix => unix::bind(handle, &address),
            #[cfg(target_os = "linux")]
            Family::Netlink => netlink::bind(handle, &address),
        }
        .map(|()| 0)
    })())
}

/// `connect(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_connect(fd: c_int, addr: usize, len: i64) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        let address = addr::copy_in(addr, len)?;
        match family_of(handle)? {
            Family::Inet => inet::connect(handle, &address, nonblocking),
            Family::Unix => unix::connect(handle, &address, nonblocking),
            #[cfg(target_os = "linux")]
            Family::Netlink => netlink::connect(handle, &address),
        }
        .map(|()| 0)
    })())
}

/// `somaxconn`: the most a `listen` backlog is taken as.
const SOMAXCONN: i32 = 4096;

/// `listen(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_listen(fd: c_int, backlog: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, _) = lookup(fd)?;
        // `(unsigned int)backlog > somaxconn`: a negative one is the maximum.
        let backlog = if backlog as u32 > SOMAXCONN as u32 {
            SOMAXCONN
        } else {
            backlog
        };
        match family_of(handle)? {
            Family::Inet => inet::listen(handle, backlog),
            Family::Unix => unix::listen(handle, backlog),
            #[cfg(target_os = "linux")]
            Family::Netlink => Err(EOPNOTSUPP),
        }
        .map(|()| 0)
    })())
}

/// `accept4(2)` (`accept` is flags 0).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_accept(fd: c_int, addr: usize, len_ptr: usize, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (nonblocking_new, cloexec) = creation_flags(flags)?;
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        crate::fd_table().lock().ensure_free(1)?;
        let (accepted, peer) = match family_of(handle)? {
            Family::Inet => inet::accept(handle, nonblocking)?,
            Family::Unix => unix::accept(handle, nonblocking)?,
            #[cfg(target_os = "linux")]
            Family::Netlink => return Err(EOPNOTSUPP),
        };
        let new_fd = {
            let mut state = lock_state();
            install(&mut state, accepted, nonblocking_new, cloexec)?
        };
        if addr != 0 {
            if let Err(errno) = addr::copy_out(&peer, addr, len_ptr) {
                crate::patina_close(new_fd);
                return Err(errno);
            }
        }
        Ok(i64::from(new_fd))
    })())
}

/// `getsockname(2)` (`peer` 0) and `getpeername(2)` (`peer` 1).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_name(fd: c_int, addr: usize, len_ptr: usize, peer: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (handle, _) = lookup(fd)?;
        let name = {
            let state = lock_state();
            let socket = state.net.sockets.table.get(&handle).ok_or(crate::EBADF)?;
            match &socket.proto {
                Proto::Inet(inet) => inet::name(socket, inet, peer != 0)?,
                Proto::Unix(unix) => unix::name(&state, unix, peer != 0)?,
                #[cfg(target_os = "linux")]
                Proto::Netlink(netlink) => netlink::name(netlink, peer != 0),
            }
        };
        addr::copy_out(&name, addr, len_ptr).map(|()| 0)
    })())
}

/// `shutdown(2)`: `SHUT_RD`/`SHUT_WR`/`SHUT_RDWR` as `sk_shutdown` bits.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_shutdown(fd: c_int, how: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, _) = lookup(fd)?;
        let bits = how.wrapping_add(1);
        if bits & !i32::from(SHUTDOWN_MASK) != 0 || bits == 0 {
            return Err(EINVAL);
        }
        match family_of(handle)? {
            Family::Inet => inet::shutdown(handle, bits as u8),
            Family::Unix => unix::shutdown(handle, bits as u8),
            #[cfg(target_os = "linux")]
            Family::Netlink => Err(EOPNOTSUPP),
        }
        .map(|()| 0)
    })())
}

/// Send one message through `handle` (every send entry and `write`).
pub(crate) fn send_message(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    let rights = message.rights.clone();
    let result = match family_of(handle) {
        Ok(Family::Inet) => inet::send(handle, message),
        Ok(Family::Unix) => unix::send(handle, message),
        #[cfg(target_os = "linux")]
        Ok(Family::Netlink) => netlink::send(handle, message),
        Err(errno) => Err(errno),
    };
    if result.is_err() {
        // Refs taken for descriptors that never left.
        release_rights(&rights);
    }
    result
}

/// Receive one message through `handle` (every receive entry and `read`).
pub(crate) fn recv_message(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    match family_of(handle)? {
        Family::Inet => inet::recv(handle, want),
        Family::Unix => unix::recv(handle, want),
        #[cfg(target_os = "linux")]
        Family::Netlink => netlink::recv(handle, want),
    }
}

/// `MSG_DONTWAIT` added for a non-blocking description.
fn with_nonblock(flags: c_int, nonblocking: bool) -> c_int {
    if nonblocking {
        flags | MSG_DONTWAIT
    } else {
        flags
    }
}

/// `sendto(2)` (`send` is no address).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_sendto(
    fd: c_int,
    buf: usize,
    len: usize,
    flags: c_int,
    addr: usize,
    alen: i64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        let to = if addr != 0 {
            Some(addr::copy_in(addr, alen)?)
        } else {
            None
        };
        let message = Outgoing::plain(
            Payload::contiguous(buf, len),
            to,
            with_nonblock(flags, nonblocking),
        );
        send_message(handle, message).map(|sent| sent as i64)
    })())
}

/// `recvfrom(2)` (`recv` is no address).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_recvfrom(
    fd: c_int,
    buf: usize,
    len: usize,
    flags: c_int,
    addr: usize,
    alen_ptr: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        let want = Want {
            capacity: len.min(MAX_RW_COUNT),
            flags: with_nonblock(flags, nonblocking),
        };
        let incoming = recv_message(handle, want)?;
        release_rights(&incoming.rights);
        uaccess::write_bytes(buf, &incoming.data)?;
        if addr != 0 {
            addr::copy_out(incoming.from.as_deref().unwrap_or(&[]), addr, alen_ptr)?;
        }
        Ok(incoming.len as i64)
    })())
}

/// Drop the in-flight references of descriptors that were not installed.
pub(crate) fn release_rights(rights: &[DescId]) {
    for desc in rights {
        let released = crate::fd_table().lock().release(*desc);
        if let Ok(Some(release)) = released {
            let _ = crate::release_description(release);
        }
    }
}

/// `read(2)` on a socket: a receive with no flags.
///
/// # Safety
/// `buf` must be writable for `len` bytes when nonzero.
pub(crate) unsafe fn socket_read(
    handle: u64,
    nonblocking: bool,
    buf: *mut c_void,
    len: usize,
) -> isize {
    if let Err(errno) = sched_point() {
        return crate::fail(errno) as isize;
    }
    let want = Want {
        capacity: len.min(MAX_RW_COUNT),
        flags: with_nonblock(0, nonblocking),
    };
    match recv_message(handle as c_int, want) {
        Ok(incoming) => {
            release_rights(&incoming.rights);
            match uaccess::write_bytes(buf as usize, &incoming.data) {
                Ok(()) => incoming.len as isize,
                Err(errno) => crate::fail(errno) as isize,
            }
        }
        Err(errno) => crate::fail(errno) as isize,
    }
}

/// `write(2)` on a socket: a send with no flags (so `SIGPIPE` is raised).
///
/// # Safety
/// `buf` must be readable for `len` bytes when nonzero.
pub(crate) unsafe fn socket_write(
    handle: u64,
    nonblocking: bool,
    buf: *const c_void,
    len: usize,
) -> isize {
    if let Err(errno) = sched_point() {
        return crate::fail(errno) as isize;
    }
    match send_message(
        handle as c_int,
        Outgoing::plain(
            Payload::contiguous(buf as usize, len),
            None,
            with_nonblock(0, nonblocking),
        ),
    ) {
        Ok(sent) => sent as isize,
        Err(errno) => crate::fail(errno) as isize,
    }
}

/// Raise `SIGPIPE` for a send that failed `EPIPE` without `MSG_NOSIGNAL`
/// (or Darwin's `SO_NOSIGPIPE`), outside every shim lock.
pub(crate) fn pipe_signal(flags: c_int, nosigpipe: bool) {
    if flags & MSG_NOSIGNAL == 0 && !nosigpipe {
        broken_pipe_signal();
    }
}

/// `setsockopt(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: usize,
    len: i64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (handle, _) = lookup(fd)?;
        if len < 0 {
            return Err(EINVAL);
        }
        let mut state = lock_state();
        let socket = state
            .net
            .sockets
            .table
            .get_mut(&handle)
            .ok_or(crate::EBADF)?;
        opts::set(socket, level, name, value, len as usize).map(|()| 0)
    })())
}

/// `getsockopt(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: usize,
    len_ptr: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let (handle, _) = lookup(fd)?;
        let mut state = lock_state();
        let listening = inet::listening(&state, handle) || unix::listening(&state, handle);
        #[cfg(target_os = "linux")]
        let peer_creds = unix::peer_creds(&state, handle);
        let socket = state
            .net
            .sockets
            .table
            .get_mut(&handle)
            .ok_or(crate::EBADF)?;
        let facts = opts::Facts {
            listening,
            #[cfg(target_os = "linux")]
            peer_creds,
        };
        opts::get(socket, facts, level, name, value, len_ptr).map(|()| 0)
    })())
}

/// Free a socket whose description's last reference went (the universal
/// `patina_close` path).
pub(crate) fn socket_close(handle: u64) -> Result<(), c_int> {
    let handle = handle as c_int;
    let mut state = lock_state();
    let Some(socket) = state.net.sockets.table.remove(&handle) else {
        return Err(crate::EBADF);
    };
    drop_inode(&mut state, socket.inode);
    let (wakes, rights) = close_socket(&mut state, handle, socket)?;
    drop(state);
    release_rights(&rights);
    wake_all(wakes);
    Ok(())
}

/// Tear a removed socket down: its family's close, and every task parked
/// on it. Answers the tasks to wake and the in-flight descriptors its queue
/// held.
fn close_socket(
    state: &mut ThreadRuntime,
    handle: c_int,
    socket: Socket,
) -> Result<(Vec<TaskId>, Vec<DescId>), c_int> {
    let mut wakes: Vec<TaskId> = socket.recv_waiters.iter().copied().collect();
    wakes.extend(socket.send_waiters.iter().copied());
    let (ty, v6only) = (socket.ty, socket.opts.v6only);
    let rights = match socket.proto {
        Proto::Inet(inet) => {
            wakes.extend(inet::close(state, handle, inet, ty == SOCK_STREAM, v6only)?);
            Vec::new()
        }
        Proto::Unix(unix) => {
            let (more, rights) = unix::close(state, handle, unix, ty, false);
            wakes.extend(more);
            rights
        }
        #[cfg(target_os = "linux")]
        Proto::Netlink(netlink) => {
            netlink::close(state, netlink);
            Vec::new()
        }
    };
    Ok((wakes, rights))
}

/// A socket's kernel poll mask (`EPOLL*` bits) and its arrival count, for
/// the readiness reactors. `None` when `handle` names no socket.
pub(super) fn socket_poll(state: &ThreadRuntime, handle: u64) -> Option<(u32, (u64, u64))> {
    let socket = state.net.sockets.table.get(&(handle as c_int))?;
    let (mask, arrivals) = match &socket.proto {
        Proto::Inet(inet) => inet::poll(socket, inet),
        Proto::Unix(unix) => unix::poll(state, handle as c_int, socket, unix),
        #[cfg(target_os = "linux")]
        Proto::Netlink(netlink) => netlink::poll(socket, netlink),
    };
    Some((mask, (arrivals, socket.write_space)))
}

/// `FIONREAD`/`SIOCINQ` on a socket: what a receive would take now.
pub(crate) fn socket_pending(handle: u64) -> Result<i32, c_int> {
    let state = lock_state();
    let socket = state
        .net
        .sockets
        .table
        .get(&(handle as c_int))
        .ok_or(crate::EBADF)?;
    match &socket.proto {
        Proto::Inet(inet) => inet::pending(socket, inet),
        Proto::Unix(unix) => unix::pending(socket, unix),
        #[cfg(target_os = "linux")]
        Proto::Netlink(netlink) => Ok(netlink::pending(netlink)),
    }
}

/// The socket's family, which the interface requests judge.
#[cfg(target_os = "linux")]
pub(crate) fn socket_family(handle: u64) -> Option<i32> {
    lock_state()
        .net
        .sockets
        .table
        .get(&(handle as c_int))
        .map(|socket| socket.family)
}
