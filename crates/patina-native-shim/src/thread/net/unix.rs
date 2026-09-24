//! `AF_UNIX`: stream, datagram and sequenced-packet sockets of the one
//! process (net/unix/af_unix.c).
//!
//! Every socket keeps its own receive queue of messages — a stream's are
//! segments read across, a datagram's and a sequenced packet's whole records
//! — and a message carries its bytes, the sender's name, its credentials and
//! the open file descriptions in flight with it (`SCM_RIGHTS`, each holding a
//! reference in the descriptor table until it is received or dropped). All of
//! it is in-process state that changes only while the acting task holds the
//! baton, so it is deterministic given the schedule and records nothing.
//!
//! A path name is a socket node the bind creates in the deterministic
//! filesystem (`0777 & ~umask`, `EADDRINUSE` for a name that exists), and a
//! socket bound to it is found through the node's inode, so a rename keeps
//! it reachable and the name outlives the socket. An abstract name lives in
//! a namespace of its own and is free again once its socket closes; binding
//! the bare family autobinds a five-hex-digit abstract name.

use patina_dst_abi::{FsEntryKind, FsNode};

use super::addr::{self, UnixName};
use super::*;
use crate::paths;
use crate::{EACCES, ENOENT, EPIPE};

/// `PF_UNIX`, the one protocol `unix_create` accepts beside 0.
const PF_UNIX: i32 = 1;
/// `net.unix.max_dgram_qlen`: datagrams a socket that is not its sender's
/// peer queues before the sender waits.
const MAX_DGRAM_QLEN: usize = 10;

/// One AF_UNIX socket's state.
pub(crate) struct Unix {
    /// The bound name.
    pub(crate) name: UnixName,
    /// The node a path name made.
    ino: Option<u64>,
    /// The connected peer: a stream's or sequenced packet's other end, a
    /// datagram socket's connect target.
    pub(crate) peer: Option<c_int>,
    state: State,
    queue: VecDeque<Message>,
    /// The bytes `queue` holds.
    queued: usize,
    /// `SO_PEERCRED`.
    peer_creds: Creds,
    /// Messages, connections and shutdowns that reached this socket: its
    /// edge-triggered arrivals.
    arrivals: u64,
}

enum State {
    Unconnected,
    /// Embryos: the sockets `connect` made, waiting for `accept`.
    Listening {
        backlog: i32,
        pending: VecDeque<c_int>,
    },
    Connected,
}

/// One queued message.
struct Message {
    data: Vec<u8>,
    /// A stream segment's bytes already read.
    read: usize,
    from: UnixName,
    rights: Vec<DescId>,
    creds: Option<Creds>,
}

impl Message {
    fn remaining(&self) -> usize {
        self.data.len() - self.read
    }
}

/// The AF_UNIX namespace.
#[derive(Default)]
pub(crate) struct Names {
    abstract_names: BTreeMap<Vec<u8>, c_int>,
    /// Path-bound sockets by their node's inode.
    paths: BTreeMap<u64, c_int>,
    next_autobind: u32,
}

impl Unix {
    fn new() -> Unix {
        Unix {
            name: UnixName::Unnamed,
            ino: None,
            peer: None,
            state: State::Unconnected,
            queue: VecDeque::new(),
            queued: 0,
            peer_creds: Creds::NONE,
            arrivals: 0,
        }
    }
}

/// `unix_create`: `SOCK_RAW` is a datagram socket for compatibility.
pub(super) fn create(ty: i32, protocol: i32) -> Result<(i32, i32, Proto), c_int> {
    if protocol != 0 && protocol != PF_UNIX {
        return Err(EPROTONOSUPPORT);
    }
    let ty = match ty {
        SOCK_STREAM | SOCK_SEQPACKET => ty,
        SOCK_DGRAM | SOCK_RAW => SOCK_DGRAM,
        _ => return Err(ESOCKTNOSUPPORT),
    };
    Ok((ty, 0, Proto::Unix(Unix::new())))
}

fn as_unix(socket: &Socket) -> &Unix {
    match &socket.proto {
        Proto::Unix(unix) => unix,
        _ => unreachable!("an AF_UNIX entry reached a socket of another family"),
    }
}

fn as_unix_mut(socket: &mut Socket) -> &mut Unix {
    match &mut socket.proto {
        Proto::Unix(unix) => unix,
        _ => unreachable!("an AF_UNIX entry reached a socket of another family"),
    }
}

fn sock(state: &ThreadRuntime, handle: c_int) -> Result<&Socket, c_int> {
    state.net.sockets.table.get(&handle).ok_or(crate::EBADF)
}

fn sock_mut(state: &mut ThreadRuntime, handle: c_int) -> Result<&mut Socket, c_int> {
    state.net.sockets.table.get_mut(&handle).ok_or(crate::EBADF)
}

/// A live AF_UNIX socket, or `None` for a peer that closed.
fn live(state: &ThreadRuntime, handle: c_int) -> Option<&Socket> {
    state
        .net
        .sockets
        .table
        .get(&handle)
        .filter(|socket| matches!(socket.proto, Proto::Unix(_)))
}

/// `unix_socketpair`: two connected ends, each the other's peer.
pub(super) fn pair(state: &mut ThreadRuntime, a: c_int, b: c_int) {
    for (me, peer) in [(a, b), (b, a)] {
        let unix = as_unix_mut(
            state
                .net
                .sockets
                .table
                .get_mut(&me)
                .expect("a new pair end"),
        );
        unix.peer = Some(peer);
        unix.state = State::Connected;
        unix.peer_creds = Creds::PROCESS;
    }
}

fn path_of(bytes: &[u8]) -> Result<String, c_int> {
    String::from_utf8(bytes.to_vec()).map_err(|_| EINVAL)
}

/// `unix_bind_bsd`'s node: a socket entry at `path` with `0777 & ~umask`;
/// an existing name (a trailing symlink included) is `EADDRINUSE`.
fn make_node(path: &str) -> Result<u64, c_int> {
    let resolved = paths::resolve(paths::AT_FDCWD, path, paths::RESOLVE_NOFOLLOW)?;
    if resolved.metadata.is_some() || paths::last_component(path) != paths::Last::Name {
        return Err(EADDRINUSE);
    }
    let mode = 0o777 & !paths::umask();
    crate::with_context(|context| context.fs_make_node(&resolved.path, FsNode::Socket, mode))
        .map_err(|errno| {
            if errno == crate::EEXIST {
                EADDRINUSE
            } else {
                errno
            }
        })?;
    let made = paths::resolve(paths::AT_FDCWD, path, paths::RESOLVE_NOFOLLOW)?;
    made.metadata.map(|metadata| metadata.ino).ok_or(ENOENT)
}

/// `unix_find_bsd`/`unix_find_abstract`: the socket bound at `name`, of
/// `ty`. A missing path is the resolver's answer (`ENOENT`, …), a name
/// nothing listens at or a node that is no socket `ECONNREFUSED`, a socket of
/// another type `EPROTOTYPE`.
fn find(name: &UnixName, ty: i32) -> Result<c_int, c_int> {
    let handle = match name {
        UnixName::Path(path) => {
            let resolved = paths::resolve(paths::AT_FDCWD, &path_of(path)?, 0)?;
            let metadata = resolved.metadata.ok_or(ENOENT)?;
            // `unix_find_bsd`: write permission on the node (the one
            // identity owns every entry, so its owner bits), then its kind.
            if metadata.mode & 0o200 == 0 {
                return Err(EACCES);
            }
            if metadata.kind != FsEntryKind::Socket {
                return Err(ECONNREFUSED);
            }
            let state = lock_state();
            state
                .net
                .sockets
                .unix
                .paths
                .get(&metadata.ino)
                .copied()
                .ok_or(ECONNREFUSED)?
        }
        UnixName::Abstract(bytes) => lock_state()
            .net
            .sockets
            .unix
            .abstract_names
            .get(bytes)
            .copied()
            .ok_or(ECONNREFUSED)?,
        UnixName::Unnamed => return Err(EINVAL),
    };
    let state = lock_state();
    let socket = live(&state, handle).ok_or(ECONNREFUSED)?;
    if socket.ty != ty {
        return Err(EPROTOTYPE);
    }
    Ok(handle)
}

/// `unix_autobind`: the next free five-hex-digit abstract name. A socket
/// already bound keeps its name.
fn autobind(state: &mut ThreadRuntime, handle: c_int) -> Result<(), c_int> {
    if as_unix(sock(state, handle)?).name != UnixName::Unnamed {
        return Ok(());
    }
    let names = &mut state.net.sockets.unix;
    let name = loop {
        let candidate = format!("{:05x}", names.next_autobind).into_bytes();
        names.next_autobind = (names.next_autobind + 1) & 0xFFFFF;
        if !names.abstract_names.contains_key(&candidate) {
            break candidate;
        }
    };
    names.abstract_names.insert(name.clone(), handle);
    as_unix_mut(sock_mut(state, handle)?).name = UnixName::Abstract(name);
    Ok(())
}

/// `bind(2)` (`unix_bind`).
pub(super) fn bind(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    let name = addr::parse_un(bytes)?;
    match name {
        UnixName::Unnamed => autobind(&mut lock_state(), handle),
        UnixName::Path(ref path) => {
            let target = path_of(path)?;
            let ino = make_node(&target)?;
            let mut state = lock_state();
            let unix = as_unix_mut(sock_mut(&mut state, handle)?);
            if unix.name != UnixName::Unnamed {
                // The kernel refuses a second bind only after the node
                // exists, then takes the node back out.
                drop(state);
                let _ = crate::with_context(|context| context.fs_remove_file(&target));
                return Err(EINVAL);
            }
            unix.name = name.clone();
            unix.ino = Some(ino);
            state.net.sockets.unix.paths.insert(ino, handle);
            Ok(())
        }
        UnixName::Abstract(ref bytes) => {
            let mut state = lock_state();
            if as_unix(sock(&state, handle)?).name != UnixName::Unnamed {
                return Err(EINVAL);
            }
            if state.net.sockets.unix.abstract_names.contains_key(bytes) {
                return Err(EADDRINUSE);
            }
            state
                .net
                .sockets
                .unix
                .abstract_names
                .insert(bytes.clone(), handle);
            as_unix_mut(sock_mut(&mut state, handle)?).name = name.clone();
            Ok(())
        }
    }
}

/// `connect(2)`: a stream or sequenced-packet connection through a
/// listener, or a datagram socket's association.
pub(super) fn connect(handle: c_int, bytes: &[u8], nonblocking: bool) -> Result<(), c_int> {
    let ty = sock(&lock_state(), handle)?.ty;
    if ty == SOCK_DGRAM {
        return connect_datagram(handle, bytes);
    }
    let name = match addr::parse_un(bytes)? {
        UnixName::Unnamed => return Err(EINVAL),
        name => name,
    };
    if sock(&lock_state(), handle)?.opts.passcred {
        autobind(&mut lock_state(), handle)?;
    }
    loop {
        let listener = find(&name, ty)?;
        let mut state = lock_state();
        let target = sock(&state, listener)?;
        let (backlog, pending) = match &as_unix(target).state {
            State::Listening { backlog, pending } if target.shutdown & RCV_SHUTDOWN == 0 => {
                (*backlog, pending.len())
            }
            _ => return Err(ECONNREFUSED),
        };
        if pending > backlog.max(0) as usize {
            if nonblocking {
                return Err(EWOULDBLOCK);
            }
            park(state, listener, Dir::Send, None, "unix-connect")?;
            continue;
        }
        match as_unix(sock(&state, handle)?).state {
            State::Unconnected => {}
            State::Connected => return Err(EISCONN),
            State::Listening { .. } => return Err(EINVAL),
        }
        // The embryo `accept` hands out: connected to the client, named as
        // the listener, crediting the connecting process.
        let listener_name = as_unix(sock(&state, listener)?).name.clone();
        let embryo = next_handle(&mut state);
        let inode = mint_inode(&mut state);
        let mut other = Unix::new();
        other.name = listener_name;
        other.peer = Some(handle);
        other.state = State::Connected;
        other.peer_creds = Creds::PROCESS;
        state.net.sockets.table.insert(
            embryo,
            Socket::new(AF_UNIX, ty, 0, Proto::Unix(other), inode),
        );
        let me = as_unix_mut(sock_mut(&mut state, handle)?);
        me.peer = Some(embryo);
        me.state = State::Connected;
        me.peer_creds = Creds::PROCESS;
        let listening = as_unix_mut(sock_mut(&mut state, listener)?);
        if let State::Listening { pending, .. } = &mut listening.state {
            pending.push_back(embryo);
        }
        listening.arrivals += 1;
        let wakes = waiters(&mut state, listener, Dir::Recv);
        drop(state);
        wake_all(wakes);
        return Ok(());
    }
}

/// `unix_dgram_connect`: associate with the socket at a name, or dissolve
/// the association (`AF_UNSPEC`).
fn connect_datagram(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    if bytes.len() < addr::SUN_PATH {
        return Err(EINVAL);
    }
    let target = if addr::family_of(bytes) == Some(AF_UNSPEC) {
        None
    } else {
        let name = match addr::parse_un(bytes)? {
            UnixName::Unnamed => return Err(EINVAL),
            name => name,
        };
        if sock(&lock_state(), handle)?.opts.passcred {
            autobind(&mut lock_state(), handle)?;
        }
        let target = find(&name, SOCK_DGRAM)?;
        let state = lock_state();
        if !may_send(&state, handle, target) {
            return Err(crate::EPERM);
        }
        Some(target)
    };
    let mut state = lock_state();
    let unix = as_unix_mut(sock_mut(&mut state, handle)?);
    unix.peer = target;
    unix.state = if target.is_some() {
        State::Connected
    } else {
        State::Unconnected
    };
    Ok(())
}

/// `unix_may_send`: a datagram reaches a socket that is unassociated or
/// associated with its sender.
fn may_send(state: &ThreadRuntime, sender: c_int, target: c_int) -> bool {
    live(state, target).is_none_or(|target| as_unix(target).peer.is_none_or(|peer| peer == sender))
}

/// `listen(2)` (`unix_listen`): only a bound stream or sequenced-packet
/// socket listens.
pub(super) fn listen(handle: c_int, backlog: i32) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    if socket.ty != SOCK_STREAM && socket.ty != SOCK_SEQPACKET {
        return Err(EOPNOTSUPP);
    }
    let unix = as_unix_mut(socket);
    if unix.name == UnixName::Unnamed {
        return Err(EINVAL);
    }
    match &mut unix.state {
        State::Connected => Err(EINVAL),
        State::Listening {
            backlog: current, ..
        } => {
            *current = backlog;
            Ok(())
        }
        State::Unconnected => {
            unix.state = State::Listening {
                backlog,
                pending: VecDeque::new(),
            };
            unix.peer_creds = Creds::PROCESS;
            Ok(())
        }
    }
}

/// Whether `handle` is a listening AF_UNIX socket (`SO_ACCEPTCONN`).
pub(super) fn listening(state: &ThreadRuntime, handle: c_int) -> bool {
    live(state, handle)
        .is_some_and(|socket| matches!(as_unix(socket).state, State::Listening { .. }))
}

/// The credentials `SO_PEERCRED` reports for `handle`.
#[cfg(target_os = "linux")]
pub(super) fn peer_creds(state: &ThreadRuntime, handle: c_int) -> Creds {
    live(state, handle).map_or(Creds::NONE, |socket| as_unix(socket).peer_creds)
}

/// `accept4(2)` (`unix_accept`): the next embryo, and its peer's name.
pub(super) fn accept(handle: c_int, nonblocking: bool) -> Result<(c_int, Vec<u8>), c_int> {
    let deadline = {
        let state = lock_state();
        let socket = sock(&state, handle)?;
        if socket.ty != SOCK_STREAM && socket.ty != SOCK_SEQPACKET {
            return Err(EOPNOTSUPP);
        }
        super::deadline(socket.opts.recv_timeout())?
    };
    loop {
        let mut state = lock_state();
        let unix = as_unix_mut(sock_mut(&mut state, handle)?);
        let State::Listening { pending, .. } = &mut unix.state else {
            return Err(EINVAL);
        };
        if let Some(embryo) = pending.pop_front() {
            let client = as_unix(sock(&state, embryo)?).peer;
            let name = client
                .and_then(|client| live(&state, client))
                .map_or(UnixName::Unnamed, |client| as_unix(client).name.clone());
            // A connect waiting for room in the backlog may proceed.
            let wakes = waiters(&mut state, handle, Dir::Send);
            drop(state);
            wake_all(wakes);
            return Ok((embryo, addr::encode_un(&name)));
        }
        if nonblocking || expired(deadline)? {
            return Err(EWOULDBLOCK);
        }
        park(state, handle, Dir::Recv, deadline, "unix-accept")?;
    }
}

/// `getsockname`/`getpeername` (`unix_getname`).
pub(super) fn name(state: &ThreadRuntime, unix: &Unix, peer: bool) -> Result<Vec<u8>, c_int> {
    if !peer {
        return Ok(addr::encode_un(&unix.name));
    }
    let peer = unix.peer.ok_or(ENOTCONN)?;
    Ok(addr::encode_un(
        &live(state, peer).map_or(UnixName::Unnamed, |peer| self::as_unix(peer).name.clone()),
    ))
}

/// `shutdown(2)` (`unix_shutdown`): the directions shut here are the
/// opposite ones at a stream or sequenced-packet peer.
pub(super) fn shutdown(handle: c_int, bits: u8) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    socket.shutdown |= bits;
    let ty = socket.ty;
    let peer = as_unix(socket).peer;
    as_unix_mut(socket).arrivals += 1;
    let mut wakes = waiters(&mut state, handle, Dir::Recv);
    wakes.extend(waiters(&mut state, handle, Dir::Send));
    if let Some(peer) = peer.filter(|_| ty != SOCK_DGRAM) {
        if let Some(other) = state.net.sockets.table.get_mut(&peer) {
            let mut peer_bits = 0;
            if bits & RCV_SHUTDOWN != 0 {
                peer_bits |= SEND_SHUTDOWN;
            }
            if bits & SEND_SHUTDOWN != 0 {
                peer_bits |= RCV_SHUTDOWN;
            }
            other.shutdown |= peer_bits;
            as_unix_mut(other).arrivals += 1;
            wakes.extend(waiters(&mut state, peer, Dir::Recv));
            wakes.extend(waiters(&mut state, peer, Dir::Send));
        }
    }
    drop(state);
    wake_all(wakes);
    Ok(())
}

/// Free a closed socket (`unix_release_sock`): its name, its embryos, and
/// what its peer sees — every direction shut, and `ECONNRESET` when it left
/// data unread. Answers the tasks to wake and the descriptors its queue
/// still held.
/// Release a closing AF_UNIX socket (`unix_release_sock`); `embryo` for a
/// connection its listener never accepted, whose client reads `ECONNRESET`.
pub(super) fn close(
    state: &mut ThreadRuntime,
    handle: c_int,
    unix: Unix,
    ty: i32,
    embryo: bool,
) -> (Vec<TaskId>, Vec<DescId>) {
    let names = &mut state.net.sockets.unix;
    match &unix.name {
        UnixName::Abstract(bytes) => {
            names.abstract_names.remove(bytes);
        }
        UnixName::Path(_) => {
            if let Some(ino) = unix.ino {
                if names.paths.get(&ino) == Some(&handle) {
                    names.paths.remove(&ino);
                }
            }
        }
        UnixName::Unnamed => {}
    }
    let mut wakes = Vec::new();
    let mut rights: Vec<DescId> = unix
        .queue
        .iter()
        .flat_map(|message| message.rights.iter().copied())
        .collect();
    if let State::Listening { pending, .. } = unix.state {
        for embryo in pending {
            if let Some(socket) = state.net.sockets.table.remove(&embryo) {
                drop_inode(state, socket.inode);
                if let Proto::Unix(embryo_state) = socket.proto {
                    let (more_wakes, more_rights) = close(state, embryo, embryo_state, ty, true);
                    wakes.extend(more_wakes);
                    rights.extend(more_rights);
                }
            }
        }
    }
    if let Some(peer) = unix.peer.filter(|_| ty != SOCK_DGRAM) {
        if let Some(other) = state.net.sockets.table.get_mut(&peer) {
            other.shutdown = SHUTDOWN_MASK;
            if !unix.queue.is_empty() || embryo {
                other.error = ECONNRESET;
            }
            as_unix_mut(other).arrivals += 1;
            wakes.extend(waiters(state, peer, Dir::Recv));
            wakes.extend(waiters(state, peer, Dir::Send));
        }
    }
    (wakes, rights)
}

/// Send one message (`unix_stream_sendmsg`, `unix_dgram_sendmsg`,
/// `unix_seqpacket_sendmsg`).
pub(super) fn send(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    if message.flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let ty = sock(&lock_state(), handle)?.ty;
    if ty == SOCK_STREAM {
        send_stream(handle, message)
    } else {
        send_record(handle, message, ty)
    }
}

/// The credentials a message carries: what the sender stated, else the
/// process's when either end asked for them at the send (`maybe_add_creds`);
/// a receiver that asks later reads none on a message sent before.
fn creds_for(
    state: &ThreadRuntime,
    handle: c_int,
    peer: c_int,
    stated: Option<Creds>,
) -> Option<Creds> {
    if stated.is_some() {
        return stated;
    }
    let passcred = |handle| live(state, handle).is_some_and(|socket| socket.opts.passcred);
    (passcred(handle) || passcred(peer)).then_some(Creds::PROCESS)
}

fn send_stream(handle: c_int, mut message: Outgoing) -> Result<usize, c_int> {
    let nosigpipe = sock(&lock_state(), handle)?.opts.nosigpipe();
    let broken = |sent: usize| {
        if sent == 0 {
            pipe_signal(message.flags, nosigpipe);
            Err(EPIPE)
        } else {
            Ok(sent)
        }
    };
    let deadline = super::deadline(sock(&lock_state(), handle)?.opts.send_timeout())?;
    let nonblocking = message.flags & MSG_DONTWAIT != 0 || deadline == Some(now()?);
    let mut sent = 0;
    loop {
        let mut state = lock_state();
        let socket = sock(&state, handle)?;
        let unix = as_unix(socket);
        if message.to.as_ref().is_some_and(|to| !to.is_empty()) {
            return Err(if matches!(unix.state, State::Connected) {
                EISCONN
            } else {
                EOPNOTSUPP
            });
        }
        let Some(peer) = unix.peer.filter(|_| matches!(unix.state, State::Connected)) else {
            return Err(ENOTCONN);
        };
        if socket.shutdown & SEND_SHUTDOWN != 0 {
            drop(state);
            return broken(sent);
        }
        let sndbuf = socket.opts.sndbuf.max(0) as usize;
        let Some(other) = live(&state, peer).filter(|other| other.shutdown & RCV_SHUTDOWN == 0)
        else {
            drop(state);
            return broken(sent);
        };
        let room = sndbuf.saturating_sub(as_unix(other).queued);
        if room == 0 && sent < message.data.len() {
            if nonblocking || expired(deadline)? {
                return if sent > 0 { Ok(sent) } else { Err(EWOULDBLOCK) };
            }
            park(state, handle, Dir::Send, deadline, "unix-send")
                .or_else(|errno| if sent > 0 { Ok(()) } else { Err(errno) })?;
            continue;
        }
        let creds = creds_for(&state, handle, peer, message.creds);
        let chunk = room.min(message.data.len() - sent);
        let data = match message.data.read(sent, chunk) {
            Ok(data) => data,
            Err(errno) => return if sent > 0 { Ok(sent) } else { Err(errno) },
        };
        let segment = Message {
            data,
            read: 0,
            from: UnixName::Unnamed,
            rights: std::mem::take(&mut message.rights),
            creds,
        };
        let other = as_unix_mut(sock_mut(&mut state, peer)?);
        other.queued += chunk;
        other.queue.push_back(segment);
        other.arrivals += 1;
        sent += chunk;
        let wakes = waiters(&mut state, peer, Dir::Recv);
        drop(state);
        wake_all(wakes);
        if sent == message.data.len() {
            return Ok(sent);
        }
    }
}

/// A datagram's or a sequenced packet's send: one record to one socket.
fn send_record(handle: c_int, mut message: Outgoing, ty: i32) -> Result<usize, c_int> {
    let named = message
        .to
        .as_ref()
        .filter(|to| !to.is_empty() && ty == SOCK_DGRAM);
    let destination = match named {
        Some(bytes) => Some(match addr::parse_un(bytes)? {
            UnixName::Unnamed => return Err(EINVAL),
            name => name,
        }),
        None => None,
    };
    {
        let state = lock_state();
        let socket = sock(&state, handle)?;
        let unix = as_unix(socket);
        if ty == SOCK_SEQPACKET && !matches!(unix.state, State::Connected) {
            return Err(ENOTCONN);
        }
        if destination.is_none() && unix.peer.is_none() {
            return Err(ENOTCONN);
        }
        let passcred = socket.opts.passcred;
        drop(state);
        if passcred {
            autobind(&mut lock_state(), handle)?;
        }
    }
    let deadline = super::deadline(sock(&lock_state(), handle)?.opts.send_timeout())?;
    let nonblocking = message.flags & MSG_DONTWAIT != 0 || deadline == Some(now()?);
    if message.data.len() > (sock(&lock_state(), handle)?.opts.sndbuf.max(32) - 32) as usize {
        return Err(EMSGSIZE);
    }
    // The record is copied in once its size is judged, before its receiver
    // is looked up.
    let mut data = message.data.read_all()?;
    loop {
        let target = match &destination {
            Some(name) => find(name, ty)?,
            None => {
                let mut state = lock_state();
                let peer = as_unix(sock(&state, handle)?).peer.ok_or(ENOTCONN)?;
                if live(&state, peer).is_none() {
                    if ty == SOCK_SEQPACKET {
                        return Err(EPIPE);
                    }
                    // The associated socket closed: this send reports it and
                    // dissolves the association.
                    let unix = as_unix_mut(sock_mut(&mut state, handle)?);
                    unix.peer = None;
                    unix.state = State::Unconnected;
                    return Err(ECONNREFUSED);
                }
                peer
            }
        };
        let mut state = lock_state();
        if !may_send(&state, handle, target) {
            return Err(crate::EPERM);
        }
        let other = sock(&state, target)?;
        if other.shutdown & RCV_SHUTDOWN != 0 {
            return Err(EPIPE);
        }
        let paired = as_unix(other).peer == Some(handle);
        if target != handle && !paired && as_unix(other).queue.len() > MAX_DGRAM_QLEN {
            if nonblocking || expired(deadline)? {
                return Err(EWOULDBLOCK);
            }
            park(state, target, Dir::Send, deadline, "unix-send")?;
            continue;
        }
        let from = as_unix(sock(&state, handle)?).name.clone();
        let creds = creds_for(&state, handle, target, message.creds);
        let len = data.len();
        let record = Message {
            data: std::mem::take(&mut data),
            read: 0,
            from,
            rights: std::mem::take(&mut message.rights),
            creds,
        };
        let other = as_unix_mut(sock_mut(&mut state, target)?);
        other.queued += len;
        other.queue.push_back(record);
        other.arrivals += 1;
        let wakes = waiters(&mut state, target, Dir::Recv);
        drop(state);
        wake_all(wakes);
        return Ok(len);
    }
}

/// A peek's own references to queued descriptors (`scm_fp_dup`).
fn peeked(rights: &[DescId]) -> Vec<DescId> {
    let mut table = crate::fd_table().lock();
    rights
        .iter()
        .copied()
        .filter(|desc| table.retain(*desc).is_ok())
        .collect()
}

/// Receive one message (`unix_stream_recvmsg`, `unix_dgram_recvmsg`,
/// `unix_seqpacket_recvmsg`).
pub(super) fn recv(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    if want.flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let (ty, timeout) = {
        let state = lock_state();
        let socket = sock(&state, handle)?;
        (socket.ty, socket.opts.recv_timeout())
    };
    let deadline = super::deadline(timeout)?;
    let nonblocking = want.flags & MSG_DONTWAIT != 0 || timeout == Some(0);
    if ty == SOCK_STREAM {
        recv_stream(handle, want, deadline, nonblocking)
    } else {
        recv_record(handle, want, deadline, nonblocking, ty)
    }
}

/// The credentials a receive reports: the message's, or none known, when
/// the socket asked for them (`SO_PASSCRED`).
fn reported(passcred: bool, creds: Option<Creds>) -> Option<Creds> {
    passcred.then(|| creds.unwrap_or(Creds::NONE))
}

fn recv_stream(
    handle: c_int,
    want: Want,
    deadline: Option<u64>,
    nonblocking: bool,
) -> Result<Incoming, c_int> {
    let peek = want.flags & MSG_PEEK != 0;
    // `sock_rcvlowat`: all of it under `MSG_WAITALL`, else `SO_RCVLOWAT`.
    let target = if want.flags & MSG_WAITALL != 0 {
        want.capacity
    } else {
        let lowat = sock(&lock_state(), handle)?.opts.rcvlowat.max(1) as usize;
        lowat.min(want.capacity)
    };
    let mut incoming = Incoming::default();
    let mut first_creds: Option<Option<Creds>> = None;
    loop {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        if !matches!(as_unix(socket).state, State::Connected) {
            return Err(EINVAL);
        }
        let passcred = socket.opts.passcred;
        let peer = as_unix(socket).peer;
        let unix = as_unix_mut(socket);
        let mut consumed = false;
        let mut offset = 0;
        while incoming.data.len() < want.capacity {
            let Some(message) = unix.queue.get_mut(offset) else {
                break;
            };
            // Never glue writers with different credentials (when they are
            // reported), and stop after a message that carried descriptors.
            match first_creds {
                Some(creds) if passcred && creds != message.creds => break,
                Some(_) if !incoming.rights.is_empty() => break,
                _ => {}
            }
            first_creds.get_or_insert(message.creds);
            let take = message.remaining().min(want.capacity - incoming.data.len());
            incoming
                .data
                .extend_from_slice(&message.data[message.read..message.read + take]);
            if peek {
                // `unix_peek_fds`: a peek installs its own references to the
                // descriptors, which stay queued.
                incoming.rights.extend(peeked(&message.rights));
                offset += 1;
                if take < message.remaining() {
                    break;
                }
                continue;
            }
            incoming.rights.append(&mut message.rights);
            message.read += take;
            unix.queued -= take;
            consumed = true;
            if message.remaining() == 0 {
                unix.queue.pop_front();
            } else {
                break;
            }
        }
        let got = incoming.data.len();
        let mut wakes = Vec::new();
        if consumed {
            if let Some(peer) = peer {
                wakes.extend(room_freed(&mut state, peer));
            }
        }
        let socket = sock_mut(&mut state, handle)?;
        let done = got >= target
            || (got > 0 && (nonblocking || socket.shutdown & RCV_SHUTDOWN != 0))
            || !incoming.rights.is_empty();
        if done || peek && got > 0 {
            incoming.len = got;
            incoming.creds = reported(passcred, first_creds.flatten());
            drop(state);
            wake_all(wakes);
            return Ok(incoming);
        }
        if let Some(error) = socket.take_error() {
            drop(state);
            wake_all(wakes);
            return if got > 0 {
                incoming.len = got;
                Ok(incoming)
            } else {
                Err(error)
            };
        }
        if socket.shutdown & RCV_SHUTDOWN != 0 {
            incoming.len = got;
            drop(state);
            wake_all(wakes);
            return Ok(incoming);
        }
        if nonblocking || expired(deadline)? {
            drop(state);
            wake_all(wakes);
            return if got > 0 {
                incoming.len = got;
                Ok(incoming)
            } else {
                Err(EWOULDBLOCK)
            };
        }
        wake_all(wakes);
        park(state, handle, Dir::Recv, deadline, "unix-recv")
            .or_else(|errno| if got > 0 { Ok(()) } else { Err(errno) })?;
    }
}

fn recv_record(
    handle: c_int,
    want: Want,
    deadline: Option<u64>,
    nonblocking: bool,
    ty: i32,
) -> Result<Incoming, c_int> {
    loop {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        let passcred = socket.opts.passcred;
        // `unix_seqpacket_recvmsg`: only a connected socket receives.
        if ty == SOCK_SEQPACKET && !matches!(as_unix(socket).state, State::Connected) {
            return Err(ENOTCONN);
        }
        let unix = as_unix_mut(socket);
        if let Some(message) = unix.queue.front() {
            let whole = message.data.len();
            let copied = whole.min(want.capacity);
            let mut incoming = Incoming {
                data: message.data[..copied].to_vec(),
                len: if want.flags & MSG_TRUNC != 0 {
                    whole
                } else {
                    copied
                },
                from: Some(addr::encode_un(&message.from)),
                flags: if copied < whole { MSG_TRUNC } else { 0 },
                creds: reported(passcred, message.creds),
                ..Incoming::default()
            };
            if want.flags & MSG_PEEK != 0 {
                // `unix_peek_fds`.
                incoming.rights = peeked(&message.rights);
            }
            if want.flags & MSG_PEEK == 0 {
                let mut message = unix.queue.pop_front().expect("the front was just seen");
                unix.queued -= whole;
                incoming.rights = std::mem::take(&mut message.rights);
                // A sender waiting for room in this queue may proceed, and
                // the associated socket, whose sends land here, has room.
                let peer = unix.peer;
                let mut wakes = waiters(&mut state, handle, Dir::Send);
                if let Some(peer) = peer.filter(|peer| *peer != handle) {
                    wakes.extend(room_freed(&mut state, peer));
                }
                drop(state);
                wake_all(wakes);
            }
            if matches!(incoming.from.as_deref(), Some(bytes) if bytes.len() == addr::SUN_PATH) {
                // An unnamed sender reports no address at all.
                incoming.from = Some(Vec::new());
            }
            return Ok(incoming);
        }
        let socket = sock_mut(&mut state, handle)?;
        if let Some(error) = socket.take_error() {
            return Err(error);
        }
        if socket.shutdown & RCV_SHUTDOWN != 0 && (ty == SOCK_SEQPACKET || !nonblocking) {
            return Ok(Incoming::default());
        }
        if nonblocking || expired(deadline)? {
            return Err(EWOULDBLOCK);
        }
        park(state, handle, Dir::Recv, deadline, "unix-recv")?;
    }
}

/// The kernel poll mask (`unix_poll` for a stream, `unix_dgram_poll` for
/// datagrams and sequenced packets) and the arrivals so far.
pub(super) fn poll(
    state: &ThreadRuntime,
    handle: c_int,
    socket: &Socket,
    unix: &Unix,
) -> (u32, u64) {
    let mut mask = 0;
    if socket.error != 0 {
        mask |= POLLERR;
    }
    if socket.shutdown == SHUTDOWN_MASK {
        mask |= POLLHUP;
    }
    if socket.shutdown & RCV_SHUTDOWN != 0 {
        mask |= POLLRDHUP | POLLIN | POLLRDNORM;
    }
    let listening = matches!(&unix.state, State::Listening { .. });
    let queued = match &unix.state {
        State::Listening { pending, .. } => !pending.is_empty(),
        _ => !unix.queue.is_empty(),
    };
    if queued {
        mask |= POLLIN | POLLRDNORM;
    }
    let connection = socket.ty == SOCK_STREAM || socket.ty == SOCK_SEQPACKET;
    if connection && matches!(unix.state, State::Unconnected) {
        mask |= POLLHUP;
    }
    // `unix_writable`: what this socket has queued at its peer is within a
    // quarter of its send buffer.
    let peer = unix.peer.and_then(|peer| live(state, peer));
    let in_flight = peer.map_or(0, |peer| self::as_unix(peer).queued);
    let mut writable = !listening && in_flight * 4 <= socket.opts.sndbuf.max(0) as usize;
    // A datagram peer that is not associated back takes at most its queue.
    if let Some(peer) = peer.filter(|_| socket.ty != SOCK_STREAM) {
        let peer_unix = self::as_unix(peer);
        if peer_unix.peer != Some(handle) && peer_unix.queue.len() > MAX_DGRAM_QLEN {
            writable = false;
        }
    }
    if writable {
        mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
    }
    (mask, unix.arrivals)
}

/// `SIOCINQ` (`unix_inq_len`): a stream's or sequenced packet's unread
/// bytes, a datagram socket's next datagram.
/// `SIOCINQ` (`unix_inq_len`): `EINVAL` on a listener; the next datagram's
/// length, or the queued bytes of a stream or sequenced-packet socket.
pub(super) fn pending(socket: &Socket, unix: &Unix) -> Result<i32, c_int> {
    if matches!(unix.state, State::Listening { .. }) {
        return Err(EINVAL);
    }
    let bytes = if socket.ty == SOCK_DGRAM {
        unix.queue.front().map_or(0, |message| message.data.len())
    } else {
        unix.queue.iter().map(Message::remaining).sum()
    };
    Ok(i32::try_from(bytes).unwrap_or(i32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_takes_the_unix_protocols_and_types_the_kernel_does() {
        assert!(matches!(create(SOCK_STREAM, 0), Ok((SOCK_STREAM, 0, _))));
        assert!(matches!(create(SOCK_RAW, PF_UNIX), Ok((SOCK_DGRAM, 0, _))));
        assert!(matches!(create(SOCK_STREAM, 2), Err(EPROTONOSUPPORT)));
        // SOCK_RDM
        assert!(matches!(create(4, 0), Err(ESOCKTNOSUPPORT)));
    }
}
