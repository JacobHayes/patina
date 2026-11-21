//! The network wire.
//!
//! Every guest `AF_INET`/`AF_INET6` stream socket is a real `AF_UNIX` stream socket whose
//! kernel peer is a socket the supervisor holds: its *hidden end*. A connection has two:
//! the client's (accepted on `@patina-wire` and paired by the preamble that names the socket)
//! and the server's (the supervisor's own socket, bound to `@patina-c-<id>` and connected to the
//! guest's listening socket `@patina-l-<port>` at the virtual moment of establishment).
//!
//! The supervisor moves bytes only in its own steps (`step`): it reads the hidden ends the
//! runtime marked (a send, a close, a shutdown), stamps what it read with a delivery time
//! `now + draw(NetDelay)` (never earlier than the previous chunk of that direction), and at
//! that time (an event in the scheduler's queue) writes it to the other hidden end. What the
//! receiver's buffer does not take stays queued and is retried when the I/O generation
//! moves. A direction holding `WINDOW` bytes is not read further, so the sender's kernel
//! buffer fills and it sees back-pressure. Every write into a guest-visible buffer and every
//! close of a hidden end bumps the I/O generation.
//!
//! EOF on a hidden end (the guest closed its last reference or shut down writing) becomes a
//! FIN, delivered as `shutdown(SHUT_WR)` on the far hidden end; `ECONNRESET` on a hidden end
//! (the guest closed with unread data) becomes a RST. Data for a guest that has gone sends a
//! RST back. A RST closes the far hidden end and marks the socket so that the runtime reports
//! `ECONNRESET` once (a RST after a FIN only closes it: the guest then sees `EPIPE`, as TCP in
//! `CLOSE_WAIT` does).
//!
//! Decision records (all `slot` 0): `DEC_WIRE_READ` [conn, dir, bytes, delivery time],
//! `DEC_WIRE_DELIVER` [conn, dir, bytes], `DEC_WIRE_ESTABLISH` [conn, server port, client port],
//! `DEC_WIRE_FIN` [conn, dir, 0 queued | 1 delivered], `DEC_WIRE_RST` [conn, side, why],
//! `DEC_WIRE_FAIL` [conn, errno], `DEC_WIRE_CLOSE` [conn], `DEC_WIRE_PROBE` [conn, side,
//! unanswered] (keepalive, `Sup::ka_fire`). Direction 0 is client to server.
//!
//! Nodes (`proto::node`): every node has its own port space and address; a connection joins a
//! client node and a server node (the same one over loopback), and each direction is a link.
//! A cut link (`link::Sup::link_cut`, a script's or the seed's) holds what is stamped on it:
//! the item keeps its delay draw and no time (`HELD`) until a heal stamps it, at the heal's
//! time plus that draw; a direction held for Linux's give-up time (or its sender's
//! `TCP_USER_TIMEOUT`) gives up, and its sender sees `ETIMEDOUT`. A connect across a cut link
//! (either direction) does not establish: it retries at TCP's SYN retry times
//! (Linux's six, or the socket's `TCP_SYNCNT`) and establishes at the first one after a
//! heal, or fails `ETIMEDOUT` after the last. The link faults (`net-*`) act on the links
//! `link_faulted` names; the others carry the default delay and nothing else.

use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use proto::nr;
use proto::vfs::{VINO_BASE, VINO_CAP};
use proto::wire::*;
use proto::{draw, Stream};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::Ordering::Relaxed;

const READ_MAX: usize = 64 << 10;
/// Event kinds in the low bits of an event key: delivery in direction 0 or 1, the connect fate.
const EV_DIR0: u64 = 0;
const EV_DIR1: u64 = 1;
const EV_CONNECT: u64 = 2;

const ECONNREFUSED: u16 = 111;
const ETIMEDOUT: u16 = 110;

/// An item stamped on a cut link: no delivery time yet, its delay draw in the low bits.
const HELD: u64 = 1 << 63;
/// Recorded socket options (`WSock::opts` keys): `TCP_SYNCNT`, `TCP_USER_TIMEOUT`, and the
/// keepalive ones.
const OPT_TCP_SYNCNT: i32 = 6 << 16 | 7;
const OPT_TCP_USER_TIMEOUT: i32 = 6 << 16 | 18;
const OPT_SO_KEEPALIVE: i32 = 1 << 16 | 9;
const OPT_TCP_KEEPIDLE: i32 = 6 << 16 | 4;
const OPT_TCP_KEEPINTVL: i32 = 6 << 16 | 5;
const OPT_TCP_KEEPCNT: i32 = 6 << 16 | 6;
/// Linux's defaults (`net.ipv4.tcp_keepalive_time`, `_intvl`, `_probes`).
const KEEPALIVE_DEFAULT: (u64, u64, u64) = (7200, 75, 9);
/// A keepalive timer's event: an `EV_CONNECT` key with this bit, the side (1: the server's)
/// in the bit above it.
const EV_KA: u64 = 1 << 40;

/// Why a RST was sent (`DEC_WIRE_RST` args[2]).
const RST_CLOSE_UNREAD: u64 = 1;
const RST_FAULT: u64 = 2;
const RST_PEER_GONE: u64 = 3;
const RST_LISTENER_GONE: u64 = 4;
/// A direction held by a cut for its give-up time (`give_up_ns`): the sender gives up.
const RST_GIVE_UP: u64 = 5;
/// A segment reached an end whose machine crashed since: the node answers it with a RST.
const RST_UNKNOWN: u64 = 6;
/// A side's keepalive probes went unanswered for its budget: it gives up (`ETIMEDOUT`) and
/// sends a RST its peer gets if it can reach it.
const RST_KEEPALIVE: u64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    Establish,
    Refuse { injected: bool },
    Timeout,
}

#[derive(Debug)]
enum Item {
    Data { t: u64, buf: Vec<u8>, off: usize },
    Fin { t: u64 },
    Rst { t: u64, why: u64 },
}

impl Item {
    fn t(&self) -> u64 {
        match self {
            Item::Data { t, .. } | Item::Fin { t } | Item::Rst { t, .. } => *t,
        }
    }
}

#[derive(Default, Debug)]
struct Dir {
    q: VecDeque<Item>,
    bytes: usize,
    last_t: u64,
    /// Chunks stamped (the draw key).
    n: u64,
    /// Pieces split off by `net-chunk-max` (their own draw key, so that enabling the fault
    /// moves no other delivery).
    pieces: u64,
    ev: Option<super::sched::EventId>,
    /// The sender's end was not read further because the window was full.
    throttled: bool,
    /// A FIN went out in this direction (its receiver is in `CLOSE_WAIT`).
    fin_done: bool,
    /// The first item held by a cut, when it was stamped (`HELD` items wait for a heal).
    held_since: Option<u64>,
}

#[derive(Debug)]
struct End {
    /// The supervisor's hidden end (-1: closed).
    fd: i32,
    /// The guest socket's table index (None: the server side before `accept`).
    idx: Option<usize>,
    /// EOF read (FIN queued).
    eof: bool,
    /// The guest closed every reference.
    gone: bool,
    /// Its node's machine crashed (`wire_machine_down`): what reaches it is answered with a RST.
    dead: bool,
}

#[derive(Debug)]
struct Conn {
    client: End,
    server: End,
    sport: u16,
    cport: u16,
    /// Address kind the client connected to (also the address both sides see).
    kind: u8,
    listener: Option<usize>,
    fate: Fate,
    established: bool,
    /// The client's padding still to discard at establishment.
    pad: u64,
    fate_ev: Option<super::sched::EventId>,
    /// Establishment found the listener's backlog full: retry when the generation moves.
    retry: bool,
    /// The server side must report a reset when it is accepted.
    server_reset: bool,
    dirs: [Dir; 2],
    /// The client's node and the server's (the same over loopback).
    cnode: usize,
    snode: usize,
    /// When the connect was made, and the SYN retries a cut has cost it so far.
    syn_at: u64,
    syn_n: usize,
    /// The give-up check of a held direction (an `EV_CONNECT` event once established).
    give_up_ev: Option<super::sched::EventId>,
    /// Each side's keepalive timer (0: the client's).
    ka: [Ka; 2],
}

/// One side's keepalive state (`Sup::ka_fire`): when it last heard from its peer, the probes
/// unanswered since, and its timer, which is set only while the peer may not answer.
#[derive(Debug, Default)]
struct Ka {
    heard: u64,
    probes: u64,
    /// Probes answered (the key of their round trip's delay draw).
    answered: u64,
    ev: Option<super::sched::EventId>,
    /// The settings last seen, and the earliest first probe they allow (`ka_arm`: as the
    /// kernel resets the timer when keepalive is turned on or its idle time changes).
    seen: Option<KaCfg>,
    anchor: u64,
    /// This side's socket went without telling its peer (its give-up across a cut): the
    /// peer's next probe gets a RST.
    rst: bool,
    /// Data it sent was delivered while the way back was cut: unacknowledged, so no probes
    /// (TCP's retransmission timer owns the connection), until it hears from its peer.
    unacked: bool,
}

/// What a keepalive probe gets back (`Sup::ka_reach`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    Answer,
    /// The peer's machine came back without the connection: its node answers with a RST.
    Rst,
    /// Lost: a cut either way, the peer's machine down, a blackout.
    Nothing,
}

/// A side's keepalive settings, in ns (`ut`: `TCP_USER_TIMEOUT`, 0 when unset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KaCfg {
    idle: u64,
    intvl: u64,
    cnt: u64,
    ut: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SockRec {
    family: u16,
    port: u16,
    kind: u8,
    listening: bool,
    /// The node of the process that made it.
    node: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortUse {
    Bound(usize),
    Client(u32),
}

#[derive(Default)]
pub struct Wire {
    listen_fd: i32,
    /// Client hidden ends accepted on `@patina-wire`, by socket index, not yet claimed by a connect.
    pending: BTreeMap<usize, i32>,
    socks: BTreeMap<usize, SockRec>,
    /// Ports in use, by (node, port): every node has its own port space.
    ports: BTreeMap<(usize, u16), PortUse>,
    /// The next ephemeral port of each node.
    next_port: BTreeMap<usize, u16>,
    conns: BTreeMap<u32, Conn>,
    next_conn: u32,
    /// Socket index → connection and side (true: server).
    by_idx: BTreeMap<usize, (u32, bool)>,
    /// Directions with due bytes that did not fit into the receiver's buffer.
    blocked: BTreeSet<(u32, usize)>,
    last_gen: u64,
    queued: u64,
    buf: Vec<u8>,
}

fn tab(ctl: &Ctl) -> &'static mut WireTab {
    unsafe { WireTab::at(ctl as *const Ctl as *mut u8) }
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn unix_socket() -> i32 {
    unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    }
}

fn fix_bufs(fd: i32) {
    let v: libc::c_int = 65_536;
    for o in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, o, &v as *const _ as *const _, 4) };
    }
}

fn sock_bind(fd: i32, prefix: &[u8], n: Option<u64>) -> i32 {
    let (a, l) = abstract_addr(prefix, n);
    unsafe { libc::bind(fd, a.as_ptr() as *const libc::sockaddr, l) }
}

fn sock_connect(fd: i32, prefix: &[u8], n: u64) -> i32 {
    let (a, l) = abstract_addr(prefix, Some(n));
    unsafe { libc::connect(fd, a.as_ptr() as *const libc::sockaddr, l) }
}

fn close(fd: i32) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

/// Is node `node`'s listener name for `port` (`@patina-l-<n>`) held by a live socket? (Bind a
/// probe to it.)
fn name_alive(node: usize, port: u16) -> bool {
    let p = unix_socket();
    if p < 0 {
        return true;
    }
    let r = sock_bind(p, LISTEN_PREFIX, Some(listen_n(node, port)));
    let e = errno();
    close(p);
    r != 0 && e == libc::EADDRINUSE
}

pub(super) fn pollhup(fd: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) == 1 && p.revents & libc::POLLHUP != 0 }
}

/// Read and discard everything pending on `fd`.
fn drain(fd: i32, buf: &mut [u8]) {
    loop {
        let r = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if r <= 0 {
            return;
        }
    }
}

fn key(id: u32, kind: u64) -> u64 {
    (id as u64) << 2 | kind
}

impl Wire {
    /// The wire listener, before the first guest exists.
    pub fn init(&mut self) -> Result<(), String> {
        let fd = unix_socket();
        if fd < 0 {
            return Err(format!("wire socket: errno {}", errno()));
        }
        if sock_bind(fd, WIRE_NAME, None) != 0 || unsafe { libc::listen(fd, 4096) } != 0 {
            return Err(format!("wire listener: errno {}", errno()));
        }
        self.listen_fd = fd;
        self.next_conn = 1;
        self.buf = vec![0u8; READ_MAX];
        Ok(())
    }

    fn port_free(&mut self, node: usize, p: u16) -> bool {
        match self.ports.get(&(node, p)) {
            None => true,
            Some(PortUse::Client(_)) => false,
            Some(PortUse::Bound(i)) => {
                if name_alive(node, p) {
                    return false;
                }
                let i = *i;
                self.ports.remove(&(node, p));
                if let Some(s) = self.socks.get_mut(&i) {
                    if s.port == p {
                        s.listening = false;
                    }
                }
                true
            }
        }
    }

    fn alloc_port(&mut self, node: usize, u: PortUse) -> Option<u16> {
        let span = (PORT_LAST - PORT_FIRST) as u32 + 1;
        for _ in 0..span {
            let next = self.next_port.entry(node).or_insert(PORT_FIRST);
            let p = *next;
            *next = if p >= PORT_LAST { PORT_FIRST } else { p + 1 };
            if let std::collections::btree_map::Entry::Vacant(e) = self.ports.entry((node, p)) {
                e.insert(u);
                return Some(p);
            }
        }
        None
    }

    /// The live listener of node `node` for a connection to `port` at address kind `kind`.
    fn listener(&mut self, node: usize, port: u16, kind: u8, ctl: &Ctl) -> Option<usize> {
        let Some(PortUse::Bound(i)) = self.ports.get(&(node, port)).copied() else {
            return None;
        };
        let s = *self.socks.get(&i)?;
        if !s.listening || s.port != port {
            return None;
        }
        let v6only = tab(ctl).socks[i].flags & WF_V6ONLY != 0;
        let ok = match (s.family, s.kind) {
            (AF_INET, ADDR_ANY) => kind != ADDR_LOOP6,
            (AF_INET6, ADDR_ANY) => !v6only || kind == ADDR_LOOP6,
            (_, k) => k == kind,
        };
        if !ok || !name_alive(node, port) {
            return None;
        }
        Some(i)
    }
}

impl Sup {
    pub(super) fn wire_decide(&mut self, code: u32, args: [u64; 6]) {
        WireTab::inc(&tab(self.ctl).counters.steps, 1);
        self.decide(code, 0, args, 0);
    }

    /// An injected network fault: a boundary record of kind `Injected` written by the
    /// supervisor; `args[4]` is the connection's server port (the object, `tcp:PORT`).
    fn wire_inject(&mut self, kind: u64, nr: u64, value: u64, conn: u32) {
        let seq = self.next_seq();
        let port = self.wire.conns.get(&conn).map_or(0, |c| c.sport as u64);
        // With nodes, the link: the client's node to the server's.
        let link = match self.wire.conns.get(&conn) {
            Some(c) if self.node_count() > 0 => inj_link(c.cnode, c.snode),
            _ => 0,
        };
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr: nr as u32,
            args: [kind, link, value, conn as u64, port, 0],
            ret: 0,
            out_hash: 0,
            in_hash: 0,
        };
        self.append(&rec);
        let f = &self.ctl.faults;
        f.injected.store(f.injected.load(Relaxed) + 1, Relaxed);
        let s = &self.ctl.stats.faults_injected;
        s.store(s.load(Relaxed) + 1, Relaxed);
    }

    pub(super) fn bump_gen(&self) {
        self.ctl
            .io
            .gen
            .store(self.ctl.io.gen.load(Relaxed) + 1, Relaxed);
    }

    fn net_cfg(&self) -> NetCfg {
        tab(self.ctl).cfg
    }

    /// In the fault window (after `setup-complete` in a run held until setup, before
    /// `faults-done`): faults may act.
    pub(super) fn faults_on(&self) -> bool {
        self.ctl.faults.cfg.in_window(self.ctl.seq.load(Relaxed))
    }

    /// A per-mille fault decision keyed by (connection, sub-key, n).
    fn net_fault(&self, permille: u64, id: u32, sub: u64, n: u64) -> bool {
        permille > 0
            && self.faults_on()
            && draw(
                self.ctl.config.seed,
                Stream::FaultNet,
                (id as u64) << 32 | sub << 28 | (n & 0x0fff_ffff),
            ) % 1000
                < permille
    }

    /// A delivery delay drawn in [min, max].
    fn net_delay(&self, id: u32, dir: u64, n: u64, range: (u64, u64)) -> u64 {
        let (lo, hi) = range;
        let d = draw(
            self.ctl.config.seed,
            Stream::NetDelay,
            (id as u64) << 32 | dir << 28 | (n & 0x0fff_ffff),
        );
        lo + d % (hi - lo + 1)
    }

    pub(super) fn delay_range(&self) -> (u64, u64) {
        let c = self.net_cfg();
        if c.delay_set != 0 {
            (c.delay_min_ns, c.delay_max_ns)
        } else {
            DEFAULT_DELAY_NS
        }
    }

    /// `net-blackout`: a delivery due at `t` on a connection between `sport` and `cport`
    /// waits for the end of the window (on a link the link faults act on).
    pub(super) fn blackout_hold(&self, t: u64, sport: u16, cport: u16) -> Option<u64> {
        let c = self.net_cfg();
        if c.blackout_set == 0 {
            return None;
        }
        let (from, to) = (
            proto::layout::VCLOCK_BOOT_NS + c.blackout_from_ns,
            proto::layout::VCLOCK_BOOT_NS + c.blackout_to_ns,
        );
        let port_ok = c.blackout_port == 0
            || c.blackout_port == sport as u64
            || c.blackout_port == cport as u64;
        (port_ok && t >= from && t < to).then_some(to)
    }

    /// The delay range of a link: the configured one where the link faults act, the default
    /// (loopback-like) one elsewhere.
    pub(super) fn link_delay_range(&self, from: usize, to: usize) -> (u64, u64) {
        if self.link_faulted(from, to) {
            self.delay_range()
        } else {
            DEFAULT_DELAY_NS
        }
    }

    /// The link direction `dir` of connection `id` travels: (from node, to node).
    fn link(c: &Conn, dir: usize) -> (usize, usize) {
        if dir == 0 {
            (c.cnode, c.snode)
        } else {
            (c.snode, c.cnode)
        }
    }

    /// Stamp the next chunk of direction `dir`: never earlier than the previous one; on a cut
    /// link, `HELD` with its draw (`wire_heal` stamps it).
    fn stamp(&mut self, id: u32, dir: usize, fin: bool) -> u64 {
        let now = self.now();
        let (n, last, sport, cport, link) = {
            let c = self.wire.conns.get_mut(&id).unwrap();
            c.dirs[dir].n += 1;
            let link = Self::link(c, dir);
            (c.dirs[dir].n, c.dirs[dir].last_t, c.sport, c.cport, link)
        };
        let faulted = self.link_faulted(link.0, link.1);
        let range = self.link_delay_range(link.0, link.1);
        let d = self.net_delay(id, dir as u64 | if fin { 2 } else { 0 }, n, range);
        let held = self.wire.conns[&id].dirs[dir].held_since.is_some();
        if held || self.link_cut(link.0, link.1) {
            self.cut_acted(link.0, link.1);
            self.hold(id, dir);
            return HELD | d;
        }
        let mut t = (now + d).max(last);
        if let Some(to) = self.blackout_hold(t, sport, cport).filter(|_| faulted) {
            t = to;
            WireTab::inc(&tab(self.ctl).counters.blacked_out, 1);
            self.wire_inject(INJ_NET_BLACKOUT, nr::SENDTO, t, id);
        }
        self.wire.conns.get_mut(&id).unwrap().dirs[dir].last_t = t;
        t
    }

    /// Make sure an event is scheduled for the head of direction `dir`.
    fn arm(&mut self, id: u32, dir: usize) {
        // A direction waiting for the receiver's room is retried when the generation moves.
        if self.wire.blocked.contains(&(id, dir)) {
            return;
        }
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return;
        };
        let d = &mut c.dirs[dir];
        let Some(t) = d.q.front().map(|i| i.t()) else {
            return;
        };
        if t & HELD != 0 {
            return;
        }
        if let Some(ev) = d.ev {
            if ev.0 <= t {
                return;
            }
            self.sched.cancel(ev);
        }
        d.ev = Some(self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: key(id, dir as u64),
            },
        ));
    }

    fn note_queued(&mut self, delta: i64) {
        self.wire.queued = (self.wire.queued as i64 + delta).max(0) as u64;
        let c = &tab(self.ctl).counters;
        if self.wire.queued > c.peak_queued.load(Relaxed) {
            c.peak_queued.store(self.wire.queued, Relaxed);
        }
    }

    pub fn wire_scan_all(&mut self) {
        tab(self.ctl).scan_all = 1;
    }

    // ---- requests ----

    pub fn wire_op(&mut self, op: Op, idx: usize, a: [u64; 6]) -> Next {
        let r = match op {
            Op::WireSocket => {
                let i = a[0] as usize;
                let node = self.node_of(idx);
                self.wire.socks.insert(
                    i,
                    SockRec {
                        family: a[1] as u16,
                        node,
                        ..SockRec::default()
                    },
                );
                0
            }
            Op::WireBind => self.wire_bind(a),
            Op::WireConnect => self.wire_connect(idx, a),
            Op::WireAccepted => self.wire_accepted(a),
            Op::WireSent => {
                self.wire_step();
                0
            }
            Op::WireRenew => self.wire_renew(idx, a),
            _ => -(libc::ENOSYS as i64),
        };
        Next::Continue(r)
    }

    /// A fresh real socket for socket `i` (`Op::WireRenew`): a new connect after a failed one,
    /// or a listener that stops (`RENEW_STOP`), whose waiting connections are reset as the
    /// kernel resets a closed listener's. The real socket is the one on the caller's
    /// descriptor `a[1]`: its inode is the host's, read here so that it never enters the
    /// request (which is recorded and compared).
    fn wire_renew(&mut self, idx: usize, a: [u64; 6]) -> i64 {
        let i = a[0] as usize;
        let tid = self.slot(idx).tid.load(Relaxed);
        let Some(ino) = super::proc::socket_ino(tid, a[1]) else {
            return -(libc::EBADF as i64);
        };
        let pids: Vec<i32> = self.procs.map.keys().copied().collect();
        if super::proc::socket_holders(&pids, ino) != (1, 0) {
            return -(libc::EBUSY as i64);
        }
        if a[2] == RENEW_STOP {
            if let Some(s) = self.wire.socks.get_mut(&i) {
                s.listening = false;
            }
            let waiting: Vec<u32> = self
                .wire
                .conns
                .iter()
                .filter(|(_, c)| c.listener == Some(i) && c.established && c.server.idx.is_none())
                .map(|(&id, _)| id)
                .collect();
            for id in waiting {
                self.reset_side(id, false, RST_LISTENER_GONE);
                self.reset_side(id, true, RST_LISTENER_GONE);
            }
        }
        match self.wire.socks.get(&i) {
            Some(s) if s.port != 0 => s.port as i64 | (s.kind as i64) << 16,
            _ => 0,
        }
    }

    fn wire_bind(&mut self, a: [u64; 6]) -> i64 {
        let (i, port, kind, mode) = (a[0] as usize, a[1] as u16, a[2] as u8, a[3]);
        let Some(mut s) = self.wire.socks.get(&i).copied() else {
            return -(libc::EBADF as i64);
        };
        if mode == WIRE_LISTEN {
            s.listening = true;
            self.wire.socks.insert(i, s);
            return s.port as i64;
        }
        let p = if port == 0 {
            match self.wire.alloc_port(s.node, PortUse::Bound(i)) {
                Some(p) => p,
                None => return -(libc::EADDRINUSE as i64),
            }
        } else {
            if !self.wire.port_free(s.node, port) {
                return -(libc::EADDRINUSE as i64);
            }
            self.wire.ports.insert((s.node, port), PortUse::Bound(i));
            port
        };
        s.port = p;
        s.kind = kind;
        self.wire.socks.insert(i, s);
        p as i64
    }

    /// Accept every connection waiting on `@patina-wire` and read its preamble.
    fn wire_accept_pending(&mut self) {
        loop {
            let fd = unsafe {
                libc::accept4(
                    self.wire.listen_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                return;
            }
            fix_bufs(fd);
            let mut pre = [0u8; PREAMBLE_LEN];
            let r = unsafe {
                libc::recv(
                    fd,
                    pre.as_mut_ptr() as *mut _,
                    PREAMBLE_LEN,
                    libc::MSG_DONTWAIT,
                )
            };
            let magic = u64::from_ne_bytes(pre[..8].try_into().unwrap());
            let vino = u64::from_ne_bytes(pre[8..].try_into().unwrap());
            if r != PREAMBLE_LEN as isize || magic != PREAMBLE_MAGIC || vino < VINO_BASE {
                close(fd);
                self.finish(Verdict::new(
                    "infra",
                    "wire: a connection without a preamble",
                ));
            }
            let i = (vino - VINO_BASE) as usize;
            if let Some(old) = self.wire.pending.insert(i, fd) {
                close(old);
            }
        }
    }

    fn wire_connect(&mut self, idx: usize, a: [u64; 6]) -> i64 {
        let (i, port, kind, pad) = (a[0] as usize, a[1] as u16, a[2] as u8, a[3]);
        // Loopback stays on the caller's node; a node address leads to that node.
        let cnode = self.node_of(idx);
        let snode = addr_node(kind).unwrap_or(cnode);
        self.wire_accept_pending();
        let Some(cfd) = self.wire.pending.remove(&i) else {
            self.finish(Verdict::new(
                "infra",
                format!("wire: no hidden end for socket {i}"),
            ));
        };
        let id = self.wire.next_conn;
        self.wire.next_conn += 1;
        let bound = self.wire.socks.get(&i).map(|s| s.port).unwrap_or(0);
        let cport = if bound != 0 {
            bound
        } else {
            match self.wire.alloc_port(cnode, PortUse::Client(id)) {
                Some(p) => p,
                None => {
                    close(cfd);
                    return -(libc::EADDRNOTAVAIL as i64);
                }
            }
        };
        let cfg = self.net_cfg();
        let listener = self.wire.listener(snode, port, kind, self.ctl);
        let faulted = self.link_faulted(cnode, snode);
        let fate = if faulted && self.net_fault(cfg.refuse_permille, id, NSUB_REFUSE, 0) {
            self.wire_inject(INJ_NET_REFUSE, nr::CONNECT, ECONNREFUSED as u64, id);
            Fate::Refuse { injected: true }
        } else if faulted && self.net_fault(cfg.timeout_permille, id, NSUB_TIMEOUT, 0) {
            self.wire_inject(INJ_NET_TIMEOUT, nr::CONNECT, ETIMEDOUT as u64, id);
            Fate::Timeout
        } else if listener.is_none() {
            Fate::Refuse { injected: false }
        } else {
            Fate::Establish
        };
        let now = self.now();
        // Across a cut link (either way) the handshake cannot complete: SYN retries.
        let cut = self.link_cut(cnode, snode) || self.link_cut(snode, cnode);
        if cut {
            self.cut_acted(cnode, snode);
            self.cut_acted(snode, cnode);
        }
        let mut t = match fate {
            Fate::Timeout => now + self.syn_retry_ns(i, self.syn_retries(i)),
            _ if cut => now + self.syn_retry_ns(i, 0),
            _ => now + self.net_delay(id, NSUB_HANDSHAKE, 0, self.link_delay_range(cnode, snode)),
        };
        if fate != Fate::Timeout && !cut && faulted {
            if let Some(to) = self.blackout_hold(t, port, cport) {
                t = to;
                WireTab::inc(&tab(self.ctl).counters.blacked_out, 1);
                self.wire_inject(INJ_NET_BLACKOUT, nr::CONNECT, t, id);
            }
        }
        let ev = self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: key(id, EV_CONNECT),
            },
        );
        let conn = Conn {
            client: End {
                fd: cfd,
                idx: Some(i),
                eof: false,
                gone: false,
                dead: false,
            },
            server: End {
                fd: -1,
                idx: None,
                eof: false,
                gone: false,
                dead: false,
            },
            sport: port,
            cport,
            kind,
            listener,
            fate,
            established: false,
            pad,
            fate_ev: Some(ev),
            retry: false,
            server_reset: false,
            dirs: [Dir::default(), Dir::default()],
            cnode,
            snode,
            syn_at: now,
            syn_n: (cut && fate != Fate::Timeout) as usize,
            give_up_ev: None,
            ka: Default::default(),
        };
        self.wire.conns.insert(id, conn);
        // A socket index may come back (a new socket in a reused inode): forget the old link.
        self.wire.by_idx.insert(i, (id, false));
        let (laddr, _) = self.wire.conns[&id].addrs(false);
        let s = &mut tab(self.ctl).socks[i];
        s.state = WS_CONNECTING;
        s.lport = cport;
        s.laddr = laddr;
        s.rport = port;
        s.raddr = kind;
        s.conn = id;
        WireTab::inc(&tab(self.ctl).counters.connections, 1);
        if faulted {
            self.link_elig(proto::node::ELIG_CONNECTIONS);
        }
        0
    }

    fn wire_accepted(&mut self, a: [u64; 6]) -> i64 {
        let (id, i) = (a[0] as u32, a[1] as usize);
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return -(libc::ECONNABORTED as i64);
        };
        c.server.idx = Some(i);
        let (sport, cport, kind, reset, snode) =
            (c.sport, c.cport, c.kind, c.server_reset, c.snode);
        let (laddr, raddr) = c.addrs(true);
        c.server_reset = false;
        self.wire.by_idx.insert(i, (id, true));
        let family = a[2] as u16;
        self.wire.socks.insert(
            i,
            SockRec {
                family,
                port: sport,
                kind,
                listening: false,
                node: snode,
            },
        );
        let s = &mut tab(self.ctl).socks[i];
        s.state = WS_CONNECTED;
        s.lport = sport;
        s.laddr = laddr;
        s.rport = cport;
        s.raddr = raddr;
        s.conn = id;
        if reset {
            s.flags |= WF_RESET;
        }
        self.ka_arm(id, true);
        0
    }

    // ---- the step ----

    /// The wire's part of a supervisor step: read the marked hidden ends, retry what was
    /// blocked if the I/O generation moved, handle fired events.
    pub fn wire_step(&mut self) {
        let t = tab(self.ctl);
        let gen = self.ctl.io.gen.load(Relaxed);
        if self.wire.conns.is_empty()
            && t.dirty_n == 0
            && t.scan_all == 0
            && self.sched.fired_wire.is_empty()
            && self.udp.blocked.is_empty()
        {
            self.wire.last_gen = gen;
            return;
        }
        // 1. Marks left by the runtime.
        let all = t.scan_all != 0;
        let n = (t.dirty_n as usize).min(DIRTY_CAP);
        let mut marked: Vec<usize> = t.dirty[..n].iter().map(|&x| x as usize).collect();
        for &i in &marked {
            if i < VINO_CAP {
                t.socks[i].flags &= !WF_SENT;
            }
        }
        t.dirty_n = 0;
        t.scan_all = 0;
        let mut sides: BTreeSet<(u32, bool)> = BTreeSet::new();
        let mut closed: Vec<usize> = vec![];
        if all {
            for (&id, c) in &self.wire.conns {
                sides.insert((id, false));
                if c.established {
                    sides.insert((id, true));
                }
            }
            for s in t.socks.iter_mut().filter(|s| s.flags & WF_SENT != 0) {
                s.flags &= !WF_SENT;
            }
        } else {
            marked.sort_unstable();
            marked.dedup();
            for i in marked {
                if i < VINO_CAP && t.socks[i].flags & WF_DGRAM != 0 {
                    closed.push(i);
                    continue;
                }
                if let Some(&(id, server)) = self.wire.by_idx.get(&i) {
                    sides.insert((id, server));
                }
                // A listener closed: its connections not yet accepted lose their embryo.
                if self.wire.socks.get(&i).is_some_and(|s| s.listening) {
                    for (&id, c) in &self.wire.conns {
                        if c.listener == Some(i) && c.established && c.server.idx.is_none() {
                            sides.insert((id, true));
                        }
                    }
                }
            }
        }
        for (id, server) in sides {
            self.read_side(id, server);
            // A keepalive option may have changed (`setsockopt` marks the socket).
            self.ka_arm(id, server);
        }
        // Datagram sockets whose last descriptor may have closed.
        if all {
            self.udp_sweep(None);
        } else if !closed.is_empty() {
            self.udp_sweep(Some(&closed));
        }
        // 2. The generation moved: receivers may have room, a backlog may have space.
        if gen != self.wire.last_gen || all {
            let blocked: Vec<(u32, usize)> =
                std::mem::take(&mut self.wire.blocked).into_iter().collect();
            for (id, dir) in blocked {
                self.deliver(id, dir);
            }
            let retry: Vec<u32> = self
                .wire
                .conns
                .iter()
                .filter(|(_, c)| c.retry)
                .map(|(&k, _)| k)
                .collect();
            for id in retry {
                self.establish(id);
            }
            let held: Vec<usize> = self.udp.blocked.iter().copied().collect();
            for j in held {
                self.udp_flush(j);
            }
        }
        // 3. Events.
        for k in std::mem::take(&mut self.sched.fired_wire) {
            let id = (k >> 2) as u32;
            if k & 3 == EV_CONNECT && k & EV_KA != 0 {
                self.ka_fire(id, k & EV_KA << 1 != 0);
                continue;
            }
            match k & 3 {
                super::udp::EV_UDP => self.udp_fire(k >> 2),
                EV_DIR0 | EV_DIR1 => {
                    let dir = (k & 3) as usize;
                    if let Some(c) = self.wire.conns.get_mut(&id) {
                        c.dirs[dir].ev = None;
                        self.deliver(id, dir);
                    }
                }
                _ => {
                    if let Some(c) = self.wire.conns.get_mut(&id) {
                        if c.established {
                            c.give_up_ev = None;
                            self.give_up(id);
                            continue;
                        }
                        c.fate_ev = None;
                        if c.syn_n > 0 && self.syn_retry(id) {
                            continue;
                        }
                        let c = &self.wire.conns[&id];
                        match c.fate {
                            Fate::Establish => self.establish(id),
                            Fate::Refuse { .. } => self.connect_failed(id, ECONNREFUSED),
                            Fate::Timeout => self.connect_failed(id, ETIMEDOUT),
                        }
                    }
                }
            }
        }
        self.wire.last_gen = self.ctl.io.gen.load(Relaxed);
    }

    /// The handshake completed: connect the server's hidden end to the guest's listener.
    fn establish(&mut self, id: u32) {
        let Some(c) = self.wire.conns.get(&id) else {
            return;
        };
        if c.established {
            return;
        }
        if c.client.gone || c.client.fd < 0 {
            self.free_conn(id);
            return;
        }
        let (sport, cfd, pad) = (c.sport, c.client.fd, c.pad);
        let mut sfd = c.server.fd;
        if sfd < 0 {
            sfd = unix_socket();
            if sfd < 0 || sock_bind(sfd, CONN_PREFIX, Some(id as u64)) != 0 {
                self.finish(Verdict::new(
                    "infra",
                    format!("wire: server end for connection {id}: errno {}", errno()),
                ));
            }
            fix_bufs(sfd);
            self.wire.conns.get_mut(&id).unwrap().server.fd = sfd;
        }
        let snode = self.wire.conns[&id].snode;
        let r = sock_connect(sfd, LISTEN_PREFIX, listen_n(snode, sport));
        let e = errno();
        if r != 0 && e == libc::EAGAIN {
            self.wire.conns.get_mut(&id).unwrap().retry = true;
            return;
        }
        if r != 0 {
            // The listener went away (closed, or no longer listening) before the handshake ended.
            self.connect_failed(id, ECONNREFUSED);
            return;
        }
        // Discard the padding that kept the client's descriptor from looking writable.
        let mut left = pad as usize;
        while left > 0 {
            let n = left.min(self.wire.buf.len());
            let r = unsafe {
                libc::recv(
                    cfd,
                    self.wire.buf.as_mut_ptr() as *mut _,
                    n,
                    libc::MSG_DONTWAIT,
                )
            };
            if r <= 0 {
                self.finish(Verdict::new(
                    "infra",
                    format!("wire: padding of connection {id} missing ({r})"),
                ));
            }
            left -= r as usize;
        }
        let now = self.now();
        let c = self.wire.conns.get_mut(&id).unwrap();
        c.established = true;
        c.retry = false;
        let (ci, cport) = (c.client.idx, c.cport);
        if let Some(ci) = ci {
            tab(self.ctl).socks[ci].state = WS_CONNECTED;
        }
        for k in &mut c.ka {
            k.heard = now;
        }
        self.bump_gen();
        self.wire_decide(
            DEC_WIRE_ESTABLISH,
            [id as u64, sport as u64, cport as u64, 0, 0, 0],
        );
        self.ka_arm(id, false);
        self.ka_arm(id, true);
        // Bytes the client wrote meanwhile (after the padding) are waiting.
        self.read_side(id, false);
    }

    fn connect_failed(&mut self, id: u32, err: u16) {
        let Some(c) = self.wire.conns.get(&id) else {
            return;
        };
        let ci = c.client.idx;
        if let Some(ci) = ci {
            let s = &mut tab(self.ctl).socks[ci];
            if s.conn == id {
                s.state = WS_FAILED;
                s.err = err;
            }
        }
        let cnt = &tab(self.ctl).counters;
        WireTab::inc(
            if err == ECONNREFUSED {
                &cnt.refused
            } else {
                &cnt.timeouts
            },
            1,
        );
        self.wire_decide(DEC_WIRE_FAIL, [id as u64, err as u64, 0, 0, 0, 0]);
        // Closing the client's hidden end with the padding unread makes its descriptor report
        // POLLOUT|POLLERR|POLLHUP, as a refused TCP connect does.
        self.free_conn(id);
        self.bump_gen();
    }

    /// Read what the guest of one side wrote (or its EOF / reset).
    fn read_side(&mut self, id: u32, server: bool) {
        let dir = server as usize; // the direction this side sends in
        let Some(c) = self.wire.conns.get(&id) else {
            return;
        };
        let e = if server { &c.server } else { &c.client };
        let fd = e.fd;
        if fd < 0 {
            return;
        }
        if !c.established {
            // Before establishment the client's hidden end holds only padding: just notice a
            // guest that gave up (closed the socket).
            if pollhup(fd) {
                self.free_conn(id);
            }
            return;
        }
        let mut moved = false;
        loop {
            let c = self.wire.conns.get_mut(&id).unwrap();
            let e = if server { &mut c.server } else { &mut c.client };
            if e.gone {
                break;
            }
            let room = WINDOW.saturating_sub(c.dirs[dir].bytes);
            if room == 0 {
                c.dirs[dir].throttled = true;
                break;
            }
            let n = room.min(READ_MAX);
            let r = unsafe {
                libc::recv(
                    fd,
                    self.wire.buf.as_mut_ptr() as *mut _,
                    n,
                    libc::MSG_DONTWAIT,
                )
            };
            let err = if r < 0 { errno() } else { 0 };
            if r > 0 {
                moved = true;
                let r = r as usize;
                let cfg = self.net_cfg();
                let k = self.wire.conns[&id].dirs[dir].n;
                WireTab::inc(&tab(self.ctl).counters.sends, 1);
                let (from, to) = Self::link(&self.wire.conns[&id], dir);
                let faulted = self.link_faulted(from, to);
                if faulted {
                    self.link_elig(proto::node::ELIG_SENDS);
                }
                if faulted
                    && self.net_fault(cfg.reset_permille, id, NSUB_RESET | (dir as u64) << 3, k)
                {
                    self.wire_inject(INJ_NET_RESET, nr::SENDTO, r as u64, id);
                    self.reset_both(id);
                    break;
                }
                let t = self.stamp(id, dir, false);
                let buf = self.wire.buf[..r].to_vec();
                let c = self.wire.conns.get_mut(&id).unwrap();
                c.dirs[dir].q.push_back(Item::Data { t, buf, off: 0 });
                c.dirs[dir].bytes += r;
                self.note_queued(r as i64);
                self.wire_decide(DEC_WIRE_READ, [id as u64, dir as u64, r as u64, t, 0, 0]);
                self.arm(id, dir);
                continue;
            }
            if r == 0 {
                let first = !e.eof;
                e.eof = true;
                let hup = pollhup(fd);
                if hup {
                    e.gone = true;
                }
                if first {
                    let t = self.stamp(id, dir, true);
                    self.wire.conns.get_mut(&id).unwrap().dirs[dir]
                        .q
                        .push_back(Item::Fin { t });
                    self.wire_decide(DEC_WIRE_FIN, [id as u64, dir as u64, 0, t, 0, 0]);
                    self.arm(id, dir);
                }
                break;
            }
            if err == libc::EAGAIN {
                break;
            }
            if err == libc::ECONNRESET || err == libc::EPIPE {
                // The guest closed with unread data: TCP sends a RST.
                e.eof = true;
                e.gone = true;
                let t = self.stamp(id, dir, false);
                self.wire.conns.get_mut(&id).unwrap().dirs[dir]
                    .q
                    .push_back(Item::Rst {
                        t,
                        why: RST_CLOSE_UNREAD,
                    });
                self.wire_decide(
                    DEC_WIRE_RST,
                    [id as u64, dir as u64, RST_CLOSE_UNREAD, t, 0, 0],
                );
                self.arm(id, dir);
                break;
            }
            self.finish(Verdict::new(
                "infra",
                format!("wire: read of connection {id}: errno {err}"),
            ));
        }
        if moved {
            self.bump_gen(); // the sender's buffer has room again
        }
        self.maybe_free(id);
    }

    /// Deliver what is due in direction `dir`.
    fn deliver(&mut self, id: u32, dir: usize) {
        let now = self.now();
        let (from, to) = match self.wire.conns.get(&id) {
            Some(c) => Self::link(c, dir),
            None => return,
        };
        let faulted = self.link_faulted(from, to);
        let chunk_max = if faulted {
            self.net_cfg().chunk_max as usize
        } else {
            0
        };
        loop {
            let Some(c) = self.wire.conns.get_mut(&id) else {
                return;
            };
            let (sport, cport) = (c.sport, c.cport);
            let dst_fd = if dir == 0 { c.server.fd } else { c.client.fd };
            let d = &mut c.dirs[dir];
            let Some(front) = d.q.front_mut() else { break };
            if front.t() > now {
                break;
            }
            let dead = if dir == 0 {
                c.server.dead
            } else {
                c.client.dead
            };
            if dead && !matches!(front, Item::Rst { .. }) {
                // Its node is back without the connection: the segment gets a RST, and the
                // rest in flight to it goes.
                let dropped = d.bytes;
                d.q.clear();
                d.bytes = 0;
                self.note_queued(-(dropped as i64));
                let c = self.wire.conns.get_mut(&id).unwrap();
                if dir == 0 {
                    c.server.dead = false;
                } else {
                    c.client.dead = false;
                }
                let back = 1 - dir;
                let t = self.stamp(id, back, false);
                self.wire.conns.get_mut(&id).unwrap().dirs[back]
                    .q
                    .push_back(Item::Rst {
                        t,
                        why: RST_UNKNOWN,
                    });
                self.wire_decide(DEC_WIRE_RST, [id as u64, back as u64, RST_UNKNOWN, t, 0, 0]);
                self.arm(id, back);
                break;
            }
            match front {
                Item::Data { buf, off, .. } => {
                    if dst_fd < 0 {
                        let left = buf.len() - *off;
                        d.bytes -= left;
                        d.q.pop_front();
                        self.note_queued(-(left as i64));
                        continue;
                    }
                    let want = buf.len() - *off;
                    let n = if chunk_max > 0 {
                        want.min(chunk_max)
                    } else {
                        want
                    };
                    let r = unsafe {
                        libc::send(
                            dst_fd,
                            buf[*off..].as_ptr() as *const _,
                            n,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                    if r > 0 {
                        let r = r as usize;
                        *off += r;
                        d.bytes -= r;
                        let done = *off == buf.len();
                        if done {
                            d.q.pop_front();
                        }
                        self.note_queued(-(r as i64));
                        let cnt = &tab(self.ctl).counters;
                        WireTab::inc(&cnt.bytes, r as u64);
                        WireTab::inc(&cnt.chunks, 1);
                        if faulted {
                            self.link_elig(proto::node::ELIG_CHUNKS);
                        }
                        self.bump_gen();
                        let split = chunk_max > 0 && !done;
                        if split {
                            self.wire_inject(INJ_NET_CHUNK, nr::SENDTO, r as u64, id);
                        }
                        self.wire_decide(
                            DEC_WIRE_DELIVER,
                            [id as u64, dir as u64, r as u64, 0, 0, 0],
                        );
                        self.ka_heard(id, dir);
                        if split {
                            // One piece per step: the rest is a chunk in flight of its own,
                            // timed from the pieces' own draw stream.
                            let c = self.wire.conns.get_mut(&id).unwrap();
                            let n = {
                                c.dirs[dir].pieces += 1;
                                c.dirs[dir].pieces
                            };
                            let cfg = self.net_cfg();
                            let gap = if cfg.chunk_gap_set != 0 {
                                (cfg.chunk_gap_min_ns, cfg.chunk_gap_max_ns)
                            } else {
                                self.delay_range()
                            };
                            let delay = self.net_delay(id, NSUB_CHUNK | dir as u64, n, gap);
                            let mut nt = now + delay.max(1);
                            if let Some(to) = self.blackout_hold(nt, sport, cport) {
                                nt = to;
                            }
                            let c = self.wire.conns.get_mut(&id).unwrap();
                            if let Some(f) = c.dirs[dir].q.front_mut() {
                                match f {
                                    Item::Data { t, .. }
                                    | Item::Fin { t }
                                    | Item::Rst { t, .. } => *t = (*t).max(nt),
                                }
                            }
                            break;
                        }
                        continue;
                    }
                    let err = errno();
                    if err == libc::EAGAIN {
                        self.wire.blocked.insert((id, dir));
                        break;
                    }
                    if err == libc::EPIPE || err == libc::ECONNRESET {
                        // The receiver is gone (or shut down reading): the data is dropped and,
                        // if it closed for good, a RST goes back to the sender.
                        let dropped = d.bytes;
                        d.q.retain(|i| !matches!(i, Item::Data { .. }));
                        d.bytes = 0;
                        self.note_queued(-(dropped as i64));
                        let c = self.wire.conns.get_mut(&id).unwrap();
                        let dst = if dir == 0 {
                            &mut c.server
                        } else {
                            &mut c.client
                        };
                        let gone = dst.gone || pollhup(dst_fd);
                        if gone {
                            dst.gone = true;
                            dst.eof = true;
                            let back = 1 - dir;
                            let t = self.stamp(id, back, false);
                            self.wire.conns.get_mut(&id).unwrap().dirs[back]
                                .q
                                .push_back(Item::Rst {
                                    t,
                                    why: RST_PEER_GONE,
                                });
                            self.wire_decide(
                                DEC_WIRE_RST,
                                [id as u64, back as u64, RST_PEER_GONE, t, 0, 0],
                            );
                            self.arm(id, back);
                        }
                        continue;
                    }
                    self.finish(Verdict::new(
                        "infra",
                        format!("wire: write of connection {id}: errno {err}"),
                    ));
                }
                Item::Fin { .. } => {
                    d.q.pop_front();
                    d.fin_done = true;
                    if dst_fd >= 0 {
                        unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                    }
                    WireTab::inc(&tab(self.ctl).counters.fins, 1);
                    if faulted {
                        self.link_elig(proto::node::ELIG_FINS);
                    }
                    self.bump_gen();
                    self.wire_decide(DEC_WIRE_FIN, [id as u64, dir as u64, 1, 0, 0, 0]);
                    self.ka_heard(id, dir);
                }
                Item::Rst { why, .. } => {
                    let why = *why;
                    d.q.pop_front();
                    self.reset_side(id, dir == 0, why);
                }
            }
        }
        // Room in the window again: read more from the sender.
        let throttled = self
            .wire
            .conns
            .get(&id)
            .is_some_and(|c| c.dirs[dir].throttled && c.dirs[dir].bytes < WINDOW);
        if throttled {
            self.wire.conns.get_mut(&id).unwrap().dirs[dir].throttled = false;
            self.read_side(id, dir == 1);
        }
        self.arm(id, dir);
        self.maybe_free(id);
    }

    /// A RST arrives at one side (`server`): its hidden end is drained and closed; the guest
    /// sees `ECONNRESET` once, or (after a FIN reached it) `EPIPE` on writes.
    fn reset_side(&mut self, id: u32, server: bool, why: u64) {
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return;
        };
        let into = server as usize ^ 1; // the direction that delivers to this side
        let after_fin = c.dirs[into].fin_done;
        // Nothing more reaches this side.
        let dropped: usize = c.dirs[into].bytes;
        c.dirs[into].q.clear();
        c.dirs[into].bytes = 0;
        if let Some(ev) = c.ka[server as usize].ev.take() {
            self.sched.cancel(ev);
        }
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return;
        };
        let e = if server { &mut c.server } else { &mut c.client };
        let (fd, idx) = (e.fd, e.idx);
        e.fd = -1;
        e.eof = true;
        e.gone = true;
        let accepted = idx.is_some();
        if (!server || accepted || why != RST_LISTENER_GONE) && !after_fin {
            match idx {
                Some(i) => tab(self.ctl).socks[i].flags |= WF_RESET,
                None if server => c.server_reset = true,
                None => {}
            }
        }
        // Its own queued sends die with it.
        let own = server as usize;
        let dropped2 = c.dirs[own].bytes;
        c.dirs[own].q.clear();
        c.dirs[own].bytes = 0;
        self.note_queued(-((dropped + dropped2) as i64));
        if fd >= 0 {
            drain(fd, &mut self.wire.buf);
            close(fd);
        }
        WireTab::inc(&tab(self.ctl).counters.resets, 1);
        self.bump_gen();
        self.wire_decide(DEC_WIRE_RST, [id as u64, server as u64, why, 1, 0, 0]);
        self.maybe_free(id);
    }

    /// `net-reset-permille`: both ends see the reset at once; bytes in flight are dropped.
    fn reset_both(&mut self, id: u32) {
        self.reset_side(id, false, RST_FAULT);
        self.reset_side(id, true, RST_FAULT);
    }

    /// Free a connection whose two guest sockets are gone and whose queues are empty.
    fn maybe_free(&mut self, id: u32) {
        let Some(c) = self.wire.conns.get(&id) else {
            return;
        };
        let side_done = |e: &End| e.fd < 0 || e.gone;
        let empty = c.dirs.iter().all(|d| d.q.is_empty());
        let server_done = side_done(&c.server) || (c.server.fd < 0 && !c.established);
        if c.established && side_done(&c.client) && server_done && empty {
            self.free_conn(id);
        }
    }

    fn free_conn(&mut self, id: u32) {
        let Some(c) = self.wire.conns.remove(&id) else {
            return;
        };
        for fd in [c.client.fd, c.server.fd] {
            close(fd);
        }
        for d in &c.dirs {
            if let Some(ev) = d.ev {
                self.sched.cancel(ev);
            }
            self.note_queued(-(d.bytes as i64));
        }
        for ev in [c.fate_ev, c.give_up_ev, c.ka[0].ev, c.ka[1].ev]
            .into_iter()
            .flatten()
        {
            self.sched.cancel(ev);
        }
        if self.wire.ports.get(&(c.cnode, c.cport)) == Some(&PortUse::Client(id)) {
            self.wire.ports.remove(&(c.cnode, c.cport));
        }
        for i in [c.client.idx, c.server.idx].into_iter().flatten() {
            if self.wire.by_idx.get(&i).is_some_and(|&(k, _)| k == id) {
                self.wire.by_idx.remove(&i);
            }
        }
        self.wire.blocked.retain(|&(k, _)| k != id);
        self.wire_decide(DEC_WIRE_CLOSE, [id as u64, 0, 0, 0, 0, 0]);
    }

    /// At the end of the run: the supervisor's peak resident memory.
    pub fn wire_note_hwm(&self) {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            if let Some(l) = s.lines().find(|l| l.starts_with("VmHWM:")) {
                let kb: u64 = l
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                tab(self.ctl).counters.sup_hwm_kb.store(kb, Relaxed);
            }
        }
    }
}

impl Conn {
    /// The (local, peer) address kinds one side sees: both the address connected to, as the
    /// one host saw them, unless the connection joins two nodes.
    fn addrs(&self, server: bool) -> (u8, u8) {
        if self.cnode == self.snode {
            return (self.kind, self.kind);
        }
        let (c, s) = (node_addr(self.cnode), self.kind);
        if server {
            (s, c)
        } else {
            (c, s)
        }
    }
}

impl Sup {
    /// SYN retries of socket `i`: its `TCP_SYNCNT` in a run with nodes (without nodes a socket
    /// option changes nothing), else Linux's default.
    fn syn_retries(&self, i: usize) -> u64 {
        if self.node_count() == 0 {
            return SYN_RETRIES_DEFAULT;
        }
        match tab(self.ctl)
            .socks
            .get(i)
            .and_then(|s| s.opt(OPT_TCP_SYNCNT))
        {
            Some(n) if n > 0 => n as u64,
            _ => SYN_RETRIES_DEFAULT,
        }
    }

    /// From a connect to its `n`-th SYN retry (`n` = the retries: the give-up), in ns.
    fn syn_retry_ns(&self, _i: usize, n: u64) -> u64 {
        syn_retry_s(n) * 1_000_000_000
    }

    /// How long direction `dir` of `id` may hold data before its sender gives up: the
    /// sender's `TCP_USER_TIMEOUT` when set in a run with nodes, else Linux's default.
    fn give_up_ns(&self, id: u32, dir: usize) -> u64 {
        if self.node_count() == 0 {
            return GIVE_UP_DEFAULT_NS;
        }
        let c = &self.wire.conns[&id];
        let sender = if dir == 0 { c.client.idx } else { c.server.idx };
        match sender.and_then(|i| {
            tab(self.ctl)
                .socks
                .get(i)
                .and_then(|s| s.opt(OPT_TCP_USER_TIMEOUT))
        }) {
            Some(ms) if ms > 0 => ms as u64 * 1_000_000,
            _ => GIVE_UP_DEFAULT_NS,
        }
    }

    /// One more chance a link fault had on a link it acts on (`proto::node::ELIG_*`).
    fn link_elig(&self, k: usize) {
        if self.node_count() > 0 {
            unsafe { proto::node::NodeTab::at(self.ctl as *const Ctl as *mut u8) }.elig[k] += 1;
        }
    }

    /// Direction `dir` of `id` holds its first item: the give-up clock starts.
    fn hold(&mut self, id: u32, dir: usize) {
        let now = self.now();
        let limit = self.give_up_ns(id, dir);
        let c = self.wire.conns.get_mut(&id).unwrap();
        if c.dirs[dir].held_since.is_some() {
            return;
        }
        c.dirs[dir].held_since = Some(now);
        let tb = unsafe { proto::node::NodeTab::at(self.ctl as *const Ctl as *mut u8) };
        tb.held += 1;
        let t = now + limit;
        if c.give_up_ev.is_some_and(|ev| ev.0 <= t) {
            return;
        }
        if let Some(ev) = c.give_up_ev.take() {
            self.sched.cancel(ev);
        }
        let ev = self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: key(id, EV_CONNECT),
            },
        );
        self.wire.conns.get_mut(&id).unwrap().give_up_ev = Some(ev);
    }

    /// The give-up check: a direction held for its give-up time resets its sender, who sees
    /// `ETIMEDOUT`; another still held is checked again at its own time.
    fn give_up(&mut self, id: u32) {
        let now = self.now();
        for dir in 0..2 {
            let Some(c) = self.wire.conns.get(&id) else {
                return;
            };
            let Some(since) = c.dirs[dir].held_since else {
                continue;
            };
            if now < since + self.give_up_ns(id, dir) {
                continue;
            }
            // The sender of `dir` is the client for direction 0.
            let sender = if dir == 0 { c.client.idx } else { c.server.idx };
            if let Some(i) = sender {
                tab(self.ctl).socks[i].err = ETIMEDOUT;
            }
            let c = self.wire.conns.get_mut(&id).unwrap();
            c.dirs[dir].held_since = None;
            c.ka[dir].rst = true;
            self.reset_side(id, dir == 1, RST_GIVE_UP);
            // Its peer's probes now get a RST (none while a cut holds them).
            self.ka_arm(id, dir == 0);
        }
        let next = self.wire.conns.get(&id).and_then(|c| {
            (0..2)
                .filter_map(|d| c.dirs[d].held_since.map(|s| s + self.give_up_ns(id, d)))
                .min()
        });
        if let Some(t) = next {
            let ev = self.sched.schedule(
                t,
                super::sched::Event::Wire {
                    key: key(id, EV_CONNECT),
                },
            );
            self.wire.conns.get_mut(&id).unwrap().give_up_ev = Some(ev);
        }
    }

    /// A connect's SYN retry under a cut came: healed, the handshake's own delay from now (to
    /// the listener there is now); still cut, the next retry, or after the last, `ETIMEDOUT`
    /// at the give-up time. True when the connect waits again.
    fn syn_retry(&mut self, id: u32) -> bool {
        let now = self.now();
        let c = &self.wire.conns[&id];
        let (cnode, snode, at, n, port, kind) =
            (c.cnode, c.snode, c.syn_at, c.syn_n, c.sport, c.kind);
        let cut = self.link_cut(cnode, snode) || self.link_cut(snode, cnode);
        let t = if !cut {
            let l = self.wire.listener(snode, port, kind, self.ctl);
            let c = self.wire.conns.get_mut(&id).unwrap();
            if c.fate == (Fate::Refuse { injected: false }) || c.fate == Fate::Establish {
                c.listener = l;
                c.fate = if l.is_some() {
                    Fate::Establish
                } else {
                    Fate::Refuse { injected: false }
                };
            }
            now + self.net_delay(id, NSUB_HANDSHAKE, 0, self.link_delay_range(cnode, snode))
        } else {
            let i = self.wire.conns[&id].client.idx.unwrap_or(usize::MAX);
            if n as u64 >= self.syn_retries(i) {
                self.wire.conns.get_mut(&id).unwrap().fate = Fate::Timeout;
            }
            at + self.syn_retry_ns(i, n as u64)
        };
        let ev = self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: key(id, EV_CONNECT),
            },
        );
        let c = self.wire.conns.get_mut(&id).unwrap();
        c.fate_ev = Some(ev);
        // Healed (or given up): the next event is the connect's fate, not another retry.
        c.syn_n = if cut && c.fate != Fate::Timeout {
            n + 1
        } else {
            0
        };
        true
    }

    /// Node `k`'s machine crashed (before its processes are killed): the wire forgets its
    /// ends without a FIN or RST to their peers. A connection within the node goes; a connect
    /// from it goes; a connect to it retries its SYN (the link is down, `link_cut`). An
    /// established connection keeps its peer's end: what the peer has in flight to the node,
    /// or sends later, is held (its give-up clock runs) until the node is back, where it gets a
    /// RST; what the node had stamped before the crash still arrives, what it held goes.
    pub(super) fn wire_machine_down(&mut self, k: usize) {
        let ids: Vec<u32> = self.wire.conns.keys().copied().collect();
        for id in ids {
            let c = &self.wire.conns[&id];
            let (on_c, on_s) = (c.cnode == k, c.snode == k);
            if !on_c && !on_s {
                continue;
            }
            if on_c && on_s || (!c.established && on_c) {
                self.free_conn(id);
                continue;
            }
            if !c.established {
                // A connect to the node: its SYN goes unanswered from here. One already
                // retrying keeps its schedule (each retry checks the link); else its first
                // retry comes at the first retry time, as for a connect across a cut.
                if c.fate != Fate::Timeout && c.syn_n == 0 {
                    let i = c.client.idx.unwrap_or(usize::MAX);
                    let t = (c.syn_at + self.syn_retry_ns(i, 0)).max(self.now());
                    let c = self.wire.conns.get_mut(&id).unwrap();
                    c.syn_n = 1;
                    // A connect waiting for room in the backlog waits no more.
                    c.retry = false;
                    if let Some(ev) = c.fate_ev.take() {
                        self.sched.cancel(ev);
                    }
                    let ev = self.sched.schedule(
                        t,
                        super::sched::Event::Wire {
                            key: key(id, EV_CONNECT),
                        },
                    );
                    self.wire.conns.get_mut(&id).unwrap().fate_ev = Some(ev);
                }
                continue;
            }
            let server = on_s;
            let own = server as usize; // the direction the dead end sends in
            let into = own ^ 1;
            let c = self.wire.conns.get_mut(&id).unwrap();
            let (cnode, cport) = (c.cnode, c.cport);
            let e = if server { &mut c.server } else { &mut c.client };
            let (fd, idx) = (e.fd, e.idx.take());
            if server {
                // Not an unaccepted connection of the listener its index may name again.
                c.listener = None;
            }
            let e = if server { &mut c.server } else { &mut c.client };
            e.fd = -1;
            e.eof = true;
            e.gone = true;
            e.dead = true;
            // What it held (in its machine's buffers) goes; what it stamped is on the wire.
            let d = &mut c.dirs[own];
            let held: usize =
                d.q.iter()
                    .filter(|i| i.t() & HELD != 0)
                    .map(|i| match i {
                        Item::Data { buf, off, .. } => buf.len() - off,
                        _ => 0,
                    })
                    .sum();
            d.q.retain(|i| i.t() & HELD == 0);
            d.bytes -= held;
            d.held_since = None;
            if fd >= 0 {
                drain(fd, &mut self.wire.buf);
                close(fd);
            }
            self.note_queued(-(held as i64));
            if let Some(i) = idx {
                if self.wire.by_idx.get(&i).is_some_and(|&(x, _)| x == id) {
                    self.wire.by_idx.remove(&i);
                }
            }
            if !server && self.wire.ports.get(&(cnode, cport)) == Some(&PortUse::Client(id)) {
                self.wire.ports.remove(&(cnode, cport));
            }
            // In flight to it: held from now, as on a cut link.
            let c = self.wire.conns.get_mut(&id).unwrap();
            let d = &mut c.dirs[into];
            let mut any = false;
            for it in d.q.iter_mut() {
                let t = match it {
                    Item::Data { t, .. } | Item::Fin { t } | Item::Rst { t, .. } => t,
                };
                if *t & HELD == 0 {
                    *t = HELD | 1;
                }
                any = true;
            }
            if let Some(ev) = d.ev.take() {
                self.sched.cancel(ev);
            }
            self.wire.blocked.remove(&(id, into));
            if any {
                self.hold(id, into);
            }
            self.wire_decide(DEC_WIRE_DEAD, [id as u64, server as u64, k as u64, 0, 0, 0]);
            if let Some(ev) = self
                .wire
                .conns
                .get_mut(&id)
                .and_then(|c| c.ka[own].ev.take())
            {
                self.sched.cancel(ev);
            }
            // Its peer's probes now go unanswered (or, once the node is back, get a RST).
            self.ka_arm(id, !server);
            self.maybe_free(id);
        }
        self.bump_gen();
    }

    /// Node `k` is paused (its links are cut, `Links::paused`): what is on its way to it and not
    /// yet delivered is held from now with the rest of its delay, so the sender's give-up clock
    /// runs; a handshake with it, either way, waits for its SYN retries (each looks at the
    /// link). What the node sent before the pause still arrives.
    pub(super) fn wire_pause(&mut self, k: usize) {
        let now = self.now();
        let ids: Vec<u32> = self.wire.conns.keys().copied().collect();
        for id in ids {
            let c = &self.wire.conns[&id];
            if c.cnode == c.snode || (c.cnode != k && c.snode != k) {
                continue;
            }
            if !c.established {
                if c.fate != Fate::Timeout && c.syn_n == 0 {
                    let i = c.client.idx.unwrap_or(usize::MAX);
                    let t = (c.syn_at + self.syn_retry_ns(i, 0)).max(now);
                    let c = self.wire.conns.get_mut(&id).unwrap();
                    c.syn_n = 1;
                    c.retry = false;
                    if let Some(ev) = c.fate_ev.take() {
                        self.sched.cancel(ev);
                    }
                    let ev = self.sched.schedule(
                        t,
                        super::sched::Event::Wire {
                            key: key(id, EV_CONNECT),
                        },
                    );
                    self.wire.conns.get_mut(&id).unwrap().fate_ev = Some(ev);
                }
                continue;
            }
            // Direction 0 goes to the server.
            let into = (c.snode != k) as usize;
            let c = self.wire.conns.get_mut(&id).unwrap();
            let d = &mut c.dirs[into];
            let mut any = false;
            for it in d.q.iter_mut() {
                let t = match it {
                    Item::Data { t, .. } | Item::Fin { t } | Item::Rst { t, .. } => t,
                };
                if *t & HELD == 0 {
                    *t = HELD | t.saturating_sub(now);
                }
                any = true;
            }
            if let Some(ev) = d.ev.take() {
                self.sched.cancel(ev);
            }
            self.wire.blocked.remove(&(id, into));
            if any {
                self.hold(id, into);
            }
        }
    }

    /// Links opened by a heal: every item held on them is stamped now (its own draw from the
    /// heal's time, never earlier than the item before it), and delivery resumes.
    pub(super) fn wire_heal(&mut self, opened: &[(usize, usize)]) {
        let now = self.now();
        let ids: Vec<u32> = self.wire.conns.keys().copied().collect();
        for id in ids {
            for dir in 0..2 {
                let c = self.wire.conns.get_mut(&id).unwrap();
                if c.dirs[dir].held_since.is_none() || !opened.contains(&Self::link(c, dir)) {
                    continue;
                }
                let d = &mut c.dirs[dir];
                d.held_since = None;
                let mut last = d.last_t;
                for it in d.q.iter_mut() {
                    let t = match it {
                        Item::Data { t, .. } | Item::Fin { t } | Item::Rst { t, .. } => t,
                    };
                    if *t & HELD != 0 {
                        *t = (now + (*t & !HELD)).max(last);
                        last = *t;
                    }
                }
                d.last_t = last;
                self.wire_decide(DEC_WIRE_HEAL, [id as u64, dir as u64, last, 0, 0, 0]);
                self.arm(id, dir);
            }
            // A side whose delivered data was not acknowledged: its retransmission gets the
            // acknowledgement now.
            for side in 0..2 {
                let c = self.wire.conns.get_mut(&id).unwrap();
                let back = Self::link(c, side ^ 1);
                if c.ka[side].unacked && opened.contains(&back) {
                    let k = &mut c.ka[side];
                    k.unacked = false;
                    k.heard = now;
                    k.probes = 0;
                    self.ka_arm(id, side == 1);
                }
            }
        }
    }
}

/// The keepalive timer key of one side of connection `id`.
fn ka_key(id: u32, server: bool) -> u64 {
    key(id, EV_CONNECT) | EV_KA | (server as u64) << 41
}

/// The first probe at or after `from` of a side whose peer answers until then: the first at
/// `first`, then one every `max(intvl, idle)` (the kernel's timer after an answered probe:
/// `intvl`, or the rest of `idle` from the answer; the answers' round trips are left out).
fn ka_grid(first: u64, cfg: &KaCfg, from: u64) -> u64 {
    let period = cfg.intvl.max(cfg.idle);
    if from <= first {
        first
    } else {
        first + (from - first).div_ceil(period) * period
    }
}

/// TCP keepalive (`SO_KEEPALIVE`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`,
/// `TCP_USER_TIMEOUT`), as the kernel's `tcp_keepalive_timer`: a side that has heard nothing
/// from its peer for `idle` probes it, then every `intvl`; an answer (any segment) resets the
/// count; after `cnt` unanswered probes (with a user timeout: once that long has passed since
/// it last heard and a probe went unanswered) it gives up: its socket reports `ETIMEDOUT` and
/// it sends a RST. A probe a peer answers changes nothing a guest can see, so the timer is
/// an event only while the peer may not answer (a cut either way, its machine down or back
/// without the connection, a `net-blackout` ahead): an idle connection whose peer is
/// reachable costs no event and no record. Every unanswered probe is a `DEC_WIRE_PROBE`
/// record.
impl Sup {
    /// Side `server` of `id` holds a guest socket that can probe (established, not closed,
    /// its machine up).
    fn ka_alive(c: &Conn, server: bool) -> bool {
        let e = if server { &c.server } else { &c.client };
        c.established && e.fd >= 0 && !e.gone && !e.dead
    }

    /// The side's keepalive settings, if keepalive is on (the server's, before `accept`,
    /// from its listener: an accepted socket inherits them).
    fn ka_cfg(&self, id: u32, server: bool) -> Option<KaCfg> {
        let c = self.wire.conns.get(&id)?;
        let (i, own) = match (server, c.server.idx) {
            (true, Some(i)) => (i, true),
            (true, None) => (c.listener?, false),
            (false, _) => (c.client.idx?, true),
        };
        let s = tab(self.ctl).socks.get(i)?;
        if s.opt(OPT_SO_KEEPALIVE).unwrap_or(0) == 0 {
            return None;
        }
        let get = |k: i32, d: u64| s.opt(k).filter(|&v| v > 0).map_or(d, |v| v as u64);
        let (idle, intvl, cnt) = KEEPALIVE_DEFAULT;
        Some(KaCfg {
            idle: get(OPT_TCP_KEEPIDLE, idle) * 1_000_000_000,
            intvl: get(OPT_TCP_KEEPINTVL, intvl) * 1_000_000_000,
            cnt: get(OPT_TCP_KEEPCNT, cnt),
            // A user timeout is not inherited at accept here (`ARCHITECTURE.md`, "Limits").
            ut: if own {
                get(OPT_TCP_USER_TIMEOUT, 0) * 1_000_000
            } else {
                0
            },
        })
    }

    /// The (this side's, peer's) nodes.
    fn ka_nodes(c: &Conn, server: bool) -> (usize, usize) {
        if server {
            (c.snode, c.cnode)
        } else {
            (c.cnode, c.snode)
        }
    }

    /// The `net-blackout` window `[from, to)` on this connection, if one acts on it.
    fn ka_blackout(&self, c: &Conn, server: bool) -> Option<(u64, u64)> {
        let b = self.net_cfg();
        let (me, peer) = Self::ka_nodes(c, server);
        let port_ok = b.blackout_port == 0
            || b.blackout_port == c.sport as u64
            || b.blackout_port == c.cport as u64;
        (b.blackout_set != 0 && port_ok && self.link_faulted(me, peer)).then_some((
            proto::layout::VCLOCK_BOOT_NS + b.blackout_from_ns,
            proto::layout::VCLOCK_BOOT_NS + b.blackout_to_ns,
        ))
    }

    /// What a probe from side `server` at `t` gets back.
    fn ka_reach(&self, id: u32, server: bool, t: u64) -> Reach {
        let c = &self.wire.conns[&id];
        let (me, peer) = Self::ka_nodes(c, server);
        if self.link_cut(me, peer) || self.link_cut(peer, me) {
            return Reach::Nothing;
        }
        if self
            .ka_blackout(c, server)
            .is_some_and(|(from, to)| t >= from && t < to)
        {
            return Reach::Nothing;
        }
        let p = if server { &c.client } else { &c.server };
        if p.dead || c.ka[!server as usize].rst {
            Reach::Rst
        } else {
            Reach::Answer
        }
    }

    /// (Re)set side `server`'s timer: the first probe the peer may not answer, if any. A side
    /// already probing keeps its schedule.
    fn ka_arm(&mut self, id: u32, server: bool) {
        let s = server as usize;
        if !self.wire.conns.contains_key(&id) {
            return;
        }
        let cfg = self.ka_cfg(id, server);
        let now = self.now();
        let c = self.wire.conns.get_mut(&id).unwrap();
        let k = &mut c.ka[s];
        if cfg != k.seen {
            match (k.seen, cfg) {
                // Turned on: the first probe one idle time from now (`tcp_set_keepalive`).
                (None, Some(n)) => k.anchor = now + n.idle,
                // A new idle time counts from when it last heard, or now if that is past.
                (Some(o), Some(n)) if o.idle != n.idle => k.anchor = now,
                _ => {}
            }
            k.seen = cfg;
        }
        if k.probes > 0 && k.ev.is_some() {
            return;
        }
        if let Some(ev) = c.ka[s].ev.take() {
            self.sched.cancel(ev);
        }
        let c = &self.wire.conns[&id];
        if !Self::ka_alive(c, server) {
            return;
        }
        let Some(cfg) = cfg else {
            return;
        };
        if c.ka[s].unacked {
            return;
        }
        let first = (c.ka[s].heard + cfg.idle).max(c.ka[s].anchor);
        let t = if self.ka_reach(id, server, now) != Reach::Answer {
            ka_grid(first, &cfg, now)
        } else if let Some((from, to)) = self.ka_blackout(c, server).filter(|w| w.1 > now) {
            let g = ka_grid(first, &cfg, from.max(now));
            if g >= to {
                return;
            }
            g
        } else {
            return;
        };
        self.ka_at(id, server, t);
    }

    fn ka_at(&mut self, id: u32, server: bool, t: u64) {
        let ev = self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: ka_key(id, server),
            },
        );
        self.wire.conns.get_mut(&id).unwrap().ka[server as usize].ev = Some(ev);
    }

    /// Every connection's timers: a cut began.
    pub(super) fn ka_arm_all(&mut self) {
        let ids: Vec<u32> = self.wire.conns.keys().copied().collect();
        for id in ids {
            self.ka_arm(id, false);
            self.ka_arm(id, true);
        }
    }

    /// A segment of direction `dir` was delivered: its receiver heard from its peer, and so
    /// does the sender when the receiver's acknowledgement can get back.
    fn ka_heard(&mut self, id: u32, dir: usize) {
        let now = self.now();
        let Some(c) = self.wire.conns.get(&id) else {
            return;
        };
        let (from, to) = Self::link(c, dir);
        let back = !self.link_cut(to, from);
        let blackout = self.net_cfg().blackout_set != 0;
        for (side, yes) in [(dir ^ 1, true), (dir, back)] {
            let c = self.wire.conns.get_mut(&id).unwrap();
            if !yes {
                // The sender's data is not acknowledged.
                c.ka[side].unacked = true;
                if let Some(ev) = c.ka[side].ev.take() {
                    self.sched.cancel(ev);
                }
                continue;
            }
            let k = &mut c.ka[side];
            k.heard = now;
            k.probes = 0;
            let rearm = k.ev.is_some() || k.unacked || blackout && k.seen.is_some();
            k.unacked = false;
            if rearm {
                self.ka_arm(id, side == 1);
            }
        }
    }

    /// Side `server`'s keepalive timer fired.
    fn ka_fire(&mut self, id: u32, server: bool) {
        let now = self.now();
        let s = server as usize;
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return;
        };
        c.ka[s].ev = None;
        if !Self::ka_alive(c, server) {
            return;
        }
        let Some(cfg) = self.ka_cfg(id, server) else {
            self.wire.conns.get_mut(&id).unwrap().ka[s].probes = 0;
            return;
        };
        let c = &self.wire.conns[&id];
        let (heard, probes) = (c.ka[s].heard, c.ka[s].probes);
        // Data of its own in flight: no probes (its give-up owns the connection); looked at
        // again an idle time later only while the peer may not answer.
        if !c.dirs[s].q.is_empty() || c.ka[s].unacked {
            if self.ka_reach(id, server, now) != Reach::Answer {
                self.ka_at(id, server, now + cfg.idle);
            }
            return;
        }
        if probes == 0 && now < (heard + cfg.idle).max(c.ka[s].anchor) {
            self.ka_arm(id, server);
            return;
        }
        let dies = if cfg.ut > 0 {
            now.saturating_sub(heard) >= cfg.ut && probes > 0
        } else {
            probes >= cfg.cnt
        };
        if dies {
            self.ka_die(id, server);
            return;
        }
        match self.ka_reach(id, server, now) {
            Reach::Answer => {
                // There and back, each way with its link's delay.
                let c = &self.wire.conns[&id];
                let (me, peer) = Self::ka_nodes(c, server);
                let n = c.ka[s].answered << 1 | s as u64;
                let rtt = self.net_delay(id, NSUB_KEEPALIVE, n, self.link_delay_range(me, peer))
                    + self.net_delay(
                        id,
                        NSUB_KEEPALIVE,
                        n | 1 << 26,
                        self.link_delay_range(peer, me),
                    );
                let k = &mut self.wire.conns.get_mut(&id).unwrap().ka[s];
                k.answered += 1;
                k.probes = 0;
                k.heard = now + rtt;
                self.ka_arm(id, server);
            }
            Reach::Rst => {
                // As a segment to an end whose machine crashed since (`deliver`).
                let into = s ^ 1;
                let c = self.wire.conns.get_mut(&id).unwrap();
                if server {
                    c.client.dead = false;
                } else {
                    c.server.dead = false;
                }
                c.ka[into].rst = false;
                let t = self.stamp(id, into, false);
                self.wire.conns.get_mut(&id).unwrap().dirs[into]
                    .q
                    .push_back(Item::Rst {
                        t,
                        why: RST_UNKNOWN,
                    });
                self.wire_decide(DEC_WIRE_RST, [id as u64, into as u64, RST_UNKNOWN, t, 0, 0]);
                self.arm(id, into);
            }
            Reach::Nothing => {
                let c = &self.wire.conns[&id];
                let (me, peer) = Self::ka_nodes(c, server);
                self.cut_acted(me, peer);
                self.cut_acted(peer, me);
                let k = &mut self.wire.conns.get_mut(&id).unwrap().ka[s];
                k.probes += 1;
                let p = k.probes;
                self.wire_decide(DEC_WIRE_PROBE, [id as u64, s as u64, p, 0, 0, 0]);
                self.ka_at(id, server, now + cfg.intvl);
            }
        }
    }

    /// Side `server` gave up: its socket reports `ETIMEDOUT`; its RST reaches the peer if
    /// the peer can be reached now, else the peer's next segment is answered with one.
    fn ka_die(&mut self, id: u32, server: bool) {
        let now = self.now();
        let c = &self.wire.conns[&id];
        if let Some(i) = if server { c.server.idx } else { c.client.idx } {
            tab(self.ctl).socks[i].err = ETIMEDOUT;
        }
        let reach = self.ka_reach(id, server, now);
        self.reset_side(id, server, RST_KEEPALIVE);
        let Some(c) = self.wire.conns.get_mut(&id) else {
            return;
        };
        let peer_alive = Self::ka_alive(c, !server);
        if reach == Reach::Answer && peer_alive {
            let own = server as usize;
            let t = self.stamp(id, own, false);
            self.wire.conns.get_mut(&id).unwrap().dirs[own]
                .q
                .push_back(Item::Rst {
                    t,
                    why: RST_KEEPALIVE,
                });
            self.wire_decide(
                DEC_WIRE_RST,
                [id as u64, own as u64, RST_KEEPALIVE, t, 0, 0],
            );
            self.arm(id, own);
        } else if peer_alive {
            let c = self.wire.conns.get_mut(&id).unwrap();
            if server {
                c.server.dead = true;
            } else {
                c.client.dead = true;
            }
            // The peer's next probe gets the RST.
            self.ka_arm(id, !server);
        }
    }
}
