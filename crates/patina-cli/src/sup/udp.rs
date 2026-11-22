//! Datagram (UDP) sockets.
//!
//! Every guest `AF_INET`/`AF_INET6` datagram socket is a real `AF_UNIX` `SOCK_SEQPACKET`
//! socket connected to a hidden end the supervisor accepts on `@patina-udp` (the first packet
//! names the socket). There are no connections: the supervisor keeps, per socket, its bound
//! port and address, its default peer and its reuse options, and routes each datagram itself.
//!
//! A send is a request (`UdpSend`): the supervisor reads the one packet the runtime just wrote,
//! assigns the next datagram id, and stamps it with a delivery time `now + draw(delay)` drawn
//! for that datagram alone, so datagrams may overtake one another inside the drawn latency, as
//! UDP allows. Faults are draws keyed by the datagram id and their own sub-key
//! (`Stream::Dgram`): drop, duplicate (the copy has its own delay), reorder (an extra hold), and
//! `net-blackout` (a datagram due inside the window is lost). With nodes, a datagram to another
//! node's address (`ADDR_NODE + j`, `rt::sys::udp`) goes to node `j`'s own address and arrives
//! from `ADDR_NODE + sender`; the link faults act on it as `net-links` says, and one sent
//! while its link is cut (`link::Sup::link_cut`) is lost. At its time (an event in the
//! scheduler's queue) the datagram is routed by its destination as Linux's lookup does
//! (connected and specific sockets first; a `SO_REUSEPORT` group by a hash of the source;
//! otherwise the most recently bound) and written to the receiver's hidden end behind a header
//! naming its source. A receiver whose queue is past its `SO_RCVBUF` (charged per datagram,
//! `dgram_charge`) loses it. A datagram nobody is bound to receive is lost; if its sender is
//! connected to that address it gets `ECONNREFUSED` (an ICMP port unreachable): `WSock::err`,
//! and a header-only packet that makes its descriptor readable.
//!
//! Decision records (`slot` 0): `DEC_UDP_SEND`, `DEC_UDP_DELIVER`, `DEC_UDP_CLOSE`
//! (`proto::ctl`). Each injected fault is an `Injected` record naming the datagram.

use super::sched::EventId;
use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use proto::vfs::{VINO_BASE, VINO_CAP};
use proto::wire::*;
use proto::{draw, Stream};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::Ordering::Relaxed;

/// Event kind of a datagram in the wire's event keys (`wire::key`).
pub const EV_UDP: u64 = 3;
const ECONNREFUSED: u64 = 111;

/// `DEC_UDP_SEND` fate bits.
const UF_DROP: u64 = 1;
const UF_DUP: u64 = 2;
const UF_REORDER: u64 = 4;
const UF_BLACKOUT: u64 = 8;
const UF_CUT: u64 = 16;
/// `DEC_UDP_DELIVER` outcomes.
const UD_DELIVERED: u64 = 0;
const UD_NO_RECEIVER: u64 = 1;
const UD_RCVBUF_FULL: u64 = 2;
const UD_HELD: u64 = 3;
/// Its node's machine crashed while it was in flight: lost, and no error comes back.
const UD_MACHINE_DOWN: u64 = 4;
/// Its node was paused when it arrived: lost, as on a cut link.
const UD_PAUSED: u64 = 5;

struct USock {
    /// The hidden end.
    fd: i32,
    family: u16,
    /// 0: not bound.
    port: u16,
    kind: u8,
    flags: u64,
    peer: Option<(u8, u16)>,
    /// Bind order (the most recent bind wins a tie).
    order: u64,
    /// Packets the kernel did not take yet (its buffer was full).
    held: VecDeque<Vec<u8>>,
    /// The node of the process that made it: datagrams stay on their node (`ADDR_HOST4` is
    /// the node's own address here, `rt::sys::udp`).
    node: usize,
}

struct Flight {
    src: usize,
    /// The node it is routed in, and the destination kind as its sender named it.
    node: usize,
    named: u8,
    skind: u8,
    sport: u16,
    dkind: u8,
    dport: u16,
    data: Vec<u8>,
    dup: bool,
}

#[derive(Default)]
pub struct Udp {
    listen_fd: i32,
    pending: BTreeMap<usize, i32>,
    socks: BTreeMap<usize, USock>,
    /// Bound sockets by (node, port): every node has its own port space.
    ports: BTreeMap<(usize, u16), Vec<usize>>,
    next_port: BTreeMap<usize, u16>,
    next_id: u64,
    next_order: u64,
    flight: BTreeMap<u64, (Flight, EventId)>,
    pub blocked: BTreeSet<usize>,
    /// Socket count at which closed sockets are looked for next.
    sweep_at: usize,
    buf: Vec<u8>,
    /// The hidden ends' send buffer the host grants (`SO_SNDBUF` as read back).
    host_sndbuf: i32,
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// The destination address kinds a socket bound at `kind` receives.
fn covers(family: u16, kind: u8, v6only: bool, dkind: u8) -> bool {
    match (family, kind) {
        (AF_INET, ADDR_ANY) => matches!(dkind, ADDR_LOOP4 | ADDR_HOST4),
        (AF_INET6, ADDR_ANY) => dkind == ADDR_LOOP6 || (!v6only && dkind != ADDR_ANY),
        (_, k) => k == dkind,
    }
}

impl Udp {
    pub fn init(&mut self) -> Result<(), String> {
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        let (a, l) = abstract_addr(UDP_NAME, None);
        if fd < 0
            || unsafe { libc::bind(fd, a.as_ptr() as *const libc::sockaddr, l) } != 0
            || unsafe { libc::listen(fd, 4096) } != 0
        {
            return Err(format!("datagram listener: errno {}", errno()));
        }
        // The hidden ends ask for DGRAM_BUF_MAX (doubled by the kernel): a host whose
        // net.core.wmem_max is lower would hold deliveries a default host makes, so a run that
        // makes a UDP socket there ends `infra` (`udp_socket`); other runs are not affected.
        let v: libc::c_int = DGRAM_BUF_MAX;
        let (mut got, mut gl): (libc::c_int, libc::socklen_t) = (0, 4);
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &v as *const _ as *const _,
                4,
            );
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &mut got as *mut _ as *mut _,
                &mut gl,
            );
        }
        self.host_sndbuf = got;
        self.listen_fd = fd;
        self.next_id = 1;
        self.sweep_at = 64;
        self.buf = vec![0u8; DGRAM_MAX6 + DGRAM_HDR + 64];
        Ok(())
    }

    fn live(&self, i: usize) -> bool {
        self.socks
            .get(&i)
            .is_some_and(|s| !super::wire::pollhup(s.fd))
    }
}

impl Sup {
    pub fn udp_op(&mut self, op: Op, idx: usize, a: [u64; 6]) -> Next {
        let r = match op {
            Op::UdpSocket => self.udp_socket(a[0] as usize, a[1] as u16, self.node_of(idx)),
            Op::UdpBind => self.udp_bind(a[0] as usize, a[1] as u16, a[2] as u8, a[3]),
            // A shutdown of the read side: wake what waits for the socket to be readable.
            Op::UdpConnect if a[3] == 2 => {
                self.udp_mark(a[0] as usize);
                0
            }
            Op::UdpConnect => {
                if let Some(s) = self.udp.socks.get_mut(&(a[0] as usize)) {
                    s.peer = (a[3] == 1).then_some((a[2] as u8, a[1] as u16));
                    s.kind = a[4] as u8;
                    if a[3] == 0 && a[5] == 0 && s.port != 0 {
                        let (p, node) = (s.port, s.node);
                        s.port = 0;
                        self.udp_unport(a[0] as usize, node, p);
                    }
                }
                0
            }
            Op::UdpSend => self.udp_send(a),
            _ => -(libc::ENOSYS as i64),
        };
        Next::Continue(r)
    }

    fn udp_socket(&mut self, i: usize, family: u16, node: usize) -> i64 {
        if self.udp.host_sndbuf < 2 * DGRAM_BUF_MAX {
            self.finish(Verdict::new(
                "infra",
                format!(
                    "datagram buffers: the host's net.core.wmem_max allows {} bytes, {} are needed",
                    self.udp.host_sndbuf / 2,
                    DGRAM_BUF_MAX
                ),
            ));
        }
        loop {
            let fd = unsafe {
                libc::accept4(
                    self.udp.listen_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                break;
            }
            // Room for what a receiver's SO_RCVBUF admits (the kernel charges the hidden end).
            let v: libc::c_int = DGRAM_BUF_MAX;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &v as *const _ as *const _,
                    4,
                )
            };
            let mut pre = [0u64; 2];
            let r = unsafe { libc::recv(fd, pre.as_mut_ptr() as *mut _, 16, libc::MSG_DONTWAIT) };
            if r != 16 || pre[0] != UDP_MAGIC || pre[1] < VINO_BASE {
                self.finish(Verdict::new("infra", "udp: a socket without a preamble"));
            }
            if let Some(old) = self.udp.pending.insert((pre[1] - VINO_BASE) as usize, fd) {
                unsafe { libc::close(old) };
            }
        }
        let Some(fd) = self.udp.pending.remove(&i) else {
            self.finish(Verdict::new(
                "infra",
                format!("udp: no hidden end for socket {i}"),
            ));
        };
        self.udp.socks.insert(
            i,
            USock {
                fd,
                family,
                port: 0,
                kind: ADDR_ANY,
                flags: 0,
                peer: None,
                order: 0,
                held: VecDeque::new(),
                node,
            },
        );
        if self.udp.socks.len() >= self.udp.sweep_at {
            self.udp_sweep(None);
            self.udp.sweep_at = self.udp.socks.len() * 2 + 64;
        }
        0
    }

    /// Forget the sockets whose guest descriptors are all closed (`only`: just these).
    pub fn udp_sweep(&mut self, only: Option<&[usize]>) {
        let cand: Vec<usize> = match only {
            Some(v) => v
                .iter()
                .copied()
                .filter(|i| self.udp.socks.contains_key(i))
                .collect(),
            None => self.udp.socks.keys().copied().collect(),
        };
        for i in cand {
            if !self.udp.live(i) {
                self.udp_close(i);
            }
        }
    }

    fn udp_close(&mut self, i: usize) {
        let Some(s) = self.udp.socks.remove(&i) else {
            return;
        };
        unsafe { libc::close(s.fd) };
        self.udp.blocked.remove(&i);
        if s.port != 0 {
            self.udp_unport(i, s.node, s.port);
        }
        self.wire_decide(DEC_UDP_CLOSE, [i as u64, s.port as u64, 0, 0, 0, 0]);
    }

    fn udp_unport(&mut self, i: usize, node: usize, p: u16) {
        if let Some(v) = self.udp.ports.get_mut(&(node, p)) {
            v.retain(|&x| x != i);
            if v.is_empty() {
                self.udp.ports.remove(&(node, p));
            }
        }
    }

    /// Live sockets of node `node` bound to `p`.
    fn udp_on_port(&mut self, node: usize, p: u16) -> Vec<usize> {
        let v = self.udp.ports.get(&(node, p)).cloned().unwrap_or_default();
        let mut out = vec![];
        for j in v {
            if self.udp.live(j) {
                out.push(j);
            } else {
                self.udp_close(j);
            }
        }
        out
    }

    fn udp_bind(&mut self, i: usize, port: u16, kind: u8, flags: u64) -> i64 {
        let Some((family, node)) = self.udp.socks.get(&i).map(|s| (s.family, s.node)) else {
            return -(libc::EBADF as i64);
        };
        let v6only = flags & UDP_V6ONLY != 0;
        let p = if port == 0 {
            let span = (PORT_LAST - PORT_FIRST) as u32 + 1;
            let mut got = None;
            for _ in 0..span {
                let next = self.udp.next_port.entry(node).or_insert(PORT_FIRST);
                let p = *next;
                *next = if p >= PORT_LAST { PORT_FIRST } else { p + 1 };
                if self.udp_on_port(node, p).is_empty() {
                    got = Some(p);
                    break;
                }
            }
            match got {
                Some(p) => p,
                None => return -(libc::EADDRINUSE as i64),
            }
        } else {
            for j in self.udp_on_port(node, port) {
                let o = &self.udp.socks[&j];
                let ov6 = o.flags & UDP_V6ONLY != 0;
                let overlap = [ADDR_LOOP4, ADDR_HOST4, ADDR_LOOP6]
                    .iter()
                    .any(|&d| covers(family, kind, v6only, d) && covers(o.family, o.kind, ov6, d));
                let shared = (flags & o.flags & UDP_REUSEADDR != 0)
                    || (flags & o.flags & UDP_REUSEPORT != 0);
                if j != i && overlap && !shared {
                    return -(libc::EADDRINUSE as i64);
                }
            }
            port
        };
        self.udp.next_order += 1;
        let order = self.udp.next_order;
        let s = self.udp.socks.get_mut(&i).unwrap();
        s.port = p;
        s.kind = kind;
        s.flags = flags;
        s.order = order;
        self.udp.ports.entry((node, p)).or_default().push(i);
        p as i64
    }

    /// A per-mille datagram fault, drawn for datagram `id` and class `sub`.
    fn dgram_fault(&self, permille: u64, id: u64, sub: u64) -> bool {
        permille > 0
            && self.faults_on()
            && draw(self.ctl.config.seed, Stream::Dgram, id << 4 | sub) % 1000 < permille
    }

    fn dgram_draw(&self, id: u64, sub: u64, (lo, hi): (u64, u64)) -> u64 {
        lo + draw(self.ctl.config.seed, Stream::Dgram, id << 4 | sub) % (hi - lo + 1)
    }

    /// An injected datagram fault: `args` = [kind, link (`inj_link`, with nodes), value, id,
    /// destination port, source port].
    #[allow(clippy::too_many_arguments)]
    fn dgram_inject(
        &mut self,
        kind: u64,
        nr: u32,
        value: u64,
        id: u64,
        dport: u16,
        sport: u16,
        link: u64,
    ) {
        let seq = self.next_seq();
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr,
            args: [kind, link, value, id, dport as u64, sport as u64],
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

    fn udp_send(&mut self, a: [u64; 6]) -> i64 {
        let (i, dport, dkind, len, nr) = (
            a[0] as usize,
            a[1] as u16,
            a[2] as u8,
            a[3] as usize,
            a[4] as u32,
        );
        let Some(s) = self.udp.socks.get(&i) else {
            self.finish(Verdict::new(
                "infra",
                format!("udp: send on unknown socket {i}"),
            ));
        };
        let (fd, sport, skind, node) = (s.fd, s.port, s.kind, s.node);
        let r = unsafe {
            libc::recv(
                fd,
                self.udp.buf.as_mut_ptr() as *mut _,
                self.udp.buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if r != len as isize {
            self.finish(Verdict::new(
                "infra",
                format!(
                    "udp: socket {i} sent {len} bytes, the supervisor read {r} (errno {})",
                    errno()
                ),
            ));
        }
        let data = self.udp.buf[..len].to_vec();
        let id = self.udp.next_id;
        self.udp.next_id += 1;
        // Another node's address: routed to that node's own, from the sender's.
        let named = dkind;
        let (dnode, dkind, skind) = match dkind {
            k if k >= ADDR_NODE => ((k - ADDR_NODE) as usize, ADDR_HOST4, ADDR_NODE + node as u8),
            k => (node, k, if skind == ADDR_ANY { k } else { skind }),
        };
        let c = &tab(self.ctl).counters;
        WireTab::inc(&c.datagrams, 1);
        let cfg = tab(self.ctl).cfg;
        let now = self.now();
        let faulted = self.link_faulted(node, dnode);
        if faulted {
            self.dgram_elig();
        }
        let link = if self.node_count() > 0 {
            inj_link(node, dnode)
        } else {
            0
        };
        let range = self.link_delay_range(node, dnode);
        let mut fate = 0;
        let mut t = now + self.dgram_draw(id, DSUB_DELAY, range);
        if self.link_cut(node, dnode) {
            fate |= UF_CUT;
            self.cut_acted(node, dnode);
        }
        if fate == 0 && faulted && self.dgram_fault(cfg.drop_permille, id, DSUB_DROP) {
            fate |= UF_DROP;
            self.dgram_inject(INJ_NET_DROP, nr, len as u64, id, dport, sport, link);
        }
        if fate == 0 && faulted && self.dgram_fault(cfg.reorder_permille, id, DSUB_REORDER) {
            // Held back past the jitter so that datagrams sent after it can arrive first.
            let hold = self.dgram_draw(id, DSUB_HOLD, (range.1.max(1), 4 * range.1 + 1_000_000));
            t += hold;
            fate |= UF_REORDER;
            self.dgram_inject(INJ_NET_REORDER, nr, hold, id, dport, sport, link);
        }
        if fate & (UF_DROP | UF_CUT) == 0
            && faulted
            && self.blackout_hold(t, sport, dport).is_some()
        {
            fate |= UF_BLACKOUT;
            WireTab::inc(&c.blacked_out, 1);
            self.dgram_inject(
                INJ_NET_BLACKOUT_DROP,
                nr,
                len as u64,
                id,
                dport,
                sport,
                link,
            );
        }
        let lost = fate & (UF_DROP | UF_BLACKOUT | UF_CUT) != 0;
        let f = |dup| Flight {
            src: i,
            node: dnode,
            named,
            skind,
            sport,
            dkind,
            dport,
            data: data.clone(),
            dup,
        };
        if !lost {
            self.udp_schedule(id, t, f(false));
        } else {
            WireTab::inc(&c.dgram_lost, 1);
        }
        if fate & UF_CUT == 0 && faulted && self.dgram_fault(cfg.dup_permille, id, DSUB_DUP) {
            let t2 = now + self.dgram_draw(id, DSUB_DUP_DELAY, range);
            fate |= UF_DUP;
            self.dgram_inject(INJ_NET_DUP, nr, len as u64, id, dport, sport, link);
            if self.blackout_hold(t2, sport, dport).is_none() {
                self.udp_schedule(id, t2, f(true));
            } else {
                WireTab::inc(&c.dgram_lost, 1);
            }
        }
        self.wire_decide(
            DEC_UDP_SEND,
            [
                id,
                sport as u64,
                dport as u64,
                len as u64,
                if lost { 0 } else { t },
                fate,
            ],
        );
        0
    }

    /// One more datagram the link faults act on (`proto::node::ELIG_DATAGRAMS`).
    fn dgram_elig(&self) {
        if self.node_count() > 0 {
            unsafe { proto::node::NodeTab::at(self.ctl as *const Ctl as *mut u8) }.elig
                [proto::node::ELIG_DATAGRAMS] += 1;
        } else if self
            .ctl
            .phases
            .phase
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0
        {
            self.ctl.phases.elig[proto::node::ELIG_DATAGRAMS]
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn udp_schedule(&mut self, id: u64, t: u64, f: Flight) {
        let k = id << 1 | f.dup as u64;
        let ev = self.sched.schedule(
            t,
            super::sched::Event::Wire {
                key: k << 2 | EV_UDP,
            },
        );
        self.udp.flight.insert(k, (f, ev));
    }

    /// The socket a datagram from (skind, sport) to (dkind, dport) reaches, if any.
    fn udp_route(
        &mut self,
        node: usize,
        skind: u8,
        sport: u16,
        dkind: u8,
        dport: u16,
    ) -> Option<usize> {
        let mut best: Vec<(u64, u64, usize)> = vec![];
        for j in self.udp_on_port(node, dport) {
            let s = &self.udp.socks[&j];
            if !covers(s.family, s.kind, s.flags & UDP_V6ONLY != 0, dkind) {
                continue;
            }
            if s.peer.is_some_and(|p| p != (skind, sport)) {
                continue;
            }
            let native = (s.family == AF_INET6) == (dkind == ADDR_LOOP6);
            let score =
                4 * s.peer.is_some() as u64 + 2 * (s.kind != ADDR_ANY) as u64 + native as u64;
            best.push((score, s.order, j));
        }
        let top = best.iter().map(|b| b.0).max()?;
        let mut tied: Vec<(u64, usize)> = best
            .iter()
            .filter(|b| b.0 == top)
            .map(|b| (b.1, b.2))
            .collect();
        tied.sort_unstable();
        let group = tied.len() > 1
            && tied
                .iter()
                .all(|&(_, j)| self.udp.socks[&j].flags & UDP_REUSEPORT != 0);
        Some(if group {
            let h = proto::draw::mix64((skind as u64) << 32 | (sport as u64) << 16 | dport as u64);
            tied[(h % tied.len() as u64) as usize].1
        } else {
            tied.last().unwrap().1
        })
    }

    /// A datagram's delivery time came (event key without its kind bits).
    pub fn udp_fire(&mut self, k: u64) {
        let Some((f, _)) = self.udp.flight.remove(&k) else {
            return;
        };
        let id = k >> 1;
        let len = f.data.len() as u64;
        let c = &tab(self.ctl).counters;
        if f.node < 64 && self.links.down >> f.node & 1 != 0 {
            WireTab::inc(&c.dgram_lost, 1);
            self.wire_decide(
                DEC_UDP_DELIVER,
                [id, 0, len, UD_MACHINE_DOWN, f.dup as u64, 0],
            );
            return;
        }
        // A datagram from another node (its sender's socket may have closed since).
        let from_other = self.udp.socks.get(&f.src).is_none_or(|s| s.node != f.node);
        if f.node < 64 && self.links.paused >> f.node & 1 != 0 && from_other {
            WireTab::inc(&c.dgram_lost, 1);
            self.wire_decide(DEC_UDP_DELIVER, [id, 0, len, UD_PAUSED, f.dup as u64, 0]);
            return;
        }
        let Some(j) = self.udp_route(f.node, f.skind, f.sport, f.dkind, f.dport) else {
            WireTab::inc(&c.dgram_lost, 1);
            self.wire_decide(
                DEC_UDP_DELIVER,
                [id, 0, len, UD_NO_RECEIVER, f.dup as u64, 0],
            );
            // Port unreachable: an error for a sender connected to that address.
            let to_sender =
                self.udp.live(f.src) && self.udp.socks[&f.src].peer == Some((f.named, f.dport));
            if to_sender && (f.src) < VINO_CAP {
                tab(self.ctl).socks[f.src].err = ECONNREFUSED as u16;
                self.udp_mark(f.src);
            }
            return;
        };
        let ws = &mut tab(self.ctl).socks[j];
        let rcvbuf = ws.opt(1 << 16 | 8).unwrap_or(DGRAM_BUF_DEFAULT).max(0) as u32;
        if ws.rq > rcvbuf {
            WireTab::inc(&c.dgram_lost, 1);
            self.wire_decide(
                DEC_UDP_DELIVER,
                [id, j as u64 + 1, len, UD_RCVBUF_FULL, f.dup as u64, 0],
            );
            return;
        }
        ws.rq = ws.rq.saturating_add(dgram_charge(len as usize));
        let hdr = [
            DG_DATA | (f.skind as u64) << 8 | (f.sport as u64) << 16,
            (id & 0xffff_ffff) | len << 32,
        ];
        let mut pkt = Vec::with_capacity(DGRAM_HDR + f.data.len());
        for w in hdr {
            pkt.extend_from_slice(&w.to_ne_bytes());
        }
        pkt.extend_from_slice(&f.data);
        WireTab::inc(&c.dgram_delivered, 1);
        let held = self.udp_put(j, pkt);
        self.wire_decide(
            DEC_UDP_DELIVER,
            [
                id,
                j as u64 + 1,
                len,
                if held { UD_HELD } else { UD_DELIVERED },
                f.dup as u64,
                0,
            ],
        );
    }

    /// Write a packet to socket `j`'s guest end, or hold it while the kernel has no room.
    /// Returns true when it was held.
    /// Make socket `j` readable with a marker (no data; the runtime skips it), unless one is
    /// already queued: a pending error or a shut read side needs one, not one per cause.
    fn udp_mark(&mut self, j: usize) {
        if j >= VINO_CAP || !self.udp.live(j) {
            return;
        }
        let ws = &mut tab(self.ctl).socks[j];
        if ws.marks & MARK_QUEUED != 0 {
            return;
        }
        ws.marks |= MARK_QUEUED;
        let hdr = [DG_ERR, 0u64];
        let pkt: Vec<u8> = hdr.iter().flat_map(|w| w.to_ne_bytes()).collect();
        self.udp_put(j, pkt);
    }

    fn udp_put(&mut self, j: usize, pkt: Vec<u8>) -> bool {
        let Some(s) = self.udp.socks.get_mut(&j) else {
            return false;
        };
        s.held.push_back(pkt);
        self.udp_flush(j);
        self.udp.blocked.contains(&j)
    }

    /// Write what socket `j` holds, in order, until the kernel refuses.
    pub fn udp_flush(&mut self, j: usize) {
        let mut moved = false;
        loop {
            let Some(s) = self.udp.socks.get_mut(&j) else {
                self.udp.blocked.remove(&j);
                break;
            };
            let Some(p) = s.held.front() else {
                self.udp.blocked.remove(&j);
                break;
            };
            let r = unsafe {
                libc::send(
                    s.fd,
                    p.as_ptr() as *const _,
                    p.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if r == p.len() as isize {
                s.held.pop_front();
                moved = true;
                continue;
            }
            let e = errno();
            if r < 0 && e == libc::EAGAIN {
                self.udp.blocked.insert(j);
                break;
            }
            if r < 0 && (e == libc::EPIPE || e == libc::ECONNRESET) {
                // Every guest descriptor of it is closed.
                self.udp_close(j);
                break;
            }
            self.finish(Verdict::new(
                "infra",
                format!("udp: write to socket {j}: {r} errno {e}"),
            ));
        }
        if moved {
            self.bump_gen();
        }
    }
}

fn tab(ctl: &Ctl) -> &'static mut WireTab {
    unsafe { WireTab::at(ctl as *const Ctl as *mut u8) }
}
