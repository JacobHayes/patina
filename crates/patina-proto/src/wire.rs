//! The network wire's shared state: one entry per
//! virtual inode number (the key of every guest socket, stream or datagram), the "sent" marks
//! the runtime leaves for the supervisor, and the outcome counters. Lives in the control region after the
//! durability state, so every process of a run sees one table. Written only by whoever holds
//! the turn: the runtime of the calling thread, or the supervisor in its own steps.

use crate::vfs::VINO_CAP;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Byte offset of `WireTab` in the control region (after `oplog::Dur`).
pub const WIRE_OFFSET: usize = (crate::oplog::DUR_OFFSET + crate::oplog::DUR_SIZE + 0xFFF) & !0xFFF;
pub const WIRE_SIZE: usize = core::mem::size_of::<WireTab>();

/// Capacity of the "sent" list; beyond it the supervisor scans every connection.
pub const DIRTY_CAP: usize = 256;
/// Recorded socket options per socket.
pub const OPTS_CAP: usize = 12;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// `WSock::state`.
pub const WS_NEW: u8 = 0;
pub const WS_BOUND: u8 = 1;
pub const WS_LISTEN: u8 = 2;
pub const WS_CONNECTING: u8 = 3;
pub const WS_CONNECTED: u8 = 4;
/// A connect failed (refused or timed out): `err` holds the errno until `SO_ERROR` reads it.
pub const WS_FAILED: u8 = 5;
/// A failed connect whose error a later `connect` reported (the kernel's `SS_UNCONNECTED`
/// after `sock_error`): another `connect` would be a new attempt.
pub const WS_ABORTED: u8 = 6;
/// A listener that `shutdown(SHUT_RD|SHUT_RDWR)` stopped (the kernel's `TCP_CLOSE`): `accept`
/// fails `EINVAL`, its real socket is a fresh unconnected one (as `poll` should see it).
pub const WS_STOPPED: u8 = 7;

/// `WSock::flags`.
pub const WF_SENT: u8 = 1;
/// The connection was reset: the next receive or send reports `ECONNRESET` once.
pub const WF_RESET: u8 = 2;
pub const WF_V6ONLY: u8 = 4;
/// A datagram (UDP) socket: `state` is `WS_NEW`, `WS_BOUND` or `WS_CONNECTED` (a default peer).
pub const WF_DGRAM: u8 = 8;
/// `shutdown` of a datagram socket: reads return 0 / writes `EPIPE`.
pub const WF_SHUT_RD: u8 = 16;
pub const WF_SHUT_WR: u8 = 32;
/// The guest bound the address (not only the port): `connect` keeps it, a disconnect does not reset it.
pub const WF_USER_ADDR: u8 = 64;
/// The guest bound the port: a disconnect keeps it.
pub const WF_USER_PORT: u8 = 128;

/// Address kinds (`laddr`, `raddr`): the host has one address plus loopback.
pub const ADDR_ANY: u8 = 0;
pub const ADDR_LOOP4: u8 = 1;
/// 10.0.0.1, the host address.
pub const ADDR_HOST4: u8 = 2;
pub const ADDR_LOOP6: u8 = 3;
/// In a run with machines, machine `k` (1 upward) has `10.0.0.(k + 1)`: kind `ADDR_MACHINE + k`. The
/// main's address is `ADDR_HOST4`, as the one host's is without machines.
pub const ADDR_MACHINE: u8 = 0x10;

/// The address kind of machine `machine`'s own address.
pub const fn machine_addr(machine: usize) -> u8 {
    if machine == 0 {
        ADDR_HOST4
    } else {
        ADDR_MACHINE + machine as u8
    }
}

/// The machine whose address kind `kind` is (`None`: any, or a loopback kind).
pub const fn addr_machine(kind: u8) -> Option<usize> {
    match kind {
        ADDR_HOST4 => Some(0),
        k if k > ADDR_MACHINE && k < ADDR_MACHINE + crate::machine::MAX_MACHINES as u8 => {
            Some((k - ADDR_MACHINE) as usize)
        }
        _ => None,
    }
}

/// The last octet of an address kind's `10.0.0.X` (`None`: not a machine address).
pub const fn addr_octet(kind: u8) -> Option<u8> {
    match addr_machine(kind) {
        Some(n) => Some(n as u8 + 1),
        None => None,
    }
}

/// The number in a listener's abstract name (`LISTEN_PREFIX`): the port, with the machine above
/// it, so that machine 0's names are the names of a run without machines.
pub const fn listen_n(machine: usize, port: u16) -> u64 {
    (machine as u64) << 16 | port as u64
}

/// One guest socket of family `AF_INET`/`AF_INET6` (`family` 0: not a wire socket).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WSock {
    pub family: u16,
    pub state: u8,
    pub flags: u8,
    /// Pending `SO_ERROR` (errno), 0 when none.
    pub err: u16,
    pub lport: u16,
    pub rport: u16,
    pub laddr: u8,
    pub raddr: u8,
    /// Connection id (0: none).
    pub conn: u32,
    pub nopts: u32,
    /// Recorded options: `[level << 16 | name, value]`.
    pub opts: [[i32; 2]; OPTS_CAP],
    /// Datagram sockets: what the datagrams waiting in the guest's receive queue are charged
    /// against `SO_RCVBUF` (`dgram_charge`). The supervisor adds at delivery, the runtime
    /// subtracts when the guest takes one.
    pub rq: u32,
    /// Datagram sockets: `MARK_QUEUED` while a marker (an error or a wake, no data) waits in
    /// the guest's queue, so at most one does. The supervisor sets it, the runtime clears it.
    pub marks: u32,
}

/// `WSock::marks`: a marker packet is queued.
pub const MARK_QUEUED: u32 = 1;

/// Outcome counters (`result.json` "counters.net").
#[repr(C)]
pub struct NetCounters {
    pub connections: AtomicU64,
    pub bytes: AtomicU64,
    /// Writes into a receiver's hidden end (deliveries).
    pub chunks: AtomicU64,
    pub resets: AtomicU64,
    /// Chunks held back by `net-blackout`.
    pub blacked_out: AtomicU64,
    pub refused: AtomicU64,
    pub timeouts: AtomicU64,
    /// Socket options answered `ENOPROTOOPT`.
    pub unknown_opts: AtomicU64,
    /// Largest number of bytes the supervisor held in its queues at once.
    pub peak_queued: AtomicU64,
    /// The supervisor's peak resident memory (KiB, `VmHWM`), written at the end of the run.
    pub sup_hwm_kb: AtomicU64,
    /// Supervisor decision records written by the wire.
    pub steps: AtomicU64,
    /// FINs delivered.
    pub fins: AtomicU64,
    /// Reads of data a guest sent.
    pub sends: AtomicU64,
    /// Datagrams sent (each one draw of every datagram fault class).
    pub datagrams: AtomicU64,
    /// Datagrams put into a receiver's queue (duplicates included).
    pub dgram_delivered: AtomicU64,
    /// Datagrams lost: injected drops, blackouts, cut links, a full receive buffer, no receiver.
    pub dgram_lost: AtomicU64,
}

#[repr(C)]
pub struct WireTab {
    /// Network fault configuration, written by the launcher.
    pub cfg: NetCfg,
    /// Entries used in `dirty`.
    pub dirty_n: u64,
    /// Non-zero: the supervisor reads every connection's hidden ends at its next step
    /// (descriptors closed in bulk: process exit, `execve`, `close_range`, `dup2` over one).
    pub scan_all: u64,
    pub dirty: [u32; DIRTY_CAP],
    pub counters: NetCounters,
    pub socks: [WSock; VINO_CAP],
}

impl WireTab {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut WireTab {
        &mut *(ctl_base.add(WIRE_OFFSET) as *mut WireTab)
    }
    /// Leave a "sent" mark for socket index `i` (bytes or a close are waiting at its hidden end).
    pub fn mark(&mut self, i: usize) {
        if i >= VINO_CAP || self.socks[i].flags & WF_SENT != 0 {
            return;
        }
        self.socks[i].flags |= WF_SENT;
        let n = self.dirty_n as usize;
        if n < DIRTY_CAP {
            self.dirty[n] = i as u32;
            self.dirty_n += 1;
        } else {
            self.scan_all = 1;
        }
    }
    pub fn inc(c: &AtomicU64, by: u64) {
        c.store(c.load(Relaxed) + by, Relaxed);
    }
}

impl WSock {
    pub fn opt(&self, key: i32) -> Option<i32> {
        self.opts[..(self.nopts as usize).min(OPTS_CAP)]
            .iter()
            .find(|o| o[0] == key)
            .map(|o| o[1])
    }
    /// Record an option (false when the table is full).
    pub fn set_opt(&mut self, key: i32, v: i32) -> bool {
        let n = (self.nopts as usize).min(OPTS_CAP);
        for o in &mut self.opts[..n] {
            if o[0] == key {
                o[1] = v;
                return true;
            }
        }
        if n == OPTS_CAP {
            return false;
        }
        self.opts[n] = [key, v];
        self.nopts += 1;
        true
    }
}

/// The preamble a client writes to `@patina-wire` right after connecting: magic, then the
/// socket's virtual inode number.
pub const PREAMBLE_MAGIC: u64 = 0x6572_6977_7461_7021; // "!patwire"
pub const PREAMBLE_LEN: usize = 16;

/// Abstract names (without the leading NUL).
pub const WIRE_NAME: &[u8] = b"patina-wire";
pub const LISTEN_PREFIX: &[u8] = b"patina-l-";
pub const CONN_PREFIX: &[u8] = b"patina-c-";
/// Guests may not bind or connect to abstract names with this prefix.
pub const RESERVED_PREFIX: &[u8] = b"patina-";

/// `sockaddr_un` for an abstract name `prefix` + decimal `n` (n < 2^32): (bytes, length).
pub fn abstract_addr(prefix: &[u8], n: Option<u64>) -> ([u8; 110], u32) {
    let mut a = [0u8; 110];
    a[0] = 1; // AF_UNIX
    let mut p = 3; // family (2 bytes), then the NUL of the abstract namespace
    for &c in prefix {
        a[p] = c;
        p += 1;
    }
    if let Some(mut n) = n {
        let mut d = [0u8; 20];
        let mut k = 0;
        loop {
            d[k] = b'0' + (n % 10) as u8;
            k += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        while k > 0 {
            k -= 1;
            a[p] = d[k];
            p += 1;
        }
    }
    (a, p as u32)
}

/// Parse the number after `prefix` in an abstract `sockaddr_un` of length `len`.
pub fn parse_abstract(a: &[u8], len: usize, prefix: &[u8]) -> Option<u64> {
    if len < 3 + prefix.len() + 1 || a[0] != 1 || a[1] != 0 || a[2] != 0 {
        return None;
    }
    let name = &a[3..len.min(a.len())];
    if !name.starts_with(prefix) {
        return None;
    }
    let mut n: u64 = 0;
    for &c in &name[prefix.len()..] {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

/// Port range of automatic allocation (port 0, client ports).
pub const PORT_FIRST: u16 = 32768;
pub const PORT_LAST: u16 = 60999;
/// SYN retransmissions before a connect gives up (Linux's `tcp_syn_retries`): retries at 1, 3,
/// 7, 15, 31 and 63 s, `ETIMEDOUT` at 127 s.
pub const SYN_RETRIES_DEFAULT: u64 = 6;
/// A direction holding unacknowledged data this long gives up (Linux's `tcp_retries2` = 15:
/// about 924.6 s).
pub const GIVE_UP_DEFAULT_NS: u64 = 924_600_000_000;

/// Seconds from a connect to its `n`-th SYN retry (from 0; the last one is the give-up), with
/// the kernel's doubling backoff from 1 s: 1, 3, 7, 15, ... (capped at 120 s between retries).
pub const fn syn_retry_s(n: u64) -> u64 {
    let mut t = 0u64;
    let mut gap = 1u64;
    let mut i = 0;
    while i <= n {
        t += gap;
        gap = if gap * 2 > 120 { 120 } else { gap * 2 };
        i += 1;
    }
    t
}
/// Default delivery delay when `net-delay-ms` is not set (loopback-like), ns.
pub const DEFAULT_DELAY_NS: (u64, u64) = (10_000, 50_000);
/// Bytes the supervisor holds per direction before it stops reading the sender's end.
pub const WINDOW: usize = 256 << 10;

/// Network fault configuration. Written by the launcher.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetCfg {
    /// 1 when `net-delay-ms` is set.
    pub delay_set: u64,
    pub delay_min_ns: u64,
    pub delay_max_ns: u64,
    /// 0: off.
    pub chunk_max: u64,
    pub reset_permille: u64,
    pub refuse_permille: u64,
    pub timeout_permille: u64,
    /// 1 when `net-blackout` is set: [from, to) virtual ns since boot, optional port (0: all).
    pub blackout_set: u64,
    pub blackout_from_ns: u64,
    pub blackout_to_ns: u64,
    pub blackout_port: u64,
    /// Datagram faults (per mille, drawn per datagram).
    pub drop_permille: u64,
    pub dup_permille: u64,
    pub reorder_permille: u64,
    /// 1 when `net-chunk-max` splits deliveries: the time between the pieces of a split
    /// delivery (1 to 10 µs); otherwise each piece takes a delivery delay.
    pub chunk_gap_set: u64,
    pub chunk_gap_min_ns: u64,
    pub chunk_gap_max_ns: u64,
    /// The machines whose links the link faults act on (bit `k`: machine `k`, main 0): a link
    /// between two of them, or a machine's loopback.
    pub links: u64,
    /// A run with machines: the seed's partitions (`partition-*`): the gap from one's end to the
    /// next one's start and each one's length, drawn in [min, max] ns; each partition's shape
    /// is drawn from every `machine::SHAPES` entry the machines fit. Off when `part_gap_max_ns` is 0.
    pub part_gap_min_ns: u64,
    pub part_gap_max_ns: u64,
    pub part_min_ns: u64,
    pub part_max_ns: u64,
}

/// Sub-keys of `draw(Stream::FaultNet, key)`.
pub const NSUB_REFUSE: u64 = 1;
pub const NSUB_TIMEOUT: u64 = 2;
pub const NSUB_RESET: u64 = 3;
pub const NSUB_HANDSHAKE: u64 = 4;
pub const NSUB_FIN: u64 = 5;
/// A keepalive probe's round trip (`sup::wire`).
pub const NSUB_KEEPALIVE: u64 = 6;
/// Pieces of `net-chunk-max` (8 | direction).
pub const NSUB_CHUNK: u64 = 8;

/// Injected-fault kinds of the wire (`Rec::args[0]` of `Injected` records written by the
/// supervisor), after `faults::INJ_*`.
pub const INJ_NET_RESET: u64 = 20;
pub const INJ_NET_REFUSE: u64 = 21;
pub const INJ_NET_TIMEOUT: u64 = 22;
/// A delivery held by `net-blackout` (value: the window's end).
pub const INJ_NET_BLACKOUT: u64 = 23;
/// A delivery split by `net-chunk-max` (value: bytes of the piece delivered).
pub const INJ_NET_CHUNK: u64 = 24;
/// Datagram faults: `args` = [kind, 0, bytes, datagram id, destination port, source port].
pub const INJ_NET_DROP: u64 = 25;
pub const INJ_NET_DUP: u64 = 26;
/// value: the extra delay (ns).
pub const INJ_NET_REORDER: u64 = 27;
/// A datagram due inside a `net-blackout` window is lost.
pub const INJ_NET_BLACKOUT_DROP: u64 = 28;
/// A partition the seed drew between machines (`partition-*`): `args` = [kind, shape, ordinal,
/// side A (machine bits), side B, length ns]; supervisor records of slot 0.
pub const INJ_NET_CUT: u64 = 29;

/// `args[1]` of a wire or datagram `Injected` record in a run with machines: the link it acted on
/// (`from`, `to`: machines); 0 without machines.
pub const fn inj_link(from: usize, to: usize) -> u64 {
    1 | (from as u64) << 8 | (to as u64) << 16
}

/// The link of an `Injected` record's `args[1]` (`inj_link`), if it names one.
pub const fn inj_link_of(a1: u64) -> Option<(usize, usize)> {
    if a1 & 1 == 0 {
        None
    } else {
        Some(((a1 >> 8 & 0xff) as usize, (a1 >> 16 & 0xff) as usize))
    }
}

// ---- datagrams (UDP) ----

/// The supervisor's listener for the hidden ends of datagram sockets (`SOCK_SEQPACKET`).
pub const UDP_NAME: &[u8] = b"patina-udp";
/// The preamble packet a datagram socket sends right after connecting to `@patina-udp`:
/// magic, then the socket's virtual inode number (16 bytes, as `PREAMBLE_LEN`).
pub const UDP_MAGIC: u64 = 0x0070_6475_7461_7021; // "!patudp"
/// Every packet the supervisor writes to a guest's datagram socket starts with this header:
/// `[kind | address kind << 8 | port << 16 | errno << 32, datagram id]`.
pub const DGRAM_HDR: usize = 16;
pub const DG_DATA: u64 = 1;
/// An ICMP-style error for a connected socket (no payload): wakes a reader; the error itself
/// is `WSock::err`.
pub const DG_ERR: u64 = 2;
/// Largest payload: 65,535 less the IPv4 and UDP headers (IPv6: less 8 only).
pub const DGRAM_MAX4: usize = 65_507;
pub const DGRAM_MAX6: usize = 65_527;
/// `SO_RCVBUF`/`SO_SNDBUF` of a datagram socket never set (Linux `rmem_default`), and the
/// most an unprivileged `setsockopt` can ask for (`rmem_max`; the kernel doubles it).
pub const DGRAM_BUF_DEFAULT: i32 = 212_992;
pub const DGRAM_BUF_MAX: i32 = 212_992;

/// What one queued datagram of `len` payload bytes costs against `SO_RCVBUF`: what the
/// kernel's allocator charges for a buffer holding it and the header (the data rounded up to
/// the allocator's size, 320 bytes of shared info, 256 of buffer head; beyond 16 KiB, pages).
/// It is never less than what the kernel charges the supervisor for the same packet, so the
/// supervisor's limit is reached before the kernel's.
pub const fn dgram_charge(len: usize) -> u32 {
    let f = len + DGRAM_HDR + 320;
    let data = if f <= 16384 {
        // At least 1024: since Linux 6.3 a small head comes from a cache sized for the largest
        // protocol header (640 bytes on common configurations), more than 512.
        let mut p = 1024;
        while p < f {
            p *= 2;
        }
        p
    } else {
        16384 + (len + DGRAM_HDR).div_ceil(4096) * 4096
    };
    (data + 256) as u32
}

/// Sub-keys of `draw(Stream::Dgram, id << 4 | sub)`: every class has its own draw per
/// datagram, so turning one on moves no other decision.
pub const DSUB_DELAY: u64 = 0;
pub const DSUB_DROP: u64 = 1;
pub const DSUB_DUP: u64 = 2;
pub const DSUB_REORDER: u64 = 3;
pub const DSUB_HOLD: u64 = 4;
pub const DSUB_DUP_DELAY: u64 = 5;

#[cfg(test)]
mod tests {
    #[test]
    fn syn_retries_follow_the_kernels_backoff() {
        let t: [u64; 7] = core::array::from_fn(|n| super::syn_retry_s(n as u64));
        assert_eq!(t, [1, 3, 7, 15, 31, 63, 127]);
        // The gap stops doubling at TCP_RTO_MAX (120 s).
        assert_eq!(super::syn_retry_s(8) - super::syn_retry_s(7), 120);
        assert_eq!(super::syn_retry_s(9) - super::syn_retry_s(8), 120);
    }
}
