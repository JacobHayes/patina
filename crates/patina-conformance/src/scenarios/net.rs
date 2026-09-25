//! The network family: sockets over loopback IPv4 and IPv6, AF_UNIX in the
//! run directory and the abstract namespace, AF_NETLINK's routing family,
//! and the libc name and interface lookups.
//!
//! The native oracle is the host's real network stack over loopback only:
//! no scenario contacts anything off the host. Patina's modeled differences
//! are declared where they show — host-allocated values (ports, netlink port
//! ids, AF_UNIX autobind names) are `Relative` labels, host-configured ones
//! (buffer sizes the kernel doubles, MTUs, every interface but `lo`) are
//! compared by relation — and the interface table the arc models (`lo` +
//! `eth0`/24, no default route, so an off-table destination is
//! `ENETUNREACH`) is never compared beyond `lo`: an off-table destination
//! would leave the host natively.
//!
//! Loopback delivery: a datagram or stream segment sent over loopback is
//! delivered before the send returns — the sender's `local_bh_enable` at the
//! end of `dev_queue_xmit` runs the NET_RX softirq inline (always so since
//! Linux 6.5, which dropped the "let ksoftirqd do its job" deferral) — so a
//! scenario may read with `MSG_DONTWAIT` or poll with a zero timeout right
//! after its send. Scenarios that rely on it say so and point here; the
//! ones that wait for an asynchronous answer (an ICMP error, a completed
//! connect) bound the wait instead.
//!
//! Port identity: a port label is an identity by number within one IP
//! protocol (the comparison keys it by the protocol of the socket the event
//! names, so a UDP and a TCP port that share a number are two ports). Within
//! a protocol, two host-allocated ports that happen to share a number read
//! as one. Patina's allocator does not repeat a number within a run, but the
//! host does: a freed port may be handed out again, two `connect`s to
//! different peers may share a source port, and binds on addresses that do
//! not conflict (`127.0.0.1` and a v6-only `::1`) may share one. A stream
//! therefore labels, per protocol, only ports the kernel keeps distinct from
//! each other: held together, and either bound on conflicting addresses or
//! a `connect` port beside `bind` ones. An address a socket only names for
//! another protocol's port (a destination a stream ignores) is labeled as
//! the naming socket's protocol, so it is a port of that protocol's too.

pub mod fortify;
pub mod getaddrinfo;
pub mod getifaddrs;
pub mod ifconfig;
pub mod inet6;
pub mod inet6_mapped;
pub mod ipctl;
pub mod ipopts;
pub mod mmsg;
pub mod msg;
pub mod netlink;
pub mod pending;
pub mod privileged;
pub mod scm;
pub mod sockopt;
pub mod sockopt_fault;
pub mod tcp;
pub mod udp;
pub mod unix_dgram;
pub mod unix_seqpacket;
pub mod unix_stream;

use crate::probe::{Probe, SIGSET_BYTES, SockAddr, neg};
use crate::signals::{empty_set, has, one_set};
use libc::{EPIPE, MSG_NOSIGNAL, SIG_BLOCK, SIG_UNBLOCK, SIGPIPE, siginfo_t};

/// How long a wait for an event already caused, or an asynchronous
/// completion, may take (loopback delivers within the causing call; the
/// bound only keeps a slow host honest).
pub const WAIT_MS: i32 = 5_000;

/// The flags every up loopback device carries.
pub const LOOPBACK_FLAGS: i32 = libc::IFF_UP | libc::IFF_LOOPBACK | libc::IFF_RUNNING;

/// `UIO_MAXIOV` (include/uapi/linux/uio.h): the most iovecs one message
/// takes, and the most messages one `sendmmsg`/`recvmmsg` handles.
pub const UIO_MAXIOV: usize = 1024;

/// The lowest port a `bind` to port 0 can be given: autoallocation draws from
/// `ip_local_port_range`, whose low end the kernel refuses below
/// `ip_unprivileged_port_start` (net/ipv4/sysctl_net_ipv4.c
/// `ipv4_local_port_range`), 1024 by default.
pub const UNPRIVILEGED_PORT: u16 = 1024;

/// Check a kernel-allocated port against [`UNPRIVILEGED_PORT`]: ports are
/// compared as labels (the host allocates them), so their range is a check.
/// Every scenario calls it last, after its stream is pinned.
pub fn check_allocated_port(p: &Probe, addr: &SockAddr) {
    p.check(
        "the kernel-allocated port is unprivileged (>= 1024)",
        addr.port().is_some_and(|port| port >= UNPRIVILEGED_PORT),
    );
}

/// An int socket option's bytes, as `setsockopt` takes and `getsockopt`
/// answers them.
pub fn int(value: i32) -> [u8; 4] {
    value.to_ne_bytes()
}

/// A `struct timeval` as `SO_RCVTIMEO`/`SO_SNDTIMEO` take it.
pub fn timeval(sec: i64, usec: i64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    bytes[8..].copy_from_slice(&usec.to_ne_bytes());
    bytes
}

/// A send that fails with `EPIPE` raises `SIGPIPE` unless `MSG_NOSIGNAL`:
/// `send(flags)` issues it (`what` names it in the labels), once with
/// `MSG_NOSIGNAL` — no signal pending after — and once without, with
/// `SIGPIPE` blocked, which queues it for a zero-timeout `sigtimedwait`.
pub fn epipe_raises_sigpipe(p: &Probe, what: &str, send: impl Fn(i32) -> i64) {
    let sigpipe = one_set(SIGPIPE);
    p.check(
        &format!("{what} with MSG_NOSIGNAL is EPIPE"),
        send(MSG_NOSIGNAL) == neg(EPIPE),
    );
    let mut pending = empty_set();
    p.rt_sigpending(&mut pending, SIGSET_BYTES as usize);
    p.check("MSG_NOSIGNAL raised no SIGPIPE", !has(&pending, SIGPIPE));
    p.check(
        "block SIGPIPE",
        p.rt_sigprocmask(SIG_BLOCK, Some(&sigpipe), None, SIGSET_BYTES as usize) == 0,
    );
    p.check(&format!("{what} is EPIPE"), send(0) == neg(EPIPE));
    // SAFETY: an all-zero siginfo is a valid out-buffer.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    p.check(
        "and raised SIGPIPE, queued while blocked",
        p.rt_sigtimedwait(&sigpipe, Some(&mut info), Some(0), SIGSET_BYTES as usize)
            == i64::from(SIGPIPE),
    );
    p.check(
        "unblock SIGPIPE",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&sigpipe), None, SIGSET_BYTES as usize) == 0,
    );
}

/// An abstract AF_UNIX name a run owns: derived from its run directory —
/// a 64-bit FNV-1a of the path, so the name's length is bounded whatever
/// the `TMPDIR` — so concurrent runs never share one and the native and
/// patina runs of one scenario name the same.
pub fn abstract_name(dir: &str, tag: &str) -> Vec<u8> {
    let hash = dir.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("patina-conformance:{hash:016x}/{tag}").into_bytes()
}
