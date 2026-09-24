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

pub mod fortify;
pub mod getaddrinfo;
pub mod getifaddrs;
pub mod ifconfig;
pub mod inet6;
pub mod ipctl;
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
pub mod unix_edges;
pub mod unix_seqpacket;
pub mod unix_stream;

use crate::probe::{Probe, SockAddr};

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
