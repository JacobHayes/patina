//! net/privileged — the network operations that need a capability, observed
//! from the unprivileged caller the virtual kernel models: each is refused
//! with `EPERM` (raw(7), packet(7), socket(7), unix(7); the checks named at
//! each call):
//!
//! * raw IPv4 sockets and packet sockets need `CAP_NET_RAW`
//!   (net/ipv4/af_inet.c `inet_create`, net/packet/af_packet.c
//!   `packet_create`);
//! * `SO_PRIORITY` above 6 and `SO_MARK` need `CAP_NET_ADMIN`, and
//!   `SO_RCVBUFFORCE` too (net/core/sock.c `sk_setsockopt`);
//! * a second `SO_BINDTODEVICE` (rebinding, or unbinding with an empty
//!   name) needs `CAP_NET_RAW` (`sock_bindtoindex_locked`);
//! * `SCM_CREDENTIALS` naming another process needs `CAP_SYS_ADMIN`
//!   (net/core/scm.c `scm_check_creds`).
//!
//! These are the privileged network rows' only unprivileged outcome, so
//! they are asserted here rather than excluded. Needs an unprivileged caller
//! and Linux 5.7 (the unprivileged first `SO_BINDTODEVICE`).

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{Control, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `ETH_P_ALL` in network byte order, the protocol of an all-frames packet
/// socket.
const ETH_P_ALL_BE: i32 = (ETH_P_ALL as u16).to_be() as i32;

fn int(value: i32) -> [u8; 4] {
    value.to_ne_bytes()
}

pub fn run(p: &Probe) {
    p.check(
        "a raw ICMP socket is EPERM",
        i64::from(p.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == neg(EPERM),
    );
    p.check(
        "a raw packet socket is EPERM",
        i64::from(p.socket(AF_PACKET, SOCK_RAW, ETH_P_ALL_BE)) == neg(EPERM),
    );
    p.check(
        "a cooked packet socket is EPERM",
        i64::from(p.socket(AF_PACKET, SOCK_DGRAM, ETH_P_ALL_BE)) == neg(EPERM),
    );

    let t = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a UDP socket", t >= 0);
    p.check(
        "SO_PRIORITY 6 needs no privilege",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_PRIORITY, &int(6), 4, "6") == 0,
    );
    p.check(
        "SO_PRIORITY 7 is EPERM",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_PRIORITY, &int(7), 4, "7") == neg(EPERM),
    );
    p.check(
        "SO_MARK is EPERM",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_MARK, &int(1), 4, "1") == neg(EPERM),
    );
    p.check(
        "SO_RCVBUFFORCE is EPERM",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_RCVBUFFORCE, &int(4096), 4, "4096") == neg(EPERM),
    );
    let lo = b"lo\0";
    p.check(
        "the first SO_BINDTODEVICE needs no privilege",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_BINDTODEVICE, lo, lo.len(), "lo") == 0,
    );
    p.check(
        "unbinding it again is EPERM",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_BINDTODEVICE, b"\0", 1, "") == neg(EPERM),
    );
    p.close(t);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("a stream socketpair", r == 0);
    // Another process: the caller's own pid is what `scm_check_creds` accepts,
    // and no fixed pid is safely someone else's under every vehicle.
    let other = p.getpid() + 1;
    let uid = p.getuid();
    let gid = p.getgid();
    p.check(
        "SCM_CREDENTIALS naming another process is EPERM",
        p.sendmsg(
            a,
            &[b"x"],
            None,
            &Control::Creds {
                pid: other as i32,
                uid: uid as u32,
                gid: gid as u32,
            },
            0,
        ) == neg(EPERM),
    );
    p.close(a);
    p.close(b);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/privileged",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_setsockopt,
        Syscall::N_socketpair,
        Syscall::N_sendmsg,
        Syscall::N_getpid,
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "setsockopt",
        "socketpair",
        "sendmsg",
        "getpid",
        "getuid",
        "getgid",
        "close",
    ],
    needs: &[Need::Unprivileged],
    kernel_floor: Some(KernelFloor {
        release: "5.7",
        why: "an unprivileged SO_BINDTODEVICE on an unbound socket (net/core/sock.c sock_bindtoindex_locked)",
    }),
    ..DEFAULTS
};
