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

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{Control, Probe, neg};
use crate::vehicle::Vehicle;
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
    let uid = p.getuid();
    let gid = p.getgid();
    p.check(
        "SCM_CREDENTIALS naming another process is EPERM",
        p.sendmsg(
            a,
            &[b"x"],
            None,
            &Control::Creds {
                pid: 1,
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
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "setsockopt",
        "socketpair",
        "sendmsg",
        "getuid",
        "getgid",
        "close",
    ],
    needs: &[Need::Unprivileged],
    kernel_floor: Some(KernelFloor {
        release: "5.7",
        why: "an unprivileged SO_BINDTODEVICE on an unbound socket (net/core/sock.c sock_bindtoindex_locked)",
    }),
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "socket(AF_INET, SOCK_RAW) answers EPROTOTYPE and socket(AF_PACKET) EAFNOSUPPORT (c/posix/net.c socket, sud/net.rs sys_socket), where the unprivileged caller the virtual kernel models is refused with EPERM (inet_create, packet_create: CAP_NET_RAW)",
            failure: Failure::Differs(&[
                Difference::field(0, "socket", "errno", Observed::Str("EPROTOTYPE")),
                Difference::check(1, "a raw ICMP socket is EPERM"),
                Difference::field(2, "socket", "errno", Observed::Str("EAFNOSUPPORT")),
                Difference::check(3, "a raw packet socket is EPERM"),
                Difference::field(4, "socket", "errno", Observed::Str("EAFNOSUPPORT")),
                Difference::check(5, "a cooked packet socket is EPERM"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "setsockopt answers ENOPROTOOPT for SO_PRIORITY, SO_MARK, SO_RCVBUFFORCE and SO_BINDTODEVICE (c/posix/net.c setsockopt, sud/net.rs sys_setsockopt accept a fixed no-op list): an in-range SO_PRIORITY and a first SO_BINDTODEVICE succeed unprivileged, the rest are EPERM (sk_setsockopt, sock_bindtoindex_locked)",
            failure: Failure::Differs(&[
                Difference::field(7, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(7, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(8, "SO_PRIORITY 6 needs no privilege"),
                Difference::field(9, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::check(10, "SO_PRIORITY 7 is EPERM"),
                Difference::field(11, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::check(12, "SO_MARK is EPERM"),
                Difference::field(13, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::check(14, "SO_RCVBUFFORCE is EPERM"),
                Difference::field(15, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(15, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(16, "the first SO_BINDTODEVICE needs no privilege"),
                Difference::field(17, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::check(18, "unbinding it again is EPERM"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "sendmsg is a soft-deny ENOSYS (c/posix/net.c sendmsg, sud/net.rs sys_sendmsg), so SCM_CREDENTIALS naming another process is not refused with EPERM (scm_check_creds)",
            failure: Failure::Differs(&[
                Difference::field(23, "sendmsg", "errno", Observed::Str("ENOSYS")),
                Difference::check(24, "SCM_CREDENTIALS naming another process is EPERM"),
            ]),
        },
    ],
    ..DEFAULTS
};
