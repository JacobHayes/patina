//! net/unix_edges — the AF_UNIX answers off the common path (unix(7),
//! net/unix/af_unix.c) and a stream's receive low-water mark (socket(7),
//! net/ipv4/tcp.c):
//!
//! * a peek at a message carrying descriptors installs its own copies of
//!   them (`unix_peek_fds`), and the receive after it installs them again;
//! * credentials ride a datagram only when an end asked for them when it was
//!   sent (`maybe_add_creds`): a receiver that asks afterwards reads none —
//!   pid 0 and the overflow ids;
//! * an unconnected sequenced-packet socket cannot receive (`ENOTCONN`);
//! * `SIOCINQ` on a listener is `EINVAL` (`unix_inq_len`);
//! * connecting to a socket node needs write permission on it (`EACCES`);
//! * a TCP stream is readable only once `SO_RCVLOWAT` bytes are queued
//!   (`tcp_poll`), yet a non-blocking receive takes fewer (`tcp_recvmsg`
//!   stops at any data once it may not wait); a blocking peek below the mark
//!   waits for it, here until its `SO_RCVTIMEO` (`sock_rcvlowat` is the
//!   peek's target too);
//! * a TCP socket's mark is capped at half its receive buffer once
//!   `SO_RCVBUF` locked it, and below `INT_MAX` (half `tcp_rmem`'s maximum)
//!   otherwise (`tcp_set_rcvlowat`); a datagram socket's -1 is `INT_MAX`.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{AT_FDCWD, Control, IoctlArg, Probe, RecvSpec, SockAddr, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// How long a wait for an event already caused may take.
const WAIT_MS: i32 = 5_000;

/// A `struct timeval` as `setsockopt` takes it.
fn timeval(sec: i64, usec: i64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    bytes[8..].copy_from_slice(&usec.to_ne_bytes());
    bytes
}

pub fn run(p: &Probe) {
    let root = p.dir();

    // ---- a peek at descriptors ----
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    p.require("a stream socketpair", r == 0);
    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o640);
    p.require("a file to pass", file >= 0);
    p.check(
        "send it",
        p.sendmsg(a, &[b"F"], None, &Control::Rights(vec![file]), 0) == 1,
    );
    let with_rights = |flags| RecvSpec {
        segments: &[8],
        name: None,
        control: 64,
        flags,
    };
    let peeked = p.recvmsg(b, with_rights(MSG_PEEK));
    p.check(
        "a peek installs a copy of the descriptor",
        peeked.result == 1 && peeked.rights.len() == 1,
    );
    let taken = p.recvmsg(b, with_rights(0));
    p.check(
        "and the receive installs it again",
        taken.result == 1 && taken.rights.len() == 1 && taken.rights != peeked.rights,
    );
    for fd in peeked.rights.iter().chain(&taken.rights) {
        p.close(*fd);
    }
    for fd in [a, b, file] {
        p.close(fd);
    }

    // ---- credentials asked for after the send ----
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_DGRAM, 0);
    p.require("a datagram socketpair", r == 0);
    p.check(
        "a datagram sent with no end asking for credentials",
        p.sendmsg(a, &[b"c"], None, &Control::None, 0) == 1,
    );
    p.check(
        "the receiver asks afterwards",
        p.setsockopt_int(b, SOL_SOCKET, SO_PASSCRED, 1) == 0,
    );
    let got = p.recvmsg(b, with_rights(0));
    p.check(
        "and reads pid 0 and the overflow ids",
        got.result == 1 && got.creds == Some((0, 65534, 65534)),
    );
    p.check(
        "a datagram sent now",
        p.sendmsg(a, &[b"d"], None, &Control::None, 0) == 1,
    );
    let got = p.recvmsg(b, with_rights(0));
    p.check(
        "carries the sender's credentials",
        got.result == 1 && got.creds.is_some_and(|(pid, _, _)| pid != 0),
    );
    p.close(a);
    p.close(b);

    // ---- an unconnected sequenced-packet socket ----
    let q = p.socket(AF_UNIX, SOCK_SEQPACKET, 0);
    p.require("a sequenced-packet socket", q >= 0);
    p.check(
        "its receive is ENOTCONN",
        p.recv(q, 8, MSG_DONTWAIT).0 == neg(ENOTCONN),
    );
    p.close(q);

    // ---- a listener ----
    let path = p.unix_path("edges.sock");
    let l = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a listener", l >= 0);
    p.check(
        "bind it to a path",
        p.bind_to(l, &SockAddr::UnixPath(path.clone())) == 0,
    );
    p.check("listen", p.listen(l, 4) == 0);
    p.check(
        "SIOCINQ on a listener is EINVAL",
        p.ioctl(l, FIONREAD, "FIONREAD", IoctlArg::Out).0 == neg(EINVAL),
    );
    p.check(
        "take write permission off the node",
        p.chmod(&path, 0o500) == 0,
    );
    let c = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.check(
        "connecting to it is EACCES",
        p.connect_to(c, &SockAddr::UnixPath(path.clone())) == neg(EACCES),
    );
    p.check("give it back", p.chmod(&path, 0o700) == 0);
    p.check(
        "and the connect succeeds",
        p.connect_to(c, &SockAddr::UnixPath(path.clone())) == 0,
    );
    for fd in [c, l] {
        p.close(fd);
    }
    p.unlinkat(AT_FDCWD, &path, 0);

    // ---- a stream's receive low-water mark ----
    let tl = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a TCP listener", tl >= 0);
    p.check("bind it", p.bind_to(tl, &SockAddr::v4(0)) == 0);
    p.check("listen on it", p.listen(tl, 1) == 0);
    let (_, addr, _) = p.name_of(tl, false, 128);
    let addr = addr.expect("getsockname tl");
    let tc = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a TCP client", tc >= 0);
    p.check("connect", p.connect_to(tc, &addr) == 0);
    let (ts, _) = p.accept_from(tl, 0, false, false);
    p.require("accept", ts >= 0);
    p.check(
        "SO_RCVLOWAT 4 on the server",
        p.setsockopt_int(ts, SOL_SOCKET, SO_RCVLOWAT, 4) == 0,
    );
    p.send_to(tc, b"ab", 0, None);
    let shown = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDHUP;
    let (n, _) = p.poll(&[(ts, POLLIN)], 0, shown);
    p.check("two bytes queued are not readable", n == 0);
    let (n, data) = p.recv(ts, 16, MSG_DONTWAIT);
    p.check(
        "a non-blocking receive takes them all the same",
        n == 2 && data == b"ab",
    );
    p.send_to(tc, b"cdef", 0, None);
    let (n, revents) = p.poll(&[(ts, POLLIN)], WAIT_MS, shown);
    p.check("four are", n == 1 && revents == vec![POLLIN]);
    let (n, data) = p.recv(ts, 16, 0);
    p.check("a receive takes them", n == 4 && data == b"cdef");
    p.check(
        "SO_RCVTIMEO 50 ms on the server",
        p.setsockopt_bytes(ts, SOL_SOCKET, SO_RCVTIMEO, &timeval(0, 50_000), 16, "50ms") == 0,
    );
    p.send_to(tc, b"gh", 0, None);
    let (_, before) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    let (n, data) = p.recv(ts, 16, MSG_PEEK);
    let (_, after) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    p.check(
        "a blocking peek below the mark waits out its timeout, then answers what is queued",
        n == 2 && data == b"gh" && after - before >= 50_000_000,
    );
    let (n, _) = p.recv(ts, 16, MSG_DONTWAIT);
    p.check("the peeked bytes are still queued", n == 2);
    p.check(
        "SO_RCVBUF 4096 locks the server's receive buffer (8192)",
        p.setsockopt_int(ts, SOL_SOCKET, SO_RCVBUF, 4096) == 0,
    );
    p.check(
        "SO_RCVLOWAT -1 on it",
        p.setsockopt_int(ts, SOL_SOCKET, SO_RCVLOWAT, -1) == 0,
    );
    p.check(
        "is capped at half the locked buffer",
        p.getsockopt_int(ts, SOL_SOCKET, SO_RCVLOWAT) == (0, 4096),
    );
    p.check(
        "SO_RCVLOWAT -1 on the listener",
        p.setsockopt_int(tl, SOL_SOCKET, SO_RCVLOWAT, -1) == 0,
    );
    let (r, mark) = p.getsockopt_hidden(tl, SOL_SOCKET, SO_RCVLOWAT);
    p.check(
        "is capped below INT_MAX (half the host's tcp_rmem maximum)",
        r == 0 && mark > 0 && mark < i32::MAX,
    );
    let du = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a UDP socket", du >= 0);
    p.check(
        "SO_RCVLOWAT -1 on a datagram socket",
        p.setsockopt_int(du, SOL_SOCKET, SO_RCVLOWAT, -1) == 0,
    );
    p.check(
        "is INT_MAX",
        p.getsockopt_int(du, SOL_SOCKET, SO_RCVLOWAT) == (0, i32::MAX),
    );
    for fd in [tc, ts, tl, du] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/unix_edges",
    run,
    covers: &[
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_sendmsg,
        Syscall::N_recvmsg,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_ioctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_poll,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_ppoll,
        Syscall::N_openat,
        Syscall::N_fchmodat,
        Syscall::N_unlinkat,
        Syscall::N_close,
    ],
    symbols: &[
        "socketpair",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "setsockopt",
        "getsockopt",
        "ioctl",
        "poll",
        "openat",
        "chmod",
        "unlinkat",
        "close",
    ],
    needs: &[Need::Unprivileged, Need::LocalBindOnly],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "a TCP peek's target is one byte, not SO_RCVLOWAT (thread/net/inet.rs recv_stream); tcp_recvmsg_locked takes sock_rcvlowat for a peek too",
            failure: Failure::Differs(&[Difference::check(
                75,
                "a blocking peek below the mark waits out its timeout, then answers what is queued",
            )]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "SO_RCVLOWAT on TCP is not capped (thread/net/opts.rs set_socket); tcp_set_rcvlowat caps it at half the locked receive buffer, or half tcp_rmem's maximum",
            failure: Failure::Differs(&[
                Difference::field(
                    82,
                    "getsockopt",
                    "fields.value",
                    Observed::Int(i32::MAX as i64),
                ),
                Difference::check(83, "is capped at half the locked buffer"),
                Difference::check(
                    87,
                    "is capped below INT_MAX (half the host's tcp_rmem maximum)",
                ),
            ]),
        },
    ],
    ..DEFAULTS
};
