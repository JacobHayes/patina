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
//! * a TCP stream is readable only once `SO_RCVLOWAT` bytes are queued, and
//!   a receive waits for them (`tcp_poll`, `sock_rcvlowat`).
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, Control, IoctlArg, Probe, RecvSpec, SockAddr, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// How long a wait for an event already caused may take.
const WAIT_MS: i32 = 5_000;

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
    p.send_to(tc, b"cd", 0, None);
    let (n, revents) = p.poll(&[(ts, POLLIN)], WAIT_MS, shown);
    p.check("four are", n == 1 && revents == vec![POLLIN]);
    let (n, data) = p.recv(ts, 16, 0);
    p.check("a receive takes them", n == 4 && data == b"abcd");
    for fd in [tc, ts, tl] {
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
        "ioctl",
        "poll",
        "openat",
        "chmod",
        "unlinkat",
        "close",
    ],
    needs: &[Need::Unprivileged, Need::LocalBindOnly],
    ..DEFAULTS
};
