//! net/unix_dgram — AF_UNIX datagram sockets on paths under the run
//! directory, abstract names derived from it, autobind, and a datagram pair
//! (unix(7); net/unix/af_unix.c `unix_dgram_sendmsg`/`unix_dgram_recvmsg`):
//!
//! * datagrams keep their boundaries; a short buffer truncates and discards
//!   the tail, and `MSG_TRUNC` answers the full length; `MSG_PEEK` leaves
//!   the datagram queued; an empty queue is `EAGAIN` under `MSG_DONTWAIT`;
//! * the source name: none (`addrlen` 0) from an unbound sender, the path or
//!   abstract name of a bound one, a five-hex-digit abstract name from an
//!   autobound one;
//! * `sendto` a missing path is `ENOENT`, a path whose socket closed
//!   `ECONNREFUSED`, a stream socket's path `EPROTOTYPE`; a send with no
//!   destination on an unconnected socket is `ENOTCONN` (not UDP's
//!   `EDESTADDRREQ`);
//! * a connected socket sends without a destination; once its peer closes,
//!   the next send is `ECONNREFUSED` and disconnects it, so the one after is
//!   `ENOTCONN`;
//! * a datagram `socketpair` keeps boundaries both ways and its ends are
//!   unnamed.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{AT_FDCWD, Probe, SockAddr, neg};
use crate::scenarios::net::abstract_name;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let root = p.dir();

    // ---- a datagram pair ----
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a datagram socketpair", r == 0);
    p.check("send one datagram", p.send_to(a, b"one", 0, None) == 3);
    p.check("send another", p.send_to(a, b"two!", 0, None) == 4);
    let (n, data, _) = p.recv_from(b, 16, 0, false);
    p.check("the first arrives alone", n == 3 && data == b"one");
    let (n, data, _) = p.recv_from(b, 16, 0, false);
    p.check("then the second", n == 4 && data == b"two!");
    p.check(
        "and back the other way",
        p.send_to(b, b"back", 0, None) == 4,
    );
    let (n, _, _) = p.recv_from(a, 16, 0, false);
    p.check("the pair is bidirectional", n == 4);
    let (_, name, len) = p.name_of(a, false, 128);
    p.check(
        "a pair's ends are unnamed",
        name == Some(SockAddr::UnixUnnamed) && len == 2,
    );
    p.close(a);
    p.close(b);

    // ---- a path ----
    let path = p.unix_path("dgram.sock");
    let r_sock = p.socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a receiver", r_sock >= 0);
    p.check(
        "bind the receiver to a path",
        p.bind_to(r_sock, &SockAddr::UnixPath(path.clone())) == 0,
    );
    let s = p.socket(AF_UNIX, SOCK_DGRAM, 0);
    p.require("an unbound sender", s >= 0);
    p.check(
        "sendto the path",
        p.send_to(s, b"hello", 0, Some(&SockAddr::UnixPath(path.clone()))) == 5,
    );
    let (n, data, from) = p.recv_from(r_sock, 64, 0, true);
    p.check(
        "an unbound sender has no name: addrlen 0",
        n == 5 && data == b"hello" && from == Some(SockAddr::Raw { family: 0, len: 0 }),
    );
    for datagram in [b"d1".as_slice(), b"datagram2", b"3"] {
        p.send_to(s, datagram, 0, Some(&SockAddr::UnixPath(path.clone())));
    }
    let (n, data, _) = p.recv_from(r_sock, 64, MSG_PEEK, false);
    p.check("MSG_PEEK sees the first datagram", n == 2 && data == b"d1");
    let (n, data, _) = p.recv_from(r_sock, 64, 0, false);
    p.check("and leaves it queued", n == 2 && data == b"d1");
    let (n, data, _) = p.recv_from(r_sock, 4, MSG_TRUNC, false);
    p.check(
        "MSG_TRUNC answers the full length of a truncated datagram",
        n == 9 && data == b"data",
    );
    let (n, data, _) = p.recv_from(r_sock, 64, 0, false);
    p.check(
        "the truncated tail was discarded; the next datagram is whole",
        n == 1 && data == b"3",
    );
    p.check(
        "an empty non-blocking receiver is EAGAIN",
        p.recv_from(r_sock, 64, 0, false).0 == neg(EAGAIN),
    );

    let named = abstract_name(&root, "sender");
    p.check(
        "bind the sender to an abstract name",
        p.bind_to(s, &SockAddr::UnixAbstract(named.clone())) == 0,
    );
    p.send_to(s, b"from", 0, Some(&SockAddr::UnixPath(path.clone())));
    let (_, _, from) = p.recv_from(r_sock, 64, 0, true);
    p.check(
        "a bound sender's datagram carries its abstract name",
        from == Some(SockAddr::UnixAbstract(named.clone())),
    );
    let auto = p.socket(AF_UNIX, SOCK_DGRAM, 0);
    p.require("an autobinding sender", auto >= 0);
    p.check(
        "autobind a datagram socket",
        p.bind_to(auto, &SockAddr::UnixUnnamed) == 0,
    );
    p.send_to(auto, b"auto", 0, Some(&SockAddr::UnixPath(path.clone())));
    let (_, _, from) = p.recv_from(r_sock, 64, 0, true);
    p.check(
        "an autobound sender's name is five hex digits",
        from.as_ref().is_some_and(SockAddr::autobound),
    );

    p.check(
        "sendto a missing path is ENOENT",
        p.send_to(
            s,
            b"x",
            0,
            Some(&SockAddr::UnixPath(p.unix_path("none.sock"))),
        ) == neg(ENOENT),
    );
    let st = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a stream socket", st >= 0);
    let st_path = p.unix_path("stream.sock");
    p.check(
        "bind the stream socket",
        p.bind_to(st, &SockAddr::UnixPath(st_path.clone())) == 0,
    );
    p.check(
        "sendto a stream socket's path is EPROTOTYPE",
        p.send_to(s, b"x", 0, Some(&SockAddr::UnixPath(st_path.clone()))) == neg(EPROTOTYPE),
    );
    p.check(
        "a send with no destination on an unconnected socket is ENOTCONN",
        p.send_to(s, b"x", 0, None) == neg(ENOTCONN),
    );

    p.check(
        "connect the sender to the receiver",
        p.connect_to(s, &SockAddr::UnixPath(path.clone())) == 0,
    );
    let (_, peer, _) = p.name_of(s, true, 128);
    p.check(
        "its peer is the receiver's path",
        peer == Some(SockAddr::UnixPath(path.clone())),
    );
    p.check(
        "a connected sender needs no destination",
        p.send_to(s, b"conn", 0, None) == 4,
    );
    let (n, data, _) = p.recv_from(r_sock, 64, 0, false);
    p.check("the receiver reads it", n == 4 && data == b"conn");
    p.check("close the receiver", p.close(r_sock) == 0);
    p.check(
        "a send to the closed peer is ECONNREFUSED",
        p.send_to(s, b"x", 0, None) == neg(ECONNREFUSED),
    );
    p.check(
        "which disconnected the sender: the next send is ENOTCONN",
        p.send_to(s, b"x", 0, None) == neg(ENOTCONN),
    );
    p.check(
        "sendto a path whose socket closed is ECONNREFUSED",
        p.send_to(auto, b"x", 0, Some(&SockAddr::UnixPath(path.clone()))) == neg(ECONNREFUSED),
    );

    for fd in [s, auto, st] {
        p.close(fd);
    }
    p.unlinkat(AT_FDCWD, &path, 0);
    p.unlinkat(AT_FDCWD, &st_path, 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/unix_dgram",
    run,
    covers: &[
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_connect,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_unlinkat,
        Syscall::N_close,
    ],
    symbols: &[
        "socketpair",
        "socket",
        "bind",
        "connect",
        "getsockname",
        "getpeername",
        "sendto",
        "recvfrom",
        "unlinkat",
        "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "socketpair(AF_UNIX, SOCK_DGRAM) answers EOPNOTSUPP (c/posix/net.c socketpair, sud/net.rs sys_socketpair model a stream pair alone), and socket(AF_UNIX) is EAFNOSUPPORT: no AF_UNIX datagram socket exists",
            failure: Failure::Differs(&[
                Difference::field(0, "socketpair", "errno", Observed::Str("EOPNOTSUPP")),
                Difference::field(0, "socketpair", "fields.first", Observed::Null),
                Difference::field(0, "socketpair", "fields.second", Observed::Null),
                Difference::field(0, "socketpair", "ret", Observed::Int(-1)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "with no socket the scenario cannot continue",
            failure: Failure::Stops {
                events: 1,
                ending: Ending::Exit(101),
                diagnostic: "net/unix_dgram: cannot continue: a datagram socketpair",
            },
        },
    ],
    ..DEFAULTS
};
