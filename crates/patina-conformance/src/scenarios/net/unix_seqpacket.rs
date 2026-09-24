//! net/unix_seqpacket — AF_UNIX sequenced-packet sockets: connection-mode
//! like a stream, record boundaries like datagrams (unix(7);
//! net/unix/af_unix.c `unix_seqpacket_sendmsg`/`unix_seqpacket_recvmsg`):
//!
//! * a pair and a listener/client/accepted trio on an abstract name derived
//!   from the run directory;
//! * every send is one record: a receive never merges two, a short buffer
//!   truncates one (`MSG_TRUNC` in `msg_flags`, the tail discarded, the
//!   `MSG_TRUNC` flag answering the record's full length);
//! * a destination on a connected socket is ignored; a send on an
//!   unconnected one is `ENOTCONN`;
//! * once the peer closes the survivor reads EOF and its send is `EPIPE`.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Control, Probe, RecvSpec, SockAddr, neg};
use crate::scenarios::net::abstract_name;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let root = p.dir();

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    p.require("a seqpacket socketpair", r == 0);
    p.check("send a record", p.send_to(a, b"abc", 0, None) == 3);
    p.check("send another", p.send_to(a, b"defgh", 0, None) == 5);
    let (n, data, _) = p.recv_from(b, 16, 0, false);
    p.check("a receive never merges records", n == 3 && data == b"abc");
    let (n, data, _) = p.recv_from(b, 16, 0, false);
    p.check("the second record is whole", n == 5 && data == b"defgh");
    p.close(a);
    p.close(b);

    let name = abstract_name(&root, "seqpacket");
    let l = p.socket(AF_UNIX, SOCK_SEQPACKET, 0);
    p.require("a seqpacket listener", l >= 0);
    p.check(
        "bind an abstract name",
        p.bind_to(l, &SockAddr::UnixAbstract(name.clone())) == 0,
    );
    p.check("listen", p.listen(l, 4) == 0);
    let u = p.socket(AF_UNIX, SOCK_SEQPACKET, 0);
    p.require("an unconnected socket", u >= 0);
    p.check(
        "a send on an unconnected socket is ENOTCONN",
        p.send_to(u, b"x", 0, None) == neg(ENOTCONN),
    );
    let c = p.socket(AF_UNIX, SOCK_SEQPACKET, 0);
    p.require("a client", c >= 0);
    p.check(
        "connect",
        p.connect_to(c, &SockAddr::UnixAbstract(name.clone())) == 0,
    );
    let (s, _) = p.accept_from(l, 0, false, false);
    p.require("accept4", s >= 0);
    p.check(
        "a destination on a connected socket is ignored",
        p.send_to(
            c,
            b"ignored",
            0,
            Some(&SockAddr::UnixAbstract(abstract_name(&root, "nobody"))),
        ) == 7,
    );
    let (n, data, _) = p.recv_from(s, 16, 0, false);
    p.check("the record arrives", n == 7 && data == b"ignored");

    // Everything below reads records through recvmsg: a runtime without it
    // stops here.
    p.check(
        "send a long record",
        p.send_to(c, b"0123456789", 0, None) == 10,
    );
    let got = p.recvmsg(s, RecvSpec::plain(&[4]));
    p.require("recvmsg on a seqpacket socket", got.result >= 0);
    p.check(
        "a short buffer truncates the record and says so",
        got.result == 4 && got.data() == b"0123" && got.msg_flags == MSG_TRUNC,
    );
    p.check("send the next record", p.send_to(c, b"next", 0, None) == 4);
    let got = p.recvmsg(s, RecvSpec::plain(&[16]));
    p.check(
        "the truncated tail was discarded",
        got.result == 4 && got.data() == b"next",
    );
    p.check("send one more", p.send_to(c, b"0123456789", 0, None) == 10);
    let got = p.recvmsg(
        s,
        RecvSpec {
            segments: &[2],
            name: None,
            control: 0,
            flags: MSG_TRUNC,
        },
    );
    p.check(
        "MSG_TRUNC answers the record's full length",
        got.result == 10 && got.data() == b"01",
    );
    p.check(
        "sendmsg of two segments is one record",
        p.sendmsg(c, &[b"ga", b"ther"], None, &Control::None, 0) == 6,
    );
    let (n, data, _) = p.recv_from(s, 16, 0, false);
    p.check("gathered into one record", n == 6 && data == b"gather");

    p.check("close the client", p.close(c) == 0);
    p.check(
        "the accepted socket reads EOF",
        p.recv_from(s, 16, 0, false).0 == 0,
    );
    p.check(
        "and its send is EPIPE",
        p.send_to(s, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    for fd in [s, u, l] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/unix_seqpacket",
    run,
    covers: &[
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_sendmsg,
        Syscall::N_recvmsg,
        Syscall::N_close,
    ],
    symbols: &[
        "socketpair",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "close",
    ],
    ..DEFAULTS
};
