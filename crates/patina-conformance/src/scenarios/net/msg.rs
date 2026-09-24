//! net/msg — sendmsg / recvmsg, the `send`/`recv` wrappers and legacy
//! `accept` over loopback IPv4 (sendmsg(2), recvmsg(2), udp(7), tcp(7);
//! net/socket.c `___sys_sendmsg`/`___sys_recvmsg`, net/ipv4/udp.c):
//!
//! * a datagram gathers every iovec (an empty one included) into ONE
//!   datagram, and a receive scatters it over the segments in order;
//! * `MSG_PEEK` leaves the datagram queued; a short buffer truncates it,
//!   sets `MSG_TRUNC` in `msg_flags`, and discards the tail, and the
//!   `MSG_TRUNC` flag makes the call answer the datagram's real length;
//! * a name buffer shorter than the source address is filled as far as it
//!   goes while `msg_namelen` reports the full length (`move_addr_to_user`);
//! * the errno vocabulary: `EDESTADDRREQ` (no destination), `EINVAL` (a
//!   destination shorter than `sockaddr_in`), `EAFNOSUPPORT` (another
//!   family), `EMSGSIZE` (past `UIO_MAXIOV` iovecs, or a datagram past
//!   65507 bytes), `EFAULT` (an unreadable header), `EAGAIN`
//!   (`MSG_DONTWAIT` on an empty queue), `ENOTSOCK`, `EBADF`;
//! * over TCP a message's segments are one byte stream, a destination on a
//!   connected stream socket is ignored (tcp_sendmsg never reads
//!   `msg_name`), and a send after `SHUT_WR` is `EPIPE` — raising `SIGPIPE`
//!   (queued while blocked) unless `MSG_NOSIGNAL` (net/core/stream.c
//!   `sk_stream_error`);
//! * legacy `accept` reports the peer (or takes a NULL name), and is
//!   `EINVAL` on a socket that does not listen and `EOPNOTSUPP` on a
//!   datagram socket.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{AT_FDCWD, Control, Probe, RecvSpec, SIGSET_BYTES, SockAddr, neg};
use crate::signals::one_set;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `UIO_MAXIOV`: the most iovecs one message takes (include/uapi/linux/uio.h).
const UIO_MAXIOV: usize = 1024;

/// The largest UDP payload over IPv4: 65535 less the IP and UDP headers.
const UDP_MAX: usize = 65507;

pub fn run(p: &Probe) {
    let root = p.dir();
    let sigpipe = one_set(SIGPIPE);

    // ---- legacy accept and send(3)/recv(3) over a byte stream ----
    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("listener", l >= 0);
    p.check("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("client", c >= 0);
    p.check("connect to the listener", p.connect_to(c, &addr_l) == 0);
    let (_, addr_c, _) = p.name_of(c, false, 128);
    let (s, peer) = p.accept_from(l, 0, true, true);
    p.require("legacy accept", s >= 0);
    p.check("accept reports the client's address", peer == addr_c);
    p.check("send(3) on the stream", p.send(c, b"hello", 0) == 5);
    let (n, data) = p.recv(s, 3, 0);
    p.check("recv(3) reads a prefix", n == 3 && data == b"hel");
    let (n, data) = p.recv(s, 16, MSG_PEEK);
    p.check("recv(3) MSG_PEEK reads the rest", n == 2 && data == b"lo");
    let (n, data) = p.recv(s, 16, 0);
    p.check("and leaves it queued", n == 2 && data == b"lo");

    p.check(
        "shut the client's writing side",
        p.shutdown(c, SHUT_WR) == 0,
    );
    p.check(
        "send(3) after SHUT_WR with MSG_NOSIGNAL is EPIPE",
        p.send(c, b"x", MSG_NOSIGNAL) == neg(EPIPE),
    );
    let mut pending = crate::signals::empty_set();
    p.rt_sigpending(&mut pending, SIGSET_BYTES as usize);
    p.check(
        "MSG_NOSIGNAL raised no SIGPIPE",
        !crate::signals::has(&pending, SIGPIPE),
    );
    p.check(
        "block SIGPIPE",
        p.rt_sigprocmask(SIG_BLOCK, Some(&sigpipe), None, SIGSET_BYTES as usize) == 0,
    );
    p.check(
        "send(3) after SHUT_WR without MSG_NOSIGNAL is EPIPE",
        p.send(c, b"x", 0) == neg(EPIPE),
    );
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
    p.check("the server reads EOF", p.recv(s, 16, 0).0 == 0);

    let c2 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("second client", c2 >= 0);
    p.check("connect again", p.connect_to(c2, &addr_l) == 0);
    let (s2, _) = p.accept_from(l, 0, true, false);
    p.check("legacy accept with a NULL name", s2 >= 0);
    p.check(
        "legacy accept on a socket that does not listen is EINVAL",
        i64::from(p.accept_from(c2, 0, true, true).0) == neg(EINVAL),
    );
    let u = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("datagram socket", u >= 0);
    p.check(
        "legacy accept on a datagram socket is EOPNOTSUPP",
        i64::from(p.accept_from(u, 0, true, true).0) == neg(EOPNOTSUPP),
    );
    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o600);
    p.require("open a file", file >= 0);
    p.check(
        "legacy accept on a file is ENOTSOCK",
        i64::from(p.accept_from(file, 0, true, true).0) == neg(ENOTSOCK),
    );
    p.check(
        "recv(3) on a file is ENOTSOCK",
        p.recv(file, 4, 0).0 == neg(ENOTSOCK),
    );
    p.check(
        "send(3) on a file is ENOTSOCK",
        p.send(file, b"x", 0) == neg(ENOTSOCK),
    );
    for fd in [c2, s2, u] {
        p.close(fd);
    }
    p.check(
        "legacy accept on a closed descriptor is EBADF",
        i64::from(p.accept_from(u, 0, true, true).0) == neg(EBADF),
    );

    // ---- datagram messages ----
    let a = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("socket a", a >= 0);
    p.check("bind a", p.bind_to(a, &SockAddr::v4(0)) == 0);
    let (_, addr_a, _) = p.name_of(a, false, 128);
    let addr_a = addr_a.expect("getsockname a");
    let b = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket b", b >= 0);
    p.check("bind b", p.bind_to(b, &SockAddr::v4(0)) == 0);
    let (_, addr_b, _) = p.name_of(b, false, 128);
    let addr_b = addr_b.expect("getsockname b");

    // Everything below needs sendmsg: a runtime without it stops here
    // rather than wait on a datagram that never left.
    let sent = p.sendmsg(a, &[b"ab", b"", b"cde"], Some(&addr_b), &Control::None, 0);
    p.require(
        "sendmsg gathers three iovecs (one empty) into one datagram",
        sent == 5,
    );
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[2, 2, 8],
            name: Some(128),
            control: 0,
            flags: 0,
        },
    );
    p.check(
        "recvmsg scatters the datagram over the segments in order",
        got.result == 5 && got.segments == [b"ab".to_vec(), b"cd".to_vec(), b"e".to_vec()],
    );
    p.check(
        "recvmsg names the sender with a full sockaddr_in",
        got.name.as_ref() == Some(&addr_a)
            && got.namelen as usize == size_of::<sockaddr_in>()
            && got.msg_flags == 0,
    );

    p.check(
        "send a ten-byte datagram",
        p.sendmsg(a, &[b"0123456789"], Some(&addr_b), &Control::None, 0) == 10,
    );
    let peeked = p.recvmsg(
        b,
        RecvSpec {
            segments: &[4],
            name: None,
            control: 0,
            flags: MSG_PEEK,
        },
    );
    p.check(
        "a short MSG_PEEK reports the truncation",
        peeked.result == 4 && peeked.data() == b"0123" && peeked.msg_flags == MSG_TRUNC,
    );
    let short_name = p.recvmsg(
        b,
        RecvSpec {
            segments: &[4],
            name: Some(4),
            control: 0,
            flags: MSG_TRUNC,
        },
    );
    p.check(
        "MSG_TRUNC answers the datagram's full length and the peeked datagram was still queued",
        short_name.result == 10
            && short_name.data() == b"0123"
            && short_name.msg_flags == MSG_TRUNC,
    );
    p.check(
        "a short name buffer still reports the full address length",
        short_name.namelen as usize == size_of::<sockaddr_in>(),
    );
    p.check(
        "the truncated tail was discarded",
        p.recvmsg(
            b,
            RecvSpec {
                segments: &[16],
                name: None,
                control: 0,
                flags: MSG_DONTWAIT,
            },
        )
        .result
            == neg(EAGAIN),
    );

    p.check(
        "sendmsg with no destination on an unconnected socket is EDESTADDRREQ",
        p.sendmsg(a, &[b"x"], None, &Control::None, 0) == neg(EDESTADDRREQ),
    );
    p.check(
        "a destination shorter than sockaddr_in is EINVAL",
        p.sendmsg(
            a,
            &[b"x"],
            Some(&SockAddr::Raw {
                family: AF_INET as u16,
                len: 8,
            }),
            &Control::None,
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "a destination of another family is EAFNOSUPPORT",
        p.sendmsg(
            a,
            &[b"x"],
            Some(&SockAddr::Raw {
                family: AF_INET6 as u16,
                len: size_of::<sockaddr_in>(),
            }),
            &Control::None,
            0,
        ) == neg(EAFNOSUPPORT),
    );
    p.check(
        "UIO_MAXIOV iovecs are accepted (the next error is the missing destination)",
        p.sendmsg_iovlen(a, UIO_MAXIOV) == neg(EDESTADDRREQ),
    );
    p.check(
        "one iovec past UIO_MAXIOV is EMSGSIZE",
        p.sendmsg_iovlen(a, UIO_MAXIOV + 1) == neg(EMSGSIZE),
    );
    let big = vec![b'z'; UDP_MAX / 2 + 1];
    p.check(
        "a datagram past 65507 bytes is EMSGSIZE",
        p.sendmsg(a, &[&big, &big], Some(&addr_b), &Control::None, 0) == neg(EMSGSIZE),
    );
    p.check(
        "an unreadable message header is EFAULT",
        p.sendmsg_bad_header(a) == neg(EFAULT),
    );
    p.check(
        "sendmsg on a file is ENOTSOCK",
        p.sendmsg(file, &[b"x"], Some(&addr_b), &Control::None, 0) == neg(ENOTSOCK),
    );
    p.check(
        "recvmsg on a file is ENOTSOCK",
        p.recvmsg(file, RecvSpec::plain(&[4])).result == neg(ENOTSOCK),
    );

    // ---- stream messages ----
    p.check(
        "sendmsg of two segments on a stream",
        p.sendmsg(s, &[b"he", b"llo"], None, &Control::None, 0) == 5,
    );
    let got = p.recvmsg(c, RecvSpec::plain(&[3, 16]));
    p.check(
        "the stream delivers the bytes across the receive segments",
        got.result == 5 && got.segments == [b"hel".to_vec(), b"lo".to_vec()],
    );
    p.check(
        "a destination on a connected stream socket is ignored",
        p.sendmsg(s, &[b"ok"], Some(&addr_b), &Control::None, 0) == 2,
    );
    let got = p.recvmsg(
        c,
        RecvSpec {
            segments: &[16],
            name: None,
            control: 0,
            flags: MSG_PEEK,
        },
    );
    p.check(
        "MSG_PEEK on a stream",
        got.result == 2 && got.data() == b"ok",
    );
    let got = p.recvmsg(c, RecvSpec::plain(&[16]));
    p.check(
        "the peeked bytes are read again",
        got.result == 2 && got.data() == b"ok",
    );
    p.check(
        "recvmsg MSG_DONTWAIT on an empty stream is EAGAIN",
        p.recvmsg(
            c,
            RecvSpec {
                segments: &[16],
                name: None,
                control: 0,
                flags: MSG_DONTWAIT,
            },
        )
        .result
            == neg(EAGAIN),
    );
    p.check(
        "sendmsg after SHUT_WR with MSG_NOSIGNAL is EPIPE",
        p.sendmsg(c, &[b"x"], None, &Control::None, MSG_NOSIGNAL) == neg(EPIPE),
    );
    p.check("close the server side", p.close(s) == 0);
    p.check(
        "recvmsg reads EOF once the peer closed",
        p.recvmsg(c, RecvSpec::plain(&[16])).result == 0,
    );

    for fd in [a, file, c, l] {
        p.close(fd);
    }
    p.check(
        "sendmsg on a closed descriptor is EBADF",
        p.sendmsg(a, &[b"x"], Some(&addr_b), &Control::None, 0) == neg(EBADF),
    );
    p.check(
        "recvmsg on a closed descriptor is EBADF",
        p.recvmsg(a, RecvSpec::plain(&[4])).result == neg(EBADF),
    );
    p.close(b);
    crate::scenarios::net::check_allocated_port(p, &addr_l);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/msg",
    run,
    covers: &[
        Syscall::N_sendmsg,
        Syscall::N_recvmsg,
        Syscall::N_accept,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_shutdown,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "sendmsg",
        "recvmsg",
        "accept",
        "send",
        "recv",
        "socket",
        "bind",
        "listen",
        "connect",
        "getsockname",
        "shutdown",
        "openat",
        "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "MSG_PEEK on a connected stream answers EOPNOTSUPP (c/posix/net.c recv, sud/net.rs sys_recvfrom: `patina_stream_flags_supported` admits MSG_NOSIGNAL alone), where tcp_recvmsg copies the queued bytes and leaves them queued",
            failure: Failure::Differs(&[
                Difference::field(16, "recv", "errno", Observed::Str("EOPNOTSUPP")),
                Difference::field(16, "recv", "ret", Observed::Int(-1)),
                Difference::field(16, "recv", "fields.data", Observed::Null),
                Difference::check(17, "recv(3) MSG_PEEK reads the rest"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "sendmsg is a soft-deny ENOSYS (c/posix/net.c sendmsg, sud/net.rs sys_sendmsg; recvmsg likewise): no scatter-gather or ancillary message reaches SimNet",
            failure: Failure::Differs(&[
                Difference::field(66, "sendmsg", "errno", Observed::Str("ENOSYS")),
                Difference::field(66, "sendmsg", "ret", Observed::Int(-1)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "with sendmsg refused, the first message never leaves and the scenario stops before every message row it pins",
            failure: Failure::Stops {
                events: 67,
                ending: Ending::Exit(101),
                diagnostic: "net/msg: cannot continue: sendmsg gathers three iovecs (one empty) into one datagram",
            },
        },
    ],
    ..DEFAULTS
};
