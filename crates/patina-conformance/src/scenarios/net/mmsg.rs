//! net/mmsg — sendmmsg / recvmmsg over loopback UDP (sendmmsg(2),
//! recvmmsg(2); net/socket.c `__sys_sendmmsg`/`do_recvmmsg`):
//!
//! * one call sends several datagrams, each to its own destination, and
//!   fills every sent message's `msg_len`; `vlen` 0 sends nothing and
//!   answers 0; a `vlen` past `UIO_MAXIOV` is silently capped to it;
//! * a failure after the first message is swallowed (the call answers the
//!   count sent; the error is lost), a failure on the first is the call's
//!   error (`EDESTADDRREQ` with no destination);
//! * `MSG_DONTWAIT` answers the datagrams queued (fewer than `vlen`), and
//!   `EAGAIN` when there are none; `MSG_WAITFORONE` turns the call
//!   non-blocking after the first datagram; a datagram longer than its
//!   buffer is truncated with `MSG_TRUNC` in its `msg_flags` and `msg_len`
//!   the bytes delivered; an invalid timeout is `EINVAL` before anything is
//!   received;
//! * `ENOTSOCK` on a file, `EBADF` on a closed descriptor.
//!
//! A blocking receive with a timeout is not exercised: the timeout is only
//! checked after each datagram (recvmmsg(2) BUGS), so it cannot bound a wait.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Outgoing, Probe, SockAddr, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `UIO_MAXIOV`: the most messages one `sendmmsg`/`recvmmsg` handles.
const UIO_MAXIOV: usize = 1024;

pub fn run(p: &Probe) {
    let root = p.dir();
    let a = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("socket a", a >= 0);
    p.require("bind a", p.bind_to(a, &SockAddr::v4(0)) == 0);
    let (_, addr_a, _) = p.name_of(a, false, 128);
    let addr_a = addr_a.expect("getsockname a");
    let b = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket b", b >= 0);
    p.require("bind b", p.bind_to(b, &SockAddr::v4(0)) == 0);
    let (_, addr_b, _) = p.name_of(b, false, 128);
    let addr_b = addr_b.expect("getsockname b");

    let to_b = |data: &'static [u8]| Outgoing {
        data,
        to: Some(addr_b.clone()),
    };
    let (n, sent) = p.sendmmsg(a, &[to_b(b"one"), to_b(b"two"), to_b(b"three")], 0);
    p.require("sendmmsg sends three datagrams", n == 3);
    p.check("every sent message's msg_len is filled", sent == [3, 3, 5]);
    let (n, got) = p.recvmmsg(b, &[8, 8, 8, 8], MSG_DONTWAIT, None);
    p.check(
        "MSG_DONTWAIT answers the three queued datagrams of four asked",
        n == 3
            && got.iter().map(|m| m.data.clone()).collect::<Vec<_>>()
                == [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
    );
    p.check(
        "each received message carries its length, no flags and the source",
        got.iter().map(|m| m.len).collect::<Vec<_>>() == [3, 3, 5]
            && got
                .iter()
                .all(|m| m.flags == 0 && m.from.as_ref() == Some(&addr_a)),
    );
    p.check(
        "MSG_DONTWAIT with nothing queued is EAGAIN",
        p.recvmmsg(b, &[8], MSG_DONTWAIT, None).0 == neg(EAGAIN),
    );
    p.check(
        "vlen 0 sends nothing and answers 0",
        p.sendmmsg(a, &[], 0).0 == 0,
    );

    let (n, _) = p.sendmmsg(a, &[to_b(b"0123456789")], 0);
    p.check("send a ten-byte datagram", n == 1);
    let (n, got) = p.recvmmsg(b, &[4], MSG_DONTWAIT, None);
    p.check(
        "a short buffer truncates: msg_len is the bytes delivered, MSG_TRUNC set",
        n == 1 && got[0].data == b"0123" && got[0].len == 4 && got[0].flags == MSG_TRUNC,
    );

    let (n, _) = p.sendmmsg(a, &[to_b(b"w1"), to_b(b"w2")], 0);
    p.check("queue two datagrams", n == 2);
    let (n, got) = p.recvmmsg(b, &[8, 8, 8], MSG_WAITFORONE, None);
    p.check(
        "MSG_WAITFORONE on a blocking socket answers what is queued after the first",
        n == 2 && got[1].data == b"w2",
    );
    p.check(
        "an invalid timeout is EINVAL",
        p.recvmmsg(b, &[8], MSG_DONTWAIT, Some((0, 1_000_000_000)))
            .0
            == neg(EINVAL),
    );
    let (n, _) = p.sendmmsg(a, &[to_b(b"t")], 0);
    p.check("queue one datagram", n == 1);
    let (n, got) = p.recvmmsg(b, &[8, 8], MSG_WAITFORONE, Some((0, 0)));
    p.check(
        "a zero timeout still answers the queued datagram",
        n == 1 && got[0].data == b"t",
    );

    let failing_second = [
        to_b(b"first"),
        Outgoing {
            data: b"nowhere",
            to: None,
        },
    ];
    p.check(
        "a failure after the first message answers the count sent",
        p.sendmmsg(a, &failing_second, 0).0 == 1,
    );
    let failing_first = [Outgoing {
        data: b"nowhere",
        to: None,
    }];
    p.check(
        "a failure on the first message is the call's error",
        p.sendmmsg(a, &failing_first, 0).0 == neg(EDESTADDRREQ),
    );
    let (n, got) = p.recvmmsg(b, &[8, 8], MSG_DONTWAIT, None);
    p.check(
        "only the first message was sent",
        n == 1 && got[0].data == b"first",
    );

    // A vlen past UIO_MAXIOV is capped, not refused: to a receiver that is
    // then closed, dropping what its buffer could not hold.
    let sink = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("sink socket", sink >= 0);
    p.require("bind the sink", p.bind_to(sink, &SockAddr::v4(0)) == 0);
    let (_, addr_sink, _) = p.name_of(sink, false, 128);
    let addr_sink = addr_sink.expect("getsockname sink");
    let flood: Vec<Outgoing<'_>> = (0..=UIO_MAXIOV)
        .map(|_| Outgoing {
            data: b"",
            to: Some(addr_sink.clone()),
        })
        .collect();
    p.check(
        "a vlen past UIO_MAXIOV is capped to it",
        p.sendmmsg(a, &flood, 0).0 == UIO_MAXIOV as i64,
    );
    p.close(sink);

    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o600);
    p.require("open a file", file >= 0);
    p.check(
        "sendmmsg on a file is ENOTSOCK",
        p.sendmmsg(file, &[to_b(b"x")], 0).0 == neg(ENOTSOCK),
    );
    p.check(
        "recvmmsg on a file is ENOTSOCK",
        p.recvmmsg(file, &[8], MSG_DONTWAIT, None).0 == neg(ENOTSOCK),
    );
    for fd in [a, file] {
        p.close(fd);
    }
    p.check(
        "sendmmsg on a closed descriptor is EBADF",
        p.sendmmsg(a, &[to_b(b"x")], 0).0 == neg(EBADF),
    );
    p.check(
        "recvmmsg on a closed descriptor is EBADF",
        p.recvmmsg(a, &[8], MSG_DONTWAIT, None).0 == neg(EBADF),
    );
    p.close(b);
    crate::scenarios::net::check_allocated_port(p, &addr_a);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/mmsg",
    run,
    covers: &[
        Syscall::N_sendmmsg,
        Syscall::N_recvmmsg,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "sendmmsg",
        "recvmmsg",
        "socket",
        "bind",
        "getsockname",
        "openat",
        "close",
    ],
    ..DEFAULTS
};
