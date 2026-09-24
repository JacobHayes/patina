//! net/unix_stream — AF_UNIX stream sockets: a connected pair, filesystem
//! paths under the run directory, and abstract names derived from it
//! (unix(7); net/unix/af_unix.c):
//!
//! * a `socketpair` end reads what the other wrote, reads EOF once the
//!   other closed (at once, even under `MSG_DONTWAIT`), and a send to a closed peer is `EPIPE` — raising
//!   `SIGPIPE` (queued while blocked) unless `MSG_NOSIGNAL`
//!   (`unix_stream_sendmsg`);
//! * `SHUT_RD` keeps the bytes already queued readable, then reads EOF
//!   without blocking, and the peer's next send is `EPIPE`; `SHUT_WR` gives
//!   the peer EOF while the other direction keeps working;
//! * `bind` to a path creates a socket inode with mode `0777 & ~umask`, a
//!   second bind to the path is `EADDRINUSE`, a path in a missing directory
//!   `ENOENT`, a length past `sizeof(struct sockaddr_un)` or another family
//!   `EINVAL`; `listen` before `bind` is `EINVAL` (no autobind for listen);
//! * names: the listener's is its path (`addrlen` = the path + its NUL +
//!   the family), a connected client's is unnamed (`addrlen` 2), the
//!   accepted socket's is the listener's path, and the client's peer is the
//!   path; `SO_PEERCRED` is the connecting process;
//! * `connect` to a missing path is `ENOENT`, to a socket that does not
//!   listen or a regular file `ECONNREFUSED`, to a datagram socket's path
//!   `EPROTOTYPE`;
//! * an abstract name has no inode, is `EADDRINUSE` while held, and is free
//!   again once its socket closes; connecting to an abstract name nobody
//!   holds is `ECONNREFUSED`; binding the bare family autobinds a
//!   five-hex-digit abstract name.
//!
//! Every path and abstract name is derived from the run directory.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, SIGSET_BYTES, SOCKADDR_UN, SockAddr, neg};
use crate::scenarios::net::abstract_name;
use crate::signals::{empty_set, has, one_set};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let root = p.dir();
    let sigpipe = one_set(SIGPIPE);

    // ---- a connected pair ----
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    p.require("socketpair", r == 0);
    p.check("send on one end", p.send_to(a, b"ping", 0, None) == 4);
    let (n, data, _) = p.recv_from(b, 16, 0, false);
    p.check("the other end reads it", n == 4 && data == b"ping");
    let (_, name, len) = p.name_of(a, false, 128);
    p.check(
        "a pair's ends are unnamed",
        name == Some(SockAddr::UnixUnnamed) && len == 2,
    );
    p.check("shut down a's writing side", p.shutdown(a, SHUT_WR) == 0);
    p.check(
        "b reads EOF",
        p.recv_from(b, 16, MSG_DONTWAIT, false).0 == 0,
    );
    p.check("b can still send to a", p.send_to(b, b"back", 0, None) == 4);
    let (n, data, _) = p.recv_from(a, 16, 0, false);
    p.check(
        "and a still reads after its own SHUT_WR",
        n == 4 && data == b"back",
    );
    p.check(
        "a send after SHUT_WR is EPIPE",
        p.send_to(a, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );

    p.check("queue bytes for b", p.send_to(b, b"queued", 0, None) == 6);
    p.check("shut down a's reading side", p.shutdown(a, SHUT_RD) == 0);
    let (n, data, _) = p.recv_from(a, 16, 0, false);
    p.check(
        "SHUT_RD keeps the queued bytes readable",
        n == 6 && data == b"queued",
    );
    p.check(
        "then reads EOF without blocking",
        p.recv_from(a, 16, MSG_DONTWAIT, false).0 == 0,
    );
    p.check(
        "and the peer's next send is EPIPE",
        p.send_to(b, b"late", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.close(a);
    p.close(b);

    let (r, [c, d]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("a second pair", r == 0);
    p.check("close one end", p.close(d) == 0);
    p.check(
        "the survivor reads EOF",
        p.recv_from(c, 16, MSG_DONTWAIT, false).0 == 0,
    );
    p.check(
        "a send to a closed peer with MSG_NOSIGNAL is EPIPE",
        p.send_to(c, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    let mut pending = empty_set();
    p.rt_sigpending(&mut pending, SIGSET_BYTES as usize);
    p.check("MSG_NOSIGNAL raised no SIGPIPE", !has(&pending, SIGPIPE));
    p.check(
        "block SIGPIPE",
        p.rt_sigprocmask(SIG_BLOCK, Some(&sigpipe), None, SIGSET_BYTES as usize) == 0,
    );
    p.check(
        "a send to a closed peer is EPIPE",
        p.send_to(c, b"x", 0, None) == neg(EPIPE),
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
    p.close(c);

    // ---- a filesystem path ----
    let path = p.unix_path("stream.sock");
    let l = p.socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    p.require("an AF_UNIX stream socket", l >= 0);
    p.check(
        "listen before bind is EINVAL",
        p.listen(l, 4) == neg(EINVAL),
    );
    p.check(
        "bind to a path in the run directory",
        p.bind_to(l, &SockAddr::UnixPath(path.clone())) == 0,
    );
    let (r, st) = p.newfstatat(AT_FDCWD, &path, AT_SYMLINK_NOFOLLOW);
    p.check(
        "bind created a socket inode with mode 0777 & ~umask",
        r == 0
            && st
                .as_ref()
                .is_some_and(|st| st.kind == "sock" && st.perm == 0o755),
    );
    let l2 = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a second stream socket", l2 >= 0);
    p.check(
        "a second bind to the path is EADDRINUSE",
        p.bind_to(l2, &SockAddr::UnixPath(path.clone())) == neg(EADDRINUSE),
    );
    p.check(
        "bind to a path in a missing directory is ENOENT",
        p.bind_to(l2, &SockAddr::UnixPath(p.unix_path("missing/s.sock"))) == neg(ENOENT),
    );
    p.check(
        "an address past sizeof(struct sockaddr_un) is EINVAL",
        p.bind_to(
            l2,
            &SockAddr::Raw {
                family: AF_UNIX as u16,
                len: SOCKADDR_UN + 1,
            },
        ) == neg(EINVAL),
    );
    p.check(
        "an address of another family is EINVAL",
        p.bind_to(
            l2,
            &SockAddr::Raw {
                family: AF_INET as u16,
                len: size_of::<sockaddr_in>(),
            },
        ) == neg(EINVAL),
    );
    p.check(
        "connect to a socket that does not listen is ECONNREFUSED",
        p.connect_to(l2, &SockAddr::UnixPath(path.clone())) == neg(ECONNREFUSED),
    );
    p.check("listen", p.listen(l, 4) == 0);
    let (r, name, len) = p.name_of(l, false, 128);
    p.check(
        "the listener's name is its path, with the NUL in addrlen",
        r == 0
            && name == Some(SockAddr::UnixPath(path.clone()))
            && len as usize == 2 + path.len() + 1,
    );
    let cl = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a client", cl >= 0);
    p.check(
        "connect to the path",
        p.connect_to(cl, &SockAddr::UnixPath(path.clone())) == 0,
    );
    let (_, name, len) = p.name_of(cl, false, 128);
    p.check(
        "a connected client is unnamed",
        name == Some(SockAddr::UnixUnnamed) && len == 2,
    );
    let (_, peer, _) = p.name_of(cl, true, 128);
    p.check(
        "the client's peer is the path",
        peer == Some(SockAddr::UnixPath(path.clone())),
    );
    let (s, from) = p.accept_from(l, SOCK_CLOEXEC, false, true);
    p.require("accept4", s >= 0);
    p.check(
        "the accepted peer is unnamed",
        from == Some(SockAddr::UnixUnnamed),
    );
    let (_, name, _) = p.name_of(s, false, 128);
    p.check(
        "the accepted socket's name is the listener's path",
        name == Some(SockAddr::UnixPath(path.clone())),
    );
    let (r, creds) = p.peercred(cl);
    let pid = p.getpid();
    let uid = p.getuid();
    let gid = p.getgid();
    p.check(
        "SO_PEERCRED is this process's pid, uid and gid",
        r == 0 && creds == Some((pid as i32, uid as u32, gid as u32)),
    );
    p.check("send over the path", p.send_to(cl, b"over", 0, None) == 4);
    let (n, data, _) = p.recv_from(s, 16, 0, false);
    p.check("the accepted socket reads it", n == 4 && data == b"over");
    p.check(
        "accept4 on a socket that does not listen is EINVAL",
        i64::from(p.accept_from(cl, 0, false, false).0) == neg(EINVAL),
    );
    p.check(
        "connect to a missing path is ENOENT",
        p.connect_to(l2, &SockAddr::UnixPath(p.unix_path("none.sock"))) == neg(ENOENT),
    );
    let file = p.unix_path("plain");
    let f = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT, 0o600);
    p.require("create a regular file", f >= 0);
    p.close(f);
    p.check(
        "connect to a regular file is ECONNREFUSED",
        p.connect_to(l2, &SockAddr::UnixPath(file)) == neg(ECONNREFUSED),
    );
    let dg = p.socket(AF_UNIX, SOCK_DGRAM, 0);
    p.require("a datagram socket", dg >= 0);
    let dg_path = p.unix_path("dgram.sock");
    p.check(
        "bind the datagram socket",
        p.bind_to(dg, &SockAddr::UnixPath(dg_path.clone())) == 0,
    );
    p.check(
        "connect a stream socket to a datagram socket's path is EPROTOTYPE",
        p.connect_to(l2, &SockAddr::UnixPath(dg_path.clone())) == neg(EPROTOTYPE),
    );
    for fd in [cl, s, l, l2, dg] {
        p.close(fd);
    }
    p.check(
        "the path outlives the socket: remove it",
        p.unlinkat(AT_FDCWD, &path, 0) == 0,
    );
    p.unlinkat(AT_FDCWD, &dg_path, 0);

    // ---- abstract names ----
    let name = abstract_name(&root, "stream");
    let la = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("an abstract listener", la >= 0);
    p.check(
        "bind an abstract name",
        p.bind_to(la, &SockAddr::UnixAbstract(name.clone())) == 0,
    );
    let (_, bound, len) = p.name_of(la, false, 128);
    p.check(
        "the name is abstract, addrlen the family + NUL + the name",
        bound == Some(SockAddr::UnixAbstract(name.clone())) && len as usize == 3 + name.len(),
    );
    let lb = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a second abstract socket", lb >= 0);
    p.check(
        "the held abstract name is EADDRINUSE",
        p.bind_to(lb, &SockAddr::UnixAbstract(name.clone())) == neg(EADDRINUSE),
    );
    p.check("listen on it", p.listen(la, 4) == 0);
    let ca = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("an abstract client", ca >= 0);
    p.check(
        "connect to the abstract name",
        p.connect_to(ca, &SockAddr::UnixAbstract(name.clone())) == 0,
    );
    let (sa, _) = p.accept_from(la, 0, false, false);
    p.check("accept it", sa >= 0);
    for fd in [ca, sa, la] {
        p.close(fd);
    }
    p.check(
        "a closed socket's abstract name is free again",
        p.bind_to(lb, &SockAddr::UnixAbstract(name.clone())) == 0,
    );
    let cn = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("another client", cn >= 0);
    p.check(
        "connect to an abstract name nobody holds is ECONNREFUSED",
        p.connect_to(cn, &SockAddr::UnixAbstract(abstract_name(&root, "nobody")))
            == neg(ECONNREFUSED),
    );
    let au = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("an autobinding socket", au >= 0);
    p.check(
        "bind with only the family autobinds",
        p.bind_to(au, &SockAddr::UnixUnnamed) == 0,
    );
    let (_, auto, len) = p.name_of(au, false, 128);
    p.check(
        "the autobind name is five hex digits in the abstract namespace",
        auto.as_ref().is_some_and(SockAddr::autobound) && len == 8,
    );
    // A connection its listener never accepted is reset when the listener
    // closes (`unix_release_sock` of the embryo): its client reads
    // ECONNRESET once, then end-of-file.
    let lr = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a listener that will not accept", lr >= 0);
    let reset = abstract_name(&root, "reset");
    p.check(
        "bind it",
        p.bind_to(lr, &SockAddr::UnixAbstract(reset.clone())) == 0,
    );
    p.check("listen", p.listen(lr, 4) == 0);
    let cr = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("a client in its backlog", cr >= 0);
    p.check(
        "connect",
        p.connect_to(cr, &SockAddr::UnixAbstract(reset)) == 0,
    );
    p.check("close the listener unaccepted", p.close(lr) == 0);
    p.check(
        "the client reads ECONNRESET",
        p.recv(cr, 8, 0).0 == neg(ECONNRESET),
    );
    p.check("then end-of-file", p.recv(cr, 8, 0).0 == 0);
    for fd in [lb, cn, au, cr] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/unix_stream",
    run,
    covers: &[
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_getsockopt,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_shutdown,
        Syscall::N_newfstatat,
        Syscall::N_unlinkat,
        Syscall::N_openat,
        Syscall::N_getpid,
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigtimedwait,
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
        "getpeername",
        "getsockopt",
        "sendto",
        "recvfrom",
        "shutdown",
        "fstatat",
        "unlinkat",
        "openat",
        "getpid",
        "getuid",
        "getgid",
        "close",
    ],
    ..DEFAULTS
};
