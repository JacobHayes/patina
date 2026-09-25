//! net/scm — ancillary data over an AF_UNIX stream pair within one process:
//! `SCM_RIGHTS` and `SCM_CREDENTIALS` (unix(7), cmsg(3); net/core/scm.c,
//! net/unix/af_unix.c):
//!
//! * `SCM_RIGHTS` installs a NEW descriptor for the same open file
//!   description: the same inode, the shared file offset, no close-on-exec
//!   unless the receive asks `MSG_CMSG_CLOEXEC`; several descriptors travel
//!   in one message, in order; a peek installs its own copies, and the
//!   receive after it installs them again (`unix_peek_fds`);
//! * a control buffer too small for the descriptors (or none at all) sets
//!   `MSG_CTRUNC` and installs nothing; a descriptor that is not open is
//!   `EBADF`, more than `SCM_MAX_FD` (253) `EINVAL`, a header shorter than
//!   a `cmsghdr` `EINVAL`;
//! * with `SO_PASSCRED` every received message carries `SCM_CREDENTIALS`
//!   of the sender — this process's pid, uid and gid — and a sender may
//!   state its own credentials explicitly; credentials ride a datagram only
//!   when an end asked for them when it was sent (`maybe_add_creds`): a
//!   receiver that asks afterwards reads none — pid 0 and the overflow ids.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Control, OptionShown, Probe, RecvSpec, neg};
use crate::scenarios::net::int;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `SCM_MAX_FD`: the most descriptors one `SCM_RIGHTS` message carries
/// (include/net/scm.h).
const SCM_MAX_FD: usize = 253;

/// `CMSG_SPACE` for `n` descriptors.
fn rights_space(n: usize) -> usize {
    // SAFETY: pure arithmetic.
    unsafe { CMSG_SPACE((n * 4) as u32) as usize }
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    p.require("a stream socketpair", r == 0);
    let file = p.openat(AT_FDCWD, &format!("{root}/shared"), O_RDWR | O_CREAT, 0o600);
    p.require("open a file", file >= 0);
    p.check("write ten bytes", p.write(file, b"0123456789") == 10);
    p.check("seek to 3", p.lseek(file, 3, SEEK_SET) == 3);

    // Everything below needs sendmsg: a runtime without it stops here
    // rather than wait on a message that never left.
    let sent = p.sendmsg(a, &[b"F"], None, &Control::Rights(vec![file]), 0);
    p.require("sendmsg with SCM_RIGHTS", sent == 1);
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: rights_space(1),
            flags: 0,
        },
    );
    p.check(
        "one descriptor arrives with the byte",
        got.result == 1 && got.msg_flags == 0 && got.rights.len() == 1,
    );
    let g = got.rights.first().copied().unwrap_or(-1);
    p.check("it is a new descriptor number", g >= 0 && g != file);
    let (_, original) = p.fstat(file);
    let (_, received) = p.fstat(g);
    p.check(
        "for the same inode",
        original.zip(received).is_some_and(|(o, r)| o.ino == r.ino),
    );
    p.check(
        "sharing the open file description's offset",
        p.lseek(g, 0, SEEK_CUR) == 3,
    );
    p.check("without close-on-exec", p.fcntl(g, F_GETFD, 0) == 0);
    p.close(g);

    p.sendmsg(a, &[b"C"], None, &Control::Rights(vec![file]), 0);
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: rights_space(1),
            flags: MSG_CMSG_CLOEXEC,
        },
    );
    let g = got.rights.first().copied().unwrap_or(-1);
    p.check(
        "MSG_CMSG_CLOEXEC installs it close-on-exec",
        g >= 0 && p.fcntl(g, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.close(g);

    p.sendmsg(a, &[b"P"], None, &Control::Rights(vec![file]), 0);
    let one_right = |flags| RecvSpec {
        segments: &[8],
        name: None,
        control: rights_space(1),
        flags,
    };
    let peeked = p.recvmsg(b, one_right(MSG_PEEK));
    p.check(
        "a peek installs a copy of the descriptor",
        peeked.result == 1 && peeked.rights.len() == 1,
    );
    let taken = p.recvmsg(b, one_right(0));
    p.check(
        "and the receive installs it again",
        taken.result == 1 && taken.rights.len() == 1 && taken.rights != peeked.rights,
    );
    for fd in peeked.rights.iter().chain(&taken.rights) {
        p.close(*fd);
    }

    let (r, [pr, pw]) = p.pipe2(O_CLOEXEC);
    p.require("a pipe", r == 0);
    p.sendmsg(a, &[b"2"], None, &Control::Rights(vec![pw, file]), 0);
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: rights_space(2),
            flags: 0,
        },
    );
    p.check("two descriptors in one message", got.rights.len() == 2);
    if let [w, f] = got.rights[..] {
        p.check("the first is the pipe's writer", p.write(w, b"via") == 3);
        let (n, data) = p.read(pr, 8);
        p.check("the pipe carries it", n == 3 && data == b"via");
        p.check(
            "the second shares the file's offset",
            p.lseek(f, 0, SEEK_CUR) == 3,
        );
        p.close(w);
        p.close(f);
    }

    p.sendmsg(a, &[b"T"], None, &Control::Rights(vec![file]), 0);
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: rights_space(0),
            flags: 0,
        },
    );
    p.check(
        "a control buffer with no room for the descriptor: MSG_CTRUNC, nothing installed",
        got.result == 1 && got.msg_flags == MSG_CTRUNC && got.rights.is_empty(),
    );
    p.sendmsg(a, &[b"N"], None, &Control::Rights(vec![file]), 0);
    let got = p.recvmsg(b, RecvSpec::plain(&[8]));
    p.check(
        "no control buffer at all: MSG_CTRUNC",
        got.result == 1 && got.msg_flags == MSG_CTRUNC,
    );
    p.check(
        "a descriptor that is not open is EBADF",
        p.sendmsg(a, &[b"x"], None, &Control::Rights(vec![900]), 0) == neg(EBADF),
    );
    p.check(
        "more than SCM_MAX_FD descriptors is EINVAL",
        p.sendmsg(
            a,
            &[b"x"],
            None,
            &Control::Rights(vec![file; SCM_MAX_FD + 1]),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "a control header shorter than a cmsghdr is EINVAL",
        p.sendmsg(a, &[b"x"], None, &Control::ShortHeader, 0) == neg(EINVAL),
    );

    // ---- credentials ----
    let pid = p.getpid();
    let uid = p.getuid();
    let gid = p.getgid();
    let (r, [da, db]) = p.socketpair(AF_UNIX, SOCK_DGRAM, 0);
    p.require("a datagram socketpair", r == 0);
    p.check(
        "a datagram sent with no end asking for credentials",
        p.sendmsg(da, &[b"c"], None, &Control::None, 0) == 1,
    );
    p.check(
        "the receiver asks afterwards",
        p.setsockopt_bytes(db, SOL_SOCKET, SO_PASSCRED, &int(1), 4, "1") == 0,
    );
    let with_creds = RecvSpec {
        segments: &[8],
        name: None,
        control: 64,
        flags: 0,
    };
    let got = p.recvmsg(db, with_creds);
    p.check(
        "and reads pid 0 and the overflow ids",
        got.result == 1 && got.creds == Some((0, 65534, 65534)),
    );
    p.check(
        "a datagram sent now",
        p.sendmsg(da, &[b"d"], None, &Control::None, 0) == 1,
    );
    let got = p.recvmsg(db, with_creds);
    p.check(
        "carries the sender's credentials",
        got.result == 1 && got.creds == Some((pid as i32, uid as u32, gid as u32)),
    );
    p.close(da);
    p.close(db);

    let one = int(1);
    p.check(
        "set SO_PASSCRED on the receiver",
        p.setsockopt_bytes(b, SOL_SOCKET, SO_PASSCRED, &one, 4, "1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(b, SOL_SOCKET, SO_PASSCRED, 4, OptionShown::Exact);
    p.check("SO_PASSCRED reads back 1", r == 0 && value == one);
    p.sendmsg(a, &[b"c"], None, &Control::None, 0);
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: 64,
            flags: 0,
        },
    );
    p.check(
        "a plain message arrives with the sender's credentials",
        got.result == 1 && got.creds == Some((pid as i32, uid as u32, gid as u32)),
    );
    p.check(
        "a sender may state its own credentials",
        p.sendmsg(
            a,
            &[b"e"],
            None,
            &Control::Creds {
                pid: pid as i32,
                uid: uid as u32,
                gid: gid as u32,
            },
            0,
        ) == 1,
    );
    let got = p.recvmsg(
        b,
        RecvSpec {
            segments: &[8],
            name: None,
            control: 64,
            flags: 0,
        },
    );
    p.check(
        "and they arrive",
        got.result == 1 && got.creds == Some((pid as i32, uid as u32, gid as u32)),
    );

    for fd in [a, b, file, pr, pw] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/scm",
    run,
    covers: &[
        Syscall::N_socketpair,
        Syscall::N_sendmsg,
        Syscall::N_recvmsg,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_read,
        Syscall::N_lseek,
        Syscall::N_fstat,
        Syscall::N_fcntl,
        Syscall::N_pipe2,
        Syscall::N_getpid,
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_close,
    ],
    symbols: &[
        "socketpair",
        "sendmsg",
        "recvmsg",
        "setsockopt",
        "getsockopt",
        "openat",
        "write",
        "read",
        "lseek",
        "fstat",
        "fcntl",
        "pipe2",
        "getpid",
        "getuid",
        "getgid",
        "close",
    ],
    ..DEFAULTS
};
