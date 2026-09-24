//! net/fortify — glibc's `_FORTIFY_SOURCE` spellings of the receive and
//! poll calls: `__recv_chk`, `__recvfrom_chk`, `__poll_chk`, `__ppoll_chk`
//! (glibc debug/recv_chk.c, recvfrom_chk.c, poll_chk.c, ppoll_chk.c). A
//! program built with `-D_FORTIFY_SOURCE` imports them in place of `recv`,
//! `recvfrom`, `poll` and `ppoll`; within the buffer size the compiler knew
//! they answer exactly what the plain call answers:
//!
//! * `__recv_chk`/`__recvfrom_chk` read a queued datagram (with its source);
//! * `__poll_chk`/`__ppoll_chk` report a readable socket.
//!
//! libc only, and through `dlsym`: the registry lists the four `Absent`
//! (the shim does not define them), so the probe binary cannot import them
//! (the pre-run audit would refuse the whole binary), and under patina
//! `dlsym` answers only what the shim defines. The overflow path
//! (`__chk_fail`, SIGABRT) is not exercised.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{Probe, SockAddr};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

type RecvChk = unsafe extern "C" fn(c_int, *mut c_void, size_t, size_t, c_int) -> ssize_t;
type RecvfromChk = unsafe extern "C" fn(
    c_int,
    *mut c_void,
    size_t,
    size_t,
    c_int,
    *mut sockaddr,
    *mut socklen_t,
) -> ssize_t;
type PollChk = unsafe extern "C" fn(*mut pollfd, nfds_t, c_int, size_t) -> c_int;
type PpollChk =
    unsafe extern "C" fn(*mut pollfd, nfds_t, *const timespec, *const sigset_t, size_t) -> c_int;

const SYMBOLS: [&str; 4] = ["__recv_chk", "__recvfrom_chk", "__poll_chk", "__ppoll_chk"];

pub fn run(p: &Probe) {
    let r = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a receiver", r >= 0);
    p.check("bind it", p.bind_to(r, &SockAddr::v4(0)) == 0);
    let (_, addr_r, _) = p.name_of(r, false, 128);
    let addr_r = addr_r.expect("getsockname r");
    let s = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", s >= 0);
    p.check("bind the sender", p.bind_to(s, &SockAddr::v4(0)) == 0);
    let (_, addr_s, _) = p.name_of(s, false, 128);

    let found: Vec<_> = SYMBOLS.iter().map(|symbol| p.resolve(symbol)).collect();
    p.require(
        "the fortified symbols resolve",
        found.iter().all(Option::is_some),
    );
    // SAFETY: glibc's definitions, by their documented types.
    let (recv_chk, recvfrom_chk, poll_chk, ppoll_chk) = unsafe {
        (
            std::mem::transmute::<*mut c_void, RecvChk>(found[0].unwrap()),
            std::mem::transmute::<*mut c_void, RecvfromChk>(found[1].unwrap()),
            std::mem::transmute::<*mut c_void, PollChk>(found[2].unwrap()),
            std::mem::transmute::<*mut c_void, PpollChk>(found[3].unwrap()),
        )
    };

    p.send_to(s, b"first", 0, Some(&addr_r));
    let mut fds = [pollfd {
        fd: r,
        events: POLLIN,
        revents: 0,
    }];
    // SAFETY: one pollfd, its size declared.
    let n = fold_errno(i64::from(unsafe {
        poll_chk(fds.as_mut_ptr(), 1, 0, size_of::<pollfd>())
    }));
    p.rec
        .event("__poll_chk", n)
        .field("revents", fds[0].revents)
        .emit();
    p.check(
        "__poll_chk reports the readable socket",
        n == 1 && fds[0].revents == POLLIN,
    );
    let zero = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    fds[0].revents = 0;
    // SAFETY: one pollfd, its size declared; a zero timeout; no mask.
    let n = fold_errno(i64::from(unsafe {
        ppoll_chk(
            fds.as_mut_ptr(),
            1,
            &zero,
            std::ptr::null(),
            size_of::<pollfd>(),
        )
    }));
    p.rec
        .event("__ppoll_chk", n)
        .field("revents", fds[0].revents)
        .emit();
    p.check(
        "__ppoll_chk reports it too",
        n == 1 && fds[0].revents == POLLIN,
    );

    let mut buf = [0u8; 16];
    // SAFETY: a 16-byte buffer, asked for 16 of its 16 bytes.
    let n = fold_errno(unsafe { recv_chk(r, buf.as_mut_ptr().cast(), 16, 16, 0) } as i64);
    p.rec
        .event("__recv_chk", n)
        .field(
            "data",
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned(),
        )
        .emit();
    p.check(
        "__recv_chk reads the datagram",
        n == 5 && buf[..5] == *b"first",
    );

    p.send_to(s, b"second", 0, Some(&addr_r));
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut from: sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<sockaddr_storage>() as socklen_t;
    // SAFETY: a 16-byte buffer, asked for 8 of its 16 bytes; a name buffer.
    let n = fold_errno(unsafe {
        recvfrom_chk(
            r,
            buf.as_mut_ptr().cast(),
            8,
            16,
            0,
            &mut from as *mut _ as *mut sockaddr,
            &mut len,
        )
    } as i64);
    let src = (n >= 0).then(|| SockAddr::decode(&from, len));
    p.rec
        .event("__recvfrom_chk", n)
        .field(
            "data",
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned(),
        )
        .field("addrlen", len)
        .emit();
    p.check(
        "__recvfrom_chk reads it with the source",
        n == 6 && buf[..6] == *b"second" && src == addr_s,
    );
    p.close(s);
    p.close(r);
    crate::scenarios::net::check_allocated_port(p, &addr_r);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/fortify",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_close,
    ],
    symbols: &[
        "__recv_chk",
        "__recvfrom_chk",
        "__poll_chk",
        "__ppoll_chk",
        "socket",
        "bind",
        "getsockname",
        "sendto",
        "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines none of __recv_chk/__recvfrom_chk/__poll_chk/__ppoll_chk (registry `Absent`): a fortified guest importing one is refused by the pre-run audit, and `dlsym` finds none (c/posix/entropy.c `__wrap_dlsym` answers the shim's own definitions alone)",
            failure: Failure::Differs(&[
                Difference::field(8, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(9, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(10, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(11, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: &[Vehicle::Libc],
            what: "with none of them resolved the scenario cannot continue",
            failure: Failure::Stops {
                events: 12,
                ending: Ending::Exit(101),
                diagnostic: "net/fortify: cannot continue: the fortified symbols resolve",
            },
        },
    ],
    ..DEFAULTS
};
