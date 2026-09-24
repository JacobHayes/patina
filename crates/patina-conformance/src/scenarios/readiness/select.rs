//! readiness/select — select(2) and pselect6 over sockets (select(2);
//! fs/select.c `core_sys_select`, `kern_select`, `do_pselect`):
//!
//! * the answer counts set bits across the three sets: a UDP socket that is
//!   readable and writable counts twice; urgent TCP data sets the
//!   exception bit (`tcp_poll` `EPOLLPRI`);
//! * a descriptor in a set that is not open is `EBADF`; a negative `nfds`
//!   `EINVAL`;
//! * select's timeout is normalized, not refused, when its microseconds
//!   reach a second (only a negative one is `EINVAL`), and Linux writes the
//!   unslept time back: zero after a full timeout;
//! * pselect6 takes its mask with the kernel's sigset size — another size is
//!   `EINVAL` — and refuses a timespec whose nanoseconds reach a second.
//!
//! Natively the `select` row is reached by the syscall and raw vehicles: glibc
//! (≥ 2.35) implements `select(3)` over `pselect6`, normalizing the timeval
//! itself, so the libc vehicle's native answer is pselect6's; under patina it
//! exercises the shim's `select` symbol, the interesting door.
//! The generic (arm64) table has no `select` row: there the syscall vehicle
//! issues `pselect6` with a timespec and converts the unslept time back
//! (glibc's own spelling). glibc's `pselect` copies its timeout, so what the
//! pselect6 row writes back is never recorded.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{Probe, SIGSET_BYTES, Sets, SockAddr, neg};
use crate::signals::one_set;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// The vehicles whose door hands a select timeval to patina unnormalized:
/// every one on x86_64 (the `select` row); on arm64 only glibc's `select`
/// (the syscall vehicle spells it `pselect6` and normalizes first).
const NORMALIZED_BY_THE_DOOR: &[Vehicle] = if cfg!(target_arch = "x86_64") {
    Vehicle::ALL
} else {
    &[Vehicle::Libc]
};

/// How long a wait for an event already caused may take: `(sec, usec)`.
const WAIT: (i64, i64) = (5, 0);

pub fn run(p: &Probe) {
    let u = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a UDP socket", u >= 0);
    p.check("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    let (_, addr_u, _) = p.name_of(u, false, 128);
    let addr_u = addr_u.expect("getsockname u");
    let nfds = u + 1;
    let both = Sets {
        read: &[u],
        write: &[u],
        except: &[],
    };
    let (n, ready, _) = p.select(nfds, both, Some((0, 0)));
    p.check(
        "an empty UDP socket is writable only",
        n == 1 && ready.read == [false] && ready.write == [true],
    );
    p.check(
        "send it a datagram",
        p.send_to(u, b"d", 0, Some(&addr_u)) == 1,
    );
    let (n, _, _) = p.select(
        nfds,
        Sets {
            read: &[u],
            ..Sets::default()
        },
        Some(WAIT),
    );
    p.check("the datagram arrives", n == 1);
    let (n, ready, _) = p.select(nfds, both, Some((0, 0)));
    p.check(
        "readable and writable counts twice",
        n == 2 && ready.read == [true] && ready.write == [true],
    );
    let (n, _, _) = p.select(nfds, both, Some((0, 1_500_000)));
    p.check(
        "a timeout whose microseconds reach a second is normalized, not refused",
        n == 2,
    );
    p.check(
        "a negative timeout is EINVAL",
        p.select(nfds, both, Some((0, -1))).0 == neg(EINVAL),
    );
    let (n, ready) = p.pselect6(nfds, both, Some((0, 0)), None, SIGSET_BYTES as usize);
    p.check(
        "pselect6 answers the same",
        n == 2 && ready.read == [true] && ready.write == [true],
    );
    let usr1 = one_set(SIGUSR1);
    let (n, _) = p.pselect6(nfds, both, Some((0, 0)), Some(&usr1), SIGSET_BYTES as usize);
    p.check("pselect6 with a mask", n == 2);
    p.check(
        "pselect6 with another sigset size is EINVAL",
        p.pselect6(nfds, both, Some((0, 0)), Some(&usr1), 4).0 == neg(EINVAL),
    );
    p.check(
        "pselect6 with nanoseconds reaching a second is EINVAL",
        p.pselect6(
            nfds,
            both,
            Some((0, 1_000_000_000)),
            None,
            SIGSET_BYTES as usize,
        )
        .0 == neg(EINVAL),
    );
    p.recv_from(u, 8, 0, false);

    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    let (n, _, left) = p.select(
        nfds,
        Sets {
            read: &[u],
            ..Sets::default()
        },
        Some((0, 2_000)),
    );
    p.check(
        "a timed select with nothing ready answers 0 and leaves no time",
        n == 0 && left == Some((0, 0)),
    );
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the clock advanced by at least the timeout",
        after - before >= 2_000_000,
    );

    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a listener", l >= 0);
    p.check("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.check("connect", p.connect_to(c, &addr_l) == 0);
    let (s, _) = p.accept_from(l, 0, false, false);
    p.require("accept4", s >= 0);
    let except = Sets {
        except: &[s],
        ..Sets::default()
    };
    let (n, _, _) = p.select(s + 1, except, Some((0, 0)));
    p.check("no urgent data: no exception", n == 0);
    p.check(
        "send an urgent byte",
        p.send_to(c, b"!", MSG_OOB, None) == 1,
    );
    let (n, ready, _) = p.select(s + 1, except, Some(WAIT));
    p.check(
        "urgent data sets the exception bit",
        n == 1 && ready.except == [true],
    );

    let x = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a socket to close", x >= 0);
    p.close(x);
    let stale = Sets {
        read: &[x],
        ..Sets::default()
    };
    p.check(
        "a set naming a closed descriptor is EBADF",
        p.select(x + 1, stale, Some((0, 0))).0 == neg(EBADF),
    );
    p.check(
        "pselect6 too",
        p.pselect6(x + 1, stale, Some((0, 0)), None, SIGSET_BYTES as usize)
            .0
            == neg(EBADF),
    );
    p.check(
        "a negative nfds is EINVAL",
        p.select(-1, Sets::default(), Some((0, 0))).0 == neg(EINVAL),
    );
    for fd in [u, l, c, s] {
        p.close(fd);
    }
    crate::scenarios::net::check_allocated_port(p, &addr_u);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/select",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_select,
        Syscall::N_pselect6,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_clock_gettime,
        Syscall::N_close,
    ],
    symbols: &[
        "select",
        "pselect",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "sendto",
        "recvfrom",
        "clock_gettime",
        "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: NORMALIZED_BY_THE_DOOR,
            what: "select refuses a timeval whose microseconds reach a second with EINVAL (c/posix/readiness.c select; on x86_64 sud/readiness.rs sys_select too — on arm64 the syscall vehicle's pselect6 spelling normalizes first, as glibc does) where the kernel normalizes it into seconds (kern_select → poll_select_set_timeout)",
            failure: Failure::Differs(&[
                Difference::field(12, "select", "errno", Observed::Str("EINVAL")),
                Difference::field(12, "select", "fields.r0_ready", Observed::Null),
                Difference::field(12, "select", "fields.w0_ready", Observed::Null),
                Difference::field(12, "select", "ret", Observed::Int(-1)),
                Difference::check(
                    13,
                    "a timeout whose microseconds reach a second is normalized, not refused",
                ),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "MSG_OOB on a connected stream answers EOPNOTSUPP (c/posix/net.c sendto: `patina_stream_flags_supported`), so no urgent byte sets the exception bit",
            failure: Failure::Differs(&[
                Difference::field(42, "sendto", "errno", Observed::Str("EOPNOTSUPP")),
                Difference::field(42, "sendto", "ret", Observed::Int(-1)),
                Difference::check(43, "send an urgent byte"),
                Difference::field(44, "select", "fields.e0_ready", Observed::Bool(false)),
                Difference::field(44, "select", "ret", Observed::Int(0)),
                Difference::check(45, "urgent data sets the exception bit"),
            ]),
        },
    ],
    ..DEFAULTS
};
