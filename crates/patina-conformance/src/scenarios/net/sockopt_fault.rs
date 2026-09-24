//! net/sockopt_fault — socket option calls whose lengths or pointers the
//! kernel cannot use (getsockopt(2); net/socket.c `do_sock_getsockopt`,
//! net/core/sock.c `sk_getsockopt`/`sk_setsockopt`):
//!
//! * a NULL `optlen` pointer is `EFAULT` (the length is read first);
//! * an int option from a NULL `optval` is `EFAULT`;
//! * a negative `optlen` is `EINVAL`, before anything is written.
//!
//! Its own scenario, because a door that writes `optlen` bytes of zeroes
//! through the value buffer on a negative length ends the whole run (and a
//! crash loses the captured event stream).

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let t = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a TCP socket", t >= 0);
    p.check(
        "a NULL optlen pointer is EFAULT",
        p.getsockopt_null_len(t, SOL_SOCKET, SO_TYPE) == neg(EFAULT),
    );
    p.check(
        "an int option from a NULL optval is EFAULT",
        p.setsockopt_null(t, SOL_SOCKET, SO_KEEPALIVE, 4) == neg(EFAULT),
    );
    // Last on purpose: a door that zeroes `optlen` bytes of the buffer on a
    // negative length crashes here, after everything above.
    p.check(
        "a negative optlen is EINVAL",
        p.getsockopt_optlen(t, SOL_SOCKET, SO_TYPE, -1) == neg(EINVAL),
    );
    p.close(t);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/sockopt_fault",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_getsockopt,
        Syscall::N_setsockopt,
        Syscall::N_close,
    ],
    symbols: &["socket", "getsockopt", "setsockopt", "close"],
    gaps: &[Gap {
        status: Status::Pending(Arc::NetworkReadiness),
        vehicles: Vehicle::ALL,
        what: "getsockopt zeroes optlen bytes of the value buffer before judging optlen (c/posix/net.c getsockopt, sud/net.rs sys_getsockopt): a negative optlen writes 4 GiB of zeroes, a SIGSEGV instead of EINVAL, and the crash loses the captured event stream (so the NULL-pointer EFAULTs before it are unjudged too)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGSEGV),
            diagnostic: "native_run signal=11",
        },
    }],
    ..DEFAULTS
};
