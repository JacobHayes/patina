//! entropy/getrandom — getrandom: lengths, the flag vocabulary, that two draws
//! differ (the bytes themselves are never recorded), and the buffer: NULL is
//! EFAULT unless the length is 0 (drivers/char/random.c copies nothing then).
//! glibc 2.39's `getrandom` is the system call, so the libc vehicle asks the
//! kernel too; from 2.41 it fills the buffer from the vDSO in user space,
//! where a NULL buffer is the caller's own SIGSEGV: a host divergence.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let (r, first) = p.getrandom(16, 0);
    p.check("getrandom fills 16 bytes", r == 16 && first.len() == 16);
    let (r, second) = p.getrandom(16, 0);
    p.check("two draws differ", r == 16 && first != second);
    let (r, _) = p.getrandom(0, 0);
    p.check("a zero-length draw returns 0", r == 0);
    let (r, _) = p.getrandom(16, GRND_NONBLOCK);
    p.check("GRND_NONBLOCK on a seeded pool fills", r == 16);
    let (r, _) = p.getrandom(16, GRND_RANDOM);
    p.check("GRND_RANDOM fills", r == 16);
    let (r, _) = p.getrandom(16, GRND_RANDOM | GRND_NONBLOCK);
    p.check("GRND_RANDOM|GRND_NONBLOCK fills", r == 16);
    let (r, _) = p.getrandom(16, 0x100);
    p.check("an unknown flag is EINVAL", r == neg(EINVAL));
    let (r, large) = p.getrandom(4096, 0);
    p.check(
        "a large draw is served in full",
        r == 4096 && large.iter().any(|&b| b != 0),
    );
    p.check(
        "a NULL buffer is EFAULT",
        p.getrandom_null(16, 0) == neg(EFAULT),
    );
    p.check(
        "a NULL buffer of zero length is 0",
        p.getrandom_null(0, 0) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "entropy/getrandom",
    run,
    covers: &[Syscall::N_getrandom],
    symbols: &["getrandom"],
    ..DEFAULTS
};
