//! entropy/getrandom — getrandom: lengths, the flag vocabulary, and that two
//! draws differ (the bytes themselves are never recorded).

use crate::catalog::{Arc, DEFAULTS, DISPATCHER, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
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
}

pub const SCENARIO: Scenario = Scenario {
    name: "entropy/getrandom",
    run,
    covers: &[Syscall::N_getrandom],
    symbols: &["getrandom"],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: DISPATCHER,
        what: "the dispatcher's getrandom row ignores flags (sud.rs sys_getrandom), so an unknown flag fills the buffer instead of EINVAL; the C getrandom validates against PATINA_GRND_KNOWN (patina_posix.c getrandom)",
        failure: Failure::Differs(&[
            Difference::field(12, "getrandom", "errno", Observed::Null),
            Difference::field(12, "getrandom", "fields.nonzero", Observed::Bool(true)),
            Difference::field(12, "getrandom", "ret", Observed::Int(16)),
            Difference::check(13, "an unknown flag is EINVAL"),
        ]),
    }],
    ..DEFAULTS
};
