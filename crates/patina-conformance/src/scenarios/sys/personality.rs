//! sys/personality — the execution domain (kernel/exec_domain.c): the
//! query `0xffffffff` answers the persona without changing it (a process
//! starts as `PER_LINUX`, 0); setting one answers the previous persona and
//! the query then answers the new one; a flag such as `UNAME26` (the one
//! persona flag container seccomp profiles let through) is kept as given.
//!
//! The native run must start in the default persona (`Need::DefaultPersona`:
//! no `setarch` launcher), as the virtual kernel's process does.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::Probe;
use patina_dst_syscalls::Syscall;

const QUERY: u32 = 0xffff_ffff;
const PER_LINUX: u32 = 0;
const UNAME26: u32 = 0x0002_0000;

pub fn run(p: &Probe) {
    p.check(
        "the query answers PER_LINUX",
        p.personality(QUERY) == i64::from(PER_LINUX),
    );
    p.check(
        "the query changed nothing",
        p.personality(QUERY) == i64::from(PER_LINUX),
    );
    p.check(
        "setting a persona answers the previous one",
        p.personality(PER_LINUX | UNAME26) == i64::from(PER_LINUX),
    );
    p.check(
        "the query answers the new one, its flag kept",
        p.personality(QUERY) == i64::from(UNAME26),
    );
    p.check(
        "restoring PER_LINUX answers it",
        p.personality(PER_LINUX) == i64::from(UNAME26),
    );
    p.check(
        "and the query is PER_LINUX again",
        p.personality(QUERY) == i64::from(PER_LINUX),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/personality",
    run,
    covers: &[Syscall::N_personality],
    symbols: &["syscall"],
    needs: &[Need::DefaultPersona],
    ..DEFAULTS
};
