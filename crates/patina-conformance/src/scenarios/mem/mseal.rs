//! mem/mseal — `mseal` (462, first in Linux 6.10) is past the virtual ABI
//! level (the registry row is `Absent`): it answers ENOSYS through every
//! vehicle, whatever it is asked to seal, exactly as a kernel of the
//! declared level does. Natively the host kernel must lack it too: on a
//! kernel that implements it the scenario is not run (`asserts_absent`).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let page = page_size();
    let (r, a) = p.mmap(
        "a",
        &At::null(),
        page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map a page", r >= 0);
    let a = a.unwrap();
    p.check(
        "sealing a mapping is ENOSYS",
        p.mseal(&a.at(0), page, 0) == neg(ENOSYS),
    );
    // The number is judged before its arguments: a kernel that implements
    // it would answer EINVAL here.
    p.check(
        "ENOSYS regardless of the arguments",
        p.mseal(&a.at(1), page, 1) == neg(ENOSYS),
    );
    p.check(
        "the page is still unmappable",
        p.munmap(&a.at(0), page) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mseal",
    run,
    asserts_absent: &[Syscall::N_mseal],
    symbols: &["syscall", "mmap", "munmap"],
    ..DEFAULTS
};
