//! entropy/getentropy_fault — glibc's `getentropy` into a buffer the caller
//! cannot write (a read-only page): `getrandom` answers EFAULT and
//! `getentropy` passes it through, writing nothing.
//!
//! Its own scenario, because a door that writes the buffer itself ends the
//! whole run (and a crash loses the captured event stream). libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    // SAFETY: a fresh private anonymous page, read-only, unmapped below.
    let page = unsafe {
        mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    p.require("map a read-only page", page != MAP_FAILED);
    // SAFETY: the page is mapped; getentropy must not write it.
    let r = fold_errno(i64::from(unsafe { getentropy(page, 16) }));
    p.rec
        .event("getentropy", r)
        .arg("len", 16)
        .arg("buffer", "read-only page")
        .emit();
    p.check("a read-only buffer is EFAULT", r == neg(EFAULT));
    // SAFETY: the page mapped above.
    unsafe { munmap(page, 4096) };
}

pub const SCENARIO: Scenario = Scenario {
    name: "entropy/getentropy_fault",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_getrandom, Syscall::N_mmap, Syscall::N_munmap],
    symbols: &["getentropy", "mmap", "munmap"],
    ..DEFAULTS
};
