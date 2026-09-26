//! entropy/getentropy — glibc's `getentropy` (misc/getentropy.c): it fills
//! the whole buffer from `getrandom` or fails, refuses a request longer than
//! 256 bytes with EIO before drawing anything (the buffer is left as it was),
//! passes `getrandom`'s EFAULT through for a NULL buffer (and for a read-only
//! one: entropy/getentropy_fault), and answers 0 for an empty request (a NULL
//! buffer too). Two draws differ; the bytes themselves are never recorded.
//! libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

/// The byte every buffer starts as, so an untouched buffer is recognizable.
const FILL: u8 = 0xAA;

/// `getentropy` into a fresh `len`-byte buffer of [`FILL`] (`null`: a NULL
/// buffer).
fn draw(p: &Probe, len: usize, null: bool) -> (i64, Vec<u8>) {
    let mut buf = vec![FILL; len];
    let pointer = if null {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr().cast()
    };
    // SAFETY: a live buffer of `len` bytes, or NULL on purpose.
    let r = fold_errno(i64::from(unsafe { getentropy(pointer, len) }));
    p.rec
        .event("getentropy", r)
        .arg("len", len)
        .arg("null", null)
        .emit();
    (r, buf)
}

pub fn run(p: &Probe) {
    let (r, first) = draw(p, 16, false);
    p.check("getentropy fills 16 bytes", r == 0);
    let (r, second) = draw(p, 16, false);
    p.check("two draws differ", r == 0 && first != second);
    let (r, full) = draw(p, 256, false);
    p.check(
        "256 bytes is the largest request",
        r == 0 && full.iter().any(|&b| b != 0),
    );
    let (r, over) = draw(p, 257, false);
    p.check("257 bytes is EIO", r == neg(EIO));
    p.check(
        "a refused request draws nothing",
        over.iter().all(|&b| b == FILL),
    );
    p.check("an empty request answers 0", draw(p, 0, false).0 == 0);
    p.check(
        "a NULL buffer is EFAULT",
        draw(p, 16, true).0 == neg(EFAULT),
    );
    p.check(
        "a NULL buffer of zero length answers 0",
        draw(p, 0, true).0 == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "entropy/getentropy",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_getrandom],
    symbols: &["getentropy"],
    ..DEFAULTS
};
