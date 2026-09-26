//! sys/nss — glibc's name-service readers a process calls about the system
//! it runs on (nss/, resolv/): the passwd database by uid and by
//! enumeration, and the resolver's configuration.
//!
//! * `__res_init` (what `res_init` names in resolv.h) rereads the resolver
//!   configuration and answers 0 (its effect, the resolver state's
//!   `RES_INIT`, is read through `__res_state`, which the pre-run audit
//!   refuses, so only the answer is compared);
//! * `getpwuid_r(0)` finds root, `root:x:0:0:root:/root:/bin/bash` as
//!   Ubuntu 24.04 has it, in the caller's own struct with every string in
//!   the caller's buffer (the reentrant contract); a buffer too small for
//!   the entry is ERANGE with no result, and a uid no entry has answers 0
//!   with no result; errno is the answer, 0 on both (`getXXbyYY_r` sets it);
//! * `setpwent`/`getpwent`/`endpwent` enumerate the database from root (its
//!   first entry) past at least one more entry (a fact of the host's
//!   database, which any passwd a model serves must match), end with NULL,
//!   and rewind.
//!
//! The caller's own entry is the host's (its name and home), so the checks
//! use root's. libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::{Value, json};
use std::ffi::CStr;

unsafe extern "C" {
    fn __res_init() -> c_int;
}

fn string(pointer: *const c_char) -> Value {
    if pointer.is_null() {
        return Value::Null;
    }
    // SAFETY: a NUL-terminated passwd field.
    Value::from(
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// A passwd entry's fields, or null.
fn entry(pw: *const passwd) -> Value {
    if pw.is_null() {
        return Value::Null;
    }
    // SAFETY: an entry glibc answered, read before the next lookup.
    let pw = unsafe { &*pw };
    json!({
        "name": string(pw.pw_name),
        "passwd": string(pw.pw_passwd),
        "uid": pw.pw_uid,
        "gid": pw.pw_gid,
        "gecos": string(pw.pw_gecos),
        "dir": string(pw.pw_dir),
        "shell": string(pw.pw_shell),
    })
}

/// `getpwuid_r(uid)` into a `buflen`-byte buffer: its returned error number
/// in the kernel convention, the entry found, and whether the entry is the
/// caller's own struct with every string inside the caller's buffer (the
/// reentrant contract; null without an entry), and the errno it leaves (EDOM
/// before the call).
fn by_uid(p: &Probe, uid: uid_t, buflen: usize) -> (i64, Value, Option<bool>, i32) {
    // SAFETY: all-zero is a valid out-parameter.
    let mut pw: passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; buflen];
    let mut result: *mut passwd = std::ptr::null_mut();
    // SAFETY: the calling thread's errno slot.
    unsafe { *__errno_location() = EDOM };
    // SAFETY: live out-parameters and a buffer of `buflen` bytes.
    let r = -i64::from(unsafe { getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buflen, &mut result) });
    let errno = crate::vehicle::errno();
    let found = entry(result);
    let owned = (!result.is_null()).then(|| {
        let range = buf.as_ptr_range();
        let inside = |field: *const c_char| range.contains(&field);
        std::ptr::eq(result, &raw const pw)
            && [
                pw.pw_name,
                pw.pw_passwd,
                pw.pw_gecos,
                pw.pw_dir,
                pw.pw_shell,
            ]
            .into_iter()
            .all(|field| inside(field))
    });
    p.rec
        .event("getpwuid_r", r)
        .arg("uid", uid)
        .arg("buflen", buflen)
        .field("entry", found.clone())
        .field("in_callers_storage", owned)
        .field(
            "errno",
            (errno != 0).then(|| crate::vehicle::errno_name(errno)),
        )
        .emit();
    (r, found, owned, errno)
}

/// Root's entry as Ubuntu 24.04's passwd has it.
fn is_root(found: &Value) -> bool {
    found["name"] == "root"
        && found["passwd"] == "x"
        && found["uid"] == 0
        && found["gid"] == 0
        && found["gecos"] == "root"
        && found["dir"] == "/root"
        && found["shell"] == "/bin/bash"
}

pub fn run(p: &Probe) {
    // SAFETY: no argument; glibc rereads its resolver configuration.
    let r = fold_errno(i64::from(unsafe { __res_init() }));
    p.rec.event("__res_init", r).emit();
    p.check("__res_init answers 0", r == 0);

    let (r, root, owned, found_errno) = by_uid(p, 0, 1024);
    p.check("uid 0 is root", r == 0 && is_root(&root));
    p.check(
        "the entry is the caller's struct, its strings in the caller's buffer",
        owned == Some(true),
    );
    let (r, small, _, _) = by_uid(p, 0, 4);
    p.check(
        "a buffer too small for the entry is ERANGE",
        r == -i64::from(ERANGE) && small.is_null(),
    );
    let (r, none, _, missing_errno) = by_uid(p, 4_000_000_000, 1024);
    p.check(
        "a uid no entry has answers 0 and no entry",
        r == 0 && none.is_null(),
    );
    p.check(
        "errno is the answer, 0, found or not",
        found_errno == 0 && missing_errno == 0,
    );

    // SAFETY: the enumeration, one thread.
    let (first, rest, after_end, rewound) = unsafe {
        setpwent();
        let first = entry(getpwent());
        let mut rest = 0;
        while !getpwent().is_null() {
            rest += 1;
        }
        let after_end = entry(getpwent());
        setpwent();
        let rewound = entry(getpwent());
        endpwent();
        (first, rest, after_end, rewound)
    };
    p.rec
        .event("getpwent", 0)
        .field("first", first.clone())
        .field("after_end", after_end.clone())
        .field("rewound", rewound.clone())
        .emit();
    p.check("enumeration starts at root", is_root(&first));
    p.check("root is not the only entry", rest > 0);
    p.check("past the end is NULL", after_end.is_null());
    p.check("setpwent rewinds to root", is_root(&rewound));
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/nss",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_openat, Syscall::N_read, Syscall::N_close],
    symbols: &[
        "__res_init",
        "getpwuid_r",
        "setpwent",
        "getpwent",
        "endpwent",
    ],
    ..DEFAULTS
};
