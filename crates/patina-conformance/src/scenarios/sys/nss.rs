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
//!   with no result;
//! * `setpwent`/`getpwent`/`endpwent` enumerate the database from root (its
//!   first entry) past at least one more entry (a fact of the host's
//!   database, which any passwd a model serves must match), end with NULL,
//!   and rewind.
//!
//! The caller's own entry is the host's (its name and home), so the checks
//! use root's. The enumeration names are `Absent` from the shim, reached
//! through `dlsym`, every lookup recorded before any is needed. libc only.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::{Value, json};
use std::ffi::CStr;

unsafe extern "C" {
    fn __res_init() -> c_int;
}

type Enumerate = unsafe extern "C" fn();
type Getpwent = unsafe extern "C" fn() -> *mut passwd;

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
/// in the kernel convention (it sets no errno), the entry found, and whether
/// the entry is the caller's own struct with every string inside the
/// caller's buffer (the reentrant contract; null without an entry).
fn by_uid(p: &Probe, uid: uid_t, buflen: usize) -> (i64, Value, Option<bool>) {
    // SAFETY: all-zero is a valid out-parameter.
    let mut pw: passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; buflen];
    let mut result: *mut passwd = std::ptr::null_mut();
    // SAFETY: live out-parameters and a buffer of `buflen` bytes.
    let r = -i64::from(unsafe { getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buflen, &mut result) });
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
        .emit();
    (r, found, owned)
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

/// Look up each of `symbols` (every lookup recorded), then require them all.
fn resolve_all<const N: usize>(p: &Probe, symbols: [&str; N]) -> [*mut c_void; N] {
    let found = symbols.map(|symbol| p.resolve(symbol));
    for (symbol, address) in symbols.iter().zip(&found) {
        p.require(&format!("glibc's {symbol} resolves"), address.is_some());
    }
    found.map(|address| address.unwrap_or(std::ptr::null_mut()))
}

pub fn run(p: &Probe) {
    // SAFETY: no argument; glibc rereads its resolver configuration.
    let r = fold_errno(i64::from(unsafe { __res_init() }));
    p.rec.event("__res_init", r).emit();
    p.check("__res_init answers 0", r == 0);

    let (r, root, owned) = by_uid(p, 0, 1024);
    p.check("uid 0 is root", r == 0 && is_root(&root));
    p.check(
        "the entry is the caller's struct, its strings in the caller's buffer",
        owned == Some(true),
    );
    let (r, small, _) = by_uid(p, 0, 4);
    p.check(
        "a buffer too small for the entry is ERANGE",
        r == -i64::from(ERANGE) && small.is_null(),
    );
    let (r, none, _) = by_uid(p, 4_000_000_000, 1024);
    p.check(
        "a uid no entry has answers 0 and no entry",
        r == 0 && none.is_null(),
    );

    let [setpwent, getpwent, endpwent] = resolve_all(p, ["setpwent", "getpwent", "endpwent"]);
    // SAFETY: glibc's definitions of these prototypes.
    let (setpwent, getpwent, endpwent): (Enumerate, Getpwent, Enumerate) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Enumerate>(setpwent),
            std::mem::transmute::<*mut c_void, Getpwent>(getpwent),
            std::mem::transmute::<*mut c_void, Enumerate>(endpwent),
        )
    };
    // SAFETY: glibc's enumeration, one thread.
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
    resolves: &["setpwent", "getpwent", "endpwent"],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: &[Vehicle::Libc],
            what: "__res_init answers ENOSYS (c/posix/sched_identity.c): the virtual system has no resolver configuration to reread",
            failure: Failure::Differs(&[
                Difference::field(0, "__res_init", "ret", Observed::Int(-1)),
                Difference::field(0, "__res_init", "errno", Observed::Str("ENOSYS")),
                Difference::check(1, "__res_init answers 0"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[Vehicle::Libc],
            what: "getpwuid_r answers no such user for every uid, whatever the buffer (c/posix/sched_identity.c getpwuid_r): the virtual system has no passwd database, so root is not found and a small buffer is not ERANGE",
            failure: Failure::Differs(&[
                Difference::field(2, "getpwuid_r", "fields.entry", Observed::Null),
                Difference::field(2, "getpwuid_r", "fields.in_callers_storage", Observed::Null),
                Difference::check(3, "uid 0 is root"),
                Difference::check(
                    4,
                    "the entry is the caller's struct, its strings in the caller's buffer",
                ),
                Difference::field(5, "getpwuid_r", "ret", Observed::Int(0)),
                Difference::field(5, "getpwuid_r", "errno", Observed::Null),
                Difference::check(6, "a buffer too small for the entry is ERANGE"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines none of setpwent, getpwent and endpwent (registry Absent), and its dlsym answers NULL for a name it does not route (c/posix/dlsym.c patina_dlsym_route): every lookup fails",
            failure: Failure::Differs(&[
                Difference::field(9, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(10, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(11, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[Vehicle::Libc],
            what: "with none of glibc's enumeration reachable, the scenario cannot call it",
            failure: Failure::Stops {
                events: 12,
                ending: Ending::Exit(101),
                diagnostic: "sys/nss: cannot continue: glibc's setpwent resolves",
            },
        },
    ],
    ..DEFAULTS
};
