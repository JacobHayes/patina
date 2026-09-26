//! proc/dl — glibc's dynamic loading interface (dlfcn/): `dlsym`,
//! `dlerror`, `dlopen` and `dlclose`.
//!
//! * `dlsym(RTLD_DEFAULT, name)` answers, for a name the process links, the
//!   very definition the static link bound (`getentropy`, called through the
//!   pointer; `getpid`, whose call answers the process's pid), glibc's own
//!   for a name only glibc defines (`gnu_get_libc_version`), and NULL for a
//!   name nothing defines;
//! * `dlsym(RTLD_NEXT, name)` from the executable answers the next object's
//!   definition (libc's `getpid`, the one the executable links);
//! * after a failed lookup `dlerror` answers a message naming the symbol,
//!   once: the next call answers NULL;
//! * `dlopen(RTLD_NOLOAD)` answers a handle for an object already loaded
//!   (libc), whose `dlsym` finds the definition the global scope finds, and
//!   `dlclose` releases it (0); `dlopen` of a missing object answers NULL and
//!   `dlerror` says it cannot be opened.
//!
//! Under patina the probe's `dlsym` is the shim's `__wrap_dlsym` (the
//! shim-linked build links `--wrap=dlsym`), the registry row this scenario
//! covers. `dlopen` and `dlclose` are `Absent` from the shim, reached through
//! `dlsym`, both lookups recorded before either is needed. libc only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

type Getentropy = unsafe extern "C" fn(*mut c_void, size_t) -> c_int;
type Dlopen = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Dlclose = unsafe extern "C" fn(*mut c_void) -> c_int;

const MISSING: &str = "patina_conformance_no_such_symbol";

/// `dlsym(handle, symbol)` (`shown` names the handle): whether it resolved
/// and whether the answer is `linked`, the definition the static link bound
/// (null when nothing is linked to compare with).
fn lookup(
    p: &Probe,
    handle: *mut c_void,
    shown: &str,
    symbol: &str,
    linked: Option<*const c_void>,
) -> Option<*mut c_void> {
    let name = CString::new(symbol).unwrap();
    // SAFETY: a NUL-terminated name looked up in a valid handle.
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    let same = linked.map(|linked| std::ptr::eq(address.cast_const(), linked));
    p.rec
        .event("dlsym", 0)
        .arg("handle", shown)
        .arg("symbol", symbol)
        .field("resolved", !address.is_null())
        .field("same_as_linked", same)
        .emit();
    (!address.is_null()).then_some(address)
}

/// `address`, which the scenario cannot continue without.
fn required(p: &Probe, symbol: &str, address: Option<*mut c_void>) -> *mut c_void {
    p.require(&format!("glibc's {symbol} resolves"), address.is_some());
    address.unwrap_or(std::ptr::null_mut())
}

/// `dlerror()`: whether it answered a message, and whether that message
/// contains `expected` (the message itself names host paths, so it is not
/// recorded).
fn error(p: &Probe, expected: &str) -> (bool, bool) {
    // SAFETY: dlerror's message is read before the next dl call.
    let message = unsafe { dlerror() };
    let text = (!message.is_null()).then(|| {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    });
    let matches = text.as_deref().is_some_and(|text| text.contains(expected));
    p.rec
        .event("dlerror", 0)
        .arg("expected", expected)
        .field("message", text.is_some())
        .field("matches", matches)
        .emit();
    (text.is_some(), matches)
}

pub fn run(p: &Probe) {
    // ---- dlsym in the global scope ------------------------------------------------
    let linked_entropy = getentropy as unsafe extern "C" fn(*mut c_void, size_t) -> c_int;
    let entropy = lookup(
        p,
        RTLD_DEFAULT,
        "RTLD_DEFAULT",
        "getentropy",
        Some(linked_entropy as *const c_void),
    );
    let r = entropy.map_or(i64::MIN, |address| {
        // SAFETY: a getentropy definition, called with a live 16-byte buffer.
        let getentropy: Getentropy = unsafe { std::mem::transmute(address) };
        let mut buf = [0u8; 16];
        fold_errno(i64::from(unsafe {
            getentropy(buf.as_mut_ptr().cast(), buf.len())
        }))
    });
    p.rec.event("getentropy", 0).field("returned", r).emit();
    p.check(
        "getentropy resolves to the linked definition, which fills its buffer",
        entropy.is_some_and(|address| std::ptr::eq(address, linked_entropy as *mut c_void))
            && r == 0,
    );

    let linked_getpid = getpid as unsafe extern "C" fn() -> pid_t;
    let found = lookup(
        p,
        RTLD_DEFAULT,
        "RTLD_DEFAULT",
        "getpid",
        Some(linked_getpid as *const c_void),
    );
    let own = found.is_some_and(|address| {
        // SAFETY: a getpid definition.
        let resolved: unsafe extern "C" fn() -> pid_t = unsafe { std::mem::transmute(address) };
        unsafe { resolved() == getpid() }
    });
    p.rec
        .event("getpid", 0)
        .field("answers_own_pid", own)
        .emit();
    p.check(
        "getpid resolves to the linked definition, which answers the pid",
        found.is_some_and(|address| std::ptr::eq(address, linked_getpid as *mut c_void)) && own,
    );
    p.check(
        "gnu_get_libc_version resolves",
        lookup(
            p,
            RTLD_DEFAULT,
            "RTLD_DEFAULT",
            "gnu_get_libc_version",
            None,
        )
        .is_some(),
    );
    p.check(
        "a missing name resolves to NULL",
        lookup(p, RTLD_DEFAULT, "RTLD_DEFAULT", MISSING, None).is_none(),
    );
    let next = lookup(
        p,
        RTLD_NEXT,
        "RTLD_NEXT",
        "getpid",
        Some(linked_getpid as *const c_void),
    );
    p.check(
        "RTLD_NEXT finds the next object's getpid",
        next.is_some_and(|address| std::ptr::eq(address, linked_getpid as *mut c_void)),
    );

    // ---- dlerror ------------------------------------------------------------------
    error(p, "");
    p.check("a failed lookup still fails", p.resolve(MISSING).is_none());
    let (message, matches) = error(p, &format!("undefined symbol: {MISSING}"));
    p.check("dlerror names the missing symbol", message && matches);
    p.check("dlerror answers once", !error(p, "").0);

    // ---- dlopen, dlclose -----------------------------------------------------------
    let [dlopen, dlclose] = ["dlopen", "dlclose"].map(|symbol| p.resolve(symbol));

    // SAFETY: glibc's definitions of these prototypes.
    let (dlopen, dlclose): (Dlopen, Dlclose) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Dlopen>(required(p, "dlopen", dlopen)),
            std::mem::transmute::<*mut c_void, Dlclose>(required(p, "dlclose", dlclose)),
        )
    };
    let libc_name = CString::new("libc.so.6").unwrap();
    // SAFETY: a NUL-terminated name; RTLD_NOLOAD loads nothing.
    let handle = unsafe { dlopen(libc_name.as_ptr(), RTLD_NOW | RTLD_NOLOAD) };
    p.rec
        .event("dlopen", 0)
        .arg("file", "libc.so.6")
        .arg("flags", "RTLD_NOW|RTLD_NOLOAD")
        .field("handle", !handle.is_null())
        .emit();
    p.check("a loaded object opens with RTLD_NOLOAD", !handle.is_null());
    let name = CString::new("getpid").unwrap();
    // SAFETY: a live handle (checked above) and a NUL-terminated name.
    let (in_handle, global) = unsafe {
        (
            dlsym(handle, name.as_ptr()),
            dlsym(RTLD_DEFAULT, name.as_ptr()),
        )
    };
    p.rec
        .event("dlsym", 0)
        .arg("handle", "libc.so.6")
        .arg("symbol", "getpid")
        .field("resolved", !in_handle.is_null())
        .field("same_as_global", in_handle == global)
        .emit();
    p.check(
        "the handle finds the global scope's definition",
        !in_handle.is_null() && in_handle == global,
    );
    // SAFETY: the handle dlopen answered.
    let r = i64::from(unsafe { dlclose(handle) });
    p.rec.event("dlclose", r).emit();
    p.check("dlclose releases the handle", r == 0);

    let absent = CString::new("libpatina-conformance-absent.so").unwrap();
    // SAFETY: a NUL-terminated name.
    let handle = unsafe { dlopen(absent.as_ptr(), RTLD_NOW) };
    p.rec
        .event("dlopen", 0)
        .arg("file", "libpatina-conformance-absent.so")
        .arg("flags", "RTLD_NOW")
        .field("handle", !handle.is_null())
        .emit();
    p.check("a missing object does not open", handle.is_null());
    let (message, matches) = error(p, "cannot open shared object file");
    p.check("dlerror says it cannot be opened", message && matches);
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/dl",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_getrandom, Syscall::N_openat],
    symbols: &["__wrap_dlsym", "dlerror", "dlopen", "dlclose"],
    resolves: &["dlopen", "dlclose"],
    gaps: &[
        Gap {
            status: Status::ByDesign,
            vehicles: &[Vehicle::Libc],
            what: "dlsym never answers a host definition: gnu_get_libc_version, glibc's own, resolves to NULL (c/posix/dlsym.c __wrap_dlsym over patina_dlsym_route, which answers only the names the shim defines)",
            failure: Failure::Differs(&[
                Difference::field(6, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::check(7, "gnu_get_libc_version resolves"),
            ]),
        },
        Gap {
            status: Status::ByDesign,
            vehicles: &[Vehicle::Libc],
            what: "the shim defines neither dlopen nor dlclose (registry Absent: loading a host object escapes the runtime, crates/patina-target/ESCAPE-CLASSES.md) and its dlsym answers NULL for them",
            failure: Failure::Differs(&[
                Difference::field(19, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(20, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::ByDesign,
            vehicles: &[Vehicle::Libc],
            what: "with dlopen refused the scenario stops before opening an object",
            failure: Failure::Stops {
                events: 21,
                ending: Ending::Exit(101),
                diagnostic: "proc/dl: cannot continue: glibc's dlopen resolves",
            },
        },
    ],
    ..DEFAULTS
};
