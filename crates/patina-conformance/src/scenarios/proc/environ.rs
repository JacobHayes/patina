//! proc/environ — glibc's environment (stdlib/setenv.c, stdlib/getenv.c,
//! stdlib/putenv.c), starting from an emptied one:
//!
//! * `clearenv` drops the array: `environ` is NULL after it;
//! * `setenv` appends a new name at the end of `environ` (insertion order),
//!   keeps an existing value unless asked to overwrite, takes an empty value,
//!   and refuses an empty name or one holding `=` (EINVAL);
//! * `getenv` answers a pointer into the `environ` entry itself (just past
//!   `name=`), NULL for an unset name;
//! * `unsetenv` removes a name, succeeds for an unset one, and refuses the
//!   names `setenv` refuses;
//! * `putenv` inserts the caller's own string, so a later write through it
//!   changes the environment, and a string without `=` removes that name;
//! * `secure_getenv` answers as `getenv` does in a process whose real and
//!   effective ids agree (the kernel sets no `AT_SECURE`);
//! * the functions work on whatever array `environ` names: after the program
//!   assigns its own, `getenv` answers that array's first entry of a name
//!   and `unsetenv` removes every entry of it.
//!
//! The starting environment is the harness's natively and the run's `--env`
//! map under patina, so the scenario clears it first. libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::ffi::{CStr, CString};

unsafe extern "C" {
    static mut environ: *const *const c_char;
    fn secure_getenv(name: *const c_char) -> *mut c_char;
}

/// The `environ` array as its entries, or `None` when the pointer is NULL.
fn entries() -> Option<Vec<String>> {
    // SAFETY: the process's environment array, NULL-terminated when non-NULL;
    // nothing else mutates it while the scenario runs (one thread).
    unsafe {
        let array = environ;
        if array.is_null() {
            return None;
        }
        let mut entries = Vec::new();
        let mut at = array;
        while !(*at).is_null() {
            entries.push(CStr::from_ptr(*at).to_string_lossy().into_owned());
            at = at.add(1);
        }
        Some(entries)
    }
}

/// Whether `pointer` is the value of one of `environ`'s entries: the entry's
/// own bytes just past `name=`.
fn aliases_environ(name: &str, pointer: *const c_char) -> bool {
    // SAFETY: as in `entries`.
    unsafe {
        let array = environ;
        if array.is_null() || pointer.is_null() {
            return false;
        }
        let mut at = array;
        while !(*at).is_null() {
            let entry = CStr::from_ptr(*at).to_bytes();
            if entry.len() > name.len()
                && entry.starts_with(name.as_bytes())
                && entry[name.len()] == b'='
            {
                return (*at).add(name.len() + 1) == pointer;
            }
            at = at.add(1);
        }
        false
    }
}

fn text(pointer: *const c_char) -> Option<String> {
    // SAFETY: a NUL-terminated value getenv answered, read before any
    // further environment call.
    (!pointer.is_null()).then(|| {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    })
}

/// `getenv(name)`: its value, and whether the answer is the `environ`
/// entry's own bytes.
fn get_aliasing(p: &Probe, name: &str) -> (Option<String>, bool) {
    let c = CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    let pointer = unsafe { getenv(c.as_ptr()) };
    let (value, aliases) = (text(pointer), aliases_environ(name, pointer));
    p.rec
        .event("getenv", 0)
        .arg("name", name)
        .field("value", value.clone())
        .field("aliases_environ", aliases)
        .emit();
    (value, aliases)
}

/// `getenv(name)`: its value.
fn get(p: &Probe, name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    let value = text(unsafe { getenv(c.as_ptr()) });
    p.rec
        .event("getenv", 0)
        .arg("name", name)
        .field("value", value.clone())
        .emit();
    value
}

/// The `environ` array (NULL recorded as null), recorded.
fn shown(p: &Probe) -> Option<Vec<String>> {
    let entries = entries();
    p.rec
        .event("environ", 0)
        .field("entries", Value::from(entries.clone()))
        .emit();
    entries
}

fn secure_get(p: &Probe, name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    let value = text(unsafe { secure_getenv(c.as_ptr()) });
    p.rec
        .event("secure_getenv", 0)
        .arg("name", name)
        .field("value", value.clone())
        .emit();
    value
}

fn set(p: &Probe, name: &str, value: &str, overwrite: bool) -> i64 {
    let (n, v) = (CString::new(name).unwrap(), CString::new(value).unwrap());
    // SAFETY: NUL-terminated strings, copied by setenv.
    let r = fold_errno(i64::from(unsafe {
        setenv(n.as_ptr(), v.as_ptr(), c_int::from(overwrite))
    }));
    p.rec
        .event("setenv", r)
        .arg("name", name)
        .arg("value", value)
        .arg("overwrite", overwrite)
        .emit();
    r
}

fn unset(p: &Probe, name: &str) -> i64 {
    let n = CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    let r = fold_errno(i64::from(unsafe { unsetenv(n.as_ptr()) }));
    p.rec.event("unsetenv", r).arg("name", name).emit();
    r
}

/// `putenv(string)`, where `string` must outlive the process: the
/// environment keeps the pointer itself.
fn put(p: &Probe, string: *mut c_char) -> i64 {
    // SAFETY: a NUL-terminated string that is never freed.
    let shown = unsafe { CStr::from_ptr(string) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: as above.
    let r = fold_errno(i64::from(unsafe { putenv(string) }));
    p.rec.event("putenv", r).arg("string", shown).emit();
    r
}

fn clear(p: &Probe) -> i64 {
    // SAFETY: no pointer into the environment is held across the call.
    let r = fold_errno(i64::from(unsafe { clearenv() }));
    p.rec.event("clearenv", r).emit();
    r
}

/// A string the environment may keep forever (`putenv` does not copy).
fn leaked(text: &str) -> *mut c_char {
    CString::new(text).unwrap().into_raw()
}

pub fn run(p: &Probe) {
    p.check("clearenv succeeds", clear(p) == 0);
    p.check("clearenv leaves environ NULL", shown(p).is_none());
    p.check("an unset name reads NULL", get(p, "B").is_none());

    // ---- setenv ----------------------------------------------------------------
    p.check("setenv a new name", set(p, "B", "2", false) == 0);
    p.check("setenv a second new name", set(p, "A", "1", false) == 0);
    p.check(
        "new names are appended in insertion order",
        shown(p) == Some(vec!["B=2".into(), "A=1".into()]),
    );
    let (value, aliases) = get_aliasing(p, "A");
    p.check("getenv answers the value", value.as_deref() == Some("1"));
    p.check("the answer is the environ entry's own bytes", aliases);
    let (r, value) = (set(p, "A", "x", false), get(p, "A"));
    p.check(
        "without overwrite an existing value stays",
        r == 0 && value.as_deref() == Some("1"),
    );
    let r = set(p, "A", "3", true);
    p.check(
        "overwrite replaces the value in place",
        r == 0 && shown(p) == Some(vec!["B=2".into(), "A=3".into()]),
    );
    let (r, value) = (set(p, "E", "", true), get(p, "E"));
    p.check(
        "an empty value is a value",
        r == 0 && value.as_deref() == Some(""),
    );
    p.check(
        "setenv with an empty name is EINVAL",
        set(p, "", "v", true) == neg(EINVAL),
    );
    p.check(
        "setenv with a name holding = is EINVAL",
        set(p, "C=D", "v", true) == neg(EINVAL),
    );

    // ---- unsetenv --------------------------------------------------------------
    let (r, value) = (unset(p, "A"), get(p, "A"));
    p.check("unsetenv removes a name", r == 0 && value.is_none());
    p.check("unsetenv of an unset name succeeds", unset(p, "A") == 0);
    p.check(
        "unsetenv with an empty name is EINVAL",
        unset(p, "") == neg(EINVAL),
    );
    p.check(
        "unsetenv with a name holding = is EINVAL",
        unset(p, "X=Y") == neg(EINVAL),
    );

    // ---- putenv ----------------------------------------------------------------
    let string = leaked("K=v");
    let (r, value) = (put(p, string), get(p, "K"));
    p.check(
        "putenv inserts the string",
        r == 0 && value.as_deref() == Some("v"),
    );
    // SAFETY: the leaked three-byte string `K=v`; its value byte is replaced.
    unsafe { *string.add(2) = b'w' as c_char };
    p.check(
        "a write through the string changes the environment",
        get(p, "K").as_deref() == Some("w"),
    );
    let (r, value) = (put(p, leaked("B")), get(p, "B"));
    p.check(
        "putenv of a bare name removes it",
        r == 0 && value.is_none(),
    );
    p.check(
        "the environment holds what putenv left",
        shown(p) == Some(vec!["E=".into(), "K=w".into()]),
    );

    // ---- secure_getenv ---------------------------------------------------------
    let (uid, euid, gid, egid) = (p.getuid(), p.geteuid(), p.getgid(), p.getegid());
    p.check("real and effective ids agree", uid == euid && gid == egid);
    let (set_value, unset_value) = (secure_get(p, "E"), secure_get(p, "A"));
    p.check(
        "secure_getenv answers as getenv does",
        set_value.as_deref() == Some("") && unset_value.is_none(),
    );

    // ---- an environ the program assigns ------------------------------------------
    let own: &'static mut [*const c_char; 4] = Box::leak(Box::new([
        leaked("Z=1"),
        leaked("Y=0"),
        leaked("Z=2"),
        std::ptr::null(),
    ]));
    // SAFETY: a NULL-terminated array of strings that live for the process.
    unsafe { environ = own.as_ptr() };
    let value = get(p, "Z");
    p.check(
        "getenv reads the assigned array's first entry",
        value.as_deref() == Some("1"),
    );
    let (r, entries) = (unset(p, "Z"), shown(p));
    p.check(
        "unsetenv removes every entry of the name from it",
        r == 0 && entries == Some(vec!["Y=0".into()]),
    );

    let (r, entries, value) = (clear(p), shown(p), get(p, "E"));
    p.check(
        "clearenv empties a populated environment",
        r == 0 && entries.is_none() && value.is_none(),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/environ",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_getuid,
        Syscall::N_geteuid,
        Syscall::N_getgid,
        Syscall::N_getegid,
    ],
    symbols: &[
        "getenv",
        "secure_getenv",
        "setenv",
        "unsetenv",
        "clearenv",
        "putenv",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
    ],
    ..DEFAULTS
};
