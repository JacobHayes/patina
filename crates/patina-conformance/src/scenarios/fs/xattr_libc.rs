//! fs/xattr_libc — glibc's extended-attribute wrappers `setxattr`,
//! `getxattr`, `listxattr`, `removexattr` and `fgetxattr` (the libc vehicle
//! of fs/xattr spells `syscall(2)` while the shim does not define them):
//! a value round-trips by path and by descriptor, a zero size asks for the
//! length, a short buffer is ERANGE, a missing name ENODATA,
//! `XATTR_CREATE` on an existing name EEXIST; the listing names every
//! attribute; a removed name is ENODATA to remove again; a name without a
//! namespace is EOPNOTSUPP, `trusted.*` without CAP_SYS_ADMIN EPERM to set;
//! a missing path is ENOENT and a closed descriptor EBADF. Needs `user.*`
//! attributes on the run directory's filesystem and an unprivileged caller.
//!
//! libc only, and through `dlsym`: the registry lists all five `Absent` (the
//! shim does not define them), so the probe binary cannot import them (the
//! pre-run audit would refuse the whole binary). Under patina `dlsym` finds
//! none: the shim's `__wrap_dlsym` routes only its entropy names.
//!
//! glibc's other wrappers — the by-link `lgetxattr`, `lsetxattr`,
//! `llistxattr`, `lremovexattr` and the by-descriptor `fsetxattr`,
//! `flistxattr`, `fremovexattr` — have no registry row yet, so no scenario
//! can name them; fs/xattr covers their rows on the syscall route.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

type Set =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_void, size_t, c_int) -> c_int;
type Get = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, size_t) -> ssize_t;
type FGet = unsafe extern "C" fn(c_int, *const c_char, *mut c_void, size_t) -> ssize_t;
type List = unsafe extern "C" fn(*const c_char, *mut c_char, size_t) -> ssize_t;
type Remove = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;

const SYMBOLS: [&str; 5] = [
    "setxattr",
    "getxattr",
    "fgetxattr",
    "listxattr",
    "removexattr",
];

fn cstr(text: &str) -> CString {
    CString::new(text).expect("no interior NUL")
}

/// An event for a read of a value: the bytes it answered, if any.
fn value_event(
    p: &Probe,
    op: &str,
    target: (&str, serde_json::Value),
    name: &str,
    size: usize,
    r: i64,
    buf: &[u8],
) {
    let builder = p.rec.event(op, r).arg(target.0, target.1);
    let builder = if target.0 == "fd" {
        builder.norm("args.fd", Norm::Relative("fd"))
    } else {
        builder
    };
    let builder = builder.arg("name", name).arg("size", size);
    let builder = if r > 0 && size > 0 {
        builder.field(
            "value",
            String::from_utf8_lossy(&buf[..r as usize]).into_owned(),
        )
    } else {
        builder
    };
    builder.emit();
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);

    let found: Vec<_> = SYMBOLS.iter().map(|symbol| p.resolve(symbol)).collect();
    p.require(
        "the xattr symbols resolve",
        found.iter().all(Option::is_some),
    );
    // SAFETY: glibc's definitions, by their documented types.
    let (set, get, fget, list, remove) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Set>(found[0].unwrap()),
            std::mem::transmute::<*mut c_void, Get>(found[1].unwrap()),
            std::mem::transmute::<*mut c_void, FGet>(found[2].unwrap()),
            std::mem::transmute::<*mut c_void, List>(found[3].unwrap()),
            std::mem::transmute::<*mut c_void, Remove>(found[4].unwrap()),
        )
    };
    let setxattr = |path: &str, name: &str, value: &[u8], flags: i32| {
        let (c_path, c_name) = (cstr(path), cstr(name));
        // SAFETY: NUL-terminated strings and a live value of its length.
        let r = fold_errno(
            unsafe {
                set(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    flags,
                )
            }
            .into(),
        );
        p.rec
            .event("setxattr", r)
            .arg("path", path)
            .arg("name", name)
            .arg("size", value.len())
            .arg("flags", flags)
            .emit();
        r
    };
    let getxattr = |path: &str, name: &str, size: usize| {
        let (c_path, c_name) = (cstr(path), cstr(name));
        let mut buf = vec![0u8; size.max(1)];
        let pointer = if size == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: NUL-terminated strings and a buffer of `size` (or NULL).
        let r = fold_errno(unsafe { get(c_path.as_ptr(), c_name.as_ptr(), pointer, size) } as i64);
        value_event(p, "getxattr", ("path", path.into()), name, size, r, &buf);
        let len = (r.max(0) as usize).min(size);
        (r, buf[..len].to_vec())
    };
    let fgetxattr = |fd: i32, name: &str, size: usize| {
        let c_name = cstr(name);
        let mut buf = vec![0u8; size.max(1)];
        // SAFETY: a NUL-terminated name and a buffer of `size`.
        let r =
            fold_errno(unsafe { fget(fd, c_name.as_ptr(), buf.as_mut_ptr().cast(), size) } as i64);
        value_event(p, "fgetxattr", ("fd", fd.into()), name, size, r, &buf);
        let len = (r.max(0) as usize).min(size);
        (r, buf[..len].to_vec())
    };
    let listxattr = |path: &str, size: usize| {
        let c_path = cstr(path);
        let mut buf = vec![0u8; size.max(1)];
        let pointer = if size == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: a NUL-terminated path and a buffer of `size` (or NULL).
        let r = fold_errno(unsafe { list(c_path.as_ptr(), pointer, size) } as i64);
        let names: Vec<String> = if r > 0 && size > 0 {
            buf[..r as usize]
                .split(|&b| b == 0)
                .filter(|name| !name.is_empty())
                .map(|name| String::from_utf8_lossy(name).into_owned())
                .collect()
        } else {
            Vec::new()
        };
        let mut sorted = names.clone();
        sorted.sort();
        p.rec
            .event("listxattr", r)
            .arg("path", path)
            .arg("size", size)
            .field("names", sorted.clone())
            .emit();
        (r, sorted)
    };
    let removexattr = |path: &str, name: &str| {
        let (c_path, c_name) = (cstr(path), cstr(name));
        // SAFETY: NUL-terminated strings.
        let r = fold_errno(unsafe { remove(c_path.as_ptr(), c_name.as_ptr()) }.into());
        p.rec
            .event("removexattr", r)
            .arg("path", path)
            .arg("name", name)
            .emit();
        r
    };

    let (r, names) = listxattr(&file, 256);
    p.check("a fresh file lists nothing", r == 0 && names.is_empty());
    p.check("setxattr user.a", setxattr(&file, "user.a", b"v1", 0) == 0);
    p.check(
        "setxattr user.b",
        setxattr(&file, "user.b", b"value", 0) == 0,
    );
    let (r, value) = getxattr(&file, "user.a", 64);
    p.check("getxattr reads the value", r == 2 && value == b"v1");
    p.check(
        "a zero size asks for the length",
        getxattr(&file, "user.b", 0).0 == 5,
    );
    p.check(
        "a buffer shorter than the value is ERANGE",
        getxattr(&file, "user.b", 2).0 == neg(ERANGE),
    );
    p.check(
        "a missing name is ENODATA",
        getxattr(&file, "user.missing", 64).0 == neg(ENODATA),
    );
    p.check(
        "XATTR_CREATE on an existing name is EEXIST",
        setxattr(&file, "user.a", b"v2", XATTR_CREATE) == neg(EEXIST),
    );
    p.check(
        "XATTR_REPLACE replaces it",
        setxattr(&file, "user.a", b"v2", XATTR_REPLACE) == 0,
    );
    let (r, value) = fgetxattr(fd, "user.a", 64);
    p.check("fgetxattr reads the new value", r == 2 && value == b"v2");
    p.check(
        "fgetxattr of a closed number is EBADF",
        fgetxattr(4000, "user.a", 64).0 == neg(EBADF),
    );
    p.check(
        "a zero size asks listxattr for the listing's length",
        listxattr(&file, 0).0 == ("user.a\0".len() + "user.b\0".len()) as i64,
    );
    p.check(
        "a listing buffer too short is ERANGE",
        listxattr(&file, 4).0 == neg(ERANGE),
    );
    let (r, names) = listxattr(&file, 256);
    p.check(
        "listxattr names every attribute",
        r == 14 && names == ["user.a", "user.b"],
    );
    p.check("removexattr user.b", removexattr(&file, "user.b") == 0);
    p.check(
        "a removed name is ENODATA to remove again",
        removexattr(&file, "user.b") == neg(ENODATA),
    );
    p.check(
        "getxattr of a missing path is ENOENT",
        getxattr(&format!("{root}/missing"), "user.a", 64).0 == neg(ENOENT),
    );
    p.check(
        "a name without a namespace is EOPNOTSUPP",
        setxattr(&file, "plain", b"v", 0) == neg(EOPNOTSUPP),
    );
    p.check(
        "trusted.* without CAP_SYS_ADMIN is EPERM to set",
        setxattr(&file, "trusted.x", b"v", 0) == neg(EPERM),
    );
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/xattr_libc",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_setxattr,
        Syscall::N_getxattr,
        Syscall::N_fgetxattr,
        Syscall::N_listxattr,
        Syscall::N_removexattr,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "setxattr",
        "getxattr",
        "fgetxattr",
        "listxattr",
        "removexattr",
        "openat",
        "close",
    ],
    resolves: &[
        "setxattr",
        "getxattr",
        "fgetxattr",
        "listxattr",
        "removexattr",
    ],
    needs: &[Need::UserXattrs, Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines none of setxattr/getxattr/fgetxattr/listxattr/removexattr (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds none (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the gap lifts only once the shim both defines them and routes them there, or the scenario imports them directly",
            failure: Failure::Differs(&[
                Difference::field(1, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(2, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(3, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(4, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(5, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "with none of them resolved the scenario cannot continue",
            failure: Failure::Stops {
                events: 6,
                ending: Ending::Exit(101),
                diagnostic: "fs/xattr_libc: cannot continue: the xattr symbols resolve",
            },
        },
    ],
    ..DEFAULTS
};
