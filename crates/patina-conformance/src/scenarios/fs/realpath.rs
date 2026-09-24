//! fs/realpath — glibc's `realpath(3)` (glibc stdlib/canonicalize.c): the
//! canonical absolute name of an existing entry, with `.`, `..`, repeated
//! and trailing slashes gone and every symlink resolved (relative and
//! absolute targets alike); a relative name resolves against the working
//! directory, and `..` of the run directory is its parent; the result lands
//! in the caller's buffer or, given none, in a `malloc`ed one. A NULL name
//! is EINVAL (glibc's own refusal), a missing entry ENOENT (a dangling
//! symlink and an empty name too), a path through a file or a trailing
//! slash on one ENOTDIR, a symlink loop ELOOP, a component past NAME_MAX
//! ENAMETOOLONG, a directory without search permission EACCES.
//!
//! The run directory's own canonical name is the host's business (its
//! temporary directory may sit under a symlink), so each answer is recorded
//! relative to it (`<root>/…`, its parent `<root>/..`), and checked to be
//! absolute.
//!
//! libc only: realpath is a library walk with no row of its own.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

/// `realpath(path, buffer or NULL)`: the answer, `<root>`-relative in the
/// event (`root_real` `None`: the call resolves the root itself), raw in the
/// return.
fn realpath_of(p: &Probe, root_real: Option<&str>, path: &str, buffer: bool) -> (i64, String) {
    let c = CString::new(path).expect("no interior NUL");
    let mut storage = vec![0 as c_char; PATH_MAX as usize];
    let destination = if buffer {
        storage.as_mut_ptr()
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: a NUL-terminated path and a PATH_MAX buffer (or NULL: glibc
    // allocates, and the answer is freed below).
    let answer = unsafe { realpath(c.as_ptr(), destination) };
    let (result, resolved) = if answer.is_null() {
        (-i64::from(errno()), String::new())
    } else {
        // SAFETY: realpath answered a NUL-terminated name.
        let text = unsafe { CStr::from_ptr(answer) }
            .to_string_lossy()
            .into_owned();
        if !buffer {
            // SAFETY: glibc's allocation, freed once.
            unsafe { free(answer.cast()) };
        }
        (0, text)
    };
    let shown = match root_real {
        None => "<root>".to_string(),
        Some(root) => match resolved.strip_prefix(root) {
            Some(rest) => format!("<root>{rest}"),
            None if Some(resolved.as_str()) == parent_of(root) => "<root>/..".to_string(),
            None => resolved.clone(),
        },
    };
    let builder = p
        .rec
        .event("realpath", result)
        .arg("path", path)
        .arg("buffer", if buffer { "caller" } else { "NULL" });
    let builder = if result == 0 {
        builder.field("resolved", shown)
    } else {
        builder
    };
    builder.emit();
    (result, resolved)
}

/// The directory an absolute canonical name is in.
fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
}

/// `realpath(NULL, buffer)`.
fn realpath_of_null(p: &Probe) -> i64 {
    let mut storage = vec![0 as c_char; PATH_MAX as usize];
    // SAFETY: a NULL name (glibc refuses it before any call) and a PATH_MAX
    // buffer.
    let answer = unsafe { realpath(std::ptr::null(), storage.as_mut_ptr()) };
    let result = if answer.is_null() {
        -i64::from(errno())
    } else {
        0
    };
    p.rec
        .event("realpath", result)
        .arg("path", "NULL")
        .arg("buffer", "caller")
        .emit();
    result
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.openat(
        AT_FDCWD,
        &format!("{root}/f"),
        O_WRONLY | O_CREAT | O_EXCL,
        0o644,
    );
    p.require("create f", fd >= 0);
    p.close(fd);
    p.check(
        "mkdirat sub",
        p.mkdirat(AT_FDCWD, &format!("{root}/sub"), 0o755) == 0,
    );
    let g = p.openat(
        AT_FDCWD,
        &format!("{root}/sub/g"),
        O_WRONLY | O_CREAT | O_EXCL,
        0o644,
    );
    p.require("create sub/g", g >= 0);
    p.close(g);
    p.check(
        "symlinkat rel -> sub/g",
        p.symlinkat("sub/g", AT_FDCWD, &format!("{root}/rel")) == 0,
    );
    p.check(
        "symlinkat abs -> <root>/sub",
        p.symlinkat(&format!("{root}/sub"), AT_FDCWD, &format!("{root}/abs")) == 0,
    );
    p.check(
        "symlinkat up -> ../f inside sub",
        p.symlinkat("../f", AT_FDCWD, &format!("{root}/sub/up")) == 0,
    );
    p.check(
        "symlinkat dangling -> nowhere",
        p.symlinkat("nowhere", AT_FDCWD, &format!("{root}/dangling")) == 0,
    );
    p.check(
        "symlinkat loop -> loop",
        p.symlinkat("loop", AT_FDCWD, &format!("{root}/loop")) == 0,
    );
    let locked = format!("{root}/locked");
    p.check(
        "mkdirat locked 0600",
        p.mkdirat(AT_FDCWD, &locked, 0o600) == 0,
    );

    let (r, root_real) = realpath_of(p, None, &root, true);
    p.require("realpath of the run directory", r == 0);
    p.check(
        "the run directory's canonical name is absolute",
        root_real.starts_with('/') && !root_real.ends_with('/'),
    );
    let at = |path: &str, buffer: bool| realpath_of(p, Some(&root_real), path, buffer);
    let expect = |rest: &str| format!("{root_real}{rest}");

    p.check(
        "a plain name is itself",
        at(&format!("{root}/f"), true).1 == expect("/f"),
    );
    p.check(
        "without a buffer glibc allocates the answer",
        at(&format!("{root}/f"), false).1 == expect("/f"),
    );
    p.check(
        ". and .. and repeated slashes go",
        at(&format!("{root}/./sub//..//sub/./g"), true).1 == expect("/sub/g"),
    );
    p.check(
        "a trailing slash on a directory goes",
        at(&format!("{root}/sub/"), true).1 == expect("/sub"),
    );
    p.check(
        "a relative symlink resolves against its directory",
        at(&format!("{root}/rel"), true).1 == expect("/sub/g"),
    );
    p.check(
        "an absolute symlink resolves from /",
        at(&format!("{root}/abs/g"), true).1 == expect("/sub/g"),
    );
    p.check(
        "a symlink's .. is its own directory's parent",
        at(&format!("{root}/sub/up"), true).1 == expect("/f"),
    );
    p.check(
        ".. through a symlinked directory is the target's parent",
        at(&format!("{root}/abs/../f"), true).1 == expect("/f"),
    );
    p.check(
        ".. of the run directory is its parent",
        Some(at(&format!("{root}/.."), true).1.as_str()) == parent_of(&root_real),
    );
    p.check("chdir into sub", p.chdir(&format!("{root}/sub")) == 0);
    p.check(
        "a relative name resolves against the working directory",
        at("g", true).1 == expect("/sub/g"),
    );
    p.check(
        "and . is the working directory",
        at(".", false).1 == expect("/sub"),
    );

    p.check(
        "a missing entry is ENOENT",
        at(&format!("{root}/missing"), true).0 == neg(ENOENT),
    );
    p.check(
        "a dangling symlink is ENOENT",
        at(&format!("{root}/dangling"), true).0 == neg(ENOENT),
    );
    p.check("an empty name is ENOENT", at("", true).0 == neg(ENOENT));
    p.check(
        "a path through a file is ENOTDIR",
        at(&format!("{root}/f/x"), true).0 == neg(ENOTDIR),
    );
    p.check(
        "and so is a trailing slash on one",
        at(&format!("{root}/f/"), true).0 == neg(ENOTDIR),
    );
    p.check("a NULL name is EINVAL", realpath_of_null(p) == neg(EINVAL));
    p.check(
        "a symlink loop is ELOOP",
        at(&format!("{root}/loop"), true).0 == neg(ELOOP),
    );
    p.check(
        "a component past NAME_MAX is ENAMETOOLONG",
        at(&format!("{root}/{}", "n".repeat(256)), true).0 == neg(ENAMETOOLONG),
    );
    p.check(
        "a directory without search permission is EACCES",
        at(&format!("{locked}/x"), true).0 == neg(EACCES),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/realpath",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_chdir,
    ],
    symbols: &[
        "realpath",
        "openat",
        "close",
        "mkdirat",
        "symlinkat",
        "chdir",
    ],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
