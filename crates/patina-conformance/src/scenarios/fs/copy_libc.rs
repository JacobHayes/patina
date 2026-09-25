//! fs/copy_libc — glibc's `copy_file_range(3)` and `sendfile(3)` wrappers
//! (the libc vehicle of fs/copy spells `syscall(2)` while the shim does not
//! define them):
//!
//! * `copy_file_range` with NULL offsets copies at and advances both
//!   cursors; with offset pointers it reads and advances them and leaves the
//!   cursors alone; past the source's EOF it copies nothing; a flag is
//!   EINVAL, a pipe at either end EINVAL, a write-only source or a directory
//!   EBADF/EISDIR;
//! * `sendfile` copies from a file's cursor to a pipe, or from `*offset`
//!   (written back, the cursor untouched) to a file, short at the input's
//!   EOF and nothing from it; a pipe as input, an `O_APPEND` output and a
//!   negative `*offset` are EINVAL, a write-only input or a closed output
//!   EBADF.
//!
//! libc only, and through `dlsym`: the registry lists both `Absent` (the
//! shim does not define them), so the probe binary cannot import them (the
//! pre-run audit would refuse the whole binary). Under patina `dlsym` finds
//! neither: the shim's `__wrap_dlsym` routes only its entropy names.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

type CopyFileRange =
    unsafe extern "C" fn(c_int, *mut off64_t, c_int, *mut off64_t, size_t, c_uint) -> ssize_t;
type Sendfile = unsafe extern "C" fn(c_int, c_int, *mut off_t, size_t) -> ssize_t;

pub fn run(p: &Probe) {
    let root = p.dir();
    let src_path = format!("{root}/src");
    let dst_path = format!("{root}/dst");
    let src = p.open_or_stop(&src_path, O_RDWR | O_CREAT | O_EXCL);
    p.check("fill src", p.write(src, b"0123456789") == 10);
    p.check("rewind src", p.lseek(src, 0, SEEK_SET) == 0);
    let dst = p.open_or_stop(&dst_path, O_RDWR | O_CREAT | O_EXCL);
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);

    let found = [p.resolve("copy_file_range"), p.resolve("sendfile")];
    p.require(
        "copy_file_range and sendfile resolve",
        found.iter().all(Option::is_some),
    );
    // SAFETY: glibc's definitions, by their documented types.
    let (copy, send) = unsafe {
        (
            std::mem::transmute::<*mut c_void, CopyFileRange>(found[0].unwrap()),
            std::mem::transmute::<*mut c_void, Sendfile>(found[1].unwrap()),
        )
    };
    let copy_range = |fd_in: i32,
                      off_in: Option<i64>,
                      fd_out: i32,
                      off_out: Option<i64>,
                      len: usize,
                      flags: u32| {
        let (mut a, mut b) = (off_in.unwrap_or(0), off_out.unwrap_or(0));
        let pa: *mut off64_t = if off_in.is_some() {
            &mut a
        } else {
            std::ptr::null_mut()
        };
        let pb: *mut off64_t = if off_out.is_some() {
            &mut b
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: offsets are live or NULL.
        let r = fold_errno(unsafe { copy(fd_in, pa, fd_out, pb, len, flags) } as i64);
        let builder = p
            .rec
            .event("copy_file_range", r)
            .arg("fd_in", fd_in)
            .norm("args.fd_in", Norm::Relative("fd"))
            .arg(
                "off_in",
                off_in.map_or("NULL".into(), serde_json::Value::from),
            )
            .arg("fd_out", fd_out)
            .norm("args.fd_out", Norm::Relative("fd"))
            .arg(
                "off_out",
                off_out.map_or("NULL".into(), serde_json::Value::from),
            )
            .arg("len", len)
            .arg("flags", flags);
        let builder = match (off_in, off_out) {
            (Some(_), Some(_)) => builder.field("off_in", a).field("off_out", b),
            _ => builder,
        };
        builder.emit();
        (r, a, b)
    };
    let send_file = |out: i32, fd_in: i32, offset: Option<i64>, count: usize| {
        let mut at = offset.unwrap_or(0);
        let pointer: *mut off_t = if offset.is_some() {
            &mut at
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: the offset is live or NULL.
        let r = fold_errno(unsafe { send(out, fd_in, pointer, count) } as i64);
        let builder = p
            .rec
            .event("sendfile", r)
            .arg("out_fd", out)
            .norm("args.out_fd", Norm::Relative("fd"))
            .arg("in_fd", fd_in)
            .norm("args.in_fd", Norm::Relative("fd"))
            .arg(
                "offset",
                offset.map_or("NULL".into(), serde_json::Value::from),
            )
            .arg("count", count);
        let builder = if offset.is_some() {
            builder.field("offset", at)
        } else {
            builder
        };
        builder.emit();
        (r, at)
    };

    // ---- copy_file_range -------------------------------------------------------
    p.check(
        "NULL offsets copy at both cursors",
        copy_range(src, None, dst, None, 4, 0).0 == 4,
    );
    p.check(
        "and advance them",
        p.lseek(src, 0, SEEK_CUR) == 4 && p.lseek(dst, 0, SEEK_CUR) == 4,
    );
    let (r, a, b) = copy_range(src, Some(6), dst, Some(8), 16, 0);
    p.check(
        "offset pointers are read and advanced, short at the source's EOF",
        r == 4 && (a, b) == (10, 12),
    );
    p.check(
        "and leave the cursors alone",
        p.lseek(src, 0, SEEK_CUR) == 4 && p.lseek(dst, 0, SEEK_CUR) == 4,
    );
    let (n, data) = p.pread64(dst, 16, 0);
    p.check(
        "dst holds both copies",
        n == 12 && data == [&b"0123"[..], &[0; 4], b"6789"].concat(),
    );
    p.check(
        "past the source's EOF nothing is copied",
        copy_range(src, Some(10), dst, Some(0), 4, 0).0 == 0,
    );
    p.check(
        "a flag is EINVAL",
        copy_range(src, Some(0), dst, Some(0), 4, 1).0 == neg(EINVAL),
    );
    let write_only = p.open_or_stop(&src_path, O_WRONLY);
    p.check(
        "a write-only source is EBADF",
        copy_range(write_only, Some(0), dst, Some(0), 4, 0).0 == neg(EBADF),
    );
    let dir = p.open_or_stop(&root, O_RDONLY | O_DIRECTORY);
    p.check(
        "a directory source is EISDIR",
        copy_range(dir, Some(0), dst, Some(0), 4, 0).0 == neg(EISDIR),
    );
    p.check(
        "a pipe source is EINVAL",
        copy_range(rd, None, dst, None, 4, 0).0 == neg(EINVAL),
    );
    p.check(
        "a pipe destination is EINVAL",
        copy_range(src, None, wr, None, 4, 0).0 == neg(EINVAL),
    );

    // ---- sendfile --------------------------------------------------------------
    p.check("rewind src", p.lseek(src, 0, SEEK_SET) == 0);
    p.check(
        "sendfile copies from the input's cursor to a pipe",
        send_file(wr, src, None, 3).0 == 3,
    );
    let (n, data) = p.read(rd, 16);
    p.check("the pipe carries it", n == 3 && data == b"012");
    p.check("and the cursor moved", p.lseek(src, 0, SEEK_CUR) == 3);
    let (r, at) = send_file(dst, src, Some(5), 3);
    p.check(
        "sendfile from an offset to a file writes the offset back",
        r == 3 && at == 8,
    );
    p.check(
        "and leaves the input's cursor alone",
        p.lseek(src, 0, SEEK_CUR) == 3,
    );
    let (n, data) = p.pread64(dst, 3, 4);
    p.check("the file got it at its cursor", n == 3 && data == b"567");
    p.check(
        "a pipe as input is EINVAL",
        send_file(dst, rd, None, 3).0 == neg(EINVAL),
    );
    p.check(
        "a write-only input is EBADF",
        send_file(wr, write_only, Some(0), 3).0 == neg(EBADF),
    );
    p.check(
        "a closed output is EBADF",
        send_file(4000, src, Some(0), 3).0 == neg(EBADF),
    );
    let append = p.open_or_stop(&dst_path, O_WRONLY | O_APPEND);
    p.check(
        "an O_APPEND output is EINVAL",
        send_file(append, src, Some(0), 3).0 == neg(EINVAL),
    );
    p.check(
        "a negative offset is EINVAL",
        send_file(dst, src, Some(-1), 3).0 == neg(EINVAL),
    );
    let (r, at) = send_file(dst, src, Some(8), 16);
    p.check("sendfile is short at the input's EOF", r == 2 && at == 10);
    p.check(
        "and sends nothing from it",
        send_file(dst, src, Some(10), 4).0 == 0,
    );

    for fd in [src, dst, rd, wr, write_only, dir, append] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/copy_libc",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_copy_file_range,
        Syscall::N_sendfile,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_read,
        Syscall::N_lseek,
        Syscall::N_pread64,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "copy_file_range",
        "sendfile",
        "openat",
        "write",
        "read",
        "lseek",
        "pread64",
        "pipe2",
        "close",
    ],
    resolves: &["copy_file_range", "sendfile"],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines neither copy_file_range nor sendfile (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds neither (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the gap lifts only once the shim both defines them and routes them there, or the scenario imports them directly",
            failure: Failure::Differs(&[
                Difference::field(7, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(8, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "with neither resolved the scenario cannot continue",
            failure: Failure::Stops {
                events: 9,
                ending: Ending::Exit(101),
                diagnostic: "fs/copy_libc: cannot continue: copy_file_range and sendfile resolve",
            },
        },
    ],
    ..DEFAULTS
};
