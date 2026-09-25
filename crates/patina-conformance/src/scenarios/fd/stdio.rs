//! fd/stdio — glibc's standard streams (libio) over a pipe, each stream's
//! descriptor redirected for the length of one session:
//!
//! * `stdout` onto a pipe is fully buffered: `printf` and the other writers
//!   leave the pipe empty (`FIONREAD` 0) until `fflush(stdout)` or
//!   `fflush(NULL)` writes the whole buffer; the bytes then arrive in order;
//! * the writers' answers: `printf`/`fprintf`/`vfprintf` the byte count,
//!   `puts` the count with its newline, `fputs` 1, `putchar`/`fputc` the
//!   byte, `fwrite` the whole items (0 for a zero size);
//! * `stderr` is unbuffered: every write reaches the pipe at once;
//! * with `stdout`'s descriptor closed the buffered writers still succeed and
//!   the error surfaces at `fflush` (EOF, EBADF).
//!
//! Events are recorded after each session, once the descriptor is restored
//! (the recorder writes to fd 1). `vfprintf` takes a `va_list` built by hand
//! from the platform ABI's layout (every argument on the overflow area).
//! libc only.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

unsafe extern "C" {
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn vfprintf(stream: *mut FILE, format: *const c_char, arguments: VaList) -> c_int;
}

/// The x86-64 SysV `va_list` element: `gp_offset` 48 (six general registers
/// consumed) and `fp_offset` 176 (48 plus eight 16-byte vector registers)
/// mark the register save area exhausted, so every `va_arg` reads
/// `overflow_arg_area`, eight bytes per argument.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct VaListTag {
    gp_offset: u32,
    fp_offset: u32,
    overflow_arg_area: *mut c_void,
    reg_save_area: *mut c_void,
}

#[cfg(target_arch = "x86_64")]
type VaList = *mut VaListTag;

/// The AAPCS64 `va_list`, passed by value: non-negative register offsets
/// send every `va_arg` to `stack`, eight bytes per argument.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct VaList {
    stack: *mut c_void,
    gr_top: *mut c_void,
    vr_top: *mut c_void,
    gr_offs: i32,
    vr_offs: i32,
}

/// `vfprintf(stream, format, …)` with integer and pointer `arguments`.
fn vfprintf_with(stream: *mut FILE, format: &std::ffi::CStr, arguments: &mut [u64]) -> c_int {
    #[cfg(target_arch = "x86_64")]
    {
        let mut tag = VaListTag {
            gp_offset: 48,
            fp_offset: 176,
            overflow_arg_area: arguments.as_mut_ptr().cast(),
            reg_save_area: std::ptr::null_mut(),
        };
        // SAFETY: the list names `arguments.len()` eight-byte arguments the
        // format consumes exactly.
        unsafe { vfprintf(stream, format.as_ptr(), &mut tag) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let list = VaList {
            stack: arguments.as_mut_ptr().cast(),
            gr_top: std::ptr::null_mut(),
            vr_top: std::ptr::null_mut(),
            gr_offs: 0,
            vr_offs: 0,
        };
        // SAFETY: as above.
        unsafe { vfprintf(stream, format.as_ptr(), list) }
    }
}

/// One observation made while a descriptor was redirected, recorded later:
/// a writer's return value and, when it answered EOF, the errno it left
/// (cleared before the call, so an EOF that sets none shows null), or a
/// `FIONREAD` count in the kernel convention.
struct Seen {
    op: &'static str,
    kind: Kind,
    arg: Option<(&'static str, &'static str)>,
}

enum Kind {
    Writer {
        returned: i64,
        errno: Option<String>,
    },
    Pending(i64),
}

impl Seen {
    /// The writer's return value, or the pending count.
    fn value(&self) -> i64 {
        match self.kind {
            Kind::Writer { returned, .. } => returned,
            Kind::Pending(count) => count,
        }
    }
}

/// Call a stdio writer and keep its answer.
fn writer(
    op: &'static str,
    arg: Option<(&'static str, &'static str)>,
    call: impl FnOnce() -> i64,
) -> Seen {
    // SAFETY: the calling thread's errno slot.
    unsafe { *__errno_location() = 0 };
    let returned = call();
    let errno = (returned == -1)
        .then(crate::vehicle::errno)
        .filter(|&errno| errno != 0)
        .map(|errno| crate::vehicle::errno_name(errno).to_string());
    Seen {
        op,
        kind: Kind::Writer { returned, errno },
        arg,
    }
}

/// Bytes waiting in the pipe (`FIONREAD`), without reading them.
fn pending(fd: c_int) -> Seen {
    let mut count: c_int = 0;
    // SAFETY: FIONREAD stores one int.
    let r = fold_errno(i64::from(unsafe { ioctl(fd, FIONREAD, &mut count) }));
    Seen {
        op: "FIONREAD",
        kind: Kind::Pending(if r < 0 { r } else { i64::from(count) }),
        arg: None,
    }
}

/// Run `body` with `target` (1 or 2) redirected onto a fresh pipe's write
/// end (`None`: closed instead); answer its observations and everything the
/// pipe received.
fn session(
    target: c_int,
    piped: bool,
    body: impl FnOnce(c_int) -> Vec<Seen>,
) -> (Vec<Seen>, Vec<u8>) {
    let mut fds = [-1; 2];
    // SAFETY: descriptor plumbing on this process's own table; `target` is
    // restored before anything records.
    unsafe {
        let saved = dup(target);
        assert!(saved >= 0);
        if piped {
            assert_eq!(pipe2(fds.as_mut_ptr(), O_CLOEXEC | O_NONBLOCK), 0);
            assert_eq!(dup2(fds[1], target), target);
            close(fds[1]);
        } else {
            close(target);
        }
        let seen = body(fds[0]);
        assert_eq!(dup2(saved, target), target);
        close(saved);
        let mut received = Vec::new();
        if piped {
            let mut chunk = [0u8; 512];
            loop {
                let n = read(fds[0], chunk.as_mut_ptr().cast(), chunk.len());
                if n <= 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n as usize]);
            }
            close(fds[0]);
        }
        (seen, received)
    }
}

fn record(p: &Probe, seen: &[Seen], received: Option<&[u8]>) {
    for Seen { op, kind, arg } in seen {
        let event = match kind {
            Kind::Writer { returned, errno } => p
                .rec
                .event(op, 0)
                .field("returned", *returned)
                .field("errno", errno.clone()),
            Kind::Pending(count) => p.rec.event(op, *count),
        };
        match arg {
            Some((key, value)) => event.arg(key, *value),
            None => event,
        }
        .emit();
    }
    if let Some(received) = received {
        p.rec
            .event("received", received.len() as i64)
            .field("data", String::from_utf8_lossy(received).into_owned())
            .emit();
    }
}

/// The value of the `nth` observation of `op`.
fn of(seen: &[Seen], op: &str, nth: usize) -> i64 {
    seen.iter()
        .filter(|seen| seen.op == op)
        .nth(nth)
        .map_or(i64::MIN, Seen::value)
}

pub fn run(p: &Probe) {
    // ---- stdout: fully buffered onto a pipe --------------------------------------
    let (out, received) = session(1, true, |pipe| {
        // SAFETY: the stream global, NUL-terminated literals, and variadic
        // arguments matching their conversions.
        unsafe {
            let out = stdout;
            let mut arguments = [c"va".as_ptr() as u64, 7, u64::from(b'z')];
            vec![
                writer("printf", Some(("format", "%s=%d\\n")), || {
                    i64::from(printf(c"%s=%d\n".as_ptr(), c"n".as_ptr(), 42))
                }),
                pending(pipe),
                writer("fflush", Some(("stream", "stdout")), || {
                    i64::from(fflush(out))
                }),
                pending(pipe),
                writer("puts", Some(("s", "line")), || {
                    i64::from(puts(c"line".as_ptr()))
                }),
                writer("putchar", Some(("c", "x")), || {
                    i64::from(putchar(c_int::from(b'x')))
                }),
                writer("fputc", Some(("c", "y")), || {
                    i64::from(fputc(c_int::from(b'y'), out))
                }),
                writer("fputs", Some(("s", "abc")), || {
                    i64::from(fputs(c"abc".as_ptr(), out))
                }),
                writer("fwrite", Some(("items", "3 of 2")), || {
                    fwrite(c"hello!".as_ptr().cast(), 2, 3, out) as i64
                }),
                writer("fwrite", Some(("items", "3 of 0")), || {
                    fwrite(c"hello!".as_ptr().cast(), 0, 3, out) as i64
                }),
                writer("fprintf", Some(("format", "[%5.1f|%-3s|%x]")), || {
                    i64::from(fprintf(
                        out,
                        c"[%5.1f|%-3s|%x]".as_ptr(),
                        2.71875f64,
                        c"a".as_ptr(),
                        255,
                    ))
                }),
                writer("vfprintf", Some(("format", "%s-%d-%c")), || {
                    i64::from(vfprintf_with(out, c"%s-%d-%c", &mut arguments))
                }),
                pending(pipe),
                writer("fflush", Some(("stream", "NULL")), || {
                    i64::from(fflush(std::ptr::null_mut()))
                }),
                pending(pipe),
            ]
        }
    });
    record(p, &out, Some(&received));
    p.check("printf answers its byte count", of(&out, "printf", 0) == 5);
    p.check(
        "the buffered output waits in the stream",
        of(&out, "FIONREAD", 0) == 0,
    );
    p.check(
        "fflush(stdout) writes it",
        of(&out, "fflush", 0) == 0 && of(&out, "FIONREAD", 1) == 5,
    );
    p.check(
        "puts answers the count with its newline",
        of(&out, "puts", 0) == 5,
    );
    p.check(
        "putchar answers the byte",
        of(&out, "putchar", 0) == i64::from(b'x'),
    );
    p.check(
        "fputc answers the byte",
        of(&out, "fputc", 0) == i64::from(b'y'),
    );
    p.check("fputs answers 1", of(&out, "fputs", 0) == 1);
    p.check(
        "fwrite answers whole items, 0 for a zero size",
        of(&out, "fwrite", 0) == 3 && of(&out, "fwrite", 1) == 0,
    );
    p.check(
        "fprintf answers its byte count",
        of(&out, "fprintf", 0) == 14,
    );
    p.check(
        "vfprintf answers its byte count",
        of(&out, "vfprintf", 0) == 6,
    );
    p.check(
        "the writers since the flush wait in the stream",
        of(&out, "FIONREAD", 2) == 5,
    );
    p.check(
        "fflush(NULL) writes them",
        of(&out, "fflush", 1) == 0 && of(&out, "FIONREAD", 3) == 41,
    );
    p.check(
        "the pipe received every byte in order",
        received == b"n=42\nline\nxyabchello![  2.7|a  |ff]va-7-z",
    );

    // ---- stderr: unbuffered --------------------------------------------------------
    let (err, received) = session(2, true, |pipe| {
        // SAFETY: as above.
        unsafe {
            let err = stderr;
            vec![
                writer("fprintf", Some(("stream", "stderr")), || {
                    i64::from(fprintf(err, c"e%d".as_ptr(), 1))
                }),
                pending(pipe),
                writer("fputs", Some(("stream", "stderr")), || {
                    i64::from(fputs(c"rr".as_ptr(), err))
                }),
                pending(pipe),
            ]
        }
    });
    record(p, &err, Some(&received));
    p.check(
        "stderr writes at once",
        of(&err, "FIONREAD", 0) == 2 && of(&err, "FIONREAD", 1) == 4 && received == b"e1rr",
    );

    // ---- a closed descriptor: the error surfaces at the flush ------------------------
    let (closed, _) = session(1, false, |_| {
        // SAFETY: as above.
        unsafe {
            let out = stdout;
            vec![
                writer("printf", Some(("format", "x")), || {
                    i64::from(printf(c"x".as_ptr()))
                }),
                writer("fputc", Some(("c", "z")), || {
                    i64::from(fputc(c_int::from(b'z'), out))
                }),
                writer("fflush", Some(("stream", "stdout")), || {
                    i64::from(fflush(out))
                }),
            ]
        }
    });
    record(p, &closed, None);
    p.check(
        "buffered writers succeed on a closed descriptor",
        of(&closed, "printf", 0) == 1 && of(&closed, "fputc", 0) == i64::from(b'z'),
    );
    let flushed = closed.iter().find(|seen| seen.op == "fflush");
    p.check(
        "the flush answers EOF with EBADF",
        matches!(
            flushed.map(|seen| &seen.kind),
            Some(Kind::Writer { returned: -1, errno: Some(errno) }) if errno == "EBADF"
        ),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/stdio",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_write,
        Syscall::N_pipe2,
        Syscall::N_dup,
        Syscall::N_dup3,
        Syscall::N_ioctl,
        Syscall::N_read,
        Syscall::N_close,
    ],
    symbols: &[
        "printf", "puts", "putchar", "fputc", "fputs", "fwrite", "fprintf", "vfprintf", "fflush",
        "stdout", "stderr", "pipe2", "dup", "dup2", "ioctl", "read", "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the standard streams are unbuffered: every writer goes straight to the descriptor through patina_write and fflush does nothing (c/posix/stdio.c), where glibc fully buffers stdout onto a pipe until a flush",
            failure: Failure::Differs(&[
                Difference::field(1, "FIONREAD", "ret", Observed::Int(5)),
                Difference::field(12, "FIONREAD", "ret", Observed::Int(41)),
                Difference::check(17, "the buffered output waits in the stream"),
                Difference::check(26, "the writers since the flush wait in the stream"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "with the streams unbuffered a write error surfaces at the writer, not at the flush: fputc answers EOF (setting no errno) on a closed descriptor and fflush answers 0 (c/posix/stdio.c fputc, fflush), where glibc's fputc buffers the byte and its fflush answers EOF with EBADF",
            failure: Failure::Differs(&[
                Difference::field(36, "fputc", "fields.returned", Observed::Int(-1)),
                Difference::field(37, "fflush", "fields.returned", Observed::Int(0)),
                Difference::field(37, "fflush", "fields.errno", Observed::Null),
                Difference::check(38, "buffered writers succeed on a closed descriptor"),
                Difference::check(39, "the flush answers EOF with EBADF"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "puts and fputs answer 0 on success (c/posix/stdio.c), where glibc's puts answers the bytes written with the newline and its fputs 1 (libio/ioputs.c, libio/iofputs.c); POSIX asks only for a non-negative number",
            failure: Failure::Differs(&[
                Difference::field(4, "puts", "fields.returned", Observed::Int(0)),
                Difference::field(7, "fputs", "fields.returned", Observed::Int(0)),
                Difference::check(19, "puts answers the count with its newline"),
                Difference::check(22, "fputs answers 1"),
                Difference::field(31, "fputs", "fields.returned", Observed::Int(0)),
            ]),
        },
    ],
    ..DEFAULTS
};
