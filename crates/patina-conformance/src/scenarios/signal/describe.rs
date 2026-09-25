//! signal/describe — glibc's signal descriptions (string/strsignal.c,
//! signal/psignal.c) in the C locale: `strsignal` names a signal
//! ("User defined signal 1"), numbers the realtime ones from `SIGRTMIN`
//! ("Real-time signal 0" for 34) and reports any other number as
//! "Unknown signal N"; `psignal` writes `"<prefix>: <description>\n"` to
//! standard error, the bare description with an empty prefix and the
//! whole of a long one, and numbers no realtime signal ("Unknown signal
//! 34").
//!
//! A libc-only subject, so the libc vehicle alone.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

unsafe extern "C" {
    fn strsignal(sig: c_int) -> *mut c_char;
    fn psignal(sig: c_int, prefix: *const c_char);
}

/// What `psignal(sig, prefix)` writes to fd 2, captured through a pipe.
fn psignal_output(sig: c_int, prefix: &CStr) -> String {
    let mut fds = [0; 2];
    let mut text = [0u8; 1024];
    // SAFETY: descriptor plumbing on this process's own table; fd 2 is
    // restored before anything else writes to it.
    let len = unsafe {
        assert_eq!(pipe2(fds.as_mut_ptr(), O_CLOEXEC), 0);
        let saved = dup(2);
        assert!(saved >= 0);
        assert_eq!(dup2(fds[1], 2), 2);
        psignal(sig, prefix.as_ptr());
        assert_eq!(dup2(saved, 2), 2);
        close(saved);
        close(fds[1]);
        let len = read(fds[0], text.as_mut_ptr().cast(), text.len());
        close(fds[0]);
        len
    };
    String::from_utf8_lossy(&text[..len.max(0) as usize]).into_owned()
}

pub fn run(p: &Probe) {
    for (sig, expected) in [
        (SIGUSR1, "User defined signal 1"),
        (34, "Real-time signal 0"),
        (65, "Unknown signal 65"),
    ] {
        // SAFETY: strsignal answers a NUL-terminated string.
        let text = unsafe { CStr::from_ptr(strsignal(sig)) }
            .to_string_lossy()
            .into_owned();
        p.rec
            .event("strsignal", 0)
            .arg("sig", sig)
            .field("text", text.as_str())
            .emit();
        p.check(
            &format!("strsignal({sig}) is {expected:?}"),
            text == expected,
        );
    }

    for (prefix, expected) in [
        ("probe", "probe: Segmentation fault\n"),
        ("", "Segmentation fault\n"),
    ] {
        let text = psignal_output(SIGSEGV, &CString::new(prefix).unwrap());
        p.rec
            .event("psignal", 0)
            .arg("prefix", prefix)
            .field("text", text.as_str())
            .emit();
        p.check(&format!("psignal with prefix {prefix:?}"), text == expected);
    }

    // Every number around the signal range, each description compared with
    // the native run's: the named signals, the reserved 32 and 33, the
    // realtime ones (which psignal does not number) and past SIGRTMAX.
    for sig in -1..=66 {
        // SAFETY: strsignal answers a NUL-terminated string.
        let text = unsafe { CStr::from_ptr(strsignal(sig)) }
            .to_string_lossy()
            .into_owned();
        p.rec
            .event("strsignal", 0)
            .arg("sig", sig)
            .field("text", text.as_str())
            .emit();
    }
    // A prefix longer than any fixed line buffer is written whole.
    let long = "p".repeat(600);
    let text = psignal_output(SIGSEGV, &CString::new(long.as_str()).unwrap());
    p.rec
        .event("psignal", 0)
        .arg("prefix_len", long.len() as i64)
        .field("text_len", text.len() as i64)
        .emit();
    p.check(
        "psignal writes a 600-byte prefix whole",
        text == format!("{long}: Segmentation fault\n"),
    );

    for sig in [0, SIGABRT, 32, 34, 64, 65] {
        let text = psignal_output(sig, c"probe");
        p.rec
            .event("psignal", 0)
            .arg("sig", sig)
            .field("text", text.as_str())
            .emit();
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/describe",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_write],
    symbols: &["strsignal", "psignal"],
    ..DEFAULTS
};
