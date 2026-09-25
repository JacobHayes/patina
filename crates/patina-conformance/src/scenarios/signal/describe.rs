//! signal/describe — glibc's signal descriptions (string/strsignal.c,
//! signal/psignal.c) in the C locale: `strsignal` names a signal
//! ("User defined signal 1"), numbers the realtime ones from `SIGRTMIN`
//! ("Real-time signal 0" for 34) and reports any other number as
//! "Unknown signal N"; `psignal` writes `"<prefix>: <description>\n"` to
//! standard error, the bare description with an empty prefix.
//!
//! The shim leaves both undefined (registry `Absent`), so the scenario
//! reaches glibc's definitions through `dlsym`. A libc-only subject, so the
//! libc vehicle alone.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

type Strsignal = unsafe extern "C" fn(c_int) -> *mut c_char;
type Psignal = unsafe extern "C" fn(c_int, *const c_char);

fn resolve(p: &Probe, symbol: &str) -> *mut c_void {
    let address = p.rec.quiet(|| p.resolve(symbol));
    p.require(&format!("glibc's {symbol} resolves"), address.is_some());
    address.unwrap_or(std::ptr::null_mut())
}

/// What `psignal(sig, prefix)` writes to fd 2, captured through a pipe.
fn psignal_output(psignal: Psignal, sig: c_int, prefix: &CStr) -> String {
    let mut fds = [0; 2];
    let mut text = [0u8; 256];
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
    // SAFETY: glibc's definitions of these prototypes.
    let strsignal: Strsignal = unsafe { std::mem::transmute(resolve(p, "strsignal")) };
    let psignal: Psignal = unsafe { std::mem::transmute(resolve(p, "psignal")) };

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
        let text = psignal_output(psignal, SIGSEGV, &CString::new(prefix).unwrap());
        p.rec
            .event("psignal", 0)
            .arg("prefix", prefix)
            .field("text", text.as_str())
            .emit();
        p.check(&format!("psignal with prefix {prefix:?}"), text == expected);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/describe",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_write],
    symbols: &["strsignal", "psignal"],
    resolves: &["strsignal", "psignal"],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: &[Vehicle::Libc],
        what: "the shim defines neither strsignal nor psignal (registry Absent), and its dlsym answers NULL for a name it does not route (c/posix/dlsym.c patina_dlsym_route), so the scenario cannot reach glibc's definitions",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Exit(101),
            diagnostic: "signal/describe: cannot continue: glibc's strsignal resolves",
        },
    }],
    ..DEFAULTS
};
