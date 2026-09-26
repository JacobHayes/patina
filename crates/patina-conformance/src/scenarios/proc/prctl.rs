//! proc/prctl — the process-local prctl options (man 2 prctl): PR_SET_NAME
//! truncation to 15 bytes, PR_SET/GET_PDEATHSIG (a signal number, EINVAL past
//! SIGRTMAX), PR_SET/GET_DUMPABLE (only 0 or 1 settable; 2 is EINVAL),
//! PR_SET_NO_NEW_PRIVS (only 1, with zero trailing arguments; sticky; per
//! thread, so a thread created after it inherits it and one that already
//! existed does not),
//! PR_SET/GET_TIMERSLACK (0 restores the 50 µs default), and EINVAL (not
//! ENOSYS) for an unknown option.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use crate::vehicle::errno_name;
use libc::*;
use std::ffi::CStr;

/// A call's second and third arguments: plain values, or a pointer to an
/// `int` the call must write this value through.
enum Arg {
    Values(u64, u64),
    Out(i32),
}
use Arg::{Out, Values};

const NONE: Arg = Values(0, 0);

/// `prctl(option, arg2, arg3, 0, 0)` and its answer, in order: each state
/// change is read back by the rows after it.
const ROWS: &[(c_int, Arg, i64)] = &[
    // A signal number; 0 clears it.
    (PR_SET_PDEATHSIG, Values(SIGTERM as u64, 0), 0),
    (PR_GET_PDEATHSIG, Out(SIGTERM), 0),
    (PR_SET_PDEATHSIG, Values(65, 0), neg(EINVAL)),
    (PR_SET_PDEATHSIG, NONE, 0),
    (PR_GET_PDEATHSIG, Out(0), 0),
    (PR_GET_PDEATHSIG, NONE, neg(EFAULT)),
    // Starts at 1; only 0 or 1 is settable through prctl.
    (PR_GET_DUMPABLE, NONE, 1),
    (PR_SET_DUMPABLE, Values(2, 0), neg(EINVAL)),
    (PR_SET_DUMPABLE, NONE, 0),
    (PR_GET_DUMPABLE, NONE, 0),
    (PR_SET_DUMPABLE, Values(1, 0), 0),
    // Only 1 can be set, with a zero trailing argument, and it sticks.
    (PR_GET_NO_NEW_PRIVS, NONE, 0),
    (PR_SET_NO_NEW_PRIVS, NONE, neg(EINVAL)),
    (PR_SET_NO_NEW_PRIVS, Values(1, 1), neg(EINVAL)),
    (PR_SET_NO_NEW_PRIVS, Values(1, 0), 0),
    (PR_GET_NO_NEW_PRIVS, NONE, 1),
    (PR_SET_NO_NEW_PRIVS, NONE, neg(EINVAL)),
    // Starts at the 50 µs default; 0 restores it.
    (PR_GET_TIMERSLACK, NONE, 50_000),
    (PR_SET_TIMERSLACK, Values(123_456, 0), 0),
    (PR_GET_TIMERSLACK, NONE, 123_456),
    (PR_SET_TIMERSLACK, NONE, 0),
    (PR_GET_TIMERSLACK, NONE, 50_000),
    // An unknown option is EINVAL, not ENOSYS.
    (UNKNOWN_OPTION, NONE, neg(EINVAL)),
];

const UNKNOWN_OPTION: c_int = 0x7fff_ffff;

fn option_name(option: c_int) -> &'static str {
    match option {
        PR_SET_PDEATHSIG => "PR_SET_PDEATHSIG",
        PR_GET_PDEATHSIG => "PR_GET_PDEATHSIG",
        PR_SET_DUMPABLE => "PR_SET_DUMPABLE",
        PR_GET_DUMPABLE => "PR_GET_DUMPABLE",
        PR_SET_NO_NEW_PRIVS => "PR_SET_NO_NEW_PRIVS",
        PR_GET_NO_NEW_PRIVS => "PR_GET_NO_NEW_PRIVS",
        PR_SET_TIMERSLACK => "PR_SET_TIMERSLACK",
        PR_GET_TIMERSLACK => "PR_GET_TIMERSLACK",
        _ => "an unknown option",
    }
}

pub fn run(p: &Probe) {
    let long = b"abcdefghijklmnopQRST\0";
    p.check(
        "PR_SET_NAME accepts a long name",
        p.prctl(PR_SET_NAME, long.as_ptr() as u64, 0, 0, 0) == 0,
    );
    let mut name = [0 as c_char; 16];
    p.check(
        "PR_GET_NAME reads the truncated name",
        p.prctl(PR_GET_NAME, name.as_mut_ptr() as u64, 0, 0, 0) == 0,
    );
    let got = unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes().to_vec();
    p.rec
        .event("prctl_name", 0)
        .field("name", String::from_utf8_lossy(&got).as_ref())
        .emit();
    p.check(
        "PR_SET_NAME truncates to 15 bytes plus NUL",
        got == b"abcdefghijklmno",
    );

    // `no_new_privs` is a task flag (`PFA_NO_NEW_PRIVS`), copied at `clone`:
    // a thread that exists before the rows set it keeps reading 0.
    std::thread::scope(|scope| {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let older = scope.spawn(move || {
            wait.recv()
                .is_ok()
                .then(|| p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0))
        });
        rows(p);
        let newer = scope
            .spawn(|| p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0))
            .join();
        p.check(
            "a thread created after PR_SET_NO_NEW_PRIVS inherits it",
            newer.ok() == Some(1),
        );
        let _ = go.send(());
        p.check(
            "a thread that existed before reads its own, unset",
            older.join().ok().flatten() == Some(0),
        );
    });
}

/// Each of [`ROWS`], in order.
fn rows(p: &Probe) {
    for (option, arg, answer) in ROWS {
        let name = option_name(*option);
        let mut written = -1i32;
        let (a2, a3, call) = match *arg {
            Values(a2, a3) => (a2, a3, format!("{name}({a2}, {a3})")),
            Out(value) => (
                &mut written as *mut i32 as u64,
                0,
                format!("{name}(&v) writes {value} and"),
            ),
        };
        let expected = match *answer {
            answer if answer < 0 => errno_name(-answer as i32),
            answer => answer.to_string(),
        };
        let r = p.prctl(*option, a2, a3, 0, 0);
        p.check(
            &format!("{call} answers {expected}"),
            r == *answer && !matches!(arg, Out(value) if written != *value),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/prctl",
    run,
    covers: &[Syscall::N_prctl],
    symbols: &["prctl"],
    ..DEFAULTS
};
