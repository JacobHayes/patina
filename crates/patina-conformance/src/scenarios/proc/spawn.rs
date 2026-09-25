//! proc/spawn — glibc's `posix_spawn` interface (posix/spawn*.c):
//!
//! * `posix_spawnp` searches `PATH` and runs the program; `waitpid` reaps it
//!   with its exit status;
//! * with file actions (`adddup2` onto standard output, `addchdir_np` into
//!   the run directory) and attributes (`setpgroup` 0 under
//!   `POSIX_SPAWN_SETPGROUP`; `setsigdefault`, whose effect is not observed)
//!   the child prints its physical working directory onto a pipe and leads
//!   its own process group; the init, set and destroy calls answer 0.
//!
//! The family is a process-lifecycle deny-trap under patina, so the first
//! call, `posix_spawnp`, is the one judged; everything after it is the
//! native oracle alone, kept to one child per shape. The spawning functions
//! return an error number rather than setting errno. `PATH` is
//! `/usr/bin:/bin`. libc only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

unsafe extern "C" {
    static mut environ: *const *mut c_char;
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut posix_spawn_file_actions_t,
        path: *const c_char,
    ) -> c_int;
}

/// Record a call that returns an error number (0 on success).
fn returned(p: &Probe, op: &str, error: c_int) -> bool {
    p.rec.event(op, -i64::from(error)).emit();
    error == 0
}

/// A NULL-terminated argv over `args` (kept alive by the caller).
fn argv(args: &[CString]) -> Vec<*mut c_char> {
    args.iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect()
}

/// `waitpid(pid, 0)`: whether it reaped `pid` exited with `code`.
fn reaped_exiting(p: &Probe, pid: pid_t, code: c_int) -> bool {
    let mut status = 0;
    // SAFETY: a live status word; `pid` is this process's child.
    let r = fold_errno(i64::from(unsafe { waitpid(pid, &mut status, 0) }));
    let reaped = r == i64::from(pid);
    p.rec
        .event("waitpid", if r < 0 { r } else { 0 })
        .field("reaped_the_child", reaped)
        .field("exited", WIFEXITED(status))
        .field("exit_status", WEXITSTATUS(status))
        .emit();
    reaped && WIFEXITED(status) && WEXITSTATUS(status) == code
}

pub fn run(p: &Probe) {
    let root = p.dir();
    // SAFETY: NUL-terminated strings, copied by setenv.
    let r = unsafe { setenv(c"PATH".as_ptr(), c"/usr/bin:/bin".as_ptr(), 1) };
    p.require("set PATH", r == 0);

    // ---- posix_spawnp alone ------------------------------------------------------
    let args = [c"sh", c"-c", c"exit 7"].map(CString::from);
    let child = argv(&args);
    let mut pid: pid_t = 0;
    // SAFETY: NUL-terminated strings, no actions or attributes.
    let spawned = returned(p, "posix_spawnp", unsafe {
        posix_spawnp(
            &mut pid,
            c"sh".as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            child.as_ptr(),
            environ,
        )
    });
    p.check("posix_spawnp finds sh on PATH", spawned && pid > 0);
    p.check("waitpid reaps it exiting 7", reaped_exiting(p, pid, 7));

    // ---- file actions and attributes -----------------------------------------------
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    let dir = CString::new(root.as_str()).unwrap();
    let args = [c"sh", c"-c", c"pwd -P"].map(CString::from);
    let child = argv(&args);
    // SAFETY: the actions and attributes are initialized before use and
    // destroyed once; every string is NUL-terminated and outlives the spawn.
    unsafe {
        let mut actions: posix_spawn_file_actions_t = std::mem::zeroed();
        let mut attributes: posix_spawnattr_t = std::mem::zeroed();
        let mut defaults: sigset_t = std::mem::zeroed();
        sigemptyset(&mut defaults);
        let set = [
            returned(
                p,
                "posix_spawn_file_actions_init",
                posix_spawn_file_actions_init(&mut actions),
            ),
            returned(
                p,
                "posix_spawn_file_actions_adddup2",
                posix_spawn_file_actions_adddup2(&mut actions, wr, 1),
            ),
            returned(
                p,
                "posix_spawn_file_actions_addchdir_np",
                posix_spawn_file_actions_addchdir_np(&mut actions, dir.as_ptr()),
            ),
            returned(
                p,
                "posix_spawnattr_init",
                posix_spawnattr_init(&mut attributes),
            ),
            returned(
                p,
                "posix_spawnattr_setflags",
                posix_spawnattr_setflags(&mut attributes, POSIX_SPAWN_SETPGROUP as c_short),
            ),
            returned(
                p,
                "posix_spawnattr_setpgroup",
                posix_spawnattr_setpgroup(&mut attributes, 0),
            ),
            returned(
                p,
                "posix_spawnattr_setsigdefault",
                posix_spawnattr_setsigdefault(&mut attributes, &defaults),
            ),
        ];
        p.check(
            "the actions and attributes are set",
            set.iter().all(|&ok| ok),
        );
        let spawned = returned(
            p,
            "posix_spawnp",
            posix_spawnp(
                &mut pid,
                c"sh".as_ptr(),
                &actions,
                &attributes,
                child.as_ptr(),
                environ,
            ),
        );
        p.check("posix_spawnp runs the child", spawned && pid > 0);
        let destroyed = returned(
            p,
            "posix_spawn_file_actions_destroy",
            posix_spawn_file_actions_destroy(&mut actions),
        ) & returned(
            p,
            "posix_spawnattr_destroy",
            posix_spawnattr_destroy(&mut attributes),
        );
        p.check("the actions and attributes are destroyed", destroyed);
    }
    p.close(wr);
    let output = p.rec.quiet(|| {
        let mut output = Vec::new();
        loop {
            let (n, chunk) = p.read(rd, 256);
            if n <= 0 {
                break output;
            }
            output.extend_from_slice(&chunk);
        }
    });
    p.close(rd);
    let physical = std::fs::canonicalize(&root).map(|path| format!("{}\n", path.display()));
    let in_dir = physical.is_ok_and(|physical| output == physical.into_bytes());
    p.rec
        .event("output", 0)
        .field("pwd_is_the_run_dir", in_dir)
        .emit();
    p.check("the child ran in the run directory, onto the pipe", in_dir);
    let group = p.getpgid(pid);
    p.check(
        "the child leads its own process group",
        group == i64::from(pid),
    );
    p.check("waitpid reaps it exiting 0", reaped_exiting(p, pid, 0));
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/spawn",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_clone3,
        Syscall::N_execve,
        Syscall::N_wait4,
        Syscall::N_getpgid,
        Syscall::N_pipe2,
        Syscall::N_read,
        Syscall::N_close,
    ],
    symbols: &[
        "posix_spawnp",
        "posix_spawn_file_actions_init",
        "posix_spawn_file_actions_adddup2",
        "posix_spawn_file_actions_addchdir_np",
        "posix_spawn_file_actions_destroy",
        "posix_spawnattr_init",
        "posix_spawnattr_setflags",
        "posix_spawnattr_setpgroup",
        "posix_spawnattr_setsigdefault",
        "posix_spawnattr_destroy",
        "waitpid",
        "setenv",
        "pipe2",
        "read",
        "close",
        "syscall",
    ],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "the posix_spawn family is a process-lifecycle deny-trap (c/posix/signal_process.c patina_process_trap; docs/arcs/syscall-conformance.md §7): the first call, posix_spawnp, aborts the run, so the file actions, attributes and waitpid after it are judged natively only",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: process spawn reached under patina: posix_spawnp",
        },
    }],
    ..DEFAULTS
};
