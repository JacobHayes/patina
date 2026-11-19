//! The process state a run inherits from whoever started it, set to fixed values.
//!
//! Everything a process passes to a child across fork and execve, enumerated from fork(2)
//! ("the child inherits"), execve(2) ("preserved"), credentials(7), capabilities(7),
//! sched(7), prctl(2) (settings documented as inherited) and proc(5) (per-process files a
//! process can write). Each item is either set here, set by the launcher or bwrap, checked
//! (a value that cannot be honoured ends the run as `infra`), not inherited through the
//! launcher's fork and bwrap's exec, or only able to change timing (which is virtual) with
//! the guest's view of it fixed by its row.
//!
//! | item                               | treatment                                                 |
//! |------------------------------------|-----------------------------------------------------------|
//! | open descriptors                   | supervisor closes all but 0-2 and the hidden 3000-3006    |
//! | stdin, stdout, stderr              | sandbox memfds (launcher)                                 |
//! | environment                        | bwrap `--clearenv`; the supervisor's fixed list           |
//! | working directory                  | bwrap `--chdir /work`                                     |
//! | umask                              | 022 (here)                                                |
//! | signal dispositions, mask          | default, empty (here and in the first guest's fork child) |
//! | pending signals, itimers, alt stack| not inherited by fork / cleared by execve                 |
//! | resource limits (all 16)           | fixed or soft = hard, minimum checked (`LIMITS`)          |
//! | persona (personality)              | exact value by the launcher (ADDR_NO_RANDOMIZE or 0)      |
//! | CPU affinity                       | one CPU by the launcher; the guest reads a virtual count  |
//! | nice, policy, ioprio, timer slack  | timing only; ioprio and slack set, nice and policy kept   |
//! | NUMA memory policy                 | default (here); get_mempolicy is virtual                  |
//! | THP disable                        | 0 (here)                                                  |
//! | KSM merge, MDWE                    | checked: must be off                                      |
//! | seccomp filters                    | an outer one is kept; the runtime's filter stacks on it   |
//! | uid, gid                           | 1000/1000 in the user namespace (bwrap `--uid`/`--gid`)   |
//! | the launcher's own uid             | as root, made by the launcher (`launch::userns`)          |
//! | supplementary groups               | cannot be dropped: getgroups is virtual                   |
//! | capabilities, ambient, bounding    | bwrap; cleared in the first guest's fork child, checked   |
//! | securebits, no_new_privs           | checked 0; no_new_privs set by bwrap and the fork child   |
//! | session, process group, terminal   | bwrap `--new-session`; no controlling terminal (checked)  |
//! | hostname, domain name              | "sim" (bwrap); the domain name reads "(none)" (uname row) |
//! | OOM score adjustment               | 1000 (here)                                               |
//! | namespaces, cgroup                 | new namespaces (bwrap); the cgroup's limits are the host's|
//! | LSM labels, Landlock domains       | not observable but as refusals; not normalised (residual) |
//! | speculation control, IO flusher    | timing only                                               |
//! | keyrings                           | keyctl, add_key, request_key are denied                   |

use proto::layout::*;

/// RLIMIT_* numbers (x86_64).
const CPU: i32 = 0;
const FSIZE: i32 = 1;
const DATA: i32 = 2;
const STACK: i32 = 3;
const CORE: i32 = 4;
const RSS: i32 = 5;
const NPROC: i32 = 6;
const NOFILE: i32 = 7;
const MEMLOCK: i32 = 8;
const AS: i32 = 9;
const LOCKS: i32 = 10;
const SIGPENDING: i32 = 11;
const MSGQUEUE: i32 = 12;
const NICE: i32 = 13;
const RTPRIO: i32 = 14;
const RTTIME: i32 = 15;
const INF: u64 = u64::MAX;

/// What a limit becomes.
#[derive(Clone, Copy)]
enum Lim {
    /// soft = hard = this value; the hard limit must be at least this.
    Fixed(u64),
    /// soft = hard = the inherited hard limit, which must be at least this. For limits the
    /// kernel counts over the whole host (processes, queued signals): their use is not the
    /// sandbox's alone, so reaching them is a host limit (`infra`) however they are set.
    Hard(u64),
}

/// Every resource limit, in order. The guest reads its own limits from a fixed virtual table;
/// these are the ones the kernel enforces underneath.
const LIMITS: [(i32, &str, Lim); 16] = [
    (CPU, "cpu", Lim::Fixed(INF)),
    // Files: soft = the inherited hard limit, which must be at least the tmpfs size (a tmpfs
    // file reaches ENOSPC first). Not a fixed value: the boundary and operation logs are host
    // files, extended by the supervisor and by the runtime in every guest process, and grow
    // past any fixed size (blocking I/O's ring: 3 GB). Reaching the limit (a log, a stdio memfd) is a
    // host limit: the runtime's EFBIG backstop ends the run as `infra`.
    (FSIZE, "fsize", Lim::Hard(0)),
    (DATA, "data", Lim::Fixed(INF)),
    // The main stack's limit also places the mmap base.
    (STACK, "stack", Lim::Fixed(8 << 20)),
    (CORE, "core", Lim::Fixed(0)),
    (RSS, "rss", Lim::Hard(0)),
    (NPROC, "nproc", Lim::Hard(4096)),
    (NOFILE, "nofile", Lim::Fixed(4096)),
    (MEMLOCK, "memlock", Lim::Hard(0)),
    (AS, "as", Lim::Fixed(INF)),
    (LOCKS, "locks", Lim::Hard(0)),
    (SIGPENDING, "sigpending", Lim::Hard(1024)),
    (MSGQUEUE, "msgqueue", Lim::Fixed(0)),
    (NICE, "nice", Lim::Fixed(0)),
    (RTPRIO, "rtprio", Lim::Fixed(0)),
    (RTTIME, "rttime", Lim::Hard(0)),
];

const PR_SET_TIMERSLACK: i32 = 29;
const PR_SET_THP_DISABLE: i32 = 41;
const PR_GET_SECUREBITS: i32 = 27;
const PR_GET_MDWE: i32 = 66;
const PR_GET_MEMORY_MERGE: i32 = 68;
const TIMER_SLACK_NS: u64 = 50_000;

fn err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Reset every signal to its default action and unblock all (async-signal-safe).
pub unsafe fn reset_signals() {
    for s in 1..=64 {
        if s == libc::SIGKILL || s == libc::SIGSTOP {
            continue;
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        // Raw rt_sigaction: glibc refuses its own internal signals (32, 33).
        libc::syscall(
            libc::SYS_rt_sigaction,
            s,
            &sa as *const libc::sigaction,
            std::ptr::null_mut::<libc::sigaction>(),
            8,
        );
    }
    let empty = 0u64;
    libc::syscall(
        libc::SYS_rt_sigprocmask,
        libc::SIG_SETMASK,
        &empty as *const u64,
        std::ptr::null_mut::<u64>(),
        8,
    );
}

/// Close every descriptor but 0-2 and the hidden ones the supervisor keeps (`FD_CTL..FD_PATINA`,
/// FD_PATINA itself already closed, the counter broker's end `FD_PMU`, which every
/// guest runtime uses, and the shared memory carried across incarnations, `FD_SHM`).
pub unsafe fn close_inherited() {
    const _: () = assert!(FD_PMU > FD_PATINA);
    libc::syscall(libc::SYS_close_range, 3u32, (FD_CTL - 1) as u32, 0u32);
    libc::syscall(
        libc::SYS_close_range,
        FD_PATINA as u32,
        (FD_PMU - 1) as u32,
        0u32,
    );
    const _: () = assert!(FD_SHM > FD_PMU + 1);
    libc::syscall(
        libc::SYS_close_range,
        (FD_PMU + 1) as u32,
        (FD_SHM - 1) as u32,
        0u32,
    );
    libc::syscall(libc::SYS_close_range, (FD_SHM + 1) as u32, u32::MAX, 0u32);
}

/// The supervisor's part, at its start: everything its guests inherit from it. `tmpfs_bytes`
/// is the size of each sandbox tmpfs (the largest file the guest can make there).
pub fn normalise(tmpfs_bytes: u64) -> Result<(), String> {
    unsafe {
        reset_signals();
        libc::umask(0o022);
        for (r, name, lim) in LIMITS {
            let mut cur: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(r as _, &mut cur) != 0 {
                return Err(err(&format!("getrlimit {name}")));
            }
            let need = match lim {
                Lim::Fixed(v) | Lim::Hard(v) => v,
            };
            let need = if r == FSIZE {
                need.max(tmpfs_bytes)
            } else {
                need
            };
            if cur.rlim_max < need {
                return Err(format!(
                    "host limit: RLIMIT_{} hard limit {} is below the {} the sandbox needs",
                    name.to_uppercase(),
                    cur.rlim_max,
                    need
                ));
            }
            let v = match lim {
                Lim::Fixed(_) => need,
                Lim::Hard(_) => cur.rlim_max,
            };
            let n = libc::rlimit {
                rlim_cur: v,
                rlim_max: v,
            };
            if libc::setrlimit(r as _, &n) != 0 {
                return Err(err(&format!("setrlimit {name}")));
            }
        }
        // OOM: the sandbox is the first choice of the host's OOM killer (raising is always
        // allowed), whatever the launcher's adjustment.
        if std::fs::write("/proc/self/oom_score_adj", b"1000").is_err() {
            return Err(err("oom_score_adj"));
        }
        // IO priority: "none" (follow the nice value); timer slack: the kernel's default.
        if libc::syscall(libc::SYS_ioprio_set, 1, 0, 0) != 0 {
            return Err(err("ioprio_set"));
        }
        if libc::prctl(PR_SET_TIMERSLACK, TIMER_SLACK_NS, 0, 0, 0) != 0 {
            return Err(err("timer slack"));
        }
        if libc::prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) != 0 {
            return Err(err("THP disable"));
        }
        if libc::syscall(libc::SYS_set_mempolicy, 0, 0, 0) != 0 {
            return Err(err("set_mempolicy"));
        }
        // Inherited settings that cannot be undone without a capability in the initial
        // namespace: a run under them would not be the run the table describes.
        let mdwe = libc::prctl(PR_GET_MDWE, 0, 0, 0, 0);
        if mdwe > 0 {
            return Err(format!("inherited memory-deny-write-execute ({mdwe:#x})"));
        }
        if libc::prctl(PR_GET_MEMORY_MERGE, 0, 0, 0, 0) > 0 {
            return Err("inherited KSM merging (PR_SET_MEMORY_MERGE)".into());
        }
        let sb = libc::prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        if sb != 0 {
            return Err(format!("inherited securebits {sb:#x}"));
        }
        // No controlling terminal (bwrap --new-session).
        let t = libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if t >= 0 {
            libc::close(t);
            return Err("the sandbox has a controlling terminal".into());
        }
    }
    Ok(())
}

/// The first guest's fork child, before it runs the runtime (async-signal-safe): signal state
/// as a new process's, no capabilities and no way to gain any (checked: bwrap gives none, and
/// its user namespace is nested, so none would reach the sandbox's namespaces anyway).
pub unsafe fn child() -> bool {
    reset_signals();
    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    libc::prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
        0,
        0,
        0,
    );
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let h = Hdr {
        version: 0x2008_0522,
        pid: 0,
    };
    let zero = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if libc::syscall(libc::SYS_capset, &h as *const Hdr, zero.as_ptr()) != 0 {
        return false;
    }
    let mut got = [Data {
        effective: 1,
        permitted: 1,
        inheritable: 1,
    }; 2];
    let h = Hdr {
        version: 0x2008_0522,
        pid: 0,
    };
    if libc::syscall(libc::SYS_capget, &h as *const Hdr, got.as_mut_ptr()) != 0 {
        return false;
    }
    got.iter()
        .all(|d| d.effective == 0 && d.permitted == 0 && d.inheritable == 0)
}

/// Copy a host directory tree into a sandbox tmpfs directory, in sorted name order (so
/// inode numbers follow the order), keeping permission bits; symlinks are recreated, file
/// contents copied, anything else skipped. Times and owners are the
/// sandbox's (the runtime reports tmpfs times from the virtual time table).
pub fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
    let mut names: Vec<_> = std::fs::read_dir(src)
        .map_err(|e| format!("{}: {e}", src.display()))?
        .flatten()
        .collect();
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let (from, to) = (e.path(), dst.join(e.file_name()));
        let md =
            std::fs::symlink_metadata(&from).map_err(|e| format!("{}: {e}", from.display()))?;
        let mode = md.permissions().mode() & 0o7777;
        let ft = md.file_type();
        if ft.is_symlink() {
            let t = std::fs::read_link(&from).map_err(|e| format!("{}: {e}", from.display()))?;
            symlink(&t, &to).map_err(|e| format!("{}: {e}", to.display()))?;
        } else if ft.is_dir() {
            std::fs::create_dir(&to).map_err(|e| format!("{}: {e}", to.display()))?;
            copy_tree(&from, &to)?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode))
                .map_err(|e| format!("{}: {e}", to.display()))?;
        } else if ft.is_file() {
            let i = std::fs::File::open(&from).map_err(|e| format!("{}: {e}", from.display()))?;
            let o = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)
                .map_err(|e| format!("{}: {e}", to.display()))?;
            // copy_file_range where the kernel allows it, else sendfile (std's copy).
            let (mut i, mut o) = (i, o);
            std::io::copy(&mut i, &mut o).map_err(|e| format!("{}: {e}", to.display()))?;
            o.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| format!("{}: {e}", to.display()))?;
        }
    }
    Ok(())
}
