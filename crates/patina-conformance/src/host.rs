//! Whether this host can be the oracle: what a scenario needs from the host
//! kernel, detected live, with the reason when it is unmet. An unmet need is
//! reported as not-run, never a pass; a scenario that runs and fails is a
//! failure, never "unavailable".

use crate::catalog::{Need, Scenario};
use crate::vehicle::errno_name;
use patina_dst_syscalls::{SYSCALLS, Syscall, parse_release};
use std::ffi::CString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The host kernel does not have it.
    Absent,
    /// The kernel has it, but this process may not use it.
    PermissionDenied,
    /// A seccomp filter stands between this process and the kernel.
    Sandboxed,
    /// The host kernel implements a row the scenario asserts absent, so it
    /// cannot be the oracle for that absence.
    Present,
    /// A per-user limit this process may not exceed is used up.
    Exhausted,
    /// The process holds a privilege whose checks the scenario asserts.
    Privileged,
    /// The process inherited a state the scenario starts from otherwise (a
    /// lowered priority, a persona) and cannot restore.
    Inherited,
    /// Detection itself failed in a way no missing capability explains (a
    /// vanished run directory, EIO, a wrong argument): a broken probe, which
    /// the harness fails rather than reports not run.
    Unexpected,
}

/// Why a run is not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotRun {
    pub cause: Cause,
    pub detail: String,
}

impl fmt::Display for NotRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self.cause {
            Cause::Absent => "absent",
            Cause::PermissionDenied => "permission denied",
            Cause::Sandboxed => "sandboxed",
            Cause::Present => "present",
            Cause::Exhausted => "exhausted",
            Cause::Privileged => "privileged",
            Cause::Inherited => "inherited",
            Cause::Unexpected => "unexpected",
        };
        write!(f, "{cause}: {}", self.detail)
    }
}

/// The host kernel's release (`uname -r`).
pub fn kernel_release() -> String {
    // SAFETY: `uname` fills the zeroed struct it is given.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return String::new();
    }
    // SAFETY: `release` is NUL-terminated by the kernel.
    unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// A behaviour known from kernel `since` on (`why` names it), as a kernel of
/// release `this` sees it next to a virtual kernel at `virtual_abi`: whether
/// `this` has the behaviour, and — when `this` and `virtual_abi` are on
/// different sides of `since`, so this kernel's answer is no oracle for the
/// virtual kernel's — why its observation is not compared. On the same side
/// (both have the behaviour or neither does) it compares strictly. A release
/// that does not parse is on neither side: never compared.
pub fn floor(since: &str, why: &str, this: &str, virtual_abi: &str) -> (bool, Option<String>) {
    let first = parse_release(since).expect("a kernel floor is a release");
    let has = |release: &str| parse_release(release).map(|release| release >= first);
    let compared = matches!((has(this), has(virtual_abi)), (Some(a), Some(b)) if a == b);
    (
        has(this).unwrap_or(false),
        (!compared)
            .then(|| format!("{why} (since {since}; kernel {this}, virtual ABI {virtual_abi})")),
    )
}

fn since(row: Syscall) -> Option<(u64, u64, u64)> {
    SYSCALLS
        .iter()
        .find(|entry| entry.id == row)
        .and_then(|entry| entry.since)
        .and_then(parse_release)
}

/// The first need of `scenario` this host kernel does not meet: a covered row
/// newer than the host kernel, or an asserted-absent row the host implements.
pub fn scenario_unmet(scenario: &Scenario) -> Option<NotRun> {
    unmet_on(scenario, &kernel_release())
}

fn unmet_on(scenario: &Scenario, release: &str) -> Option<NotRun> {
    let host = parse_release(release)?;
    if let Some(floor) = scenario.kernel_floor {
        let first = parse_release(floor.release).expect("a kernel floor is a release");
        if host < first {
            return Some(NotRun {
                cause: Cause::Absent,
                detail: format!(
                    "host kernel {release} predates {} ({})",
                    floor.release, floor.why
                ),
            });
        }
    }
    for row in scenario.covers {
        if let Some(first) = since(*row).filter(|first| host < *first) {
            return Some(NotRun {
                cause: Cause::Absent,
                detail: format!(
                    "host kernel {release} predates {} (first in {}.{})",
                    row.name(),
                    first.0,
                    first.1
                ),
            });
        }
    }
    None
}

/// The asserted-absent rows this host kernel implements, as the reason their
/// native observation is not run. Such a host is still an oracle for the rest
/// of the scenario: a row past the virtual ABI level answers ENOSYS by
/// declaration, so the native run substitutes that declared answer
/// (`Probe::with_declared_absent`) and the patina run is judged against it.
pub fn declared_absent(scenario: &Scenario) -> Option<NotRun> {
    declared_absent_on(scenario, &kernel_release())
}

fn declared_absent_on(scenario: &Scenario, release: &str) -> Option<NotRun> {
    let host = parse_release(release)?;
    let present: Vec<&str> = scenario
        .asserts_absent
        .iter()
        .filter(|row| {
            host >= since(**row).expect("an asserted-absent row is dated in the registry")
        })
        .map(|row| row.name())
        .collect();
    (!present.is_empty()).then(|| NotRun {
        cause: Cause::Present,
        detail: format!(
            "host kernel {release} implements {}: their native answers are the declared ENOSYS",
            present.join(", ")
        ),
    })
}

/// The first host capability `scenario` needs that the run directory `dir`
/// (an existing directory on the filesystem the native run uses) lacks, with
/// the need (whether it is [`Need::hardware`] decides how strict a required
/// oracle is about it).
pub fn needs_unmet(scenario: &Scenario, dir: &Path) -> Option<(Need, NotRun)> {
    scenario
        .needs
        .iter()
        .find_map(|need| need_unmet(*need, dir).err().map(|reason| (*need, reason)))
}

/// Detect `need` live in `dir`. Every call goes through `syscall(2)`: the
/// probe binary links this module, and importing a glibc wrapper the shim
/// does not define would make the pre-run audit refuse it.
pub fn need_unmet(need: Need, dir: &Path) -> Result<(), NotRun> {
    match need {
        Need::Ipv6Loopback => ipv6_loopback(),
        Need::Fanotify => fanotify(dir),
        Need::LocalBindOnly => local_bind_only(),
        Need::UserXattrs => user_xattrs(dir),
        Need::Inotify => inotify(dir),
        Need::FileHandles => file_handles(dir),
        Need::Whiteouts => whiteouts(dir),
        Need::Unprivileged => unprivileged(),
        Need::SysvShm => memipc::sysv_shm(),
        Need::SysvSem => memipc::sysv_sem(),
        Need::SysvMsg => memipc::sysv_msg(),
        Need::PosixMqueue => memipc::posix_mqueue(dir),
        Need::LockedPages(pages) => memipc::locked_pages(pages),
        Need::Membarrier => memipc::membarrier(),
        Need::ProtectionKeys => memipc::protection_keys(),
        Need::ShadowStack => memipc::shadow_stack(),
        Need::SecretMemory => memipc::secret_memory(),
        Need::OneNumaNode => memipc::one_numa_node(),
        Need::NiceZero => timeid::nice_zero(),
        Need::DefaultPersona => timeid::default_persona(),
        Need::SysfsSyscall => timeid::sysfs_syscall(),
        Need::HighResTimers => timeid::high_res_timers(),
    }
}

/// An AF_INET6 datagram socket bound to `[::1]:0`, through `syscall(2)`.
fn ipv6_loopback() -> Result<(), NotRun> {
    // SAFETY: integer arguments.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket,
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        let errno = crate::vehicle::errno();
        return Err(NotRun {
            cause: if errno == libc::EAFNOSUPPORT {
                Cause::Absent
            } else {
                refusal("", errno).cause
            },
            detail: format!(
                "socket(AF_INET6, SOCK_DGRAM) answered {}",
                errno_name(errno)
            ),
        });
    }
    // SAFETY: an all-zero sockaddr_in6 is a valid value.
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_addr.s6_addr[15] = 1;
    // SAFETY: a sockaddr_in6 of the length passed; the descriptor opened above.
    let bound = unsafe {
        libc::syscall(
            libc::SYS_bind,
            fd,
            &addr as *const libc::sockaddr_in6,
            std::mem::size_of::<libc::sockaddr_in6>(),
        )
    };
    let errno = crate::vehicle::errno();
    // SAFETY: the descriptor opened above.
    unsafe { libc::syscall(libc::SYS_close, fd) };
    if bound < 0 {
        return Err(NotRun {
            cause: if errno == libc::EADDRNOTAVAIL {
                Cause::Absent
            } else {
                refusal("", errno).cause
            },
            detail: format!("bind([::1]:0) answered {}", errno_name(errno)),
        });
    }
    Ok(())
}

/// An unprivileged fanotify group reporting file handles, and an inode mark
/// on the run directory the scenario will mark (`<dir>/run`, made for the
/// look and removed), through `syscall(2)`. A filesystem that cannot report
/// file handles — a zero fsid (`fanotify_test_fsid`: `ENODEV`) or one the
/// group cannot encode across (`EXDEV`) — lacks the capability; it is no
/// broken detection.
fn fanotify(dir: &Path) -> Result<(), NotRun> {
    let run = dir.join("run");
    std::fs::create_dir_all(&run).map_err(|error| NotRun {
        cause: Cause::Unexpected,
        detail: format!("create {}: {error}", run.display()),
    })?;
    let result = fanotify_mark_on(&run);
    let _ = std::fs::remove_dir(&run);
    result
}

fn fanotify_mark_on(run: &Path) -> Result<(), NotRun> {
    // SAFETY: integer arguments.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_REPORT_FID,
            libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(refusal(
            "fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID)",
            crate::vehicle::errno(),
        ));
    }
    let c = path_of(run);
    // SAFETY: a NUL-terminated path; the descriptor opened above.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd,
            libc::FAN_MARK_ADD,
            libc::FAN_CREATE,
            libc::AT_FDCWD,
            c.as_ptr(),
        )
    };
    let errno = crate::vehicle::errno();
    // SAFETY: the descriptor opened above.
    unsafe { libc::syscall(libc::SYS_close, fd) };
    if marked < 0 {
        let what = "fanotify_mark on the run directory";
        return Err(match errno {
            libc::ENODEV | libc::EXDEV => NotRun {
                cause: Cause::Absent,
                detail: format!(
                    "{what} answered {}: its filesystem reports no file handles",
                    errno_name(errno)
                ),
            },
            _ => refusal(what, errno),
        });
    }
    Ok(())
}

/// `net.ipv4.ip_nonlocal_bind` and `net.ipv6.ip_nonlocal_bind` are 0 (a host
/// without IPv6 has no IPv6 knob: nothing to allow).
fn local_bind_only() -> Result<(), NotRun> {
    for knob in ["ipv4", "ipv6"] {
        let path = format!("/proc/sys/net/{knob}/ip_nonlocal_bind");
        match std::fs::read_to_string(&path) {
            Ok(value) if value.trim() == "0" => {}
            Ok(value) => {
                return Err(NotRun {
                    cause: Cause::Absent,
                    detail: format!(
                        "net.{knob}.ip_nonlocal_bind is {}: a bind to an address no interface has succeeds",
                        value.trim()
                    ),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && knob == "ipv6" => {}
            Err(error) => {
                return Err(NotRun {
                    cause: Cause::Unexpected,
                    detail: format!("read {path}: {error}"),
                });
            }
        }
    }
    Ok(())
}

fn path_of(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("no interior NUL in a temp path")
}

/// Classify a refused detection call: only "not supported" means absent;
/// an errno no missing capability explains is `Unexpected`.
fn refusal(what: &str, errno: i32) -> NotRun {
    NotRun {
        cause: match errno {
            libc::EOPNOTSUPP | libc::ENOSYS => Cause::Absent,
            libc::EPERM | libc::EACCES => Cause::PermissionDenied,
            libc::EMFILE | libc::ENFILE | libc::ENOSPC => Cause::Exhausted,
            _ => Cause::Unexpected,
        },
        detail: format!("{what} answered {}", errno_name(errno)),
    }
}

/// A scratch file in the run directory, or the `Unexpected` failure.
fn scratch(path: &Path) -> Result<(), NotRun> {
    std::fs::File::create(path)
        .map(drop)
        .map_err(|error| NotRun {
            cause: Cause::Unexpected,
            detail: format!("create {}: {error}", path.display()),
        })
}

fn user_xattrs(dir: &Path) -> Result<(), NotRun> {
    let file = dir.join(".patina-need-xattr");
    scratch(&file)?;
    let c = path_of(&file);
    let name = c"user.patina-need";
    let mut listing = [0u8; 256];
    // SAFETY: NUL-terminated strings and buffers of the lengths passed.
    let (listed, set) = unsafe {
        let listed = libc::syscall(
            libc::SYS_listxattr,
            c.as_ptr(),
            listing.as_mut_ptr(),
            listing.len(),
        );
        let listed = if listed < 0 {
            -(crate::vehicle::errno() as i64)
        } else {
            listed as i64
        };
        let set = libc::syscall(
            libc::SYS_setxattr,
            c.as_ptr(),
            name.as_ptr(),
            c"1".as_ptr(),
            1,
            0,
        );
        let set = if set < 0 { crate::vehicle::errno() } else { 0 };
        (listed, set)
    };
    let _ = std::fs::remove_file(&file);
    if set != 0 {
        return Err(refusal(
            "setxattr(user.*) on the run directory's filesystem",
            set,
        ));
    }
    if listed != 0 {
        return Err(NotRun {
            cause: Cause::Absent,
            detail: format!(
                "a fresh file on the run directory's filesystem lists attributes ({}): no unlabeled file to observe",
                if listed < 0 {
                    errno_name((-listed) as i32)
                } else {
                    format!("{listed} bytes")
                }
            ),
        });
    }
    Ok(())
}

fn inotify(dir: &Path) -> Result<(), NotRun> {
    // SAFETY: plain integer arguments; the descriptor is closed below.
    let fd = unsafe { libc::syscall(libc::SYS_inotify_init1, libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(refusal("inotify_init1", crate::vehicle::errno()));
    }
    let c = path_of(dir);
    // SAFETY: a NUL-terminated path.
    let wd = unsafe { libc::syscall(libc::SYS_inotify_add_watch, fd, c.as_ptr(), libc::IN_CREATE) };
    let errno = crate::vehicle::errno();
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd as libc::c_int) };
    if wd < 0 {
        return Err(refusal("inotify_add_watch", errno));
    }
    Ok(())
}

fn file_handles(dir: &Path) -> Result<(), NotRun> {
    let mut handle = crate::probe::FileHandle::declaring(crate::probe::FileHandle::MAX);
    let mut mount_id: libc::c_int = 0;
    let c = path_of(dir);
    // SAFETY: a NUL-terminated path, a handle of the declared size, an int.
    let result = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            c.as_ptr(),
            &mut handle as *mut crate::probe::FileHandle,
            &mut mount_id as *mut libc::c_int,
            0,
        )
    };
    if result < 0 {
        return Err(refusal(
            "name_to_handle_at on the run directory",
            crate::vehicle::errno(),
        ));
    }
    Ok(())
}

/// A whiteout left by `renameat2(RENAME_WHITEOUT)` on the run directory's
/// filesystem (overlayfs refuses the flag with EINVAL; so does a filesystem
/// without whiteout support).
fn whiteouts(dir: &Path) -> Result<(), NotRun> {
    let from = dir.join(".patina-need-whiteout");
    let to = dir.join(".patina-need-whiteout-moved");
    scratch(&from)?;
    let (cf, ct) = (path_of(&from), path_of(&to));
    // SAFETY: NUL-terminated paths and integer flags.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            cf.as_ptr(),
            libc::AT_FDCWD,
            ct.as_ptr(),
            libc::RENAME_WHITEOUT,
        )
    };
    let errno = crate::vehicle::errno();
    let _ = std::fs::remove_file(&from);
    let _ = std::fs::remove_file(&to);
    if result < 0 {
        return Err(NotRun {
            cause: if errno == libc::EINVAL {
                Cause::Absent
            } else {
                refusal("", errno).cause
            },
            detail: format!(
                "renameat2(RENAME_WHITEOUT) on the run directory's filesystem answered {}",
                errno_name(errno)
            ),
        });
    }
    Ok(())
}

/// The effective user and capabilities from `/proc/self/status`: the checks a
/// scenario asserts for an unprivileged caller (EPERM, EACCES, empty
/// capability sets) hold only with euid ≠ 0 and empty effective, permitted,
/// inheritable and ambient capability sets.
fn unprivileged() -> Result<(), NotRun> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|error| NotRun {
        cause: Cause::Unexpected,
        detail: format!("read /proc/self/status: {error}"),
    })?;
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
            .map(str::to_string)
    };
    let euid = field("Uid:").and_then(|uids| uids.split_whitespace().nth(1).map(str::to_string));
    match euid.as_deref() {
        Some("0") => {
            return Err(NotRun {
                cause: Cause::Privileged,
                detail: "the effective uid is 0".into(),
            });
        }
        Some(_) => {}
        None => {
            return Err(NotRun {
                cause: Cause::Unexpected,
                detail: "no Uid in /proc/self/status".into(),
            });
        }
    }
    for set in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
        match field(set).map(|hex| u64::from_str_radix(&hex, 16)) {
            Some(Ok(0)) => {}
            Some(Ok(caps)) => {
                return Err(NotRun {
                    cause: Cause::Privileged,
                    detail: format!("{} is {caps:#x}", set.trim_end_matches(':')),
                });
            }
            _ => {
                return Err(NotRun {
                    cause: Cause::Unexpected,
                    detail: format!("no {set} in /proc/self/status"),
                });
            }
        }
    }
    Ok(())
}

/// The time, scheduling and identity needs: a process attribute the native
/// run inherits from the harness, or a kernel-configuration fact.
mod timeid {
    use super::{Cause, NotRun, refusal};
    use crate::vehicle::errno;

    /// `syscall(2)` with a raw number; the kernel convention (`-errno`).
    fn sys(number: libc::c_long, args: [libc::c_long; 2]) -> i64 {
        // SAFETY: the rows below take no pointer this frame does not own.
        let result = unsafe { libc::syscall(number, args[0], args[1]) };
        if result == -1 {
            -i64::from(errno())
        } else {
            result
        }
    }

    pub(super) fn nice_zero() -> Result<(), NotRun> {
        // The raw row answers 20 - nice.
        match sys(
            libc::SYS_getpriority,
            [libc::PRIO_PROCESS as libc::c_long, 0],
        ) {
            20 => Ok(()),
            result if result > 0 => Err(NotRun {
                cause: Cause::Inherited,
                detail: format!("the harness runs at nice {}", 20 - result),
            }),
            result => Err(refusal("getpriority(PRIO_PROCESS, 0)", -result as i32)),
        }
    }

    pub(super) fn default_persona() -> Result<(), NotRun> {
        match sys(libc::SYS_personality, [0xffff_ffff, 0]) {
            0 => Ok(()),
            result if result > 0 => Err(NotRun {
                cause: Cause::Inherited,
                detail: format!("the harness runs in persona {result:#x}"),
            }),
            result => Err(refusal("personality(0xffffffff)", -result as i32)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn sysfs_syscall() -> Result<(), NotRun> {
        match sys(libc::SYS_sysfs, [3, 0]) {
            count if count >= 0 => Ok(()),
            result => Err(refusal("sysfs(3)", -result as i32)),
        }
    }

    /// The generic (arm64) table has no `sysfs` row.
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn sysfs_syscall() -> Result<(), NotRun> {
        Err(NotRun {
            cause: Cause::Absent,
            detail: "this architecture's table has no sysfs row".into(),
        })
    }

    pub(super) fn high_res_timers() -> Result<(), NotRun> {
        let mut res = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = sys(
            libc::SYS_clock_getres,
            [
                libc::CLOCK_MONOTONIC as libc::c_long,
                &mut res as *mut libc::timespec as libc::c_long,
            ],
        );
        match (result, res.tv_sec, res.tv_nsec) {
            (0, 0, 1) => Ok(()),
            (0, sec, nsec) => Err(NotRun {
                cause: Cause::Absent,
                detail: format!("CLOCK_MONOTONIC resolves to {sec}.{nsec:09} s, a tick"),
            }),
            (result, _, _) => Err(refusal("clock_getres(CLOCK_MONOTONIC)", -result as i32)),
        }
    }
}

/// The memory and IPC needs: each creates the smallest object of its kind
/// the scenario would, then releases it. Refusals classify through
/// [`refusal`]; a row whose errno names the missing capability says so where
/// it is used.
mod memipc {
    use super::{Cause, NotRun, refusal};
    use crate::vehicle::errno;
    use patina_dst_syscalls::Syscall;
    use std::path::Path;

    /// `syscall(2)` with the row's number; the kernel convention (`-errno`).
    fn sys(row: Syscall, args: [i64; 6]) -> i64 {
        // SAFETY: every pointer passed below is owned by the caller for the
        // duration of the call.
        let result = unsafe {
            libc::syscall(
                row.number() as libc::c_long,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            )
        };
        if result < 0 {
            -i64::from(errno())
        } else {
            result
        }
    }

    fn page() -> i64 {
        crate::probe::page_size() as i64
    }

    fn check(what: &str, result: i64) -> Result<i64, NotRun> {
        if result < 0 {
            Err(refusal(what, (-result) as i32))
        } else {
            Ok(result)
        }
    }

    /// A System V creation: ENOSPC is `shmmni`/`semmni`/`msgmni` and ENOMEM
    /// `shmall` or the namespace's memory (ipc/shm.c, ipc/util.c) — limits,
    /// not a broken probe.
    fn sysv(what: &str, result: i64) -> Result<i64, NotRun> {
        if result == -i64::from(libc::ENOMEM) {
            return Err(unmet(Cause::Exhausted, format!("{what} answered ENOMEM")));
        }
        check(what, result)
    }

    fn unmet(cause: Cause, detail: String) -> NotRun {
        NotRun { cause, detail }
    }

    pub(super) fn sysv_shm() -> Result<(), NotRun> {
        let id = sysv(
            "shmget(IPC_PRIVATE, one page)",
            sys(
                Syscall::N_shmget,
                [0, page(), (libc::IPC_CREAT | 0o600) as i64, 0, 0, 0],
            ),
        )?;
        check(
            "shmctl(IPC_RMID)",
            sys(Syscall::N_shmctl, [id, libc::IPC_RMID as i64, 0, 0, 0, 0]),
        )
        .map(drop)
    }

    pub(super) fn sysv_sem() -> Result<(), NotRun> {
        let id = sysv(
            "semget(IPC_PRIVATE, 1)",
            sys(
                Syscall::N_semget,
                [0, 1, (libc::IPC_CREAT | 0o600) as i64, 0, 0, 0],
            ),
        )?;
        check(
            "semctl(IPC_RMID)",
            sys(Syscall::N_semctl, [id, 0, libc::IPC_RMID as i64, 0, 0, 0]),
        )
        .map(drop)
    }

    pub(super) fn sysv_msg() -> Result<(), NotRun> {
        let id = sysv(
            "msgget(IPC_PRIVATE)",
            sys(
                Syscall::N_msgget,
                [0, (libc::IPC_CREAT | 0o600) as i64, 0, 0, 0, 0],
            ),
        )?;
        check(
            "msgctl(IPC_RMID)",
            sys(Syscall::N_msgctl, [id, libc::IPC_RMID as i64, 0, 0, 0, 0]),
        )
        .map(drop)
    }

    /// The attributes the mqueue scenario creates its queue with.
    const MQ_MAXMSG: i64 = 4;
    const MQ_MSGSIZE: i64 = 16;

    pub(super) fn posix_mqueue(dir: &Path) -> Result<(), NotRun> {
        let base = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = std::ffi::CString::new(format!("{base}-need-mq")).expect("no NUL");
        // SAFETY: mq_attr is plain data.
        let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
        attr.mq_maxmsg = MQ_MAXMSG;
        attr.mq_msgsize = MQ_MSGSIZE;
        let fd = check(
            "mq_open(O_CREAT|O_EXCL, 4 x 16 bytes)",
            sys(
                Syscall::N_mq_open,
                [
                    name.as_ptr() as i64,
                    (libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC) as i64,
                    0o600,
                    &attr as *const libc::mq_attr as i64,
                    0,
                    0,
                ],
            ),
        )?;
        sys(Syscall::N_close, [fd, 0, 0, 0, 0, 0]);
        check(
            "mq_unlink",
            sys(Syscall::N_mq_unlink, [name.as_ptr() as i64, 0, 0, 0, 0, 0]),
        )
        .map(drop)
    }

    fn anonymous(pages: i64) -> Result<i64, NotRun> {
        check(
            "mmap(anonymous)",
            sys(
                Syscall::N_mmap,
                [
                    0,
                    pages * page(),
                    (libc::PROT_READ | libc::PROT_WRITE) as i64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as i64,
                    -1,
                    0,
                ],
            ),
        )
    }

    /// `mlock` answers ENOMEM when the pages exceed a nonzero
    /// `RLIMIT_MEMLOCK` and EPERM when the limit is 0 (man 2 mlock).
    pub(super) fn locked_pages(pages: usize) -> Result<(), NotRun> {
        let pages = pages as i64;
        let base = anonymous(pages)?;
        let locked = sys(Syscall::N_mlock, [base, pages * page(), 0, 0, 0, 0]);
        sys(Syscall::N_munlock, [base, pages * page(), 0, 0, 0, 0]);
        sys(Syscall::N_munmap, [base, pages * page(), 0, 0, 0, 0]);
        match locked {
            0 => Ok(()),
            error if error == -i64::from(libc::ENOMEM) => Err(unmet(
                Cause::Exhausted,
                format!("mlock of {pages} pages answered ENOMEM (RLIMIT_MEMLOCK)"),
            )),
            error => Err(refusal(&format!("mlock of {pages} pages"), (-error) as i32)),
        }
    }

    /// `MEMBARRIER_CMD_{GLOBAL,PRIVATE}_EXPEDITED` and their registrations.
    const MEMBARRIER_PORTABLE: i64 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4);

    pub(super) fn membarrier() -> Result<(), NotRun> {
        let mask = check(
            "membarrier(MEMBARRIER_CMD_QUERY)",
            sys(Syscall::N_membarrier, [0; 6]),
        )?;
        if mask & MEMBARRIER_PORTABLE != MEMBARRIER_PORTABLE {
            return Err(unmet(
                Cause::Absent,
                format!("membarrier offers no expedited commands (mask {mask:#x})"),
            ));
        }
        Ok(())
    }

    /// With valid arguments `pkey_alloc` refuses only for want of keys: ENOSPC
    /// when no key is free (always, where only key 0 exists), and on x86_64
    /// EINVAL when the CPU lacks OSPKE (`arch_set_user_pkey_access`).
    pub(super) fn protection_keys() -> Result<(), NotRun> {
        let key = sys(Syscall::N_pkey_alloc, [0; 6]);
        for (errno, name) in [(libc::ENOSPC, "ENOSPC"), (libc::EINVAL, "EINVAL")] {
            if key == -i64::from(errno) {
                return Err(unmet(
                    Cause::Absent,
                    format!("pkey_alloc answered {name} (no allocatable protection key)"),
                ));
            }
        }
        let key = check("pkey_alloc", key)?;
        check("pkey_free", sys(Syscall::N_pkey_free, [key, 0, 0, 0, 0, 0])).map(drop)
    }

    pub(super) fn shadow_stack() -> Result<(), NotRun> {
        let base = check(
            "map_shadow_stack(one page)",
            sys(Syscall::N_map_shadow_stack, [0, page(), 0, 0, 0, 0]),
        )?;
        sys(Syscall::N_munmap, [base, page(), 0, 0, 0, 0]);
        Ok(())
    }

    /// A secret page is locked memory: its mapping answers EAGAIN past
    /// `RLIMIT_MEMLOCK` (mm/secretmem.c).
    pub(super) fn secret_memory() -> Result<(), NotRun> {
        let fd = check(
            "memfd_secret",
            sys(
                Syscall::N_memfd_secret,
                [libc::O_CLOEXEC as i64, 0, 0, 0, 0, 0],
            ),
        )?;
        let sized = sys(Syscall::N_ftruncate, [fd, page(), 0, 0, 0, 0]);
        let mapped = if sized == 0 {
            sys(
                Syscall::N_mmap,
                [
                    0,
                    page(),
                    (libc::PROT_READ | libc::PROT_WRITE) as i64,
                    libc::MAP_SHARED as i64,
                    fd,
                    0,
                ],
            )
        } else {
            sized
        };
        if mapped >= 0 {
            sys(Syscall::N_munmap, [mapped, page(), 0, 0, 0, 0]);
        }
        sys(Syscall::N_close, [fd, 0, 0, 0, 0, 0]);
        match mapped {
            mapped if mapped >= 0 => Ok(()),
            error if error == -i64::from(libc::EAGAIN) => Err(unmet(
                Cause::Exhausted,
                "mapping a secret-memory page answered EAGAIN (RLIMIT_MEMLOCK)".into(),
            )),
            error => Err(refusal(
                "sizing and mapping a secret-memory page",
                (-error) as i32,
            )),
        }
    }

    pub(super) fn one_numa_node() -> Result<(), NotRun> {
        const MPOL_F_MEMS_ALLOWED: i64 = 1 << 2;
        let mut mode: i32 = 0;
        let mut mask = [0u64; 16];
        check(
            "get_mempolicy(MPOL_F_MEMS_ALLOWED)",
            sys(
                Syscall::N_get_mempolicy,
                [
                    &mut mode as *mut i32 as i64,
                    mask.as_mut_ptr() as i64,
                    (mask.len() * 64) as i64,
                    0,
                    MPOL_F_MEMS_ALLOWED,
                    0,
                ],
            ),
        )?;
        let nodes: u32 = mask.iter().map(|word| word.count_ones()).sum();
        if nodes != 1 {
            return Err(unmet(
                Cause::Absent,
                format!("this task may allocate from {nodes} memory nodes, not one"),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn an_impossible_lock_is_unmet_not_passed() {
            assert!(locked_pages(1 << 40).is_err());
        }
    }
}

/// Whether a seccomp filter is installed on this process
/// (`/proc/self/status` `Seccomp: 2`).
#[cfg(target_arch = "x86_64")]
fn seccomp_filtered() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status.lines().any(|line| {
            line.strip_prefix("Seccomp:")
                .is_some_and(|mode| mode.trim() == "2")
        })
    })
}

/// Classify a refused kernel feature probe by its errno.
#[cfg(target_arch = "x86_64")]
fn refused(feature: &str, errno: i32) -> NotRun {
    let name = crate::vehicle::errno_name(errno);
    let cause = match errno {
        libc::EINVAL => Cause::Absent,
        _ if seccomp_filtered() => Cause::Sandboxed,
        libc::EPERM | libc::EACCES => Cause::PermissionDenied,
        _ => Cause::Absent,
    };
    NotRun {
        cause,
        detail: format!("{feature} answered {name}"),
    }
}

/// Syscall user dispatch, which the raw vehicle needs under patina: turning
/// it off for this process is a no-op probe of the kernel's support.
#[cfg(target_arch = "x86_64")]
pub fn syscall_user_dispatch() -> Result<(), NotRun> {
    const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;
    const PR_SYS_DISPATCH_OFF: libc::c_ulong = 0;
    // SAFETY: disabling dispatch for this process changes nothing.
    let result = unsafe { libc::prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(refused(
            "prctl(PR_SET_SYSCALL_USER_DISPATCH)",
            crate::vehicle::errno(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::DEFAULTS;

    const NEEDS_CLOSE_RANGE: Scenario = Scenario {
        name: "planted/needs-close-range",
        covers: &[Syscall::N_close_range],
        ..DEFAULTS
    };

    const ASSERTS_FCHROOT_ABSENT: Scenario = Scenario {
        name: "planted/asserts-fchroot-absent",
        asserts_absent: &[Syscall::N_fchroot],
        ..DEFAULTS
    };

    #[test]
    fn a_kernel_predating_a_covered_row_is_no_oracle() {
        let unmet = unmet_on(&NEEDS_CLOSE_RANGE, "5.4.0-200-generic").expect("unmet");
        assert_eq!(unmet.cause, Cause::Absent);
        assert!(unmet.detail.contains("close_range"), "{unmet}");
    }

    #[test]
    fn a_kernel_with_the_covered_row_is_an_oracle() {
        assert_eq!(unmet_on(&NEEDS_CLOSE_RANGE, "6.8.0-139-generic"), None);
    }

    #[test]
    fn a_kernel_implementing_an_asserted_absent_row_answers_by_declaration() {
        assert_eq!(unmet_on(&ASSERTS_FCHROOT_ABSENT, "7.3.0"), None);
        let declared = declared_absent_on(&ASSERTS_FCHROOT_ABSENT, "7.3.0").expect("declared");
        assert_eq!(declared.cause, Cause::Present);
        assert!(declared.detail.contains("fchroot"), "{declared}");
    }

    #[test]
    fn a_kernel_lacking_an_asserted_absent_row_observes_it() {
        assert_eq!(unmet_on(&ASSERTS_FCHROOT_ABSENT, "7.2.9"), None);
        assert_eq!(declared_absent_on(&ASSERTS_FCHROOT_ABSENT, "7.2.9"), None);
    }

    const NEEDS_6_4: Scenario = Scenario {
        name: "planted/needs-6.4",
        covers: &[Syscall::N_close_range],
        kernel_floor: Some(crate::catalog::KernelFloor {
            release: "6.4",
            why: "planted",
        }),
        ..DEFAULTS
    };

    #[test]
    fn a_kernel_below_the_floor_is_no_oracle() {
        let unmet = unmet_on(&NEEDS_6_4, "6.1.100").expect("unmet");
        assert_eq!(unmet.cause, Cause::Absent);
        assert_eq!(unmet_on(&NEEDS_6_4, "6.4.0"), None);
    }

    /// A per-check floor below the virtual ABI level (a behaviour the virtual
    /// kernel has): a host older than the floor lacks it and is no oracle for
    /// it; a host at the floor or past it compares strictly.
    #[test]
    fn a_host_older_than_a_check_floor_does_not_compare_it() {
        let (has, reason) = floor("6.13", "planted", "6.8.0-139-generic", "7.0");
        assert!(!has);
        let reason = reason.expect("not compared");
        assert!(reason.contains("6.8.0-139-generic"), "{reason}");
    }

    #[test]
    fn a_host_at_a_check_floor_compares_it() {
        assert_eq!(floor("6.13", "planted", "6.13.0", "7.0"), (true, None));
    }

    #[test]
    fn a_host_newer_than_a_check_floor_compares_it() {
        assert_eq!(
            floor("6.13", "planted", "6.17.0-1-azure", "7.0"),
            (true, None)
        );
        assert_eq!(floor("6.13", "planted", "7.3.0", "7.0"), (true, None));
    }

    /// Under patina this kernel is the virtual one: always compared.
    #[test]
    fn the_virtual_kernel_compares_every_floor_it_reports() {
        assert_eq!(
            floor("6.13", "planted", "7.0.0-patina", "7.0"),
            (true, None)
        );
        assert_eq!(
            floor("7.3", "planted", "7.0.0-patina", "7.0"),
            (false, None)
        );
    }

    /// A floor past the virtual ABI level (a behaviour the virtual kernel
    /// lacks) compares only on hosts that lack it too; a host release that
    /// does not parse is never an oracle.
    #[test]
    fn a_floor_past_the_virtual_abi_compares_only_hosts_before_it() {
        assert_eq!(floor("7.3", "planted", "6.8.0", "7.0"), (false, None));
        assert!(floor("7.3", "planted", "7.3.1", "7.0").1.is_some());
        assert!(floor("6.13", "planted", "", "7.0").1.is_some());
    }

    /// Detection fails closed: a run directory that does not exist meets no
    /// need, so an unmet need is reported, never passed.
    #[test]
    fn every_need_is_unmet_without_a_run_directory() {
        let missing = std::env::temp_dir().join(format!(
            "patina-conformance-no-such-dir-{}",
            std::process::id()
        ));
        for need in [
            Need::UserXattrs,
            Need::Inotify,
            Need::FileHandles,
            Need::Whiteouts,
        ] {
            let reason = need_unmet(need, &missing).expect_err("a missing directory meets no need");
            assert_eq!(reason.cause, Cause::Unexpected, "{need:?}: {reason}");
        }
    }

    #[test]
    fn an_unexpected_errno_is_not_an_absent_feature() {
        assert_eq!(refusal("probe", libc::ENOENT).cause, Cause::Unexpected);
        assert_eq!(refusal("probe", libc::EIO).cause, Cause::Unexpected);
        assert_eq!(refusal("probe", libc::EOPNOTSUPP).cause, Cause::Absent);
        assert_eq!(refusal("probe", libc::EPERM).cause, Cause::PermissionDenied);
        assert_eq!(refusal("probe", libc::EMFILE).cause, Cause::Exhausted);
    }
}
