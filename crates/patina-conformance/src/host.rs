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
/// (an existing directory on the filesystem the native run uses) lacks.
pub fn needs_unmet(scenario: &Scenario, dir: &Path) -> Option<NotRun> {
    scenario
        .needs
        .iter()
        .find_map(|need| need_unmet(*need, dir).err())
}

/// Detect `need` live in `dir`. Every call goes through `syscall(2)`: the
/// probe binary links this module, and importing a glibc wrapper the shim
/// does not define would make the pre-run audit refuse it.
pub fn need_unmet(need: Need, dir: &Path) -> Result<(), NotRun> {
    match need {
        Need::UserXattrs => user_xattrs(dir),
        Need::Inotify => inotify(dir),
        Need::FileHandles => file_handles(dir),
        Need::Whiteouts => whiteouts(dir),
        Need::Unprivileged => unprivileged(),
    }
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
/// scenario asserts for an unprivileged caller (EPERM, EACCES) hold only with
/// euid ≠ 0 and an empty effective capability set.
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
    let caps = field("CapEff:");
    match (
        euid.as_deref(),
        caps.as_deref().map(|hex| u64::from_str_radix(hex, 16)),
    ) {
        (Some("0"), _) => Err(NotRun {
            cause: Cause::Privileged,
            detail: "the effective uid is 0".into(),
        }),
        (Some(_), Some(Ok(0))) => Ok(()),
        (Some(_), Some(Ok(caps))) => Err(NotRun {
            cause: Cause::Privileged,
            detail: format!("the effective capability set is {caps:#x}"),
        }),
        _ => Err(NotRun {
            cause: Cause::Unexpected,
            detail: "no Uid/CapEff in /proc/self/status".into(),
        }),
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
