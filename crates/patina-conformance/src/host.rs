//! Whether this host can be the oracle: what a scenario needs from the host
//! kernel, detected live, with the reason when it is unmet. An unmet need is
//! reported as not-run, never a pass; a scenario that runs and fails is a
//! failure, never "unavailable".

use crate::catalog::Scenario;
use patina_dst_syscalls::{SYSCALLS, Syscall, parse_release};
use std::fmt;

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
    for row in scenario.asserts_absent {
        let first = since(*row).expect("an asserted-absent row is dated in the registry");
        if host >= first {
            return Some(NotRun {
                cause: Cause::Present,
                detail: format!(
                    "host kernel {release} implements {} (first in {}.{})",
                    row.name(),
                    first.0,
                    first.1
                ),
            });
        }
    }
    None
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
    fn a_kernel_implementing_an_asserted_absent_row_is_no_oracle() {
        let unmet = unmet_on(&ASSERTS_FCHROOT_ABSENT, "7.3.0").expect("unmet");
        assert_eq!(unmet.cause, Cause::Present);
    }

    #[test]
    fn a_kernel_lacking_an_asserted_absent_row_is_an_oracle() {
        assert_eq!(unmet_on(&ASSERTS_FCHROOT_ABSENT, "7.2.9"), None);
    }
}
