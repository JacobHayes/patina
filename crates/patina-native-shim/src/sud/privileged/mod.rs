//! SUD rows — the privileged rows, answered as the pinned kernel answers the
//! virtual credential (`crate::identity::credential`).
//!
//! Each row's answer is a function of the credential, the virtual kernel's
//! declared configuration, its arguments and the modeled filesystem and
//! descriptor table: the checks the kernel makes before its capability
//! check, in the kernel's order, then the capability check itself
//! ([`gate`]). What any caller may do goes through the model's own rows:
//! `open_tree` without a clone opens as `openat` does, and
//! `unshare(CLONE_SYSVSEM)` applies the semaphore adjustments as exit does. A credential without the capability gets the kernel's
//! refusal (`EPERM`, `EACCES`, …). A credential that holds it reaches what
//! the kernel would then do, which is not modeled: [`Unmodeled::Granted`], a
//! named fatal. The capability a row checks is declared on its registry row
//! (`SyscallRow::capabilities`); the tests hold each check to that
//! declaration.
//!
//! No decision here is recorded: every answer follows from the credential
//! and the declared configuration, which replay reproduces, and from the
//! filesystem's and descriptor table's own lookups, which are recorded and
//! replayed as every other row's are.

use crate::identity::{Credential, credential};
use crate::registry::Capability;
#[cfg(test)]
use crate::registry::Syscall;
use linux_raw_sys::errno;
use std::ffi::c_int;

mod admin;
#[cfg(target_arch = "x86_64")]
mod ioport;
mod kernel;
mod keys;
mod landlock;
mod lsm;
mod mount;
mod process;
mod seccomp;
pub(super) use admin::*;
#[cfg(target_arch = "x86_64")]
pub(super) use ioport::*;
pub(super) use kernel::*;
pub(super) use keys::*;
pub(super) use landlock::*;
pub(super) use lsm::*;
pub(super) use mount::*;
pub(super) use process::*;
pub(super) use seccomp::*;

/// What a privileged row answers: the raw return value (`-errno` for a
/// refusal), or the point past which the model does not go.
pub(super) type Answer = Result<i64, Unmodeled>;

/// Where a privileged row's model ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Unmodeled {
    /// The credential holds the capability the kernel checks: what the
    /// kernel then does is not modeled.
    Granted(Capability),
    /// A path the kernel takes for any caller that the model does not
    /// have: what it is.
    Path(String),
}

/// A refusal: `-errno`.
fn refuse(code: impl Into<i64>) -> Answer {
    Ok(-code.into())
}

/// The guest's path at `address`: `EFAULT` for NULL (`getname`,
/// [`super::guest_path`]), then the shim's one decode of a C path.
fn guest_path(address: u64) -> Result<String, c_int> {
    let pointer = super::guest_path(address).map_err(|code| -code as c_int)?;
    crate::path_from_c(pointer)
}

/// `user_path_at(AT_FDCWD, path, …)`; see [`lookup_at`].
fn lookup(address: u64, follow: bool) -> Result<crate::paths::Resolved, c_int> {
    lookup_at(crate::paths::AT_FDCWD, address, follow)
}

/// `user_path_at(dirfd, path, …)`: the entry a guest path names, with or
/// without following a final symlink — the resolver's refusals, and
/// `ENOENT` for a missing entry.
fn lookup_at(dirfd: c_int, address: u64, follow: bool) -> Result<crate::paths::Resolved, c_int> {
    let path = guest_path(address)?;
    let flags = if follow {
        0
    } else {
        crate::paths::RESOLVE_NOFOLLOW
    };
    let resolved = crate::paths::resolve(dirfd, &path, flags)?;
    if resolved.metadata.is_none() {
        return Err(errno::ENOENT as c_int);
    }
    Ok(resolved)
}

/// The capability check (`capable`, `ns_capable`, `may_mount`): `refusal`
/// without `capability`; with it, the end of the model.
fn gate(credential: &Credential, capability: Capability, refusal: u32) -> Answer {
    if credential.capable(capability) {
        Err(Unmodeled::Granted(capability))
    } else {
        refuse(refusal)
    }
}

/// A privileged row's check, over the credential and the six argument
/// registers.
pub(super) type Check = fn(&Credential, &[u64; 6]) -> Answer;

/// Answer syscall `nr` for the guest's credential, or stop the run by name
/// (its registry row's) where the model ends.
pub(super) fn answer(nr: i64, check: Check, args: [u64; 6]) -> i64 {
    let row = || super::row_for(nr).map_or("a privileged row", |(_, row)| row.name);
    match check(credential(), &args) {
        Ok(value) => value,
        Err(Unmodeled::Granted(capability)) => crate::trap_fatal(&format!(
            "capability {} granted but {} is not modeled: the virtual credential holds it, and \
             what the kernel does for such a caller is outside the model; failing closed",
            capability.name(),
            row()
        )),
        Err(Unmodeled::Path(what)) => {
            crate::trap_fatal(&format!("{}: {what} is not modeled; failing closed", row()))
        }
    }
}

/// `sethostname`/`setdomainname` (kernel/sys.c): `CAP_SYS_ADMIN` in the UTS
/// namespace's owner first, before the length.
pub(super) fn set_uts_name(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential holding exactly `capabilities` (effective and permitted).
    fn holding(capabilities: u64) -> Credential {
        Credential {
            effective: capabilities,
            permitted: capabilities,
            ..*credential()
        }
    }

    fn mask(capabilities: &[Capability]) -> u64 {
        capabilities.iter().fold(0, |set, cap| set | cap.bit())
    }

    /// One privileged row asked with arguments that pass every check before
    /// the capability, and the refusal the kernel gives a caller without it.
    struct Case {
        row: Syscall,
        check: Check,
        args: [u64; 6],
        refusal: u32,
    }

    /// Every case, one list per group of rows.
    fn cases() -> Vec<Case> {
        [
            uts_cases(),
            mount_cases(),
            admin_cases(),
            ioport_cases(),
            chroot_cases(),
            config_cases(),
            robust_list_cases(),
            sandbox_cases(),
            key_cases(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The rows that declare a capability no caller of the model reaches:
    /// the kernel checks it only past a refusal every descriptor or device
    /// of the virtual machine gets.
    const UNREACHABLE: &[Syscall] = &[Syscall::N_quotactl, Syscall::N_quotactl_fd];

    /// The row's answer to `case` for a credential holding `held`.
    fn outcome(case: &Case, held: u64) -> Answer {
        (case.check)(&holding(held), &case.args)
    }

    /// Every row that declares capabilities has a case (or is listed in
    /// [`UNREACHABLE`]), and every case holds its row to its declaration:
    /// a credential lacking every declared capability (holding every other
    /// one), and the guest's, get the kernel's refusal; one holding just the
    /// declared ones reaches the not-modeled end at one of them. And each
    /// declared capability is consulted by some case: taking it from the
    /// declared set, or giving it alone, changes the answer. So a check that
    /// consults an undeclared capability, or none, or never the one it
    /// declares, fails here.
    #[test]
    fn every_declaring_row_is_gated_on_its_declaration() {
        let cases = cases();
        for case in &cases {
            let row = crate::registry::syscall(case.row.name()).expect("a registry row");
            assert!(
                !row.capabilities.is_empty() && !UNREACHABLE.contains(&case.row),
                "{}: a case for a row that declares no reachable capability",
                row.name
            );
        }
        for row in crate::registry::SYSCALLS
            .iter()
            .filter(|row| !row.capabilities.is_empty())
        {
            if UNREACHABLE.contains(&row.id) {
                continue;
            }
            let declared = mask(row.capabilities);
            let mut consulted = 0;
            let mut asked = false;
            for case in cases.iter().filter(|case| case.row == row.id) {
                asked = true;
                assert_eq!(
                    outcome(case, Capability::ALL & !declared),
                    refuse(case.refusal),
                    "{}: refused without its capabilities",
                    row.name
                );
                assert_eq!(
                    (case.check)(credential(), &case.args),
                    refuse(case.refusal),
                    "{}: the guest's credential is refused",
                    row.name
                );
                match outcome(case, declared) {
                    Err(Unmodeled::Granted(capability)) => assert!(
                        declared & capability.bit() != 0,
                        "{}: granted {} it does not declare",
                        row.name,
                        capability.name()
                    ),
                    other => panic!("{}: with its capabilities answered {other:?}", row.name),
                }
                for capability in row.capabilities {
                    let bit = capability.bit();
                    if outcome(case, declared & !bit) != outcome(case, declared)
                        || outcome(case, bit) != outcome(case, 0)
                    {
                        consulted |= bit;
                    }
                }
            }
            assert!(asked, "{}: declares capabilities but has no case", row.name);
            for capability in row.capabilities {
                assert!(
                    consulted & capability.bit() != 0,
                    "{}: declares {} but no case consults it",
                    row.name,
                    capability.name()
                );
            }
        }
    }

    fn uts_cases() -> Vec<Case> {
        vec![
            Case {
                row: Syscall::N_sethostname,
                check: set_uts_name,
                args: [0, u64::MAX, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_setdomainname,
                check: set_uts_name,
                args: [0; 6],
                refusal: errno::EPERM,
            },
        ]
    }

    /// The mount rows: past their own argument checks (and, for `mount` and
    /// `umount2`, a target the lookup finds), each is `may_mount`.
    fn mount_cases() -> Vec<Case> {
        const CLONE: u64 = 1;
        let first = |row, check| Case {
            row,
            check,
            args: [u64::MAX; 6],
            refusal: errno::EPERM,
        };
        vec![
            first(Syscall::N_fsopen, may_mount),
            first(Syscall::N_fspick, may_mount),
            first(Syscall::N_fsmount, may_mount),
            first(Syscall::N_move_mount, may_mount),
            first(Syscall::N_pivot_root, may_mount),
            Case {
                row: Syscall::N_mount,
                check: |credential, a| mount_finding(credential, a, |_| Ok(())),
                args: [0, 1, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_umount2,
                check: |credential, a| umount2_finding(credential, a, |_, _| Ok(())),
                args: [1, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_mount_setattr,
                check: mount_setattr,
                args: [0, 0, 0, 0, 32, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_open_tree,
                check: open_tree,
                args: [0, 0, CLONE, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    /// The administration rows, each asked with every argument it checks
    /// after its capability invalid.
    fn admin_cases() -> Vec<Case> {
        let first = |row, check| Case {
            row,
            check,
            args: [u64::MAX; 6],
            refusal: errno::EPERM,
        };
        vec![
            first(Syscall::N_acct, acct),
            first(Syscall::N_vhangup, vhangup),
            first(Syscall::N_swapoff, swapoff),
            first(Syscall::N_reboot, boot),
            first(Syscall::N_kexec_load, boot),
            first(Syscall::N_kexec_file_load, boot),
            first(Syscall::N_init_module, module),
            first(Syscall::N_finit_module, module),
            first(Syscall::N_delete_module, module),
            Case {
                row: Syscall::N_swapon,
                check: swapon,
                args: [u64::MAX, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    /// swapon's flags come first, for every credential.
    #[test]
    fn swapon_checks_its_flags_before_the_capability() {
        let unknown_flag = [0, 1 << 30, 0, 0, 0, 0];
        for held in [0, Capability::ALL] {
            assert_eq!(swapon(&holding(held), &unknown_flag), refuse(errno::EINVAL));
        }
    }

    /// Raising the I/O privilege level or turning ports on needs
    /// `CAP_SYS_RAWIO`.
    #[cfg(target_arch = "x86_64")]
    fn ioport_cases() -> Vec<Case> {
        vec![
            Case {
                row: Syscall::N_iopl,
                check: iopl,
                args: [3, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_ioperm,
                check: ioperm,
                args: [0x80, 1, 1, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn ioport_cases() -> Vec<Case> {
        Vec::new()
    }

    /// Keeping I/O privilege level 0 or turning ports off needs nothing.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn keeping_the_io_ports_closed_needs_no_privilege() {
        let nothing = holding(0);
        assert_eq!(iopl(&nothing, &[0; 6]), Ok(0));
        assert_eq!(ioperm(&nothing, &[0x80, 1, 0, 0, 0, 0]), Ok(0));
        assert_eq!(
            ioperm(&nothing, &[u64::MAX, 2, 1, 0, 0, 0]),
            refuse(errno::EINVAL)
        );
    }

    /// `chroot` of a directory the caller may search needs
    /// `CAP_SYS_CHROOT`.
    /// Reading init's robust list and comparing its objects:
    /// `ptrace_may_access`. Copying init's memory: `mm_access`, past a local
    /// vector with a byte to copy. Taking one of init's descriptors through
    /// its pidfd: `ptrace_may_access`. Joining init's UTS namespace through
    /// its pidfd: `ptrace_may_access`, then `utsns_install`.
    /// Advising a process's memory through its pidfd: init's `mm_access`,
    /// then `CAP_SYS_NICE`, even for the guest's own.
    fn robust_list_cases() -> Vec<Case> {
        static BYTE: [u8; 1] = [0];
        let range = Box::leak(Box::new([BYTE.as_ptr() as u64, 1]));
        let vector = range.as_ptr() as u64;
        let copy = |row, check| Case {
            row,
            check,
            args: [1, vector, 1, vector, 1, 0],
            refusal: errno::EPERM,
        };
        vec![
            Case {
                row: Syscall::N_get_robust_list,
                check: get_robust_list,
                args: [1, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            copy(Syscall::N_process_vm_readv, process_vm_readv),
            copy(Syscall::N_process_vm_writev, process_vm_writev),
            Case {
                row: Syscall::N_process_madvise,
                check: |credential, a| {
                    madvise_from(credential, a, || Ok(crate::identity::Process::Guest))
                },
                args: [0, 0, 0, u64::from(linux_raw_sys::general::MADV_COLD), 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_process_madvise,
                check: |credential, a| {
                    madvise_from(credential, a, || Ok(crate::identity::Process::Init))
                },
                args: [0, 0, 0, u64::from(linux_raw_sys::general::MADV_COLD), 0, 0],
                refusal: errno::EACCES,
            },
            Case {
                row: Syscall::N_pidfd_getfd,
                check: |credential, a| {
                    getfd_from(credential, a, || Ok(crate::identity::Process::Init))
                },
                args: [0; 6],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_setns,
                check: |credential, a| {
                    join_namespaces(credential, a[1], crate::identity::Process::Init)
                },
                args: [
                    0,
                    u64::from(linux_raw_sys::general::CLONE_NEWUTS),
                    0,
                    0,
                    0,
                    0,
                ],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_kcmp,
                check: kcmp,
                args: [1, 1, u64::MAX, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    fn chroot_cases() -> Vec<Case> {
        vec![Case {
            row: Syscall::N_chroot,
            check: |credential, a| chroot_finding(credential, a, |_| Ok(())),
            args: [1, 0, 0, 0, 0, 0],
            refusal: errno::EPERM,
        }]
    }

    /// A zeroed BPF attribute: no start id.
    static NO_ID: [u8; 16] = [0; 16];
    /// `BPF_MAP_CREATE`'s attribute for a one-entry array map of four-byte
    /// keys and values.
    static ARRAY_MAP: [u32; 4] = [2, 4, 4, 1];

    /// The rows the declared configuration restricts: each refuses a
    /// caller without the capability exactly where the configuration says,
    /// after its argument checks.
    fn config_cases() -> Vec<Case> {
        const PTRACE_ATTACH: u64 = 16;
        const PTRACE_SEIZE: u64 = 0x4206;
        const SUSPEND_SECCOMP: u64 = 1 << 21;
        const CLONE_NEWUTS: u64 = 0x0400_0000;
        const BPF_MAP_CREATE: u64 = 0;
        const BPF_PROG_GET_NEXT_ID: u64 = 11;
        const BPF_PROG_QUERY: u64 = 16;
        vec![
            Case {
                row: Syscall::N_syslog,
                check: syslog,
                args: [3, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_perf_event_open,
                check: perf_event_open,
                args: [0, 0, u64::MAX, u64::MAX, 0, 0],
                refusal: errno::EACCES,
            },
            Case {
                row: Syscall::N_bpf,
                check: bpf,
                args: [BPF_PROG_GET_NEXT_ID, NO_ID.as_ptr() as u64, 16, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_bpf,
                check: bpf,
                args: [BPF_MAP_CREATE, ARRAY_MAP.as_ptr() as u64, 16, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_bpf,
                check: bpf,
                args: [BPF_PROG_QUERY, NO_ID.as_ptr() as u64, 16, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_userfaultfd,
                check: userfaultfd,
                args: [0; 6],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_ptrace,
                check: ptrace,
                args: [PTRACE_ATTACH, 1, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_ptrace,
                check: ptrace,
                args: [PTRACE_SEIZE, 1, 0, SUSPEND_SECCOMP, 0, 0],
                refusal: errno::EPERM,
            },
            Case {
                row: Syscall::N_unshare,
                check: unshare,
                args: [CLONE_NEWUTS, 0, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    /// One instruction: a program `seccomp_prepare_filter` takes to its
    /// privilege check.
    static ONE_INSTRUCTION: [u64; 2] = [1, 0];

    /// Without `no_new_privs`, a seccomp filter needs `CAP_SYS_ADMIN`
    /// (`EACCES`) once its flags, copy and length pass, and enforcing a
    /// Landlock ruleset needs it (`EPERM`) before anything else.
    fn sandbox_cases() -> Vec<Case> {
        const SECCOMP_SET_MODE_FILTER: u64 = 1;
        vec![
            Case {
                row: Syscall::N_seccomp,
                check: |credential, a| seccomp_as(credential, a, false),
                args: [
                    SECCOMP_SET_MODE_FILTER,
                    0,
                    ONE_INSTRUCTION.as_ptr() as u64,
                    0,
                    0,
                    0,
                ],
                refusal: errno::EACCES,
            },
            Case {
                row: Syscall::N_landlock_restrict_self,
                check: |credential, a| restrict_self_as(credential, a, false),
                args: [u64::MAX, u64::MAX, 0, 0, 0, 0],
                refusal: errno::EPERM,
            },
        ]
    }

    /// Handing the process keyring (made on demand) to root needs
    /// `CAP_SYS_ADMIN` (`EACCES`).
    fn key_cases() -> Vec<Case> {
        const KEYCTL_CHOWN: u64 = 4;
        const KEY_SPEC_PROCESS_KEYRING: i64 = -2;
        vec![Case {
            row: Syscall::N_keyctl,
            check: keyctl,
            args: [
                KEYCTL_CHOWN,
                KEY_SPEC_PROCESS_KEYRING as u64,
                0,
                u64::from(u32::MAX),
                0,
                0,
            ],
            refusal: errno::EACCES,
        }]
    }

    /// `PTRACE_O_SUSPEND_SECCOMP` needs `CAP_SYS_ADMIN`; past it, seizing
    /// the caller's own thread group is still refused, for every credential.
    #[test]
    fn a_granted_option_still_meets_the_thread_group_check() {
        const PTRACE_SEIZE: u64 = 0x4206;
        const SUSPEND_SECCOMP: u64 = 1 << 21;
        let own = crate::registry::IDENTITY_PID as u64;
        let seize = [PTRACE_SEIZE, own, 0, SUSPEND_SECCOMP, 0, 0];
        assert_eq!(ptrace(&holding(0), &seize), refuse(errno::EPERM));
        assert_eq!(
            ptrace(&holding(Capability::ALL), &seize),
            refuse(errno::EPERM)
        );
        assert!(matches!(
            ptrace(credential(), &[0; 6]),
            Err(Unmodeled::Path(_))
        ));
    }
}
