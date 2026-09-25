//! SUD rows — the privileged rows, answered as the pinned kernel answers the
//! virtual credential (`crate::identity::credential`).
//!
//! Each row is a pure function of the credential, the virtual kernel's
//! declared configuration, its arguments and the modeled filesystem and
//! descriptor table: the checks the kernel makes before its capability
//! check, in the kernel's order, then the capability check itself
//! ([`gate`]). A credential without the capability gets the kernel's
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

/// What a privileged row answers: the raw return value (`-errno` for a
/// refusal), or the point past which the model does not go.
pub(super) type Answer = Result<i64, Unmodeled>;

/// Where a privileged row's model ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Unmodeled {
    /// The credential holds the capability the kernel checks: what the
    /// kernel then does is not modeled.
    Granted(Capability),
}

/// A refusal: `-errno`.
const fn refuse(code: u32) -> Answer {
    Ok(-(code as i64))
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
        [uts_cases()].into_iter().flatten().collect()
    }

    /// The rows that declare a capability no caller of the model reaches:
    /// the kernel checks it only past a refusal every descriptor or device
    /// of the virtual machine gets.
    const UNREACHABLE: &[Syscall] = &[];

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
}
