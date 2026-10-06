//! Linux row construction: source implementation state owns Removed/ENOSYS.
use super::{Disposition, Family, Syscall, SyscallRow};

pub(super) const fn r(
    id: Syscall,
    family: Family,
    disposition: Disposition,
    reasoning: &'static str,
    closes_in: Option<&'static str>,
) -> SyscallRow {
    assert!(
        id.is_implemented(),
        "unimplemented syscall must use derived disposition"
    );
    assert!(
        !matches!(family, Family::Removed),
        "implemented syscall cannot be Removed"
    );
    SyscallRow {
        id,
        name: id.name(),
        nr: id.number(),
        family,
        disposition,
        reasoning,
        closes_in,
        since: None,
        capabilities: &[],
    }
}

pub(super) const fn removed(id: Syscall) -> SyscallRow {
    assert!(
        !id.is_implemented(),
        "implemented syscall cannot be Removed"
    );
    SyscallRow {
        id,
        name: id.name(),
        nr: id.number(),
        family: Family::Removed,
        disposition: Disposition::SoftDeny(38),
        reasoning: "The kernel lists this number without an implementation and answers ENOSYS natively; the shim returns ENOSYS byte-identically instead of trapping or reaching the host.",
        closes_in: None,
        since: None,
        capabilities: &[],
    }
}
