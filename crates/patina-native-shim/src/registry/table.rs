//! Parser for the vendored upstream syscall tables under `abi/`.
//!
//! The registry rows are gated against these tables (every number in the
//! table for an arch has exactly one row; every row's numbers exist in the
//! table), and `cargo patina syscalls` prints the table's provenance beside the
//! rows, so the same small parser serves both. The tables are verbatim upstream
//! copies — `scripts/refresh-syscall-tables.sh` re-fetches and diffs them — and
//! carry their own SPDX headers.
//!
//! Which lines of a table an arch uses is the kernel's own rule, restated here:
//!
//! * `syscall_64.tbl` (x86_64): the `common` and `64` ABI columns; `x32` rows
//!   are the x32 ILP32 ABI and never reach a 64-bit process.
//! * `syscall.tbl` (the generic table arm64 has used since 6.11): the `common`
//!   and `64` columns plus the three arm64-selected extras
//!   `arch/arm64/kernel/Makefile.syscalls` names — `renameat`, `rlimit`, and
//!   `memfd_secret`. The `32`/`time32`/`stat64` columns are the 32-bit ABIs
//!   and the remaining columns (`arc`, `csky`, `nios2`, `or1k`, `riscv`) are
//!   other architectures' private numbers.
//!
//! The Darwin table (`syscalls.master`) is vendored so the `(os, arch)` keying
//! is real from day one; it is not parsed yet (a later arc adds the rows).

use super::Arch;

/// The vendored x86_64 table (`arch/x86/entry/syscalls/syscall_64.tbl`).
pub const LINUX_X86_64_TABLE: &str = include_str!("../../abi/linux/syscall_64.tbl");
/// The vendored generic table (`scripts/syscall.tbl`), used by arm64.
pub const LINUX_GENERIC_TABLE: &str = include_str!("../../abi/linux/syscall.tbl");
/// The vendored xnu table (`bsd/kern/syscalls.master`); present, not parsed.
pub const DARWIN_TABLE: &str = include_str!("../../abi/darwin/syscalls.master");

/// One line of a Linux table that the arch's ABI rule selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableEntry {
    pub nr: u32,
    pub abi: &'static str,
    pub name: &'static str,
    /// The kernel entry point, or `None` for a number the table lists without
    /// one (a removed syscall the kernel answers with `ENOSYS`). A literal
    /// `sys_ni_syscall` entry means the same thing and is reported as `None`.
    pub entry: Option<&'static str>,
}

impl TableEntry {
    /// Whether the kernel implements this number at all: `false` for removed
    /// and never-implemented numbers, which the kernel answers with `ENOSYS`.
    pub fn is_implemented(&self) -> bool {
        self.entry.is_some()
    }
}

/// Where a Linux table came from, for the verb's provenance output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSource {
    /// Path under the shim crate.
    pub path: &'static str,
    /// The upstream URL `scripts/refresh-syscall-tables.sh` fetches.
    pub url: &'static str,
    /// The ABI columns the arch selects from the table.
    pub abis: &'static [&'static str],
}

/// The table and ABI-column rule for a Linux arch.
pub fn linux_source(arch: Arch) -> TableSource {
    match arch {
        Arch::X86_64 => TableSource {
            path: "abi/linux/syscall_64.tbl",
            url: "https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl",
            abis: &["common", "64"],
        },
        Arch::Aarch64 => TableSource {
            path: "abi/linux/syscall.tbl",
            url: "https://raw.githubusercontent.com/torvalds/linux/master/scripts/syscall.tbl",
            abis: &["common", "64", "renameat", "rlimit", "memfd_secret"],
        },
    }
}

/// The numbers a Linux arch's kernel dispatches, sorted by number. Panics on a
/// malformed table or on two selected lines sharing a number — the vendored
/// tables are inputs the registry is gated against, so a corrupt one must fail
/// loudly rather than shrink the gate.
pub fn linux_table(arch: Arch) -> Vec<TableEntry> {
    let text = match arch {
        Arch::X86_64 => LINUX_X86_64_TABLE,
        Arch::Aarch64 => LINUX_GENERIC_TABLE,
    };
    let source = linux_source(arch);
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(nr), Some(abi), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!(
                "{}:{}: malformed table line {line:?}",
                source.path,
                index + 1
            );
        };
        let nr: u32 = nr.parse().unwrap_or_else(|error| {
            panic!(
                "{}:{}: bad syscall number {nr:?}: {error}",
                source.path,
                index + 1
            )
        });
        if !source.abis.contains(&abi) {
            continue;
        }
        let entry = fields.next().filter(|entry| *entry != "sys_ni_syscall");
        entries.push(TableEntry {
            nr,
            abi,
            name,
            entry,
        });
    }
    entries.sort_by_key(|entry| entry.nr);
    for pair in entries.windows(2) {
        assert!(
            pair[0].nr != pair[1].nr,
            "{}: number {} appears twice under the {:?} ABI rule ({} and {})",
            source.path,
            pair[0].nr,
            source.abis,
            pair[0].name,
            pair[1].name
        );
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_table_selects_common_and_64_rows() {
        let table = linux_table(Arch::X86_64);
        assert_eq!(
            table.len(),
            386,
            "the vendored x86_64 table has 386 64-bit numbers"
        );
        assert_eq!(
            table[0],
            TableEntry {
                nr: 0,
                abi: "common",
                name: "read",
                entry: Some("sys_read")
            }
        );
        assert!(
            table
                .iter()
                .any(|entry| entry.nr == 13 && entry.abi == "64" && entry.name == "rt_sigaction")
        );
        assert!(
            table.iter().all(|entry| entry.abi != "x32"),
            "x32 rows never reach a 64-bit process"
        );
        // Removed numbers keep their line but have no entry point.
        let uselib = table.iter().find(|entry| entry.name == "uselib").unwrap();
        assert!(!uselib.is_implemented());
        let sysctl = table.iter().find(|entry| entry.name == "_sysctl").unwrap();
        assert!(
            !sysctl.is_implemented(),
            "a literal sys_ni_syscall entry is not an implementation"
        );
    }

    #[test]
    fn aarch64_table_applies_the_arm64_column_rule() {
        let table = linux_table(Arch::Aarch64);
        assert_eq!(
            table.len(),
            328,
            "the vendored generic table has 328 arm64 numbers"
        );
        let by_name = |name: &str| {
            table
                .iter()
                .find(|entry| entry.name == name)
                .map(|entry| entry.nr)
        };
        assert_eq!(
            by_name("renameat"),
            Some(38),
            "arm64 selects the `renameat` column"
        );
        assert_eq!(
            by_name("getrlimit"),
            Some(163),
            "arm64 selects the `rlimit` column"
        );
        assert_eq!(
            by_name("memfd_secret"),
            Some(447),
            "arm64 selects the `memfd_secret` column"
        );
        assert_eq!(
            by_name("fcntl"),
            Some(25),
            "the `64` column wins over the `32` fcntl64 row"
        );
        assert_eq!(by_name("fcntl64"), None);
        assert_eq!(
            by_name("clock_gettime64"),
            None,
            "time64 spellings are the 32-bit ABI"
        );
        assert_eq!(
            by_name("epoll_wait"),
            None,
            "arm64 never had the legacy epoll_wait number"
        );
    }

    #[test]
    fn every_aarch64_name_exists_on_x86_64() {
        // The registry keys rows by x86_64 names; this pins the assumption that
        // arm64 introduces no name of its own, so a row-per-x86_64-name table can
        // carry every arm64 number.
        let x86: std::collections::BTreeSet<&str> = linux_table(Arch::X86_64)
            .iter()
            .map(|entry| entry.name)
            .collect();
        let missing: Vec<&str> = linux_table(Arch::Aarch64)
            .iter()
            .map(|entry| entry.name)
            .filter(|name| !x86.contains(name))
            .collect();
        assert!(
            missing.is_empty(),
            "arm64-only names need rows of their own: {missing:?}"
        );
    }

    #[test]
    fn darwin_table_is_vendored_verbatim() {
        assert!(DARWIN_TABLE.contains("{ int fork(void) NO_SYSCALL_STUB; }"));
    }
}
