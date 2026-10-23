//! Registry entries of this target that no scenario covers and no exclusion
//! accounts for: every syscall row, and every symbol row the shim objects of
//! this OS define.

use crate::catalog::{EXCLUSIONS, Entry, Exclusion, SCENARIOS, Scenario};
use patina_dst_syscalls::{Os, SYMBOLS, SYSCALLS, SymbolRow, SyscallRow};

pub struct Uncovered {
    pub syscalls: Vec<&'static SyscallRow>,
    pub symbols: Vec<&'static SymbolRow>,
}

impl Uncovered {
    pub fn is_empty(&self) -> bool {
        self.syscalls.is_empty() && self.symbols.is_empty()
    }
}

/// Whether a scenario covers `entry` or an exclusion accounts for it.
fn accounted(entry: Entry, scenarios: &[&Scenario], exclusions: &[Exclusion]) -> bool {
    exclusions.iter().any(|exclusion| exclusion.entry == entry)
        || scenarios.iter().any(|scenario| match entry {
            Entry::Syscall(row) => {
                scenario.covers.contains(&row) || scenario.asserts_absent.contains(&row)
            }
            Entry::Symbol(name) => scenario.symbols.contains(&name),
        })
}

/// The entries the catalog's scenarios and exclusions leave uncovered.
pub fn uncovered() -> Uncovered {
    uncovered_in(SCENARIOS, EXCLUSIONS)
}

/// The entries `scenarios` and `exclusions` leave uncovered.
pub fn uncovered_in(scenarios: &[&Scenario], exclusions: &[Exclusion]) -> Uncovered {
    let accounted = |entry| accounted(entry, scenarios, exclusions);
    Uncovered {
        syscalls: SYSCALLS
            .iter()
            .filter(|row| !accounted(Entry::Syscall(row.id)))
            .collect(),
        symbols: SYMBOLS
            .iter()
            .filter(|row| row.platform.defines_on(Os::host()))
            .filter(|row| !accounted(Entry::Symbol(row.name)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::DEFAULTS;
    use patina_dst_syscalls::Syscall;

    const COVERS_OPENAT: Scenario = Scenario {
        name: "planted/covers-openat",
        covers: &[Syscall::N_openat],
        symbols: &["openat"],
        ..DEFAULTS
    };

    const EXCLUDES_READV: &[Exclusion] = &[
        Exclusion {
            entry: Entry::Syscall(Syscall::N_readv),
            reason: "planted",
        },
        Exclusion {
            entry: Entry::Symbol("readv"),
            reason: "planted",
        },
    ];

    /// Only an entry neither covered nor excluded is reported, as a syscall
    /// row and as a symbol alike.
    #[test]
    fn only_entries_neither_covered_nor_excluded_are_reported() {
        let report = uncovered_in(&[&COVERS_OPENAT], EXCLUDES_READV);
        for (row, name, reported) in [
            (Syscall::N_openat, "openat", false),
            (Syscall::N_readv, "readv", false),
            (Syscall::N_writev, "writev", true),
        ] {
            assert_eq!(
                report.syscalls.iter().any(|entry| entry.id == row),
                reported,
                "{name} row"
            );
            assert_eq!(
                report.symbols.iter().any(|entry| entry.name == name),
                reported,
                "{name} symbol"
            );
        }
    }
}
