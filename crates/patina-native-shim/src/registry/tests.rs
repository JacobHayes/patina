//! The registry's completeness gates against the vendored tables (design §3
//! tests (a) and (b)) and the structural invariants the rows must hold. These
//! run on every platform: they read the vendored tables and the rows, never
//! the host kernel.
//!
//! Each gate is proven non-vacuous by a planted failure in the builder report
//! (a removed row, a duplicated number, a mis-numbered row); the assertions
//! name the offending rows so the failure is actionable.

use std::collections::{BTreeMap, BTreeSet};

use super::table::linux_table;
use super::*;

/// (a) Every number the vendored table lists for an arch has exactly one row,
/// and (b) every row's number for that arch is in the table under the row's
/// own name. Runs for both Linux arches.
#[test]
fn every_table_number_has_exactly_one_row_and_every_row_is_in_the_table() {
    for &arch in Arch::ALL {
        let table: BTreeMap<u32, &str> = linux_table(arch)
            .iter()
            .map(|entry| (entry.nr, entry.name))
            .collect();
        let mut seen: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
        for row in SYSCALLS {
            if let Some(nr) = row.nr.for_arch(arch) {
                seen.entry(nr).or_default().push(row.name);
            }
        }
        // (b) every row number is in the table, under the same name.
        let mut wrong: Vec<String> = Vec::new();
        for (nr, names) in &seen {
            match table.get(nr) {
                None => wrong.push(format!("{names:?} claim {nr}, which is not in the table")),
                Some(table_name) if !names.contains(table_name) => wrong.push(format!(
                    "{names:?} claim {nr}, which the table calls {table_name}"
                )),
                Some(_) => {}
            }
        }
        assert!(
            wrong.is_empty(),
            "{}: registry rows disagree with the vendored table:\n  {}",
            arch.name(),
            wrong.join("\n  ")
        );
        // (a) every table number has exactly one row.
        let missing: Vec<String> = table
            .iter()
            .filter(|(nr, _)| !seen.contains_key(nr))
            .map(|(nr, name)| format!("{nr} {name}"))
            .collect();
        let duplicated: Vec<String> = seen
            .iter()
            .filter(|(_, names)| names.len() > 1)
            .map(|(nr, names)| format!("{nr} {names:?}"))
            .collect();
        assert!(
            missing.is_empty() && duplicated.is_empty(),
            "{}: every number in the vendored table needs exactly one registry row.\n  \
             missing rows: {missing:?}\n  duplicated numbers: {duplicated:?}",
            arch.name()
        );
    }
}

/// A row's `Removed` family is exactly the set of numbers the table lists
/// without an implementation, and a `removed` trap class is used by exactly
/// those rows — so a number the kernel drops or revives moves the row.
#[test]
fn removed_rows_are_exactly_the_tables_unimplemented_numbers() {
    let unimplemented: BTreeSet<&str> = linux_table(Arch::X86_64)
        .iter()
        .filter(|entry| !entry.is_implemented())
        .map(|entry| entry.name)
        .collect();
    let removed_rows: BTreeSet<&str> = SYSCALLS
        .iter()
        .filter(|row| row.family == Family::Removed)
        .map(|row| row.name)
        .collect();
    assert_eq!(
        removed_rows, unimplemented,
        "the Removed family must be exactly the table's entry-less numbers"
    );
    for row in SYSCALLS {
        let removed_class = matches!(row.disposition, Disposition::Trap(TRAP_REMOVED));
        assert_eq!(
            removed_class,
            row.family == Family::Removed,
            "{}: trap({TRAP_REMOVED}) and Family::Removed go together",
            row.name
        );
    }
}

/// Names are unique, every trap class is a known one, every routed row and
/// every trap that is not final names the arc that changes it, and no row
/// claims `Absent` yet (that flip belongs to the signals arc).
#[test]
fn rows_are_well_formed() {
    let mut names = BTreeSet::new();
    for row in SYSCALLS {
        assert!(names.insert(row.name), "{}: duplicate row", row.name);
        assert!(
            row.nr.x86_64.is_some(),
            "{}: every row is keyed by an x86_64 number",
            row.name
        );
        assert!(
            !row.reasoning.is_empty(),
            "{}: reasoning is required",
            row.name
        );
        match row.disposition {
            Disposition::Trap(class) => {
                assert!(
                    TRAP_CLASSES.contains(&class),
                    "{}: unknown trap class {class}",
                    row.name
                );
                let final_class = class == TRAP_PROCESS || class == TRAP_PRIVILEGED;
                assert!(
                    final_class || row.closes_in.is_some(),
                    "{}: a trap that is not process/privileged must name the arc that closes it",
                    row.name
                );
            }
            Disposition::Absent => panic!(
                "{}: no row is Absent yet (docs/arcs/syscall-conformance.md §3)",
                row.name
            ),
            _ => {}
        }
        assert!(
            row.probe.is_none(),
            "{}: probes land with the conformance testbed",
            row.name
        );
    }
}

/// Every symbol row that names syscall rows names existing ones; Darwin-only
/// symbols name entries of the vendored xnu table; names are unique; the
/// dispatcher vehicle is exactly `syscall`.
#[test]
fn symbol_rows_reference_real_rows() {
    let syscall_names: BTreeSet<&str> = SYSCALLS.iter().map(|row| row.name).collect();
    let darwin_names: BTreeSet<&str> = table::DARWIN_TABLE
        .lines()
        .filter_map(|line| {
            let inner = line.split_once('{')?.1;
            let before_paren = inner.split_once('(')?.0;
            before_paren.rsplit([' ', '*']).next()
        })
        .collect();
    let mut names = BTreeSet::new();
    for symbol in SYMBOLS {
        assert!(
            names.insert(symbol.name),
            "{}: duplicate symbol row",
            symbol.name
        );
        match symbol.serves {
            Serves::Syscalls(rows) => {
                assert!(
                    !rows.is_empty(),
                    "{}: an empty serves list is LibcOnly",
                    symbol.name
                );
                for name in rows {
                    assert!(
                        syscall_names.contains(name),
                        "{}: serves unknown syscall {name}",
                        symbol.name
                    );
                }
                assert!(
                    symbol.platform != Platform::Darwin,
                    "{}: a Darwin-only symbol names xnu entries",
                    symbol.name
                );
            }
            Serves::Darwin(rows) => {
                assert_eq!(
                    symbol.platform,
                    Platform::Darwin,
                    "{}: Serves::Darwin is for Darwin-only symbols",
                    symbol.name
                );
                for name in rows {
                    assert!(
                        darwin_names.contains(name),
                        "{}: names {name}, which is not in syscalls.master",
                        symbol.name
                    );
                }
            }
            Serves::Dispatcher => assert_eq!(
                symbol.name, "syscall",
                "only the libc syscall(2) vehicle serves every row"
            ),
            Serves::LibcOnly => {}
        }
        if let SymbolStatus::Absent = symbol.status {
            assert_eq!(
                symbol.platform,
                Platform::Linux,
                "{}: Absent rows enumerate the glibc ABI",
                symbol.name
            );
        }
        assert!(
            !is_control_plane_abi(symbol.name),
            "{}: the patina_* ABI is excluded by rule, not listed",
            symbol.name
        );
    }
}

/// The per-arch view is sorted and complete: x86_64 has every row, aarch64 has
/// exactly the table's count.
#[test]
fn rows_for_arch_match_the_table_sizes() {
    assert_eq!(rows_for(Arch::X86_64).len(), 386);
    assert_eq!(rows_for(Arch::Aarch64).len(), 328);
    for &arch in Arch::ALL {
        let rows = rows_for(arch);
        assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
}
