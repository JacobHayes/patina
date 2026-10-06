//! The syscall registry's object-level, classification, and conformance
//! cross-gates (design §3 tests (c), (d) and (e)):
//!
//! Probe/manifest associations are gated in the pure conformance library's
//! `src/registry_gate.rs`, using typed native associations rather than foreign
//! inventories. This test retains the independent object/symbol surface gates.
//!
//! * (d) every symbol row names a symbol the compiled shim objects define on
//!   this platform — or, for `Absent`, provably do NOT define — and every
//!   defined public symbol has a row (the `patina_*` runtime ABI is excluded
//!   by the prefix rule, and the Rust objects may export nothing else);
//! * (e) `patina-target`'s classification lists agree with the rows: the
//!   deny-trap list is exactly the `Deny(class)` rows, which are exactly the
//!   trap-calling definitions in the shim's C, and no interposed symbol is in
//!   the deny-trap list; the load-bearing live interposers are rows the shim
//!   defines.
//!
//! The comparisons are pure functions over sets, and the `planted_*` tests
//! feed them doctored inputs so no gate can silently pass.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_native_shim::registry::{Os, Platform, SYMBOLS, SymbolStatus, is_control_plane_abi};
use patina_dst_target::{NATIVE_LINUX_LIVE_INTERPOSERS, native_deny_trap_symbols};

use common::{compile_posix_object, defined_public_symbols, for_each_shim_member, shim_archive};

/// The (d) comparison: what the objects define versus what the rows claim,
/// for one OS. Pure so a planted set can drive it.
#[derive(Debug, Default, PartialEq, Eq)]
struct Gaps {
    /// Defined by the objects, no row (and not the `patina_*` ABI).
    unlisted: Vec<String>,
    /// A non-`Absent` row for this OS the objects do not define.
    undefined: Vec<String>,
    /// An `Absent` row the objects DO define.
    absent_but_defined: Vec<String>,
}

fn gaps(defined: &BTreeSet<String>, os: Os) -> Gaps {
    let mut gaps = Gaps::default();
    let mut rows: BTreeMap<&str, SymbolStatus> = BTreeMap::new();
    for symbol in SYMBOLS {
        if symbol.platform.defines_on(os) || symbol.status == SymbolStatus::Absent {
            rows.insert(symbol.name, symbol.status);
        }
    }
    for name in defined {
        if is_control_plane_abi(name) {
            continue;
        }
        match rows.get(name.as_str()) {
            None => gaps.unlisted.push(name.clone()),
            Some(SymbolStatus::Absent) => gaps.absent_but_defined.push(name.clone()),
            Some(_) => {}
        }
    }
    for (name, status) in rows {
        if status != SymbolStatus::Absent && !defined.contains(name) {
            gaps.undefined.push(name.to_owned());
        }
    }
    gaps
}

fn host_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Darwin
    } else {
        Os::Linux
    }
}

/// (d) The C object's public definitions are exactly the rows for this OS
/// (minus the runtime ABI), and no `Absent` row is defined anywhere.
#[test]
fn every_defined_public_symbol_has_a_row_and_every_row_is_defined() {
    let dir = tempfile::tempdir().unwrap();
    let object_path = compile_posix_object(dir.path());
    let bytes = std::fs::read(&object_path).unwrap();
    let object = object::File::parse(&*bytes).expect("parse the POSIX shim object");
    let mut defined = defined_public_symbols(&object);
    // The Rust objects contribute the `patina_*` runtime ABI (prefix-excluded)
    // and must export nothing else unmangled: the crate deliberately defines no
    // ambient libc name in Rust. Fold them in so the same gap logic judges them.
    let archive = std::fs::read(shim_archive()).unwrap();
    let mut rust_exports = BTreeSet::new();
    for_each_shim_member(&archive, |member| {
        for name in defined_public_symbols(member) {
            if rustc_demangle::try_demangle(&name).is_err() {
                rust_exports.insert(name);
            }
        }
    });
    // rustc emits unmangled globals of its own into the Rust object set: the
    // DWARF EH personality reference, the gdb-scripts section marker, and
    // allocator shims. None is a definition the shim wrote, so none
    // needs a row.
    let toolchain_glue = |name: &str| {
        name.starts_with("DW.ref.")
            || name.starts_with("__rustc_")
            || matches!(
                name,
                "__rust_alloc"
                    | "__rust_alloc_error_handler"
                    | "__rust_alloc_error_handler_should_panic"
                    | "__rust_alloc_zeroed"
                    | "__rust_dealloc"
                    | "__rust_no_alloc_shim_is_unstable"
                    | "__rust_realloc"
            )
    };
    let stray: Vec<&String> = rust_exports
        .iter()
        .filter(|name| !is_control_plane_abi(name) && !toolchain_glue(name))
        .collect();
    assert!(
        stray.is_empty(),
        "the Rust shim objects export unmangled symbols outside the patina_* ABI: {stray:?}"
    );
    defined.extend(
        rust_exports
            .into_iter()
            .filter(|name| !toolchain_glue(name)),
    );

    let gaps = gaps(&defined, host_os());
    assert_eq!(
        gaps,
        Gaps::default(),
        "the symbol registry and the compiled shim objects disagree on {}:\n  \
         defined but no row (add a SymbolRow): {:?}\n  \
         row but not defined (a stale row, or a definition lost from the link): {:?}\n  \
         Absent row that IS defined (flip it to a real status): {:?}",
        host_os().name(),
        gaps.unlisted,
        gaps.undefined,
        gaps.absent_but_defined
    );
}

/// Non-vacuity: a doctored definition set reports each gap direction.
#[test]
fn planted_gaps_are_reported() {
    let mut defined: BTreeSet<String> = SYMBOLS
        .iter()
        .filter(|symbol| symbol.platform.defines_on(Os::Linux))
        .filter(|symbol| symbol.status != SymbolStatus::Absent)
        .map(|symbol| symbol.name.to_owned())
        .collect();
    assert_eq!(
        gaps(&defined, Os::Linux),
        Gaps::default(),
        "the control set is clean"
    );
    // An Absent row, now defined: any one the registry still lists.
    let absent = SYMBOLS
        .iter()
        .find(|symbol| {
            symbol.status == SymbolStatus::Absent && symbol.platform.defines_on(Os::Linux)
        })
        .expect("the registry lists an Absent Linux symbol")
        .name
        .to_owned();
    defined.insert(absent.clone());
    defined.insert("nonesuch".to_owned()); // defined, no row
    defined.remove("read"); // a row the objects lost
    defined.insert("patina_planted".to_owned()); // runtime ABI: excluded by rule
    let gaps = gaps(&defined, Os::Linux);
    assert_eq!(gaps.unlisted, vec!["nonesuch".to_owned()]);
    assert_eq!(gaps.undefined, vec!["read".to_owned()]);
    assert_eq!(gaps.absent_but_defined, vec![absent]);
}

/// (e) Registry agreement on the deny-trap surface, and the interposed rows
/// never in it.
#[test]
fn deny_rows_agree_with_patina_target() {
    let rows: BTreeSet<(String, String)> = SYMBOLS
        .iter()
        .filter_map(|symbol| match symbol.status {
            SymbolStatus::Deny(class) => Some((symbol.name.to_owned(), class.to_owned())),
            _ => None,
        })
        .collect();
    let target: BTreeSet<(String, String)> = native_deny_trap_symbols()
        .iter()
        .map(|(symbol, class)| ((*symbol).to_owned(), (*class).to_owned()))
        .collect();
    assert_eq!(
        rows,
        target,
        "registry Deny rows and patina-target's NATIVE_DENY_TRAP_SYMBOLS differ.\n  \
         rows not in patina-target: {:?}\n  patina-target entries with no Deny row: {:?}",
        rows.difference(&target).collect::<Vec<_>>(),
        target.difference(&rows).collect::<Vec<_>>()
    );
    let trap_names: BTreeSet<&str> = target.iter().map(|(name, _)| name.as_str()).collect();
    let interposed_in_deny: Vec<&str> = SYMBOLS
        .iter()
        .filter(|symbol| {
            matches!(
                symbol.status,
                SymbolStatus::Modeled | SymbolStatus::Partial | SymbolStatus::ControlPlane
            )
        })
        .map(|symbol| symbol.name)
        .filter(|name| trap_names.contains(name))
        .collect();
    assert!(
        interposed_in_deny.is_empty(),
        "an interposed symbol is never in the deny-trap list: {interposed_in_deny:?}"
    );
    // The live-interposer set the Linux link must keep is a set of rows the
    // shim defines on Linux.
    let missing: Vec<&str> = NATIVE_LINUX_LIVE_INTERPOSERS
        .iter()
        .copied()
        .filter(|name| {
            !SYMBOLS.iter().any(|symbol| {
                symbol.name == *name
                    && symbol.platform != Platform::Darwin
                    && symbol.status != SymbolStatus::Absent
                    && !matches!(symbol.status, SymbolStatus::Deny(_))
            })
        })
        .collect();
    assert!(
        missing.is_empty(),
        "NATIVE_LINUX_LIVE_INTERPOSERS names symbols the registry does not define on Linux: {missing:?}"
    );
}

/// Every glibc cancellation point is a compiled shim definition or remains an
/// import the real audit refuses. Paired with registry-derived C AST lints for
/// the contracts of definitions; an import has no C body those lints can inspect.
#[cfg(target_os = "linux")]
#[test]
fn unimplemented_cancellation_points_are_refused_imports() {
    let dir = tempfile::tempdir().unwrap();
    let path = compile_posix_object(dir.path());
    let bytes = std::fs::read(path).unwrap();
    let object = object::File::parse(&*bytes).unwrap();
    let defined = defined_public_symbols(&object);
    let allowed =
        unprotected_cancellation_imports(&defined, patina_dst_target::native_elf_import_allowed);
    assert!(
        allowed.is_empty(),
        "unimplemented glibc cancellation points escape through allowed host imports: {allowed:?}"
    );
}

#[cfg(target_os = "linux")]
fn unprotected_cancellation_imports(
    defined: &BTreeSet<String>,
    import_allowed: impl Fn(&str) -> bool,
) -> Vec<&'static str> {
    patina_dst_native_shim::registry::cancellation::GLIBC_CANCELLATION_POINTS
        .iter()
        .copied()
        .filter(|name| !defined.contains(*name) && import_allowed(name))
        .collect()
}

/// Standalone detector selftest: granting an unimplemented cancellation import
/// must be a finding even though there is no wrapper for the C syntax lint.
#[cfg(target_os = "linux")]
#[test]
fn cancellation_refusal_detector_rejects_planted_allowance() {
    // The planted definition set deliberately lacks this import, independently
    // of how many cancellation points the real shim eventually implements.
    let defined = BTreeSet::new();
    assert_eq!(
        unprotected_cancellation_imports(&defined, |name| name == "aio_suspend"),
        vec!["aio_suspend"]
    );
    assert!(unprotected_cancellation_imports(&defined, |_| false).is_empty());
}
