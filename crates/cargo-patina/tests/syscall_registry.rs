//! The syscall registry's object-level, classification, and conformance
//! cross-gates (design §3 tests (c), (d) and (e)):
//!
//! * (c) the registry and the conformance testbed's `probes.toml` agree both
//!   ways: every `probe` a syscall or symbol row names is a probe that covers
//!   that row, every row/symbol the manifest names exists (an `absent` row is
//!   `Absent`, an exercised row is not), and every `Modeled` syscall row
//!   without a probe is reported — a failure under
//!   `PATINA_CONFORMANCE_STRICT=1` (VALIDATION.md);
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

use patina_dst_native_shim::registry::{
    Disposition, Os, Platform, SYMBOLS, SYSCALLS, SymbolStatus, is_control_plane_abi,
    modeled_rows_without_probe,
};
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
    // DWARF EH personality reference, the gdb-scripts section marker, and (on
    // MSRV 1.86) allocator shims. None is a definition the shim wrote, so none
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
    defined.insert("copy_file_range".to_owned()); // an Absent row, now defined
    defined.insert("nonesuch".to_owned()); // defined, no row
    defined.remove("read"); // a row the objects lost
    defined.insert("patina_planted".to_owned()); // runtime ABI: excluded by rule
    let gaps = gaps(&defined, Os::Linux);
    assert_eq!(gaps.unlisted, vec!["nonesuch".to_owned()]);
    assert_eq!(gaps.undefined, vec!["read".to_owned()]);
    assert_eq!(gaps.absent_but_defined, vec!["copy_file_range".to_owned()]);
}

/// The identifier argument of a `MACRO(Ident)` invocation at the start of a
/// trimmed `line`, e.g. `PATINA_FRAMEWORK_TRAP(CFArrayCreate)` → `CFArrayCreate`.
fn macro_invocation_arg(line: &str, macro_name: &str) -> Option<String> {
    let rest = line.strip_prefix(macro_name)?.strip_prefix('(')?;
    let end = rest.find(')')?;
    let ident = &rest[..end];
    (!ident.is_empty() && ident.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| ident.to_owned())
}

/// The single string-literal argument of `prefix"…")` in `line`, if present.
fn one_literal_arg(line: &str, prefix: &str) -> Option<String> {
    let rest = line.split_once(prefix)?.1.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// `patina_native_trap("class", "symbol")` → `(class, symbol)`.
fn native_trap_args(line: &str) -> Option<(String, String)> {
    let rest = line.split_once("patina_native_trap(")?.1;
    let mut literals = rest.split('"').skip(1).step_by(2);
    let class = literals.next()?.to_owned();
    let symbol = literals.next()?.to_owned();
    Some((symbol, class))
}

/// Every deny-trap-calling definition in the shim's C, as `(symbol, class)`:
/// the two trap macros' invocations, the explicit `patina_native_trap` sites,
/// and the `patina_process_trap` sites. The macro class is fixed by the macro
/// (its body calls `patina_native_trap` with that literal class).
fn c_deny_traps() -> BTreeSet<(String, String)> {
    let mut set = BTreeSet::new();
    for (_, source) in patina_dst_native_shim::POSIX_C_FAMILY_SOURCES {
        for raw in source.lines() {
            let line = raw.trim_start();
            // Skip preprocessor lines so the macro `#define`/`#undef` are ignored;
            // real invocations sit at column 0 with no leading `#`.
            if !line.starts_with('#') {
                if let Some(symbol) = macro_invocation_arg(line, "PATINA_FRAMEWORK_TRAP") {
                    set.insert((symbol, "macos-framework".to_owned()));
                    continue;
                }
                if let Some(symbol) = macro_invocation_arg(line, "PATINA_INTROSPECTION_TRAP") {
                    set.insert((symbol, "host-introspection".to_owned()));
                    continue;
                }
            }
            if let Some(symbol) = one_literal_arg(line, "patina_process_trap(") {
                set.insert((symbol, "process".to_owned()));
            }
            if let Some((symbol, class)) = native_trap_args(line) {
                set.insert((symbol, class));
            }
        }
    }
    set
}

/// (e) Three-way agreement on the deny-trap surface, and the interposed rows
/// never in it.
#[test]
fn deny_rows_agree_with_patina_target_and_the_c_trap_sites() {
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
    let c = c_deny_traps();
    assert_eq!(
        rows,
        c,
        "registry Deny rows and the shim's C trap sites differ.\n  \
         rows with no trap site (a trap became a real model? flip the row): {:?}\n  \
         trap sites with no Deny row (add one): {:?}",
        rows.difference(&c).collect::<Vec<_>>(),
        c.difference(&rows).collect::<Vec<_>>()
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

/// Non-vacuity for the C parse: the parser sees each trap shape.
#[test]
fn c_trap_parser_recognizes_every_trap_shape() {
    let traps = c_deny_traps();
    assert!(traps.contains(&("fork".to_owned(), "process".to_owned())));
    assert!(traps.contains(&("CFRetain".to_owned(), "macos-framework".to_owned())));
    assert!(traps.contains(&("IOIteratorNext".to_owned(), "host-introspection".to_owned())));
    assert_eq!(traps.len(), native_deny_trap_symbols().len());
}

// ---- (c) registry ↔ probes.toml ---------------------------------------------

/// The conformance manifest as the gate reads it. Unknown keys are refused so
/// a stale `[abi]`/`[since]` table (both live in the registry now) cannot sit
/// in the file unread.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    probe: BTreeMap<String, ProbeSpec>,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ProbeSpec {
    /// Rows the probe exercises (semantics host-checked).
    #[serde(default)]
    syscalls: Vec<String>,
    /// Rows the probe asserts `ENOSYS` for (numbers past the virtual ABI level).
    #[serde(default)]
    absent: Vec<String>,
    /// Symbol rows the `libc` vehicle goes through.
    #[serde(default)]
    symbols: Vec<String>,
}

const MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testbeds/syscall-conformance/probes.toml"
);

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(MANIFEST_PATH)
        .unwrap_or_else(|error| panic!("read {MANIFEST_PATH}: {error}"));
    toml::from_str(&text).unwrap_or_else(|error| panic!("{MANIFEST_PATH}: {error}"))
}

/// A syscall row as the cross-gate sees it.
#[derive(Clone, Copy)]
struct RowView {
    name: &'static str,
    modeled: bool,
    absent: bool,
    probe: Option<&'static str>,
}

/// A symbol row as the cross-gate sees it.
#[derive(Clone, Copy)]
struct SymbolView {
    name: &'static str,
    probe: Option<&'static str>,
}

fn row_views() -> Vec<RowView> {
    SYSCALLS
        .iter()
        .map(|row| RowView {
            name: row.name,
            modeled: row.disposition == Disposition::Modeled,
            absent: row.disposition == Disposition::Absent,
            probe: row.probe,
        })
        .collect()
}

fn symbol_views() -> Vec<SymbolView> {
    SYMBOLS
        .iter()
        .map(|symbol| SymbolView {
            name: symbol.name,
            probe: symbol.probe,
        })
        .collect()
}

/// Every way the registry and the manifest can disagree; each field is one
/// direction, and each is planted below.
#[derive(Debug, Default, PartialEq, Eq)]
struct CrossGaps {
    /// A row names a probe id the manifest does not have.
    unknown_probe: Vec<String>,
    /// A row names a probe that does not list the row (`syscalls`/`absent` for
    /// a syscall row, `symbols` for a symbol row).
    probe_does_not_cover: Vec<String>,
    /// The manifest names a syscall with no registry row.
    unknown_syscall: Vec<String>,
    /// The manifest names a symbol with no symbol row.
    unknown_symbol: Vec<String>,
    /// A manifest `absent` row the registry does not disposition `Absent`, or
    /// an exercised (`syscalls`) row that is `Absent`.
    disposition_mismatch: Vec<String>,
    /// A probe that exercises no row at all.
    empty_probe: Vec<String>,
    /// `Modeled` syscall rows with no probe: reported always, refused under
    /// `PATINA_CONFORMANCE_STRICT=1`.
    modeled_without_probe: Vec<String>,
}

fn cross_gaps(rows: &[RowView], symbols: &[SymbolView], manifest: &Manifest) -> CrossGaps {
    let mut gaps = CrossGaps::default();
    let row_by_name: BTreeMap<&str, &RowView> = rows.iter().map(|row| (row.name, row)).collect();
    let symbol_names: BTreeSet<&str> = symbols.iter().map(|symbol| symbol.name).collect();
    for row in rows {
        if let Some(probe) = row.probe {
            match manifest.probe.get(probe) {
                None => gaps.unknown_probe.push(format!("{} -> {probe}", row.name)),
                Some(spec) => {
                    let covered = spec.syscalls.iter().any(|name| name == row.name)
                        || spec.absent.iter().any(|name| name == row.name);
                    if !covered {
                        gaps.probe_does_not_cover
                            .push(format!("{} -> {probe}", row.name));
                    }
                }
            }
        }
        if row.modeled && row.probe.is_none() {
            gaps.modeled_without_probe.push(row.name.to_owned());
        }
    }
    for symbol in symbols {
        if let Some(probe) = symbol.probe {
            match manifest.probe.get(probe) {
                None => gaps
                    .unknown_probe
                    .push(format!("symbol {} -> {probe}", symbol.name)),
                Some(spec) if !spec.symbols.iter().any(|name| name == symbol.name) => gaps
                    .probe_does_not_cover
                    .push(format!("symbol {} -> {probe}", symbol.name)),
                Some(_) => {}
            }
        }
    }
    for (id, spec) in &manifest.probe {
        if spec.syscalls.is_empty() && spec.absent.is_empty() {
            gaps.empty_probe.push(id.clone());
        }
        for name in &spec.syscalls {
            match row_by_name.get(name.as_str()) {
                None => gaps.unknown_syscall.push(format!("{id}: {name}")),
                Some(row) if row.absent => gaps
                    .disposition_mismatch
                    .push(format!("{id}: exercises {name}, which is Absent")),
                Some(_) => {}
            }
        }
        for name in &spec.absent {
            match row_by_name.get(name.as_str()) {
                None => gaps.unknown_syscall.push(format!("{id}: {name}")),
                Some(row) if !row.absent => gaps
                    .disposition_mismatch
                    .push(format!("{id}: asserts {name} absent, which is not Absent")),
                Some(_) => {}
            }
        }
        for name in &spec.symbols {
            if !symbol_names.contains(name.as_str()) {
                gaps.unknown_symbol.push(format!("{id}: {name}"));
            }
        }
    }
    gaps
}

fn strict() -> bool {
    std::env::var_os("PATINA_CONFORMANCE_STRICT").is_some_and(|value| value == "1")
}

/// (c) The registry's probe ids and the manifest's rows agree both ways. The
/// `Modeled`-without-probe set is printed as a count and names; it fails only
/// under `PATINA_CONFORMANCE_STRICT=1`, the switch the arc flips on once every
/// modeled row has its probe.
#[test]
fn registry_probes_and_the_conformance_manifest_agree() {
    let manifest = manifest();
    let mut gaps = cross_gaps(&row_views(), &symbol_views(), &manifest);
    let unprobed = std::mem::take(&mut gaps.modeled_without_probe);
    assert_eq!(
        unprobed,
        modeled_rows_without_probe(),
        "the registry's own report of unprobed Modeled rows is the gate's"
    );
    println!(
        "modeled rows without a probe: {} ({})",
        unprobed.len(),
        unprobed.join(" ")
    );
    assert_eq!(
        gaps,
        CrossGaps::default(),
        "the syscall registry and {MANIFEST_PATH} disagree:\n  \
         row names a probe the manifest lacks: {:?}\n  \
         row names a probe that does not list it: {:?}\n  \
         manifest names a syscall with no row: {:?}\n  \
         manifest names a symbol with no row: {:?}\n  \
         absent/exercised disposition mismatch: {:?}\n  \
         probe exercises nothing: {:?}",
        gaps.unknown_probe,
        gaps.probe_does_not_cover,
        gaps.unknown_syscall,
        gaps.unknown_symbol,
        gaps.disposition_mismatch,
        gaps.empty_probe
    );
    if strict() {
        assert!(
            unprobed.is_empty(),
            "PATINA_CONFORMANCE_STRICT=1: {} Modeled rows have no conformance probe: {}",
            unprobed.len(),
            unprobed.join(" ")
        );
    }
}

/// Non-vacuity: a doctored registry and a doctored manifest report every
/// direction of (c).
#[test]
fn planted_cross_gaps_are_reported() {
    let manifest = manifest();
    let mut rows = row_views();
    let mut symbols = symbol_views();
    let control = cross_gaps(&rows, &symbols, &manifest);
    assert_eq!(
        CrossGaps {
            modeled_without_probe: control.modeled_without_probe.clone(),
            ..CrossGaps::default()
        },
        control,
        "the control set is clean apart from the reported unprobed rows"
    );

    fn row<'a>(rows: &'a mut [RowView], name: &str) -> &'a mut RowView {
        rows.iter_mut().find(|row| row.name == name).unwrap()
    }
    fn symbol<'a>(symbols: &'a mut [SymbolView], name: &str) -> &'a mut SymbolView {
        symbols
            .iter_mut()
            .find(|symbol| symbol.name == name)
            .unwrap()
    }
    row(&mut rows, "read").probe = Some("nonesuch/probe"); // a probe id the manifest lacks
    row(&mut rows, "write").probe = Some("time/clocks"); // a probe that does not list write
    row(&mut rows, "readv").probe = None; // Modeled, unprobed (already so; stays reported)
    symbol(&mut symbols, "openat").probe = Some("nonesuch/probe");
    symbol(&mut symbols, "close").probe = Some("thread/futex"); // does not list close
    let gaps = cross_gaps(&rows, &symbols, &manifest);
    assert_eq!(
        gaps.unknown_probe,
        vec![
            "read -> nonesuch/probe".to_owned(),
            "symbol openat -> nonesuch/probe".to_owned()
        ]
    );
    assert_eq!(
        gaps.probe_does_not_cover,
        vec![
            "write -> time/clocks".to_owned(),
            "symbol close -> thread/futex".to_owned()
        ]
    );
    assert!(gaps.modeled_without_probe.contains(&"readv".to_owned()));

    let mut manifest = manifest;
    manifest.probe.insert(
        "planted/bad".to_owned(),
        ProbeSpec {
            syscalls: vec!["nonesuch".to_owned(), "fchroot".to_owned()],
            absent: vec!["read".to_owned(), "nonesuch2".to_owned()],
            symbols: vec!["nonesuch_symbol".to_owned()],
        },
    );
    manifest
        .probe
        .insert("planted/empty".to_owned(), ProbeSpec::default());
    let gaps = cross_gaps(&row_views(), &symbol_views(), &manifest);
    assert_eq!(
        gaps.unknown_syscall,
        vec![
            "planted/bad: nonesuch".to_owned(),
            "planted/bad: nonesuch2".to_owned()
        ]
    );
    assert_eq!(
        gaps.unknown_symbol,
        vec!["planted/bad: nonesuch_symbol".to_owned()]
    );
    assert_eq!(
        gaps.disposition_mismatch,
        vec![
            "planted/bad: exercises fchroot, which is Absent".to_owned(),
            "planted/bad: asserts read absent, which is not Absent".to_owned()
        ]
    );
    assert_eq!(gaps.empty_probe, vec!["planted/empty".to_owned()]);
}
