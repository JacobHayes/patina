//! Native registry/manifest reverse-association gate, separate from the live oracle.
use patina_dst_syscalls::{modeled_rows_without_probe, Disposition, SYMBOLS, SYSCALLS};
use std::collections::{BTreeMap, BTreeSet};
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

const MANIFEST_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/probes.toml");

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(MANIFEST_PATH)
        .unwrap_or_else(|error| panic!("read {MANIFEST_PATH}: {error}"));
    let manifest: Manifest =
        toml::from_str(&text).unwrap_or_else(|error| panic!("{MANIFEST_PATH}: {error}"));
    // Only explicitly cfg-classified inapplicable associations are omitted.
    // Unknown names remain in the gate and fail, never silently disappear.
    #[cfg(target_arch = "aarch64")]
    let mut manifest = manifest;
    #[cfg(target_arch = "aarch64")]
    for spec in manifest.probe.values_mut() {
        let applicable = |name: &String| {
            !matches!(
                crate::associations::syscall(name),
                Some(crate::associations::Association::ArchitectureUnavailable)
            )
        };
        spec.syscalls.retain(applicable);
        spec.absent.retain(applicable);
    }
    manifest
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
