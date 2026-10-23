//! Host-alias doctrine: static enforcement over the native shim's own objects.
//!
//! The doctrine (see the shim's `hostapi` module and ARCHITECTURE.md
//! "Host-alias doctrine") requires that shim-internal code never name a public,
//! interposable host symbol as an undefined external — such a name lands in the
//! guest binary's import table and forces a name-based `--allow` that guest code
//! can ride past the audit (the class the macOS dispatch-semaphore Parker escape
//! belonged to). Every host vehicle is instead resolved at runtime through the
//! single `dlsym` primitive.
//!
//! This test enforces that structurally: it scans the shim's *own* compiled
//! object files (isolated from the ~1000 std/dependency members bundled into the
//! staticlib) and fails on any undefined external that the native import audit
//! would deny as a classified escape, given the shim's declared control-plane
//! allowance. The classifier (`patina_dst_target::shim_host_alias_violation`)
//! is the exact predicate the
//! guest-binary audit uses, so the shim is held to the standard it enforces.
//!
//! Red→green: on the pre-doctrine shim (which named `semaphore_wait`,
//! `read$NOCANCEL`, ... directly) this fails; once those route through the alias
//! table it passes with `dlsym` as the only escape-surface residue. The scan
//! must see the shim's own undefined externals, so it cannot pass vacuously;
//! the classifier's planted vehicle names are `patina-target`'s unit test
//! (`shim_host_alias_violation_flags_planted_vehicle_names`).

mod common;

use std::collections::BTreeSet;

use object::{Object, ObjectSymbol};
use patina_dst_target::{shim_control_plane_symbols, shim_host_alias_violation};

use common::{for_each_shim_member, shim_archive};

/// Collect the undefined external symbol names of the shim's *own* object
/// members (named `patina_dst_native_shim-*`), excluding the bundled std/dep
/// members whose imports the shim's strong definitions satisfy at final link.
fn shim_undefined_externals(archive_bytes: &[u8]) -> BTreeSet<String> {
    let mut undefined = BTreeSet::new();
    for_each_shim_member(archive_bytes, |object| {
        for symbol in object.symbols() {
            if symbol.is_undefined()
                && let Ok(name) = symbol.name()
            {
                undefined.insert(name.to_owned());
            }
        }
    });
    undefined
}

/// Run the doctrine classifier over a set of undefined externals, returning the
/// violating `(symbol, category)` pairs.
fn violations(
    undefined: &BTreeSet<String>,
    allow: &BTreeSet<String>,
) -> Vec<(String, &'static str)> {
    let macho = cfg!(target_os = "macos");
    undefined
        .iter()
        .filter_map(|symbol| {
            shim_host_alias_violation(symbol, macho, allow)
                .map(|category| (symbol.clone(), category))
        })
        .collect()
}

#[test]
fn shim_objects_name_no_undeclared_host_escape() {
    let archive = shim_archive();
    let bytes = std::fs::read(&archive).expect("read shim staticlib");
    let undefined = shim_undefined_externals(&bytes);
    assert!(
        !undefined.is_empty(),
        "the shim's own objects name no undefined externals: the scan is vacuous"
    );
    let allow = shim_control_plane_symbols();
    let violations = violations(&undefined, &allow);
    assert!(
        violations.is_empty(),
        "the native shim names {} host escape symbol(s) as undefined externals, \
violating the host-alias doctrine (route them through the hostapi table, or, if \
genuinely a sanctioned vehicle, declare them in shim_control_plane_symbols):\n{}",
        violations.len(),
        violations
            .iter()
            .map(|(symbol, category)| format!("  {symbol} ({category})"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
