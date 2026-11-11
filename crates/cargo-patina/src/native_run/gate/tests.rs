//! Regression tests for gate.

use super::*;
use crate::UnsupportedPolicy;
use patina_dst_target::NativeEscape;

/// `--allow NAME` against an instruction-class finding:
/// its own name (`instruction@.text+OFF`) moves on every relink, so the
/// CONTAINING symbol its provenance names matches too — scoped to that one
/// function, never `all`. A symbol finding keeps matching only by its own
/// (stable) name; a crate name is not a symbol.
#[test]
fn unsupported_only_matches_an_instruction_finding_by_its_containing_symbol() {
    use patina_dst_target::NativeProvenance;

    let provenance = |containing: Option<&str>| NativeProvenance {
        object: "unknown".into(),
        crate_name: Some("simd".into()),
        containing_symbol: containing.map(str::to_string),
        section: Some(".text".into()),
    };
    let instruction = NativeEscape {
        symbol: "instruction@.text+0x1f40".into(),
        category: "cpu-nondeterminism",
        provenance: vec![provenance(Some("simd::kernel::avx512_sum"))],
        mnemonic: None,
        image: None,
        binding: None,
    };
    let only = |names: &[&str]| {
        UnsupportedPolicy::Only(names.iter().map(|name| name.to_string()).collect())
    };
    assert!(policy_downgrades(
        &only(&["simd::kernel::avx512_sum"]),
        &instruction
    ));
    assert!(policy_downgrades(
        &only(&["instruction@.text+0x1f40"]),
        &instruction
    ));
    assert!(!policy_downgrades(
        &only(&["simd::kernel::other"]),
        &instruction
    ));
    assert!(!policy_downgrades(&only(&["simd"]), &instruction));
    let unattributed = NativeEscape {
        provenance: vec![provenance(None)],
        ..instruction.clone()
    };
    assert!(!policy_downgrades(
        &only(&["simd::kernel::avx512_sum"]),
        &unattributed
    ));
    let symbol = NativeEscape {
        symbol: "rdtsc_helper".into(),
        ..instruction.clone()
    };
    assert!(!policy_downgrades(
        &only(&["simd::kernel::avx512_sum"]),
        &symbol
    ));
    assert!(policy_downgrades(&only(&["rdtsc_helper"]), &symbol));
    assert!(policy_downgrades(&UnsupportedPolicy::All, &instruction));
    assert!(!policy_downgrades(&UnsupportedPolicy::Deny, &instruction));
}

/// A verdict counts code sites (instructions and immediates, named by offset)
/// apart from symbols: a refusal of one `rdrand` is one site, not one symbol.
#[test]
fn finding_counts_keep_sites_apart_from_symbols() {
    let finding = |symbol: &str| NativeEscape {
        symbol: symbol.into(),
        category: "cpu-nondeterminism",
        provenance: Vec::new(),
        mnemonic: None,
        image: None,
        binding: None,
    };
    let findings = [
        finding("instruction@.text+0x10"),
        finding("tzset"),
        finding("immediate@.text+0x20"),
    ];
    assert_eq!(
        FindingCounts::of(&findings),
        FindingCounts {
            symbols: 1,
            sites: 2
        }
    );
    assert_eq!(
        FindingCounts::of(&findings[..1]),
        FindingCounts {
            symbols: 0,
            sites: 1
        }
    );
}
