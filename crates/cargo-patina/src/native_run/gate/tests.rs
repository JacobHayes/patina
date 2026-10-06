//! Regression tests for gate.

use super::*;
use crate::UnsupportedPolicy;
use patina_dst_target::NativeEscape;

/// `--allow-unsupported-symbols NAME` against an instruction-class finding:
/// its own name (`instruction@.text+OFF`) moves on every relink, so the
/// CONTAINING symbol its provenance names matches too — scoped to that one
/// function, never `all`. A symbol finding keeps matching only by its own
/// (stable) name; a crate name is not a symbol.
#[cfg(unix)]
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
