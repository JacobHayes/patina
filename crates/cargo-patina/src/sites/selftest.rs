//! Site recognizer detector fixtures and selftests.

use super::*;

pub(super) fn run_selftest() -> Result<i32, CliError> {
    let result = run_selftest_inner()?;
    println!("== sites recognizer selftest ==");
    println!(
        "fixture_sites={} files_scanned={} files_unparsed={} recognizers={}",
        result.sites.len(),
        result.files_scanned,
        result.files_unparsed,
        RECOGNIZER_NAMES.len()
    );
    for kind in KIND_ORDER {
        let count = result
            .sites
            .iter()
            .filter(|site| site.kind == *kind)
            .count();
        if count > 0 {
            println!("  {kind}: {count}");
        }
    }
    println!(
        "sites selftest passed: recognizers fired and wrapper macro stayed an expected static miss"
    );
    Ok(0)
}

fn run_selftest_inner() -> Result<StaticScan, CliError> {
    let dir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create sites selftest fixture: {error}")))?;
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("src")).map_err(|error| {
        CliError(format!(
            "failed to create sites selftest source dir: {error}"
        ))
    })?;
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "sites-fixture"
version = "0.0.0"
edition = "2024"
"#,
    )
    .map_err(|error| CliError(format!("failed to write sites selftest manifest: {error}")))?;
    fs::write(root.join("src/lib.rs"), SELFTEST_LIB).map_err(|error| {
        CliError(format!(
            "failed to write sites selftest source fixture: {error}"
        ))
    })?;
    fs::create_dir_all(root.join("tests")).map_err(|error| {
        CliError(format!(
            "failed to create sites selftest tests dir: {error}"
        ))
    })?;
    fs::write(root.join("tests/prop.rs"), SELFTEST_TEST).map_err(|error| {
        CliError(format!(
            "failed to write sites selftest test fixture: {error}"
        ))
    })?;
    let package = ScanPackage {
        name: "sites-fixture".to_string(),
        root: root.clone(),
        targets: vec![TargetHint {
            src_path: root.join("src/lib.rs"),
            name: "sites_fixture".to_string(),
            context: ContextKind::Src,
        }],
    };
    let scan = scan_packages(root, vec![package], false)?;
    assert_selftest_counts(&scan)?;
    Ok(scan)
}

const SELFTEST_LIB: &str = r#"
use patina_dst::always as renamed_always;
use antithesis_sdk::assert_sometimes as renamed_antithesis_sometimes;

macro_rules! wrapper_fault {
    () => { patina_dst::buggify!("wrapped-static-miss") };
}

pub fn exercise(input: i32) {
    let dynamic = format!("dyn-{input}");
    let _ = patina_dst::buggify!("fq-fault");
    let _ = buggify_with_prob!("bare-fault", 0.5);
    let _ = patina_dst::buggify_delay!("fq-delay");
    let _ = patina_dst::buggify_knob!("fq-knob", 3, 1, 9);
    patina_dst::always!(input >= 0, "fq-always");
    sometimes!(input == 1, "bare-sometimes");
    patina_dst::reachable!("fq-reachable");
    renamed_always!(input != 99, "renamed-always");
    let _ = patina_dst::buggify!(dynamic);

    assert!(input >= 0);
    assert_eq!(input, input);
    assert_ne!(input, -1);
    debug_assert!(input < 1000);
    debug_assert_eq!(input + 1, input + 1);
    debug_assert_ne!(input, -2);
    unreachable!("std unreachable inventory only");

    prop_assert!(input >= 0);
    prop_assert_eq!(input, input);
    prop_assert_ne!(input, -1);
    quickcheck! { fn qc_macro(x: u8) -> bool { x == x } }

    antithesis_sdk::assert_always!(input >= 0, "anti-always");
    assert_always_or_unreachable!(input >= 0, "anti-always-or-unreachable");
    renamed_antithesis_sometimes!(input == 1, "anti-sometimes");
    antithesis_sdk::assert_reachable!("anti-reachable");
    assert_unreachable!("anti-unreachable");

    let _ = wrapper_fault!();
}

#[cfg(test)]
mod tests {
    pub fn test_context() {
        reachable!("cfg-test-reachable");
    }
}
"#;

const SELFTEST_TEST: &str = r#"
#[quickcheck]
fn attr_quickcheck(x: u8) -> bool { x == x }

proptest! {
    #[test]
    fn proptest_case(a in 0u8..10) {
        prop_assert!(a < 10);
    }
}
"#;

fn assert_selftest_counts(scan: &StaticScan) -> Result<(), CliError> {
    if scan.files_unparsed != 0 {
        return Err(CliError(format!(
            "sites selftest fixture failed to parse: {:?}",
            scan.unparsed
        )));
    }
    let counts = count_by_kind(&scan.sites);
    let expected = BTreeMap::from([
        ("fault", 3usize),
        ("delay", 1),
        ("knob", 1),
        ("always", 2),
        ("sometimes", 1),
        ("reachable", 2),
        ("assert", 3),
        ("debug_assert", 3),
        ("prop_assert", 3),
        ("proptest", 1),
        ("quickcheck", 2),
        ("antithesis_always", 2),
        ("antithesis_sometimes", 1),
        ("antithesis_reachable", 1),
        ("antithesis_unreachable", 1),
        ("unreachable", 1),
    ]);
    for (kind, expected) in expected {
        let actual = counts.get(kind).copied().unwrap_or(0);
        if actual != expected {
            return Err(CliError(format!(
                "sites selftest kind {kind} expected {expected}, got {actual}; sites={:#?}",
                scan.sites
            )));
        }
    }
    let dynamic = scan
        .sites
        .iter()
        .find(|site| site.label_dynamic)
        .ok_or_else(|| CliError("sites selftest did not find dynamic-label SDK site".into()))?;
    if dynamic.label.is_some() || dynamic.runtime != "driven" {
        return Err(CliError(format!(
            "sites selftest dynamic label row malformed: {dynamic:#?}"
        )));
    }
    let cfg_test = scan
        .sites
        .iter()
        .find(|site| site.label.as_deref() == Some("cfg-test-reachable"))
        .ok_or_else(|| CliError("sites selftest missed #[cfg(test)] module site".into()))?;
    if cfg_test.context != "test" {
        return Err(CliError(format!(
            "sites selftest expected cfg(test) context, got {}",
            cfg_test.context
        )));
    }
    if scan
        .sites
        .iter()
        .any(|site| site.label.as_deref() == Some("wrapped-static-miss"))
    {
        return Err(CliError(
            "sites selftest wrapper macro was counted; wrapper expansions must remain an expected static miss"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
