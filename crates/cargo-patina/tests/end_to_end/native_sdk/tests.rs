//! Native cooperative SDK fixtures, site reporting, and buggify behavior.

use super::*;

// Class pairing: the SDK declaration generates macros and literal descriptors
// together. Exercise all declared macros through the linked product, including
// a newly added registry row.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn every_declared_sdk_macro_emits_an_unreached_linked_descriptor() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("registry");
    let calls = patina_dst::SDK_SITE_MACROS
        .iter()
        .map(|site| format!("let _ = patina_dst::{};\n", site.fixture))
        .collect::<String>();
    let guest = format!(
        "fn main() {{ patina_dst::lifecycle::setup_complete();\nif std::hint::black_box(false) {{\n{calls}}}\n}}\n"
    );
    write_sdk_fixture(&pkg, &guest);
    let bin = directory.path().join("sdk-registry");
    invoke(
        native_workspace(),
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let out = directory.path().join("campaign");
    let campaign = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "campaign",
            bin.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    let sites: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("sites.json")).unwrap()).unwrap();
    for metadata in patina_dst::SDK_SITE_MACROS {
        let label = format!("registry-{}", metadata.name);
        let call = format!("let _ = patina_dst::{}!(", metadata.name);
        let source_line = guest
            .lines()
            .position(|line| line.starts_with(&call))
            .unwrap()
            + 1;
        let row = sites["sites"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["label"].as_str() == Some(&label))
            .unwrap_or_else(|| panic!("missing descriptor for {}: {sites:#}", metadata.name));
        assert_eq!(row["kind"], metadata.kind);
        assert_eq!(row["site"], format!("src/main.rs:{source_line}"));
        assert_eq!(row["registered_gens"], 0);
        assert_eq!(row["first_registered_gen"], serde_json::Value::Null);
    }
    assert_eq!(
        campaign.status.code(),
        Some(1),
        "unreached reachable site must fail coverage: {campaign:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sdk_fixtures_with_shared_cargo_target_dir_do_not_reuse_stale_binary() {
    let directory = tempdir().unwrap();
    let first_pkg = directory.path().join("first");
    let second_pkg = directory.path().join("second");
    write_sdk_fixture(
        &first_pkg,
        r#"fn main() { println!("SDK_TARGET_COLLISION first"); }"#,
    );
    write_sdk_fixture(
        &second_pkg,
        r#"fn main() { println!("SDK_TARGET_COLLISION second"); }"#,
    );

    let workspace = native_workspace();
    let shared_target = directory.path().join("shared-target");
    let shared_target = shared_target.to_str().unwrap();
    let first_bin = directory.path().join("first-bin");
    let second_bin = directory.path().join("second-bin");
    invoke_in_with_env(
        workspace,
        &[
            "build",
            first_pkg.to_str().unwrap(),
            "--output",
            first_bin.to_str().unwrap(),
        ],
        &[("CARGO_TARGET_DIR", shared_target)],
    );
    invoke_in_with_env(
        workspace,
        &[
            "build",
            second_pkg.to_str().unwrap(),
            "--output",
            second_bin.to_str().unwrap(),
        ],
        &[("CARGO_TARGET_DIR", shared_target)],
    );

    let second = invoke(
        workspace,
        &["run", second_bin.to_str().unwrap(), "--seed", "1"],
    );
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains("SDK_TARGET_COLLISION second"),
        "shared target dir reused the first SDK fixture's stale binary instead of the second:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        !stdout.contains("SDK_TARGET_COLLISION first"),
        "shared target dir ran the first SDK fixture from the second build output:\nstdout:\n{stdout}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_sdk_reports_records_and_replays() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_sdk_fixture(&pkg, BUGGIFY_SDK_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-sdk");
    invoke(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Seeded run with every site active and always firing.
    let flags = ["--buggify=1000", "--buggify-activation-permille", "1000"];
    let seeded = invoke(
        workspace,
        &[
            &["run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
        ]
        .concat(),
    );
    let stdout = String::from_utf8_lossy(&seeded.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&seeded.stderr).into_owned();
    assert!(
        stdout.contains("fired=8"),
        "all sites should fire: {stdout}"
    );
    assert!(
        stderr.contains("PATINA_SDK_REPORT enabled=1"),
        "expected SDK report: {stderr}"
    );
    assert!(
        stderr.contains("total_firings=") && !stderr.contains("total_firings=0"),
        "expected nonzero firings: {stderr}"
    );
    assert!(
        sdk_report_line(&seeded).contains("|@src/main.rs:"),
        "SDK report rows must carry Wave 2 file:line identities: {stderr}"
    );
    assert_sites_join_for_sdk_report(
        &pkg,
        &stderr,
        &[
            "batch",
            "loop-body",
            "early-return",
            "index-is-three",
            "fired-in-bounds",
        ],
    );

    // Record, then replay WITHOUT re-supplying --buggify: byte-identical stdout.
    let trace = directory.path().join("buggify.patina");
    let recorded = invoke(
        workspace,
        &[
            &["run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
            &["--record", trace.to_str().unwrap()][..],
        ]
        .concat(),
    );
    let replayed = invoke(
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "record/replay stdout diverged"
    );
    // Point pin for `--buggify=N` value-form plumbing; class-level pairing:
    // the trace/runtime `+buggify` fingerprint metadata-coherence invariant.
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let buggify = bundle
        .metadata
        .buggify
        .as_ref()
        .expect("value-form --buggify must record an armed SDK config");
    assert_eq!(buggify.fire_permille, 1000);
    assert_eq!(buggify.activation_permille, 1000);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_static_site_table_surfaces_never_called_reachable_in_campaign() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("never");
    write_sdk_fixture(&pkg, BUGGIFY_NEVER_REACHABLE_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-never-reachable");
    invoke(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let out_dir = directory.path().join("campaign");
    let campaign = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "campaign",
            bin.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
    );
    let campaign_stdout = String::from_utf8_lossy(&campaign.stdout);
    assert_eq!(
        campaign.status.code(),
        Some(1),
        "never-called reachable! must fail the campaign coverage gate\nstdout:\n{campaign_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&campaign.stderr)
    );
    assert!(
        campaign_stdout.contains("UNMET reachable 'never-called-reachable'")
            && campaign_stdout.contains("registered_gens=0"),
        "campaign did not surface the never-called reachable site:\n{campaign_stdout}"
    );

    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            out_dir.to_str().unwrap(),
            "--site",
            "never-called-reachable",
            "--format",
            "json",
        ],
    );
    assert!(
        joined.status.success(),
        "sites --exercised campaign out-dir failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    let joined_json: serde_json::Value = serde_json::from_slice(&joined.stdout).unwrap();
    assert_eq!(
        joined_json["unmatched_runtime_labels"], 0,
        "{joined_json:#}"
    );
    assert_eq!(
        joined_json["totals"]["exercised"]["never_exercised"], 1,
        "{joined_json:#}"
    );
    assert_eq!(
        joined_json["sites"][0]["exercised"]["registered_gens"], 0,
        "{joined_json:#}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_duplicate_label_aborts_with_marker() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("dup");
    write_sdk_fixture(&pkg, BUGGIFY_DUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-dup");
    invoke(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(!output.status.success(), "duplicate label must abort");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=same-label"),
        "expected duplicate-label marker: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("unreachable"),
        "guest ran past the duplicate label"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_after_setup_never_called_fails_loudly() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("nosetup");
    write_sdk_fixture(&pkg, BUGGIFY_NO_SETUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-nosetup");
    invoke(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // With the gate declared but never reached: fatal marker + nonzero exit,
    // even though buggify itself injected no fault.
    let gated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify",
            "--buggify-after-setup",
        ],
    );
    assert!(
        !gated.status.success(),
        "declared-but-never-called must fail"
    );
    assert!(
        String::from_utf8_lossy(&gated.stderr).contains("PATINA_BUGGIFY_SETUP_NEVER_CALLED"),
        "expected never-called marker: {}",
        String::from_utf8_lossy(&gated.stderr)
    );

    // Same guest WITHOUT the gate declaration runs clean.
    let plain = invoke(
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1", "--buggify"],
    );
    assert!(
        String::from_utf8_lossy(&plain.stdout).contains("guest-finished"),
        "ungated run should finish cleanly"
    );
}
