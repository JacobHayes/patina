//! Native cooperative SDK fixtures, site reporting, and buggify behavior.

use super::*;
use common::native::Guest;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_sdk_reports_records_replays_and_gates_on_setup() {
    let (package, binary) = sdk_guest();
    let guest = Guest {
        dir: tempdir().unwrap(),
        binary,
    };

    // Every site active and always firing; the run is deterministic and its
    // replay carries no --buggify.
    let flags = ["--buggify=1000", "--buggify-activation-permille", "1000"];
    let (seeded, trace) = guest.assert_recorded(4, &flags);
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
        "SDK report rows must carry file:line identities: {stderr}"
    );
    assert_sites_join_for_campaign(
        &package,
        &guest.binary,
        &[
            "batch",
            "loop-body",
            "early-return",
            "index-is-three",
            "fired-in-bounds",
        ],
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

    // With the setup gate declared but never reached: fatal marker and a
    // nonzero exit, even though buggify itself injected no fault.
    let gated = guest.command(
        "run",
        &[
            "--seed",
            "1",
            "--buggify",
            "--buggify-after-setup",
            "--",
            "no-setup",
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
    // The same guest without the gate declaration runs clean.
    let plain = guest.command("run", &["--seed", "1", "--buggify", "--", "no-setup"]);
    assert!(
        plain.status.success() && String::from_utf8_lossy(&plain.stdout).contains("RESULT"),
        "ungated run should finish cleanly: {}",
        String::from_utf8_lossy(&plain.stderr)
    );
}

// `run --param` reaches the guest through `patina_dst::param`, and the trace
// carries it: the parameter changes how many boundary operations the run makes,
// and a flag-free replay reproduces the recording.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_run_parameter_reaches_the_guest_and_replays_from_the_trace() {
    let (_, binary) = sdk_guest();
    let guest = Guest {
        dir: tempdir().unwrap(),
        binary,
    };
    let result = |output: &Output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("RESULT"))
            .unwrap_or_else(|| panic!("missing RESULT: {output:?}"))
            .to_owned()
    };
    let (recorded, trace) = guest.assert_recorded(4, &["--param", "naps=3"]);
    assert!(
        result(&recorded).ends_with("naps=Some(\"3\")"),
        "{}",
        result(&recorded)
    );
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    assert_eq!(
        bundle.metadata.params.get("naps").map(String::as_str),
        Some("3")
    );
    let unset = guest.assert_run_success(4, &[]);
    assert!(result(&unset).ends_with("naps=None"), "{}", result(&unset));
}

// `minimize --params` reduces a failing native run's parameters: a candidate
// still fails when the run exits as the original did, so the irrelevant
// parameter goes and the load-bearing one shrinks to the smallest failing value.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn minimize_params_reduces_a_failing_native_runs_parameters() {
    let (_, binary) = sdk_guest();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    // A `--param` environment default must not refill a parameter a candidate
    // dropped.
    let output = invoke_in_with_env(
        native_workspace(),
        &[
            "minimize",
            "--params",
            "--",
            patina,
            "run",
            binary.to_str().unwrap(),
            "--seed",
            "4",
            "--param",
            "naps=40",
            "--param",
            "noise=loud",
        ],
        &[("PATINA_PARAM", "naps=40")],
    );
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PATINA_MINIMIZE_PARAMS_COMPLETE"))
        .unwrap_or_else(|| panic!("missing completion: {output:?}"))
        .to_owned();
    assert!(line.contains("params=[naps=5]"), "{line}");
}

// Class pairing: the SDK declaration generates macros and literal descriptors
// together. Every declared macro, a newly added registry row included, emits a
// linked descriptor at its own source line though no run reaches it, and a
// campaign fails coverage on the never-called `reachable!` and joins it back to
// the source through `sites --exercised`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn every_declared_sdk_macro_emits_an_unreached_linked_descriptor() {
    let (package, binary) = sdk_guest();
    let directory = tempdir().unwrap();
    let out = directory.path().join("campaign");
    let campaign = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "campaign",
            binary.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    let campaign_stdout = String::from_utf8_lossy(&campaign.stdout);
    assert_eq!(
        campaign.status.code(),
        Some(1),
        "an unreached reachable site must fail coverage\nstdout:\n{campaign_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&campaign.stderr)
    );
    assert!(
        campaign_stdout.contains("UNMET reachable 'registry-reachable'")
            && campaign_stdout.contains("registered_gens=0"),
        "campaign did not surface the never-called reachable site:\n{campaign_stdout}"
    );

    let source = sdk_main();
    let sites: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("sites.json")).unwrap()).unwrap();
    for metadata in patina_dst::SDK_SITE_MACROS {
        let label = format!("registry-{}", metadata.name);
        let call = format!("let _ = patina_dst::{}!(", metadata.name);
        let source_line = source
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

    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &package,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            out.to_str().unwrap(),
            "--site",
            "registry-reachable",
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

/// A build into a Cargo target directory that already holds another SDK
/// package's binary runs its own: artifact discovery reads Cargo's target
/// directory rather than assuming a binary name. The target is the SDK guest's,
/// and this package is new on every run.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn an_sdk_build_into_a_shared_target_dir_does_not_reuse_another_binary() {
    sdk_guest();
    let directory = tempdir().unwrap();
    let package = directory.path().join("second");
    write_sdk_fixture(
        &package,
        r#"fn main() { println!("SDK_TARGET_COLLISION second"); }"#,
    );
    let workspace = native_workspace();
    let binary = directory.path().join("second-bin");
    invoke_in_with_env(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--output",
            binary.to_str().unwrap(),
        ],
        &[("CARGO_TARGET_DIR", shared_sdk_target().to_str().unwrap())],
    );
    let second = invoke(workspace, &["run", binary.to_str().unwrap(), "--seed", "1"]);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains("SDK_TARGET_COLLISION second") && !stdout.contains("RESULT"),
        "the shared target dir ran another SDK package's binary:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stderr)
    );
}
