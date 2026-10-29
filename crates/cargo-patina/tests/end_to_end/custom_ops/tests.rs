//! Native custom operations, replay, faults, and campaign discovery.

use super::*;

/// The native custom-op ABI end to end, on one package build.
///
/// `patina_dst::custom_op_bytes` reaches the shim's three verbs, each call
/// becomes a `custom_op` trace event carrying the label, key, and result bytes,
/// and a replay reproduces the guest's observable output from the recording
/// WITHOUT running `perform` (the counter reads zero). A recording that answers a
/// different question is refused, naming the label.
///
/// The fault knob: eligibility crosses the shim ABI, a fired fault replaces the
/// effect rather than discarding its result, the undeclared operation is
/// untouched, and the plane reports itself.
///
/// The campaign: the knob is a first-class banded knob, so a bug reachable only
/// under a particular custom-op failure PATTERN is found by ordinary campaign
/// exploration and classified through the guest's own verdict.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_custom_ops_record_replay_fault_and_drive_a_campaign() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_sdk_fixture(&pkg, CUSTOM_OP_SDK_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("custom-op-guest");
    invoke(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bin = bin.to_str().unwrap();
    record_replay_and_key_mismatch(directory.path(), bin);
    faults_fire_report_and_replay(directory.path(), bin);
    campaign_finds_a_planted_mishandling(directory.path(), bin);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_replay_and_key_mismatch(directory: &Path, bin: &str) {
    let workspace = native_workspace();
    let trace = directory.join("custom-op.patina");
    let recorded = invoke(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "4",
            "--record",
            trace.to_str().unwrap(),
            "--",
            "record",
        ],
    );
    assert_eq!(
        result_line(&recorded),
        "PATINA_RESULT performed=2 object=etag-7 empty_len=0",
        "the record pass must run both closures:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );

    // Each call is a trace event carrying the label, the key, and the result.
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let events: Vec<_> = bundle
        .resolved_timeline("main")
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.operation {
            patina_dst_abi::Operation::CustomOp { label, key } => Some((label, key, event.outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].0, "s3.get_object");
    assert_eq!(events[0].1, b"bucket/key".to_vec());
    assert_eq!(
        events[0].2,
        patina_dst_abi::Outcome::Bytes(b"etag-7".to_vec())
    );
    assert_eq!(events[1].0, "host.uptime");
    assert!(events[1].1.is_empty(), "the empty key must survive");
    assert_eq!(events[1].2, patina_dst_abi::Outcome::Bytes(Vec::new()));

    // Replay: the guest sees the same values, but `perform` never ran.
    let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
    assert_eq!(
        result_line(&replayed),
        "PATINA_RESULT performed=0 object=etag-7 empty_len=0",
        "replay must reproduce the recorded bytes and run neither closure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&replayed.stderr)
    );

    // A plain seeded run performs for real, exactly like the record pass.
    let plain = invoke(workspace, &["run", bin, "--seed", "4", "--", "record"]);
    assert_eq!(
        result_line(&plain),
        "PATINA_RESULT performed=2 object=etag-7 empty_len=0"
    );

    // A recording that answers a DIFFERENT question is refused, naming the label.
    // Editing the recorded key is how a guest asking something else looks from
    // the replayer's side; the guest binary itself cannot be varied without
    // changing the fingerprint, which would fail for an unrelated reason.
    let mut edited = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let event = edited.timelines[0]
        .decisions
        .iter_mut()
        .find(|event| matches!(event.operation, patina_dst_abi::Operation::CustomOp { .. }))
        .expect("a recorded custom op");
    event.operation = patina_dst_abi::Operation::CustomOp {
        label: "s3.get_object".into(),
        key: b"another/key".to_vec(),
    };
    let mismatched = directory.join("custom-op-mismatch.patina");
    edited.write_atomic(&mismatched).unwrap();
    let refused = invoke_with_deadline(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["replay", bin, mismatched.to_str().unwrap()],
        Duration::from_secs(20),
    )
    .expect("custom-op refusal must terminate rather than deadlock inside the shim");
    assert!(
        !refused.status.success(),
        "a custom-op key mismatch must fail the replay"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("PATINA_CUSTOM_OP_REFUSED label=s3.get_object")
            && stderr.contains("another/key"),
        "the refusal must name the label and the recorded key:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("PATINA_RESULT"),
        "the guest must not carry on past a refused custom op"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn faults_fire_report_and_replay(directory: &Path, bin: &str) {
    let workspace = native_workspace();
    // Knob off: the declared failure is never reached, both closures run.
    let clean = invoke(workspace, &["run", bin, "--seed", "4", "--", "probe"]);
    assert_eq!(
        result_line(&clean),
        "PATINA_RESULT performed=2 faultable=obj-1 plain=7"
    );
    assert!(
        !String::from_utf8_lossy(&clean.stderr).contains("PATINA_CUSTOMOP_FAULT_REPORT"),
        "an unarmed run has no custom-op fault plane to report"
    );

    // Knob at a certain rate: the faultable op returns the guest's declared
    // failure WITHOUT performing, and the op that declared nothing is untouched
    // — so `performed=1` is the whole control in one number.
    let trace = directory.join("custom-op-fault.patina");
    let faulted = invoke(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "4",
            "--custom-op-fail-permille",
            "1000",
            "--record",
            trace.to_str().unwrap(),
            "--",
            "probe",
        ],
    );
    assert_eq!(
        result_line(&faulted),
        "PATINA_RESULT performed=1 faultable=UNAVAILABLE plain=7",
        "the eligible op must fault without performing; the ineligible one must not:\nstderr:\n{}",
        String::from_utf8_lossy(&faulted.stderr)
    );
    let faulted_stderr = String::from_utf8_lossy(&faulted.stderr);
    assert!(
        faulted_stderr
            .contains("PATINA_CUSTOMOP_FAULT_REPORT eligible_ops=1 fail_vacuity_diagnosable=0 faults_injected=1 vacuous=0"),
        "the plane must account for the fault it applied:\n{faulted_stderr}"
    );

    // The fault is in the trace, named as an error rather than as bytes that
    // happen to spell a failure — so triage can tell an injected fault from an
    // upstream one the guest really saw.
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let outcomes: Vec<_> = bundle
        .resolved_timeline("main")
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.operation {
            patina_dst_abi::Operation::CustomOp { label, .. } => Some((label, event.outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert_eq!(outcomes[0].0, "s3.get_object");
    assert!(
        matches!(&outcomes[0].1, patina_dst_abi::Outcome::Error(error)
            if error.message.contains("injected custom-op fault")),
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes[1].1,
        patina_dst_abi::Outcome::Bytes(b"7".to_vec()),
        "the undeclared op keeps its recorded bytes"
    );

    // Flag-free replay: the trace restores the knob and reproduces the fault.
    let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
    assert_eq!(
        result_line(&replayed),
        "PATINA_RESULT performed=0 faultable=UNAVAILABLE plain=7",
        "replay reproduces both operations from the recording, faulted or not:\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stderr)
    );

    // Vacuity, the honest half: the knob armed over a guest that reached no
    // fault-eligible operation at all is a coverage failure, not a clean run.
    let vacuous = invoke(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "4",
            "--custom-op-fail-permille",
            "500",
            "--",
            "bare",
        ],
    );
    let vacuous_stderr = String::from_utf8_lossy(&vacuous.stderr);
    assert!(
        vacuous_stderr.contains("PATINA_CUSTOMOP_FAULT_REPORT eligible_ops=0")
            && vacuous_stderr.contains("vacuous=1")
            && vacuous_stderr.contains("PATINA WARNING: custom-op fault knob inert"),
        "an armed knob that reached nothing eligible must say so loudly:\n{vacuous_stderr}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn campaign_finds_a_planted_mishandling(directory: &Path, bin: &str) {
    let workspace = native_workspace();
    let campaign = |out: &Path, custom_op_faults: bool| {
        let mut args = vec![
            "campaign",
            bin,
            "--gens",
            "12",
            "--faults",
            "--out-dir",
            out.to_str().unwrap(),
        ];
        if custom_op_faults {
            args.push("--custom-op-faults");
        }
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &args)
    };

    // RED twin first: without the declaration the knob is not banded, no fetch
    // ever fails, and the campaign is clean. That is what makes the green leg
    // below evidence about THIS knob rather than about the campaign at large.
    let unbanded_out = directory.join("camp-unbanded");
    let unbanded = campaign(&unbanded_out, false);
    assert_eq!(
        unbanded.status.code(),
        Some(0),
        "with the custom-op band off the planted bug is unreachable:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&unbanded.stdout),
        String::from_utf8_lossy(&unbanded.stderr)
    );

    let out = directory.join("camp");
    let found = campaign(&out, true);
    let stdout = String::from_utf8_lossy(&found.stdout);
    assert_eq!(
        found.status.code(),
        Some(1),
        "the banded campaign must find the planted mishandling:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&found.stderr)
    );
    assert!(
        stdout.contains("VIOLATION"),
        "the finding must be classified through the guest's own verdict:\n{stdout}"
    );
    assert!(
        !stdout.contains("VACUOUS_CUSTOM_OP_FAULT"),
        "no generation may report an inert custom-op plane over a guest that \
         declares one on every fetch:\n{stdout}"
    );
    let signatures = fs::read_to_string(out.join("signatures.json")).unwrap();
    assert!(
        signatures.contains("no-stale-objects-served"),
        "the signature must name the invariant the guest broke:\n{signatures}"
    );
}
