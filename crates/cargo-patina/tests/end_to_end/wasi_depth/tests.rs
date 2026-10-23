//! WASI depth telemetry, determinism, and report controls.

use super::*;

// Depth is a measurement, so it obeys the same determinism contract as every other
// Patina observation: byte-identical for one seed across record -> replay, while a
// different seed moves it (otherwise the "measurement" would be a constant and the
// campaign's novelty signal inert). The structured envelope carries the same facts.
//
// A WASI guest executes in the supervisor process, so its report knobs come from
// the supervisor's environment rather than a forwarded child environment: a
// different path from native's, resolved through the same table and parser. The
// depth line is the one report the supervisor itself appends, so it is the one
// that would break if the unified resolution stopped reaching this family.
#[test]
fn wasi_depth_replays_varies_by_seed_and_is_suppressed_by_its_knob() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("depth.wasm");
    fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
    let module_path = module.to_str().unwrap().to_string();
    let run = |arguments: &[&str], envs: &[(&str, &str)]| {
        let output = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            arguments,
            envs,
        );
        assert!(
            output.status.success(),
            "WASI depth guest {arguments:?} failed:\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let trace = directory.path().join("depth.patina");
    let trace_path = trace.to_str().unwrap().to_string();
    let recorded = run(
        &["run", &module_path, "--seed", "5", "--record", &trace_path],
        &[],
    );
    let baseline = depth_report_line(&recorded);
    let replayed = run(&["replay", &module_path, &trace_path], &[]);
    assert_eq!(
        baseline,
        depth_report_line(&replayed),
        "replay must reproduce the recorded run's depth exactly"
    );

    // Seed variation: the guest's loop length comes from deterministic entropy, so
    // some seed must report different fuel.
    let varied = (6..16).any(|seed| {
        depth_report_line(&run(
            &["run", &module_path, "--seed", &seed.to_string()],
            &[],
        )) != baseline
    });
    assert!(
        varied,
        "depth never changed across ten seeds; the measurement is inert:\n{baseline}"
    );

    // An import the guest never calls has no row at all: "no depth data" is never
    // spelled as zero.
    let json = run(
        &["run", &module_path, "--seed", "5", "--format", "json"],
        &[],
    );
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let depth = &envelope["depth"];
    assert_eq!(depth["family"], "wasi");
    assert_eq!(depth["hostcalls"]["fd_write"], 1);
    assert_eq!(depth["hostcalls"]["random_get"], 1);
    assert_eq!(depth["hostcalls"]["clock_time_get"], 1);
    assert_eq!(depth["hostcalls_total"], 3);
    assert!(depth["hostcalls"].get("fd_read").is_none());
    assert!(depth["fuel_consumed"].as_u64().unwrap() > 0);
    assert!(
        envelope["markers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|marker| marker.as_str().unwrap().starts_with("PATINA_DEPTH_REPORT ")),
        "the depth marker must surface in the envelope's markers"
    );

    let quiet = run(
        &["run", &module_path, "--seed", "5"],
        &[("PATINA_DEPTH_REPORT", "0")],
    );
    let quiet = String::from_utf8_lossy(&quiet.stderr);
    assert!(
        !quiet.contains("PATINA_DEPTH_REPORT "),
        "PATINA_DEPTH_REPORT=0 did not suppress the WASI depth line; stderr:\n{quiet}"
    );
}
