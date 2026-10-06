//! Native JSON envelopes, failure reports, and timeline rendering.

#[cfg(test)]
mod tests {
    use super::super::*;

    // ---------------------------------------------------------------------------
    // Wave 14: observability — HTML timeline (`--render`/`--report`) and the
    // machine-readable `--format json` result envelope. These prove the render path
    // is a pure read-only consumer (rendering a trace does not change its hash) and
    // that the envelope has a stable, parseable shape for each verb.
    // ---------------------------------------------------------------------------

    // A small threaded guest that touches the scheduler and the filesystem, so its
    // trace has multiple task lanes and fs ops to render.
    const RENDER_GUEST_SOURCE: &str = r#"
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0u64));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let c = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                *c.lock().unwrap() += 1;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = *counter.lock().unwrap();
    std::fs::write("/out.txt", format!("{total}")).unwrap();
    println!("PATINA_RESULT total={total}");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_render_produces_standalone_timeline_and_preserves_replay_hash() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("render_guest.rs");
        fs::write(&source, RENDER_GUEST_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("render-guest");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let trace = directory.path().join("run.patina");
        invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let recorded_bytes = fs::read(&trace).unwrap();

        // Replaying WITH --render must not perturb the trace file (render only reads
        // it and writes a separate HTML file).
        let html = directory.path().join("timeline.html");
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--render",
                html.to_str().unwrap(),
            ],
        );
        assert!(replayed.status.success());
        assert_eq!(
            recorded_bytes,
            fs::read(&trace).unwrap(),
            "rendering a trace changed its bytes — the render path is not read-only"
        );

        let page = fs::read_to_string(&html).unwrap();
        // Well-formed, self-contained HTML.
        assert!(page.starts_with("<!doctype html>"), "missing doctype");
        assert!(page.trim_end().ends_with("</html>"), "unterminated html");
        assert!(
            !page.contains("http://") && !page.contains("https://"),
            "external reference leaked"
        );
        assert!(!page.contains("<script"), "unexpected script tag");
        // The three spawned workers plus the main lane are rendered.
        assert!(page.contains("task 1") && page.contains("task 2") && page.contains("task 3"));
        // Event count on the page reflects the recorded timeline.
        let events = trace_event_count(&trace);
        assert!(
            page.contains(&format!("{events} events")),
            "event count not shown ({events})"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_run_source_json_artifact_names_source_not_tempdir() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source_json.rs");
        fs::write(&source, "fn main() { println!(\"SOURCE_JSON_OK\"); }\n").unwrap();
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                source.to_str().unwrap(),
                "--seed",
                "0",
                "--format",
                "json",
            ],
        );
        assert!(
            output.status.success(),
            "source-first json run failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
        assert_eq!(value["artifact"], source.to_str().unwrap());
        assert!(
            !value["artifact"]
                .as_str()
                .unwrap()
                .contains("patina-run-artifact"),
            "source-first envelope must not name the throwaway build artifact: {value}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_run_json_envelope_has_stable_shape() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("json_guest.rs");
        fs::write(&source, RENDER_GUEST_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("json-guest");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let trace = directory.path().join("run.patina");
        let output = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: serde_json::Value =
            serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
                panic!("--format json stdout was not a single JSON object: {error}\n{stdout}")
            });
        assert_eq!(value["schema"], "patina.result/v1");
        assert_eq!(value["verb"], "run");
        assert_eq!(value["family"], "native");
        assert_eq!(value["result"], "ok");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["seed"], 7);
        assert_eq!(
            value["trace"]["format_version"],
            patina_dst_trace::TRACE_FORMAT_VERSION
        );
        assert!(value["trace"]["event_count"].as_u64().unwrap() > 0);
        // The guest's PATINA_RESULT line is captured and surfaced as a marker.
        assert!(
            value["markers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m.as_str().unwrap().starts_with("PATINA_RESULT")),
            "PATINA_RESULT marker missing from envelope: {value}"
        );
        // Metadata is rendered generically (seed + policy present).
        assert_eq!(value["trace"]["metadata"]["root_seed"], 7);
    }

    // A guest that fails loudly with a violation marker, to exercise the per-failure
    // report and the `violation` classification.
    const PLANTED_FAILURE_SOURCE: &str = r#"
fn main() {
    eprintln!("GUEST_VIOLATION planted two-leaders term=4");
    std::process::exit(3);
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_planted_failure_emits_report_and_json_violation() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("planted.rs");
        fs::write(&source, PLANTED_FAILURE_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("planted");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let trace = directory.path().join("run.patina");
        let report = directory.path().join("report.html");
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--report",
                report.to_str().unwrap(),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(3),
            "planted failure must propagate exit 3"
        );
        let page = fs::read_to_string(&report).unwrap();
        assert!(page.starts_with("<!doctype html>"));
        assert!(
            page.contains("Run failed"),
            "failure summary section missing"
        );
        assert!(
            page.contains("GUEST_VIOLATION planted"),
            "violation line missing from report"
        );

        // The same run under --format json classifies as a violation and echoes the
        // result line.
        let trace2 = directory.path().join("run2.patina");
        let json = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace2.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        assert_eq!(json.status.code(), Some(3));
        let value: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim()).unwrap();
        assert_eq!(value["result"], "violation");
        assert_eq!(value["exit_code"], 3);
        assert_eq!(
            value["result_line"],
            "GUEST_VIOLATION planted two-leaders term=4"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_build_json_envelope_reports_output_and_hash() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("build_json.rs");
        fs::write(&source, "fn main() { println!(\"hi\"); }\n").unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("build-json");
        let output = invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let value: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
        assert_eq!(value["verb"], "build");
        assert_eq!(value["result"], "ok");
        assert_eq!(value["family"], "native");
        assert!(
            value["content_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            value["output_path"]
                .as_str()
                .unwrap()
                .ends_with("build-json")
        );
    }

    // `--render` on a plain seeded run (no trace on disk) is a clear error, not a
    // silent no-op.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn render_without_a_trace_is_rejected() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("no_trace.rs");
        fs::write(&source, "fn main() { println!(\"hi\"); }\n").unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("no-trace");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let html = directory.path().join("out.html");
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--render",
                html.to_str().unwrap(),
            ],
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("recorded or replayed trace"),
            "expected a clear no-trace error, got: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Count flattened v5 events (operations plus lifecycle markers) in the main timeline.
    fn trace_event_count(trace: &Path) -> usize {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
        value["timelines"][0]["decisions"].as_array().unwrap().len()
            + value["timelines"][0]["lifecycle"].as_array().unwrap().len()
    }
}
