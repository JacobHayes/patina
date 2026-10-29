//! Native JSON envelopes, failure reports, and timeline rendering.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A small threaded guest that touches the scheduler and the filesystem, so its
    // trace has multiple task lanes and fs ops to render. With the `fail` argument
    // it fails loudly with a violation marker instead, for the per-failure report
    // and the `violation` classification.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const RENDER_GUEST_SOURCE: &str = r#"
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("fail") {
        eprintln!("GUEST_VIOLATION planted two-leaders term=4");
        std::process::exit(3);
    }
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

    /// One JSON object on stdout.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn envelope(output: &Output) -> serde_json::Value {
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
            panic!("--format json stdout was not a single JSON object: {error}\n{stdout}")
        })
    }

    // Observability: the machine-readable `--format json` envelope of each verb has
    // a stable, parseable shape, and the HTML timeline (`--render`/`--report`) is a
    // pure read-only consumer: rendering a trace does not change its bytes, and
    // rendering with no trace on disk is a clear error, not a silent no-op.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_json_envelopes_and_html_timelines() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("render_guest.rs");
        fs::write(&source, RENDER_GUEST_SOURCE).unwrap();
        let workspace = native_workspace();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let bin = directory.path().join("render-guest");
        let built = envelope(&invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
                "--format",
                "json",
            ],
        ));
        assert_eq!(built["verb"], "build");
        assert_eq!(built["result"], "ok");
        assert_eq!(built["family"], "native");
        assert!(
            built["content_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            built["output_path"]
                .as_str()
                .unwrap()
                .ends_with("render-guest")
        );

        let trace = directory.path().join("run.patina");
        let value = envelope(&invoke(
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
        ));
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
        // Metadata is rendered generically (seed + policy present).
        assert_eq!(value["trace"]["metadata"]["root_seed"], 7);

        // Replaying WITH --render must not perturb the trace file (render only
        // reads it and writes a separate HTML file).
        let recorded_bytes = fs::read(&trace).unwrap();
        let html = directory.path().join("timeline.html");
        invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--render",
                html.to_str().unwrap(),
            ],
        );
        assert_eq!(
            recorded_bytes,
            fs::read(&trace).unwrap(),
            "rendering a trace changed its bytes: the render path is not read-only"
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

        let untraced = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--render",
                directory.path().join("out.html").to_str().unwrap(),
            ],
        );
        assert!(!untraced.status.success());
        assert!(
            String::from_utf8_lossy(&untraced.stderr).contains("recorded or replayed trace"),
            "expected a clear no-trace error, got: {}",
            String::from_utf8_lossy(&untraced.stderr)
        );

        // A failing run's report carries the failure summary and its violation line.
        let report = directory.path().join("report.html");
        let failed = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                directory.path().join("fail.patina").to_str().unwrap(),
                "--report",
                report.to_str().unwrap(),
                "--",
                "fail",
            ],
        );
        assert_eq!(
            failed.status.code(),
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

        // A source-first run of the same failure echoes its result line and
        // names the source rather than the throwaway build artifact. The guest
        // only PRINTS a violation (no verdict ABI), so the run is a plain
        // failure: nothing classifies guest text.
        let json = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                source.to_str().unwrap(),
                "--seed",
                "1",
                "--format",
                "json",
                "--",
                "fail",
            ],
        );
        assert_eq!(json.status.code(), Some(3));
        let value = envelope(&json);
        assert_eq!(value["result"], "failure");
        assert_eq!(value["exit_code"], 3);
        assert_eq!(
            value["result_line"],
            "GUEST_VIOLATION planted two-leaders term=4"
        );
        assert_eq!(value["artifact"], source.to_str().unwrap());
        assert!(
            !value["artifact"]
                .as_str()
                .unwrap()
                .contains("patina-run-artifact"),
            "source-first envelope must not name the throwaway build artifact: {value}"
        );
    }

    /// Count flattened v5 events (operations plus lifecycle markers) in the main timeline.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn trace_event_count(trace: &Path) -> usize {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
        value["timelines"][0]["decisions"].as_array().unwrap().len()
            + value["timelines"][0]["lifecycle"].as_array().unwrap().len()
    }
}
