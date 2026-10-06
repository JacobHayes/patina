//! WASI depth telemetry, determinism, and report controls.

use super::*;

fn depth_report_line(output: &Output) -> String {
    let line = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("PATINA_DEPTH_REPORT "))
        .unwrap_or_default()
        .to_string();
    assert!(
        !line.is_empty(),
        "a WASI run must emit PATINA_DEPTH_REPORT:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    line
}

#[cfg(test)]
#[path = "wasi_depth/tests.rs"]
mod tests;
