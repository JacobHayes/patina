//! Coverage and result marker protocol.

use super::*;

pub(super) fn coverage_report_line(stdout: &str, stderr: &str) -> Option<CoverageReport> {
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(parse_coverage_report_line)
}

fn parse_coverage_report_line(line: &str) -> Option<CoverageReport> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PATINA_COVERAGE_REPORT" {
        return None;
    }
    let mut edges_total = None;
    let mut edges_covered = None;
    let mut covered_permille = None;
    let mut hits_total = None;
    let mut hits_max = None;
    let mut saturated = None;
    for part in parts {
        let (key, value) = part.split_once('=')?;
        match key {
            "edges_total" => edges_total = value.parse().ok(),
            "edges_covered" => edges_covered = value.parse().ok(),
            "covered_permille" => covered_permille = value.parse().ok(),
            "hits_total" => hits_total = value.parse().ok(),
            "hits_max" => hits_max = value.parse().ok(),
            "saturated" => saturated = value.parse().ok(),
            _ => {}
        }
    }
    Some(CoverageReport {
        edges_total: edges_total?,
        edges_covered: edges_covered?,
        covered_permille: covered_permille?,
        hits_total: hits_total?,
        hits_max: hits_max?,
        saturated: saturated?,
        map_path: None,
    })
}

/// The single most representative result line for the failure summary: a
/// violation marker if present, else the guest's `PATINA_RESULT`, else the last
/// non-empty stderr line.
pub(super) fn result_line(stdout: &str, stderr: &str) -> Option<String> {
    let combined: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
    for needle in ["PATINA_VIOLATION", "VIOLATION", "mismatch"] {
        if let Some(line) = combined.iter().find(|l| l.contains(needle)) {
            return Some(line.trim().to_string());
        }
    }
    if let Some(line) = combined
        .iter()
        .find(|l| l.trim_start().starts_with("PATINA_RESULT"))
    {
        return Some(line.trim().to_string());
    }
    stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
}

#[cfg(test)]
mod tests;
