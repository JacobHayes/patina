//! Coverage, depth, and result marker protocol.

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

pub(super) fn depth_report_line(stdout: &str, stderr: &str) -> Option<DepthReport> {
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(parse_depth_report_line)
}

/// Parse a `PATINA_DEPTH_REPORT` marker back into its structured form. The three
/// fixed keys are reserved; every other `name=count` token is a hostcall row, so
/// a newly counted import needs no parser change. A line whose declared
/// `hostcalls_total` disagrees with its rows is rejected rather than silently
/// re-derived — a truncated depth line must not read as a smaller-but-valid one.
pub(crate) fn parse_depth_report_line(line: &str) -> Option<DepthReport> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PATINA_DEPTH_REPORT" {
        return None;
    }
    let mut family: Option<String> = None;
    let mut fuel_consumed: Option<u64> = None;
    let mut declared_total: Option<u64> = None;
    let mut hostcalls: Vec<(String, u64)> = Vec::new();
    for part in parts {
        let (key, value) = part.split_once('=')?;
        match key {
            "family" => family = Some(value.to_string()),
            "fuel_consumed" => fuel_consumed = Some(value.parse().ok()?),
            "hostcalls_total" => declared_total = Some(value.parse().ok()?),
            name => hostcalls.push((name.to_string(), value.parse().ok()?)),
        }
    }
    let report = DepthReport {
        family: family?,
        fuel_consumed: fuel_consumed?,
        hostcalls,
    };
    if report.hostcalls_total() != declared_total? {
        return None;
    }
    Some(report)
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
