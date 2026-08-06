//! Parser and aggregation for runtime `PATINA_SDK_REPORT` lines.
//!
//! This is the single cargo-patina parser for the runtime report format emitted
//! by `patina-dst-runtime::emit_sdk_report`. The format is intentionally strict:
//! Wave 2 adds a required trailing `|@<file:line>` site identity to every
//! `site=` token, and old rows without it are malformed rather than accepted as
//! a compatibility alias.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::CliError;

const PREFIX: &str = "PATINA_SDK_REPORT ";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SdkReport {
    pub(crate) enabled: Option<bool>,
    pub(crate) sites: Vec<SdkSiteReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SdkSiteReport {
    pub(crate) label: String,
    pub(crate) kind: String,
    pub(crate) active: bool,
    pub(crate) evals: u64,
    pub(crate) fires: u64,
    pub(crate) reachable: bool,
    pub(crate) sometimes_satisfied: bool,
    pub(crate) always_violated: bool,
    pub(crate) knob: Option<i64>,
    pub(crate) site: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ExercisedSite {
    pub(crate) label: String,
    pub(crate) kind: String,
    pub(crate) site: String,
    pub(crate) runs_registered: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) runs_active: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) evals: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) fires: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) runs_fired: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) sometimes_satisfied_runs: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) reachable_runs: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) always_violated_runs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) knob_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) knob_max: Option<i64>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl ExercisedSite {
    fn add(&mut self, site: &SdkSiteReport) {
        if self.kind.is_empty() {
            self.kind = site.kind.clone();
        } else if self.kind != site.kind {
            // Keep the first kind as the stable key-level descriptor. The raw
            // rows remain visible through parser tests; a future campaign feed
            // can classify kind conflicts if a real workload ever triggers one.
        }
        if self.site.is_empty() {
            self.site = site.site.clone();
        }
        self.runs_registered += 1;
        if site.active {
            self.runs_active += 1;
        }
        self.evals += site.evals;
        self.fires += site.fires;
        if site.fires > 0 {
            self.runs_fired += 1;
        }
        if site.sometimes_satisfied {
            self.sometimes_satisfied_runs += 1;
        }
        if site.reachable {
            self.reachable_runs += 1;
        }
        if site.always_violated {
            self.always_violated_runs += 1;
        }
        if let Some(knob) = site.knob {
            self.knob_min = Some(self.knob_min.map_or(knob, |old| old.min(knob)));
            self.knob_max = Some(self.knob_max.map_or(knob, |old| old.max(knob)));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExercisedSource {
    pub(crate) path: String,
    pub(crate) reports: usize,
    pub(crate) sites: BTreeMap<String, ExercisedSite>,
}

/// Parse every `PATINA_SDK_REPORT` line in `path` and aggregate rows by label.
/// A file with no report line, or any malformed report row, fails loudly.
pub(crate) fn parse_exercised_file(path: &Path) -> Result<ExercisedSource, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read exercised SDK report file {}: {error}",
            path.display()
        ))
    })?;
    let mut reports = 0_usize;
    let mut sites: BTreeMap<String, ExercisedSite> = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(PREFIX) {
            continue;
        }
        let report = parse_report_line(line)
            .map_err(|error| CliError(format!("{}:{}: {error}", path.display(), index + 1)))?;
        reports += 1;
        for site in report.sites {
            sites
                .entry(site.label.clone())
                .or_insert_with(|| ExercisedSite {
                    label: site.label.clone(),
                    ..ExercisedSite::default()
                })
                .add(&site);
        }
    }
    if reports == 0 {
        return Err(CliError(format!(
            "exercised SDK report file {} contained no PATINA_SDK_REPORT lines",
            path.display()
        )));
    }
    Ok(ExercisedSource {
        path: path.display().to_string(),
        reports,
        sites,
    })
}

pub(crate) fn parse_report_line(line: &str) -> Result<SdkReport, String> {
    let rest = line
        .strip_prefix(PREFIX)
        .ok_or_else(|| "SDK report line must start with PATINA_SDK_REPORT".to_string())?;
    let mut enabled = None;
    let mut sites = Vec::new();
    for token in rest.split_whitespace() {
        if let Some(body) = token.strip_prefix("site=") {
            sites.push(parse_site_token(body)?);
        } else if let Some(value) = token.strip_prefix("enabled=") {
            enabled = Some(parse_header_bool("enabled", value)?);
        }
    }
    Ok(SdkReport { enabled, sites })
}

fn parse_site_token(body: &str) -> Result<SdkSiteReport, String> {
    let parts = body.split('|').collect::<Vec<_>>();
    if parts.len() != 10 {
        return Err(format!(
            "malformed SDK site token {body:?}: expected 10 pipe-separated fields including trailing |@<file:line>"
        ));
    }
    let label = required_text("label", parts[0])?;
    let kind = parse_kind(parts[1])?.to_string();
    let active = parse_prefixed_bool("active", parts[2], 'a')?;
    let evals = parse_prefixed_u64("evals", parts[3], 'e')?;
    let fires = parse_prefixed_u64("fires", parts[4], 'f')?;
    let reachable = parse_prefixed_bool("reachable", parts[5], 'r')?;
    let sometimes_satisfied = parse_prefixed_bool("sometimes_satisfied", parts[6], 's')?;
    let always_violated = parse_prefixed_bool("always_violated", parts[7], 'v')?;
    let knob = parse_knob(parts[8])?;
    let site = parts[9]
        .strip_prefix('@')
        .ok_or_else(|| format!("site identity field must start with @ in {body:?}"))?;
    let site = required_text("site identity", site)?;
    Ok(SdkSiteReport {
        label: label.to_string(),
        kind,
        active,
        evals,
        fires,
        reachable,
        sometimes_satisfied,
        always_violated,
        knob,
        site: site.to_string(),
    })
}

fn required_text<'a>(name: &str, value: &'a str) -> Result<&'a str, String> {
    if value.is_empty() {
        Err(format!("SDK report {name} must not be empty"))
    } else {
        Ok(value)
    }
}

fn parse_kind(value: &str) -> Result<&str, String> {
    match value {
        "fault" | "delay" | "knob" | "always" | "sometimes" | "reachable" => Ok(value),
        other => Err(format!("unknown SDK report site kind {other:?}")),
    }
}

fn parse_header_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(format!("SDK report {name} must be 0 or 1; got {other:?}")),
    }
}

fn parse_prefixed_bool(name: &str, value: &str, prefix: char) -> Result<bool, String> {
    let rest = value.strip_prefix(prefix).ok_or_else(|| {
        format!("SDK report {name} field must start with {prefix:?}; got {value:?}")
    })?;
    parse_header_bool(name, rest)
}

fn parse_prefixed_u64(name: &str, value: &str, prefix: char) -> Result<u64, String> {
    let rest = value.strip_prefix(prefix).ok_or_else(|| {
        format!("SDK report {name} field must start with {prefix:?}; got {value:?}")
    })?;
    rest.parse::<u64>()
        .map_err(|_| format!("SDK report {name} must be an unsigned integer; got {rest:?}"))
}

fn parse_knob(value: &str) -> Result<Option<i64>, String> {
    let rest = value
        .strip_prefix('k')
        .ok_or_else(|| format!("SDK report knob field must start with 'k'; got {value:?}"))?;
    if rest == "-" {
        Ok(None)
    } else {
        rest.parse::<i64>()
            .map(Some)
            .map_err(|_| format!("SDK report knob value must be an integer or '-'; got {rest:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wave2_site_rows_with_file_line_identity() {
        let parsed = parse_report_line(
            "PATINA_SDK_REPORT enabled=1 sites_registered=2 \
             site=commit|fault|a1|e3|f2|r1|s0|v0|k-|@src/main.rs:9 \
             site=batch|knob|a1|e0|f0|r1|s0|v0|k42|@src/main.rs:4",
        )
        .unwrap();
        assert_eq!(parsed.enabled, Some(true));
        assert_eq!(parsed.sites.len(), 2);
        assert_eq!(parsed.sites[0].label, "commit");
        assert_eq!(parsed.sites[0].site, "src/main.rs:9");
        assert_eq!(parsed.sites[0].fires, 2);
        assert_eq!(parsed.sites[1].knob, Some(42));
    }

    #[test]
    fn rejects_legacy_site_rows_without_file_line_identity() {
        let error =
            parse_report_line("PATINA_SDK_REPORT enabled=1 site=commit|fault|a1|e3|f2|r1|s0|v0|k-")
                .unwrap_err();
        assert!(
            error.contains("expected 10 pipe-separated fields"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn aggregates_multiple_reports_by_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stderr.log");
        fs::write(
            &path,
            "noise\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:3\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e2|f0|r1|s1|v0|k-|@src/main.rs:3\n",
        )
        .unwrap();
        let source = parse_exercised_file(&path).unwrap();
        assert_eq!(source.reports, 2);
        let site = &source.sites["x"];
        assert_eq!(site.runs_registered, 2);
        assert_eq!(site.evals, 3);
        assert_eq!(site.reachable_runs, 2);
        assert_eq!(site.sometimes_satisfied_runs, 1);
    }
}
