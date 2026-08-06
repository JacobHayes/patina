//! Parser and aggregation for runtime `PATINA_SDK_REPORT` lines.
//!
//! This is the single cargo-patina parser for the runtime report format emitted
//! by `patina-dst-runtime::emit_sdk_report`. The format is intentionally strict:
//! Wave 2 adds a required trailing `|@<file:line>` site identity to every
//! `site=` token, and old rows without it are malformed rather than accepted as
//! a compatibility alias. Campaigns fold the same rows into `<out>/sites.json`
//! (`patina.campaign.sites/v1`), which `cargo patina sites --exercised` also
//! consumes.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::CliError;

pub(crate) const CAMPAIGN_SITES_SCHEMA: &str = "patina.campaign.sites/v1";
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExercisedSite {
    pub(crate) label: String,
    pub(crate) kind: String,
    pub(crate) site: String,
    pub(crate) first_registered_gen: Option<u64>,
    pub(crate) last_registered_gen: Option<u64>,
    pub(crate) registered_gens: u64,
    pub(crate) satisfied_gens: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) runs_active: u64,
    pub(crate) evals: u64,
    pub(crate) fires: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) runs_fired: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) sometimes_satisfied_runs: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) reachable_runs: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) always_violated_runs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) first_satisfied_gen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) first_satisfied_seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) knob_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) knob_max: Option<i64>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl ExercisedSite {
    fn new(site: &SdkSiteReport) -> Self {
        Self {
            label: site.label.clone(),
            kind: site.kind.clone(),
            site: site.site.clone(),
            ..Self::default()
        }
    }

    fn add(
        &mut self,
        generation: u64,
        seed: Option<u64>,
        site: &SdkSiteReport,
    ) -> Result<(), String> {
        if self.label.is_empty() {
            self.label = site.label.clone();
        } else if self.label != site.label {
            return Err(format!(
                "SDK report label mismatch in aggregate: have {:?}, got {:?}",
                self.label, site.label
            ));
        }
        if self.kind.is_empty() {
            self.kind = site.kind.clone();
        } else if self.kind != site.kind {
            return Err(format!(
                "SDK report label {:?} changed kind from {:?} to {:?}",
                site.label, self.kind, site.kind
            ));
        }
        if self.site.is_empty() {
            self.site = site.site.clone();
        } else if self.site != site.site {
            return Err(format!(
                "SDK report label {:?} changed site identity from {:?} to {:?}",
                site.label, self.site, site.site
            ));
        }

        self.first_registered_gen = Some(
            self.first_registered_gen
                .map_or(generation, |old| old.min(generation)),
        );
        self.last_registered_gen = Some(
            self.last_registered_gen
                .map_or(generation, |old| old.max(generation)),
        );
        self.registered_gens += 1;
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
        if oracle_satisfied(site) {
            self.satisfied_gens += 1;
            if self.first_satisfied_gen.is_none_or(|old| generation < old) {
                self.first_satisfied_gen = Some(generation);
                self.first_satisfied_seed = seed;
            }
        }
        if let Some(knob) = site.knob {
            self.knob_min = Some(self.knob_min.map_or(knob, |old| old.min(knob)));
            self.knob_max = Some(self.knob_max.map_or(knob, |old| old.max(knob)));
        }
        Ok(())
    }

    pub(crate) fn is_oracle(&self) -> bool {
        matches!(self.kind.as_str(), "sometimes" | "reachable")
    }
}

fn oracle_satisfied(site: &SdkSiteReport) -> bool {
    match site.kind.as_str() {
        "sometimes" => site.sometimes_satisfied,
        "reachable" => site.reachable,
        _ => false,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoverageTally {
    pub(crate) generations_observed: u64,
    pub(crate) sites: BTreeMap<String, ExercisedSite>,
}

impl CoverageTally {
    pub(crate) fn observe_generation(
        &mut self,
        generation: u64,
        seed: u64,
        stderr: &str,
    ) -> Result<(), String> {
        self.generations_observed += 1;
        let Some(line) = last_report_line(stderr) else {
            return Ok(());
        };
        self.add_report(generation, Some(seed), line)
    }

    fn add_report(&mut self, generation: u64, seed: Option<u64>, line: &str) -> Result<(), String> {
        let report = parse_report_line(line)?;
        for site in report.sites {
            self.sites
                .entry(site.label.clone())
                .or_insert_with(|| ExercisedSite::new(&site))
                .add(generation, seed, &site)?;
        }
        Ok(())
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "schema": CAMPAIGN_SITES_SCHEMA,
            "generations_observed": self.generations_observed,
            "sites": self.sites.values().collect::<Vec<_>>(),
        })
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Store {
            schema: String,
            generations_observed: u64,
            sites: Vec<ExercisedSite>,
        }

        let store: Store = serde_json::from_value(value.clone())
            .map_err(|error| format!("campaign sites store is invalid: {error}"))?;
        if store.schema != CAMPAIGN_SITES_SCHEMA {
            return Err(format!("unsupported schema {:?}", store.schema));
        }
        let mut sites = BTreeMap::new();
        for site in store.sites {
            validate_site_record(&site)?;
            let label = site.label.clone();
            if sites.insert(label.clone(), site).is_some() {
                return Err(format!("duplicate campaign sites label {label:?}"));
            }
        }
        let tally = Self {
            generations_observed: store.generations_observed,
            sites,
        };
        if tally.to_json() != *value {
            return Err("campaign sites store is not in canonical lossless form".to_string());
        }
        Ok(tally)
    }
}

fn validate_site_record(site: &ExercisedSite) -> Result<(), String> {
    required_text("label", &site.label)?;
    parse_kind(&site.kind)?;
    required_text("site identity", &site.site)?;
    if site.registered_gens == 0 {
        return Err(format!(
            "campaign sites label {:?} has registered_gens=0; absent sites must be omitted until static enumeration lands",
            site.label
        ));
    }
    let first = site.first_registered_gen.ok_or_else(|| {
        format!(
            "campaign sites label {:?} missing first_registered_gen",
            site.label
        )
    })?;
    let last = site.last_registered_gen.ok_or_else(|| {
        format!(
            "campaign sites label {:?} missing last_registered_gen",
            site.label
        )
    })?;
    if first > last {
        return Err(format!(
            "campaign sites label {:?} has first_registered_gen {first} after last_registered_gen {last}",
            site.label
        ));
    }
    if site.satisfied_gens > site.registered_gens {
        return Err(format!(
            "campaign sites label {:?} has satisfied_gens {} greater than registered_gens {}",
            site.label, site.satisfied_gens, site.registered_gens
        ));
    }
    if site.first_satisfied_seed.is_some() && site.first_satisfied_gen.is_none() {
        return Err(format!(
            "campaign sites label {:?} has first_satisfied_seed without first_satisfied_gen",
            site.label
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExercisedSource {
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) reports: usize,
    pub(crate) generations_observed: u64,
    pub(crate) sites: BTreeMap<String, ExercisedSite>,
}

/// Parse an exercised source: either a campaign out-dir (or `sites.json` file)
/// with schema `patina.campaign.sites/v1`, or a raw file containing one or more
/// `PATINA_SDK_REPORT` lines. A source with no report line, a missing campaign
/// store, or any malformed report row fails loudly.
pub(crate) fn parse_exercised_file(path: &Path) -> Result<ExercisedSource, CliError> {
    if path.is_dir() {
        return parse_campaign_sites_store(&path.join("sites.json"), Some(path));
    }

    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read exercised SDK report file {}: {error}",
            path.display()
        ))
    })?;
    if let Ok(json) = serde_json::from_str::<Value>(&text) {
        if json.get("schema").and_then(Value::as_str) == Some(CAMPAIGN_SITES_SCHEMA) {
            return exercised_source_from_store(path, &json);
        }
    }
    parse_raw_report_file(path, &text)
}

fn parse_campaign_sites_store(
    path: &Path,
    display_path: Option<&Path>,
) -> Result<ExercisedSource, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read campaign sites store {}: {error}",
            path.display()
        ))
    })?;
    let json: Value = serde_json::from_str(&text).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    let mut source = exercised_source_from_store(path, &json)?;
    if let Some(display_path) = display_path {
        source.path = display_path.display().to_string();
    }
    Ok(source)
}

fn exercised_source_from_store(path: &Path, json: &Value) -> Result<ExercisedSource, CliError> {
    let tally = CoverageTally::from_json(json).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is invalid: {error}",
            path.display()
        ))
    })?;
    Ok(ExercisedSource {
        kind: "campaign".to_string(),
        path: path.display().to_string(),
        reports: tally.generations_observed as usize,
        generations_observed: tally.generations_observed,
        sites: tally.sites,
    })
}

fn parse_raw_report_file(path: &Path, text: &str) -> Result<ExercisedSource, CliError> {
    let mut reports = 0_usize;
    let mut tally = CoverageTally::default();
    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(PREFIX) {
            continue;
        }
        tally
            .add_report(reports as u64, None, line)
            .map_err(|error| CliError(format!("{}:{}: {error}", path.display(), index + 1)))?;
        reports += 1;
    }
    if reports == 0 {
        return Err(CliError(format!(
            "exercised SDK report file {} contained no PATINA_SDK_REPORT lines",
            path.display()
        )));
    }
    tally.generations_observed = reports as u64;
    Ok(ExercisedSource {
        kind: "sdk_report".to_string(),
        path: path.display().to_string(),
        reports,
        generations_observed: tally.generations_observed,
        sites: tally.sites,
    })
}

pub(crate) fn last_report_line(stderr: &str) -> Option<&str> {
    stderr.lines().rfind(|line| line.starts_with(PREFIX))
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
    fn last_line_wins_and_absent_line_is_ok_for_campaign_observation() {
        let stderr = "noise\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:3\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e2|f0|r1|s1|v0|k-|@src/main.rs:3\n";
        assert!(last_report_line("noise only").is_none());
        let mut tally = CoverageTally::default();
        tally.observe_generation(0, 11, "noise only").unwrap();
        assert_eq!(tally.generations_observed, 1);
        assert!(tally.sites.is_empty());
        tally.observe_generation(1, 12, stderr).unwrap();
        let site = &tally.sites["x"];
        assert_eq!(site.registered_gens, 1);
        assert_eq!(site.satisfied_gens, 1);
        assert_eq!(site.evals, 2);
        assert_eq!(site.first_satisfied_seed, Some(12));
    }

    #[test]
    fn raw_report_file_aggregates_multiple_reports_by_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stderr.log");
        fs::write(
            &path,
            "noise\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:3\nPATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e2|f0|r1|s1|v0|k-|@src/main.rs:3\n",
        )
        .unwrap();
        let source = parse_exercised_file(&path).unwrap();
        assert_eq!(source.kind, "sdk_report");
        assert_eq!(source.reports, 2);
        assert_eq!(source.generations_observed, 2);
        let site = &source.sites["x"];
        assert_eq!(site.registered_gens, 2);
        assert_eq!(site.evals, 3);
        assert_eq!(site.reachable_runs, 2);
        assert_eq!(site.sometimes_satisfied_runs, 1);
        assert_eq!(site.satisfied_gens, 1);
    }

    #[test]
    fn campaign_sites_store_round_trips_and_loads_from_out_dir() {
        let mut tally = CoverageTally::default();
        tally
            .observe_generation(
                0,
                123,
                "PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e4|f0|r1|s0|v0|k-|@src/main.rs:3",
            )
            .unwrap();
        tally
            .observe_generation(
                1,
                456,
                "PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e5|f0|r1|s1|v0|k-|@src/main.rs:3 site=f|fault|a1|e1|f1|r1|s0|v0|k-|@src/main.rs:4",
            )
            .unwrap();
        let json = tally.to_json();
        let loaded = CoverageTally::from_json(&json).unwrap();
        assert_eq!(loaded, tally);
        assert_eq!(json, loaded.to_json());

        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("sites.json"),
            serde_json::to_string_pretty(&json).unwrap(),
        )
        .unwrap();
        let source = parse_exercised_file(dir.path()).unwrap();
        assert_eq!(source.kind, "campaign");
        assert_eq!(source.generations_observed, 2);
        assert_eq!(source.sites["x"].first_satisfied_seed, Some(456));
    }

    #[test]
    fn malformed_rows_fail_loudly() {
        let mut tally = CoverageTally::default();
        let error = tally
            .observe_generation(
                0,
                1,
                "PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-",
            )
            .unwrap_err();
        assert!(
            error.contains("expected 10 pipe-separated fields"),
            "{error}"
        );
    }
}
