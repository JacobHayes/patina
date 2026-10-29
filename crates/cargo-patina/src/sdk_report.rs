//! Cross-generation aggregation of the cooperative-SUT site counters.
//!
//! Each run's counters arrive structured, as the `sdk` object of its
//! `patina.runfacts/v1` document (carried into the `patina.result/v1`
//! envelope). Link-time declarations (`declared_sites`) fold into
//! `<out>/sites.json` (`patina.campaign.sites/v1`) with `registered_gens=0`
//! until an evaluated site (`sites`) registers them. `cargo patina sites
//! --exercised` reads the same store back.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::CliError;

pub(crate) const CAMPAIGN_SITES_SCHEMA: &str = "patina.campaign.sites/v1";

/// One run's `sdk` facts object: the fields the tally folds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct SdkReport {
    #[serde(default)]
    pub(crate) declared_sites: Vec<SdkDeclaredSiteReport>,
    #[serde(default)]
    pub(crate) sites: Vec<SdkSiteReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct SdkDeclaredSiteReport {
    pub(crate) label: String,
    pub(crate) kind: String,
    pub(crate) site: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

    fn declared(site: &SdkDeclaredSiteReport) -> Self {
        Self {
            label: site.label.clone(),
            kind: site.kind.clone(),
            site: site.site.clone(),
            ..Self::default()
        }
    }

    fn reconcile_declaration(&mut self, site: &SdkDeclaredSiteReport) -> Result<(), String> {
        if self.label.is_empty() {
            self.label = site.label.clone();
        } else if self.label != site.label {
            return Err(format!(
                "SDK report declaration label mismatch in aggregate: have {:?}, got {:?}",
                self.label, site.label
            ));
        }
        if self.kind.is_empty() {
            self.kind = site.kind.clone();
        } else if self.kind != site.kind {
            return Err(format!(
                "SDK report label {:?} declaration changed kind from {:?} to {:?}",
                site.label, self.kind, site.kind
            ));
        }
        if self.site.is_empty() {
            self.site = site.site.clone();
        } else if self.site != site.site {
            return Err(format!(
                "SDK report label {:?} declaration changed site identity from {:?} to {:?}",
                site.label, self.site, site.site
            ));
        }
        Ok(())
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
    /// Fold one generation's `sdk` facts, or count a generation that had none
    /// (no cooperative site declared or evaluated).
    pub(crate) fn observe_generation(
        &mut self,
        generation: u64,
        seed: u64,
        sdk: Option<&Value>,
    ) -> Result<(), String> {
        self.generations_observed += 1;
        let Some(sdk) = sdk else {
            return Ok(());
        };
        let report: SdkReport = serde_json::from_value(sdk.clone())
            .map_err(|error| format!("the run's sdk facts are malformed: {error}"))?;
        self.add_report(generation, Some(seed), report)
    }

    fn add_report(
        &mut self,
        generation: u64,
        seed: Option<u64>,
        report: SdkReport,
    ) -> Result<(), String> {
        for site in report.declared_sites {
            validate_identity(&site.label, &site.kind, &site.site)?;
            self.sites
                .entry(site.label.clone())
                .or_insert_with(|| ExercisedSite::declared(&site))
                .reconcile_declaration(&site)?;
        }
        for site in report.sites {
            validate_identity(&site.label, &site.kind, &site.site)?;
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
    validate_identity(&site.label, &site.kind, &site.site)?;
    if site.registered_gens == 0 {
        if site.first_registered_gen.is_some() || site.last_registered_gen.is_some() {
            return Err(format!(
                "campaign sites label {:?} has registered_gens=0 but non-null registration bounds",
                site.label
            ));
        }
        if site.satisfied_gens != 0
            || site.runs_active != 0
            || site.evals != 0
            || site.fires != 0
            || site.runs_fired != 0
            || site.sometimes_satisfied_runs != 0
            || site.reachable_runs != 0
            || site.always_violated_runs != 0
            || site.first_satisfied_gen.is_some()
            || site.first_satisfied_seed.is_some()
            || site.knob_min.is_some()
            || site.knob_max.is_some()
        {
            return Err(format!(
                "campaign sites label {:?} has registered_gens=0 but nonzero exercised counters",
                site.label
            ));
        }
        return Ok(());
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
    pub(crate) path: String,
    pub(crate) generations_observed: u64,
    pub(crate) sites: BTreeMap<String, ExercisedSite>,
}

/// Parse an exercised source: a campaign out-dir, or its `sites.json` store
/// (schema `patina.campaign.sites/v1`). A missing or malformed store fails
/// loudly.
pub(crate) fn parse_exercised_file(path: &Path) -> Result<ExercisedSource, CliError> {
    if path.is_dir() {
        return parse_campaign_sites_store(&path.join("sites.json"), Some(path));
    }
    parse_campaign_sites_store(path, None)
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
        path: path.display().to_string(),
        generations_observed: tally.generations_observed,
        sites: tally.sites,
    })
}

fn validate_identity(label: &str, kind: &str, site: &str) -> Result<(), String> {
    required_text("label", label)?;
    parse_kind(kind)?;
    required_text("site identity", site)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sdk(sites: Value) -> Value {
        json!({"enabled": true, "sites": sites})
    }

    fn site(label: &str, evals: u64, satisfied: bool) -> Value {
        json!({
            "label": label, "kind": "sometimes", "site": "src/main.rs:3",
            "active": false, "evals": evals, "fires": 0, "reachable": true,
            "sometimes_satisfied": satisfied, "always_violated": false, "knob": null,
        })
    }

    #[test]
    fn malformed_sdk_facts_fail_loudly() {
        let mut tally = CoverageTally::default();
        let mut nameless = site("x", 1, false);
        nameless["site"] = json!("");
        assert!(
            tally
                .observe_generation(0, 1, Some(&sdk(json!([nameless]))))
                .is_err()
        );
        let mut unknown_kind = site("x", 1, false);
        unknown_kind["kind"] = json!("maybe");
        assert!(
            tally
                .observe_generation(1, 1, Some(&sdk(json!([unknown_kind]))))
                .is_err()
        );
        assert!(
            tally
                .observe_generation(2, 1, Some(&json!({"sites": 3})))
                .is_err()
        );
    }

    #[test]
    fn a_generation_without_sdk_facts_is_counted_but_folds_nothing() {
        let mut tally = CoverageTally::default();
        tally.observe_generation(0, 11, None).unwrap();
        assert_eq!(tally.generations_observed, 1);
        assert!(tally.sites.is_empty());
        tally
            .observe_generation(1, 12, Some(&sdk(json!([site("x", 2, true)]))))
            .unwrap();
        let site = &tally.sites["x"];
        assert_eq!(site.registered_gens, 1);
        assert_eq!(site.satisfied_gens, 1);
        assert_eq!(site.evals, 2);
        assert_eq!(site.first_satisfied_seed, Some(12));
    }

    #[test]
    fn campaign_sites_store_round_trips_and_loads_from_out_dir() {
        let mut tally = CoverageTally::default();
        tally
            .observe_generation(0, 123, Some(&sdk(json!([site("x", 4, false)]))))
            .unwrap();
        let mut fault = site("f", 1, false);
        fault["kind"] = json!("fault");
        fault["fires"] = json!(1);
        tally
            .observe_generation(1, 456, Some(&sdk(json!([site("x", 5, true), fault]))))
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
        for source in [dir.path().to_path_buf(), dir.path().join("sites.json")] {
            let source = parse_exercised_file(&source).unwrap();
            assert_eq!(source.generations_observed, 2);
            assert_eq!(source.sites["x"].first_satisfied_seed, Some(456));
        }

        // Declared sites that never registered round-trip as zero-registered rows.
        let declared = json!({
            "enabled": true,
            "declared_sites": [
                {"label": "never", "kind": "reachable", "site": "src/main.rs:9"},
                {"label": "maybe", "kind": "sometimes", "site": "src/main.rs:10"},
            ],
            "sites": [{
                "label": "maybe", "kind": "sometimes", "site": "src/main.rs:10",
                "active": false, "evals": 1, "fires": 0, "reachable": true,
                "sometimes_satisfied": false, "always_violated": false, "knob": null,
            }],
        });
        let mut tally = CoverageTally::default();
        tally.observe_generation(0, 7, Some(&declared)).unwrap();
        let never = &tally.sites["never"];
        assert_eq!(never.kind, "reachable");
        assert_eq!(never.registered_gens, 0);
        assert_eq!(never.first_registered_gen, None);
        assert_eq!(tally.sites["maybe"].registered_gens, 1);
        let json = tally.to_json();
        assert_eq!(CoverageTally::from_json(&json).unwrap(), tally);
    }
}
