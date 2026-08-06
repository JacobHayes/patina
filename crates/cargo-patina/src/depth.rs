//! Campaign accumulation of WASI **depth** — fuel plus per-import hostcall
//! counts — and the `depth_plateau` signal derived from it.
//!
//! Depth is deliberately not called coverage (`docs/arcs/coverage-depth.md` §5):
//! `wasm32-wasip1` has no sancov instrumentation, so there are no edges to union.
//! What a WASI campaign can honestly accumulate is how far its guests ran (fuel
//! high-water mark) and which host surface they touched (hostcall kinds), which
//! makes the plateau signal correspondingly weaker — it is named `depth_plateau`
//! everywhere so it can never be read as edge-coverage plateau.
//!
//! The store follows the shared auxiliary-store resume contract in
//! [`crate::aux_store`], exactly like the native coverage store: `fuel_max` is
//! idempotent (a max) but the hostcall sums are not (saturating adds), so a
//! generation already covered by the `generations_applied` watermark contributes
//! nothing on resume.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::CliError;
use crate::aux_store::{AuxFoldDecision, fold_decision, validate_resume_watermark};
use crate::coverage::{
    CoverageArtifact, atomic_write_json, json_optional_u64, json_required_bool, json_required_str,
    json_required_u64,
};
use crate::output::DepthReport;

pub(crate) const CAMPAIGN_DEPTH_SCHEMA: &str = "patina.depth.campaign/v1";

/// The persisted depth accumulation for one campaign out-dir.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CampaignDepthMeta {
    pub(crate) artifact: CoverageArtifact,
    pub(crate) fingerprint: String,
    /// Resume watermark: how many generations the sums below already reflect.
    pub(crate) generations_applied: u64,
    /// How many of those generations actually carried a depth report. A failing
    /// generation can die before the report is emitted, so this is reported
    /// separately rather than assumed equal to `generations_applied` — zero here
    /// is "no depth data", never "zero depth".
    pub(crate) generations_with_depth: u64,
    pub(crate) fuel_max: u64,
    pub(crate) fuel_total: u64,
    /// Cumulative call counts per imported function name, across generations.
    pub(crate) hostcalls: BTreeMap<String, u64>,
    pub(crate) last_new_depth_gen: Option<u64>,
    pub(crate) plateau_window: u64,
    pub(crate) depth_plateaued: bool,
    /// Sparse novelty log: `(generation, new_hostcall_kinds, fuel_max_after)` for
    /// the generations that moved either depth dimension.
    pub(crate) new_depth_log: Vec<(u64, u64, u64)>,
}

impl CampaignDepthMeta {
    fn new(artifact: CoverageArtifact, fingerprint: String, plateau_window: u64) -> Self {
        Self {
            artifact,
            fingerprint,
            generations_applied: 0,
            generations_with_depth: 0,
            fuel_max: 0,
            fuel_total: 0,
            hostcalls: BTreeMap::new(),
            last_new_depth_gen: None,
            plateau_window,
            depth_plateaued: false,
            new_depth_log: Vec::new(),
        }
    }

    pub(crate) fn hostcall_kinds(&self) -> u64 {
        self.hostcalls.len() as u64
    }

    pub(crate) fn hostcalls_total(&self) -> u64 {
        self.hostcalls
            .values()
            .fold(0u64, |total, count| total.saturating_add(*count))
    }

    /// True when the campaign produced generations but none of them carried a
    /// depth report — an accumulation that would otherwise look like a clean
    /// "zero depth" result.
    pub(crate) fn is_vacuous(&self) -> bool {
        self.generations_applied > 0 && self.generations_with_depth == 0
    }

    /// The same exact rule the native edge plateau uses, over the weaker depth
    /// novelty signal: plateaued after generation `g` iff
    /// `g - last_new_depth_gen >= plateau_window`, with `0` disabling it.
    fn update_plateau(&mut self, generation: u64) {
        self.depth_plateaued = self.plateau_window != 0
            && self
                .last_new_depth_gen
                .is_some_and(|last| generation.saturating_sub(last) >= self.plateau_window);
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "schema": CAMPAIGN_DEPTH_SCHEMA,
            "artifact": self.artifact.to_json(),
            "fingerprint": self.fingerprint.clone(),
            "generations_applied": self.generations_applied,
            "generations_with_depth": self.generations_with_depth,
            "fuel_max": self.fuel_max,
            "fuel_total": self.fuel_total,
            "hostcall_kinds": self.hostcall_kinds(),
            "hostcalls_total": self.hostcalls_total(),
            "hostcalls": self.hostcalls.iter().map(|(name, count)| (name.clone(), Value::from(*count))).collect::<serde_json::Map<_, _>>(),
            "last_new_depth_gen": self.last_new_depth_gen,
            "plateau_window": self.plateau_window,
            "depth_plateaued": self.depth_plateaued,
            "new_depth_log": self.new_depth_log.iter().map(|(generation, new_kinds, fuel_max)| json!([generation, new_kinds, fuel_max])).collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "campaign depth meta must be an object".to_string())?;
        let schema = json_required_str(object, "schema")?;
        if schema != CAMPAIGN_DEPTH_SCHEMA {
            return Err(format!("unsupported schema {schema:?}"));
        }
        let hostcalls = object
            .get("hostcalls")
            .and_then(Value::as_object)
            .ok_or_else(|| "hostcalls must be an object".to_string())?
            .iter()
            .map(|(name, count)| {
                Ok((
                    name.clone(),
                    count.as_u64().ok_or_else(|| {
                        format!("hostcall {name} count must be an unsigned integer")
                    })?,
                ))
            })
            .collect::<Result<BTreeMap<String, u64>, String>>()?;
        let new_depth_log = object
            .get("new_depth_log")
            .and_then(Value::as_array)
            .ok_or_else(|| "new_depth_log must be an array".to_string())?
            .iter()
            .map(|entry| {
                let values = entry
                    .as_array()
                    .ok_or_else(|| "new_depth_log entries must be arrays".to_string())?;
                if values.len() != 3 {
                    return Err("new_depth_log entries must have three elements".to_string());
                }
                let field = |index: usize, label: &str| {
                    values[index]
                        .as_u64()
                        .ok_or_else(|| format!("new_depth_log {label} must be an unsigned integer"))
                };
                Ok((
                    field(0, "generation")?,
                    field(1, "new_kinds")?,
                    field(2, "fuel_max")?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let meta = Self {
            artifact: CoverageArtifact::from_json(
                object
                    .get("artifact")
                    .ok_or_else(|| "campaign depth meta missing artifact".to_string())?,
            )?,
            fingerprint: json_required_str(object, "fingerprint")?.to_string(),
            generations_applied: json_required_u64(object, "generations_applied")?,
            generations_with_depth: json_required_u64(object, "generations_with_depth")?,
            fuel_max: json_required_u64(object, "fuel_max")?,
            fuel_total: json_required_u64(object, "fuel_total")?,
            hostcalls,
            last_new_depth_gen: json_optional_u64(object, "last_new_depth_gen")?,
            plateau_window: json_required_u64(object, "plateau_window")?,
            depth_plateaued: json_required_bool(object, "depth_plateaued")?,
            new_depth_log,
        };
        meta.validate()?;
        if meta.to_json() != *value {
            return Err("campaign depth meta is not in canonical lossless form".to_string());
        }
        Ok(meta)
    }

    fn validate(&self) -> Result<(), String> {
        if self.generations_with_depth > self.generations_applied {
            return Err(format!(
                "generations_with_depth={} exceeds generations_applied={}",
                self.generations_with_depth, self.generations_applied
            ));
        }
        if self.generations_with_depth == 0 && (self.fuel_max != 0 || !self.hostcalls.is_empty()) {
            return Err("depth sums are non-empty but no generation reported depth".to_string());
        }
        if self.fuel_max > self.fuel_total {
            return Err(format!(
                "fuel_max={} exceeds fuel_total={}",
                self.fuel_max, self.fuel_total
            ));
        }
        if let Some(last) = self.last_new_depth_gen {
            if last >= self.generations_applied {
                return Err(format!(
                    "last_new_depth_gen={last} is not below generations_applied={}",
                    self.generations_applied
                ));
            }
        }
        let mut previous = None;
        for (generation, new_kinds, fuel_max) in &self.new_depth_log {
            if *new_kinds == 0 && previous.is_some_and(|(_, fuel)| fuel == *fuel_max) {
                return Err(format!(
                    "new_depth_log generation {generation} records neither a new hostcall kind nor a fuel high-water mark"
                ));
            }
            if *generation >= self.generations_applied {
                return Err(format!(
                    "new_depth_log generation {generation} is beyond generations_applied={}",
                    self.generations_applied
                ));
            }
            if previous.is_some_and(|(old, _)| *generation <= old) {
                return Err("new_depth_log generations must be strictly increasing".to_string());
            }
            previous = Some((*generation, *fuel_max));
        }
        if self
            .new_depth_log
            .last()
            .map(|(generation, _, _)| *generation)
            != self.last_new_depth_gen
        {
            return Err(
                "last_new_depth_gen must match the final new_depth_log generation".to_string(),
            );
        }
        if self.new_depth_log.last().map(|(_, _, fuel)| *fuel) != Some(self.fuel_max)
            && self.fuel_max != 0
        {
            return Err(format!(
                "fuel_max={} does not match the final new_depth_log high-water mark",
                self.fuel_max
            ));
        }
        let expected = self.plateau_window != 0
            && self.last_new_depth_gen.is_some_and(|last| {
                self.generations_applied
                    .saturating_sub(1)
                    .saturating_sub(last)
                    >= self.plateau_window
            });
        if self.generations_applied == 0 {
            if self.depth_plateaued {
                return Err("empty depth state cannot be plateaued".to_string());
            }
        } else if self.depth_plateaued != expected {
            return Err(format!(
                "depth_plateaued={} does not match plateau_window={} last_new_depth_gen={:?} generations_applied={}",
                self.depth_plateaued,
                self.plateau_window,
                self.last_new_depth_gen,
                self.generations_applied
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DepthFoldOutcome {
    pub(crate) generation: u64,
    pub(crate) new_hostcall_kinds: u64,
    pub(crate) raised_fuel_high_water: bool,
    pub(crate) skipped_by_watermark: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CampaignDepthStore {
    dir: PathBuf,
    meta: CampaignDepthMeta,
}

impl CampaignDepthStore {
    pub(crate) fn fresh(
        dir: PathBuf,
        artifact: CoverageArtifact,
        fingerprint: String,
        plateau_window: u64,
    ) -> Self {
        Self {
            meta: CampaignDepthMeta::new(artifact, fingerprint, plateau_window),
            dir,
        }
    }

    pub(crate) fn load(
        dir: PathBuf,
        artifact: CoverageArtifact,
        fingerprint: String,
        plateau_window: u64,
        campaign_generations_done: u64,
    ) -> Result<Self, CliError> {
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            if campaign_generations_done == 0 {
                return Ok(Self::fresh(dir, artifact, fingerprint, plateau_window));
            }
            return Err(CliError(format!(
                "campaign out-dir is missing WASI depth store {} for {} already-recorded generations; refusing to resume partially",
                meta_path.display(),
                campaign_generations_done
            )));
        }
        let meta = read_depth_meta(&meta_path)?;
        if meta.artifact != artifact {
            return Err(CliError(format!(
                "depth state artifact identity mismatch: meta records {} sha256 {} family {}, campaign records {} sha256 {} family {}; start a new out-dir for the new module",
                meta.artifact.path,
                meta.artifact.sha256,
                meta.artifact.family,
                artifact.path,
                artifact.sha256,
                artifact.family,
            )));
        }
        if meta.fingerprint != fingerprint {
            return Err(CliError(format!(
                "depth state fingerprint mismatch: meta records {} but this campaign expects {}; depth sums from different modules/policies cannot be accumulated",
                meta.fingerprint, fingerprint
            )));
        }
        if meta.plateau_window != plateau_window {
            return Err(CliError(format!(
                "depth state plateau_window {} does not match campaign spec {}; start a new out-dir to change --plateau-after",
                meta.plateau_window, plateau_window
            )));
        }
        validate_resume_watermark(
            "depth state",
            "generations_applied",
            meta.generations_applied,
            campaign_generations_done,
            "per-generation depth reports are transient, so refusing to resume with missing depth folds",
        )?;
        Ok(Self { dir, meta })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn meta(&self) -> &CampaignDepthMeta {
        &self.meta
    }

    fn fold_decision(&self, generation: u64) -> Result<AuxFoldDecision, CliError> {
        fold_decision(
            "depth state",
            "generations_applied",
            self.meta.generations_applied,
            generation,
        )
    }

    /// Fold one generation's depth report into the store.
    ///
    /// `report` is `None` when the generation produced no `PATINA_DEPTH_REPORT`
    /// line. That is tolerated only for a generation that did not run the guest
    /// to completion (`requires_report == false`); a cleanly finished generation
    /// without depth means the plumbing broke, and is refused loudly rather than
    /// folded as zero.
    pub(crate) fn fold_generation(
        &mut self,
        generation: u64,
        report: Option<&DepthReport>,
        requires_report: bool,
    ) -> Result<DepthFoldOutcome, CliError> {
        if self.fold_decision(generation)? == AuxFoldDecision::SkipAlreadyApplied {
            return Ok(DepthFoldOutcome {
                generation,
                new_hostcall_kinds: 0,
                raised_fuel_high_water: false,
                skipped_by_watermark: true,
            });
        }
        let mut new_hostcall_kinds = 0u64;
        let mut raised_fuel_high_water = false;
        match report {
            None if requires_report => {
                return Err(CliError(format!(
                    "generation {generation} finished cleanly but emitted no PATINA_DEPTH_REPORT line; refusing a depth campaign that cannot tell missing measurements from zero depth"
                )));
            }
            None => {}
            Some(report) => {
                for (name, count) in &report.hostcalls {
                    let entry = self.meta.hostcalls.entry(name.clone()).or_insert_with(|| {
                        new_hostcall_kinds += 1;
                        0
                    });
                    *entry = entry.saturating_add(*count);
                }
                if report.fuel_consumed > self.meta.fuel_max {
                    self.meta.fuel_max = report.fuel_consumed;
                    raised_fuel_high_water = true;
                }
                self.meta.fuel_total = self.meta.fuel_total.saturating_add(report.fuel_consumed);
                self.meta.generations_with_depth += 1;
            }
        }
        if new_hostcall_kinds > 0 || raised_fuel_high_water {
            self.meta.last_new_depth_gen = Some(generation);
            self.meta
                .new_depth_log
                .push((generation, new_hostcall_kinds, self.meta.fuel_max));
        }
        self.meta.generations_applied = generation + 1;
        self.meta.update_plateau(generation);
        Ok(DepthFoldOutcome {
            generation,
            new_hostcall_kinds,
            raised_fuel_high_water,
            skipped_by_watermark: false,
        })
    }

    pub(crate) fn write_checkpoint(&self) -> Result<(), CliError> {
        self.meta
            .validate()
            .map_err(|error| CliError(format!("refusing to write invalid depth meta: {error}")))?;
        atomic_write_json(
            &self.dir.join("meta.json"),
            &self.meta.to_json(),
            "depth meta",
        )
    }
}

fn read_depth_meta(path: &Path) -> Result<CampaignDepthMeta, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read campaign depth meta {}: {error}",
            path.display()
        ))
    })?;
    let json: Value = serde_json::from_str(&text).map_err(|error| {
        CliError(format!(
            "campaign depth meta {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    CampaignDepthMeta::from_json(&json).map_err(|error| {
        CliError(format!(
            "campaign depth meta {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))
    })
}

/// The depth detectors reported by `cargo patina campaign --selftest`. Each entry
/// is `(name, passed, detail)`, matching the native coverage selftest's shape.
pub(crate) fn campaign_detector_selftest() -> Vec<(&'static str, bool, String)> {
    vec![
        detector_fingerprint_mismatch(),
        detector_plateau_exactness(),
        detector_watermark_idempotency(),
        detector_missing_report_refused(),
    ]
}

fn test_artifact() -> CoverageArtifact {
    CoverageArtifact {
        path: "guest.wasm".into(),
        sha256: "abc".into(),
        family: "wasi".into(),
    }
}

fn synthetic_depth(fuel: u64, hostcalls: &[(&str, u64)]) -> DepthReport {
    DepthReport {
        family: "wasi".to_string(),
        fuel_consumed: fuel,
        hostcalls: hostcalls
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect(),
    }
}

fn detector_fingerprint_mismatch() -> (&'static str, bool, String) {
    const NAME: &str = "depth-fingerprint-mismatch-refuses";
    let result = (|| -> Result<String, CliError> {
        let temp = tempfile::tempdir()
            .map_err(|error| CliError(format!("failed to create tempdir: {error}")))?;
        let dir = temp.path().join("depth");
        fs::create_dir_all(&dir)
            .map_err(|error| CliError(format!("failed to create depth dir: {error}")))?;
        let mut store =
            CampaignDepthStore::fresh(dir.clone(), test_artifact(), "patina-wasi".into(), 200);
        store.fold_generation(0, Some(&synthetic_depth(10, &[("fd_write", 1)])), true)?;
        store.write_checkpoint()?;
        let mut meta: Value = serde_json::from_str(
            &fs::read_to_string(dir.join("meta.json"))
                .map_err(|error| CliError(format!("failed to read meta: {error}")))?,
        )
        .map_err(|error| CliError(format!("failed to parse meta: {error}")))?;
        meta["fingerprint"] = "other".into();
        fs::write(
            dir.join("meta.json"),
            serde_json::to_string_pretty(&meta)
                .map_err(|error| CliError(format!("failed to encode meta: {error}")))?,
        )
        .map_err(|error| CliError(format!("failed to rewrite meta: {error}")))?;
        let error = CampaignDepthStore::load(dir, test_artifact(), "patina-wasi".into(), 200, 1)
            .unwrap_err();
        Ok(error.0)
    })();
    match result {
        Ok(message) if message.contains("depth state fingerprint mismatch") => {
            (NAME, true, "loud mismatch".to_string())
        }
        Ok(message) => (NAME, false, format!("wrong error: {message}")),
        Err(error) => (NAME, false, error.to_string()),
    }
}

fn detector_plateau_exactness() -> (&'static str, bool, String) {
    const NAME: &str = "depth-plateau-exactness";
    // Generation 0 is novel (it establishes the fuel high-water mark); the
    // repeats add neither a kind nor a high-water mark, so with window 2 the
    // plateau must fire at generation 2 and NOT at generation 1.
    let first = synthetic_depth(100, &[("fd_write", 2)]);
    let repeat = synthetic_depth(100, &[("fd_write", 2)]);
    let mut store = CampaignDepthStore::fresh(
        PathBuf::from("out/depth"),
        test_artifact(),
        "patina-wasi".into(),
        2,
    );
    let ok = store.fold_generation(0, Some(&first), true).is_ok()
        && !store.meta().depth_plateaued
        && store.fold_generation(1, Some(&repeat), true).is_ok()
        && !store.meta().depth_plateaued
        && store.fold_generation(2, Some(&repeat), true).is_ok()
        && store.meta().depth_plateaued;
    let mut disabled = CampaignDepthStore::fresh(
        PathBuf::from("out/depth"),
        test_artifact(),
        "patina-wasi".into(),
        0,
    );
    let disabled_ok = disabled.fold_generation(0, Some(&first), true).is_ok()
        && disabled.fold_generation(1, Some(&repeat), true).is_ok()
        && disabled.fold_generation(2, Some(&repeat), true).is_ok()
        && !disabled.meta().depth_plateaued;
    (
        NAME,
        ok && disabled_ok,
        "fires at N, not N-1; zero disables".to_string(),
    )
}

fn detector_watermark_idempotency() -> (&'static str, bool, String) {
    const NAME: &str = "depth-watermark-idempotency";
    let mut store = CampaignDepthStore::fresh(
        PathBuf::from("out/depth"),
        test_artifact(),
        "patina-wasi".into(),
        200,
    );
    let report = synthetic_depth(500, &[("fd_write", 3), ("clock_time_get", 2)]);
    let ok = store.fold_generation(0, Some(&report), true).is_ok();
    let folded = store.meta().clone();
    let skipped = store
        .fold_generation(0, Some(&report), true)
        .map(|outcome| outcome.skipped_by_watermark)
        .unwrap_or(false);
    (
        NAME,
        ok && skipped && *store.meta() == folded,
        "second fold skipped without double-counting hostcall sums".to_string(),
    )
}

fn detector_missing_report_refused() -> (&'static str, bool, String) {
    const NAME: &str = "depth-missing-report-refused";
    let mut store = CampaignDepthStore::fresh(
        PathBuf::from("out/depth"),
        test_artifact(),
        "patina-wasi".into(),
        200,
    );
    let refused = store
        .fold_generation(0, None, true)
        .err()
        .is_some_and(|error| error.0.contains("emitted no PATINA_DEPTH_REPORT"));
    // A generation that never finished the guest is allowed to carry no depth,
    // and must advance the watermark without inventing a zero measurement.
    let tolerated = store.fold_generation(0, None, false).is_ok()
        && store.meta().generations_applied == 1
        && store.meta().generations_with_depth == 0
        && store.meta().is_vacuous();
    (
        NAME,
        refused && tolerated,
        "clean generation without depth refused; aborted generation tolerated as no-data"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> CampaignDepthStore {
        CampaignDepthStore::fresh(
            PathBuf::from("out/depth"),
            test_artifact(),
            "patina-wasi".into(),
            200,
        )
    }

    #[test]
    fn selftest_detectors_all_fire() {
        for (name, ok, detail) in campaign_detector_selftest() {
            assert!(ok, "{name} failed: {detail}");
        }
    }

    #[test]
    fn fold_accumulates_kinds_fuel_high_water_and_sums() {
        let mut store = store();
        store
            .fold_generation(0, Some(&synthetic_depth(100, &[("fd_write", 2)])), true)
            .unwrap();
        let second = store
            .fold_generation(
                1,
                Some(&synthetic_depth(80, &[("fd_write", 1), ("fd_read", 4)])),
                true,
            )
            .unwrap();
        assert_eq!(second.new_hostcall_kinds, 1);
        assert!(!second.raised_fuel_high_water);
        let meta = store.meta();
        assert_eq!(meta.fuel_max, 100);
        assert_eq!(meta.fuel_total, 180);
        assert_eq!(meta.hostcalls.get("fd_write"), Some(&3));
        assert_eq!(meta.hostcalls.get("fd_read"), Some(&4));
        assert_eq!(meta.generations_with_depth, 2);
        assert_eq!(meta.last_new_depth_gen, Some(1));
        assert!(!meta.is_vacuous());
    }

    #[test]
    fn a_higher_fuel_generation_counts_as_novel_without_new_kinds() {
        let mut store = store();
        store
            .fold_generation(0, Some(&synthetic_depth(100, &[("fd_write", 1)])), true)
            .unwrap();
        let outcome = store
            .fold_generation(1, Some(&synthetic_depth(140, &[("fd_write", 1)])), true)
            .unwrap();
        assert_eq!(outcome.new_hostcall_kinds, 0);
        assert!(outcome.raised_fuel_high_water);
        assert_eq!(store.meta().last_new_depth_gen, Some(1));
    }

    #[test]
    fn meta_round_trips_through_canonical_json() {
        let mut store = store();
        store
            .fold_generation(
                0,
                Some(&synthetic_depth(100, &[("fd_write", 2), ("proc_exit", 1)])),
                true,
            )
            .unwrap();
        store.fold_generation(1, None, false).unwrap();
        let json = store.meta().to_json();
        let parsed = CampaignDepthMeta::from_json(&json).expect("canonical meta round-trips");
        assert_eq!(&parsed, store.meta());
    }

    #[test]
    fn corrupt_meta_is_refused_rather_than_partially_resumed() {
        let mut json = {
            let mut store = store();
            store
                .fold_generation(0, Some(&synthetic_depth(10, &[("fd_write", 1)])), true)
                .unwrap();
            store.meta().to_json()
        };
        json["generations_with_depth"] = Value::from(9u64);
        let error = CampaignDepthMeta::from_json(&json).unwrap_err();
        assert!(error.contains("exceeds generations_applied"), "{error}");
    }

    #[test]
    fn non_sequential_generations_are_refused() {
        let mut store = store();
        store
            .fold_generation(0, Some(&synthetic_depth(10, &[("fd_write", 1)])), true)
            .unwrap();
        let error = store
            .fold_generation(2, Some(&synthetic_depth(10, &[("fd_write", 1)])), true)
            .unwrap_err();
        assert!(error.0.contains("fold gap"), "{error}");
    }
}
