//! Campaign coverage, SDK-site folds, and guidance inputs.

use super::state::CampaignState;
use super::{CampaignSpec, RunFacts};
use crate::CliError;
use crate::aux_store::{AuxFoldDecision, fold_decision};
use crate::coverage::{CampaignCoverageStore, CoverageArtifact, FoldOutcome};
use crate::guided::{GuidancePlan, NoveltyEntry};
use crate::sdk_report::CoverageTally;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) enum EdgeCoverageState {
    Active(Box<CampaignCoverageStore>),
    Unavailable {
        reason: &'static str,
        hint: Option<&'static str>,
    },
}

impl EdgeCoverageState {
    fn active_mut(&mut self) -> Option<&mut CampaignCoverageStore> {
        match self {
            Self::Active(store) => Some(store.as_mut()),
            Self::Unavailable { .. } => None,
        }
    }

    pub(super) fn active(&self) -> Option<&CampaignCoverageStore> {
        match self {
            Self::Active(store) => Some(store.as_ref()),
            Self::Unavailable { .. } => None,
        }
    }

    pub(super) fn unavailable(reason: &'static str, hint: Option<&'static str>) -> Self {
        Self::Unavailable { reason, hint }
    }
}

pub(super) fn initialize_edge_coverage(
    out_dir: &Path,
    state: &CampaignState,
    campaign_generations_done: u64,
) -> Result<EdgeCoverageState, CliError> {
    let artifact_path = PathBuf::from(&state.artifact.path);
    // Edge coverage rides the SanitizerCoverage counters an `--instrument` build
    // keeps at every stride, 0 included, so a guided campaign pays no
    // preemption cost just to see coverage.
    let image = fs::File::open(&artifact_path)
        .and_then(|file| crate::run_cache::Image::map(&file))
        .map_err(|error| {
            CliError(format!(
                "failed to read {} to detect its instrumentation: {error}",
                artifact_path.display()
            ))
        })?;
    let instrumented = crate::binary_instrumented(image.bytes());
    if state.spec.yield_stride && !instrumented {
        return Err(CliError(format!(
            "--yield-stride draws a scheduling-point stride per generation, but {} was not built \
with cargo patina build --instrument, so it has no edge hook to take them",
            artifact_path.display()
        )));
    }
    if !instrumented {
        return Ok(EdgeCoverageState::unavailable(
            "not-instrumented",
            Some("rebuild with cargo patina build --instrument"),
        ));
    }
    let coverage_dir = out_dir.join("coverage");
    fs::create_dir_all(&coverage_dir).map_err(|error| {
        CliError(format!(
            "failed to create campaign coverage dir {}: {error}",
            coverage_dir.display()
        ))
    })?;
    let artifact = CoverageArtifact {
        path: state.artifact.path.clone(),
        sha256: state.artifact.sha256.clone(),
    };
    let fingerprint = campaign_coverage_fingerprint(&state.spec, instrumented);
    let store = CampaignCoverageStore::load(
        coverage_dir,
        artifact,
        fingerprint,
        state.spec.plateau_after,
        campaign_generations_done,
    )?;
    Ok(EdgeCoverageState::Active(Box::new(store)))
}

pub(super) fn campaign_coverage_fingerprint(spec: &CampaignSpec, instrumented: bool) -> String {
    let mut fingerprint =
        crate::instrumentation_fingerprint(crate::DEFAULT_NATIVE_FINGERPRINT, instrumented);
    if spec.buggify {
        fingerprint.push_str("+buggify");
    }
    if spec.pct {
        fingerprint.push_str("+pct");
    }
    if spec.swarm {
        fingerprint.push_str("+swarm");
    }
    if spec.yield_stride {
        fingerprint.push_str("+yieldstride");
    }
    fingerprint
}

/// The guidance signal, or a loud refusal naming why there is none: a guided
/// campaign steers on edge coverage.
pub(super) fn guidance_source_or_refuse(edge_coverage: &EdgeCoverageState) -> Result<(), CliError> {
    if edge_coverage.active().is_some() {
        return Ok(());
    }
    Err(CliError(
        "--guided needs a novelty signal but this campaign has no edge coverage; rebuild with \
cargo patina build --instrument so generations have edge coverage to steer by"
            .to_string(),
    ))
}

/// Resolve the guidance plan from the edge-coverage novelty log. Built per
/// generation rather than cached: the log is sparse, so the forward pass is a
/// handful of hashes, and rebuilding keeps the derivation an obvious pure
/// function of the persisted state rather than of loop-carried state.
pub(super) fn guidance_plan(
    spec: &CampaignSpec,
    edge_coverage: &EdgeCoverageState,
) -> GuidancePlan {
    let log: Vec<NoveltyEntry> = edge_coverage
        .active()
        .map(CampaignCoverageStore::novelty_log)
        .unwrap_or_default();
    GuidancePlan::new(spec.seed_base, spec.plateau_after, &log)
}

pub(super) fn fold_sites_generation(
    coverage: &mut CoverageTally,
    generation: u64,
    seed: u64,
    sdk: Option<&serde_json::Value>,
) -> Result<AuxFoldDecision, CliError> {
    let decision = fold_decision(
        "campaign sites store",
        "generations_observed",
        coverage.generations_observed,
        generation,
    )?;
    if decision == AuxFoldDecision::Apply {
        coverage
            .observe_generation(generation, seed, sdk)
            .map_err(|error| CliError(format!("generation {generation}: {error}")))?;
    }
    Ok(decision)
}

/// Whether this generation could have written its coverage map at all.
///
/// The map is dumped from the shim's shutdown path. A generation the supervisor
/// KILLED never reaches it: a `--timeout-secs` kill SIGKILLs the process
/// group, and a guest that died on a signal
/// (an `abort()`, a fatal fault) skips `atexit` by definition. A generation that
/// exited on its own — with any status, zero or not — did reach shutdown, so a
/// missing map there is a real plumbing failure and must stay loud.
pub(super) fn generation_reached_shutdown(facts: &RunFacts) -> bool {
    !facts.timed_out && facts.signal.is_none()
}

pub(super) fn fold_edge_coverage_generation(
    edge_coverage: &mut EdgeCoverageState,
    generation: u64,
    coverage_map_path: Option<&Path>,
    reached_shutdown: bool,
) -> Result<Option<FoldOutcome>, CliError> {
    let Some(store) = edge_coverage.active_mut() else {
        return Ok(None);
    };
    let path = coverage_map_path.expect("active coverage has a generation path");
    if store.fold_decision(generation)? == AuxFoldDecision::SkipAlreadyApplied {
        let _ = fs::remove_file(path);
        return Ok(Some(FoldOutcome {
            generation,
            new_edges: 0,
            skipped_by_watermark: true,
        }));
    }
    let len = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if len == 0 {
        // A killed generation has no coverage to contribute and never claimed to,
        // so it is skipped. Failing the whole campaign here would make a
        // `--timeout-secs` kill unusable with coverage.
        if !reached_shutdown {
            let _ = fs::remove_file(path);
            store.note_generation_without_covmap(generation);
            return Ok(None);
        }
        return Err(CliError(format!(
            "generation {generation} requested native coverage but did not produce a covmap at {}; refusing a partial coverage campaign",
            path.display()
        )));
    }
    let covmap = crate::coverage::read_covmap(path).map_err(|error| {
        CliError(format!(
            "generation {generation} produced malformed native coverage map {}: {error}",
            path.display()
        ))
    })?;
    let outcome = store.fold_covmap(generation, &covmap)?;
    let _ = fs::remove_file(path);
    Ok(Some(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aux_store::AuxFoldDecision;
    use crate::sdk_report::CoverageTally;

    #[test]
    fn sites_fold_is_watermark_idempotent() {
        let sdk = serde_json::json!({"sites": [{
            "label": "oracle", "kind": "sometimes", "site": "src/main.rs:9", "active": true,
            "evals": 3, "fires": 2, "reachable": true, "sometimes_satisfied": true,
            "always_violated": false, "knob": null,
        }]});
        let mut coverage = CoverageTally::default();
        let first = fold_sites_generation(&mut coverage, 0, 99, Some(&sdk)).expect("first fold");
        assert_eq!(first, AuxFoldDecision::Apply);
        let after_first = coverage.clone();
        let second =
            fold_sites_generation(&mut coverage, 0, 99, Some(&sdk)).expect("watermark skip");
        assert_eq!(second, AuxFoldDecision::SkipAlreadyApplied);
        assert_eq!(
            coverage, after_first,
            "duplicate sites fold must not double-count evals/fires/generation tallies"
        );
        let site = coverage.sites.get("oracle").unwrap();
        assert_eq!(site.evals, 3);
        assert_eq!(site.fires, 2);
        assert_eq!(site.registered_gens, 1);
        assert_eq!(coverage.generations_observed, 1);
    }
}
