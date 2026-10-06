//! Campaign coverage, depth, SDK-site folds, and guidance inputs.

use super::classify::STARVATION_STALL_EXIT;
use super::state::CampaignState;
use super::{CampaignSpec, RunFacts};
use crate::CliError;
use crate::aux_store::{AuxFoldDecision, fold_decision};
use crate::coverage::{CampaignCoverageStore, CoverageArtifact, FoldOutcome};
use crate::depth::{CampaignDepthStore, DepthFoldOutcome};
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
    if state.artifact.family != "native" {
        return Ok(EdgeCoverageState::unavailable(
            "not-native",
            Some(
                "only instrumented native binaries carry edge coverage; a WASI module accumulates depth instead",
            ),
        ));
    }
    let artifact_path = PathBuf::from(&state.artifact.path);
    // Edge coverage rides the SanitizerCoverage counters, which BOTH instrumented
    // build modes emit. `--coverage-points` emits them without the per-block
    // scheduler hook, so a guided campaign no longer has to pay --yield-points'
    // preemption cost just to see coverage.
    let instrumentation = crate::binary_instrumentation(&artifact_path)?;
    if !instrumentation.has_coverage() {
        return Ok(EdgeCoverageState::unavailable(
            "not-instrumented",
            Some("rebuild with cargo patina build --coverage-points (or --yield-points)"),
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
        family: state.artifact.family.to_string(),
    };
    let fingerprint = campaign_coverage_fingerprint(&state.spec, instrumentation);
    let store = CampaignCoverageStore::load(
        coverage_dir,
        artifact,
        fingerprint,
        state.spec.plateau_after,
        campaign_generations_done,
    )?;
    Ok(EdgeCoverageState::Active(Box::new(store)))
}

pub(super) fn campaign_coverage_fingerprint(
    spec: &CampaignSpec,
    instrumentation: crate::GuestInstrumentation,
) -> String {
    let mut fingerprint =
        crate::instrumentation_fingerprint(crate::DEFAULT_NATIVE_FINGERPRINT, instrumentation);
    if spec.buggify {
        fingerprint.push_str("+buggify");
    }
    if spec.pct {
        fingerprint.push_str("+pct");
    }
    if spec.starve {
        fingerprint.push_str("+starve");
    }
    if spec.swarm {
        fingerprint.push_str("+swarm");
    }
    fingerprint
}

/// The depth store's compatibility fingerprint. It binds accumulated depth to the
/// exploration policy that produced it, exactly as the coverage fingerprint does:
/// re-running a WASI campaign under different knobs explores a different space, so
/// its fuel high-water marks and hostcall sums must not be unioned with the old
/// ones. Module identity itself rides the artifact hash, not this string.
/// Which store supplies the guidance signal, or a loud refusal naming why there
/// is none. Native campaigns steer on edge coverage, WASI campaigns on depth.
pub(super) fn guidance_source_or_refuse(
    edge_coverage: &EdgeCoverageState,
    depth: &DepthState,
    family: &'static str,
) -> Result<(), CliError> {
    if edge_coverage.active().is_some() || depth.active().is_some() {
        return Ok(());
    }
    let hint = if family == "native" {
        "rebuild with cargo patina build --yield-points so generations have edge coverage to steer by"
    } else {
        "coverage-guided campaigns need a native yield-point binary or a WASI module"
    };
    Err(CliError(format!(
        "--guided needs a novelty signal but this {family} campaign has neither edge coverage nor WASI depth; {hint}"
    )))
}

/// Resolve the guidance plan from whichever store is accumulating novelty. Built
/// per generation rather than cached: the log is sparse, so the forward pass is
/// a handful of hashes, and rebuilding keeps the derivation an obvious pure
/// function of the persisted state rather than of loop-carried state.
pub(super) fn guidance_plan(
    spec: &CampaignSpec,
    edge_coverage: &EdgeCoverageState,
    depth: &DepthState,
) -> GuidancePlan {
    let log: Vec<NoveltyEntry> = match (edge_coverage.active(), depth.active()) {
        (Some(store), _) => store.novelty_log(),
        (None, Some(store)) => store.novelty_log(),
        (None, None) => Vec::new(),
    };
    GuidancePlan::new(spec.seed_base, spec.plateau_after, &log)
}

fn campaign_depth_fingerprint(spec: &CampaignSpec) -> String {
    let mut fingerprint = "patina-wasi".to_string();
    if spec.buggify {
        fingerprint.push_str("+buggify");
    }
    if spec.faults {
        fingerprint.push_str("+faults");
    }
    fingerprint
}

/// WASI depth accumulation state, mirroring [`EdgeCoverageState`]. A native
/// campaign reports `unavailable` here and edge coverage there, so exactly one of
/// the two blocks carries data and neither is silently absent.
#[derive(Debug)]
pub(super) enum DepthState {
    Active(Box<CampaignDepthStore>),
    Unavailable {
        reason: &'static str,
        hint: Option<&'static str>,
    },
}

impl DepthState {
    fn active_mut(&mut self) -> Option<&mut CampaignDepthStore> {
        match self {
            Self::Active(store) => Some(store.as_mut()),
            Self::Unavailable { .. } => None,
        }
    }

    pub(super) fn active(&self) -> Option<&CampaignDepthStore> {
        match self {
            Self::Active(store) => Some(store.as_ref()),
            Self::Unavailable { .. } => None,
        }
    }
}

pub(super) fn initialize_depth(
    out_dir: &Path,
    state: &CampaignState,
    campaign_generations_done: u64,
) -> Result<DepthState, CliError> {
    if state.artifact.family != "wasi" {
        return Ok(DepthState::Unavailable {
            reason: "not-wasi",
            hint: Some(
                "depth (fuel + hostcalls) is the WASI family's measure; native binaries accumulate edge coverage instead",
            ),
        });
    }
    let depth_dir = out_dir.join("depth");
    fs::create_dir_all(&depth_dir).map_err(|error| {
        CliError(format!(
            "failed to create campaign depth dir {}: {error}",
            depth_dir.display()
        ))
    })?;
    let artifact = CoverageArtifact {
        path: state.artifact.path.clone(),
        sha256: state.artifact.sha256.clone(),
        family: state.artifact.family.to_string(),
    };
    let store = CampaignDepthStore::load(
        depth_dir,
        artifact,
        campaign_depth_fingerprint(&state.spec),
        state.spec.plateau_after,
        campaign_generations_done,
    )?;
    Ok(DepthState::Active(Box::new(store)))
}

/// Fold one generation's `PATINA_DEPTH_REPORT` (parsed out of the child's already
/// captured stderr — no descriptor plumbing needed) into the depth store.
///
/// A generation that exited cleanly must carry a depth line; one that was killed
/// by the wall-clock backstop or died inside the engine may not, and contributes
/// no measurement while still advancing the watermark.
pub(super) fn fold_depth_generation(
    depth: &mut DepthState,
    generation: u64,
    exit: i32,
    timed_out: bool,
    stderr: &str,
) -> Result<Option<DepthFoldOutcome>, CliError> {
    let Some(store) = depth.active_mut() else {
        return Ok(None);
    };
    let report = stderr
        .lines()
        .find_map(crate::output::parse_depth_report_line);
    let requires_report = exit == 0 && !timed_out;
    store
        .fold_generation(generation, report.as_ref(), requires_report)
        .map(Some)
}

pub(super) fn fold_sites_generation(
    coverage: &mut CoverageTally,
    generation: u64,
    seed: u64,
    stderr: &str,
) -> Result<AuxFoldDecision, CliError> {
    let decision = fold_decision(
        "campaign sites store",
        "generations_observed",
        coverage.generations_observed,
        generation,
    )?;
    if decision == AuxFoldDecision::Apply {
        coverage
            .observe_generation(generation, seed, stderr)
            .map_err(|error| {
                CliError(format!(
                    "generation {generation} has malformed PATINA_SDK_REPORT: {error}"
                ))
            })?;
    }
    Ok(decision)
}

/// Whether this generation could have written its coverage map at all.
///
/// The map is dumped from the shim's shutdown path. A generation the supervisor
/// KILLED never reaches it: a `--timeout-secs` kill and the `--starve` stall
/// backstop both SIGKILL the process group, and a guest that died on a signal
/// (an `abort()`, a fatal fault) skips `atexit` by definition. A generation that
/// exited on its own — with any status, zero or not — did reach shutdown, so a
/// missing map there is a real plumbing failure and must stay loud.
pub(super) fn generation_reached_shutdown(facts: &RunFacts) -> bool {
    !facts.timed_out && facts.signal.is_none() && facts.exit_code != STARVATION_STALL_EXIT
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
        // A killed generation has no coverage to contribute and never claimed to:
        // it is skipped, exactly like a killed generation's missing depth line.
        // Failing the whole campaign here would make `--starve` (whose stall
        // backstop kills a wedged generation BY DESIGN) unusable with coverage.
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
        let stderr = "PATINA_SDK_REPORT enabled=1 \
             site=oracle|sometimes|a1|e3|f2|r1|s1|v0|k-|@src/main.rs:9";
        let mut coverage = CoverageTally::default();
        let first = fold_sites_generation(&mut coverage, 0, 99, stderr).expect("first fold");
        assert_eq!(first, AuxFoldDecision::Apply);
        let after_first = coverage.clone();
        let second = fold_sites_generation(&mut coverage, 0, 99, stderr).expect("watermark skip");
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
