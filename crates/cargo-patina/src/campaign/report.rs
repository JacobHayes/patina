//! Campaign progress, coverage verdicts, and result rendering.

use super::AllowUnmetSometimes;
use super::classify::{HOST_KILL_SHAPE, SHUTDOWN_FAILURE_SHAPE};
use super::observe::{DepthState, EdgeCoverageState};
use super::state::{
    CampaignState, GenerationOutcome, InvocationRecord, SignatureRecord, allow_unmet_to_json,
    class_counts_failures, signatures_to_json,
};
use crate::coverage::top_uncovered_crates;
use crate::guided::GuidanceTally;
use crate::sdk_report::{CoverageTally, ExercisedSite};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

/// The stable schema identifier for the campaign JSON envelope, extending the
/// `patina.result/v1` family. `v2` is summary-first: `notable_runs` carries only
/// the novel/failing generations (v1's `runs` dumped every generation), and an
/// `artifacts` object points at the full on-disk detail.
const CAMPAIGN_ENVELOPE_SCHEMA: &str = "patina.campaign/v2";

pub(super) fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CoverageGate {
    Pass,
    Fail,
    Waived,
}

impl CoverageGate {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            CoverageGate::Pass => "pass",
            CoverageGate::Fail => "fail",
            CoverageGate::Waived => "waived",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct CoverageSummary<'a> {
    labels_seen: u64,
    oracle_sites: u64,
    satisfied: u64,
    sometimes_unsatisfied: u64,
    reachable_unreached: u64,
    always_violated: u64,
    pub(super) unmet: Vec<&'a ExercisedSite>,
}

#[derive(Clone, Debug)]
pub(super) struct CoverageVerdict<'a> {
    pub(super) summary: CoverageSummary<'a>,
    pub(super) gate: CoverageGate,
    waiver: Option<AllowUnmetSometimes>,
}

fn coverage_summary(coverage: &CoverageTally) -> CoverageSummary<'_> {
    let mut summary = CoverageSummary {
        labels_seen: coverage.sites.len() as u64,
        oracle_sites: 0,
        satisfied: 0,
        sometimes_unsatisfied: 0,
        reachable_unreached: 0,
        always_violated: 0,
        unmet: Vec::new(),
    };
    for site in coverage.sites.values() {
        if site.kind == "always" && site.always_violated_runs > 0 {
            summary.always_violated += 1;
        }
        if !site.is_oracle() {
            continue;
        }
        summary.oracle_sites += 1;
        if site.satisfied_gens > 0 {
            summary.satisfied += 1;
        } else {
            if site.kind == "sometimes" {
                summary.sometimes_unsatisfied += 1;
            } else if site.kind == "reachable" {
                summary.reachable_unreached += 1;
            }
            summary.unmet.push(site);
        }
    }
    summary
}

pub(super) fn coverage_verdict(
    coverage: &CoverageTally,
    waiver: Option<AllowUnmetSometimes>,
) -> CoverageVerdict<'_> {
    let summary = coverage_summary(coverage);
    let gate = if summary.unmet.is_empty() {
        CoverageGate::Pass
    } else if waiver_applies(waiver, coverage.generations_observed) {
        CoverageGate::Waived
    } else {
        CoverageGate::Fail
    };
    CoverageVerdict {
        summary,
        gate,
        waiver,
    }
}

fn waiver_applies(waiver: Option<AllowUnmetSometimes>, generations_observed: u64) -> bool {
    match waiver {
        Some(AllowUnmetSometimes::Always) => true,
        Some(AllowUnmetSometimes::BelowGenerations(min)) => generations_observed < min,
        None => false,
    }
}

fn waiver_json(waiver: Option<AllowUnmetSometimes>) -> serde_json::Value {
    waiver.map_or(serde_json::Value::Null, allow_unmet_to_json)
}

/// Print one human-mode progress heartbeat: enough to answer "is it still running,
/// and how is it going?" without the full per-generation stream. `elapsed_secs` is
/// the only wall-clock-derived field and appears solely on this line (never on a
/// deterministic `PATINA_CAMPAIGN_GEN` line).
pub(super) struct ProgressHeartbeatInput<'a> {
    pub(super) done: u64,
    pub(super) total: u64,
    pub(super) elapsed_secs: u64,
    pub(super) failures: u64,
    pub(super) novel: u64,
    pub(super) class_counts: &'a BTreeMap<String, u64>,
    pub(super) coverage: &'a CoverageTally,
    pub(super) edge_coverage: &'a EdgeCoverageState,
    pub(super) depth: &'a DepthState,
    pub(super) guidance: Option<GuidanceTally>,
}

pub(super) fn print_progress_heartbeat(input: ProgressHeartbeatInput<'_>) {
    let mut line = format!(
        "PATINA_CAMPAIGN_PROGRESS generation={}/{} elapsed_secs={} failures={} novel={}",
        input.done, input.total, input.elapsed_secs, input.failures, input.novel
    );
    for (class, count) in input.class_counts {
        line.push_str(&format!(" {class}={count}"));
    }
    let coverage_summary = coverage_summary(input.coverage);
    line.push_str(&format!(
        " sdk_labels={} oracle_sites={} oracle_unmet={}",
        coverage_summary.labels_seen,
        coverage_summary.oracle_sites,
        coverage_summary.unmet.len()
    ));
    append_edge_coverage_progress(&mut line, input.edge_coverage);
    append_depth_progress(&mut line, input.depth);
    if let Some(guidance) = input.guidance {
        line.push_str(&format!(
            " guided_exploit={}/{}",
            guidance.exploited, guidance.generations
        ));
    }
    println!("{line}");
}

fn append_edge_coverage_progress(line: &mut String, edge_coverage: &EdgeCoverageState) {
    match edge_coverage {
        EdgeCoverageState::Active(store) => {
            if let Some(meta) = store.meta() {
                line.push_str(&format!(
                    " coverage={}/{} covered_permille={} last_new_edge_gen={} plateau={}",
                    meta.edges_covered,
                    meta.edges_total,
                    meta.covered_permille(),
                    meta.last_new_edge_gen
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    meta.plateaued as u8,
                ));
            } else {
                line.push_str(" coverage=pending");
            }
        }
        EdgeCoverageState::Unavailable { reason, .. } => {
            line.push_str(&format!(" coverage=unavailable reason={reason}"));
        }
    }
}

fn append_depth_progress(line: &mut String, depth: &DepthState) {
    match depth {
        DepthState::Active(store) => {
            let meta = store.meta();
            line.push_str(&format!(
                " depth_gens={}/{} fuel_max={} hostcall_kinds={} last_new_depth_gen={} depth_plateau={}",
                meta.generations_with_depth,
                meta.generations_applied,
                meta.fuel_max,
                meta.hostcall_kinds(),
                meta.last_new_depth_gen
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                meta.depth_plateaued as u8,
            ));
        }
        DepthState::Unavailable { reason, .. } => {
            line.push_str(&format!(" depth=unavailable reason={reason}"));
        }
    }
}

/// The final depth block. Depth is labeled as a proxy everywhere: it says how far
/// the guests ran and which host surface they touched, never which code they
/// covered (`docs/arcs/coverage-depth.md` §5, §11).
fn print_depth_summary(depth: &DepthState) {
    println!("-- depth (wasi fuel/hostcalls) --");
    match depth {
        DepthState::Unavailable { reason, hint } => {
            println!("depth=unavailable reason={reason}");
            if let Some(hint) = hint {
                println!("hint: {hint}");
            }
        }
        DepthState::Active(store) if store.meta().generations_applied == 0 => {
            println!("depth=pending no generation has folded a depth report yet");
            println!("depth store: {}", store.dir().display());
        }
        DepthState::Active(store) => {
            let meta = store.meta();
            println!(
                "generations_with_depth={}/{} fuel_max={} fuel_total={} hostcall_kinds={} hostcalls_total={}",
                meta.generations_with_depth,
                meta.generations_applied,
                meta.fuel_max,
                meta.fuel_total,
                meta.hostcall_kinds(),
                meta.hostcalls_total(),
            );
            println!(
                "last_new_depth_gen={} plateau_after={} depth_plateaued={}",
                meta.last_new_depth_gen
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                meta.plateau_window,
                meta.depth_plateaued as u8,
            );
            if meta.is_vacuous() {
                // Non-vacuity is a gate, not a nicety: an accumulation with no
                // measurement at all must announce itself rather than read as a
                // clean "zero depth" result.
                println!(
                    "PATINA_CAMPAIGN_DEPTH_VACUOUS generations={} reason=no-generation-reported-depth",
                    meta.generations_applied
                );
            } else {
                let mut hottest: Vec<(&String, &u64)> = meta.hostcalls.iter().collect();
                hottest.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
                println!("top_hostcalls:");
                for (name, count) in hottest.iter().take(5) {
                    println!("  {name} calls={count}");
                }
            }
            println!("depth store: {}", store.dir().display());
        }
    }
}

fn append_depth_complete(line: &mut String, depth: &DepthState) {
    if let DepthState::Active(store) = depth {
        let meta = store.meta();
        line.push_str(&format!(
            " fuel_max={} hostcall_kinds={} depth_plateaued={}",
            meta.fuel_max,
            meta.hostcall_kinds(),
            meta.depth_plateaued as u8,
        ));
    }
}

/// The guidance block. Absent entirely for an unguided campaign — the mode is
/// opt-in, so silence means "not asked for" rather than "asked for and did
/// nothing", which is exactly the distinction the vacuity line below draws.
fn print_guidance_summary(guidance: Option<GuidanceTally>) {
    let Some(guidance) = guidance else {
        return;
    };
    println!("-- guided generation scheduling --");
    println!(
        "generations={} exploited={} explored={} no_ancestors={}",
        guidance.generations, guidance.exploited, guidance.explored, guidance.no_ancestors
    );
    if guidance.is_vacuous() {
        // An inert knob is a bug: every generation was derived exactly as an
        // unguided campaign would have derived it, so a clean result here says
        // nothing about guidance.
        println!(
            "PATINA_CAMPAIGN_GUIDED_VACUOUS generations={} reason=no-generation-was-novel-to-steer-toward",
            guidance.generations
        );
    }
}

fn guidance_json(guidance: Option<GuidanceTally>) -> serde_json::Value {
    match guidance {
        None => serde_json::json!({ "state": "off" }),
        Some(guidance) => serde_json::json!({
            "state": if guidance.is_vacuous() { "vacuous" } else { "active" },
            "generations": guidance.generations,
            "exploited": guidance.exploited,
            "explored": guidance.explored,
            "no_ancestors": guidance.no_ancestors,
        }),
    }
}

fn depth_json(depth: &DepthState) -> serde_json::Value {
    match depth {
        DepthState::Unavailable { reason, hint } => serde_json::json!({
            "state": "unavailable",
            "reason": reason,
            "hint": hint,
        }),
        DepthState::Active(store) => {
            let meta = store.meta();
            // Three distinguishable states, mirroring the edge-coverage object:
            // nothing folded yet, folded but no generation carried a measurement,
            // and real data. Collapsing the first two into "available" would print
            // all-zero depth for a store that never measured anything.
            let state = if meta.generations_applied == 0 {
                "pending"
            } else if meta.is_vacuous() {
                "vacuous"
            } else {
                "available"
            };
            serde_json::json!({
                "state": state,
                "schema": crate::depth::CAMPAIGN_DEPTH_SCHEMA,
                "depth_dir": store.dir().display().to_string(),
                "generations_applied": meta.generations_applied,
                "generations_with_depth": meta.generations_with_depth,
                "fuel_max": meta.fuel_max,
                "fuel_total": meta.fuel_total,
                "hostcall_kinds": meta.hostcall_kinds(),
                "hostcalls_total": meta.hostcalls_total(),
                "hostcalls": meta.hostcalls.iter().map(|(name, count)| (name.clone(), serde_json::Value::from(*count))).collect::<serde_json::Map<_, _>>(),
                "last_new_depth_gen": meta.last_new_depth_gen,
                "plateau_after": meta.plateau_window,
                "depth_plateaued": meta.depth_plateaued,
                "new_depth_log": meta.new_depth_log.iter().map(|(generation, new_kinds, fuel_max)| serde_json::json!([generation, new_kinds, fuel_max])).collect::<Vec<_>>(),
            })
        }
    }
}

pub(super) struct CampaignSummaryInput<'a> {
    pub(super) class_counts: &'a BTreeMap<String, u64>,
    pub(super) signatures: &'a BTreeMap<String, SignatureRecord>,
    pub(super) coverage: &'a CoverageTally,
    pub(super) coverage_verdict: &'a CoverageVerdict<'a>,
    pub(super) edge_coverage: &'a EdgeCoverageState,
    pub(super) depth: &'a DepthState,
    pub(super) guidance: Option<GuidanceTally>,
    pub(super) artifact_path: &'a Path,
    pub(super) failures: u64,
    pub(super) novel: u64,
    pub(super) generations: u64,
    pub(super) store_path: &'a Path,
    pub(super) sites_path: &'a Path,
}

pub(super) fn print_campaign_summary(input: CampaignSummaryInput<'_>) {
    println!("== campaign summary ==");
    println!(
        "generations={} failures={} novel_signatures={}",
        input.generations, input.failures, input.novel
    );
    for (class, count) in input.class_counts {
        println!("  class {class:<18} {count}");
    }
    // Host kills get their own line: an operator reading a campaign summary needs
    // to see "the box ran out of memory" as an OPERATIONAL fact, not hunt for it
    // inside an INFRA tally that also holds timeouts and build failures.
    let host_killed: u64 = input
        .signatures
        .iter()
        .filter(|(key, _)| key.contains(HOST_KILL_SHAPE))
        .map(|(_, record)| record.count)
        .sum();
    if host_killed > 0 {
        println!(
            "  host-killed        {host_killed} (SIGKILL from outside the guest — OOM killer, \
cgroup limit, or an operator; not findings)"
        );
    }
    // Same reasoning for patina's own recorder giving out: the operator needs to
    // read "N generations produced no answer because MY trace limit blew" as an
    // operational fact about this run, not hunt for it inside the INFRA tally.
    let shutdown_failed: u64 = input
        .signatures
        .iter()
        .filter(|(key, _)| key.contains(SHUTDOWN_FAILURE_SHAPE))
        .map(|(_, record)| record.count)
        .sum();
    if shutdown_failed > 0 {
        println!(
            "  shutdown-failed    {shutdown_failed} (patina's own recorder failed at the end of \
the run — the trace resource limit, an unwritable trace; not findings)"
        );
    }
    if !input.signatures.is_empty() {
        println!("-- failure signatures --");
        for (key, record) in input.signatures {
            println!(
                "  [{}] count={} first_gen={} seed={}",
                record.class.as_str(),
                record.count,
                record.first_seen_gen,
                record.seed
            );
            println!("      signature: {key}");
            println!("      reproduce: {}", record.reproduce);
            if let Some(trace) = &record.trace {
                println!("      trace:     {trace}");
            }
            if let Some(log) = &record.log {
                // Stored relative to the output directory; shown absolute.
                let shown = match input.store_path.parent() {
                    Some(out_dir) => out_dir.join(log).display().to_string(),
                    None => log.clone(),
                };
                println!("      log:       {shown}");
            }
        }
    }
    print_coverage_summary(input.coverage, input.coverage_verdict, input.sites_path);
    print_edge_coverage_summary(input.edge_coverage, input.artifact_path);
    print_depth_summary(input.depth);
    print_guidance_summary(input.guidance);
    println!("signature store: {}", input.store_path.display());
    let mut complete = format!(
        "PATINA_CAMPAIGN_COMPLETE generations={} failures={} novel={}",
        input.generations, input.failures, input.novel
    );
    append_edge_coverage_complete(&mut complete, input.edge_coverage);
    append_depth_complete(&mut complete, input.depth);
    if let Some(guidance) = input.guidance {
        complete.push_str(&format!(
            " guided_exploit={} guided_explore={}",
            guidance.exploited, guidance.explored
        ));
    }
    println!("{complete}");
}

fn print_edge_coverage_summary(edge_coverage: &EdgeCoverageState, artifact_path: &Path) {
    println!("-- coverage (native edges) --");
    match edge_coverage {
        EdgeCoverageState::Unavailable { reason, hint } => {
            println!("coverage=unavailable reason={reason}");
            if let Some(hint) = hint {
                println!("hint: {hint}");
            }
        }
        EdgeCoverageState::Active(store) => {
            if let Some(meta) = store.meta() {
                println!(
                    "edges={}/{} covered_permille={} last_new_edge_gen={} plateau_after={} plateaued={} generations_applied={}",
                    meta.edges_covered,
                    meta.edges_total,
                    meta.covered_permille(),
                    meta.last_new_edge_gen
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    meta.plateau_window,
                    meta.plateaued as u8,
                    meta.generations_applied,
                );
                println!("coverage store: {}", store.dir().display());
                match top_uncovered_crates(artifact_path, store, 5) {
                    Ok(rows) if rows.is_empty() => println!("top_uncovered_crates: none"),
                    Ok(rows) => {
                        println!("top_uncovered_crates:");
                        for (krate, uncovered, total) in rows {
                            println!("  {krate} uncovered={uncovered}/{total}");
                        }
                    }
                    Err(error) => println!("top_uncovered_crates: unavailable ({error})"),
                }
            } else {
                println!("coverage=pending no finalized generation has produced a covmap yet");
                println!("coverage store: {}", store.dir().display());
            }
        }
    }
}

fn append_edge_coverage_complete(line: &mut String, edge_coverage: &EdgeCoverageState) {
    if let EdgeCoverageState::Active(store) = edge_coverage {
        if let Some(meta) = store.meta() {
            line.push_str(&format!(
                " covered_permille={} plateaued={}",
                meta.covered_permille(),
                meta.plateaued as u8,
            ));
        }
    }
}

fn print_coverage_summary(
    coverage: &CoverageTally,
    coverage_verdict: &CoverageVerdict<'_>,
    sites_path: &Path,
) {
    let summary = &coverage_verdict.summary;
    println!("-- coverage (sometimes!/reachable!) --");
    if summary.oracle_sites == 0 {
        println!("coverage: no sometimes!/reachable! sites registered");
    } else {
        println!(
            "oracle_sites={} satisfied={} unmet={}",
            summary.oracle_sites,
            summary.satisfied,
            summary.unmet.len()
        );
        for site in &summary.unmet {
            let waived = if coverage_verdict.gate == CoverageGate::Waived {
                " (waived)"
            } else {
                ""
            };
            println!(
                "  UNMET {} '{}' satisfied_gens=0/{} registered_gens={} evals={}{}",
                site.kind,
                site.label,
                coverage.generations_observed,
                site.registered_gens,
                site.evals,
                waived
            );
        }
    }
    println!("coverage store: {}", sites_path.display());
    println!(
        "PATINA_CAMPAIGN_COVERAGE oracle_sites={} satisfied={} unmet={} gate={}",
        summary.oracle_sites,
        summary.satisfied,
        summary.unmet.len(),
        coverage_verdict.gate.as_str()
    );
}

/// Build the summary-first `patina.campaign/v2` JSON envelope. Progressive
/// disclosure: the top level carries the class-count histogram and the deduped
/// signatures; `notable_runs` holds per-generation detail ONLY for novel and
/// failing generations (the interesting minority — an OK generation adds no
/// triage value and is fully accounted for by `classes`), each carrying the
/// `verdicts` it reported so a reader — `minimize --generation` included — can
/// see WHICH failure it was without replaying it; and `artifacts` points
/// at the full on-disk detail (the state file, signature store, saved failing
/// traces, optional reports) so nothing the v1 all-runs dump exposed becomes
/// unreachable. Pure (returns the `Value`) so the shape is unit-testable without
/// capturing stdout.
pub(super) struct CampaignEnvelopeInput<'a> {
    pub(super) result: &'a str,
    pub(super) exit_code: i32,
    pub(super) state: &'a CampaignState,
    pub(super) coverage: &'a CoverageTally,
    pub(super) coverage_verdict: &'a CoverageVerdict<'a>,
    pub(super) edge_coverage: &'a EdgeCoverageState,
    pub(super) depth: &'a DepthState,
    pub(super) guidance: Option<GuidanceTally>,
    pub(super) out_dir: &'a Path,
    pub(super) state_path: &'a Path,
    pub(super) sites_path: &'a Path,
}

/// How many distinct FINDINGS the store holds — the novel-signature budget.
/// `INFRA` and `STARVATION_STALL` records are excluded: they are conditions of
/// the run, not results. Both still appear in the class histogram and keep their
/// signatures; what they do not do is claim to be a bug.
pub(super) fn novel_findings(signatures: &BTreeMap<String, SignatureRecord>) -> u64 {
    signatures
        .values()
        .filter(|record| record.class.is_finding())
        .count() as u64
}

pub(super) fn build_campaign_envelope(input: CampaignEnvelopeInput<'_>) -> serde_json::Value {
    let state = input.state;
    let classes: serde_json::Map<String, serde_json::Value> = state
        .classes
        .iter()
        .map(|(class, count)| (class.clone(), serde_json::Value::from(*count)))
        .collect();
    let signature_json = signatures_to_json(&state.signatures);
    let notable_runs: Vec<serde_json::Value> = state
        .notable_runs
        .iter()
        .map(GenerationOutcome::to_json)
        .collect();
    let failures = class_counts_failures(&state.classes);
    let novel = novel_findings(&state.signatures);
    // Machine-readable pointers to the full on-disk detail. `failures` and
    // `reports` are directories that exist only once a failing generation has
    // populated them, so they are announced conditionally rather than promising a
    // path that may not exist.
    let mut artifacts = serde_json::Map::new();
    artifacts.insert("out_dir".into(), input.out_dir.display().to_string().into());
    artifacts.insert(
        "campaign_state".into(),
        input.state_path.display().to_string().into(),
    );
    artifacts.insert(
        "signature_store".into(),
        input
            .out_dir
            .join("signatures.json")
            .display()
            .to_string()
            .into(),
    );
    artifacts.insert(
        "site_coverage".into(),
        input.sites_path.display().to_string().into(),
    );
    if let Some(store) = input.edge_coverage.active() {
        artifacts.insert(
            "coverage_dir".into(),
            store.dir().display().to_string().into(),
        );
    }
    if let Some(store) = input.depth.active() {
        artifacts.insert("depth_dir".into(), store.dir().display().to_string().into());
    }
    if failures > 0 {
        artifacts.insert(
            "failures_dir".into(),
            input.out_dir.join("failures").display().to_string().into(),
        );
    }
    if state.spec.report && failures > 0 {
        artifacts.insert(
            "reports_dir".into(),
            input.out_dir.join("reports").display().to_string().into(),
        );
    }
    let coverage_json = coverage_envelope_json(
        input.coverage,
        input.coverage_verdict,
        input.edge_coverage,
        Path::new(&state.artifact.path),
    );
    let sdk_sites_json = sdk_sites_summary_json(input.coverage, input.coverage_verdict);
    let mut envelope = serde_json::json!({
        "schema": CAMPAIGN_ENVELOPE_SCHEMA,
        "verb": "campaign",
        "result": input.result,
        "exit_code": input.exit_code,
        "artifact": state.artifact.path.clone(),
        "family": state.artifact.family,
        "generations": state.spec.generations,
        "seed_base": state.spec.seed_base,
        "failures": failures,
        "novel_signatures": novel,
        "classes": classes,
        "signatures": signature_json,
        "notable_runs": notable_runs,
        "invocations": state.invocations.iter().map(InvocationRecord::to_json).collect::<Vec<_>>(),
        "sdk_sites": sdk_sites_json,
        "coverage": coverage_json,
        "depth": depth_json(input.depth),
        "guidance": guidance_json(input.guidance),
        "artifacts": artifacts,
    });
    if let (Some(object), Some(config)) =
        (envelope.as_object_mut(), crate::config::provenance_json())
    {
        object.insert("config".to_string(), config);
    }
    envelope
}

fn coverage_envelope_json(
    coverage: &CoverageTally,
    verdict: &CoverageVerdict<'_>,
    edge_coverage: &EdgeCoverageState,
    artifact_path: &Path,
) -> serde_json::Value {
    let unmet = verdict
        .summary
        .unmet
        .iter()
        .map(|site| {
            serde_json::json!({
                "label": &site.label,
                "kind": &site.kind,
                "satisfied_gens": site.satisfied_gens,
                "registered_gens": site.registered_gens,
                "generations_observed": coverage.generations_observed,
                "evals": site.evals,
                "waived": verdict.gate == CoverageGate::Waived,
            })
        })
        .collect::<Vec<_>>();
    let edge = edge_coverage_json(edge_coverage, artifact_path);
    serde_json::json!({
        "oracle_sites": verdict.summary.oracle_sites,
        "satisfied": verdict.summary.satisfied,
        "gate": verdict.gate.as_str(),
        "waiver": waiver_json(verdict.waiver),
        "unmet": unmet,
        "edge": edge,
    })
}

fn edge_coverage_json(
    edge_coverage: &EdgeCoverageState,
    artifact_path: &Path,
) -> serde_json::Value {
    match edge_coverage {
        EdgeCoverageState::Unavailable { reason, hint } => serde_json::json!({
            "state": "unavailable",
            "reason": reason,
            "hint": hint,
        }),
        EdgeCoverageState::Active(store) => {
            let Some(meta) = store.meta() else {
                return serde_json::json!({
                    "state": "pending",
                    "coverage_dir": store.dir().display().to_string(),
                });
            };
            let (top_uncovered, top_uncovered_error) =
                match top_uncovered_crates(artifact_path, store, 5) {
                    Ok(rows) => (
                        rows.into_iter()
                            .map(|(krate, uncovered, total)| {
                                serde_json::json!({
                                    "crate": krate,
                                    "uncovered_edges": uncovered,
                                    "edges_total": total,
                                })
                            })
                            .collect::<Vec<_>>(),
                        serde_json::Value::Null,
                    ),
                    Err(error) => (Vec::new(), serde_json::json!(error.to_string())),
                };
            serde_json::json!({
                "state": "available",
                "schema": crate::coverage::CAMPAIGN_COVERAGE_SCHEMA,
                "coverage_dir": store.dir().display().to_string(),
                "edges_total": meta.edges_total,
                "edges_covered": meta.edges_covered,
                "covered_permille": meta.covered_permille(),
                "generations_applied": meta.generations_applied,
                "last_new_edge_gen": meta.last_new_edge_gen,
                "plateau_after": meta.plateau_window,
                "plateaued": meta.plateaued,
                "new_edge_log": meta.new_edge_log.iter().map(|(generation, new_edges)| serde_json::json!([generation, new_edges])).collect::<Vec<_>>(),
                "top_uncovered_crates": top_uncovered,
                "top_uncovered_crates_error": top_uncovered_error,
            })
        }
    }
}

fn sdk_sites_summary_json(
    coverage: &CoverageTally,
    verdict: &CoverageVerdict<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "labels_seen": verdict.summary.labels_seen,
        "generations_observed": coverage.generations_observed,
        "sometimes_unsatisfied": verdict.summary.sometimes_unsatisfied,
        "reachable_unreached": verdict.summary.reachable_unreached,
        "always_violated": verdict.summary.always_violated,
    })
}

#[cfg(test)]
mod tests {
    use super::super::classify::STARVATION_STALL_EXIT;
    use super::super::observe::{DepthState, EdgeCoverageState};
    use super::super::selftest::planted;
    use super::super::state::{ArtifactIdentity, CampaignState, GenerationOutcome};
    use super::super::{CampaignClass, CampaignSpec, ClassifyRules, RunFacts, classify};
    use super::*;
    use crate::sdk_report::CoverageTally;
    use std::path::Path;

    /// A wedge the `--starve` backstop killed is not a bug found. The backstop
    /// arms only under `--starve`, so exit 111 always means patina's own injector
    /// was holding tasks off when progress stopped, and std's uninstrumented spin
    /// loops make that wedge a limitation of the injector rather than a verdict
    /// on the guest. It stays its own class — an operator tunes
    /// `--starve-scale-permille` by reading it — and it stays a failure, but it
    /// must not spend the novel-signature budget that counts DISTINCT BUGS. The
    /// guest's own livelock keeps its finding: that one arrives as `LIVENESS`,
    /// from a watchdog that fires while the scheduler is still making decisions.
    #[test]
    fn a_starvation_stall_is_reported_but_is_not_counted_as_a_bug_found() {
        assert!(CampaignClass::StarvationStall.is_failure());
        assert!(!CampaignClass::StarvationStall.is_finding());
        assert!(CampaignClass::Liveness.is_finding());
        assert_ne!(
            CampaignClass::StarvationStall.as_str(),
            CampaignClass::Infra.as_str(),
            "folding the stall into INFRA would erase which generations the injector wedged"
        );
        // Both halves of the classifier still reach the class: the supervisor's
        // distinct exit code, and the envelope refusal the child reports.
        let rules = ClassifyRules::default();
        assert_eq!(
            classify(
                &planted(RunFacts::ok().exit(STARVATION_STALL_EXIT).no_envelope(), ""),
                &rules
            ),
            CampaignClass::StarvationStall
        );
        assert_eq!(
            classify(
                &planted(RunFacts::ok().exit(2).refusal("starvation_stall"), ""),
                &rules
            ),
            CampaignClass::StarvationStall
        );
    }

    #[test]
    fn envelope_is_summary_first_with_artifact_pointers() {
        // A campaign of four generations: two OK, one failing (non-novel repeat),
        // one novel failing. The v2 envelope must expose the class histogram and
        // deduped signatures, but per-run detail (`notable_runs`) ONLY for the
        // novel/failing generations — the two OK generations are elided.
        let mk = |generation: u64, class: CampaignClass, novel: bool| GenerationOutcome {
            generation,
            seed: generation,
            class,
            flags: Vec::new(),
            novel,
            signature_key: class.is_failure().then(|| "LIVENESS|shape|".to_string()),
            verdicts: Vec::new(),
        };
        let outcomes = vec![
            mk(0, CampaignClass::Ok, false),
            mk(1, CampaignClass::Liveness, true),
            mk(2, CampaignClass::Ok, false),
            mk(3, CampaignClass::Liveness, false),
        ];
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec {
                generations: 4,
                ..CampaignSpec::default()
            },
        );
        state.classes.insert("OK".to_string(), 2);
        state.classes.insert("LIVENESS".to_string(), 2);
        state.generations_done = 4;
        state.notable_runs = outcomes
            .into_iter()
            .filter(GenerationOutcome::is_notable)
            .collect();
        let coverage = CoverageTally {
            generations_observed: 4,
            ..CoverageTally::default()
        };
        let coverage_verdict = coverage_verdict(&coverage, None);
        let edge_coverage = EdgeCoverageState::unavailable("not-instrumented", None);
        let depth = DepthState::Unavailable {
            reason: "not-wasi",
            hint: None,
        };
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result: "failure",
            exit_code: 1,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            depth: &depth,
            guidance: None,
            out_dir: Path::new("out"),
            state_path: Path::new("out/campaign-state.json"),
            sites_path: Path::new("out/sites.json"),
        });

        assert_eq!(envelope["schema"], CAMPAIGN_ENVELOPE_SCHEMA);
        assert_eq!(envelope["schema"], "patina.campaign/v2");
        assert_eq!(envelope["classes"]["OK"], 2);
        assert_eq!(envelope["classes"]["LIVENESS"], 2);

        // Only the two novel/failing generations appear in `notable_runs`; the OK
        // generations are represented solely by the class histogram.
        let notable = envelope["notable_runs"].as_array().unwrap();
        assert_eq!(
            notable.len(),
            2,
            "OK generations must be elided: {envelope:#}"
        );
        let gens: Vec<u64> = notable
            .iter()
            .map(|r| r["generation"].as_u64().unwrap())
            .collect();
        assert_eq!(gens, vec![1, 3]);
        assert!(notable.iter().all(|r| r["class"] == "LIVENESS"));

        // Machine-readable pointers keep the full on-disk detail reachable.
        let artifacts = &envelope["artifacts"];
        assert_eq!(artifacts["out_dir"], "out");
        assert!(
            artifacts["campaign_state"]
                .as_str()
                .unwrap()
                .ends_with("campaign-state.json")
        );
        assert!(
            artifacts["signature_store"]
                .as_str()
                .unwrap()
                .ends_with("signatures.json")
        );
        assert!(
            artifacts["failures_dir"]
                .as_str()
                .unwrap()
                .ends_with("failures"),
            "a failing campaign must point at its saved-trace dir: {envelope:#}"
        );
        assert!(
            artifacts["site_coverage"]
                .as_str()
                .unwrap()
                .ends_with("sites.json")
        );
        assert_eq!(envelope["sdk_sites"]["labels_seen"], 0);
        assert_eq!(envelope["coverage"]["gate"], "pass");
        // No `--report`, so no reports pointer is promised.
        assert!(artifacts.get("reports_dir").is_none());
    }

    #[test]
    fn envelope_clean_campaign_omits_failure_pointers() {
        // A clean campaign advertises no failures dir (it is never created).
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec::default(),
        );
        state.classes.insert("OK".to_string(), 1);
        state.generations_done = 1;
        let coverage = CoverageTally {
            generations_observed: 1,
            ..CoverageTally::default()
        };
        let coverage_verdict = coverage_verdict(&coverage, None);
        let edge_coverage = EdgeCoverageState::unavailable("not-instrumented", None);
        let depth = DepthState::Unavailable {
            reason: "not-wasi",
            hint: None,
        };
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result: "ok",
            exit_code: 0,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            depth: &depth,
            guidance: None,
            out_dir: Path::new("out"),
            state_path: Path::new("out/campaign-state.json"),
            sites_path: Path::new("out/sites.json"),
        });
        assert_eq!(envelope["failures"], 0);
        assert!(envelope["notable_runs"].as_array().unwrap().is_empty());
        assert!(envelope["artifacts"].get("failures_dir").is_none());
    }
}
