//! Static/runtime site joins and reports.

use super::*;

const RUNTIME_ORDER: &[&str] = &["driven", "observed", "invisible"];
pub(super) const KIND_ORDER: &[&str] = &[
    "fault",
    "delay",
    "knob",
    "always",
    "sometimes",
    "reachable",
    "assert",
    "debug_assert",
    "prop_assert",
    "proptest",
    "quickcheck",
    "antithesis_always",
    "antithesis_sometimes",
    "antithesis_reachable",
    "antithesis_unreachable",
    "unreachable",
];

#[derive(Clone, Debug)]
struct JoinedSite<'a> {
    site: &'a SiteRecord,
    exercised: Option<&'a ExercisedSite>,
    never_exercised: bool,
}

impl RollupLeaf for JoinedSite<'_> {
    fn crate_name(&self) -> &str {
        &self.site.crate_name
    }

    fn module(&self) -> &str {
        &self.site.module
    }

    fn groups(&self) -> &[String] {
        &self.site.groups
    }

    fn bucket(&self) -> &str {
        &self.site.runtime
    }

    fn is_gap(&self) -> bool {
        self.never_exercised
    }
}

#[derive(Clone, Debug, Default)]
struct JoinResult<'a> {
    by_site_id: BTreeMap<String, &'a ExercisedSite>,
    unmatched: Vec<UnmatchedRuntimeSite>,
}

#[derive(Clone, Debug, Serialize)]
struct UnmatchedRuntimeSite {
    label: String,
    kind: String,
    site: String,
    origin: &'static str,
}

/// The named marker line for a static duplicate-label finding, mirroring the
/// runtime's fatal `PATINA_BUGGIFY_DUPLICATE_LABEL` abort (see `Buggify::declare`
/// / `Buggify::register` in `patina-runtime`) so the same class is visible at
/// inventory time instead of only at first run.
const SITES_DUPLICATE_LABEL_MARKER: &str = "PATINA_SITES_DUPLICATE_LABEL";

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DuplicateLabelFinding {
    label: String,
    count: usize,
    sites: Vec<String>,
}

pub(super) fn duplicate_label_marker_line(finding: &DuplicateLabelFinding) -> String {
    format!(
        "{SITES_DUPLICATE_LABEL_MARKER} label={} count={} sites={}",
        finding.label,
        finding.count,
        finding.sites.join(",")
    )
}

/// Find labels that the runtime would reject as a fatal duplicate: the same
/// literal label used for the SDK's own cooperative-SUT macros
/// (`buggify`/`always`/`sometimes`/`reachable`, i.e. `runtime` "driven" or
/// "observed") at more than one distinct `(file:line, kind)`. This mirrors
/// `Buggify::declare`/`Buggify::register`'s `existing.site != site ||
/// existing.kind != kind` test exactly, so the static gate and the runtime
/// abort agree on what counts as a duplicate. Dynamic labels (unknowable
/// statically) and antithesis-facade labels (`runtime` "invisible", a
/// different registry) are not compared.
pub(super) fn find_duplicate_labels(sites: &[SiteRecord]) -> Vec<DuplicateLabelFinding> {
    let mut by_label: BTreeMap<&str, Vec<&SiteRecord>> = BTreeMap::new();
    for site in sites {
        if site.label_dynamic || site.runtime == "invisible" {
            continue;
        }
        if let Some(label) = &site.label {
            by_label.entry(label.as_str()).or_default().push(site);
        }
    }
    by_label
        .into_iter()
        .filter_map(|(label, group)| {
            fn identity(site: &SiteRecord) -> (&str, usize, &str) {
                (site.file.as_str(), site.line, site.kind.as_str())
            }
            let first = identity(group[0]);
            if !group.iter().any(|site| identity(site) != first) {
                return None;
            }
            let mut sites = group
                .iter()
                .map(|site| format!("{}:{}", site.file, site.line))
                .collect::<Vec<_>>();
            sites.sort();
            sites.dedup();
            Some(DuplicateLabelFinding {
                label: label.to_string(),
                count: group.len(),
                sites,
            })
        })
        .collect()
}

pub(super) fn build_report(
    scan: &StaticScan,
    options: &SitesOptions,
    exercised: Option<&ExercisedSource>,
    duplicate_labels: &[DuplicateLabelFinding],
) -> Value {
    let join = exercised
        .map(|source| join_exercised(scan, source))
        .unwrap_or_default();
    let filtered = scan
        .sites
        .iter()
        .filter(|site| site_matches(site, options))
        .map(|site| {
            let exercised_site = join.by_site_id.get(&site.id).copied();
            JoinedSite {
                site,
                exercised: exercised_site,
                never_exercised: exercised.is_some()
                    && site.runtime != "invisible"
                    && exercised_site.is_none_or(|row| row.registered_gens == 0),
            }
        })
        .collect::<Vec<_>>();
    let warnings = exercised
        .filter(|source| source.sites.is_empty())
        .and_then(|_| {
            filtered
                .iter()
                .any(|joined| joined.site.runtime == "driven")
                .then(|| {
                    "WARNING: exercised source contained zero SDK site rows while the static inventory has driven sites; coverage may be vacuous"
                        .to_string()
                })
        })
        .into_iter()
        .collect::<Vec<_>>();
    let rollup = build_rollup(&filtered, RUNTIME_ORDER);
    let static_sites = filtered
        .iter()
        .map(|joined| joined.site.clone())
        .collect::<Vec<_>>();
    let by_kind = count_by_kind(&static_sites);

    let mut totals = json!({
        "sites": filtered.len(),
        "by_runtime": rollup.by_bucket,
        "by_kind": by_kind,
    });
    if exercised.is_some() {
        totals["exercised"] = exercised_totals(&filtered, &join);
    }

    let mut root = Map::new();
    root.insert("schema".to_string(), json!(SITES_SCHEMA));
    root.insert("verb".to_string(), json!("sites"));
    root.insert(
        "scan".to_string(),
        json!({
            "workspace_root": scan.workspace_root.display().to_string(),
            "files_scanned": scan.files_scanned,
            "files_unparsed": scan.files_unparsed,
            "cache": scan.cache_state.as_str(),
            "recognizers": RECOGNIZER_NAMES.len(),
            "recognizer_version": RECOGNIZER_TABLE_VERSION,
            "unparsed": scan.unparsed,
        }),
    );
    if let Some(source) = exercised {
        root.insert(
            "exercised_source".to_string(),
            json!({
                "kind": source.kind,
                "path": source.path,
                "reports": source.reports,
                "generations_observed": source.generations_observed,
            }),
        );
    }
    if !warnings.is_empty() {
        root.insert("warnings".to_string(), json!(warnings));
    }
    if !duplicate_labels.is_empty() {
        root.insert("duplicate_labels".to_string(), json!(duplicate_labels));
    }
    if let Some(config) = crate::config::provenance_json() {
        root.insert("config".to_string(), config);
    }
    root.insert("totals".to_string(), totals);
    root.insert(
        "crates".to_string(),
        crate_rollups_json(&rollup.crates, exercised.is_some()),
    );
    root.insert(
        "groups".to_string(),
        group_rollups_json(&rollup.groups, exercised.is_some()),
    );
    root.insert(
        "unmatched_runtime_labels".to_string(),
        json!(join.unmatched.len()),
    );
    if !join.unmatched.is_empty() {
        root.insert("unmatched".to_string(), json!(join.unmatched));
    }
    if options.scoped() {
        root.insert("sites".to_string(), site_rows_json(&filtered));
        root.insert(
            "detail".to_string(),
            json!({
                "mode": if exercised.is_some() { "static+exercised" } else { "static" },
                "honesty": if exercised.is_some() {
                    "Runtime rows are joined to static SDK labels or dynamic-label file:line sites; invisible sites remain inventory-only and carry no exercised object."
                } else {
                    "Static-only report has no exercised source; invisible sites are inventoried but Patina cannot observe their execution."
                },
            }),
        );
    } else {
        root.insert(
            "detail".to_string(),
            json!({
                "hint": "Per-site rows are omitted from this index.",
                "command_template": "cargo patina sites --module {module} --format json",
            }),
        );
    }
    Value::Object(root)
}

fn join_exercised<'a>(scan: &StaticScan, source: &'a ExercisedSource) -> JoinResult<'a> {
    let mut by_label: BTreeMap<&str, &SiteRecord> = BTreeMap::new();
    let mut dynamic_by_location: BTreeMap<String, &SiteRecord> = BTreeMap::new();
    for site in &scan.sites {
        if matches!(site.runtime.as_str(), "driven" | "observed") {
            if let Some(label) = &site.label {
                by_label.insert(label, site);
            } else if site.label_dynamic {
                dynamic_by_location.insert(format!("{}:{}", site.file, site.line), site);
            }
        }
    }

    let mut joined = JoinResult::default();
    for exercised in source.sites.values() {
        if let Some(site) = by_label.get(exercised.label.as_str()) {
            joined.by_site_id.insert(site.id.clone(), exercised);
            continue;
        }
        if let Some(location) = normalize_runtime_site(&scan.workspace_root, &exercised.site) {
            if let Some(site) = dynamic_by_location.get(&location) {
                joined.by_site_id.insert(site.id.clone(), exercised);
                continue;
            }
        }
        joined.unmatched.push(UnmatchedRuntimeSite {
            label: exercised.label.clone(),
            kind: exercised.kind.clone(),
            site: exercised.site.clone(),
            origin: "expanded",
        });
    }
    joined
}

fn normalize_runtime_site(workspace_root: &Path, site: &str) -> Option<String> {
    let (file, line) = site.rsplit_once(':')?;
    if line.parse::<usize>().is_err() {
        return None;
    }
    let mut file = file.replace('\\', "/");
    let root = workspace_root.to_string_lossy().replace('\\', "/");
    if let Some(stripped) = file.strip_prefix(root.trim_end_matches('/')) {
        file = stripped.trim_start_matches('/').to_string();
    }
    Some(format!("{file}:{line}"))
}

fn exercised_totals(filtered: &[JoinedSite<'_>], join: &JoinResult<'_>) -> Value {
    let mut joined_runtime_labels = 0_u64;
    let mut driven_fired = 0_u64;
    let mut observed_satisfied = 0_u64;
    let mut never_exercised = 0_u64;
    for joined in filtered {
        if joined.never_exercised {
            never_exercised += 1;
        }
        let Some(exercised) = joined.exercised else {
            continue;
        };
        joined_runtime_labels += 1;
        match joined.site.kind.as_str() {
            "fault" | "delay" if exercised.fires > 0 => driven_fired += 1,
            "knob" if exercised.knob_min.is_some() => driven_fired += 1,
            "always" if exercised.evals > 0 && exercised.always_violated_runs == 0 => {
                observed_satisfied += 1;
            }
            "sometimes" if exercised.sometimes_satisfied_runs > 0 => observed_satisfied += 1,
            "reachable" if exercised.reachable_runs > 0 => observed_satisfied += 1,
            _ => {}
        }
    }
    json!({
        "runtime_labels": joined_runtime_labels + join.unmatched.len() as u64,
        "joined_runtime_labels": joined_runtime_labels,
        "unmatched_runtime_labels": join.unmatched.len(),
        "driven_fired": driven_fired,
        "observed_satisfied": observed_satisfied,
        "never_exercised": never_exercised,
    })
}

fn site_rows_json(sites: &[JoinedSite<'_>]) -> Value {
    Value::Array(
        sites
            .iter()
            .map(|joined| {
                let mut value = serde_json::to_value(joined.site)
                    .expect("site records are JSON-serializable objects");
                if let (Some(object), Some(exercised)) = (value.as_object_mut(), joined.exercised) {
                    if joined.site.runtime != "invisible" {
                        object.insert("exercised".to_string(), json!(exercised));
                    }
                }
                value
            })
            .collect(),
    )
}

fn site_matches(site: &SiteRecord, options: &SitesOptions) -> bool {
    if let Some(crate_filter) = &options.crate_filter {
        if &site.crate_name != crate_filter {
            return false;
        }
    }
    if let Some(module_filter) = &options.module_filter {
        if &site.module != module_filter {
            return false;
        }
    }
    if let Some(group_filter) = &options.group_filter {
        if !site.groups.iter().any(|group| group == group_filter) {
            return false;
        }
    }
    if let Some(site_filter) = &options.site_filter {
        if &site.id != site_filter && site.label.as_ref() != Some(site_filter) {
            return false;
        }
    }
    if let Some(kind_filter) = &options.kind_filter {
        if &site.kind != kind_filter {
            return false;
        }
    }
    if let Some(runtime_filter) = &options.runtime_filter {
        if &site.runtime != runtime_filter {
            return false;
        }
    }
    true
}

pub(super) fn count_by_kind(sites: &[SiteRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for kind in KIND_ORDER {
        counts.insert((*kind).to_string(), 0);
    }
    for site in sites {
        *counts.entry(site.kind.clone()).or_insert(0) += 1;
    }
    counts
}

fn crate_rollups_json(crates: &[crate::rollup::CrateRollup], include_gaps: bool) -> Value {
    Value::Array(
        crates
            .iter()
            .map(|krate| {
                let mut value = json!({
                    "name": krate.name,
                    "sites": krate.total,
                    "by_runtime": krate.by_bucket,
                    "modules": krate.modules.iter().map(|module| {
                        let mut module_value = json!({
                            "module": module.module,
                            "sites": module.total,
                            "by_runtime": module.by_bucket,
                        });
                        if include_gaps {
                            module_value["never_exercised"] = json!(module.gaps);
                        }
                        module_value
                    }).collect::<Vec<_>>(),
                });
                if include_gaps {
                    value["never_exercised"] = json!(krate.gaps);
                }
                value
            })
            .collect(),
    )
}

fn group_rollups_json(groups: &[crate::rollup::GroupRollup], include_gaps: bool) -> Value {
    Value::Array(
        groups
            .iter()
            .map(|group| {
                let mut value = json!({
                    "name": group.name,
                    "sites": group.total,
                    "by_runtime": group.by_bucket,
                });
                if include_gaps {
                    value["never_exercised"] = json!(group.gaps);
                }
                value
            })
            .collect(),
    )
}

pub(super) fn print_human(report: &Value) {
    let scan = &report["scan"];
    let totals = &report["totals"];
    println!("== sites static inventory ==");
    println!(
        "workspace={} files_scanned={} files_unparsed={} cache={} recognizers={}",
        scan["workspace_root"].as_str().unwrap_or("?"),
        scan["files_scanned"].as_u64().unwrap_or(0),
        scan["files_unparsed"].as_u64().unwrap_or(0),
        scan["cache"].as_str().unwrap_or("?"),
        scan["recognizers"].as_u64().unwrap_or(0),
    );
    println!(
        "sites={} driven={} observed={} invisible={}",
        totals["sites"].as_u64().unwrap_or(0),
        totals["by_runtime"]["driven"].as_u64().unwrap_or(0),
        totals["by_runtime"]["observed"].as_u64().unwrap_or(0),
        totals["by_runtime"]["invisible"].as_u64().unwrap_or(0),
    );
    if let Some(source) = report.get("exercised_source") {
        println!(
            "exercised_source={} kind={} reports={} generations_observed={} joined={} unmatched={} never_exercised={}",
            source["path"].as_str().unwrap_or("?"),
            source["kind"].as_str().unwrap_or("?"),
            source["reports"].as_u64().unwrap_or(0),
            source["generations_observed"].as_u64().unwrap_or(0),
            totals["exercised"]["joined_runtime_labels"]
                .as_u64()
                .unwrap_or(0),
            totals["exercised"]["unmatched_runtime_labels"]
                .as_u64()
                .unwrap_or(0),
            totals["exercised"]["never_exercised"].as_u64().unwrap_or(0),
        );
    }
    // Duplicate-label findings are NOT re-printed here: the marker goes to
    // stderr in both output modes at the run_scan level, so wrappers that
    // discard stdout still see which label collided.
    if let Some(warnings) = report.get("warnings").and_then(Value::as_array) {
        for warning in warnings {
            println!(
                "{}",
                warning.as_str().unwrap_or("WARNING: unknown sites warning")
            );
        }
    }
    if scan["files_unparsed"].as_u64().unwrap_or(0) > 0 {
        println!("WARNING: unparsed Rust files were counted and omitted from site totals:");
        if let Some(unparsed) = scan["unparsed"].as_array() {
            for row in unparsed {
                println!(
                    "  {}: {}",
                    row["file"].as_str().unwrap_or("?"),
                    row["error"].as_str().unwrap_or("?")
                );
            }
        }
    }
    if let Some(sites) = report.get("sites").and_then(Value::as_array) {
        println!("\n== sites ==");
        for site in sites {
            let label = site.get("label").and_then(Value::as_str).unwrap_or("-");
            let dynamic = if site
                .get("label_dynamic")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                " dynamic-label"
            } else {
                ""
            };
            let exercised = site.get("exercised").map_or_else(String::new, |row| {
                format!(
                    " exercised(reg={} evals={} fires={} satisfied={} reached={})",
                    row["registered_gens"].as_u64().unwrap_or(0),
                    row["evals"].as_u64().unwrap_or(0),
                    row["fires"].as_u64().unwrap_or(0),
                    row["satisfied_gens"].as_u64().unwrap_or(0),
                    row["reachable_runs"].as_u64().unwrap_or(0),
                )
            });
            println!(
                "{}:{} {} {} id={} label={} module={} context={} macro={}{}{}",
                site["file"].as_str().unwrap_or("?"),
                site["line"].as_u64().unwrap_or(0),
                site["kind"].as_str().unwrap_or("?"),
                site["runtime"].as_str().unwrap_or("?"),
                site["id"].as_str().unwrap_or("?"),
                label,
                site["module"].as_str().unwrap_or("?"),
                site["context"].as_str().unwrap_or("?"),
                site["macro_path"].as_str().unwrap_or("?"),
                dynamic,
                exercised,
            );
        }
        if report.get("exercised_source").is_some() {
            println!(
                "\nRuntime rows are joined by label (or dynamic-label file:line); invisible sites remain inventory-only."
            );
        } else {
            println!(
                "\nStatic-only report: exercised data is absent; invisible sites render as inventory only."
            );
        }
    } else {
        println!(
            "\n{:<32} {:>6} {:>7} {:>8} {:>9} {:>7}",
            "crate/module", "sites", "driven", "observed", "invisible", "never"
        );
        if let Some(crates) = report["crates"].as_array() {
            for krate in crates {
                print_rollup_row("", krate, "name");
                if let Some(modules) = krate["modules"].as_array() {
                    for module in modules {
                        print_rollup_row("  ", module, "module");
                    }
                }
            }
        }
        println!(
            "\nPer-site rows omitted. Drill down with `cargo patina sites --module <PATH>` or `--all`."
        );
    }
}

fn print_rollup_row(prefix: &str, row: &Value, name_key: &str) {
    let name = row[name_key].as_str().unwrap_or("?");
    let sites = row["sites"].as_u64().unwrap_or(0);
    let driven = row["by_runtime"]["driven"].as_u64().unwrap_or(0);
    let observed = row["by_runtime"]["observed"].as_u64().unwrap_or(0);
    let invisible = row["by_runtime"]["invisible"].as_u64().unwrap_or(0);
    let never = row["never_exercised"].as_u64().unwrap_or(0);
    println!(
        "{:<32} {:>6} {:>7} {:>8} {:>9} {:>7}",
        format!("{prefix}{name}"),
        sites,
        pct(driven, sites),
        pct(observed, sites),
        pct(invisible, sites),
        never,
    );
}

fn pct(count: u64, total: u64) -> String {
    count
        .checked_mul(100)
        .and_then(|percent| percent.checked_div(total))
        .map(|percent| format!("{percent}%"))
        .unwrap_or_else(|| "0%".to_string())
}

#[cfg(test)]
mod tests;
