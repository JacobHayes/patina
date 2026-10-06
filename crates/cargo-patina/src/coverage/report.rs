//! Coverage JSON and human reports.

use super::*;

pub(super) fn coverage_json(
    invocation: &CoverageInvocation,
    data: &CoverageData,
    report: &CoverageReportTree,
) -> Value {
    json!({
        "schema": COVERAGE_ENVELOPE_SCHEMA,
        "verb": "coverage",
        "artifact": invocation.binary.display().to_string(),
        "input": invocation.input.display().to_string(),
        "input_kind": data.input_kind,
        "summary": coverage_summary_json(data),
        "rollup": rollup_json(report, data),
        "functions": functions_json(report, data),
        "focus": invocation.options.focus,
    })
}

fn coverage_summary_json(data: &CoverageData) -> Value {
    let mut object = Map::new();
    object.insert("edges_total".into(), data.edges_total.into());
    object.insert("edges_covered".into(), data.edges_covered.into());
    object.insert("covered_permille".into(), data.covered_permille.into());
    object.insert("hits_total".into(), data.hits_total.into());
    object.insert("hits_max".into(), data.hits_max.into());
    object.insert("saturated".into(), data.saturated.into());
    object.insert("range_count".into(), (data.ranges.len() as u64).into());
    if let Some(value) = data.generations_applied {
        object.insert("generations_applied".into(), value.into());
    }
    if let Some(value) = data.last_new_edge_gen {
        object.insert("last_new_edge_gen".into(), value.into());
    }
    if let Some(value) = data.plateau_window {
        object.insert("plateau_window".into(), value.into());
    }
    if let Some(value) = data.plateaued {
        object.insert("plateaued".into(), value.into());
    }
    if !data.new_edge_log.is_empty() {
        object.insert(
            "new_edge_log".into(),
            data.new_edge_log
                .iter()
                .map(|(generation, new_edges)| json!([generation, new_edges]))
                .collect::<Vec<_>>()
                .into(),
        );
    }
    Value::Object(object)
}

fn rollup_json(report: &CoverageReportTree, data: &CoverageData) -> Value {
    let crates = report
        .rollup
        .crates
        .iter()
        .map(|krate| {
            let stats = report.crates.get(&krate.name).cloned().unwrap_or_default();
            let modules = krate
                .modules
                .iter()
                .map(|module| {
                    let stats = report
                        .modules
                        .get(&(krate.name.clone(), module.module.clone()))
                        .cloned()
                        .unwrap_or_default();
                    json!({
                        "module": module.module,
                        "edges_total": stats.edges_total,
                        "edges_covered": stats.edges_covered,
                        "covered_permille": stats.covered_permille(),
                        "hits_total": stats.hits_total,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "name": krate.name,
                "edges_total": stats.edges_total,
                "edges_covered": stats.edges_covered,
                "covered_permille": stats.covered_permille(),
                "hits_total": stats.hits_total,
                "hits_share_permille": permille(stats.hits_total, data.hits_total),
                "over_rep_permille": over_rep_permille(stats.edges_total, stats.hits_total, data.edges_total, data.hits_total),
                "by_edge_state": krate.by_bucket,
                "modules": modules,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "edges_total": data.edges_total,
        "by_edge_state": report.rollup.by_bucket,
        "crates": crates,
    })
}

fn functions_json(report: &CoverageReportTree, data: &CoverageData) -> Value {
    report
        .functions
        .iter()
        .map(|(function, stats)| {
            json!({
                "function": function,
                "edges_total": stats.edges_total,
                "edges_covered": stats.edges_covered,
                "covered_permille": stats.covered_permille(),
                "hits_total": stats.hits_total,
                "hits_share_permille": permille(stats.hits_total, data.hits_total),
            })
        })
        .collect::<Vec<_>>()
        .into()
}

fn over_rep_permille(edges: u64, hits: u64, total_edges: u64, total_hits: u64) -> u64 {
    if edges == 0 || total_edges == 0 || total_hits == 0 {
        return 0;
    }
    // (hits / total_hits) / (edges / total_edges) scaled by 1000.
    ((hits as u128 * total_edges as u128 * 1000) / (total_hits as u128 * edges as u128)) as u64
}

pub(super) fn print_coverage_human(
    invocation: &CoverageInvocation,
    data: &CoverageData,
    report: &CoverageReportTree,
) {
    println!("== coverage ==");
    println!(
        "artifact={} input={} kind={}",
        invocation.binary.display(),
        invocation.input.display(),
        data.input_kind
    );
    println!(
        "edges={}/{} covered={} hits_total={} hits_max={} saturated={}",
        data.edges_covered,
        data.edges_total,
        percent_string_permille(data.covered_permille),
        data.hits_total,
        data.hits_max,
        data.saturated
    );
    if let Some(generations) = data.generations_applied {
        println!(
            "campaign_generations_applied={} last_new_edge_gen={} plateau_after={} plateaued={}",
            generations,
            data.last_new_edge_gen
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            data.plateau_window.unwrap_or(0),
            data.plateaued.unwrap_or(false) as u8,
        );
    }
    println!("-- crates --");
    println!("crate edges pct hits_share over_rep");
    for krate in &report.rollup.crates {
        let stats = report.crates.get(&krate.name).cloned().unwrap_or_default();
        println!(
            "{} {}/{} {} {} {}x",
            krate.name,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            percent_string(stats.hits_total, data.hits_total),
            ratio_string(over_rep_permille(
                stats.edges_total,
                stats.hits_total,
                data.edges_total,
                data.hits_total,
            )),
        );
    }
    if let Some(focus) = &invocation.options.focus {
        print_focus(focus, report);
    }
    if let Some(top) = invocation.options.top {
        print_top(top, report);
    }
}

fn ratio_string(permille: u64) -> String {
    format!("{}.{:03}", permille / 1000, permille % 1000)
}

fn print_focus(focus: &str, report: &CoverageReportTree) {
    println!("-- focus {focus} --");
    println!("path edges pct hits");
    for ((_, module), stats) in report
        .modules
        .iter()
        .filter(|((krate, module), _)| krate == focus || module.starts_with(focus))
    {
        println!(
            "{} {}/{} {} {}",
            module,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            stats.hits_total,
        );
    }
    for (function, stats) in report
        .functions
        .iter()
        .filter(|(function, _)| function.starts_with(focus))
    {
        println!(
            "{} {}/{} {} {}",
            function,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            stats.hits_total,
        );
    }
}

fn print_top(top: usize, report: &CoverageReportTree) {
    if top == 0 {
        return;
    }
    let mut functions: Vec<_> = report.functions.iter().collect();
    functions.sort_by(|(left_name, left), (right_name, right)| {
        right
            .hits_total
            .cmp(&left.hits_total)
            .then_with(|| right.edges_covered.cmp(&left.edges_covered))
            .then_with(|| left_name.cmp(right_name))
    });
    println!("-- top hot functions --");
    for (function, stats) in functions.iter().take(top) {
        println!(
            "{} hits={} edges={}/{} pct={}",
            function,
            stats.hits_total,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
        );
    }
    functions.sort_by(|(left_name, left), (right_name, right)| {
        left.edges_covered
            .cmp(&right.edges_covered)
            .then_with(|| right.edges_total.cmp(&left.edges_total))
            .then_with(|| left_name.cmp(right_name))
    });
    println!("-- top cold functions --");
    for (function, stats) in functions.iter().take(top) {
        println!(
            "{} hits={} edges={}/{} pct={}",
            function,
            stats.hits_total,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
        );
    }
}

pub(crate) fn top_uncovered_crates(
    binary: &Path,
    store: &CampaignCoverageStore,
    limit: usize,
) -> Result<Vec<(String, u64, u64)>, CliError> {
    let Some(data) = store.as_coverage_data() else {
        return Ok(Vec::new());
    };
    let report = symbolize_coverage(binary, &data)?;
    let mut rows: Vec<_> = report
        .crates
        .iter()
        .map(|(name, stats)| {
            (
                name.clone(),
                stats.edges_total.saturating_sub(stats.edges_covered),
                stats.edges_total,
            )
        })
        .filter(|(_, uncovered, _)| *uncovered > 0)
        .collect();
    rows.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });
    rows.truncate(limit);
    Ok(rows)
}
