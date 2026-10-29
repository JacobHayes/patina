//! Regression tests for report.

use super::*;

/// A statically scanned site in crate `pkg`; no label means a dynamic one.
fn site(
    id: &str,
    kind: &str,
    runtime: &str,
    label: Option<&str>,
    file: &str,
    line: usize,
) -> SiteRecord {
    SiteRecord {
        id: id.to_string(),
        kind: kind.to_string(),
        runtime: runtime.to_string(),
        label: label.map(str::to_string),
        label_dynamic: label.is_none(),
        file: file.to_string(),
        line,
        crate_name: "pkg".to_string(),
        module: "pkg".to_string(),
        context: "src".to_string(),
        macro_path: kind.to_string(),
    }
}

fn scan(sites: Vec<SiteRecord>) -> StaticScan {
    StaticScan {
        workspace_root: PathBuf::from("/workspace"),
        files_scanned: sites.len(),
        sites,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    }
}

fn sdk_report(sites: BTreeMap<String, ExercisedSite>) -> ExercisedSource {
    ExercisedSource {
        kind: "sdk_report".to_string(),
        path: "stderr.log".to_string(),
        reports: 1,
        generations_observed: 1,
        sites,
    }
}

fn exercised(label: &str, site: &str, evals: u64, fires: u64) -> ExercisedSite {
    ExercisedSite {
        label: label.to_string(),
        kind: "fault".to_string(),
        site: site.to_string(),
        first_registered_gen: Some(0),
        last_registered_gen: Some(0),
        registered_gens: 1,
        runs_active: u64::from(fires > 0),
        evals,
        fires,
        runs_fired: u64::from(fires > 0),
        ..ExercisedSite::default()
    }
}

#[test]
fn exercised_source_joins_labels_and_dynamic_file_line_sites() {
    let scan = scan(vec![
        site(
            "static-label",
            "fault",
            "driven",
            Some("static-label"),
            "src/main.rs",
            10,
        ),
        site(
            "src/main.rs:12:5#fault",
            "fault",
            "driven",
            None,
            "src/main.rs",
            12,
        ),
    ]);
    let source = sdk_report(BTreeMap::from([
        (
            "static-label".to_string(),
            exercised("static-label", "src/main.rs:10", 2, 1),
        ),
        (
            "dynamic-at-runtime".to_string(),
            exercised("dynamic-at-runtime", "/workspace/src/main.rs:12", 1, 0),
        ),
    ]));
    let report = build_report(
        &scan,
        &SitesOptions {
            all: true,
            ..SitesOptions::default()
        },
        Some(&source),
        &[],
    );
    assert_eq!(report["schema"], SITES_SCHEMA);
    assert_eq!(report["unmatched_runtime_labels"], 0);
    assert_eq!(report["totals"]["exercised"]["joined_runtime_labels"], 2);
    let rows = report["sites"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["exercised"]["fires"], 1);
    assert_eq!(rows[1]["exercised"]["label"], "dynamic-at-runtime");
}

#[test]
fn unmatched_runtime_labels_are_visible_not_dropped() {
    let source = sdk_report(BTreeMap::from([(
        "wrapped".to_string(),
        exercised("wrapped", "src/lib.rs:1", 0, 0),
    )]));
    let report = build_report(
        &scan(Vec::new()),
        &SitesOptions::default(),
        Some(&source),
        &[],
    );
    assert_eq!(report["unmatched_runtime_labels"], 1);
    assert_eq!(report["unmatched"][0]["origin"], "expanded");
}

#[test]
fn empty_exercised_source_warns_when_static_driven_sites_exist() {
    let scan = scan(vec![site(
        "static-label",
        "fault",
        "driven",
        Some("static-label"),
        "src/main.rs",
        10,
    )]);
    let source = ExercisedSource {
        kind: "campaign".to_string(),
        path: "out".to_string(),
        reports: 3,
        generations_observed: 3,
        sites: BTreeMap::new(),
    };
    let report = build_report(&scan, &SitesOptions::default(), Some(&source), &[]);
    assert!(
        report["warnings"]
            .as_array()
            .is_some_and(|warnings| !warnings.is_empty()),
        "expected vacuity warning: {report:#}"
    );
}

/// The runtime's `Buggify::declare`/`register` reject a label declared at two
/// call sites at first run as `PATINA_BUGGIFY_DUPLICATE_LABEL`; the static gate
/// must catch it before anything runs, for a same-kind or a cross-kind reuse,
/// while dynamic labels and antithesis-facade labels (a different registry)
/// are never compared.
#[test]
fn a_label_reused_across_call_sites_is_a_fatal_finding() {
    let label = Some("dedup-suppressed-double-apply");
    let sites = vec![
        site(
            "src/apply.rs:42#sometimes",
            "sometimes",
            "observed",
            label,
            "src/apply.rs",
            42,
        ),
        site(
            "src/dedup.rs:17#sometimes",
            "sometimes",
            "observed",
            label,
            "src/dedup.rs",
            17,
        ),
    ];
    let findings = find_duplicate_labels(&sites);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].label, "dedup-suppressed-double-apply");
    assert_eq!(findings[0].count, 2);
    assert_eq!(
        findings[0].sites,
        vec!["src/apply.rs:42".to_string(), "src/dedup.rs:17".to_string()]
    );
    assert_eq!(
        duplicate_label_marker_line(&findings[0]),
        "PATINA_SITES_DUPLICATE_LABEL label=dedup-suppressed-double-apply count=2 sites=src/apply.rs:42,src/dedup.rs:17"
    );
    // The finding is carried into the JSON report.
    let report = build_report(
        &scan(sites.clone()),
        &SitesOptions::default(),
        None,
        &findings,
    );
    assert_eq!(
        report["duplicate_labels"][0]["label"],
        "dedup-suppressed-double-apply"
    );
    assert_eq!(report["duplicate_labels"][0]["count"], 2);

    // Unique labels: no finding.
    let mut clean = sites.clone();
    clean[1].label = Some("dedup-suppressed-double-apply-2".to_string());
    assert!(find_duplicate_labels(&clean).is_empty());

    // The runtime compares `(site, kind)`, so a cross-kind reuse is fatal too.
    let cross_kind = vec![
        site(
            "src/a.rs:1#fault",
            "fault",
            "driven",
            Some("shared"),
            "src/a.rs",
            1,
        ),
        site(
            "src/b.rs:2#always",
            "always",
            "observed",
            Some("shared"),
            "src/b.rs",
            2,
        ),
    ];
    assert_eq!(find_duplicate_labels(&cross_kind).len(), 1);

    let mut dynamic = cross_kind.clone();
    for site in &mut dynamic {
        site.label_dynamic = true;
    }
    assert!(find_duplicate_labels(&dynamic).is_empty());
    let antithesis = |file: &str, line: usize| {
        site(
            &format!("{file}:{line}#antithesis_always"),
            "antithesis_always",
            "invisible",
            Some("antithesis-label"),
            file,
            line,
        )
    };
    assert!(
        find_duplicate_labels(&[antithesis("src/c.rs", 3), antithesis("src/d.rs", 4)]).is_empty()
    );
}
