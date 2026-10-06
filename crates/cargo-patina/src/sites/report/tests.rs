//! Regression tests for report.

use super::*;

#[test]
fn scoped_json_carries_site_rows() {
    let scan = StaticScan {
        workspace_root: PathBuf::from("/w"),
        sites: vec![SiteRecord {
            id: "label".to_string(),
            kind: "always".to_string(),
            runtime: "observed".to_string(),
            label: Some("label".to_string()),
            label_dynamic: false,
            file: "src/lib.rs".to_string(),
            line: 1,
            crate_name: "pkg".to_string(),
            module: "pkg".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "always".to_string(),
        }],
        files_scanned: 1,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    };
    let report = build_report(
        &scan,
        &SitesOptions {
            module_filter: Some("pkg".to_string()),
            ..SitesOptions::default()
        },
        None,
        &[],
    );
    assert_eq!(report["schema"], SITES_SCHEMA);
    assert_eq!(report["sites"].as_array().unwrap().len(), 1);
    assert_eq!(report["unmatched_runtime_labels"], 0);
}

#[test]
fn exercised_source_joins_labels_and_dynamic_file_line_sites() {
    let scan = StaticScan {
        workspace_root: PathBuf::from("/workspace"),
        sites: vec![
            SiteRecord {
                id: "static-label".to_string(),
                kind: "fault".to_string(),
                runtime: "driven".to_string(),
                label: Some("static-label".to_string()),
                label_dynamic: false,
                file: "src/main.rs".to_string(),
                line: 10,
                crate_name: "pkg".to_string(),
                module: "pkg".to_string(),
                context: "src".to_string(),
                groups: Vec::new(),
                macro_path: "buggify".to_string(),
            },
            SiteRecord {
                id: "src/main.rs:12:5#fault".to_string(),
                kind: "fault".to_string(),
                runtime: "driven".to_string(),
                label: None,
                label_dynamic: true,
                file: "src/main.rs".to_string(),
                line: 12,
                crate_name: "pkg".to_string(),
                module: "pkg".to_string(),
                context: "src".to_string(),
                groups: Vec::new(),
                macro_path: "buggify".to_string(),
            },
        ],
        files_scanned: 1,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    };
    let mut exercised_sites = BTreeMap::new();
    exercised_sites.insert(
        "static-label".to_string(),
        ExercisedSite {
            label: "static-label".to_string(),
            kind: "fault".to_string(),
            site: "src/main.rs:10".to_string(),
            first_registered_gen: Some(0),
            last_registered_gen: Some(0),
            registered_gens: 1,
            runs_active: 1,
            evals: 2,
            fires: 1,
            runs_fired: 1,
            ..ExercisedSite::default()
        },
    );
    exercised_sites.insert(
        "dynamic-at-runtime".to_string(),
        ExercisedSite {
            label: "dynamic-at-runtime".to_string(),
            kind: "fault".to_string(),
            site: "/workspace/src/main.rs:12".to_string(),
            first_registered_gen: Some(0),
            last_registered_gen: Some(0),
            registered_gens: 1,
            evals: 1,
            ..ExercisedSite::default()
        },
    );
    let source = ExercisedSource {
        kind: "sdk_report".to_string(),
        path: "stderr.log".to_string(),
        reports: 1,
        generations_observed: 1,
        sites: exercised_sites,
    };
    let report = build_report(
        &scan,
        &SitesOptions {
            all: true,
            ..SitesOptions::default()
        },
        Some(&source),
        &[],
    );
    assert_eq!(report["unmatched_runtime_labels"], 0);
    assert_eq!(report["totals"]["exercised"]["joined_runtime_labels"], 2);
    let rows = report["sites"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["exercised"]["fires"], 1);
    assert_eq!(rows[1]["exercised"]["label"], "dynamic-at-runtime");
}

#[test]
fn unmatched_runtime_labels_are_visible_not_dropped() {
    let scan = StaticScan {
        workspace_root: PathBuf::from("/workspace"),
        sites: Vec::new(),
        files_scanned: 0,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    };
    let mut exercised_sites = BTreeMap::new();
    exercised_sites.insert(
        "wrapped".to_string(),
        ExercisedSite {
            label: "wrapped".to_string(),
            kind: "fault".to_string(),
            site: "src/lib.rs:1".to_string(),
            first_registered_gen: Some(0),
            last_registered_gen: Some(0),
            registered_gens: 1,
            ..ExercisedSite::default()
        },
    );
    let source = ExercisedSource {
        kind: "sdk_report".to_string(),
        path: "stderr.log".to_string(),
        reports: 1,
        generations_observed: 1,
        sites: exercised_sites,
    };
    let report = build_report(&scan, &SitesOptions::default(), Some(&source), &[]);
    assert_eq!(report["unmatched_runtime_labels"], 1);
    assert_eq!(report["unmatched"][0]["origin"], "expanded");
}

#[test]
fn empty_exercised_source_warns_when_static_driven_sites_exist() {
    let scan = StaticScan {
        workspace_root: PathBuf::from("/workspace"),
        sites: vec![SiteRecord {
            id: "static-label".to_string(),
            kind: "fault".to_string(),
            runtime: "driven".to_string(),
            label: Some("static-label".to_string()),
            label_dynamic: false,
            file: "src/main.rs".to_string(),
            line: 10,
            crate_name: "pkg".to_string(),
            module: "pkg".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "buggify".to_string(),
        }],
        files_scanned: 1,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    };
    let source = ExercisedSource {
        kind: "campaign".to_string(),
        path: "out".to_string(),
        reports: 3,
        generations_observed: 3,
        sites: BTreeMap::new(),
    };
    let report = build_report(&scan, &SitesOptions::default(), Some(&source), &[]);
    assert!(
        report["warnings"][0]
            .as_str()
            .unwrap()
            .contains("zero SDK site rows"),
        "expected vacuity warning: {report:#}"
    );
}

#[test]
fn duplicate_sometimes_label_across_call_sites_is_a_fatal_finding() {
    // Real historical shape: two `sometimes!` sites both declared under the
    // label "dedup-suppressed-double-apply" at different call sites. This is
    // exactly what the runtime's `Buggify::declare`/`register` reject at
    // first run as `PATINA_BUGGIFY_DUPLICATE_LABEL`; the static gate must
    // catch it before anything runs.
    let planted = |file: &str, line: usize| SiteRecord {
        id: format!("{file}:{line}#sometimes"),
        kind: "sometimes".to_string(),
        runtime: "observed".to_string(),
        label: Some("dedup-suppressed-double-apply".to_string()),
        label_dynamic: false,
        file: file.to_string(),
        line,
        crate_name: "workq".to_string(),
        module: "workq".to_string(),
        context: "src".to_string(),
        groups: Vec::new(),
        macro_path: "sometimes".to_string(),
    };
    let sites = vec![planted("src/apply.rs", 42), planted("src/dedup.rs", 17)];

    let findings = find_duplicate_labels(&sites);
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one duplicate label finding: {findings:?}"
    );
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

    // Clean tree (unique labels): the same shape must pass with no findings.
    let mut clean = sites.clone();
    clean[1].label = Some("dedup-suppressed-double-apply-2".to_string());
    assert!(
        find_duplicate_labels(&clean).is_empty(),
        "clean tree must have no duplicate-label findings"
    );

    // The finding is carried into the JSON report, not just returned to the
    // caller for post-processing.
    let scan = StaticScan {
        workspace_root: PathBuf::from("/workspace"),
        sites,
        files_scanned: 2,
        files_unparsed: 0,
        unparsed: Vec::new(),
        cache_state: CacheState::Cold,
    };
    let report = build_report(&scan, &SitesOptions::default(), None, &findings);
    assert_eq!(
        report["duplicate_labels"][0]["label"],
        "dedup-suppressed-double-apply"
    );
    assert_eq!(report["duplicate_labels"][0]["count"], 2);
}

#[test]
fn duplicate_label_across_different_kinds_is_also_fatal() {
    // The runtime's duplicate check compares `(site, kind)`, so the same
    // label reused for a different SDK macro kind is fatal too, not just a
    // same-kind reuse.
    let sites = vec![
        SiteRecord {
            id: "src/a.rs:1#fault".to_string(),
            kind: "fault".to_string(),
            runtime: "driven".to_string(),
            label: Some("shared-label".to_string()),
            label_dynamic: false,
            file: "src/a.rs".to_string(),
            line: 1,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "buggify".to_string(),
        },
        SiteRecord {
            id: "src/b.rs:2#always".to_string(),
            kind: "always".to_string(),
            runtime: "observed".to_string(),
            label: Some("shared-label".to_string()),
            label_dynamic: false,
            file: "src/b.rs".to_string(),
            line: 2,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "always".to_string(),
        },
    ];
    let findings = find_duplicate_labels(&sites);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].count, 2);
}

#[test]
fn dynamic_and_antithesis_labels_are_not_compared() {
    // Dynamic labels are unknowable statically, and antithesis-facade
    // labels are a different registry than the SDK's own buggify/always/
    // sometimes/reachable labels; neither should trip the static gate.
    let sites = vec![
        SiteRecord {
            id: "src/a.rs:1#fault".to_string(),
            kind: "fault".to_string(),
            runtime: "driven".to_string(),
            label: Some("dyn-label".to_string()),
            label_dynamic: true,
            file: "src/a.rs".to_string(),
            line: 1,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "buggify".to_string(),
        },
        SiteRecord {
            id: "src/b.rs:2#fault".to_string(),
            kind: "fault".to_string(),
            runtime: "driven".to_string(),
            label: Some("dyn-label".to_string()),
            label_dynamic: true,
            file: "src/b.rs".to_string(),
            line: 2,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "buggify".to_string(),
        },
        SiteRecord {
            id: "src/c.rs:3#antithesis_always".to_string(),
            kind: "antithesis_always".to_string(),
            runtime: "invisible".to_string(),
            label: Some("antithesis-label".to_string()),
            label_dynamic: false,
            file: "src/c.rs".to_string(),
            line: 3,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "antithesis_sdk::assert_always".to_string(),
        },
        SiteRecord {
            id: "src/d.rs:4#antithesis_always".to_string(),
            kind: "antithesis_always".to_string(),
            runtime: "invisible".to_string(),
            label: Some("antithesis-label".to_string()),
            label_dynamic: false,
            file: "src/d.rs".to_string(),
            line: 4,
            crate_name: "workq".to_string(),
            module: "workq".to_string(),
            context: "src".to_string(),
            groups: Vec::new(),
            macro_path: "antithesis_sdk::assert_always".to_string(),
        },
    ];
    assert!(find_duplicate_labels(&sites).is_empty());
}
