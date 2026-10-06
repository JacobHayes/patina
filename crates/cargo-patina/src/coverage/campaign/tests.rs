//! Regression tests for campaign.

use super::*;

use super::super::tests::*;

#[test]
fn campaign_fold_is_watermark_idempotent() {
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1, 2], &[10, 20]), Path::new("a"))
        .expect("valid covmap");
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        },
        "patina-native+yieldpoints".into(),
        200,
    );
    let first = store.fold_covmap(0, &covmap).expect("first fold");
    assert_eq!(first.new_edges, 2);
    let hits_after_first = store.hits.clone();
    let second = store.fold_covmap(0, &covmap).expect("watermark skip");
    assert!(second.skipped_by_watermark);
    assert_eq!(
        store.hits, hits_after_first,
        "duplicate fold must not double-count hits"
    );
}

#[test]
fn campaign_load_validates_resume_watermark() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("coverage");
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
        family: "native".into(),
    };
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
    let mut store = CampaignCoverageStore::fresh(
        dir.clone(),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        200,
    );
    store.fold_covmap(0, &covmap).unwrap();
    store.write_checkpoint().unwrap();

    CampaignCoverageStore::load(
        dir.clone(),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        200,
        0,
    )
    .expect("one-generation tear ahead is resumable");
    let behind = CampaignCoverageStore::load(
        dir.clone(),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        200,
        2,
    )
    .unwrap_err();
    assert!(
        behind.0.contains("missing coverage folds"),
        "unexpected error: {behind}"
    );

    let meta_path = dir.join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["generations_applied"] = 3.into();
    fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    let ahead =
        CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
            .unwrap_err();
    assert!(
        ahead
            .0
            .contains("at most one checkpoint-tear generation ahead"),
        "unexpected error: {ahead}"
    );
}

#[test]
fn campaign_meta_rejects_schema_and_edges_total_mismatch() {
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
    let meta = CampaignCoverageMeta::new(
        CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        },
        "patina-native+yieldpoints".into(),
        &covmap,
        200,
    )
    .to_json();

    let mut bad_schema = meta.clone();
    bad_schema["schema"] = "patina.coverage.campaign/v999".into();
    assert!(
        CampaignCoverageMeta::from_json(&bad_schema)
            .unwrap_err()
            .contains("unsupported schema")
    );

    let mut bad_edges = meta;
    bad_edges["edges_total"] = 2.into();
    let error = CampaignCoverageMeta::from_json(&bad_edges).unwrap_err();
    assert!(
        error.contains("expected edges_total=2"),
        "unexpected error: {error}"
    );
}

#[test]
fn plateau_rule_is_exact_and_zero_disables() {
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1, 0], &[10, 20]), Path::new("a"))
        .expect("valid covmap");
    let no_new = parse_covmap_bytes(&covmap_bytes(&[1, 0], &[10, 20]), Path::new("b"))
        .expect("valid covmap");
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
        family: "native".into(),
    };
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        2,
    );
    store.fold_covmap(0, &covmap).unwrap();
    assert!(!store.meta().unwrap().plateaued);
    store.fold_covmap(1, &no_new).unwrap();
    assert!(!store.meta().unwrap().plateaued, "N-1 must not plateau");
    store.fold_covmap(2, &no_new).unwrap();
    assert!(store.meta().unwrap().plateaued, "N must plateau");

    let mut disabled = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact,
        "patina-native+yieldpoints".into(),
        0,
    );
    disabled.fold_covmap(0, &covmap).unwrap();
    disabled.fold_covmap(1, &no_new).unwrap();
    disabled.fold_covmap(2, &no_new).unwrap();
    assert!(!disabled.meta().unwrap().plateaued);
}

#[test]
fn campaign_meta_rejects_fingerprint_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("coverage");
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
        family: "native".into(),
    };
    let mut store = CampaignCoverageStore::fresh(
        dir.clone(),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        200,
    );
    store.fold_covmap(0, &covmap).unwrap();
    store.write_checkpoint().unwrap();
    let mut meta: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("meta.json")).unwrap()).unwrap();
    meta["fingerprint"] = "other".into();
    fs::write(
        dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    let error =
        CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
            .unwrap_err();
    assert!(
        error.0.contains("coverage state fingerprint mismatch"),
        "unexpected error: {}",
        error.0
    );
}
