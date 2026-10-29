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
        },
        "patina-native+instrumented".into(),
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
fn campaign_meta_refuses_a_torn_or_mismatched_store() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("coverage");
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
    };
    let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
    let mut store = CampaignCoverageStore::fresh(
        dir.clone(),
        artifact.clone(),
        "patina-native+instrumented".into(),
        200,
    );
    store.fold_covmap(0, &covmap).unwrap();
    store.write_checkpoint().unwrap();

    CampaignCoverageStore::load(
        dir.clone(),
        artifact.clone(),
        "patina-native+instrumented".into(),
        200,
        0,
    )
    .expect("one-generation tear ahead is resumable");
    // The watermark rule itself is tested in `aux_store`; this is the wiring.
    assert!(
        CampaignCoverageStore::load(
            dir.clone(),
            artifact.clone(),
            "patina-native+instrumented".into(),
            200,
            2,
        )
        .is_err(),
        "a store behind the campaign cursor must be refused"
    );

    let meta_path = dir.join("meta.json");
    let rewrite_meta = |edit: &dyn Fn(&mut Value)| {
        let mut meta: Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        edit(&mut meta);
        fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    };
    rewrite_meta(&|meta| meta["generations_applied"] = 3.into());
    assert!(
        CampaignCoverageStore::load(
            dir.clone(),
            artifact.clone(),
            "patina-native+instrumented".into(),
            200,
            1,
        )
        .is_err(),
        "a store too far ahead of the campaign cursor must be refused"
    );

    rewrite_meta(&|meta| {
        meta["generations_applied"] = 1.into();
        meta["fingerprint"] = "other".into();
    });
    assert!(
        CampaignCoverageStore::load(dir, artifact, "patina-native+instrumented".into(), 200, 1)
            .is_err(),
        "a store of another fingerprint must be refused"
    );
    // An unknown schema or a covmap of a different size is refused.
    {
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
        let meta = CampaignCoverageMeta::new(
            CoverageArtifact {
                path: "guest".into(),
                sha256: "abc".into(),
            },
            "patina-native+instrumented".into(),
            &covmap,
            200,
        )
        .to_json();

        assert!(CampaignCoverageMeta::from_json(&meta).is_ok());

        let mut bad_schema = meta.clone();
        bad_schema["schema"] = "patina.coverage.campaign/v999".into();
        assert!(CampaignCoverageMeta::from_json(&bad_schema).is_err());

        let mut bad_edges = meta;
        bad_edges["edges_total"] = 2.into();
        assert!(CampaignCoverageMeta::from_json(&bad_edges).is_err());
    }
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
    };
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact.clone(),
        "patina-native+instrumented".into(),
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
        "patina-native+instrumented".into(),
        0,
    );
    disabled.fold_covmap(0, &covmap).unwrap();
    disabled.fold_covmap(1, &no_new).unwrap();
    disabled.fold_covmap(2, &no_new).unwrap();
    assert!(!disabled.meta().unwrap().plateaued);
}

/// Only a newly covered edge is novel: taking a covered edge more often than
/// before is not. The first-cover record is generation-ordered, so the coverage
/// as of any earlier generation is recoverable, and it survives a checkpoint
/// round trip.
#[test]
fn only_a_newly_covered_edge_is_novel_and_the_log_rewinds() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("coverage");
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
    };
    let map = |counters: &[u32]| {
        parse_covmap_bytes(&covmap_bytes(counters, &[10, 20]), Path::new("m")).unwrap()
    };
    let fingerprint = || "patina-native+instrumented".to_string();
    let mut store = CampaignCoverageStore::fresh(dir.clone(), artifact.clone(), fingerprint(), 0);
    assert_eq!(store.fold_covmap(0, &map(&[1, 0])).unwrap().new_edges, 1);
    assert_eq!(store.fold_covmap(1, &map(&[40, 0])).unwrap().new_edges, 0);
    assert_eq!(store.fold_covmap(2, &map(&[1, 3])).unwrap().new_edges, 1);
    assert_eq!(store.fold_covmap(3, &map(&[0, 9])).unwrap().new_edges, 0);

    let novel = |store: &CampaignCoverageStore| -> Vec<u64> {
        let mut generations: Vec<u64> = store
            .edge_log()
            .iter()
            .map(|record| record.generation)
            .collect();
        generations.dedup();
        generations
    };
    assert_eq!(novel(&store), [0, 2]);
    assert_eq!(
        store.edge_log_below(2).len(),
        1,
        "rewound before generation 2"
    );
    assert_eq!(store.edge_log_below(3).len(), 2);

    store.write_checkpoint().unwrap();
    let loaded = CampaignCoverageStore::load(dir.clone(), artifact.clone(), fingerprint(), 0, 4)
        .expect("round trip");
    assert_eq!(novel(&loaded), [0, 2]);
    assert_eq!(loaded.edge_log(), store.edge_log());

    // An edge log that disagrees with the rest of the store is refused: edge 0
    // is already recorded, so a second record of it cannot be.
    let log = dir.join("edges.u64le");
    let mut bytes = fs::read(&log).unwrap();
    bytes.extend_from_slice(&3u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&1u64.to_le_bytes());
    fs::write(&log, &bytes).unwrap();
    assert!(CampaignCoverageStore::load(dir, artifact, fingerprint(), 0, 4).is_err());
}

/// Each edge counts the generations that covered it, and the decision log
/// round-trips with the store; a decision naming a generation that was never
/// novel is refused.
#[test]
fn edge_hits_and_decisions_round_trip() {
    use crate::guided::GuidanceDecision;
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("coverage");
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
    };
    let map = |counters: &[u32]| {
        parse_covmap_bytes(&covmap_bytes(counters, &[10, 20]), Path::new("m")).unwrap()
    };
    let fingerprint = || "patina-native+instrumented".to_string();
    let mut store = CampaignCoverageStore::fresh(dir.clone(), artifact.clone(), fingerprint(), 0);
    let decisions = [
        GuidanceDecision::NoAncestors,
        GuidanceDecision::NoAncestors,
        GuidanceDecision::Explore,
        GuidanceDecision::Exploit { ancestor: 1 },
    ];
    for (generation, counters) in [[1, 0], [1, 1], [1, 0], [1, 1]].iter().enumerate() {
        store.record_decision(generation as u64, decisions[generation]);
        store
            .fold_covmap(generation as u64, &map(counters))
            .unwrap();
    }
    let hits: Vec<(u64, u64)> = store
        .edge_log()
        .iter()
        .map(|record| (record.generation, record.hits))
        .collect();
    assert_eq!(hits, [(0, 4), (1, 2)]);
    store.write_checkpoint().unwrap();
    let loaded = CampaignCoverageStore::load(dir.clone(), artifact.clone(), fingerprint(), 0, 4)
        .expect("round trip");
    assert_eq!(loaded.decisions(), decisions);
    assert_eq!(loaded.edge_log(), store.edge_log());

    // Generation 2 found nothing, so nothing can have exploited it.
    let guidance = dir.join("guidance.u64le");
    let mut bytes = fs::read(&guidance).unwrap();
    bytes[32..40].copy_from_slice(&2u64.to_le_bytes());
    fs::write(&guidance, &bytes).unwrap();
    let error = CampaignCoverageStore::load(dir.clone(), artifact.clone(), fingerprint(), 0, 4)
        .unwrap_err();
    assert!(
        error.0.contains("guidance log"),
        "unexpected error: {error}"
    );

    // A guidance log from an earlier checkpoint than the rest of the store
    // (a crash part way through a checkpoint) is refused, not steered from.
    let mut stale = 3u64.to_le_bytes().to_vec();
    for word in [u64::MAX, u64::MAX, u64::MAX - 1] {
        stale.extend_from_slice(&word.to_le_bytes());
    }
    fs::write(&guidance, &stale).unwrap();
    let error = CampaignCoverageStore::load(dir, artifact, fingerprint(), 0, 4).unwrap_err();
    assert!(error.0.contains("torn"), "unexpected error: {error}");
}
