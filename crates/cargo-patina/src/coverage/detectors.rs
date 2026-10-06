//! Campaign coverage detector selftests.

use super::*;

pub(crate) fn campaign_detector_selftest() -> Vec<(&'static str, bool, String)> {
    vec![
        detector_fingerprint_mismatch(),
        detector_plateau_exactness(),
        detector_watermark_idempotency(),
    ]
}

pub(super) fn synthetic_covmap(counters: &[u32], deltas: &[i64]) -> Covmap {
    assert_eq!(counters.len(), deltas.len());
    Covmap {
        guard_count: counters.len() as u64,
        ranges: vec![CovmapRange {
            guard_offset: 0,
            guard_count: counters.len() as u64,
            pc_offset: 0,
            pc_count: deltas.len() as u64,
        }],
        counters: counters.to_vec(),
        deltas: deltas.to_vec(),
    }
}

fn detector_fingerprint_mismatch() -> (&'static str, bool, String) {
    let result = (|| -> Result<String, CliError> {
        let temp = tempfile::tempdir()
            .map_err(|error| CliError(format!("failed to create tempdir: {error}")))?;
        let dir = temp.path().join("coverage");
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
        store.fold_covmap(0, &synthetic_covmap(&[1], &[10]))?;
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
        let error =
            CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
                .unwrap_err();
        Ok(error.0)
    })();
    match result {
        Ok(message) if message.contains("coverage state fingerprint mismatch") => (
            "coverage-fingerprint-mismatch-refuses",
            true,
            "loud mismatch".to_string(),
        ),
        Ok(message) => (
            "coverage-fingerprint-mismatch-refuses",
            false,
            format!("wrong error: {message}"),
        ),
        Err(error) => (
            "coverage-fingerprint-mismatch-refuses",
            false,
            error.to_string(),
        ),
    }
}

fn detector_plateau_exactness() -> (&'static str, bool, String) {
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
        family: "native".into(),
    };
    let first = synthetic_covmap(&[1, 0], &[10, 20]);
    let repeat = synthetic_covmap(&[1, 0], &[10, 20]);
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        2,
    );
    let ok = store.fold_covmap(0, &first).is_ok()
        && !store.meta().unwrap().plateaued
        && store.fold_covmap(1, &repeat).is_ok()
        && !store.meta().unwrap().plateaued
        && store.fold_covmap(2, &repeat).is_ok()
        && store.meta().unwrap().plateaued;
    let mut disabled = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact,
        "patina-native+yieldpoints".into(),
        0,
    );
    let disabled_ok = disabled.fold_covmap(0, &first).is_ok()
        && disabled.fold_covmap(1, &repeat).is_ok()
        && disabled.fold_covmap(2, &repeat).is_ok()
        && !disabled.meta().unwrap().plateaued;
    (
        "coverage-plateau-exactness",
        ok && disabled_ok,
        "fires at N, not N-1; zero disables".to_string(),
    )
}

fn detector_watermark_idempotency() -> (&'static str, bool, String) {
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
    let covmap = synthetic_covmap(&[1, 2], &[10, 20]);
    let ok = store.fold_covmap(0, &covmap).is_ok();
    let hits = store.hits.clone();
    let skipped = store
        .fold_covmap(0, &covmap)
        .map(|outcome| outcome.skipped_by_watermark)
        .unwrap_or(false);
    (
        "coverage-watermark-idempotency",
        ok && skipped && store.hits == hits,
        "second fold skipped without hit double-count".to_string(),
    )
}
