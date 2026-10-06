//! Regression tests for scan.

use super::*;

#[test]
fn cache_reuses_clean_file_and_invalidates_on_recognizer_changes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() { assert!(true); }\n").unwrap();
    let package = ScanPackage {
        name: "cache-fixture".to_string(),
        root: root.clone(),
        targets: vec![TargetHint {
            src_path: root.join("src/lib.rs"),
            name: "cache_fixture".to_string(),
            context: ContextKind::Src,
        }],
    };
    let first = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
    assert_eq!(first.cache_state, CacheState::Cold);
    assert_eq!(first.sites.len(), 1);
    let ignore = fs::read_to_string(root.join(".patina/.gitignore")).unwrap();
    assert!(ignore.lines().any(|line| line.trim() == "/out/"));
    let second = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
    assert_eq!(second.cache_state, CacheState::Hit);
    let cache_path = root.join(".patina/out/sites-cache.json");
    let mut stale: Value = serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
    stale["sdk_signature"] = Value::String("previous-sdk-declaration".into());
    fs::write(&cache_path, serde_json::to_vec(&stale).unwrap()).unwrap();
    let changed_sdk = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
    assert_eq!(changed_sdk.cache_state, CacheState::Cold);
    assert_eq!(changed_sdk.sites.len(), 1);
    let refreshed = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
    assert_eq!(refreshed.cache_state, CacheState::Hit);
    fs::write(
        cache_path,
        b"{\"schema\":\"patina.sites-cache/v1\",\"recognizer_version\":\"old\",\"files\":{}}",
    )
    .unwrap();
    let third = scan_packages(root, vec![package], true).unwrap();
    assert_eq!(third.cache_state, CacheState::Cold);
}
