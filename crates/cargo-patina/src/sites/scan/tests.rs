//! Regression tests for scan.

use super::*;

#[test]
fn cache_reuses_clean_file_and_invalidates_on_recognizer_version() {
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
    fs::write(
        root.join(".patina/out/sites-cache.json"),
        b"{\"schema\":\"patina.sites-cache/v1\",\"recognizer_version\":\"old\",\"files\":{}}",
    )
    .unwrap();
    let third = scan_packages(root, vec![package], true).unwrap();
    assert_eq!(third.cache_state, CacheState::Cold);
}
