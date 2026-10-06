//! Sorted recursive Rust-source inputs for source-level regression detectors.

use std::path::{Path, PathBuf};

pub(super) fn rust_sources(directory: &str) -> Vec<(PathBuf, String)> {
    fn collect(directory: &Path, paths: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("source directory exists") {
            let path = entry.expect("source directory entry is readable").path();
            if path.is_dir() {
                collect(&path, paths);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                paths.push(path);
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    collect(&root.join(directory), &mut paths);
    paths.sort();
    assert!(!paths.is_empty(), "source scan must not become vacuous");
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).expect("Rust source is readable");
            (path.strip_prefix(root).unwrap().to_owned(), source)
        })
        .collect()
}

pub(super) fn production_sources(directory: &str) -> String {
    rust_sources(directory)
        .into_iter()
        .filter(|(path, _)| {
            !path.components().any(|part| part.as_os_str() == "tests")
                && !path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name == "tests.rs" || name.ends_with("_tests.rs")
                })
        })
        // These detectors previously scanned complete files, including inline
        // tests. Keep that scope: some files have production code after an
        // inline test module, so truncating there would hide later boundaries.
        .map(|(_, source)| format!("{source}\n"))
        .collect()
}
