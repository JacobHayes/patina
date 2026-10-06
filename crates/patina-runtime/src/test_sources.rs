//! Shared directory discovery for source-scanning tests.

use std::path::{Path, PathBuf};

pub(super) fn rust_sources(directory: &str) -> Vec<(PathBuf, String)> {
    fn collect(directory: &Path, paths: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("cannot scan {}: {error}", directory.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
                .path();
            if path.is_dir() {
                collect(&path, paths);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                paths.push(path);
            }
        }
    }

    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(directory);
    let mut paths = Vec::new();
    collect(&directory, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            (path, source)
        })
        .collect()
}
