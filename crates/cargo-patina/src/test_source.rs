//! Shared test-time discovery and reading of Rust source directories.

use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn rust_sources(relative_directory: &str) -> Vec<(String, String)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_directory);
    let mut paths = Vec::new();
    collect_rust_paths(&directory, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            let file = path
                .strip_prefix(&directory)
                .expect("discovered source must be under the scanned directory")
                .to_string_lossy()
                .into_owned();
            (file, source)
        })
        .collect()
}

fn collect_rust_paths(directory: &Path, paths: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("cannot read an entry in {}: {error}", directory.display())
        });
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
        if file_type.is_dir() {
            collect_rust_paths(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}
