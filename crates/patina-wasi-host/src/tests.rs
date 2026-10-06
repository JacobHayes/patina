//! Shared test fixtures and cross-module import-counter source lint.

use crate::abi::{
    WASI_OFLAG_CREATE, WASI_OFLAG_DIRECTORY, WASI_RIGHT_FD_READ, WASI_RIGHT_FD_WRITE,
};
use crate::fs::WasiPathOpen;
use patina_dst_runtime::{Context, RuntimeConfig};

pub(super) fn read_stdout_u64s(stdout: &[u8]) -> Vec<u64> {
    stdout
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

pub(super) fn seeded_memfs(files: &[(&str, &[u8])]) -> patina_dst_fs_mem::MemFs {
    let mut fs = patina_dst_fs_mem::MemFs::new();
    for (path, bytes) in files {
        fs = fs.with_file(path, bytes.to_vec()).unwrap();
    }
    fs
}

pub(super) fn seeded_context(seed: u64, files: &[(&str, &[u8])]) -> Context {
    patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::seeded(seed))
        .with_default_drivers()
        .with_filesystem(seeded_memfs(files))
        .build()
        .unwrap()
}

pub(super) fn read_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: 0,
        rights: WASI_RIGHT_FD_READ,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}

pub(super) fn create_write_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: WASI_OFLAG_CREATE,
        rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}

pub(super) fn directory_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: WASI_OFLAG_DIRECTORY,
        rights: 0,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}

/// Source-level convention lint for the depth counters: every imported function
/// defined in `define_preview1`/`define_patina_sdk` must bump the hostcall
/// counter under its OWN name, as the first statement of its wrapper. The
/// counters are per-wrapper by design (there is no interception point in
/// `Linker::func_wrap`), so this lint is what keeps a newly added import from
/// silently dropping out of the depth report.
#[test]
fn every_wasi_import_wrapper_counts_its_own_hostcall() {
    fn collect(directory: &std::path::Path, paths: &mut Vec<std::path::PathBuf>) {
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

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    collect(&directory, &mut paths);
    paths.sort();
    let source = paths
        .into_iter()
        .map(|path| {
            std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace("pub(super) ", "");
    let body = source.as_str();
    // Assembled at runtime so this lint's own text cannot satisfy itself.
    let counter = format!("count_{}(\"", "hostcall");
    let mut names: Vec<String> = Vec::new();
    let mut counted: Vec<String> = Vec::new();
    let mut previous = "";
    for line in body.lines() {
        if previous.trim() == "MODULE," {
            if let Some(name) = line
                .trim()
                .strip_prefix('"')
                .and_then(|r| r.split_once('"'))
            {
                names.push(name.0.to_string());
            }
        }
        if let Some(rest) = line.split_once(&counter) {
            counted.push(
                rest.1
                    .split_once('"')
                    .expect("counted name is quoted")
                    .0
                    .to_string(),
            );
        }
        previous = line;
    }
    assert!(
        names.len() > 40,
        "the lint failed to find the import table; it found {} names",
        names.len()
    );
    assert_eq!(
        names, counted,
        "every import wrapper must count its own name, in definition order"
    );
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        names.len(),
        "import names must be unique so depth rows cannot silently merge"
    );
}
