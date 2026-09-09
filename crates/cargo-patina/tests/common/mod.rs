//! Shared helpers for the tests that scan the native shim's own compiled
//! objects: the Rust staticlib (`libpatina_dst_native_shim.a`, built here on
//! demand) and the C POSIX layer (compiled from the embedded sources with the
//! same flags `cargo patina build` uses).

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::archive::ArchiveFile;
use object::{Object, ObjectSymbol};

/// The profile directory (`.../target/debug` or `.../release`) that holds the
/// test binary and, alongside it, the shim staticlib.
pub fn profile_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_cargo-patina"))
        .parent()
        .expect("cargo-patina bin has a parent profile directory")
        .to_path_buf()
}

pub fn workspace_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is two levels below the workspace root")
        .join("Cargo.toml")
}

/// Build (idempotently) and locate `libpatina_dst_native_shim.a`.
pub fn shim_archive() -> PathBuf {
    let profile = profile_dir();
    let target_dir = profile
        .parent()
        .expect("profile dir has a target parent")
        .to_path_buf();
    let mut build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    build
        .arg("build")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(workspace_manifest())
        .arg("-p")
        .arg("patina-dst-native-shim")
        .arg("--target-dir")
        .arg(&target_dir);
    if profile.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    }
    let status = build
        .status()
        .expect("cargo build -p patina-dst-native-shim runs");
    assert!(
        status.success(),
        "failed to build the native shim staticlib"
    );
    let archive = profile.join("libpatina_dst_native_shim.a");
    assert!(
        archive.exists(),
        "shim staticlib not found at {}",
        archive.display()
    );
    archive
}

/// Visit the shim's *own* object members (named `patina_dst_native_shim-*`),
/// excluding the bundled std/dependency members. Asserts at least one is seen
/// so a renamed member prefix cannot make a scan vacuously pass.
pub fn for_each_shim_member(archive_bytes: &[u8], mut visit: impl FnMut(&object::File<'_>)) {
    let archive = ArchiveFile::parse(archive_bytes).expect("parse shim staticlib");
    let mut saw_shim_member = false;
    for member in archive.members() {
        let member = member.expect("archive member");
        let name = String::from_utf8_lossy(member.name());
        if !name.starts_with("patina_dst_native_shim-") {
            continue;
        }
        saw_shim_member = true;
        let data = member.data(archive_bytes).expect("member data");
        let object = object::File::parse(data).expect("parse shim object member");
        visit(&object);
    }
    assert!(
        saw_shim_member,
        "no patina_dst_native_shim-* members found in the staticlib"
    );
}

/// Compile the embedded C POSIX layer (umbrella + family slices + header) into
/// `dir` with the flags `cargo patina build` uses, returning the object path.
pub fn compile_posix_object(dir: &Path) -> PathBuf {
    for (relative, source) in patina_dst_native_shim::POSIX_C_FAMILY_SOURCES {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, source).unwrap();
    }
    std::fs::write(
        dir.join("patina_native.h"),
        patina_dst_native_shim::NATIVE_HEADER,
    )
    .unwrap();
    let source = dir.join("patina_posix.c");
    std::fs::write(&source, patina_dst_native_shim::POSIX_C_SOURCE).unwrap();
    let object = dir.join("patina_posix.o");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&cc)
        .args([
            "-std=c11",
            "-D_POSIX_C_SOURCE=200809L",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg("-I")
        .arg(dir)
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("cc compiles the POSIX shim layer");
    assert!(status.success(), "compiling the POSIX shim layer failed");
    object
}

/// The public (global, defined) symbol names of one object, with the Mach-O
/// leading underscore removed so the names read as the C identifiers.
pub fn defined_public_symbols(object: &object::File<'_>) -> BTreeSet<String> {
    object
        .symbols()
        .filter(|symbol| symbol.is_definition() && symbol.is_global())
        .filter_map(|symbol| symbol.name().ok())
        .map(|name| {
            if cfg!(target_os = "macos") {
                name.strip_prefix('_').unwrap_or(name).to_owned()
            } else {
                name.to_owned()
            }
        })
        .collect()
}
