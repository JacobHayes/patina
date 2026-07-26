//! Host-alias doctrine: static enforcement over the native shim's own objects.
//!
//! The doctrine (see the shim's `hostapi` module and ARCHITECTURE.md
//! "Host-alias doctrine") requires that shim-internal code never name a public,
//! interposable host symbol as an undefined external — such a name lands in the
//! guest binary's import table and forces a name-based `--allow` that guest code
//! can ride past the audit (the class the macOS dispatch-semaphore Parker escape
//! belonged to). Every host vehicle is instead resolved at runtime through the
//! single `dlsym` primitive.
//!
//! This test enforces that structurally: it scans the shim's *own* compiled
//! object files (isolated from the ~1000 std/dependency members bundled into the
//! staticlib) and fails on any undefined external that the native import audit
//! would deny as a classified escape, given the shim's declared control-plane
//! allowance. It is the automated, in-suite half of the
//! `scripts/validate-native-shim.sh` "host-alias" section; the classifier it
//! calls (`patina_target::shim_host_alias_violation`) is the exact predicate the
//! guest-binary audit uses, so the shim is held to the standard it enforces.
//!
//! Red→green: on the pre-doctrine shim (which named `semaphore_wait`,
//! `read$NOCANCEL`, ... directly) this fails; once those route through the alias
//! table it passes with `dlsym` as the only escape-surface residue. The
//! `planted_leak_is_caught` test keeps the scan non-vacuous.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::archive::ArchiveFile;
use object::{Object, ObjectSymbol};
use patina_target::{shim_control_plane_symbols, shim_host_alias_violation};

/// The profile directory (`.../target/debug` or `.../release`) that holds the
/// test binary and, alongside it, the shim staticlib.
fn profile_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_cargo-patina"))
        .parent()
        .expect("cargo-patina bin has a parent profile directory")
        .to_path_buf()
}

fn workspace_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is two levels below the workspace root")
        .join("Cargo.toml")
}

/// Build (idempotently) and locate `libpatina_native_shim.a`.
fn shim_archive() -> PathBuf {
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
        .arg("patina-native-shim")
        .arg("--target-dir")
        .arg(&target_dir);
    if profile.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    }
    let status = build
        .status()
        .expect("cargo build -p patina-native-shim runs");
    assert!(
        status.success(),
        "failed to build the native shim staticlib"
    );
    let archive = profile.join("libpatina_native_shim.a");
    assert!(
        archive.exists(),
        "shim staticlib not found at {}",
        archive.display()
    );
    archive
}

/// Collect the undefined external symbol names of the shim's *own* object
/// members (named `patina_native_shim-*`), excluding the bundled std/dep
/// members whose imports the shim's strong definitions satisfy at final link.
fn shim_undefined_externals(archive_bytes: &[u8]) -> BTreeSet<String> {
    let archive = ArchiveFile::parse(archive_bytes).expect("parse shim staticlib");
    let mut undefined = BTreeSet::new();
    let mut saw_shim_member = false;
    for member in archive.members() {
        let member = member.expect("archive member");
        let name = String::from_utf8_lossy(member.name());
        if !name.starts_with("patina_native_shim-") {
            continue;
        }
        saw_shim_member = true;
        let data = member.data(archive_bytes).expect("member data");
        let object = object::File::parse(data).expect("parse shim object member");
        for symbol in object.symbols() {
            if symbol.is_undefined() {
                if let Ok(name) = symbol.name() {
                    undefined.insert(name.to_owned());
                }
            }
        }
    }
    assert!(
        saw_shim_member,
        "no patina_native_shim-* members found in the staticlib"
    );
    undefined
}

/// Run the doctrine classifier over a set of undefined externals, returning the
/// violating `(symbol, category)` pairs.
fn violations(
    undefined: &BTreeSet<String>,
    allow: &BTreeSet<String>,
) -> Vec<(String, &'static str)> {
    let macho = cfg!(target_os = "macos");
    undefined
        .iter()
        .filter_map(|symbol| {
            shim_host_alias_violation(symbol, macho, allow)
                .map(|category| (symbol.clone(), category))
        })
        .collect()
}

#[test]
fn shim_objects_name_no_undeclared_host_escape() {
    let archive = shim_archive();
    let bytes = std::fs::read(&archive).expect("read shim staticlib");
    let undefined = shim_undefined_externals(&bytes);
    let allow = shim_control_plane_symbols();
    let violations = violations(&undefined, &allow);
    assert!(
        violations.is_empty(),
        "the native shim names {} host escape symbol(s) as undefined externals, \
violating the host-alias doctrine (route them through the hostapi table, or, if \
genuinely a sanctioned vehicle, declare them in shim_control_plane_symbols):\n{}",
        violations.len(),
        violations
            .iter()
            .map(|(symbol, category)| format!("  {symbol} ({category})"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Non-vacuity guard: a fixture object that deliberately names `open` and
/// `semaphore_wait` as undefined externals must be flagged by the exact same
/// extraction-and-classification pipeline, so the scan can never silently pass.
#[test]
fn planted_leak_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("planted_leak.c");
    let obj = dir.path().join("planted_leak.o");
    // References real host escape symbols so they appear as undefined externals.
    std::fs::write(
        &src,
        r#"extern long semaphore_wait(unsigned int);
extern int open(const char *, int, ...);
long __patina_planted_leak(const char *p) {
    return semaphore_wait(0) + open(p, 0);
}
"#,
    )
    .unwrap();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&cc)
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("cc compiles the planted-leak fixture");
    assert!(status.success(), "planted-leak fixture failed to compile");

    let bytes = std::fs::read(&obj).unwrap();
    let object = object::File::parse(&*bytes).expect("parse planted-leak object");
    let undefined: BTreeSet<String> = object
        .symbols()
        .filter(|symbol| symbol.is_undefined())
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect();

    // Empty allow set: even the sanctioned residue is not exempt for a planted
    // leak, and the two planted names must both be classified escapes.
    let flagged = violations(&undefined, &BTreeSet::new());
    let categories: BTreeSet<&str> = flagged.iter().map(|(_, c)| *c).collect();
    assert!(
        categories.contains("unmanaged-sync"),
        "planted semaphore_wait leak was not flagged as unmanaged-sync; flagged={flagged:?}"
    );
    assert!(
        categories.contains("filesystem"),
        "planted open leak was not flagged as filesystem; flagged={flagged:?}"
    );
}
