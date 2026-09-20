//! Pack the native-shim source closure into the `cargo-patina` binary.
//!
//! An installed `cargo-patina` must be able to build a guest's linked shim with
//! no Patina checkout on disk. To do that it carries the shim's whole workspace
//! dependency closure — 12 crates — embedded as source, and unpacks it into a
//! per-user cache at guest-build time (the shim must be compiled by the exact
//! rustc that compiles the guest, so a prebuilt staticlib is not an option).
//!
//! This script discovers each crate's source directory over cargo's
//! `links`/`DEP_<pkg>_SRC_DIR` channel: every closure crate carries
//! `links = "<package-name>"` and a build script that publishes its
//! `CARGO_MANIFEST_DIR`, and cargo hands that value to the build script of every
//! DIRECT dependent as `DEP_<UPPER_SNAKE>_SRC_DIR`. `cargo-patina` therefore
//! depends directly on all 12 (see its Cargo.toml comment). This channel works
//! identically in-tree, from the crates.io registry checkout, and from a git
//! checkout — the one documented way for a dependent's build script to learn a
//! dependency's source directory.
//!
//! Each embedded `Cargo.toml` is normalized (workspace inheritance resolved,
//! internal deps repointed to sibling paths, dev-deps and any `[workspace]`
//! table stripped). In the crates.io form the manifests carry no
//! `key.workspace = true`, so the resolution is a genuine no-op — one code path,
//! not two.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The shim's workspace dependency closure, directory-order-independent. The
/// runtime writes them in this order and the bundle digest hashes them in this
/// order, so keep it stable.
const SHIM_PACKAGES: &[&str] = &[
    "patina-dst-abi",
    "patina-dst-syscalls",
    "patina-dst-driver-api",
    "patina-dst-fs-crash",
    "patina-dst-fs-mem",
    "patina-dst-net-sim",
    "patina-dst-rng-seeded",
    "patina-dst-runtime",
    "patina-dst-sched-det",
    "patina-dst-time-virtual",
    "patina-dst-trace",
    "patina-dst-wrapper-fault",
    "patina-dst-native-shim",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let pkg_set: BTreeSet<&str> = SHIM_PACKAGES.iter().copied().collect();

    // Each crate's source dir, from its `links` metadata.
    let mut src_dirs: BTreeMap<&str, PathBuf> = BTreeMap::new();
    for &pkg in SHIM_PACKAGES {
        let var = dep_env(pkg);
        let dir = env::var_os(&var).unwrap_or_else(|| {
            panic!(
                "missing {var}: cargo-patina must depend directly on {pkg}; the native-shim \
                 source bundle needs all 12 closure crates as direct dependencies so cargo \
                 exposes their DEP_*_SRC_DIR to this build script"
            )
        });
        src_dirs.insert(pkg, PathBuf::from(dir));
    }

    // The workspace root (nearest ancestor manifest with a `[workspace]` table),
    // walking up from any crate dir — cargo's own rule for workspace inheritance.
    // In the crates.io/git form there is none, and no manifest carries a
    // `.workspace = true` key, so `ws` stays `None` and every resolution below is
    // a no-op rather than a second code path.
    let any_dir = src_dirs.values().next().expect("at least one crate");
    let ws = find_workspace_root(any_dir).map(|root| {
        println!(
            "cargo:rerun-if-changed={}",
            root.join("Cargo.toml").display()
        );
        load_workspace_tables(&root)
    });

    let mut file_tables = String::new();
    let mut hasher = Sha256::new();

    for &pkg in SHIM_PACKAGES {
        let dir = &src_dirs[pkg];
        // Cargo rescans a watched directory recursively, so a content edit under
        // the crate retriggers this script (include_bytes! also pins each file).
        println!("cargo:rerun-if-changed={}", dir.display());

        let mut files: Vec<(String, PathBuf)> = Vec::new();
        collect_files(dir, dir, &mut files);
        files.sort();

        // The manifest travels normalized; everything else travels verbatim.
        let manifest_src = fs::read_to_string(dir.join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("reading {}/Cargo.toml: {e}", dir.display()));
        let normalized = normalize_manifest(pkg, &manifest_src, ws.as_ref(), &pkg_set);
        let norm_path = out_dir.join(format!("{pkg}.Cargo.toml"));
        fs::write(&norm_path, normalized.as_bytes()).expect("write normalized manifest");

        file_tables.push_str(&format!("static {}: &[EmbeddedFile] = &[\n", ident(pkg)));
        for (rel, abs) in &files {
            let (literal, bytes) = if rel == "Cargo.toml" {
                (path_literal(&norm_path), normalized.clone().into_bytes())
            } else {
                (
                    path_literal(abs),
                    fs::read(abs).expect("read embedded file"),
                )
            };
            file_tables.push_str(&format!(
                "    ({}, include_bytes!({})),\n",
                str_literal(rel),
                literal
            ));
            hash_frame(&mut hasher, pkg.as_bytes());
            hash_frame(&mut hasher, rel.as_bytes());
            hash_frame(&mut hasher, &bytes);
        }
        file_tables.push_str("];\n\n");
    }

    // The nearest Cargo.lock walking up from this crate: in-tree the workspace
    // lock, from the registry the lock shipped inside the cargo-patina package.
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lock_path = find_cargo_lock(&manifest_dir)
        .expect("no Cargo.lock found walking up from cargo-patina; cannot pin the shim build");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock_bytes = fs::read(&lock_path).expect("read Cargo.lock");
    hash_frame(&mut hasher, b"Cargo.lock");
    hash_frame(&mut hasher, &lock_bytes);
    let lock_out = out_dir.join("shim.Cargo.lock");
    fs::write(&lock_out, &lock_bytes).expect("write embedded Cargo.lock");

    let mut generated = String::new();
    generated.push_str("// @generated by cargo-patina/build.rs — do not edit.\n\n");
    generated.push_str("/// One embedded file: (path relative to its crate dir, bytes).\n");
    generated.push_str("pub type EmbeddedFile = (&'static str, &'static [u8]);\n");
    generated.push_str("/// One embedded crate: (package name, its files).\n");
    generated.push_str("pub type EmbeddedCrate = (&'static str, &'static [EmbeddedFile]);\n\n");
    generated.push_str(&file_tables);
    generated.push_str("/// Every embedded crate, in dependency-closure order.\n");
    generated.push_str("pub static EMBEDDED_SHIM_SOURCES: &[EmbeddedCrate] = &[\n");
    for &pkg in SHIM_PACKAGES {
        generated.push_str(&format!("    ({}, {}),\n", str_literal(pkg), ident(pkg)));
    }
    generated.push_str("];\n\n");
    generated.push_str("/// The Cargo.lock that pins the shim build.\n");
    generated.push_str(&format!(
        "pub static EMBEDDED_SHIM_CARGO_LOCK: &[u8] = include_bytes!({});\n\n",
        path_literal(&lock_out)
    ));
    generated.push_str("/// Content address of the whole bundle; names its unpack cache dir.\n");
    generated.push_str(&format!(
        "pub static EMBEDDED_SHIM_BUNDLE_SHA256: &str = {};\n",
        str_literal(&hex(hasher.finalize()))
    ));
    fs::write(out_dir.join("shim_sources.rs"), generated).expect("write shim_sources.rs");
}

/// `DEP_<UPPER_SNAKE>_SRC_DIR` for a `links = "<pkg>"` crate.
fn dep_env(pkg: &str) -> String {
    format!("DEP_{}_SRC_DIR", pkg.to_uppercase().replace('-', "_"))
}

/// The generated per-crate table identifier, e.g. `PATINA_DST_ABI_FILES`.
fn ident(pkg: &str) -> String {
    format!("{}_FILES", pkg.to_uppercase().replace('-', "_"))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name = name.to_str().expect("utf-8 filename");
        // Skip build artifacts and dot-entries (VCS metadata, editor state).
        if name == "target" || name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        // Follow a symlink to a regular file and embed the target's bytes —
        // exactly what `cargo package` does with the per-crate `LICENSE-*`
        // links, so the in-tree and registry forms of a crate embed the same
        // files. A symlinked directory (a cycle risk) is still refused.
        let file_type = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .file_type();
        if file_type.is_dir() {
            if entry.file_type().expect("file type").is_symlink() {
                panic!(
                    "{}: a symlinked directory cannot be embedded",
                    path.display()
                );
            }
            collect_files(root, &path, out);
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_str()
                .expect("utf-8 path")
                .replace('\\', "/");
            out.push((rel, path));
        } else {
            // A special file (or a dangling symlink, which fails the stat above)
            // cannot travel as bytes; refusing beats silently shipping a bundle
            // that builds differently from the tree.
            panic!(
                "{}: not a regular file or directory; cannot embed it",
                path.display()
            );
        }
    }
}

// --- manifest normalization ------------------------------------------------

struct WorkspaceTables {
    package: toml::Table,
    deps: toml::Table,
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            if let Ok(text) = fs::read_to_string(&manifest) {
                if let Ok(doc) = toml::from_str::<toml::Table>(&text) {
                    if doc.contains_key("workspace") {
                        return Some(dir.to_path_buf());
                    }
                }
            }
        }
        cur = dir.parent();
    }
    None
}

fn load_workspace_tables(root: &Path) -> WorkspaceTables {
    let text = fs::read_to_string(root.join("Cargo.toml")).expect("read workspace manifest");
    let doc: toml::Table = toml::from_str(&text).expect("parse workspace manifest");
    let ws = doc
        .get("workspace")
        .and_then(toml::Value::as_table)
        .expect("[workspace] table");
    WorkspaceTables {
        package: ws
            .get("package")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default(),
        deps: ws
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default(),
    }
}

fn normalize_manifest(
    pkg: &str,
    src: &str,
    ws: Option<&WorkspaceTables>,
    pkg_set: &BTreeSet<&str>,
) -> String {
    let mut doc: toml::Table =
        toml::from_str(src).unwrap_or_else(|e| panic!("parse {pkg} Cargo.toml: {e}"));

    if let Some(toml::Value::Table(package)) = doc.get_mut("package") {
        let keys: Vec<String> = package.keys().cloned().collect();
        for key in keys {
            if is_workspace_true(package.get(&key)) {
                let ws = ws.unwrap_or_else(|| {
                    panic!("{pkg}: `package.{key}.workspace = true` but no [workspace] root found")
                });
                let value = ws
                    .package
                    .get(&key)
                    .unwrap_or_else(|| panic!("{pkg}: workspace.package has no `{key}`"))
                    .clone();
                package.insert(key, value);
            }
        }
    }

    for section in ["dependencies", "build-dependencies"] {
        if let Some(toml::Value::Table(deps)) = doc.get_mut(section) {
            let names: Vec<String> = deps.keys().cloned().collect();
            for name in names {
                let raw = deps.get(&name).expect("dep present").clone();
                let resolved = resolve_dep(pkg, &name, &raw, ws, pkg_set);
                deps.insert(name, resolved);
            }
        }
    }

    // Dev-deps reach crates outside the closure and cargo resolves them even for
    // `cargo build`; a `[workspace]` table cargo's packaging may have added would
    // fight the generated root manifest.
    doc.remove("dev-dependencies");
    doc.remove("workspace");

    // Any other inherited table (`[lints] workspace = true`, ...) would need the
    // generated root manifest to carry it. None does today; refuse rather than
    // ship a manifest the unpacked workspace cannot load.
    for (key, value) in &doc {
        if !matches!(
            key.as_str(),
            "package" | "dependencies" | "build-dependencies"
        ) && is_workspace_true(Some(value))
        {
            panic!("{pkg}: `[{key}] workspace = true` is not supported by the shim source bundle");
        }
    }

    toml::to_string(&doc).unwrap_or_else(|e| panic!("serialize {pkg} Cargo.toml: {e}"))
}

fn resolve_dep(
    pkg: &str,
    name: &str,
    raw: &toml::Value,
    ws: Option<&WorkspaceTables>,
    pkg_set: &BTreeSet<&str>,
) -> toml::Value {
    let mut spec = to_dep_table(pkg, name, raw);

    if spec.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
        spec.remove("workspace");
        let ws = ws.unwrap_or_else(|| {
            panic!("{pkg}: dependency `{name}.workspace = true` but no [workspace] root found")
        });
        let base = ws
            .deps
            .get(name)
            .unwrap_or_else(|| panic!("{pkg}: workspace.dependencies has no `{name}`"));
        spec = merge_ws_dep(to_dep_table(pkg, name, base), spec);
    }

    if pkg_set.contains(name) {
        // Repoint every closure crate to its sibling in the unpacked workspace,
        // keeping the crates.io version requirement and any feature selection.
        let mut out = toml::Table::new();
        let version = spec
            .get("version")
            .cloned()
            .unwrap_or_else(|| panic!("{pkg}: internal dependency `{name}` has no version"));
        out.insert("version".into(), version);
        out.insert("path".into(), toml::Value::String(format!("../{name}")));
        for key in ["features", "optional", "default-features"] {
            if let Some(value) = spec.get(key) {
                out.insert(key.into(), value.clone());
            }
        }
        toml::Value::Table(out)
    } else {
        toml::Value::Table(spec)
    }
}

fn to_dep_table(pkg: &str, name: &str, value: &toml::Value) -> toml::Table {
    match value {
        toml::Value::String(version) => {
            let mut table = toml::Table::new();
            table.insert("version".into(), toml::Value::String(version.clone()));
            table
        }
        toml::Value::Table(table) => table.clone(),
        other => panic!("{pkg}: dependency `{name}` has an unexpected spec: {other}"),
    }
}

/// Overlay a `workspace = true` entry's local keys onto the workspace base:
/// features union, everything else (optional, default-features, version) wins
/// locally — cargo's inheritance rule.
fn merge_ws_dep(mut base: toml::Table, local: toml::Table) -> toml::Table {
    for (key, value) in local {
        if key == "features" {
            let mut features: Vec<toml::Value> = base
                .get("features")
                .and_then(toml::Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(extra) = value.as_array() {
                for feature in extra {
                    if !features.contains(feature) {
                        features.push(feature.clone());
                    }
                }
            }
            base.insert("features".into(), toml::Value::Array(features));
        } else {
            base.insert(key, value);
        }
    }
    base
}

fn is_workspace_true(value: Option<&toml::Value>) -> bool {
    value
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true)
}

fn find_cargo_lock(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let lock = dir.join("Cargo.lock");
        if lock.is_file() {
            return Some(lock);
        }
        cur = dir.parent();
    }
    None
}

// --- codegen helpers -------------------------------------------------------

fn hash_frame(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut out = String::new();
    for byte in bytes.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A Rust string literal for `text` (escaped, quoted).
fn str_literal(text: &str) -> String {
    format!("{text:?}")
}

/// A Rust string literal for a path, for `include_bytes!`.
fn path_literal(path: &Path) -> String {
    str_literal(path.to_str().expect("utf-8 path"))
}
