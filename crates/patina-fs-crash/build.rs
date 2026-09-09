// This crate is part of the native-shim build closure that `cargo-patina`
// carries embedded and unpacks to build a guest's linked shim. The only job of
// this build script is to publish this crate's source directory to the build
// script of any direct dependent via cargo's `links`/`DEP_*` metadata channel
// (see `crates/patina-native-shim/AGENTS.md`), which is how `cargo-patina`'s
// build script discovers every crate to embed — in-tree, from the crates.io
// registry checkout, and from a git checkout alike.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:src_dir={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
}
