//! Class: **installed binary depends on the source checkout.**
//!
//! `cargo-patina` builds a guest's linked native shim at guest-build time. It
//! once located the shim crate by baking its own source checkout path into the
//! binary (`env!("CARGO_MANIFEST_DIR")`) and running `cargo build -p
//! patina-dst-native-shim` there — so a binary produced by `cargo install`
//! (registry checkout, no workspace around it), `cargo install --git` (temporary
//! checkout, deleted), or CI could not build any native guest. Only in-tree
//! builds worked. The shim source now travels inside the binary and is unpacked
//! into a per-user cache, and nothing in the binary may name the checkout.
//!
//! This is the standalone detector for that class: it reads its own CLI binary
//! and fails if the loadable image contains the absolute workspace root path.
//! Only sections mapped into the process image are scanned: DWARF carries the
//! compile directory (`DW_AT_comp_dir` in `.debug_str`) by design, is absent
//! from release and installed builds, and is never read by the running program.
//! The `.rodata` string a runtime path lookup bakes in is what this test is for.
//! Red before the source bundle (the path sat in `.rodata`, twice), green after.

use object::{Object, ObjectSection, SectionFlags, SectionKind};
use std::path::Path;

/// Whether a section is part of the process image. ELF says so directly
/// (`SHF_ALLOC`; DWARF sections such as `.debug_str` are unallocated string
/// tables). Other formats fall back to the section kind: a linked Mach-O binary
/// carries no DWARF at all, so everything but an explicit debug kind counts.
fn loadable(section: &object::Section<'_, '_>) -> bool {
    match section.flags() {
        SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
        _ => !matches!(
            section.kind(),
            SectionKind::Debug | SectionKind::DebugString
        ),
    }
}

/// The workspace root this test binary was compiled from: the grandparent of
/// the `cargo-patina` crate directory, exactly what the old lookup baked in.
fn workspace_root() -> &'static str {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is two levels below the workspace root")
        .to_str()
        .expect("utf-8 workspace path")
}

#[test]
fn the_cli_binary_does_not_name_its_source_checkout() {
    let path = env!("CARGO_BIN_EXE_cargo-patina");
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("reading {path}: {error}"));
    let file =
        object::File::parse(&*bytes).unwrap_or_else(|error| panic!("parsing {path}: {error}"));
    let needle = workspace_root().as_bytes();
    assert!(!needle.is_empty());

    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for section in file.sections() {
        if !loadable(&section) {
            continue;
        }
        let Ok(data) = section.data() else { continue };
        scanned += data.len();
        let hits = data
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count();
        if hits > 0 {
            offenders.push(format!(
                "{} [{:?}] ({hits} occurrence{})",
                section.name().unwrap_or("<unnamed>"),
                section.kind(),
                if hits == 1 { "" } else { "s" }
            ));
        }
    }
    assert!(
        scanned > 0,
        "no loadable section data in {path}: the scan is vacuous"
    );
    assert!(
        offenders.is_empty(),
        "{path} names its source checkout {:?} in loadable section(s) {}: an installed \
         cargo-patina would depend on a checkout that is not there (the class this test pins: \
         installed binary depends on the source checkout)",
        workspace_root(),
        offenders.join(", ")
    );
}
