//! Embedded native interposer sources and compile flags.

/// The POSIX interposer C translation unit, exposed as text so out-of-tree
/// tooling (`cargo patina build`) can reproduce the native link recipe from the
/// installed crate without the workspace source tree. It lives here — the crate
/// that generates `patina_posix.c` — so the shim's C and any embedded copy can
/// never drift, and so both this crate and `cargo-patina` package cleanly for
/// publish (each is self-contained; neither reaches across crate boundaries).
///
/// The unit is an umbrella: it `#include`s the per-family slices in
/// [`POSIX_C_FAMILY_SOURCES`], which must be staged beside it (at their
/// relative paths) before it is compiled.
pub const POSIX_C_SOURCE: &str = include_str!(concat!(env!("OUT_DIR"), "/patina_posix.c"));
/// Guest-only flags keep the extraction anchor and aliases with the definitions.
/// Never apply these to a dependency rlib or bare prefixed-ABI archive.
pub const POSIX_RUST_FLAGS: &[&str] = &["--cfg=patina_posix_exports", "-Ccodegen-units=1"];
/// Code-generation flags shared by the shipped POSIX object and its tests.
/// Unwind tables let glibc's forced pthread unwind cross C shim frames.
pub const POSIX_C_FLAGS: &[&str] = &[
    "-std=c11",
    "-D_POSIX_C_SOURCE=200809L",
    "-fno-stack-protector",
    "-fasynchronous-unwind-tables",
    "-Wall",
    "-Wextra",
    "-Werror",
];
// Staged family slices and generated routing metadata. `build_support.rs`
// emits both this list and the umbrella's includes from one ordered inventory.
include!(concat!(env!("OUT_DIR"), "/posix_sources.rs"));
/// The companion C header for [`POSIX_C_SOURCE`] (`include/patina_native.h`).
pub const NATIVE_HEADER: &str = include_str!("../include/patina_native.h");
