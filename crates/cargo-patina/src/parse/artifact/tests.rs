//! Argument parsing regression tests.

use super::*;
use crate::tests::strings;
use crate::{ArtifactRef, BuildSpecKind, NativeBuildTarget};
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

#[test]
fn detects_artifact_family_from_magic() {
    // WebAssembly preamble.
    assert_eq!(
        detect_artifact_family(b"\0asm\x01\0\0\0"),
        Some(ArtifactFamily::Wasm)
    );
    // ELF.
    assert_eq!(
        detect_artifact_family(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
        Some(ArtifactFamily::Native)
    );
    // Mach-O thin (both byte orders) and universal ("fat").
    for magic in [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ] {
        assert_eq!(
            detect_artifact_family(&magic),
            Some(ArtifactFamily::Native),
            "Mach-O magic {magic:02x?} should classify as native"
        );
    }
    // Unrecognized: a Cargo.toml, a too-short buffer, an empty buffer.
    assert_eq!(detect_artifact_family(b"[package]\nname = \"x\"\n"), None);
    assert_eq!(detect_artifact_family(b"\0as"), None);
    assert_eq!(detect_artifact_family(b""), None);
}

#[test]
fn extracts_target_selector() {
    let (target, rest) =
        extract_target(strings(&["src.rs", "--target", "wasi", "--release"])).unwrap();
    assert_eq!(target.as_deref(), Some("wasi"));
    assert_eq!(rest, strings(&["src.rs", "--release"]));

    let (target, rest) = extract_target(strings(&["pkg", "--target=native"])).unwrap();
    assert_eq!(target.as_deref(), Some("native"));
    assert_eq!(rest, strings(&["pkg"]));

    // A `--target` past `--` is a rustc/cargo flag, left in place.
    let (target, rest) = extract_target(strings(&["src.rs", "--", "--target", "x86"])).unwrap();
    assert_eq!(target, None);
    assert_eq!(rest, strings(&["src.rs", "--", "--target", "x86"]));

    assert_eq!(target_family("native").unwrap(), ArtifactFamily::Native);
    assert_eq!(target_family("wasi").unwrap(), ArtifactFamily::Wasm);
    assert!(target_family("riscv").is_err());
}

#[test]
fn classifies_and_resolves_positional_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();

    // A native (ELF) magic file is a built artifact.
    let elf = root.join("bin");
    fs::write(&elf, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    assert!(matches!(
        classify_arg(elf.as_os_str()).unwrap(),
        ArgKind::Artifact(ArtifactFamily::Native)
    ));
    // A WebAssembly magic file is a built artifact.
    let wasm = root.join("mod.wasm");
    fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
    assert!(matches!(
        classify_arg(wasm.as_os_str()).unwrap(),
        ArgKind::Artifact(ArtifactFamily::Wasm)
    ));
    // A `.rs` source, a package directory, and a Cargo.toml are sources.
    let source = root.join("main.rs");
    fs::write(&source, "fn main() {}").unwrap();
    assert!(matches!(
        classify_arg(source.as_os_str()).unwrap(),
        ArgKind::SourceFile(_)
    ));
    let pkg = root.join("pkg");
    fs::create_dir(&pkg).unwrap();
    fs::write(pkg.join("Cargo.toml"), "[package]").unwrap();
    match classify_arg(pkg.as_os_str()).unwrap() {
        ArgKind::SourcePackage(manifest) => assert_eq!(manifest, pkg.join("Cargo.toml")),
        _ => panic!("expected a source package"),
    }
    assert!(matches!(
        classify_arg(pkg.join("Cargo.toml").as_os_str()).unwrap(),
        ArgKind::SourcePackage(_)
    ));
    // A leading flag and a plain non-source file are neither.
    assert!(matches!(
        classify_arg(OsStr::new("--seed")).unwrap(),
        ArgKind::Other
    ));
    let plain = root.join("notes.txt");
    fs::write(&plain, "hello").unwrap();
    assert!(matches!(
        classify_arg(plain.as_os_str()).unwrap(),
        ArgKind::Other
    ));

    // Resolution: a lone `.rs` builds native; `--target wasi` on a `.rs`
    // errors (native-only); a prebuilt artifact with a mismatched --target
    // errors.
    let (family, artifact) = resolve_positional(source.as_os_str(), None)
        .unwrap()
        .unwrap();
    assert_eq!(family, ArtifactFamily::Native);
    assert!(matches!(artifact, ArtifactRef::Build(_)));
    assert!(resolve_positional(source.as_os_str(), Some("wasi")).is_err());
    assert!(resolve_positional(wasm.as_os_str(), Some("native")).is_err());

    // A package directory resolves to a native build-on-the-fly with no
    // `--target` — the SAME path `audit` uses, so an existing directory is
    // never reinterpreted as guest argv. (Keeping a runtime-linked package on
    // the cargo family is a `run`/`replay` routing decision made upstream via
    // `package_integrates_patina`, not by this pure resolver.) `--target wasi`
    // selects the WASI package build.
    let (family, artifact) = resolve_positional(pkg.as_os_str(), None).unwrap().unwrap();
    assert_eq!(family, ArtifactFamily::Native);
    assert!(matches!(artifact, ArtifactRef::Build(_)));
    let (family, _) = resolve_positional(pkg.as_os_str(), Some("wasi"))
        .unwrap()
        .unwrap();
    assert_eq!(family, ArtifactFamily::Wasm);
    // A leading flag resolves to nothing (the caller's no-artifact path).
    assert!(
        resolve_positional(OsStr::new("--seed"), None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn source_first_package_selection_threads_into_the_build_spec() {
    // `--package`/`--bin` are extracted from the head (before any `--`) and the
    // rest is passed through; a `--package` in the guest section is untouched.
    let selection = take_package_bin(strings(&[
        "--package",
        "member",
        "--seed",
        "1",
        "--bin",
        "app",
        "--",
        "--package",
        "guest",
    ]))
    .unwrap();
    assert_eq!(selection.package.as_deref(), Some("member"));
    assert_eq!(selection.bin.as_deref(), Some("app"));
    assert_eq!(
        selection.rest,
        strings(&["--seed", "1", "--", "--package", "guest"])
    );

    // Applied to a native package build spec, they select the member/binary.
    let mut artifact = ArtifactRef::Build(Box::new(native_package_spec(
        PathBuf::from("ws"),
        PathBuf::from("ws/Cargo.toml"),
    )));
    apply_package_selection(&mut artifact, Some("member".into()), Some("app".into())).unwrap();
    match &artifact {
        ArtifactRef::Build(spec) => match &spec.kind {
            BuildSpecKind::Native(inv) => match &inv.target {
                NativeBuildTarget::Package { package, bin, .. } => {
                    assert_eq!(package.as_deref(), Some("member"));
                    assert_eq!(bin.as_deref(), Some("app"));
                }
                _ => panic!("expected a package target"),
            },
            _ => panic!("expected a native build"),
        },
        _ => panic!("expected a build spec"),
    }

    // A prebuilt artifact or a single `.rs` source has nothing to select, so a
    // stray selection fails closed rather than being silently ignored; an empty
    // selection is a no-op on any artifact.
    let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
    assert!(apply_package_selection(&mut prebuilt, Some("x".into()), None).is_err());
    assert!(apply_package_selection(&mut prebuilt, None, None).is_ok());
    let mut source = ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs"))));
    assert!(apply_package_selection(&mut source, None, Some("x".into())).is_err());
}

#[test]
fn source_first_release_threads_into_the_build_spec() {
    // `--release` is extracted from the head (before any `--`); the rest passes
    // through, and a `--release` in the guest section stays untouched.
    let (release, rest) =
        take_release(strings(&["--release", "--seed", "1", "--", "--release"])).unwrap();
    assert!(release);
    assert_eq!(rest, strings(&["--seed", "1", "--", "--release"]));

    // Absent, it defaults off; an inline value is rejected (valueless switch).
    let (release, rest) = take_release(strings(&["--seed", "1"])).unwrap();
    assert!(!release);
    assert_eq!(rest, strings(&["--seed", "1"]));
    assert!(take_release(strings(&["--release=yes"])).is_err());

    // Applied to a native source/package build, it flips the release profile;
    // a WASI package build spec flips too.
    for mut artifact in [
        ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs")))),
        ArtifactRef::Build(Box::new(native_package_spec(
            PathBuf::from("ws"),
            PathBuf::from("ws/Cargo.toml"),
        ))),
        ArtifactRef::Build(Box::new(wasi_package_spec(
            PathBuf::from("ws"),
            PathBuf::from("ws/Cargo.toml"),
        ))),
    ] {
        apply_release(&mut artifact, true).unwrap();
        let released = match &artifact {
            ArtifactRef::Build(spec) => match &spec.kind {
                BuildSpecKind::Native(inv) => inv.release,
                BuildSpecKind::Wasi(inv) => inv.release,
            },
            _ => panic!("expected a build spec"),
        };
        assert!(
            released,
            "release profile did not thread into the build spec"
        );
    }

    // An already-built artifact carries no build profile, so `--release` on a
    // prebuilt positional fails closed rather than being silently ignored; a
    // false (absent) release is a no-op on any artifact.
    let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
    assert!(apply_release(&mut prebuilt, true).is_err());
    assert!(apply_release(&mut prebuilt, false).is_ok());
}
