//! Argument parsing regression tests.

use super::*;
use crate::tests::strings;
use crate::{ArtifactRef, NativeBuildTarget};
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

#[test]
fn recognizes_native_magic() {
    // ELF.
    assert!(is_native_magic(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]));
    // Mach-O thin (both byte orders) and universal ("fat").
    for magic in [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ] {
        assert!(
            is_native_magic(&magic),
            "Mach-O magic {magic:02x?} should classify as native"
        );
    }
    // Unrecognized: a WebAssembly module, a Cargo.toml, a too-short buffer, an
    // empty buffer.
    assert!(!is_native_magic(b"\0asm\x01\0\0\0"));
    assert!(!is_native_magic(b"[package]\nname = \"x\"\n"));
    assert!(!is_native_magic(b"\x7fEL"));
    assert!(!is_native_magic(b""));
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
        ArgKind::Artifact
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

    // Resolution: a prebuilt binary is used as-is and a lone `.rs` builds.
    assert!(matches!(
        resolve_positional("run", elf.as_os_str()).unwrap(),
        ArtifactRef::Prebuilt(_)
    ));
    assert!(matches!(
        resolve_positional("run", source.as_os_str()).unwrap(),
        ArtifactRef::Build(_)
    ));

    // A package directory resolves to a native build-on-the-fly, so an existing
    // directory is never reinterpreted as guest argv.
    assert!(matches!(
        resolve_positional("run", pkg.as_os_str()).unwrap(),
        ArtifactRef::Build(_)
    ));
    // A leading flag or a plain file is neither.
    assert!(resolve_positional("run", OsStr::new("--seed")).is_err());
    assert!(resolve_positional("run", plain.as_os_str()).is_err());
}

#[test]
fn source_first_package_selection_and_release_thread_into_the_build_spec() {
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
        ArtifactRef::Build(spec) => match &spec.build.target {
            NativeBuildTarget::Package { package, bin, .. } => {
                assert_eq!(package.as_deref(), Some("member"));
                assert_eq!(bin.as_deref(), Some("app"));
            }
            _ => panic!("expected a package target"),
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
    {
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

        // Applied to a source/package build, it flips the release profile.
        for mut artifact in [
            ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs")))),
            ArtifactRef::Build(Box::new(native_package_spec(
                PathBuf::from("ws"),
                PathBuf::from("ws/Cargo.toml"),
            ))),
        ] {
            apply_release(&mut artifact, true).unwrap();
            let released = match &artifact {
                ArtifactRef::Build(spec) => spec.build.release,
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
}
