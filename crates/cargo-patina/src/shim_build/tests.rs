use super::*;
use crate::native_build::GuestInstrumentation;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use crate::shim_cache;

#[test]
fn a_shim_object_is_keyed_by_the_sdk_the_compiler_reads() {
    let hash = |sdk: Option<&str>| {
        shim_object_hash_in(
            OsStr::new("cc"),
            &PATINA_YIELD_OBJECT,
            "x86_64-unknown-linux-gnu",
            &[],
            |name| {
                (name == "SDKROOT")
                    .then_some(sdk)
                    .flatten()
                    .map(OsString::from)
            },
        )
        .unwrap()
    };
    let unset = hash(None);
    let older = hash(Some("/sdks/MacOSX26.sdk"));
    let newer = hash(Some("/sdks/MacOSX27.sdk"));
    assert_eq!(older, hash(Some("/sdks/MacOSX26.sdk")));
    assert_ne!(older, newer);
    assert_ne!(unset, older);
    assert_ne!(unset, hash(Some("")));
}

#[test]
fn a_relative_rustc_probes_as_one_program_from_both_directories() {
    let from = Path::new("/work/guest");
    // A bare name is PATH-resolved, which does not vary by directory.
    assert_eq!(
        anchored_program(None, from, "rustc"),
        OsString::from("rustc")
    );
    assert_eq!(
        anchored_program(Some("rustc".into()), from, "rustc"),
        OsString::from("rustc")
    );
    // An absolute path already names one program.
    assert_eq!(
        anchored_program(Some("/opt/rust/bin/rustc".into()), from, "rustc"),
        OsString::from("/opt/rust/bin/rustc")
    );
    // A relative path with a directory component would otherwise resolve
    // against each probe's own working directory — two different programs,
    // reported as a toolchain split that does not exist.
    assert_eq!(
        anchored_program(Some("./tools/rustc".into()), from, "rustc"),
        OsString::from("/work/guest/./tools/rustc")
    );
    assert_eq!(
        anchored_program(Some("tools/rustc".into()), from, "rustc"),
        OsString::from("/work/guest/tools/rustc")
    );
}

#[test]
fn shim_caches_are_separated_by_source_bundle_and_complete_toolchain_identity() {
    let cache = tempfile::tempdir().unwrap();
    let workspace = cache.path();
    let archive = workspace.join("cargo.a");
    fs::write(&archive, b"stable archive").unwrap();
    let stable = RustcIdentity {
        banner: "rustc 1.98.0 (stable)".into(),
        verbose: "rustc 1.98.0 (stable)\ncommit-hash: stable".into(),
    };
    let other = RustcIdentity {
        banner: "rustc 1.98.1 (other)".into(),
        verbose: "rustc 1.98.1 (other)\ncommit-hash: other".into(),
    };
    let base = native_shim_cache_base(workspace, None).unwrap();
    let stable_artifact =
        publish_native_shim(&archive, &base, "bundle-a", &stable, "debug").unwrap();
    fs::write(&archive, b"other archive").unwrap();
    let other_artifact = publish_native_shim(&archive, &base, "bundle-a", &other, "debug").unwrap();
    let changed = publish_native_shim(&archive, &base, "bundle-b", &stable, "debug").unwrap();
    assert_ne!(stable_artifact.staticlib, other_artifact.staticlib);
    assert_ne!(stable_artifact.staticlib, changed.staticlib);
    let same_bytes_other_bundle =
        publish_native_shim(&archive, &base, "bundle-a", &stable, "debug").unwrap();
    assert_ne!(same_bytes_other_bundle.staticlib, changed.staticlib);
    assert_eq!(
        fs::read(&stable_artifact.staticlib).unwrap(),
        b"stable archive"
    );
    assert_eq!(
        fs::read(&other_artifact.staticlib).unwrap(),
        b"other archive"
    );
    // Equal banners and bytes still cannot alias different complete identities.
    let mut rebuilt_toolchain = stable.clone();
    rebuilt_toolchain
        .verbose
        .push_str("\nLLVM version: different");
    let rebuilt =
        publish_native_shim(&archive, &base, "bundle-b", &rebuilt_toolchain, "debug").unwrap();
    assert_ne!(rebuilt.staticlib, changed.staticlib);
    let release = publish_native_shim(&archive, &base, "bundle-b", &stable, "release").unwrap();
    assert_ne!(release.staticlib, changed.staticlib);

    assert_eq!(
        native_shim_cache_base(workspace, Some(OsStr::new("/custom-target"))).unwrap(),
        PathBuf::from("/custom-target/patina-native-shim")
    );
    assert_eq!(
        native_shim_cache_base(workspace, Some(OsStr::new("relative"))).unwrap(),
        env::current_dir()
            .unwrap()
            .join("relative/patina-native-shim")
    );
    // PATINA_SHIM_TARGET_DIR takes precedence over CARGO_TARGET_DIR; an empty one is unset.
    {
        let shim = || Some(OsString::from("/shim-target"));
        let cargo = || Some(OsString::from("/cargo-target"));
        assert_eq!(shim_target_base(shim(), cargo()), shim());
        assert_eq!(shim_target_base(shim(), None), shim());
        assert_eq!(shim_target_base(None, cargo()), cargo());
        assert_eq!(shim_target_base(Some(OsString::new()), cargo()), cargo());
        assert_eq!(shim_target_base(None, None), None);
    }
}

#[test]
fn incomplete_shim_source_bundle_is_repaired() {
    let cache = tempfile::tempdir().unwrap();
    let bundles = cache.path().join("shim-src");
    let key = shim_bundle::EMBEDDED_SHIM_BUNDLE_SHA256;
    let partial = bundles.join(key);
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("Cargo.toml"), b"interrupted old extraction").unwrap();
    let lease = shim_cache::acquire_initialized(&bundles, key, 1, || {
        unpack_embedded_shim_sources(cache.path()).map(|_| ())
    })
    .unwrap();
    assert!(shim_cache::complete(&lease.dir, key).unwrap());
    for (package, files) in shim_bundle::EMBEDDED_SHIM_SOURCES {
        for (path, bytes) in *files {
            assert_eq!(
                fs::read(lease.dir.join(package).join(path)).unwrap(),
                *bytes
            );
        }
    }
}

/// Build real archives with deliberately different link-time answers. This
/// is the class-level detector for restored-bundle Cargo freshness, mutable
/// output handoff, and cross-bundle concurrent builds (not just key strings).
#[test]
#[cfg(unix)]
fn concurrent_shim_bundles_link_their_own_archives_after_a_bundle_restore() {
    if shim_cache::isolated_test() {
        return;
    }
    let cache = tempfile::tempdir().unwrap();
    let make_bundle = |key: &'static str, answer: u32| {
        let lease = shim_cache::acquire(&cache.path().join("shim-src"), key, 4).unwrap();
        // Even an ambient/configured Cargo intermediate directory must not
        // escape the leased, size-bounded scratch target.
        fs::create_dir_all(lease.dir.join(".cargo")).unwrap();
        fs::write(
            lease.dir.join(".cargo/config.toml"),
            format!(
                "[build]\nbuild-dir = {:?}\n",
                cache.path().join("escaped-build-dir")
            ),
        )
        .unwrap();
        let mut members = Vec::new();
        let mut lock = String::from("version = 3\n");
        // The shim depends on one other closure package, as the real shim
        // depends on its closure, so a switch has an unchanged dependency.
        let dependency = shim_bundle::EMBEDDED_SHIM_SOURCES
            .iter()
            .map(|(package, _)| *package)
            .find(|package| *package != "patina-dst-native-shim")
            .unwrap();
        for (package, _) in shim_bundle::EMBEDDED_SHIM_SOURCES {
            members.push(format!("{package:?}"));
            let dir = lease.dir.join(package);
            fs::create_dir_all(dir.join("src")).unwrap();
            let is_shim = *package == "patina-dst-native-shim";
            fs::write(dir.join("Cargo.toml"), format!(
                "[package]\nname = {package:?}\nversion = \"0.0.0\"\nedition = \"2021\"\n{}",
                if is_shim {
                    format!("[lib]\ncrate-type = [\"staticlib\"]\n[dependencies]\n{dependency:?} = {{ path = \"../{dependency}\" }}\n")
                } else {
                    String::new()
                }
            )).unwrap();
            fs::write(dir.join("src/lib.rs"), if is_shim {
                format!("#[no_mangle] pub extern \"C\" fn shim_cache_sentinel() -> u32 {{ {answer} }}\n")
            } else { String::new() }).unwrap();
            lock.push_str(&format!(
                "\n[[package]]\nname = {package:?}\nversion = \"0.0.0\"\n"
            ));
            if is_shim {
                lock.push_str(&format!("dependencies = [\n {dependency:?},\n]\n"));
            }
        }
        fs::write(
            lease.dir.join("Cargo.toml"),
            format!(
                "[workspace]\nresolver = \"2\"\nmembers = [{}]\n",
                members.join(",")
            ),
        )
        .unwrap();
        fs::write(lease.dir.join("Cargo.lock"), lock).unwrap();
        ShimSources {
            cache_root: cache.path().into(),
            dir: lease.dir.clone(),
            bundle_hash: key,
            _lease: lease,
        }
    };
    let a = make_bundle("a", 17);
    let b = make_bundle("b", 29);
    let mut rustc = check_native_toolchain_agreement(&a.dir).unwrap();
    let quote = |path: &OsStr| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    // Reproduce clonefile-preserved timestamps on every platform. Without
    // clean -p, Cargo sees the old dep-info as fresh despite different bytes.
    let backdate = cache.path().join("cargo-backdate");
    fs::write(&backdate, format!(
        "#!/bin/sh\nset -eu\nfind . -type f -exec touch -t 200001010000 {{}} +\nexec {} \"$@\"\n",
        quote(&rustc.cargo_command)
    )).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&backdate, fs::Permissions::from_mode(0o755)).unwrap();
    rustc.cargo_command = backdate.as_os_str().into();
    let link = |built: &BuiltNativeShim, expected: u32| {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("guest.c");
        let guest = dir.path().join("guest");
        fs::write(&source, format!("extern unsigned shim_cache_sentinel(void); int main(void) {{ return shim_cache_sentinel() != {expected}; }}")).unwrap();
        let mut cc = Command::new("cc");
        cc.arg(source).arg(&built.staticlib).arg("-o").arg(&guest);
        if cfg!(target_os = "linux") {
            cc.args(["-ldl", "-lpthread", "-lm"]);
        }
        assert!(cc.status().unwrap().success());
        assert!(Command::new(guest).status().unwrap().success());
    };
    // Both archive handles survive while another bundle overwrites Cargo's
    // same-named output. Rendezvous AFTER build, BEFORE either guest links.
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = [(&a, 17), (&b, 29)]
            .into_iter()
            .map(|(bundle, expected)| {
                let rustc = &rustc;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    (
                        build_native_shim_at(
                            false,
                            rustc,
                            bundle,
                            None,
                            GuestInstrumentation::None,
                        )
                        .unwrap(),
                        expected,
                    )
                })
            })
            .collect();
        let built: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (artifact, expected) in built {
            link(&artifact, expected);
        }
    });
    // The compiled libraries of the closure packages other than the shim,
    // which the two bundles share byte for byte, by path and mtime.
    let shared_artifacts = || {
        let builds = native_shim_cache_base(cache.path(), None)
            .unwrap()
            .join("builds");
        let mut artifacts = std::collections::BTreeMap::new();
        for work in fs::read_dir(builds).unwrap() {
            let deps = work.unwrap().path().join("target/debug/deps");
            for entry in fs::read_dir(&deps).into_iter().flatten() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if name.ends_with(".rlib") && !name.starts_with("libpatina_dst_native_shim") {
                    let modified = fs::metadata(&path).unwrap().modified().unwrap();
                    artifacts.insert(path, modified);
                }
            }
        }
        assert!(!artifacts.is_empty(), "non-vacuous shared artifacts");
        artifacts
    };
    let before_switches = shared_artifacts();
    // A file in the shim crate's incremental history, which `cargo clean
    // -p` removes with the crate's artifacts.
    let history_marker = || {
        let builds = native_shim_cache_base(cache.path(), None)
            .unwrap()
            .join("builds");
        let work = fs::read_dir(builds)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap();
        let incremental = work.join("target/debug/incremental");
        let crate_dir = fs::read_dir(&incremental)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("patina_dst_native_shim-")
            })
            .expect("the debug shim keeps incremental history");
        crate_dir.join("kept-across-switches")
    };
    fs::write(history_marker(), "").unwrap();
    // Force A -> B -> A even if the concurrent scheduling chose B -> A.
    for (bundle, expected) in [(&a, 17), (&b, 29), (&a, 17)] {
        let built =
            build_native_shim_at(false, &rustc, bundle, None, GuestInstrumentation::None).unwrap();
        link(&built, expected);
    }
    // Each switch replaced only the package whose bytes differ: the
    // packages the bundles share were never rebuilt, and the replaced
    // one's rebuild kept its incremental history.
    assert_eq!(shared_artifacts(), before_switches);
    assert!(
        history_marker().exists(),
        "a switch discarded incremental history"
    );
    assert!(!cache.path().join("escaped-build-dir").exists());

    // A compiler-wrapper server can outlive the command that started it.
    // It may pin shared state, but the next real build must acquire the
    // exclusive build lock without waiting for that server to exit.
    let fifo = cache.path().join("daemon-control");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    struct ResumeDaemon(fs::File);
    impl Drop for ResumeDaemon {
        fn drop(&mut self) {
            use std::io::Write;
            let _ = self.0.write_all(b"finish\n");
        }
    }
    let resume = ResumeDaemon(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap(),
    );
    let ready = cache.path().join("daemon-ready");
    let claim = cache.path().join("daemon-started");
    let wrapper = cache.path().join("cargo-daemon-wrapper");
    fs::write(&wrapper, format!(
        "#!/bin/sh\nset -eu\nif [ \"$1\" = rustc ] && mkdir {} 2>/dev/null; then\n  (exec 3< {}; : > {}; read reply <&3) </dev/null >/dev/null 2>&1 &\nfi\nexec {} \"$@\"\n",
        quote(claim.as_os_str()), quote(fifo.as_os_str()), quote(ready.as_os_str()), quote(backdate.as_os_str())
    )).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let mut daemon_rustc = rustc.clone();
    daemon_rustc.cargo_command = wrapper.into();
    let first =
        build_native_shim_at(false, &daemon_rustc, &a, None, GuestInstrumentation::None).unwrap();
    link(&first, 17);
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        ready.exists(),
        "wrapper's long-lived child never became ready"
    );
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let next = scope.spawn(move || {
            let built =
                build_native_shim_at(false, &daemon_rustc, &b, None, GuestInstrumentation::None);
            tx.send(()).unwrap();
            built
        });
        let unblocked = rx.recv_timeout(std::time::Duration::from_secs(30)).is_ok();
        drop(resume); // release the server even when detecting the regression
        let built = next.join().unwrap().unwrap();
        assert!(
            unblocked,
            "a wrapper daemon retained the exclusive build lock"
        );
        link(&built, 29);
    });

    let builds = native_shim_cache_base(cache.path(), None)
        .unwrap()
        .join("builds");
    let work = fs::read_dir(&builds)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    let release = build_native_shim_at(true, &rustc, &a, None, GuestInstrumentation::None).unwrap();
    link(&release, 17);
    // A debug build never waits for a release build: while another builder
    // holds every release work dir's build lock, a debug build completes.
    let release_works = fs::read_dir(&builds)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.join("target/release")
                .join(NATIVE_SHIM_STATICLIB)
                .exists()
        })
        .collect::<Vec<_>>();
    assert!(!release_works.is_empty());
    let held = release_works
        .iter()
        .map(|work| lock_target_dir(work).unwrap())
        .collect::<Vec<_>>();
    let debug = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let (rustc, a) = (&rustc, &a);
        let builder = scope.spawn(move || {
            let built = build_native_shim_at(false, rustc, a, None, GuestInstrumentation::None);
            tx.send(()).unwrap();
            built
        });
        let finished = rx.recv_timeout(std::time::Duration::from_secs(30)).is_ok();
        drop(held); // let a queued build finish even when detecting the regression
        let debug = builder.join().unwrap().unwrap();
        assert!(
            finished,
            "a debug shim build waited for a release build's lock"
        );
        debug
    });
    link(&debug, 17);
    assert!(
        work.join("target/debug")
            .join(NATIVE_SHIM_STATICLIB)
            .exists()
    );
    assert_ne!(release.staticlib, debug.staticlib);
    let growth = work.join("target/oversized-scratch");
    fs::File::create(&growth)
        .unwrap()
        .set_len(shim_cache::BUILD_BYTES + 1)
        .unwrap();
    // Model an old torn entry: the completion marker is missing but the
    // bundle marker survived alongside a broken private copy. Retrying A must
    // replace it, and oversized scratch must actually be removed.
    fs::remove_file(work.join("source").join(shim_cache::COMPLETE)).unwrap();
    // Keep the old bundle marker: it alone is not proof of source integrity.
    fs::write(
        work.join("source/patina-dst-native-shim/src/lib.rs"),
        "compile_error!(\"incomplete source switch\");",
    )
    .unwrap();
    let restored =
        build_native_shim_at(false, &rustc, &a, None, GuestInstrumentation::None).unwrap();
    link(&restored, 17);
    assert!(!growth.exists());
}

#[test]
fn a_same_version_toolchain_split_still_names_the_difference() {
    // Two compilers can print the same banner and still be different builds
    // (a rebuilt nightly, a vendored rustc). The banner alone would then read
    // as a contradiction — "these two identical toolchains disagree" — so the
    // refusal falls back to the full `-vV` blocks.
    let shim = RustcIdentity {
        banner: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)".into(),
        verbose: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)\ncommit-hash: aaaaaaaaa\nLLVM version: \
                  20.1.0"
            .into(),
    };
    let guest = RustcIdentity {
        banner: shim.banner.clone(),
        verbose: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)\ncommit-hash: bbbbbbbbb\nLLVM version: \
                  21.1.0"
            .into(),
    };
    assert_ne!(shim, guest);
    let message = toolchain_mismatch_message(
        &shim,
        Path::new("/patina"),
        &guest,
        Path::new("/work/guest"),
    );
    assert!(message.contains("refusing to build"), "{message}");
    assert!(
        message.contains("/patina") && message.contains("/work/guest"),
        "{message}"
    );
    assert!(
        message.contains("commit-hash: aaaaaaaaa") && message.contains("commit-hash: bbbbbbbbb"),
        "the same-banner case must show the full identities:\n{message}"
    );
    assert!(message.contains("No ambient fallback"), "{message}");
    assert!(
        message.contains("absolute, matching RUSTC and CARGO"),
        "{message}"
    );

    // Differing banners are self-explanatory; no full dump.
    let other = RustcIdentity {
        banner: "rustc 1.98.1 (48a229cea 2026-09-01)".into(),
        verbose: "rustc 1.98.1 (48a229cea 2026-09-01)\ncommit-hash: 48a229cea".into(),
    };
    let message = toolchain_mismatch_message(&shim, Path::new("/patina"), &other, Path::new("/g"));
    assert!(message.contains("rustc 1.98.1"), "{message}");
    assert!(
        !message.contains("commit-hash: 48a229cea"),
        "differing banners need no full dump:\n{message}"
    );
}

// A guest relinks when the shim changes because the staticlib it links is
// named by its bytes and Cargo fingerprints the `cargo rustc --` link
// arguments. Same bytes must publish to the same path (an unchanged rebuild
// stays a cache hit and stores nothing new); changed bytes, even at the same
// length, to a new one; and a published copy never changes afterwards.
#[test]
fn published_shim_staticlib_is_named_by_its_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let staticlib = directory.path().join(NATIVE_SHIM_STATICLIB);
    let identity = RustcIdentity {
        banner: "test".into(),
        verbose: "test complete identity".into(),
    };
    let publish =
        || publish_native_shim(&staticlib, directory.path(), "bundle", &identity, "debug").unwrap();
    fs::write(&staticlib, b"shim bytes").unwrap();
    let first = publish();
    let abandoned = first._lease.dir.join("archive.partial");
    fs::write(&abandoned, b"interrupted publication").unwrap();
    assert_eq!(publish().staticlib, first.staticlib);
    assert!(!abandoned.exists());

    fs::write(&staticlib, b"shim bytez").unwrap();
    let flipped = publish();
    fs::write(&staticlib, b"rebuilt shim bytes").unwrap();
    let rebuilt = publish();
    assert_ne!(
        first.staticlib, flipped.staticlib,
        "a same-length edit must publish a new name"
    );
    assert_ne!(first.staticlib, rebuilt.staticlib);
    assert_ne!(flipped.staticlib, rebuilt.staticlib);

    assert_eq!(fs::read(&first.staticlib).unwrap(), b"shim bytes");
    assert_eq!(fs::read(&flipped.staticlib).unwrap(), b"shim bytez");
    assert_eq!(fs::read(&rebuilt.staticlib).unwrap(), b"rebuilt shim bytes");
}
