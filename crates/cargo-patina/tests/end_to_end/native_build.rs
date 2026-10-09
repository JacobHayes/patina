//! Native package builds, shim linking, cache reuse, and atomic copy-out.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Whole Cargo-package `native-build`: a package with a path dependency and a
    // build script builds under Patina control, passes the strict audit, and
    // records/replays byte-identically, while multi-bin ambiguity and an
    // off-allowlist binary fail closed. `native-build` builds the `patina-dst-native-shim`
    // staticlib from the surrounding Patina workspace, so it runs with the workspace
    // as its working directory while the fixture is addressed by absolute path.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_build_package_audits_records_and_fails_closed() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("pkg");
        create_package_fixture(directory.path());
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();

        // The clean binary builds through the package's own `cargo build`, with the
        // shim link args isolated to the final binary by the explicit host --target
        // (the build script's file I/O proves it did not leak onto host artifacts).
        let clean = package.join("clean-bin");
        let built = invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--bin",
                "patina-native-pkg-fixture",
                "--output",
                clean.to_str().unwrap(),
            ],
        );
        assert!(
            String::from_utf8_lossy(&built.stdout).contains("PATINA_NATIVE_BUILD"),
            "missing build marker:\n{}",
            String::from_utf8_lossy(&built.stdout)
        );
        assert!(clean.is_file());

        // The produced binary passes the same strict audit as a single-source
        // binary, with the shim control-plane symbol allowed per audited binary.
        // Under the host-alias doctrine the trace-fd, baton, and thread-creation
        // vehicles are all resolved at runtime through the `dlsym` primitive, so
        // their names never reach the guest import table — the control plane is the
        // single `dlsym` residue on both platforms (Linux reaches the resolver
        // through `-Wl,--wrap=dlsym`).
        let control_plane: &[&str] = &["dlsym"];
        let mut audit_args = vec!["audit", clean.to_str().unwrap()];
        for symbol in control_plane {
            audit_args.push("--allow");
            audit_args.push(symbol);
        }
        invoke(workspace, &audit_args);

        // The package binary runs under native-run with cross-process seed stability,
        // seed variation, and byte-identical record/replay through the supervisor.
        let seeded = package_result(&invoke(
            workspace,
            &["run", clean.to_str().unwrap(), "--seed", "5"],
        ));
        let repeated = package_result(&invoke(
            workspace,
            &["run", clean.to_str().unwrap(), "--seed", "5"],
        ));
        let other = package_result(&invoke(
            workspace,
            &["run", clean.to_str().unwrap(), "--seed", "6"],
        ));
        assert_eq!(seeded, repeated);
        assert_ne!(seeded, other);
        assert!(
            seeded.contains("built=1"),
            "build-script env missing: {seeded}"
        );
        assert!(
            seeded.contains("stored=hello from greeter"),
            "path dependency output missing: {seeded}"
        );

        let trace = directory.path().join("pkg.patina");
        let recorded = package_result(&invoke(
            workspace,
            &[
                "run",
                clean.to_str().unwrap(),
                "--seed",
                "5",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "native-pkg-v1",
            ],
        ));
        let replayed = package_result(&invoke(
            workspace,
            &[
                "replay",
                clean.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "native-pkg-v1",
            ],
        ));
        assert_eq!(recorded, seeded);
        assert_eq!(replayed, seeded);

        // Multiple binary targets with no --bin selection fails with a clear message
        // rather than guessing.
        let ambiguous = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["build", package.to_str().unwrap()],
        );
        assert!(!ambiguous.status.success());
        let ambiguous_stderr = String::from_utf8_lossy(&ambiguous.stderr);
        assert!(
            ambiguous_stderr.contains("multiple binary targets")
                && ambiguous_stderr.contains("--bin"),
            "missing ambiguity diagnostic:\n{ambiguous_stderr}"
        );

        // A binary whose build product imports an off-allowlist symbol builds, but
        // fails the audit with the existing category diagnostic.
        let leaky = package.join("leaky-bin");
        invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--bin",
                "leaky",
                "--output",
                leaky.to_str().unwrap(),
            ],
        );
        let denied = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", leaky.to_str().unwrap()],
        );
        assert!(!denied.status.success());
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains("process"),
            "missing process-category diagnostic:\n{}",
            String::from_utf8_lossy(&denied.stderr)
        );
    }

    // Cargo may rewrite an unchanged executable during uplift. Its typed
    // compiler-artifact receipts expose freshness independently of file times.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn second_native_package_build_reuses_cargo_cache() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("pkg");
        create_package_fixture(directory.path());
        let workspace = native_workspace();
        let receipts = directory.path().join("cargo-receipts.jsonl");
        let cargo = directory.path().join("cargo");
        fs::write(
            &cargo,
            r#"#!/bin/sh
[ "$1" = rustc ] || exec "$PATINA_TEST_REAL_CARGO" "$@"
CARGO_LOG=cargo::core::compiler::fingerprint=info \
    "$PATINA_TEST_REAL_CARGO" "$@" > "$PATINA_TEST_CARGO_RECEIPTS" \
    2> "$PATINA_TEST_CARGO_RECEIPTS.log"
status=$?
cat "$PATINA_TEST_CARGO_RECEIPTS.log" >&2
cat "$PATINA_TEST_CARGO_RECEIPTS"
exit "$status"
"#,
        )
        .unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        let real_cargo = active_toolchain_binary("cargo");
        let envs = [
            ("CARGO", cargo.to_str().unwrap()),
            ("PATINA_TEST_REAL_CARGO", real_cargo.to_str().unwrap()),
            ("PATINA_TEST_CARGO_RECEIPTS", receipts.to_str().unwrap()),
        ];
        let package_text = package.to_str().unwrap();
        let plain = [
            "build",
            package_text,
            "--bin",
            "patina-native-pkg-fixture",
            "--release",
        ];
        let yielded = [
            "build",
            package_text,
            "--bin",
            "patina-native-pkg-fixture",
            "--release",
            "--yield-points",
        ];
        for flags in [&plain[..], &yielded[..]] {
            invoke_in_with_env(workspace, flags, &envs);
            invoke_in_with_env(workspace, flags, &envs);
            let artifacts = cargo_artifact_receipts(&receipts);
            // Cargo's own account of why a unit was dirty, for a failure.
            let log = fs::read_to_string(receipts.with_extension("jsonl.log")).unwrap_or_default();
            let reasons: Vec<_> = log.lines().filter(|line| line.contains("dirty")).collect();
            assert!(
                artifacts.iter().all(|row| row["fresh"] == true),
                "unchanged build ({flags:?}) recompiled guest artifacts: {artifacts:?}\n\
                 Cargo's fingerprint log: {reasons:#?}"
            );
        }

        // Positive control: a compiled guest-input change must fire this detector.
        let main = package.join("src/main.rs");
        fs::write(&main, "fn main() { println!(\"CACHE_REBUILD_PROBE\"); }\n").unwrap();
        invoke_in_with_env(workspace, &yielded, &envs);
        let artifacts = cargo_artifact_receipts(&receipts);
        assert!(
            artifacts.iter().any(|row| row["fresh"] == false),
            "rebuild detector did not fire: {artifacts:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn cargo_artifact_receipts(path: &Path) -> Vec<serde_json::Value> {
        let artifacts: Vec<_> = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["reason"] == "compiler-artifact")
            .collect();
        assert!(
            artifacts
                .iter()
                .any(|row| row["target"]["name"] == "patina-native-pkg-fixture"
                    && row["executable"].is_string()),
            "missing guest artifact receipt: {artifacts:?}"
        );
        assert!(
            artifacts.iter().all(|row| row["fresh"].is_boolean()),
            "artifact freshness must be typed: {artifacts:?}"
        );
        artifacts
    }

    // Regression for the SlateDB dogfooding feedback: a dependency that declares
    // `crate-type = ["rlib", "cdylib"]` (crc-fast 1.10.0 in the field report) makes
    // Cargo build BOTH crate types even though the guest links only the rlib, and
    // the cdylib runs a real link. The shim's link arguments must never reach it: on
    // x86_64 Linux that link is refused outright (`relocation R_X86_64_PC32 cannot
    // be used against symbol 'environ'`, from the shim's environment code), and on every
    // platform the whole deterministic shim is force-included into a shared object
    // nobody loads. Scoping the link arguments to `cargo rustc`'s trailing arguments
    // confines them to the guest's own final link.
    //
    // The load-bearing assertion is the shim-symbol one, which goes red on macOS and
    // Linux alike. The personality check is a realism guard — it keeps the
    // dependency a stand-in for crc-fast rather than a trivial arithmetic crate —
    // and is deliberately NOT claimed as the duplicate-symbol discriminator: a
    // dependency like this still links clean under `-fPIC`, so that rung of the
    // original report remains unreproduced synthetically (see
    // `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`). Exercised under
    // `--yield-points`, whose extra object travels the same path.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_build_package_keeps_shim_link_args_off_a_dependency_cdylib() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("cdylib-pkg");
        create_cdylib_dependency_package_fixture(directory.path());
        let workspace = native_workspace();

        let output = package.join("cdylib-dep-bin");
        let built = invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--yield-points",
                "--output",
                output.to_str().unwrap(),
            ],
        );
        assert!(
            String::from_utf8_lossy(&built.stdout).contains("PATINA_NATIVE_BUILD"),
            "missing build marker:\n{}",
            String::from_utf8_lossy(&built.stdout)
        );
        assert!(output.is_file());

        let cdylib = find_dependency_cdylib(&package.join("Cargo.toml"));
        let cdylib_bytes = fs::read(&cdylib).unwrap();
        assert!(
            contains_symbol(&cdylib_bytes, b"rust_eh_personality"),
            "{} does not reference the unwind personality, so it could not have hit \
         the duplicate-symbol failure this fixture pins; the dependency needs \
         real landing pads",
            cdylib.display()
        );
        for symbol in SHIM_LINK_MARKER_SYMBOLS {
            assert!(
                !contains_symbol(&cdylib_bytes, symbol),
                "shim symbol {} leaked into the dependency cdylib {}: the shim link \
             arguments are reaching more than the guest's final link",
                String::from_utf8_lossy(symbol),
                cdylib.display()
            );
        }

        // The same markers must still be in the guest binary: scoping the link args
        // must not have weakened interposition on the artifact that matters.
        let guest_bytes = fs::read(&output).unwrap();
        for symbol in SHIM_LINK_MARKER_SYMBOLS {
            assert!(
                contains_symbol(&guest_bytes, symbol),
                "shim symbol {} missing from the guest binary {}",
                String::from_utf8_lossy(symbol),
                output.display()
            );
        }

        let result = String::from_utf8_lossy(
            &invoke(workspace, &["run", output.to_str().unwrap(), "--seed", "1"]).stdout,
        )
        .into_owned();
        assert!(
            result.contains("NATIVE_CDYLIB_DEP_RESULT"),
            "missing result marker: {result}"
        );
    }

    /// Symbols that exist only because the shim's C object and staticlib were on a
    /// link line: the POSIX layer's constructor-retained `environ` accessor and the
    /// `--yield-points` hook.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SHIM_LINK_MARKER_SYMBOLS: &[&[u8]] = &[b"patina_environ_install", b"patina_yield_point"];

    /// Whether `image`'s symbol table names `symbol`. Symbol names are stored as
    /// plain NUL-terminated strings in both Mach-O and ELF string tables, so a byte
    /// search reads both without shelling out to `nm`/`objdump`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn contains_symbol(image: &[u8], symbol: &[u8]) -> bool {
        image.windows(symbol.len()).any(|window| window == symbol)
    }

    /// Locate the `cdylib-dep` shared library Cargo built alongside the guest.
    /// Cargo may place intermediates outside `target/` (the `build-dir` setting), so
    /// ask `cargo metadata` for both directories and search each.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_dependency_cdylib(manifest: &Path) -> std::path::PathBuf {
        let metadata = Command::new(env!("CARGO"))
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .arg("--manifest-path")
            .arg(manifest)
            .output()
            .unwrap();
        assert!(
            metadata.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&metadata.stderr)
        );
        let metadata = String::from_utf8_lossy(&metadata.stdout).into_owned();
        let roots: Vec<String> = ["target_directory", "build_directory"]
            .iter()
            .filter_map(|key| {
                let needle = format!("\"{key}\":\"");
                let start = metadata.find(&needle)? + needle.len();
                let rest = &metadata[start..];
                Some(rest[..rest.find('"')?].to_string())
            })
            .collect();
        assert!(
            !roots.is_empty(),
            "cargo metadata reported no build directories"
        );
        let mut found = Vec::new();
        for root in &roots {
            collect_files(Path::new(root), &mut found);
        }
        let mut cdylibs: Vec<std::path::PathBuf> = found
            .into_iter()
            .filter(|path| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with("libcdylib_dep")
                    && (name.ends_with(".so") || name.ends_with(".dylib"))
            })
            .collect();
        cdylibs.sort();
        assert!(
            !cdylibs.is_empty(),
            "no cdylib-dep shared library under {roots:?}; the dependency's cdylib \
         crate type was not built, so this fixture would pass vacuously"
        );
        cdylibs.remove(0)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn collect_files(directory: &Path, into: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, into);
            } else {
                into.push(path);
            }
        }
    }

    // The converse of the cache-hit test above: when the shim staticlib's BYTES
    // change, the guest must relink. Cargo fingerprints the link arguments, never
    // the files they name, so a guest that links a staticlib at an unchanging path
    // is reported fresh ("Finished in 0.01s") after a shim/runtime change and
    // `build` hands back a binary still linked against the PREVIOUS shim. The guest
    // links the copy `publish_native_shim` names by its bytes, so changed bytes are
    // a changed link argument.
    //
    // The assertion is the GUEST'S OWN OUTPUT, which is the one observable the
    // staleness under test cannot fake: the fixture calls `patina_relink_probe()`,
    // supplied by an extra archive member appended to this test's private copy of
    // the staticlib. Replacing that member with one returning a different value and
    // rebuilding must change what the guest prints. A stale binary keeps printing
    // the old value no matter what the build log says — build-output text and file
    // mtimes are exactly what a skipped link leaves untouched, so neither is
    // trusted here.
    //
    // `CARGO_TARGET_DIR` redirects the whole build into the tempdir so the doctored
    // staticlib is private to this test and the real workspace artifact is never
    // touched, and a stub `CARGO` skips the shim's own `cargo build -p
    // patina-dst-native-shim` (which would overwrite the doctored copy) while
    // forwarding every other Cargo invocation unchanged. Because the observable is
    // guest output rather than a rebuild count, a machine-global `build.build-dir`
    // redirect — the setting that hid this bug, since deleting the guest's local
    // `target/` no longer busts anything — cannot make this pass vacuously.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn changed_shim_staticlib_bytes_relink_the_guest() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

        let shim_target = directory.path().join("shim-target");
        let package = directory.path().join("probe-pkg");
        write_plain_package(
            &package,
            "patina-relink-probe-fixture",
            "unsafe extern \"C\" {\n    fn patina_relink_probe() -> u32;\n}\n\nfn main() {\n    \
         println!(\"RELINK_PROBE={}\", unsafe { patina_relink_probe() });\n}\n",
        );

        // Build once through cargo-patina so the private explicit CARGO_TARGET_DIR is
        // populated at the exact namespaced path `build_native_shim` selected. The
        // primer does not call the doctored symbol; only the later builds do.
        let primer = directory.path().join("primer-pkg");
        write_plain_package(
            &primer,
            "patina-relink-primer-fixture",
            "fn main() { println!(\"PRIMER\"); }\n",
        );
        let pristine = directory.path().join("pristine");
        let primed = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "build",
                primer.to_str().unwrap(),
                "--output",
                pristine.to_str().unwrap(),
            ],
            &[("CARGO_TARGET_DIR", shim_target.to_str().unwrap())],
        );
        assert!(
            primed.status.success(),
            "priming build failed with {}\nstdout:\n{}\nstderr:\n{}",
            primed.status,
            String::from_utf8_lossy(&primed.stdout),
            String::from_utf8_lossy(&primed.stderr)
        );
        let staticlib = find_private_shim_staticlib(&shim_target);
        // Cargo 1.98+ writes its artifacts read-only; `ar` rewrites an archive
        // through a temp file it then copies over the original, so the private copy
        // that gets doctored must be writable.
        fs::set_permissions(&staticlib, fs::Permissions::from_mode(0o644)).unwrap();

        // A `cargo` stub that no-ops the shim's own build (which would replace our
        // doctored archive with the pristine one) and forwards everything else.
        let stub = directory.path().join("cargo-stub.sh");
        fs::write(
            &stub,
            format!(
                "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \
             \"patina-dst-native-shim\" ]; then exit 0; fi\ndone\nexec {cargo} \"$@\"\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        let envs: &[(&str, &str)] = &[
            ("CARGO", stub.to_str().unwrap()),
            ("CARGO_TARGET_DIR", shim_target.to_str().unwrap()),
        ];
        let mut printed = Vec::new();
        for (generation, binary) in [(1u32, "gen1"), (2u32, "gen2")] {
            append_relink_probe(directory.path(), &staticlib, generation);
            let output = package.join(binary);
            let built = invoke_unchecked_clean_env(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "build",
                    package.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                ],
                envs,
            );
            assert!(
                built.status.success(),
                "generation {generation} build failed with {}\nstdout:\n{}\nstderr:\n{}",
                built.status,
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr)
            );
            let ran = invoke_unchecked_clean_env(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &["run", output.to_str().unwrap(), "--seed", "5"],
                envs,
            );
            assert!(
                ran.status.success(),
                "generation {generation} run failed with {}\nstderr:\n{}",
                ran.status,
                String::from_utf8_lossy(&ran.stderr)
            );
            let stdout = String::from_utf8_lossy(&ran.stdout).into_owned();
            printed.push(
                stdout
                    .lines()
                    .find(|line| line.starts_with("RELINK_PROBE="))
                    .unwrap_or_else(|| panic!("missing RELINK_PROBE in stdout:\n{stdout}"))
                    .to_owned(),
            );
        }

        assert_eq!(
            printed,
            vec!["RELINK_PROBE=1".to_owned(), "RELINK_PROBE=2".to_owned()],
            "the guest did not relink against the changed shim staticlib: it still runs code \
         from the previous archive, so a shim or runtime change silently produces a stale \
         binary"
        );
    }

    // Cargo owns the shim's `<profile>/libpatina_dst_native_shim.a` and republishes
    // it on every `cargo build`, fresh or not, wherever it copies instead of
    // hard-linking (always on macOS; on Linux when the build dir is on another
    // filesystem): remove, then stream a new copy in. Concurrent guest builds of the
    // same shim therefore linked a half-written archive (`ld: malformed archive`)
    // whenever another process's shim build landed inside their link. This pins
    // that interleaving deterministically: a `cargo` stub leaves the shim build
    // alone and, before every later Cargo invocation of the same `build`, replaces
    // Cargo's copy with its first 4 KiB, which is what a linker opening the path
    // mid-copy reads.
    //
    // Class pairing: a link input must never be read through a path another process
    // can rewrite. Every shim link input is published immutably under a name derived
    // from its content (`stage_shim_object`, `publish_native_shim`), and
    // `changed_shim_staticlib_bytes_relink_the_guest` holds the converse, that
    // changed bytes still relink.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn guest_link_is_immune_to_cargo_rewriting_its_shim_copy() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let shim_target = directory.path().join("shim-target");
        let package = directory.path().join("guest-pkg");
        write_plain_package(
            &package,
            "patina-shim-rewrite-fixture",
            "fn main() { println!(\"LINKED_AGAINST_WHOLE_SHIM\"); }\n",
        );

        let rewrites = directory.path().join("rewrites.log");
        let stub = directory.path().join("cargo-stub.sh");
        fs::write(
        &stub,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"patina-dst-native-shim\" ]; then \
             exec {cargo} \"$@\"; fi\ndone\nfor archive in $(find {target} -name \
             libpatina_dst_native_shim.a); do\n  head -c 4096 \"$archive\" > \"$archive.torn\"\n  \
             mv -f \"$archive.torn\" \"$archive\"\n  echo \"$archive\" >> {rewrites}\ndone\nexec \
             {cargo} \"$@\"\n",
            target = shim_target.join("patina-native-shim/builds").display(),
            rewrites = rewrites.display(),
        ),
    )
    .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        let envs: &[(&str, &str)] = &[
            ("CARGO", stub.to_str().unwrap()),
            ("CARGO_TARGET_DIR", shim_target.to_str().unwrap()),
        ];

        let output = package.join("guest");
        let built = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ],
            envs,
        );
        assert!(
            built.status.success(),
            "the guest build read Cargo's rewritten shim copy instead of an immutable one: {}\n\
         stdout:\n{}\nstderr:\n{}",
            built.status,
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr)
        );
        let rewritten = fs::read_to_string(&rewrites).unwrap_or_default();
        assert!(
            !rewritten.is_empty(),
            "the stub never rewrote Cargo's shim copy after the shim build, so the link was not \
         exposed to a rewrite"
        );
        let ran = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", output.to_str().unwrap(), "--seed", "5"],
            &[],
        );
        let stdout = String::from_utf8_lossy(&ran.stdout);
        assert!(
            ran.status.success() && stdout.contains("LINKED_AGAINST_WHOLE_SHIM"),
            "the guest linked during the rewrite did not run: {}\nstdout:\n{stdout}\nstderr:\n{}",
            ran.status,
            String::from_utf8_lossy(&ran.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_private_shim_staticlib(target_base: &Path) -> PathBuf {
        let mut files = Vec::new();
        // Mutate only Cargo scratch, never the immutable published link inputs.
        collect_files(&target_base.join("patina-native-shim/builds"), &mut files);
        let mut staticlibs: Vec<_> = files
            .into_iter()
            .filter(|path| {
                path.file_name() == Some(std::ffi::OsStr::new("libpatina_dst_native_shim.a"))
            })
            .collect();
        staticlibs.sort();
        assert_eq!(
            staticlibs.len(),
            1,
            "expected exactly one private shim staticlib under {}, found {staticlibs:?}",
            target_base.display()
        );
        staticlibs.remove(0)
    }

    // Append (or replace) an archive member defining `patina_relink_probe`, so the
    // staticlib's bytes differ per generation AND the difference is visible in the
    // linked guest: the fixture calls the probe, so the linker must pull this member
    // in and the returned value reaches the guest's stdout.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn append_relink_probe(scratch: &Path, staticlib: &Path, generation: u32) {
        let source = scratch.join("patina_relink_probe.c");
        fs::write(
            &source,
            format!("unsigned patina_relink_probe(void) {{ return {generation}u; }}\n"),
        )
        .unwrap();
        let object = scratch.join("patina_relink_probe.o");
        let cc = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let compiled = Command::new(&cc)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "compiling the relink probe failed:\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let archived = Command::new("ar")
            .arg("rcs")
            .arg(staticlib)
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            archived.status.success(),
            "adding the relink probe to the staticlib failed:\n{}",
            String::from_utf8_lossy(&archived.stderr)
        );
    }

    /// A concurrent cargo-patina build caught mid-uplift: it holds `dir`'s build
    /// lock and its Cargo has put back only a prefix of `artifact`. Dropping it
    /// finishes the uplift and releases the lock.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct TornUplift {
        artifact: PathBuf,
        whole: PathBuf,
        _lock: fs::File,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl TornUplift {
        /// Start one, unless a build already holds `dir`'s lock — a concurrent build
        /// would wait for it rather than uplift.
        fn begin(dir: &Path, artifact: &Path) -> Option<Self> {
            use std::os::fd::AsRawFd;
            const LOCK_EX: i32 = 2;
            const LOCK_NB: i32 = 4;
            unsafe extern "C" {
                fn flock(fd: i32, operation: i32) -> i32;
            }
            let lock = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(dir.join(".patina-build.lock"))
                .unwrap();
            // SAFETY: `flock` only reads the descriptor, which `lock` keeps open.
            if unsafe { flock(lock.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock,
                    "flock in {}: {error}",
                    dir.display()
                );
                return None;
            }
            let mut whole = artifact.as_os_str().to_owned();
            whole.push(".whole");
            let whole = PathBuf::from(whole);
            fs::rename(artifact, &whole).unwrap();
            let bytes = fs::read(&whole).unwrap();
            fs::write(artifact, &bytes[..bytes.len() / 2]).unwrap();
            Some(Self {
                artifact: artifact.to_path_buf(),
                whole,
                _lock: lock,
            })
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for TornUplift {
        fn drop(&mut self) {
            let finished = fs::rename(&self.whole, &self.artifact);
            if !std::thread::panicking() {
                finished.unwrap();
            }
        }
    }

    // Cargo rewrites every output in its target dir on every invocation, fresh or
    // not, wherever it copies rather than hard-links (always on macOS; on Linux when
    // the build dir is on another filesystem): for a moment the path holds only a
    // prefix. `build --output` copies the guest executable out AFTER its Cargo has
    // exited, so a concurrent build of the same package in the same target dir
    // could hand it a truncated binary — every generation of a campaign over that
    // guest then classified INFRA, and `campaign_extend_equals_fresh_campaign` lost
    // its NOVEL line. This forces the window: a stand-in Cargo pauses the build
    // between the executable's uplift and the copy-out, and the test plays a
    // concurrent build mid-uplift whenever the target dir's lock allows one.
    //
    // Class pairing: every build that reads a Cargo output back (native package,
    // native harness, WASI, and the shim publish that
    // `guest_link_is_immune_to_cargo_rewriting_its_shim_copy` pins) holds
    // `lock_target_dir` from before its Cargo invocation through the read.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn guest_copy_out_is_immune_to_a_concurrent_uplift() {
        use std::io::{BufRead, BufReader};

        let directory = tempdir().unwrap();
        let sync = directory.path();
        let bin = "patina-uplift-race-fixture";
        let package = sync.join("guest");
        write_plain_package(&package, bin, "fn main() {}\n");
        let target = common::guest_target_dir("uplift-race");
        for fifo in ["to-test", "to-cargo"] {
            let made = Command::new("mkfifo")
                .arg(sync.join(fifo))
                .status()
                .unwrap();
            assert!(made.success(), "mkfifo {fifo} failed");
        }
        let cargo = sync.join("cargo");
        // The shim and guest both use cargo rustc. Pause the selected guest
        // binary only, after its successful uplift, rather than a Cargo verb.
        fs::write(
            &cargo,
            format!(
                "#!/bin/sh\n\
             real=\"{real}\"\n\
             guest=0; previous=\"\"\n\
             for arg do\n\
               if [ \"$previous\" = --bin ] && [ \"$arg\" = \"{bin}\" ]; then guest=1; fi\n\
               previous=\"$arg\"\n\
             done\n\
             [ \"$guest\" = 1 ] || exec \"$real\" \"$@\"\n\
             \"$real\" \"$@\"; status=$?\n\
             [ \"$status\" = 0 ] || exit \"$status\"\n\
             echo uplifted > \"{sync}/to-test\"; read _ < \"{sync}/to-cargo\"\n\
             exit $status\n",
                real = active_toolchain_binary("cargo").display(),
                sync = sync.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();

        // Both FIFOs are held open read-write, so no open on either side blocks.
        let fifo = |name: &str| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(sync.join(name))
                .unwrap()
        };
        let mut to_test = BufReader::new(fifo("to-test"));
        let mut to_cargo = fifo("to-cargo");
        let output_path = sync.join("built");
        let child = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(&package)
            .args([
                "build",
                package.to_str().unwrap(),
                "--output",
                output_path.to_str().unwrap(),
            ])
            .env("RUSTC", active_toolchain_binary("rustc"))
            .env("CARGO", &cargo)
            .env("CARGO_TARGET_DIR", &target)
            .env_remove("RUSTUP_TOOLCHAIN")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A build that exits before the pause must not leave the test waiting.
        let exited = fifo("to-test");
        let build = std::thread::spawn(move || {
            let output = child.wait_with_output().unwrap();
            writeln!(&exited, "exited").unwrap();
            output
        });
        let mut line = String::new();
        to_test.read_line(&mut line).unwrap();
        let report = |output: &Output| {
            format!(
                "exit {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        };
        assert_eq!(
            line.trim_end(),
            "uplifted",
            "the build never finished its guest Cargo run: {}",
            report(&build.join().unwrap())
        );
        let executable = fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().path().join("debug").join(bin))
            .find(|path| path.is_file())
            .expect("the guest Cargo run uplifted no executable");
        let torn = TornUplift::begin(&target, &executable);
        writeln!(to_cargo, "go").unwrap();
        let built = build.join().unwrap();
        drop(torn);

        assert!(
            built.status.success(),
            "the build failed: {}",
            report(&built)
        );
        assert!(
            fs::read(&output_path).unwrap() == fs::read(&executable).unwrap(),
            "the build copied out a torn executable"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn package_result(output: &Output) -> String {
        let stdout = String::from_utf8(output.stdout.clone()).unwrap();
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("NATIVE_PKG_RESULT")),
            "missing package result: {stdout}"
        );
        // Compare the entire stream, not just the summary: extra nondeterministic
        // output must fail the package's seed/record/replay checks too.
        stdout
    }

    // Build a self-contained fixture: an ordinary-`std` package with a path
    // dependency (`greeter`), a build script (whose output the binary reads back,
    // and whose host-side file I/O proves the shim link args do not leak onto build
    // scripts), a clean binary that audits and replays, and a second binary that
    // imports an off-allowlist process symbol.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn create_package_fixture(root: &Path) {
        let greeter = root.join("greeter");
        fs::create_dir_all(greeter.join("src")).unwrap();
        fs::write(
            greeter.join("Cargo.toml"),
            "[package]\nname = \"greeter\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            greeter.join("src/lib.rs"),
            "pub fn greeting() -> String {\n    format!(\"hello from {}\", \"greeter\")\n}\n",
        )
        .unwrap();

        let package = root.join("pkg");
        fs::create_dir_all(package.join("src/bin")).unwrap();
        fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"patina-native-pkg-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ngreeter = { path = \"../greeter\" }\n",
    )
    .unwrap();
        fs::write(
            package.join("build.rs"),
            r#"fn main() {
    // Runs on the host. If the shim link args leaked onto this build script, its
    // file I/O would route into an uninitialized Patina runtime and abort; the
    // explicit host --target keeps them off host artifacts.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::fs::read(std::path::Path::new(&manifest).join("Cargo.toml")).unwrap();
    println!("cargo:rustc-env=PKG_BUILT=1");
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
        )
        .unwrap();
        fs::write(
            package.join("src/main.rs"),
            r#"use std::hash::{BuildHasher, Hasher};

fn main() {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(greeter::greeting().as_bytes());
    let hash = hasher.finish();
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", greeter::greeting().as_bytes()).unwrap();
    let stored = std::fs::read_to_string("/state/value").unwrap();
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_PKG_RESULT built={} hash={hash:016x} stored={stored}",
        env!("PKG_BUILT")
    );
}
"#,
        )
        .unwrap();
        fs::write(
            package.join("src/bin/leaky.rs"),
            r#"// Imports an uninterposed process-class libc symbol (`system`) that the native
// audit denies as "process". The spawn family (fork/posix_spawn*/...) is
// shim-defined deny-traps and `kill` a deterministic-model interposer, so a
// `Command::spawn` — or a `kill` — would
// leave no process *import* to flag; this reaches for a still-uninterposed member
// of the class instead. Taking its address forces the undefined import. Building
// succeeds; the audit must reject the product with the "process" category.
unsafe extern "C" {
    fn system(command: *const u8) -> i32;
}
fn main() {
    let reached = system as *const ();
    std::process::exit((reached as usize & 1) as i32);
}
"#,
        )
        .unwrap();
    }

    /// A package depending on a local path crate whose `[lib]` declares
    /// `crate-type = ["rlib", "cdylib"]` — the shape that made crc-fast 1.10.0 fail
    /// the native shim link on Linux (see
    /// `native_build_package_keeps_shim_link_args_off_a_dependency_cdylib`). No
    /// external dependency is needed to reproduce the shape: Cargo builds every
    /// declared crate type for a path dependency regardless of which one the
    /// depender actually links against, so the dependency's own `cdylib` link always
    /// runs alongside the guest build.
    ///
    /// The dependency's exported functions allocate, format, and catch a panic so
    /// the cdylib has genuine cleanup landing pads and a live `rust_eh_personality`
    /// reference — keeping it a realistic stand-in for crc-fast instead of a trivial
    /// arithmetic crate. That is a realism guard, not the trigger for the
    /// duplicate-symbol rung of the original report: measured on x86_64 Linux, a
    /// dependency shaped exactly like this still links clean once the shim objects
    /// are `-fPIC`.
    fn create_cdylib_dependency_package_fixture(root: &Path) {
        let dependency = root.join("cdylib-dep");
        fs::create_dir_all(dependency.join("src")).unwrap();
        fs::write(
        dependency.join("Cargo.toml"),
        "[package]\nname = \"cdylib-dep\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"rlib\", \"cdylib\"]\n",
    )
    .unwrap();
        fs::write(
            dependency.join("src/lib.rs"),
            r#"use std::panic::{self, AssertUnwindSafe};

/// Exported from the cdylib (so it survives dead-stripping) and full of
/// unwinding cleanup: the `String`s need drop glue on the unwind path and
/// `catch_unwind` pulls in the personality routine directly.
#[unsafe(no_mangle)]
pub extern "C" fn cdylib_dep_landing_pads(count: u32) -> u32 {
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut rendered = String::new();
        for index in 0..count {
            rendered.push_str(&format!("{index},"));
            if index == u32::MAX {
                panic!("unreachable, but the compiler cannot prove it");
            }
        }
        rendered.len() as u32
    }));
    caught.unwrap_or(0)
}

pub fn checksum(bytes: &[u8]) -> u32 {
    let seed = cdylib_dep_landing_pads(bytes.len() as u32);
    bytes
        .iter()
        .fold(seed, |acc, byte| acc.wrapping_mul(31).wrapping_add(u32::from(*byte)))
}
"#,
        )
        .unwrap();

        let package = root.join("cdylib-pkg");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"patina-native-cdylib-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ncdylib-dep = { path = \"../cdylib-dep\" }\n",
    )
    .unwrap();
        fs::write(
            package.join("src/main.rs"),
            r#"fn main() {
    let checksum = cdylib_dep::checksum(b"patina");
    println!("NATIVE_CDYLIB_DEP_RESULT checksum={checksum}");
}
"#,
        )
        .unwrap();
    }
}
