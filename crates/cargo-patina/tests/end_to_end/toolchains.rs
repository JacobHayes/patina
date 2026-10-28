//! Guest compiler identity, toolchain selection, and proxy/path handling.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A native build links the shim staticlib, always built in the unpacked shim
    // source cache, into a guest built in the caller's working directory. Under rustup
    // those two directories can resolve DIFFERENT toolchains, and then two Rust
    // standard libraries meet at the guest link: a `duplicate symbol:
    // rust_eh_personality` error on Linux and — as this fixture showed before the
    // detector — a SILENT success on macOS, producing a guest carrying two libstds.
    // The split is staged hermetically: a proxy reports an identity its concrete
    // sysroot compiler cannot reproduce. The propagation gate above the link must
    // refuse it. The hostile-proxy success test is the class-level pairing.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_unverifiable_guest_compiler_is_refused_before_the_link() {
        let directory = tempdir().unwrap();

        // A proxy claims a guest identity that its sysroot cannot reproduce.
        let stub = directory.path().join("rustc-split.sh");
        fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = -vV ]; then \"{}\" -vV \
             | sed '1s/.*/rustc 9.9.9-patina-split-stub (0000000 2000-01-01)/'; exit 0; fi\n\
             exec \"{}\" \"$@\"\n",
                active_toolchain_binary("rustc").display(),
                active_toolchain_binary("rustc").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        let package = directory.path().join("guest-pkg");
        write_plain_package(
            &package,
            "patina-toolchain-split-fixture",
            "fn main() { println!(\"TOOLCHAIN_SPLIT_FIXTURE_OK\"); }\n",
        );
        let split_output = package.join("split-build");

        // Split: the shim half and the guest half resolve different compilers.
        let refused = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &package,
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                split_output.to_str().unwrap(),
            ],
            &[("RUSTC", stub.to_str().unwrap())],
        );
        let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert!(
            !refused.status.success(),
            "a split shim/guest toolchain built without complaint (exit {}); the guest links two \
         libstds\nstdout:\n{}\nstderr:\n{stderr}",
            refused.status,
            String::from_utf8_lossy(&refused.stdout)
        );
        // The refusal must NAME both toolchains, where each resolved, and the fix —
        // a bare failure would leave the operator with the same confusing link error.
        for expected in [
            "refusing to build",
            "two different rustc toolchains",
            "9.9.9-patina-split-stub",
            "shim toolchain:",
            "guest toolchain:",
            "No ambient fallback",
            "absolute, matching RUSTC and CARGO binaries from one toolchain",
        ] {
            assert!(
                stderr.contains(expected),
                "refusal did not mention {expected:?}:\n{stderr}"
            );
        }
        // Verification already fails in the guest directory; name that physical
        // directory rather than claiming a cache-directory probe ran.
        let package_physical = fs::canonicalize(&package).unwrap();
        assert!(
            stderr.contains(&package_physical.display().to_string()),
            "refusal did not name the guest directory {}:\n{stderr}",
            package_physical.display()
        );
        assert!(
            !split_output.exists(),
            "the refusal produced a binary at {}; it must refuse BEFORE the link",
            split_output.display()
        );
    }

    // Class-level detector: per-directory selectors must never be re-entered after
    // materializing the guest compiler. Both ambient tools are hostile in the cache.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_no_bundle_toolchain_pin(cache: &Path) {
        let mut bundles = 0;
        for entry in fs::read_dir(cache).unwrap() {
            let bundle = entry.unwrap().path();
            if bundle.is_dir() {
                bundles += 1;
                for pin in [
                    "rust-toolchain",
                    "rust-toolchain.toml",
                    "mise.toml",
                    ".mise.toml",
                    ".cargo",
                ] {
                    assert!(
                        !bundle.join(pin).exists(),
                        "mutable pin in {}",
                        bundle.display()
                    );
                }
            }
        }
        assert!(bundles > 0, "no extracted bundles were inspected");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_hostile_per_directory_proxy_builds_with_the_guest_compiler() {
        let directory = tempdir().unwrap();
        let shim_sources = shim_source_cache();
        let real_rustc = active_toolchain_binary("rustc");
        let real_cargo = active_toolchain_binary("cargo");

        let proxy_dir = directory.path().join("proxy-bin");
        fs::create_dir_all(&proxy_dir).unwrap();
        let rustc_proxy = proxy_dir.join("rustc");
        fs::write(
            &rustc_proxy,
            format!(
                "#!/bin/sh\ncase \"$(pwd -P)\" in\n  \"{}\"/*)\n    \
             echo HOSTILE_SHIM_RUSTC_USED >&2; exit 99;;\nesac\nexec \"{}\" \"$@\"\n",
                fs::canonicalize(&shim_sources).unwrap().display(),
                real_rustc.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&rustc_proxy, fs::Permissions::from_mode(0o755)).unwrap();

        let package = directory.path().join("mise-like-guest");
        write_plain_package(
            &package,
            "patina-toolchain-mise-like-fixture",
            "fn main() { println!(\"TOOLCHAIN_MISE_LIKE_FIXTURE_OK\"); }\n",
        );
        let cargo_proxy = proxy_dir.join("cargo");
        fs::write(
            &cargo_proxy,
            "#!/bin/sh\necho HOSTILE_PATH_CARGO_USED >&2\nexit 99\n",
        )
        .unwrap();
        fs::set_permissions(&cargo_proxy, fs::Permissions::from_mode(0o755)).unwrap();
        let propagated_output = package.join("propagated-build");
        let aligned_output = package.join("aligned-build");
        let path = format!(
            "{}:{}",
            proxy_dir.display(),
            env::var_os("PATH").unwrap_or_default().to_string_lossy()
        );

        let built = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(&package)
            .args([
                "build",
                package.to_str().unwrap(),
                "--output",
                propagated_output.to_str().unwrap(),
            ])
            .env("PATH", &path)
            .env("RUSTUP_TOOLCHAIN", "1.96.1")
            .env_remove("RUSTC")
            .env_remove("CARGO")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&built.stderr).into_owned();
        assert!(
            built.status.success(),
            "a Mise-like proxy guest failed to build (exit {})\nstdout:\n{}\nstderr:\n{stderr}",
            built.status,
            String::from_utf8_lossy(&built.stdout)
        );
        assert!(propagated_output.is_file());
        assert_no_bundle_toolchain_pin(&shim_sources);

        // From here on, PATH is hostile: the aligned build must use the RUSTC/CARGO
        // values below for every compiler probe and Cargo child. If any later step
        // falls back to PATH, this test fails instead of passing vacuously. The
        // values are relative to the guest's directory, so they work only if they
        // are anchored before the shim build changes directory.
        fs::write(
            &rustc_proxy,
            "#!/bin/sh\necho HOSTILE_PATH_RUSTC_USED \"$@\" >&2\nexit 99\n",
        )
        .unwrap();
        let tools = package.join("tools");
        fs::create_dir_all(&tools).unwrap();
        for (name, real) in [("rustc", &real_rustc), ("cargo", &real_cargo)] {
            let wrapper = tools.join(name);
            fs::write(
                &wrapper,
                format!("#!/bin/sh\nexec \"{}\" \"$@\"\n", real.display()),
            )
            .unwrap();
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let aligned = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(&package)
            .args([
                "build",
                package.to_str().unwrap(),
                "--output",
                aligned_output.to_str().unwrap(),
            ])
            .env("PATH", &path)
            .env("RUSTUP_TOOLCHAIN", "1.96.1")
            .env("RUSTC", "./tools/rustc")
            .env("CARGO", "./tools/cargo")
            .output()
            .unwrap();
        assert!(
            aligned.status.success(),
            "relative, matching RUSTC/CARGO were refused (exit {})\nstdout:\n{}\nstderr:\n{}",
            aligned.status,
            String::from_utf8_lossy(&aligned.stdout),
            String::from_utf8_lossy(&aligned.stderr)
        );
        assert!(
            aligned_output.is_file(),
            "the aligned build produced no binary at {}",
            aligned_output.display()
        );
    }

    // Refusal matrix paired with the hostile-proxy propagation detector. Every
    // planted failure must stop before Cargo or the link, naming a concrete remedy.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unmaterializable_guest_toolchains_refuse_without_fallback() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("guest");
        write_plain_package(&package, "unmaterializable-guest", "fn main() {}\n");
        let real = active_toolchain_binary("rustc");
        let fake_root = directory.path().join("sysroot");
        fs::create_dir_all(fake_root.join("bin")).unwrap();
        let fake_rustc = fake_root.join("bin/rustc");
        fs::write(&fake_rustc, format!(
        "#!/bin/sh\ncase \"$(pwd -P)\" in \"{}\"/*) echo rustc-SHIM-VERIFICATION-MISMATCH; exit 0;; esac\nexec \"{}\" \"$@\"\n",
        fs::canonicalize(shim_source_cache()).unwrap().display(), real.display()
    )).unwrap();
        fs::set_permissions(&fake_rustc, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            fake_root.join("bin/cargo"),
            "#!/bin/sh\necho CARGO_MUST_NOT_RUN >&2\nexit 98\n",
        )
        .unwrap();
        fs::set_permissions(
            fake_root.join("bin/cargo"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let cases = [
            (
                "query",
                "echo GUEST_QUERY_FAILED >&2; exit 91".to_owned(),
                "GUEST_QUERY_FAILED",
            ),
            (
                "sysroot-query",
                "if [ \"$1\" = --print ]; then echo NO_SYSROOT >&2; exit 92; fi".to_owned(),
                "NO_SYSROOT",
            ),
            (
                "empty-sysroot",
                "if [ \"$1\" = --print ]; then exit 0; fi".to_owned(),
                "sysroot is not an absolute path",
            ),
            (
                "missing-binaries",
                format!(
                    "if [ \"$1\" = --print ]; then echo '{}'; exit 0; fi",
                    directory.path().join("missing").display()
                ),
                "missing bin/rustc or bin/cargo",
            ),
            (
                "shim-verification",
                format!(
                    "if [ \"$1\" = --print ]; then echo '{}'; exit 0; fi",
                    fake_root.display()
                ),
                "rustc-SHIM-VERIFICATION-MISMATCH",
            ),
        ];
        for (name, body, expected) in cases {
            let proxy = directory.path().join(name);
            fs::write(
                &proxy,
                format!("#!/bin/sh\n{body}\nexec \"{}\" \"$@\"\n", real.display()),
            )
            .unwrap();
            fs::set_permissions(&proxy, fs::Permissions::from_mode(0o755)).unwrap();
            let output = package.join("must-not-exist");
            let refused = invoke_unchecked_clean_env(
                env!("CARGO_BIN_EXE_cargo-patina"),
                &package,
                &[
                    "build",
                    package.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                ],
                &[("RUSTC", proxy.to_str().unwrap())],
            );
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(!refused.status.success(), "{name} built unexpectedly");
            for text in [
                "refusing to build",
                expected,
                "absolute, matching RUSTC and CARGO binaries from one toolchain",
            ] {
                assert!(stderr.contains(text), "{name}: missing {text:?}: {stderr}");
            }
            assert!(!stderr.contains("CARGO_MUST_NOT_RUN"), "{stderr}");
            assert!(!output.exists());
            eprintln!("{name}: refused before link ({expected})");
        }
        assert_no_bundle_toolchain_pin(&shim_source_cache());
    }

    /// Where the CLI unpacks its embedded shim source bundle and builds the shim:
    /// `<cache root>/patina/shim-src`, with the cache root resolved exactly as the
    /// CLI resolves it (`XDG_CACHE_HOME`, else the platform's per-user cache under
    /// `HOME`). Created here so a caller can canonicalize it before the CLI's first
    /// unpack.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn shim_source_cache() -> PathBuf {
        let root = match env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
            Some(xdg) => PathBuf::from(xdg),
            None => {
                let home = PathBuf::from(env::var_os("HOME").expect("HOME is set"));
                if cfg!(target_os = "macos") {
                    home.join("Library").join("Caches")
                } else {
                    home.join(".cache")
                }
            }
        };
        let dir = root.join("patina").join("shim-src");
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
