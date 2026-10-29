//! Native audit boundaries, import provenance, and host-identity findings.

#[cfg(test)]
mod tests {
    use super::super::*;

    // The audit's import lines, excluding the build-on-the-fly identity note.
    fn audit_imports(output: &Output) -> Vec<String> {
        let mut imports: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.starts_with("PATINA_"))
            .map(str::to_string)
            .collect();
        imports.sort();
        imports
    }

    // Real toolchain shapes paired with code_ranges::tests' synthetic class
    // detectors. The control main actually calls the untyped/CFI-less entry.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn native_audit_refuses_untyped_and_fdeless_entries() {
        use object::{Object, ObjectSymbol};
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("main.c"), "extern unsigned long sized(void); extern unsigned long hidden(void);\nint main(void) { sized(); hidden(); return 0; }\n").unwrap();
        // ET_REL must be a named input refusal, not merely an incidental unwind
        // relocation failure. Exercise both ordinary and no-unwind object files.
        for unwind in [
            "-fasynchronous-unwind-tables",
            "-fno-asynchronous-unwind-tables",
        ] {
            let object = root.join("guest.o");
            let compiled = Command::new("cc")
                .args(["-c", unwind])
                .arg(root.join("main.c"))
                .arg("-o")
                .arg(&object)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let audit = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                root,
                &["audit", object.to_str().unwrap(), "--raw"],
            );
            assert_eq!(audit.status.code(), Some(2));
            assert!(
                String::from_utf8_lossy(&audit.stderr).contains("relocatable ELF (ET_REL)"),
                "{}",
                String::from_utf8_lossy(&audit.stderr)
            );
        }
        let sized = ".text\n.globl sized\n.type sized,@function\nsized:\nxor %eax,%eax\nret\n.size sized,.-sized\n";
        let cases = [
            (
                "gap",
                ".globl hidden\nhidden:\nrdrand %rax\nret\n",
                false,
                true,
            ),
            (
                "operand",
                ".globl carrier\n.type carrier,@function\ncarrier:\n.byte 0x48,0xb8\n.globl hidden\nhidden:\n.byte 0x48,0x0f,0xc7,0xf0,0xc3,0x90,0x90,0x90\nret\n.size carrier,.-carrier\n",
                false,
                true,
            ),
            (
                "fdeless",
                ".globl hidden\n.type hidden,@function\nhidden:\nrdrand %rax\nret\n.size hidden,.-hidden\n",
                true,
                true,
            ),
            (
                "bounded",
                ".globl carrier\n.type carrier,@function\ncarrier:\nxor %eax,%eax\n.globl hidden\nhidden:\nret\n.size carrier,.-carrier\n.asciz \"OGAMS\"\n",
                false,
                false,
            ),
        ];
        for (name, body, stripped, denied) in cases {
            let asm = root.join(format!("{name}.s"));
            fs::write(
                &asm,
                format!("{sized}{body}\n.section .note.GNU-stack,\"\",@progbits\n"),
            )
            .unwrap();
            let binary = root.join(name);
            let compiled = Command::new("cc")
                .arg("-fno-asynchronous-unwind-tables")
                .arg(root.join("main.c"))
                .arg(&asm)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            if stripped {
                let bytes = fs::read(&binary).unwrap();
                let file = object::File::parse(&*bytes).unwrap();
                assert!(
                    file.symbols()
                        .any(|s| s.name() == Ok("hidden") && s.size() > 0)
                );
                let status = Command::new("strip")
                    .arg("--strip-all")
                    .arg(&binary)
                    .status()
                    .unwrap();
                assert!(status.success());
                let bytes = fs::read(&binary).unwrap();
                let file = object::File::parse(&*bytes).unwrap();
                assert!(file.symbols().next().is_none());
                assert!(
                    file.section_by_name(".eh_frame").is_some(),
                    "must retain crt FDEs"
                );
            }
            // Prove the planted entry is executed in the native control, when this
            // host implements RDRAND. Static refusal remains unconditional.
            if !denied || std::is_x86_feature_detected!("rdrand") {
                assert!(
                    Command::new(&binary).status().unwrap().success(),
                    "native control {name}"
                );
            }
            let audit = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                root,
                &[
                    "audit",
                    binary.to_str().unwrap(),
                    "--raw",
                    "--format",
                    "json",
                ],
            );
            assert_eq!(
                audit.status.code(),
                Some(if denied { 2 } else { 0 }),
                "{name}: {}",
                String::from_utf8_lossy(&audit.stderr)
            );
            if denied {
                let result: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
                assert!(
                    result["finding_details"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|f| f["mnemonic"] == "rdrand"),
                    "{name}: {result}"
                );
            }
        }
    }

    // Class-level detector for source-first audit metadata loss: exercise each
    // final-link path with stripping requested, not just command-line flag spelling.
    // The untyped ret label must not make its containing function absorb the data.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn native_source_builds_preserve_auditable_code_boundaries() {
        use object::{Object, ObjectSymbol, SymbolKind};
        fn assert_boundaries(path: &Path) {
            let bytes = fs::read(path).unwrap();
            let file = object::File::parse(&*bytes).unwrap();
            assert!(
                file.symbols().any(|s| s.kind() == SymbolKind::Text
                    && s.size() > 0
                    && s.name() == Ok("audit_probe")),
                "missing sized audit symbol in {}",
                path.display()
            );
        }
        let directory = tempdir().unwrap();
        let root = directory.path();
        let source = r##"
core::arch::global_asm!(r#"
.pushsection .text.audit_probe,"ax",@progbits
.globl audit_probe
.type audit_probe,@function
audit_probe:
    mov $42, %eax
.globl audit_probe_ret
audit_probe_ret:
    ret
.size audit_probe, .-audit_probe
.asciz "OGAMS"
.popsection
"#, options(att_syntax));
unsafe extern "C" { fn audit_probe() -> u32; }
fn main() { assert_eq!(unsafe { audit_probe() }, 42); println!("BOUNDARIES_OK"); }
#[test] fn boundaries() { main(); }
"##;
        // Keep the fixture source independent of the checkout and its build outputs.
        let single = root.join("single.rs");
        fs::write(&single, source).unwrap();
        let binary = root.join("single");
        invoke(
            root,
            &[
                "build",
                single.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
                "--",
                "-C",
                "strip=symbols",
            ],
        );
        assert_boundaries(&binary);
        invoke(root, &["audit", binary.to_str().unwrap()]);
        invoke(root, &["run", binary.to_str().unwrap(), "--seed", "1"]);

        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), source).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"audit_boundaries\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[profile.dev]\nstrip = true\n[profile.release]\nstrip = \"symbols\"\n").unwrap();
        let binary = root.join("package-guest");
        invoke(root, &["build", ".", "--output", binary.to_str().unwrap()]);
        assert_boundaries(&binary);
        invoke(root, &["audit", binary.to_str().unwrap()]);
        invoke(root, &["audit", "."]);
        invoke(root, &["run", "."]);
        invoke(
            root,
            &[
                "test",
                ".",
                "--harness-target",
                "audit_boundaries",
                "--exact",
                "boundaries",
                "--seed",
                "1",
            ],
        );
        let guest = fixture_target_directory(root)
            .join("patina/dst/audit_boundaries/bin/audit_boundaries/boundaries/guest");
        assert_boundaries(&guest);
        invoke(root, &["audit", guest.to_str().unwrap()]);
    }

    // A single `.rs` source is first-class for `run`, `audit` and `replay`.
    // `run <SOURCE.rs>` builds native on the fly and matches an explicit `build`
    // + `run`, printing a one-line identity note so an implicit build is never
    // silent. Auditing the source equals auditing the built artifact, and both
    // pass with no `--allow`: the shim's `dlsym` control-plane vehicle, which
    // the pre-run gate permits, is not reported as a dynamic-loading denial,
    // and a Patina-built binary audits without the raw-audit banner. Replaying
    // the unchanged source reproduces a recording of the artifact; after a
    // behaviour-changing edit, source-first replay fails closed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_source_is_first_class_for_run_audit_and_replay() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("sf.rs");
        // The guest reads the virtual clock (a recorded boundary decision) so a
        // behaviour-changing edit alters the op-stream and replay can fail closed:
        // stdout alone is captured output, not a replay-checked decision.
        fs::write(
            &source,
            "use std::time::Instant; \
             fn main() { let s = Instant::now(); let _ = s.elapsed(); \
             let a: Vec<String> = std::env::args().skip(1).collect(); \
             println!(\"SF_MARKER v1 args={a:?}\"); }",
        )
        .unwrap();
        let bin = directory.path().join("sf");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let artifact_audit = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        let audit_out = String::from_utf8_lossy(&artifact_audit.stdout);
        assert!(
            !audit_out.contains("dynamic-loading") && !audit_out.contains("PATINA_RAW_AUDIT"),
            "a Patina-built binary must audit cleanly with no --allow and no raw banner:\n{audit_out}"
        );
        let source_audit = invoke(workspace, &["audit", source.to_str().unwrap()]);
        assert_eq!(audit_imports(&artifact_audit), audit_imports(&source_audit));

        let trace = directory.path().join("sf.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "sf-v1",
                "--",
                "hi",
                "there",
            ],
        );
        let recorded_line = stdout_line_with(&recorded, "SF_MARKER");
        assert!(
            recorded_line.contains("[\"hi\", \"there\"]"),
            "{recorded_line}"
        );

        let implicit = invoke(
            workspace,
            &[
                "run",
                source.to_str().unwrap(),
                "--seed",
                "1",
                "--",
                "hi",
                "there",
            ],
        );
        assert_eq!(stdout_line_with(&implicit, "SF_MARKER"), recorded_line);
        let note = stdout_line_with(&implicit, "PATINA_BUILD_ON_RUN");
        assert!(
            note.contains("sha256="),
            "missing build-on-the-fly identity note:\n{}",
            String::from_utf8_lossy(&implicit.stdout)
        );

        let replay_source = || {
            invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "replay",
                    source.to_str().unwrap(),
                    trace.to_str().unwrap(),
                    "--fingerprint",
                    "sf-v1",
                ],
            )
        };
        let replayed = common::assert_success(replay_source());
        assert_eq!(stdout_line_with(&replayed, "SF_MARKER"), recorded_line);

        // An edit that reads the clock more times than the recording: the rebuilt
        // binary's op-stream diverges, so source-first replay must fail closed.
        fs::write(
            &source,
            "use std::time::Instant; \
             fn main() { let s = Instant::now(); let mut acc = 0u128; \
             for _ in 0..8 { acc = acc.wrapping_add(s.elapsed().as_nanos()); } \
             println!(\"SF_MARKER v2 CHANGED acc={acc}\"); }",
        )
        .unwrap();
        let broken = replay_source();
        assert!(
            !broken.status.success(),
            "source-first replay of a behaviour-changed source must fail closed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&broken.stdout),
            String::from_utf8_lossy(&broken.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_audit_attributes_unsupported_imports_to_dependency_crates() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("provenance-pkg");
        fs::create_dir_all(package.join("src")).unwrap();
        for crate_name in ["leaker_a", "leaker_b"] {
            fs::create_dir_all(package.join(crate_name).join("src")).unwrap();
        }
        fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"provenance-pkg\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nleaker-a = { path = \"leaker_a\" }\nleaker-b = { path = \"leaker_b\" }\n\n[workspace]\n",
    )
    .unwrap();
        fs::write(
        package.join("src/main.rs"),
        "fn main() { let value = leaker_a::addr() ^ leaker_b::addr(); std::process::exit((value & 1) as i32); }\n",
    )
    .unwrap();
        fs::write(
            package.join("leaker_a/Cargo.toml"),
            "[package]\nname = \"leaker-a\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
        package.join("leaker_a/src/lib.rs"),
        "unsafe extern \"C\" { fn system(command: *const u8) -> i32; }\n#[inline(never)] pub fn addr() -> usize { system as *const () as usize }\n",
    )
    .unwrap();
        fs::write(
            package.join("leaker_b/Cargo.toml"),
            "[package]\nname = \"leaker-b\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
        package.join("leaker_b/src/lib.rs"),
        "unsafe extern \"C\" { fn shm_open(name: *const core::ffi::c_char, oflag: i32, mode: u32) -> i32; }\n#[inline(never)] pub fn addr() -> usize { shm_open as *const () as usize }\n",
    )
    .unwrap();

        let workspace = native_workspace();
        let bin = directory.path().join("provenance-bin");
        invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let human = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", bin.to_str().unwrap()],
        );
        assert!(!human.status.success());
        let stderr = String::from_utf8_lossy(&human.stderr);
        let mut needles = vec![
            "unsupported native imports:",
            "provenance=crate=leaker_a",
            "provenance=crate=leaker_b",
            "system (process)",
            "shm_open (shared-memory-ipc)",
        ];
        // Object identity is what each format records, and the two formats record
        // different amounts. Mach-O carries a per-address object/archive-member map,
        // so the defining rlib member is named outright. A linked ELF only records
        // object identity for an input file's *local* symbols — a crate's public
        // function is global, so no object is recoverable for it, and the crate
        // recovered from the symbol's own mangling plus the containing symbol is the
        // whole honest answer.
        if cfg!(target_os = "macos") {
            needles.extend(["object=libleaker_a-", "object=libleaker_b-"]);
        }
        for needle in needles {
            assert!(
                stderr.contains(needle),
                "missing {needle:?} in provenance-grouped audit stderr:\n{stderr}"
            );
        }
        for crate_name in ["leaker_a", "leaker_b"] {
            assert!(
                stderr
                    .lines()
                    .any(|line| line.contains("symbol=") && line.contains(crate_name)),
                "no containing symbol names {crate_name} in audit stderr:\n{stderr}"
            );
        }
        let junk = provenance_junk_lines(&stderr);
        assert!(
            junk.is_empty(),
            "audit reported provenance that names nothing real: {junk:#?}\nfull stderr:\n{stderr}"
        );

        let json = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", bin.to_str().unwrap(), "--format", "json"],
        );
        assert!(!json.status.success());
        let value: serde_json::Value =
            serde_json::from_slice(&json.stdout).unwrap_or_else(|error| {
                panic!(
                    "audit --format json did not emit JSON: {error}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&json.stdout),
                    String::from_utf8_lossy(&json.stderr)
                )
            });
        assert_eq!(value["result"], "violation");
        assert_eq!(value["exit_code"], 2);
        assert_json_finding_has_crate(&value, "system", "leaker_a");
        assert_json_finding_has_crate(&value, "shm_open", "leaker_b");

        // `run` applies the same pre-run default-deny gate to the prebuilt binary
        // and to the package directory built on the fly: both are refused before
        // the guest runs, naming the same denied process-class symbol.
        let denied_line = |target: &Path| -> String {
            let out = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &["run", target.to_str().unwrap(), "--seed", "1"],
            );
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(!out.status.success(), "{} ran:\n{stderr}", target.display());
            stderr
                .lines()
                .find(|line| line.contains("(process)"))
                .unwrap_or_else(|| panic!("no denied-symbol line in stderr:\n{stderr}"))
                .trim()
                .to_owned()
        };
        let prebuilt = denied_line(&bin);
        assert!(prebuilt.contains("system"), "{prebuilt}");
        assert_eq!(
            prebuilt,
            denied_line(&package),
            "the two paths named different denied symbols (gate not shared)"
        );
    }

    /// Audit output lines whose `object=` names nothing real.
    ///
    /// Attributing a site to an object it does not belong to is a wrong answer, not
    /// a missing feature, and the two Linux architectures produced different flavors
    /// of it from the same cause. Every ELF global symbol used to inherit whichever
    /// STT_FILE marker came last in the symbol table: on x86_64 that was a C
    /// translation unit, so Rust crates were reported as defined by `crtstuff.c`; on
    /// arm64 the marker's name was empty, so the finding rendered as a bare
    /// `object=` with nothing after it. Checking only the first shape would let the
    /// second through, so this covers both, plus the `unknown` sentinel leaking into
    /// human output instead of being omitted.
    fn provenance_junk_lines(stderr: &str) -> Vec<&str> {
        stderr
            .lines()
            .filter(|line| {
                let Some(rest) = line.split("object=").nth(1) else {
                    return false;
                };
                let object = rest.split_whitespace().next().unwrap_or_default();
                rest.is_empty()
                    || rest.starts_with(char::is_whitespace)
                    || object.ends_with(".c")
                    || object == "unknown"
            })
            .collect()
    }

    // The junk detector has to fire on the real signatures, or the pin above is
    // decoration. These are verbatim lines from the pre-fix audit on each
    // architecture.
    #[test]
    fn provenance_junk_detector_fires_on_both_architectures_signatures() {
        let x86_64 = "  provenance=crate=leaker_a object=crtstuff.c (1 finding)";
        let arm64 = "  provenance=crate=leaker_a object= (1 finding)";
        let sentinel = "  provenance=crate=leaker_a object=unknown (1 finding)";
        for junk in [x86_64, arm64, sentinel] {
            assert_eq!(
                provenance_junk_lines(junk),
                vec![junk],
                "the junk detector missed a known signature"
            );
        }

        let good = "unsupported native imports:\n  \
        provenance=crate=leaker_a (1 finding)\n    \
        killpg (process) [symbol=_RNvCslpz1a3WbgXx_8leaker_a4addr section=.text]\n  \
        provenance=crate=foo object=libfoo-1234abcd.rlib(foo.o) (1 finding)";
        assert!(
            provenance_junk_lines(good).is_empty(),
            "the junk detector must not fire on real attribution: {:#?}",
            provenance_junk_lines(good)
        );
    }

    fn assert_json_finding_has_crate(value: &serde_json::Value, symbol: &str, crate_name: &str) {
        let details = value["finding_details"]
            .as_array()
            .unwrap_or_else(|| panic!("missing finding_details array in {value:#}"));
        let finding = details
            .iter()
            .find(|detail| {
                detail["symbol"]
                    .as_str()
                    .map(|got| got.trim_start_matches('_') == symbol)
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("missing finding for {symbol} in {value:#}"));
        let provenance = finding["provenance"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provenance for {symbol}: {finding:#}"));
        assert!(
            provenance.iter().any(|origin| {
                origin["crate"].as_str() == Some(crate_name)
                && origin["containing_symbol"]
                    .as_str()
                    .map(|containing| containing.contains(crate_name))
                    .unwrap_or(false)
                // Mach-O names the defining rlib member; a linked ELF records no
                // object for a global symbol, which reports as `unknown` rather
                // than borrowing a neighbor's.
                && origin["object"]
                    .as_str()
                    .map(|object| {
                        if cfg!(target_os = "macos") {
                            object.starts_with(&format!("lib{crate_name}-"))
                        } else {
                            object == "unknown" || object.starts_with(crate_name)
                        }
                    })
                    .unwrap_or(false)
            }),
            "finding for {symbol} lacks crate/object provenance {crate_name}: {finding:#}"
        );
    }

    // Auditing a *prebuilt* native binary that was NOT produced by `cargo patina
    // build` fails closed: its imports are unsatisfied libc calls (the surface the
    // shim interposes once linked), not the post-interposition residual, so a raw
    // listing is the opposite of the truth. The refusal names the source-first form.
    // `--raw` overrides the gate and runs the full audit (instruction scan and
    // escape categories stay meaningful) under a loud stderr banner. A
    // Patina-built binary defines the shim control-plane marker and audits with no
    // banner (`native_source_is_first_class_for_run_audit_and_replay`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn audit_prebuilt_non_shim_binary_fails_closed_unless_raw() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();

        // A stock binary built by plain `rustc` — no `cargo patina build`, so the
        // shim staticlib is not linked and `patina_init_from_env` is undefined.
        let source = directory.path().join("stock.rs");
        fs::write(&source, "fn main() { println!(\"STOCK\"); }").unwrap();
        let stock = directory.path().join("stock");
        let compiled = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&stock)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "rustc failed to build the stock fixture:\nstderr:\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        );

        // (a) A bare audit of the stock binary is refused, not silently listed.
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", stock.to_str().unwrap()],
        );
        assert!(
            !refused.status.success(),
            "audit of a non-shim-linked binary must fail closed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        );
        let refusal = String::from_utf8_lossy(&refused.stderr);
        assert!(
            refusal.contains("not built with `cargo patina build`")
                && refusal.contains("cargo patina audit ./Cargo.toml")
                && refusal.contains("--raw"),
            "refusal must explain the shim-link gap and point to source-first + --raw:\n{refusal}"
        );

        // (b) `--raw` runs the full audit anyway under the loud banner. The stock
        // binary's unsatisfied libc surface is denied, so the audit still fails
        // closed — but now with the real categorized findings, which is what makes
        // `--raw` useful for planted-escape fixtures (instruction scan included).
        let raw = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", stock.to_str().unwrap(), "--raw"],
        );
        assert!(
            !raw.status.success(),
            "--raw audit of a stock binary must still fail closed on its denied imports\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&raw.stdout),
            String::from_utf8_lossy(&raw.stderr)
        );
        let raw_stderr = String::from_utf8_lossy(&raw.stderr);
        assert!(
            raw_stderr.contains("PATINA_RAW_AUDIT"),
            "--raw audit must lead with the raw-audit banner:\n{raw_stderr}"
        );
        assert!(
            raw_stderr.contains("unsupported native imports"),
            "--raw audit must render the real categorized findings:\n{raw_stderr}"
        );
    }

    /// Build a minimal well-formed little-endian x86-64 ELF64 whose single
    /// `ALLOC|EXECINSTR` `.text` section carries `text`. Enough for the audit to
    /// parse the file, classify the architecture, and run the instruction scan —
    /// which is the whole subject here. Hand-built rather than compiled because the
    /// instruction under test (`cpuid`) is x86-64-only and this suite must assert the
    /// same reporting on an arm64 host.
    fn synthetic_x86_64_elf(text: &[u8]) -> Vec<u8> {
        const EM_X86_64: u16 = 62;
        let shstr: &[u8] = b"\0.text\0.shstrtab\0"; // ".text" at 1, ".shstrtab" at 7
        let text_off = 64u64;
        let shstr_off = text_off + text.len() as u64;
        let shoff = (shstr_off + shstr.len() as u64 + 7) & !7;

        let mut elf = Vec::new();
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]); // ELFCLASS64, LSB
        elf.extend_from_slice(&[0u8; 8]);
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        elf.extend_from_slice(&EM_X86_64.to_le_bytes());
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx
        assert_eq!(elf.len(), 64, "ELF64 header is 64 bytes");
        elf.extend_from_slice(text);
        elf.extend_from_slice(shstr);
        while (elf.len() as u64) < shoff {
            elf.push(0);
        }
        let mut push_shdr = |name: u32, typ: u32, flags: u64, offset: u64, size: u64| {
            elf.extend_from_slice(&name.to_le_bytes());
            elf.extend_from_slice(&typ.to_le_bytes());
            elf.extend_from_slice(&flags.to_le_bytes());
            elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
            elf.extend_from_slice(&offset.to_le_bytes());
            elf.extend_from_slice(&size.to_le_bytes());
            elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
            elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
            elf.extend_from_slice(&4u64.to_le_bytes()); // sh_addralign
            elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
        };
        push_shdr(0, 0, 0, 0, 0); // SHN_UNDEF
        push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64); // .text PROGBITS A|X
        push_shdr(7, 3, 0, shstr_off, shstr.len() as u64); // .shstrtab STRTAB
        elf
    }

    // `audit` REPORTS inline host-identity reads (`cpuid`) instead of passing them in
    // silence — and does not refuse them. This is the end-to-end half of the
    // patina-target unit test: an operator running the real CLI sees the heading, and
    // the exit code is unchanged at 0 on a binary whose only finding is host identity.
    //
    // The gap this closes was measured, not imagined: on the fastant calibrating
    // guest, `objdump` counted 11 `cpuid` sites in a binary whose 2 `rdtsc` sites the
    // audit did report, and in that guest `cpuid` is the branch selecting the
    // timestamp-counter path over the `SystemTime` fallback — so the same guest at
    // the same seed can take a different path on a host with different feature bits,
    // with nothing in the report saying so.
    //
    // RED before the `0f a2` decode row: `--format json` carries no `host-identity`
    // detail and stderr carries no heading, while the exit code is already 0 — i.e.
    // the audit passed the binary and said nothing.
    #[test]
    fn audit_reports_host_identity_reads_without_refusing_them() {
        let directory = tempdir().unwrap();
        // cpuid; ret; cpuid; ret; nop; nop
        let binary = directory.path().join("cpuid-probe");
        fs::write(
            &binary,
            synthetic_x86_64_elf(&[0x0f, 0xa2, 0xc3, 0x0f, 0xa2, 0xc3, 0x90, 0x90]),
        )
        .unwrap();

        // `--raw`: the fixture is not shim-linked, and the audit rightly refuses to
        // report a non-Patina-built binary's imports without it. The instruction scan
        // — the subject here — runs either way.
        let audited = invoke(
            directory.path(),
            &["audit", binary.to_str().unwrap(), "--raw"],
        );
        let stderr = String::from_utf8_lossy(&audited.stderr);
        assert_eq!(
            audited.status.code(),
            Some(0),
            "a host-identity read is informational and must not change the exit code:\
         \nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&audited.stdout)
        );
        assert!(
            stderr.contains("host-identity reads (cpuid, 2 sites)"),
            "the audit must name the class and its site count:\n{stderr}"
        );
        assert!(
            stderr.contains("cross-host") && stderr.contains("unmanaged"),
            "the note must say what is unmanaged and what it costs:\n{stderr}"
        );
        assert!(
            stderr.contains("instruction@.text+0x0") && stderr.contains("instruction@.text+0x3"),
            "each site is named by its .text offset:\n{stderr}"
        );

        // JSON: the sites ride in finding_details like other findings, the result
        // stays `ok`, and they are NOT promoted into `findings` (which would read as
        // a violation to a consumer).
        let json = invoke(
            directory.path(),
            &[
                "audit",
                binary.to_str().unwrap(),
                "--raw",
                "--format",
                "json",
            ],
        );
        assert_eq!(json.status.code(), Some(0));
        let envelope: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim())
                .expect("audit --format json emits one envelope");
        assert_eq!(envelope["result"], "ok");
        assert_eq!(envelope["exit_code"], 0);
        let details = envelope["finding_details"]
            .as_array()
            .expect("finding_details is an array")
            .clone();
        assert_eq!(details.len(), 2, "both sites are detailed: {details:?}");
        for detail in &details {
            assert_eq!(detail["category"], "host-identity");
            assert_eq!(detail["disposition"], "unmanaged-visible");
        }

        // The neighbouring refusal class is unchanged: an `rdtsc` in the same text
        // still fails closed with exit 2 on this (non-x86-Linux) host, and the
        // host-identity site is still reported alongside the refusal.
        let with_rdtsc = directory.path().join("cpuid-and-rdtsc");
        fs::write(
            &with_rdtsc,
            synthetic_x86_64_elf(&[0x0f, 0xa2, 0x0f, 0x31, 0xc3, 0x90, 0x90, 0x90]),
        )
        .unwrap();
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["audit", with_rdtsc.to_str().unwrap(), "--raw"],
        );
        let refused_stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "the counter read must still refuse:\n{refused_stderr}"
        );
        assert!(
            refused_stderr.contains("cpu-nondeterminism"),
            "the refusal still names the counter read:\n{refused_stderr}"
        );
        assert!(
            refused_stderr.contains("host-identity reads (cpuid, 1 site)"),
            "a refusal reports host-identity sites too, or the class is visible on \
         some outcomes and silent on others:\n{refused_stderr}"
        );
    }
}
