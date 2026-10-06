//! Campaign native invocation forwarding, output drainage, and classification.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A harness fixture cheap enough to sweep: one interposed `std::fs` round trip,
    // no faults, so every generation is OK once the harness deferral is forwarded.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_CAMPAIGN_SRC: &str = r#"
fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run(|| {
        std::fs::create_dir_all("/state")?;
        std::fs::write("/state/v", b"hello")?;
        println!("HARNESS_OUT read={}", std::fs::read_to_string("/state/v")?);
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}
"#;

    // Gate: a `patina-dst-harness` binary is sweepable. Without `--harness` the
    // supervisor installs the runtime itself and the guest's own install fails closed
    // (`AlreadyInstalled`) in every generation; with it, every generation runs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_forwards_harness_deferral_to_every_generation() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("camp-harness");
        write_harness_fixture(&fixture, "harness-campaign", HARNESS_CAMPAIGN_SRC);
        let guest = directory.path().join("harness-campaign-bin");
        build_harness_bin(&fixture, &guest);

        // RED: no `--harness`. Every generation fails closed, identically.
        let refused = campaign_run(&directory.path().join("red"), &guest, &[]);
        assert!(
            !refused.status.success(),
            "a harness guest swept without --harness must not report a clean campaign"
        );
        let envelope = campaign_json_stdout(&refused);
        assert_eq!(
            envelope["classes"]["OK"],
            serde_json::Value::Null,
            "no generation can have run the guest: {}",
            envelope["classes"]
        );
        let signatures = serde_json::to_string(&envelope["signatures"]).unwrap();
        assert!(
            signatures.contains("AlreadyInstalled"),
            "the refusal must be the harness double-install one:\n{signatures}"
        );

        // GREEN: forwarded to every generation.
        let swept = campaign_run(&directory.path().join("green"), &guest, &["--harness"]);
        assert!(
            swept.status.success(),
            "the forwarded --harness must let the campaign sweep:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&swept.stdout),
            String::from_utf8_lossy(&swept.stderr)
        );
        assert_eq!(campaign_json_stdout(&swept)["classes"]["OK"], 2);

        // And it is campaign SHAPE: recorded in the out-dir spec, so a continuation
        // re-derives it without re-supplying (and refuses an attempt to change it).
        let extended = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "campaign",
                "--extend",
                "1",
                "--out-dir",
                directory.path().join("green").to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        assert!(
            extended.status.success(),
            "a resumed harness campaign must re-derive --harness from the recorded spec:\nstderr:\n{}",
            String::from_utf8_lossy(&extended.stderr)
        );
        assert_eq!(campaign_json_stdout(&extended)["classes"]["OK"], 3);
    }

    // A guest whose captured streams are well past a pipe buffer (64 KiB on Linux,
    // at most that on macOS). Under `run --format json` they travel INSIDE the
    // envelope, so the child's stdout is one ~200 KiB line.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const WIDE_OUTPUT_SOURCE: &str = r#"
fn main() {
    let line = "w".repeat(1023);
    for _ in 0..200 {
        eprintln!("{line}");
    }
    println!("WIDE_OUT done");
}
"#;

    // Gate: a generation whose output exceeds the pipe buffer is drained, not wedged.
    // The campaign's timeout loop polls the child without reading its pipes; before
    // the reader threads, a child this wide blocked on its envelope write, never
    // exited, and was killed at the deadline as INFRA — so a guest with hundreds of
    // SDK sites (one `PATINA_SDK_REPORT` line past 64 KiB) could not be swept at
    // all. RED: no OK generation, the run fails, and the deadline is what ends it;
    // GREEN: every generation is OK, well inside the deadline.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_drains_generation_output_wider_than_the_pipe_buffer() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("wide.rs");
        fs::write(&source, WIDE_OUTPUT_SOURCE).unwrap();
        let guest = directory.path().join("wide");
        invoke(
            native_workspace(),
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
            ],
        );
        let swept = campaign_run(
            &directory.path().join("out"),
            &guest,
            &["--timeout-secs", "20"],
        );
        assert!(
            swept.status.success(),
            "a generation wider than the pipe buffer must be drained, not killed at the deadline:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&swept.stdout),
            String::from_utf8_lossy(&swept.stderr)
        );
        let envelope = campaign_json_stdout(&swept);
        assert_eq!(
            envelope["classes"]["OK"], 2,
            "both generations must run to completion: {}",
            envelope["classes"]
        );
    }

    // A guest that aborts itself, with nothing patina would call a refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const GUEST_ABORT_SOURCE: &str = r#"
fn main() {
    eprintln!("GUEST: invariant failed, aborting");
    std::process::abort();
}
"#;

    // The outcome-channel arc's §4.4 split, end to end: the SAME SIGABRT lands in two
    // different campaign classes depending on one envelope field. A guest that aborts
    // itself is `GUEST_ABORT` — a finding attributed to the system under test — while
    // a patina fail-closed refusal (a duplicate buggify label, which the shim aborts
    // on) still classifies `FAIL_CLOSED_ABORT`. Before the envelope carried a
    // `refusal` record, EVERY exit-134 generation was blamed on patina and buried in
    // the fail-closed bucket; both halves are asserted here so neither can quietly
    // absorb the other.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_splits_a_guest_abort_from_a_patina_refusal() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();

        // (a) the guest's own abort.
        let source = directory.path().join("guest_abort.rs");
        fs::write(&source, GUEST_ABORT_SOURCE).unwrap();
        let aborting = directory.path().join("guest-abort");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                aborting.to_str().unwrap(),
            ],
        );
        let swept = campaign_run(&directory.path().join("guest"), &aborting, &[]);
        let envelope = campaign_json_stdout(&swept);
        assert_eq!(
            envelope["classes"]["GUEST_ABORT"], 2,
            "an unattributed abort is the guest's own doing: {}",
            envelope["classes"]
        );
        assert_eq!(
            envelope["classes"]["FAIL_CLOSED_ABORT"],
            serde_json::Value::Null,
            "a guest abort must not be blamed on patina: {}",
            envelope["classes"]
        );

        // (b) patina's own refusal, on the same exit code.
        let pkg = directory.path().join("dup");
        write_sdk_fixture(&pkg, BUGGIFY_DUP_MAIN);
        let refusing = directory.path().join("dup-label");
        invoke(
            workspace,
            &[
                "build",
                pkg.to_str().unwrap(),
                "--output",
                refusing.to_str().unwrap(),
            ],
        );
        let refused = campaign_run(&directory.path().join("refusal"), &refusing, &[]);
        let envelope = campaign_json_stdout(&refused);
        assert_eq!(
            envelope["classes"]["FAIL_CLOSED_ABORT"], 2,
            "an abort patina attributed to itself stays fail-closed: {}",
            envelope["classes"]
        );
        assert_eq!(
            envelope["classes"]["GUEST_ABORT"],
            serde_json::Value::Null,
            "a patina refusal must not be filed as a guest finding: {}",
            envelope["classes"]
        );
    }

    // A level-1 guest — no verdict ABI, no patina-visible failure at all — is
    // classified from rules its own campaign spec declares, with zero guest changes.
    // The RED half is in the same test: the identical guest with no declared rules
    // classifies OK, so it is the spec that classifies, never the string.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_classifies_a_level_one_guest_from_spec_declared_patterns() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("level_one.rs");
        fs::write(
            &source,
            "fn main() { println!(\"GUEST: checksum mismatch on page 7\"); }\n",
        )
        .unwrap();
        let guest = directory.path().join("level-one");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
            ],
        );

        // RED: exit 0, nothing structured — patina sees a clean run.
        let bare = campaign_run(&directory.path().join("bare"), &guest, &[]);
        assert_eq!(campaign_json_stdout(&bare)["classes"]["OK"], 2);

        // GREEN: the guest's own dialect, declared in its spec.
        let spec = directory.path().join("spec.json");
        fs::write(
            &spec,
            r#"{"classify": {"patterns": {"VIOLATION": ["checksum mismatch"]}}}"#,
        )
        .unwrap();
        let declared = campaign_run(
            &directory.path().join("declared"),
            &guest,
            &["--spec", spec.to_str().unwrap()],
        );
        let envelope = campaign_json_stdout(&declared);
        assert_eq!(
            envelope["classes"]["VIOLATION"], 2,
            "declared patterns must classify a level-1 guest: {}",
            envelope["classes"]
        );

        // A malformed rule is a loud spec error, never a silently inert rule.
        fs::write(&spec, r#"{"classify": {"patterns": {"NOPE": ["x"]}}}"#).unwrap();
        let bad = campaign_run(
            &directory.path().join("bad"),
            &guest,
            &["--spec", spec.to_str().unwrap()],
        );
        assert!(!bad.status.success(), "an unknown class must be refused");
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("unknown class")
                || String::from_utf8_lossy(&bad.stdout).contains("unknown class"),
            "the refusal must name the problem:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&bad.stdout),
            String::from_utf8_lossy(&bad.stderr)
        );
    }

    // A WASI campaign carrying the native invocation surface is refused BY NAME
    // where the artifact family is finally known, not silently swept without it —
    // the same shape as the `--dns-entry` family refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_refuses_the_native_invocation_surface_for_a_wasi_artifact() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("app.wasm");
        fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
        for (flag, value) in [
            ("--harness", None),
            ("--allow", Some("dlsym")),
            ("--allow-unsupported-symbols", Some("all")),
        ] {
            let out = directory.path().join(flag.trim_start_matches('-'));
            let mut args = vec![
                "campaign",
                module.to_str().unwrap(),
                "--gens",
                "1",
                "--out-dir",
                out.to_str().unwrap(),
                flag,
            ];
            if let Some(value) = value {
                args.push(value);
            }
            let refused = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                native_workspace(),
                &args,
            );
            assert!(!refused.status.success(), "{flag} must be refused for WASI");
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(
                stderr.contains(flag) && stderr.contains("native"),
                "the refusal must name {flag} and the family:\n{stderr}"
            );
        }
    }
}
