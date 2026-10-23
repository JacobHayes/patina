//! Campaign native invocation forwarding, output drainage, and classification.

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::super::run_facts::{outcome_guest, shared_sdk_guest};
    use super::super::*;

    // Gate: a `patina-dst-harness` binary is sweepable. Without `--harness` the
    // supervisor installs the runtime itself and the guest's own install fails closed
    // (`AlreadyInstalled`) in every generation; with it, every generation runs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_forwards_harness_deferral_to_every_generation() {
        let directory = tempdir().unwrap();
        let guest = super::super::sdk_harness::harness_guest();

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
        // re-derives it without re-supplying.
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

    // One native guest, several outcomes, each landing in the class its attribution
    // earns:
    //
    // * Output wider than the pipe buffer is drained, not wedged: the guest's
    //   streams travel INSIDE its `--format json` envelope, so the child's stdout is
    //   one ~200 KiB line, and the campaign's timeout loop polls the child without
    //   reading its pipes. Before the reader threads such a child blocked on its
    //   envelope write and was killed at the deadline as INFRA, so a guest with
    //   hundreds of SDK sites could not be swept at all.
    // * The outcome-channel arc's §4.4 split: the SAME SIGABRT lands in two classes
    //   depending on one envelope field. A guest that aborts itself is
    //   `GUEST_ABORT`, a finding attributed to the system under test, while a patina
    //   fail-closed refusal (a duplicate buggify label, which the shim aborts on
    //   with its marker before the guest runs past it) stays `FAIL_CLOSED_ABORT`.
    //   Both halves are asserted so neither can quietly absorb the other.
    // * A level-1 guest (no verdict ABI, no patina-visible failure at all) is
    //   classified from rules its own campaign spec declares, with zero guest
    //   changes; without the rules the same guest is OK, so it is the spec that
    //   classifies, never the string, and a malformed rule is a loud spec error.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_classifies_each_guest_outcome_by_its_attribution() {
        let directory = tempdir().unwrap();
        let guest = outcome_guest();
        let classes = |name: &str, guest: &Path, extra: &[&str]| {
            let output = campaign_run(&directory.path().join(name), guest, extra);
            (
                output.status.success(),
                campaign_json_stdout(&output)["classes"].clone(),
            )
        };

        let (success, wide) = classes("wide", &guest, &["--timeout-secs", "20", "--", "wide"]);
        assert!(
            success && wide["OK"] == 2,
            "a generation wider than the pipe buffer must be drained, not killed at the deadline: {wide}"
        );

        let (_, aborted) = classes("abort", &guest, &["--", "abort"]);
        assert_eq!(
            aborted["GUEST_ABORT"], 2,
            "an unattributed abort is the guest's own doing: {aborted}"
        );
        assert_eq!(
            aborted["FAIL_CLOSED_ABORT"],
            serde_json::Value::Null,
            "a guest abort must not be blamed on patina: {aborted}"
        );

        let refusing = shared_sdk_guest("buggify-dup", BUGGIFY_DUP_MAIN);
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &["run", refusing.to_str().unwrap(), "--seed", "1"],
        );
        assert!(!output.status.success(), "duplicate label must abort");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=same-label"),
            "expected duplicate-label marker: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("unreachable"),
            "guest ran past the duplicate label"
        );
        let (_, refused) = classes("refusal", &refusing, &[]);
        assert_eq!(
            refused["FAIL_CLOSED_ABORT"], 2,
            "an abort patina attributed to itself stays fail-closed: {refused}"
        );
        assert_eq!(
            refused["GUEST_ABORT"],
            serde_json::Value::Null,
            "a patina refusal must not be filed as a guest finding: {refused}"
        );

        let (_, bare) = classes("bare", &guest, &["--", "level-one"]);
        assert_eq!(bare["OK"], 2, "{bare}");
        let spec = directory.path().join("spec.json");
        fs::write(
            &spec,
            r#"{"classify": {"patterns": {"VIOLATION": ["checksum mismatch"]}}}"#,
        )
        .unwrap();
        let spec_arg = spec.to_str().unwrap();
        let (_, declared) = classes("declared", &guest, &["--spec", spec_arg, "--", "level-one"]);
        assert_eq!(
            declared["VIOLATION"], 2,
            "declared patterns must classify a level-1 guest: {declared}"
        );
        fs::write(&spec, r#"{"classify": {"patterns": {"NOPE": ["x"]}}}"#).unwrap();
        let bad = campaign_run(
            &directory.path().join("bad"),
            &guest,
            &["--spec", spec_arg, "--", "level-one"],
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

    // A campaign asked for a mode its artifact cannot serve is refused by name, never
    // swept in a different mode than the operator asked for. A plain native binary
    // (no yield points) has no edge coverage and is not WASI, so `--guided` has no
    // novelty signal; a WASI campaign carrying the native invocation surface is
    // refused where the artifact family is finally known, the same shape as the
    // `--dns-entry` family refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_refuses_a_mode_its_artifact_cannot_serve() {
        let directory = tempdir().unwrap();
        let refused = campaign_run(
            &directory.path().join("guided"),
            &outcome_guest(),
            &["--guided"],
        );
        assert_ne!(
            refused.status.code(),
            Some(0),
            "--guided without a novelty signal must not succeed quietly"
        );
        // Under `--format json` the refusal travels in the envelope.
        let refusal = format!(
            "{}{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            refusal.contains("--guided needs a novelty signal")
                && refusal.contains("--yield-points"),
            "the refusal must name the cause and the fix:\n{refusal}"
        );

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
