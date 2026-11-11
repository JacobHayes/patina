//! Campaign invocation forwarding, output drainage, and classification.

#[cfg(test)]
mod tests {
    use super::super::run_facts::{outcome_guest, shared_sdk_guest};
    use super::super::*;

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
            success && wide["ok"] == 2,
            "a generation wider than the pipe buffer must be drained, not killed at the deadline: {wide}"
        );

        let (_, aborted) = classes("abort", &guest, &["--", "abort"]);
        assert_eq!(
            aborted,
            serde_json::json!({"crash": 2}),
            "an abort is the guest's own doing, never blamed on patina"
        );

        let refusing = shared_sdk_guest("buggify-dup", BUGGIFY_DUP_MAIN);
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
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
        // The same SIGABRT, stopped by patina for an SDK contract the guest
        // broke: the stop's class decides, not the signal.
        let (_, refused) = classes("refusal", &refusing, &[]);
        assert_eq!(
            refused,
            serde_json::json!({"violation": 2}),
            "a duplicate label is the guest's violation, not a bare crash"
        );

        let (_, bare) = classes("bare", &guest, &["--", "level-one"]);
        assert_eq!(bare["ok"], 2, "{bare}");
        let spec = directory.path().join("spec.json");
        fs::write(
            &spec,
            r#"{"classify": {"patterns": {"violation": ["checksum mismatch"]}}}"#,
        )
        .unwrap();
        let spec_arg = spec.to_str().unwrap();
        let (_, declared) = classes("declared", &guest, &["--spec", spec_arg, "--", "level-one"]);
        assert_eq!(
            declared["violation"], 2,
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

    // A campaign asked for a mode its artifact cannot serve is refused, never
    // swept in a different mode than the operator asked for. A plain native
    // binary (`--no-instrument`: no edge hook) has no edge coverage, so
    // `--guided` has no novelty signal.
    #[test]
    fn campaign_refuses_guided_without_a_novelty_signal() {
        let directory = tempdir().unwrap();
        let plain = build_facts_guest_with(
            directory.path(),
            "plain",
            "fn main() { println!(\"plain\"); }\n",
            &["--no-instrument"],
        );
        let refused = campaign_run(&directory.path().join("guided"), &plain, &["--guided"]);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "--guided without a novelty signal must be refused as patina's, not run:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        );
    }
}
