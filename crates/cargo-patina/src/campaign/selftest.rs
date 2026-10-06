//! Planted campaign classifier and exploration detector selftests.

mod scaling;

use super::classify::{
    HOST_KILL_SHAPE, SIGABRT, SIGABRT_EXIT, STARVATION_STALL_EXIT, TRACE_UNAVAILABLE_CLASS,
    is_runtime_diagnostic,
};
use super::generation::{SIGKILL, facts_from_envelope};
use super::report::{CoverageGate, coverage_verdict};
use super::spec::json_classify_rules;
use super::{
    AllowUnmetSometimes, CampaignClass, ClassifyRules, FindingFacts, GenerationFacts, RunFacts,
    VerdictFacts, classify, signature,
};
use crate::CliError;
use crate::sdk_report::CoverageTally;
use scaling::{fault_scale_selftest, starve_scale_selftest};

// ===========================================================================
// Selftest
// ===========================================================================

/// A planted generation for the selftest: structured facts plus the captured
/// output only the spec-declared matcher may read.
pub(super) fn planted(facts: RunFacts, output: &str) -> GenerationFacts {
    GenerationFacts {
        facts,
        output: output.to_string(),
        result_line: None,
    }
}

impl RunFacts {
    /// A clean, envelope-carrying generation — the base every selftest fixture
    /// mutates by exactly the one fact it is proving.
    pub(super) fn ok() -> Self {
        RunFacts {
            envelope: true,
            ..RunFacts::default()
        }
    }

    pub(super) fn exit(mut self, code: i32) -> Self {
        self.exit_code = code;
        self
    }

    pub(super) fn signal(mut self, signal: i32) -> Self {
        self.signal = Some(signal);
        self
    }

    pub(super) fn timed_out(mut self) -> Self {
        self.timed_out = true;
        self
    }

    pub(super) fn no_envelope(mut self) -> Self {
        self.envelope = false;
        self
    }

    pub(super) fn refusal(mut self, class: &str) -> Self {
        self.refusal = Some(class.to_string());
        self
    }

    /// The status the GUEST reached before the refusal's abort replaced it.
    fn guest_exit(mut self, code: i32) -> Self {
        self.refusal_guest_exit_code = Some(code);
        self
    }

    pub(super) fn verdict(mut self, kind: &str, label: &str) -> Self {
        self.verdicts.push(VerdictFacts {
            kind: kind.to_string(),
            label: label.to_string(),
        });
        self
    }

    pub(super) fn finding(mut self, source: &str, kind: &str) -> Self {
        self.findings.push(FindingFacts {
            source: source.to_string(),
            kind: kind.to_string(),
            known_limit: false,
        });
        self
    }

    pub(super) fn vacuous(mut self, plane: &str) -> Self {
        self.vacuous_planes.push(plane.to_string());
        self
    }
}

/// The selftest's level-1 guest rules, built through the same spec parser an
/// operator's `--spec FILE.json` goes through — so the selftest proves the
/// declared-rule GRAMMAR too, not just the matcher.
pub(super) fn declared_rules_fixture() -> ClassifyRules {
    json_classify_rules(&serde_json::json!({
        "patterns": {"VIOLATION": ["checksum mismatch"]},
        "exit_codes": {"VIOLATION": [3]},
    }))
    .expect("the selftest's declared rules must parse")
}

/// Prove every classifier class is reachable from the structured envelope facts
/// (with the spec-declared rules as the only text-reading path), and that the
/// signature store dedups repeats and flags novel signatures — mirroring the
/// fuzz-sweep `--selftest` discipline.
pub(super) fn selftest() -> Result<i32, CliError> {
    let mut failures = 0u32;
    let mut fired: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    let mut check = |name: &str, want: CampaignClass, got: CampaignClass| {
        if want == got {
            fired.insert(got.as_str());
            println!("  ok   {name:<40} -> {}", got.as_str());
        } else {
            println!(
                "  FAIL {name:<40} -> {} (want {})",
                got.as_str(),
                want.as_str()
            );
            failures += 1;
        }
    };

    println!("== campaign classifier selftest ==");
    // Every class must be proven fireable through the STRUCTURED channel, and
    // every class-deciding fact must be proven load-bearing: each check below is
    // paired with a red twin that removes exactly the one fact and lands
    // somewhere else. A check that cannot fail is a bug.
    let no_rules = ClassifyRules::default();
    check(
        "clean-exit-0",
        CampaignClass::Ok,
        classify(&planted(RunFacts::ok(), ""), &no_rules),
    );

    // A typed runtime limit must survive envelope reduction and must never
    // spend the campaign's novel-guest-finding budget. Removing the bit is RED.
    for (known_limit, expected) in [
        (true, CampaignClass::Infra),
        (false, CampaignClass::Liveness),
    ] {
        let facts = facts_from_envelope(&serde_json::json!({
            "exit_code": 134,
            "runtime_findings": [{"source": "liveness", "kind": "liveness", "known_limit": known_limit}]
        }));
        check(
            "runtime-limit-bit-is-load-bearing",
            expected,
            classify(&planted(facts, ""), &no_rules),
        );
    }

    // -- liveness: a runtime finding attributed to the watchdog ---------------
    check(
        "liveness-watchdog-finding",
        CampaignClass::Liveness,
        classify(
            &planted(
                RunFacts::ok().exit(1).finding("liveness", "no_progress"),
                "",
            ),
            &no_rules,
        ),
    );
    check(
        "heal-then-converge-finding",
        CampaignClass::Liveness,
        classify(
            &planted(RunFacts::ok().exit(2).finding("liveness", "converge"), ""),
            &no_rules,
        ),
    );
    // RED twin: the same run WITHOUT the liveness finding is not LIVENESS, so
    // the finding is what fires the class (a schedule-sourced finding must not).
    check(
        "liveness-red-without-the-finding",
        CampaignClass::Unclassified,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(1)
                    .finding("schedule", "vacuous_schedule"),
                "",
            ),
            &no_rules,
        ),
    );

    // -- violation: a `violation` verdict through the verdict ABI -------------
    check(
        "violation-verdict-on-exit-0",
        CampaignClass::Violation,
        classify(
            &planted(RunFacts::ok().verdict("violation", "two-leaders"), ""),
            &no_rules,
        ),
    );
    check(
        "always-violation-abort-is-violation-not-guest-abort",
        CampaignClass::Violation,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .verdict("violation", "must-hold"),
                "",
            ),
            &no_rules,
        ),
    );
    // RED twin: a `pass` verdict is not a finding.
    check(
        "violation-red-a-pass-verdict-is-not-a-finding",
        CampaignClass::Ok,
        classify(
            &planted(RunFacts::ok().verdict("pass", "queue-drained"), ""),
            &no_rules,
        ),
    );

    // -- per-plane coverage failures -----------------------------------------
    // Each plane carries its own `vacuous` bit in `fault_reports{}`, so one
    // plane's vacuity can never be filed under another's class — the whole
    // reason these are separate classes.
    for (name, class) in [
        ("fs", CampaignClass::VacuousFsFault),
        ("dns", CampaignClass::VacuousDnsFault),
        ("net", CampaignClass::VacuousNetFault),
        ("entropy", CampaignClass::VacuousEntropyFault),
        ("clock", CampaignClass::VacuousClockFault),
        ("custom_op", CampaignClass::VacuousCustomOpFault),
        ("swarm", CampaignClass::VacuousSwarm),
    ] {
        check(
            &format!("vacuous-{name}-plane"),
            class,
            classify(&planted(RunFacts::ok().vacuous(name), ""), &no_rules),
        );
    }
    // RED twin: a plane that is present but NOT vacuous fires nothing.
    check(
        "fs-plane-that-fired-is-not-vacuous",
        CampaignClass::Ok,
        classify(&planted(RunFacts::ok(), ""), &no_rules),
    );
    // Per-plane attribution, both directions: a vacuous DNS plane alongside a
    // healthy fs plane is the DNS class, never the fs one.
    check(
        "dns-vacuity-is-not-filed-under-the-fs-class",
        CampaignClass::VacuousDnsFault,
        classify(&planted(RunFacts::ok().vacuous("dns"), ""), &no_rules),
    );
    // Two vacuous planes get ONE class, and which one is pinned rather than left
    // to whichever check runs first, so the same run always dedups the same way.
    check(
        "both-planes-vacuous-reports-the-fs-class",
        CampaignClass::VacuousFsFault,
        classify(
            &planted(RunFacts::ok().vacuous("dns").vacuous("fs"), ""),
            &no_rules,
        ),
    );
    // A real finding still wins: an inert fault plane never hides a SUT bug.
    check(
        "violation-beats-vacuous-swarm",
        CampaignClass::Violation,
        classify(
            &planted(
                RunFacts::ok()
                    .vacuous("swarm")
                    .verdict("violation", "two-leaders"),
                "",
            ),
            &no_rules,
        ),
    );

    // Patina's own end-of-run recorder failure (an unwritable trace, a bundle
    // that would not serialize) aborts the guest with a SIGABRT the guest never
    // raised. When the GUEST itself came through clean that is the harness
    // failing, not a finding: INFRA, like a timeout. Its red twin is the same
    // SIGABRT with no refusal, two checks below.
    check(
        "shutdown-failure-over-a-clean-guest-is-infra",
        CampaignClass::Infra,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .refusal("shutdown_failure")
                    .guest_exit(0),
                "",
            ),
            &no_rules,
        ),
    );
    // RED twin, and the whole point of the rule: the recorder gives out on LONG
    // runs, which are the runs most likely to have found something. A guest that
    // had ALREADY failed on its own — a panic (101), a nonzero return — is the
    // finding; the unusable trace is a footnote the report still carries. Filing
    // this INFRA would delete a real failure, and delete it selectively from the
    // deepest generations in the campaign.
    for guest_code in [1, 101, 2] {
        check(
            &format!("shutdown-failure-over-a-failing-guest-{guest_code}-keeps-the-guests-class"),
            CampaignClass::Unclassified,
            classify(
                &planted(
                    RunFacts::ok()
                        .exit(SIGABRT_EXIT)
                        .signal(SIGABRT)
                        .refusal("shutdown_failure")
                        .guest_exit(guest_code),
                    "",
                ),
                &no_rules,
            ),
        );
    }
    // A guest verdict still outranks the refusal, as before: a violation the
    // guest reported is a VIOLATION whatever the recorder then did.
    check(
        "violation-beats-shutdown-failure",
        CampaignClass::Violation,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .refusal("shutdown_failure")
                    .guest_exit(101)
                    .verdict("violation", "integrity-check"),
                "",
            ),
            &no_rules,
        ),
    );
    // With no recorded guest status there is no evidence the guest failed, so
    // the demotion stands — patina's recorder is the only thing known to have
    // gone wrong.
    check(
        "shutdown-failure-with-no-recorded-guest-status-stays-infra",
        CampaignClass::Infra,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .refusal("shutdown_failure"),
                "",
            ),
            &no_rules,
        ),
    );

    // Patina's own trace CHANNEL failing — the recorder's scratch file could not
    // be opened, read, or renamed — is an operational condition of the host, in
    // the same family as a timeout or an OOM kill. Before this it landed in
    // UNCLASSIFIED, and because every such run's message named its own scratch
    // path, one environmental problem read as dozens of separate novel findings.
    check(
        "trace-channel-failure-over-a-clean-guest-is-infra",
        CampaignClass::Infra,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(2)
                    .refusal("trace_unavailable")
                    .guest_exit(0),
                "",
            ),
            &no_rules,
        ),
    );
    // With no recorded guest status, patina's channel is the only thing known to
    // have gone wrong: the demotion stands.
    check(
        "trace-channel-failure-with-no-guest-status-stays-infra",
        CampaignClass::Infra,
        classify(
            &planted(RunFacts::ok().exit(2).refusal("trace_unavailable"), ""),
            &no_rules,
        ),
    );
    // RED twin, and the difference from the recorder-budget rule: nothing about
    // a channel failure interferes with the guest's own death, so a guest that
    // aborted is still a GUEST_ABORT and one that exited nonzero is still
    // UNCLASSIFIED — the guest's status falls through to its own rules rather
    // than being consumed by the refusal.
    check(
        "trace-channel-failure-over-an-aborting-guest-is-still-a-guest-abort",
        CampaignClass::GuestAbort,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .refusal("trace_unavailable")
                    .guest_exit(SIGABRT_EXIT),
                "",
            ),
            &no_rules,
        ),
    );
    check(
        "trace-channel-failure-over-a-failing-guest-keeps-the-guests-class",
        CampaignClass::Unclassified,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(101)
                    .refusal("trace_unavailable")
                    .guest_exit(101),
                "",
            ),
            &no_rules,
        ),
    );
    // A guest verdict still outranks it, as with every other refusal.
    check(
        "violation-beats-a-trace-channel-failure",
        CampaignClass::Violation,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(2)
                    .refusal("trace_unavailable")
                    .guest_exit(0)
                    .verdict("violation", "integrity-check"),
                "",
            ),
            &no_rules,
        ),
    );

    // -- host-side death vs guest-side death --------------------------------
    // A SIGKILL is never the guest's doing: it cannot raise it, catch it, or
    // survive it. It is INFRA — the same bucket as a timeout — and NOT a bug
    // class, because a campaign that files an OOM kill as a finding reports a
    // failure that does not exist and hands over a reproduce command that
    // cannot reproduce it. The red twin below is the same fixture with SIGABRT.
    check(
        "sigkill-is-host-side-infra",
        CampaignClass::Infra,
        classify(
            &planted(RunFacts::ok().exit(128 + SIGKILL).signal(SIGKILL), ""),
            &no_rules,
        ),
    );
    check(
        "sigabrt-is-still-a-guest-abort",
        CampaignClass::GuestAbort,
        classify(
            &planted(RunFacts::ok().exit(SIGABRT_EXIT).signal(SIGABRT), ""),
            &no_rules,
        ),
    );
    // A guest that RETURNS 137 deliberately is not host-killed: only a real
    // signal counts, or this rule would hide findings instead of unmasking them.
    check(
        "exit-137-without-a-signal-is-not-a-host-kill",
        CampaignClass::Unclassified,
        classify(&planted(RunFacts::ok().exit(128 + SIGKILL), ""), &no_rules),
    );
    // A host kill outranks the guest's own output: a killed generation ran no
    // invariant to completion, so a declared pattern must not turn it into a bug.
    let mut declares_violation = ClassifyRules::default();
    declares_violation
        .patterns
        .insert(CampaignClass::Violation, vec!["CORRUPTION".to_string()]);
    check(
        "host-kill-outranks-a-declared-pattern",
        CampaignClass::Infra,
        classify(
            &planted(
                RunFacts::ok().exit(128 + SIGKILL).signal(SIGKILL),
                "CORRUPTION detected",
            ),
            &declares_violation,
        ),
    );
    // -- the GUEST_ABORT / FAIL_CLOSED_ABORT split (arc §4.4) ----------------
    // The same SIGABRT lands in two different classes depending on ONE envelope
    // field: whether patina attributed the failure to itself.
    check(
        "guest-abort-unattributed-sigabrt",
        CampaignClass::GuestAbort,
        classify(
            &planted(RunFacts::ok().exit(SIGABRT_EXIT).signal(SIGABRT), ""),
            &no_rules,
        ),
    );
    check(
        "guest-abort-enriched-by-an-abort-intent-verdict",
        CampaignClass::GuestAbort,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .verdict("abort_intent", "checksum"),
                "",
            ),
            &no_rules,
        ),
    );
    // A family whose supervisor sees only a code still splits on the refusal.
    check(
        "guest-abort-exit-134-without-a-signal",
        CampaignClass::GuestAbort,
        classify(&planted(RunFacts::ok().exit(SIGABRT_EXIT), ""), &no_rules),
    );
    // RED twin: the SAME abort WITH a patina refusal is patina's fault, not the
    // guest's — this is the split the arc calls for.
    check(
        "fail-closed-abort-is-the-same-sigabrt-with-a-refusal",
        CampaignClass::FailClosedAbort,
        classify(
            &planted(
                RunFacts::ok()
                    .exit(SIGABRT_EXIT)
                    .signal(SIGABRT)
                    .refusal("buggify_duplicate_label"),
                "",
            ),
            &no_rules,
        ),
    );
    check(
        "fail-closed-refusal-without-an-abort",
        CampaignClass::FailClosedAbort,
        classify(
            &planted(RunFacts::ok().exit(2).refusal("fingerprint_mismatch"), ""),
            &no_rules,
        ),
    );

    // -- the supervisor backstops --------------------------------------------
    check(
        "starvation-stall-exit-111",
        CampaignClass::StarvationStall,
        classify(
            &planted(RunFacts::ok().exit(STARVATION_STALL_EXIT).no_envelope(), ""),
            &no_rules,
        ),
    );
    check(
        "starvation-stall-refusal-class",
        CampaignClass::StarvationStall,
        classify(
            &planted(RunFacts::ok().exit(2).refusal("starvation_stall"), ""),
            &no_rules,
        ),
    );
    check(
        "infra-wall-clock-timeout",
        CampaignClass::Infra,
        classify(&planted(RunFacts::ok().timed_out(), ""), &no_rules),
    );
    // A child that never produced a result envelope is patina's own harness
    // failing (a build error, a pre-run gate refusal), not a SUT finding.
    check(
        "infra-child-produced-no-envelope",
        CampaignClass::Infra,
        classify(
            &planted(
                RunFacts::ok().exit(2).no_envelope(),
                "cargo-patina: could not compile foo",
            ),
            &no_rules,
        ),
    );
    check(
        "bare-nonzero-is-unclassified-not-ok",
        CampaignClass::Unclassified,
        classify(&planted(RunFacts::ok().exit(2), ""), &no_rules),
    );

    // -- spec-declared rules for a level-1 guest (arc §4.3) ------------------
    // The grep mechanism survives only as explicit per-guest configuration.
    let declared = declared_rules_fixture();
    check(
        "declared-pattern-classifies-a-level-1-guest",
        CampaignClass::Violation,
        classify(
            &planted(RunFacts::ok(), "GUEST: checksum mismatch on page 7"),
            &declared,
        ),
    );
    // RED twin: the identical output with NO declared rule stays OK — the
    // pattern, not the text, is what classifies.
    check(
        "declared-pattern-red-without-the-rule",
        CampaignClass::Ok,
        classify(
            &planted(RunFacts::ok(), "GUEST: checksum mismatch on page 7"),
            &no_rules,
        ),
    );
    check(
        "declared-exit-code-classifies-a-level-1-guest",
        CampaignClass::Violation,
        classify(&planted(RunFacts::ok().exit(3), ""), &declared),
    );
    check(
        "declared-exit-code-red-without-the-rule",
        CampaignClass::Unclassified,
        classify(&planted(RunFacts::ok().exit(3), ""), &no_rules),
    );
    // Declared rules ADD findings; they never downgrade one the envelope made.
    check(
        "declared-rules-never-downgrade-an-envelope-finding",
        CampaignClass::Liveness,
        classify(
            &planted(
                RunFacts::ok().exit(3).finding("liveness", "no_progress"),
                "GUEST: checksum mismatch on page 7",
            ),
            &declared,
        ),
    );

    // Non-vacuity: every class the campaign can report must have been fired
    // above through the structured channel. A class nobody proved reachable is
    // a class nobody can trust.
    println!("-- class coverage --");
    for class in CampaignClass::ALL {
        if fired.contains(class.as_str()) {
            println!("  ok   {:<40} -> fired", class.as_str());
        } else {
            println!(
                "  FAIL {:<40} -> never fired in the selftest",
                class.as_str()
            );
            failures += 1;
        }
    }

    // Signature dedup + novelty, from the same structured facts.
    println!("-- signature dedup --");
    // A guest finding recovered from under a recorder failure keeps the guest's
    // own shape, plus the standing note that its trace was never written — so
    // the printed `reproduce` command cannot promise a replay that has no
    // artifact behind it.
    let unusable = signature(
        CampaignClass::Unclassified,
        &planted(
            RunFacts::ok()
                .exit(SIGABRT_EXIT)
                .signal(SIGABRT)
                .refusal("shutdown_failure")
                .guest_exit(101),
            "thread 'main' panicked at src/x.rs:1:1:\nboom\n",
        ),
    );
    if unusable.shape.ends_with(" trace=unusable") {
        println!(
            "  ok   shutdown-failure-shape-flags-the-unusable-trace -> {}",
            unusable.shape
        );
    } else {
        println!("  FAIL shutdown-failure-shape-flags-the-unusable-trace -> {unusable:?}");
        failures += 1;
    }
    let a = signature(
        CampaignClass::Liveness,
        &planted(
            RunFacts::ok().exit(1).finding("liveness", "no_progress"),
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600",
        ),
    );
    let b = signature(
        CampaignClass::Liveness,
        &planted(
            RunFacts::ok().exit(1).finding("liveness", "no_progress"),
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=999999 budget_ns=600",
        ),
    );
    if a.key() == b.key() {
        println!(
            "  ok   run-specific-values-dedup             -> {}",
            a.key()
        );
    } else {
        println!(
            "  FAIL run-specific-values-dedup             -> {} vs {}",
            a.key(),
            b.key()
        );
        failures += 1;
    }
    let c = signature(
        CampaignClass::Violation,
        &planted(RunFacts::ok().verdict("violation", "two-leaders"), ""),
    );
    if a.key() != c.key() {
        println!("  ok   distinct-findings-distinct-signatures -> ok");
    } else {
        println!("  FAIL distinct-findings-distinct-signatures");
        failures += 1;
    }
    // Two violations under DIFFERENT verdict labels are different bugs.
    let other = signature(
        CampaignClass::Violation,
        &planted(RunFacts::ok().verdict("violation", "lost-update"), ""),
    );
    if c.key() != other.key() {
        println!("  ok   verdict-label-distinguishes           -> ok");
    } else {
        println!("  FAIL verdict-label-distinguishes");
        failures += 1;
    }
    // A policy bug-depth annotation distinguishes otherwise-identical findings.
    let shallow = signature(
        CampaignClass::Violation,
        &planted(
            RunFacts::ok().verdict("violation", "x"),
            "PATINA_SCHEDULE_POLICY pct=1 bug_depth=1 decisions=10",
        ),
    );
    let deep = signature(
        CampaignClass::Violation,
        &planted(
            RunFacts::ok().verdict("violation", "x"),
            "PATINA_SCHEDULE_POLICY pct=1 bug_depth=5 decisions=10",
        ),
    );
    if shallow.key() != deep.key() {
        println!("  ok   bug-depth-annotation-distinguishes    -> ok");
    } else {
        println!("  FAIL bug-depth-annotation-distinguishes");
        failures += 1;
    }
    // An UNCLASSIFIED generation has no structured shape. The envelope's
    // `result_line` (the guest's own finding) must win over the raw output's
    // last line, which is a supervisor diagnostic the child appended after the
    // guest finished — otherwise every such failure under a note-emitting host
    // (the deny-trap-armed symbol note on Linux) dedups to the NOTE, not the bug.
    let supervisor_note = "note: 24 linked symbol(s) are deny-trap armed under patina \
(a call aborts deterministically): fork (process), waitpid (process)";
    let shadowed = signature(
        CampaignClass::Unclassified,
        &GenerationFacts {
            facts: RunFacts::ok().exit(1),
            output: format!("\nError: AlreadyInstalled\n{supervisor_note}\n"),
            result_line: Some("Error: AlreadyInstalled".to_string()),
        },
    );
    if shadowed.shape == "Error: AlreadyInstalled" {
        println!(
            "  ok   result-line-beats-supervisor-note     -> {}",
            shadowed.key()
        );
    } else {
        println!(
            "  FAIL result-line-beats-supervisor-note     -> shape {:?}",
            shadowed.shape
        );
        failures += 1;
    }
    // The runtime's OWN end-of-run reports print on the GUEST's stderr, after the
    // guest's last word, so they reach the shape through BOTH paths: the run
    // verb's `result_line` (its last-stderr-line fallback picks one up) and the
    // captured output's last line. Each embeds per-generation counters, so a
    // shape taken from one is unique per generation and every repeat of the SAME
    // failure files as NOVEL. The guest's own last meaningful line must win.
    let guest_error = "Error: SqliteFailure(Error { code: SystemIoFailure, \
extended_code: 5386 }, Some(\"disk I/O error\"))";
    let reports = |activated: u32, edges: u32| {
        format!(
            "PATINA_SCHEDULE_REPORT tasks_spawned=3 boundaries={edges}\n\
             PATINA_SDK_REPORT enabled=1 sites_registered=160 \
sites_activated={activated} site=core/storage/btree.rs:12:9:page_should_be_loaded\
|always|a1|e{edges}|f0\n"
        )
    };
    // What the campaign appends after the guest's streams: the child supervisor's
    // OWN stderr, whose pre-run advisory block is chronologically first and
    // textually last.
    let supervisor_block = "patina: 3 direct-syscall instruction site(s) in /tmp/guest are \
SUD-managed: trapped into the deterministic runtime via syscall-user-dispatch.\n\
patina: WARNING: running /tmp/guest with 2 UNSUPPORTED symbol(s) downgraded from error by \
--allow-unsupported-symbols:\n\
patina:   qsort (effect)\n\
patina:     provenance=direct call from guest\n\
patina: these host symbols are NOT interposed by the deterministic runtime; if the guest \
reaches them at run time it can block, read host time, or otherwise escape the scheduler.\n\
note: 24 linked symbol(s) are deny-trap armed under patina (a call aborts deterministically): \
fork (process)\n";
    let shadowed_by_report = |activated: u32, edges: u32| {
        signature(
            CampaignClass::Unclassified,
            &GenerationFacts {
                facts: RunFacts::ok().exit(1),
                output: format!(
                    "{guest_error}\n{}{supervisor_block}",
                    reports(activated, edges)
                ),
                // What the run verb's last-stderr-line fallback actually returns
                // for this guest: the runtime's report, not the guest's finding.
                result_line: reports(activated, edges)
                    .lines()
                    .next_back()
                    .map(str::to_string),
            },
        )
    };
    let first = shadowed_by_report(33, 400);
    let second = shadowed_by_report(35, 917);
    if first.shape.starts_with("Error: SqliteFailure")
        && !first.shape.contains("PATINA_")
        && !first.shape.contains("patina:")
    {
        println!(
            "  ok   runtime-report-never-shadows-guest   -> {}",
            first.key()
        );
    } else {
        println!(
            "  FAIL runtime-report-never-shadows-guest   -> shape {:?}",
            first.shape
        );
        failures += 1;
    }
    if first.key() == second.key() {
        println!("  ok   runtime-report-counters-still-dedup  -> 1 signature");
    } else {
        println!(
            "  FAIL runtime-report-counters-still-dedup  -> {:?} vs {:?}",
            first.shape, second.shape
        );
        failures += 1;
    }
    // The whole family is skipped by shape, not by one hardcoded prefix, and the
    // markers that ARE evidence are never skipped.
    let family = [
        "PATINA_SCHEDULE_REPORT a=1",
        "PATINA_SCHEDULE_POLICY pct=1 bug_depth=2",
        "PATINA_SWARM_REPORT drawn=2",
        "PATINA_LIVENESS_REPORT armed=1",
        "PATINA_SDK_REPORT enabled=1",
        "PATINA_FS_FAULT_REPORT errors=3",
        "PATINA_DNS_FAULT_REPORT errors=0",
        "PATINA_NET_FAULT_REPORT drops=1",
        "PATINA_ENTROPY_FAULT_REPORT failures=1",
        "PATINA_CLOCK_FAULT_REPORT jumps=1",
        "PATINA_CUSTOMOP_FAULT_REPORT refusals=1",
        "PATINA_COVERAGE_REPORT edges=9",
        "PATINA_DEPTH_REPORT family=wasi fuel_consumed=7 hostcalls_total=0",
        "PATINA_LIFECYCLE setup_complete",
        "PATINA_LIFECYCLE_EVENT label=x",
        "note: 24 linked symbol(s) are deny-trap armed under patina",
        "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
        "patina: WARNING: running /tmp/guest with 2 UNSUPPORTED symbol(s) downgraded",
        "patina:   qsort (effect)",
        "patina:     provenance=direct call from guest",
        "patina: these host symbols are NOT interposed by the deterministic runtime; if the \
guest reaches them at run time it can block, read host time, or otherwise escape the scheduler.",
        "patina: 3 direct-syscall instruction site(s) in /tmp/guest are SUD-managed: trapped \
into the deterministic runtime via syscall-user-dispatch.",
        "patina: 2 timestamp-counter instruction site(s) in /tmp/guest are trapped",
    ];
    let evidence = [
        "PATINA_RESULT ok=0",
        "PATINA_VIOLATION lost-update",
        "PATINA_VERDICT kind=violation label=x",
        "PATINA_INFRA reason=x",
        "PATINA_FRAMEWORK_TRAP symbol=fork",
        "PATINA_CUSTOM_OP_REFUSED name=x",
        "PATINA_BUGGIFY_DUPLICATE_LABEL label=x",
        "patina: campaign generation exceeded timeout_secs=5",
        // Fail-closed refusals: patina's own lines, but they ARE the cause of
        // death, and `output.rs`'s `REFUSAL_CLASSES` structures only some of
        // them — the rest reach a signature only through this fallback.
        "patina: epoll_pwait with a signal mask is not modeled; failing closed",
        "patina: always! invariant violated: label=page_should_be_loaded",
        "patina: step budget of 100 boundary operations was exhausted",
        "patina: the deterministic runtime failed to initialize: fingerprint mismatch",
        "patina: interposed call before deterministic runtime initialization",
        "patina: starvation stall",
        "cargo-patina: could not compile guest",
        "Error: disk I/O error",
    ];
    let missed: Vec<&str> = family
        .iter()
        .copied()
        .filter(|line| !is_runtime_diagnostic(line))
        .chain(
            evidence
                .iter()
                .copied()
                .filter(|line| is_runtime_diagnostic(line)),
        )
        .collect();
    if missed.is_empty() {
        println!(
            "  ok   runtime-diagnostic-family-covered    -> {} diagnostic / {} evidence",
            family.len(),
            evidence.len()
        );
    } else {
        println!("  FAIL runtime-diagnostic-family-covered    -> misjudged {missed:?}");
        failures += 1;
    }
    // Output that is NOTHING but diagnostics still gets a shape: an empty one
    // would collapse every such generation into one meaningless signature.
    let all_diagnostic = signature(
        CampaignClass::Unclassified,
        &planted(
            RunFacts::ok().exit(1),
            "PATINA_SCHEDULE_REPORT tasks_spawned=3\nPATINA_SDK_REPORT enabled=1\n",
        ),
    );
    if all_diagnostic.shape == "PATINA_SDK_REPORT enabled=#" {
        println!(
            "  ok   all-diagnostic-output-keeps-a-shape  -> {}",
            all_diagnostic.key()
        );
    } else {
        println!(
            "  FAIL all-diagnostic-output-keeps-a-shape  -> shape {:?}",
            all_diagnostic.shape
        );
        failures += 1;
    }
    // Every host kill dedups onto ONE signature, whatever the guest had printed
    // when the kernel took it away — it must not spray novel signatures.
    let killed = |tail: &str| {
        signature(
            CampaignClass::Infra,
            &planted(RunFacts::ok().exit(128 + SIGKILL).signal(SIGKILL), tail),
        )
    };
    let first_kill = killed("inserting row 8123\n");
    if first_kill.shape == HOST_KILL_SHAPE && first_kill.key() == killed("checkpoint 41\n").key() {
        println!(
            "  ok   host-kill-has-one-stable-shape        -> {}",
            first_kill.key()
        );
    } else {
        println!(
            "  FAIL host-kill-has-one-stable-shape        -> shape {:?}",
            first_kill.shape
        );
        failures += 1;
    }
    // The same bargain for a failed trace channel: every generation that loses
    // its trace channel must collapse onto ONE signature. Each such run's own
    // message names its own randomly named scratch path, so without a shared shape a
    // single environmental problem reads as one novel finding per generation —
    // which is exactly what it did on this campaign's B02 (26) and B08 (16).
    let channel_lost = |tail: &str| {
        signature(
            CampaignClass::Infra,
            &planted(
                RunFacts::ok()
                    .exit(2)
                    .refusal(TRACE_UNAVAILABLE_CLASS)
                    .guest_exit(0),
                tail,
            ),
        )
    };
    let first_loss = channel_lost(
        "PATINA_INFRA native_run trace=incomplete trace_path=\"a/generation-1.patina\"          reason=\"failed to open trace a/.generation-1.patina.tmp.11.0\"\n",
    );
    if first_loss.shape == format!("refusal class={TRACE_UNAVAILABLE_CLASS}")
        && first_loss.key()
            == channel_lost(
                "PATINA_INFRA native_run trace=incomplete trace_path=\"a/generation-77.patina\"                  reason=\"failed to open trace a/.generation-77.patina.tmp.22.0\"\n",
            )
            .key()
    {
        println!(
            "  ok   trace-channel-loss-has-one-shape      -> {}",
            first_loss.key()
        );
    } else {
        println!(
            "  FAIL trace-channel-loss-has-one-shape      -> shape {:?}",
            first_loss.shape
        );
        failures += 1;
    }
    // A timed-out generation is host-killed too (the backstop uses SIGKILL), but
    // WHY it died is the finding there, so it keeps the timeout marker.
    let timed_out_kill = signature(
        CampaignClass::Infra,
        &planted(
            RunFacts::ok()
                .no_envelope()
                .timed_out()
                .exit(128 + SIGKILL)
                .signal(SIGKILL),
            "patina: campaign generation exceeded timeout_secs=5",
        ),
    );
    if timed_out_kill.shape == "patina: campaign generation exceeded timeout_secs=#" {
        println!(
            "  ok   timeout-keeps-its-own-shape           -> {}",
            timed_out_kill.shape
        );
    } else {
        println!(
            "  FAIL timeout-keeps-its-own-shape           -> shape {:?}",
            timed_out_kill.shape
        );
        failures += 1;
    }
    // A fault signal is a GUEST failure but not an abort: it never reached
    // `abort()` and never said anything. Name the signal rather than dedupping
    // every crash onto whatever text happened to be last.
    let segfault = signature(
        CampaignClass::Unclassified,
        &planted(
            RunFacts::ok().exit(128 + 11).signal(11),
            "inserting row 8123\nPATINA_SDK_REPORT enabled=1 sites_activated=7\n",
        ),
    );
    if segfault.shape == "guest_fault signal=SIGSEGV inserting row #" {
        println!(
            "  ok   fault-signal-names-the-signal         -> {}",
            segfault.shape
        );
    } else {
        println!(
            "  FAIL fault-signal-names-the-signal         -> shape {:?}",
            segfault.shape
        );
        failures += 1;
    }

    // An abort patina could not attribute structurally: `guest_abort
    // unattributed` alone made every distinct abort in a campaign ONE signature.
    // The guest's own last words are recovered instead, so two aborts at two
    // sites stay two findings.
    let aborted = |tail: &str| {
        signature(
            CampaignClass::GuestAbort,
            &planted(
                RunFacts::ok().exit(134).signal(SIGABRT),
                &format!("running the workload\n{tail}"),
            ),
        )
    };
    let panicked = |site: &str, thread: &str| {
        aborted(&format!(
            "thread '{thread}' ({}) panicked at {site}:\n\
             called `Result::unwrap()` on an `Err` value: PoisonError {{ .. }}\n\
             note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n\
             PATINA_SDK_REPORT enabled=1 sites_activated=7\n",
            2
        ))
    };
    let panic_shape = panicked("testing/stress/sql_logging.rs:74:35", "main");
    let want = "guest_abort unattributed panic thread=main \
at=testing/stress/sql_logging.rs:#:# msg=called `Result::unwrap()` on an `Err` value: \
PoisonError { .. }";
    if panic_shape.shape == want {
        println!(
            "  ok   guest-abort-recovers-the-panic-site   -> {}",
            panic_shape.shape
        );
    } else {
        println!("  FAIL guest-abort-recovers-the-panic-site   -> shape {panic_shape:?}");
        failures += 1;
    }
    if panic_shape.key() != panicked("core/storage/btree.rs:12:9", "main").key()
        && panic_shape.key() != panicked("testing/stress/sql_logging.rs:74:35", "worker").key()
    {
        println!("  ok   guest-abort-splits-by-site-and-thread -> 3 signatures");
    } else {
        println!("  FAIL guest-abort-splits-by-site-and-thread");
        failures += 1;
    }
    // No panic: patina's OWN abort diagnostics are the attribution, and are
    // deliberately not filtered as runtime noise.
    let infra_abort = aborted(
        "Error: disk I/O error\n\
         PATINA_SDK_REPORT enabled=1 sites_activated=7\n\
         patina: runtime shutdown failed: trace resource limit exceeded: timeline main has \
3103466 events; limit is 1000000\n\
         PATINA_INFRA native_run signal=6 trace=incomplete reason=\"record finalization did not \
complete\"\n",
    );
    if infra_abort
        .shape
        .starts_with("guest_abort unattributed PATINA_INFRA native_run signal=#")
    {
        println!(
            "  ok   guest-abort-keeps-patinas-own-diagnostic -> {}",
            infra_abort.shape
        );
    } else {
        println!(
            "  FAIL guest-abort-keeps-patinas-own-diagnostic -> shape {:?}",
            infra_abort.shape
        );
        failures += 1;
    }
    // A cooperative `abort_intent` verdict still wins over any recovered text.
    let claimed = signature(
        CampaignClass::GuestAbort,
        &planted(
            RunFacts::ok()
                .exit(134)
                .signal(SIGABRT)
                .verdict("abort_intent", "checksum"),
            "thread 'main' panicked at src/x.rs:1:1:\nboom\n",
        ),
    );
    if claimed.shape == "guest_abort label=checksum" {
        println!(
            "  ok   abort-intent-still-beats-recovery    -> {}",
            claimed.shape
        );
    } else {
        println!(
            "  FAIL abort-intent-still-beats-recovery    -> shape {:?}",
            claimed.shape
        );
        failures += 1;
    }
    // Without an envelope there is no result line: the raw output's last line is
    // the shape (the INFRA timeout marker relies on exactly this).
    let raw = signature(
        CampaignClass::Infra,
        &planted(
            RunFacts::ok().no_envelope().timed_out(),
            "some guest line\npatina: campaign generation exceeded timeout_secs=5",
        ),
    );
    if raw.shape == "patina: campaign generation exceeded timeout_secs=#" {
        println!(
            "  ok   no-envelope-falls-back-to-last-line   -> {}",
            raw.key()
        );
    } else {
        println!(
            "  FAIL no-envelope-falls-back-to-last-line   -> shape {:?}",
            raw.shape
        );
        failures += 1;
    }

    println!("-- coverage gate --");
    let mut coverage_check = |name: &str,
                              tally: &CoverageTally,
                              waiver: Option<AllowUnmetSometimes>,
                              want_gate: CoverageGate,
                              want_unmet: usize| {
        let verdict = coverage_verdict(tally, waiver);
        if verdict.gate == want_gate && verdict.summary.unmet.len() == want_unmet {
            println!(
                "  ok   {name:<40} -> gate={} unmet={}",
                verdict.gate.as_str(),
                verdict.summary.unmet.len()
            );
        } else {
            println!(
                "  FAIL {name:<40} -> gate={} unmet={} (want gate={} unmet={})",
                verdict.gate.as_str(),
                verdict.summary.unmet.len(),
                want_gate.as_str(),
                want_unmet
            );
            failures += 1;
        }
    };
    let unmet = coverage_fixture(false).expect("unmet coverage fixture parses");
    let met = coverage_fixture(true).expect("met coverage fixture parses");
    coverage_check("sometimes-met-passes", &met, None, CoverageGate::Pass, 0);
    coverage_check("sometimes-unmet-fails", &unmet, None, CoverageGate::Fail, 1);
    coverage_check(
        "sometimes-unmet-waived-bare",
        &unmet,
        Some(AllowUnmetSometimes::Always),
        CoverageGate::Waived,
        1,
    );
    coverage_check(
        "sometimes-unmet-waived-under-threshold",
        &unmet,
        Some(AllowUnmetSometimes::BelowGenerations(3)),
        CoverageGate::Waived,
        1,
    );
    coverage_check(
        "sometimes-unmet-enforced-at-threshold",
        &unmet,
        Some(AllowUnmetSometimes::BelowGenerations(2)),
        CoverageGate::Fail,
        1,
    );
    let declared_reachable =
        declared_reachable_fixture().expect("declared reachable fixture parses");
    coverage_check(
        "declared-reachable-unreached-fails",
        &declared_reachable,
        None,
        CoverageGate::Fail,
        1,
    );
    let mut malformed = CoverageTally::default();
    match malformed.observe_generation(
        0,
        1,
        "PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-",
    ) {
        Ok(()) => {
            println!("  FAIL malformed-coverage-row-rejected       -> parsed");
            failures += 1;
        }
        Err(error) if error.contains("expected 10 pipe-separated fields") => {
            println!("  ok   malformed-coverage-row-rejected       -> loud error");
        }
        Err(error) => {
            println!("  FAIL malformed-coverage-row-rejected       -> {error}");
            failures += 1;
        }
    }

    println!("-- native edge coverage store --");
    for (name, ok, detail) in crate::coverage::campaign_detector_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!("-- wasi depth store --");
    for (name, ok, detail) in crate::depth::campaign_detector_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!("-- fault intensity scaling (--fault-scale-permille) --");
    for (name, ok, detail) in fault_scale_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!("-- starvation intensity scaling (--starve-scale-permille) --");
    for (name, ok, detail) in starve_scale_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!("-- guided generation scheduling --");
    for (name, ok, detail) in crate::guided::campaign_detector_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!();
    if failures == 0 {
        println!("CAMPAIGN SELFTEST PASSED");
        Ok(0)
    } else {
        println!("CAMPAIGN SELFTEST FAILED ({failures} checks)");
        Ok(1)
    }
}

fn coverage_fixture(satisfied: bool) -> Result<CoverageTally, String> {
    let mut tally = CoverageTally::default();
    let bit = if satisfied { 1 } else { 0 };
    tally.observe_generation(
        0,
        100,
        &format!(
            "PATINA_SDK_REPORT enabled=1 site=oracle|sometimes|a0|e4|f0|r1|s{bit}|v0|k-|@src/main.rs:10"
        ),
    )?;
    tally.observe_generation(
        1,
        101,
        "PATINA_SDK_REPORT enabled=1 site=faulty|fault|a1|e1|f1|r1|s0|v0|k-|@src/main.rs:11",
    )?;
    Ok(tally)
}

fn declared_reachable_fixture() -> Result<CoverageTally, String> {
    let mut tally = CoverageTally::default();
    tally.observe_generation(
        0,
        200,
        "PATINA_SDK_REPORT enabled=1 sites_declared=1 declared_site=never|reachable|@src/main.rs:12",
    )?;
    Ok(tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest().unwrap(), 0);
    }
}
