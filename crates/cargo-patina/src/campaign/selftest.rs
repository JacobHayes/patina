//! Planted campaign classifier and exploration detector checks.

mod scaling;

use super::classify::{HOST_KILL_SHAPE, is_runtime_diagnostic};
use super::generation::SIGKILL;
use super::report::{CoverageGate, coverage_verdict};
use super::spec::json_classify_rules;
use super::verify::{selftest_class_checks, selftest_sampling};
use super::{
    ClassifyRules, FindingFacts, GenerationFacts, RunClass, RunFacts, VerdictFacts, classify,
    signature,
};
use crate::sdk_report::CoverageTally;
use scaling::fault_scale_selftest;

// ===========================================================================
// Selftest
// ===========================================================================

/// A planted generation for the selftest: structured facts plus the captured
/// output only the spec-declared matcher may read.
pub(super) fn planted(facts: RunFacts, output: &str) -> GenerationFacts {
    GenerationFacts {
        facts,
        output: output.to_string(),
        guest_output: None,
        stop_detail: None,
        result_line: None,
        exact_verdicts: Vec::new(),
        bug_depth: None,
    }
}

impl RunFacts {
    /// A clean, envelope-carrying generation — the base every selftest fixture
    /// mutates by exactly the one fact it is proving. The builders below keep
    /// `class` what the generation's own run would have reported for the
    /// facts planted, since the campaign reads that class rather than
    /// re-deriving it.
    pub(super) fn ok() -> Self {
        RunFacts {
            envelope: true,
            class: Some(RunClass::Ok),
            guest_exit_code: Some(0),
            ..RunFacts::default()
        }
    }

    /// The guest's own exit status: a nonzero one is a `failure`, and the
    /// child's own status follows the class.
    pub(super) fn exit(mut self, code: i32) -> Self {
        self.guest_exit_code = Some(code);
        if code != 0 && self.class == Some(RunClass::Ok) {
            self.class = Some(RunClass::Failure);
        }
        self.exit_code = self.class.map_or(2, RunClass::exit_code);
        self
    }

    /// The guest died on `signal`: a `crash`, unless a finding or a stop
    /// already says why.
    pub(super) fn signal(mut self, signal: i32) -> Self {
        self.signal = Some(signal);
        if matches!(self.class, Some(RunClass::Ok | RunClass::Failure)) {
            self.class = Some(RunClass::Crash);
        }
        self.exit_code = self.class.map_or(2, RunClass::exit_code);
        self
    }

    /// The child `patina run` itself was killed from outside.
    pub(super) fn killed_from_outside(mut self) -> Self {
        self.child_signal = Some(SIGKILL);
        self.signal = Some(SIGKILL);
        self.exit_code = -1;
        self
    }

    pub(super) fn timed_out(mut self) -> Self {
        self.timed_out = true;
        self
    }

    pub(super) fn no_envelope(mut self) -> Self {
        self.envelope = false;
        self.class = None;
        self
    }

    /// The run was stopped for `reason` under `class`.
    pub(super) fn stopped(mut self, class: RunClass, reason: &str) -> Self {
        self.class = Some(class);
        self.stop = Some(reason.to_string());
        self.exit_code = class.exit_code();
        self
    }

    /// The run's recording was lost under a class that is the guest's own.
    pub(super) fn trace_unusable(mut self) -> Self {
        self.trace_unusable = true;
        self
    }

    pub(super) fn verdict(mut self, kind: &str, label: &str) -> Self {
        self.verdicts.push(VerdictFacts {
            kind: kind.to_string(),
            label: label.to_string(),
        });
        if kind == "violation" {
            self.class = Some(RunClass::Violation);
            self.exit_code = RunClass::Violation.exit_code();
        }
        self
    }

    pub(super) fn finding(mut self, source: &str, kind: &str) -> Self {
        self.findings.push(FindingFacts {
            source: source.to_string(),
            kind: kind.to_string(),
            known_limit: false,
        });
        if source == "liveness" {
            self.class = Some(RunClass::Liveness);
            self.exit_code = RunClass::Liveness.exit_code();
        }
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
        "patterns": {"violation": ["checksum mismatch"]},
        "exit_codes": {"violation": [3]},
    }))
    .expect("the selftest's declared rules must parse")
}

/// Every classifier class is reachable from the structured envelope facts
/// (with the spec-declared rules as the only text-reading path), and the
/// signature store dedups repeats and flags novel signatures.
#[test]
fn classifier_and_detector_checks() {
    let mut failures = 0u32;
    let mut check = |name: &str, want: RunClass, got: RunClass| {
        if want == got {
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

    // Every class must be proven fireable through the STRUCTURED channel, and
    // every class-deciding fact must be proven load-bearing: each check below is
    // paired with a red twin that removes exactly the one fact and lands
    // somewhere else. A check that cannot fail is a bug.
    // A generation's class is the one its own `patina run` reported (the
    // run-side classification has its own table); these are the rules only the
    // campaign applies over it, each with the twin that lands somewhere else.
    let no_rules = ClassifyRules::default();
    let declared = declared_rules_fixture();
    const SIGABRT: i32 = 6;
    let level_one = "GUEST: checksum mismatch on page 7";
    for (name, want, facts, output, rules) in [
        ("clean", RunClass::Ok, RunFacts::ok(), "", &no_rules),
        // The run's own class passes through, whichever it is.
        (
            "the-runs-class-passes-through",
            RunClass::Unsupported,
            RunFacts::ok().stopped(RunClass::Unsupported, "not_modeled"),
            "",
            &no_rules,
        ),
        // The campaign's wall-clock backstop, whatever the child had reported.
        (
            "wall-clock-backstop",
            RunClass::Timeout,
            RunFacts::ok().timed_out(),
            "",
            &no_rules,
        ),
        // A child killed from outside reported nothing the campaign can
        // stand on, whatever its envelope said before it died. Its twin is a
        // guest that died on a signal under a child that lived to report it.
        (
            "host-kill",
            RunClass::Internal,
            RunFacts::ok().killed_from_outside(),
            "",
            &no_rules,
        ),
        // The envelope's word is never taken over the process's: a child
        // that reported clean and then exited otherwise did not finish the
        // run it described.
        (
            "an-ok-envelope-over-a-failed-child",
            RunClass::Internal,
            RunFacts {
                exit_code: 1,
                ..RunFacts::ok()
            },
            "",
            &no_rules,
        ),
        (
            "host-kill-red-another-signal-is-the-guests",
            RunClass::Crash,
            RunFacts::ok().signal(SIGABRT),
            "",
            &no_rules,
        ),
        // A guest that RETURNS 137 deliberately is not host-killed: only a
        // real signal counts, or the rule would hide findings.
        (
            "host-kill-red-exit-137-without-a-signal",
            RunClass::Failure,
            RunFacts::ok().exit(137),
            "",
            &no_rules,
        ),
        // A child that reported no run at all is patina failing to report.
        (
            "no-envelope",
            RunClass::Internal,
            RunFacts::ok().exit(2).no_envelope(),
            "",
            &no_rules,
        ),
        // Inert planes are judged only on a run that otherwise passed.
        (
            "vacuous-plane",
            RunClass::Vacuous,
            RunFacts::ok().vacuous("net"),
            "",
            &no_rules,
        ),
        (
            "vacuous-red-a-failing-run-keeps-its-class",
            RunClass::Failure,
            RunFacts::ok().exit(4).vacuous("net"),
            "",
            &no_rules,
        ),
        (
            "vacuous-red-a-finding-keeps-its-class",
            RunClass::Violation,
            RunFacts::ok()
                .vacuous("swarm")
                .verdict("violation", "two-leaders"),
            "",
            &no_rules,
        ),
        // Spec-declared rules for a level-1 guest: the grep mechanism survives
        // only as explicit per-guest configuration, and only ADDS findings.
        (
            "declared-pattern",
            RunClass::Violation,
            RunFacts::ok(),
            level_one,
            &declared,
        ),
        (
            "declared-pattern-red-without-the-rule",
            RunClass::Ok,
            RunFacts::ok(),
            level_one,
            &no_rules,
        ),
        (
            "declared-exit-code",
            RunClass::Violation,
            RunFacts::ok().exit(3),
            "",
            &declared,
        ),
        (
            "declared-exit-code-red-without-the-rule",
            RunClass::Failure,
            RunFacts::ok().exit(3),
            "",
            &no_rules,
        ),
        (
            "declared-rules-never-downgrade-a-finding",
            RunClass::Liveness,
            RunFacts::ok().exit(3).finding("liveness", "no_progress"),
            level_one,
            &declared,
        ),
        (
            "declared-rules-never-reclaim-a-patina-stop",
            RunClass::Unsupported,
            RunFacts::ok().stopped(RunClass::Unsupported, "prerun_audit"),
            level_one,
            &declared,
        ),
        // A host kill outranks the guest's own output: a killed generation ran
        // no invariant to completion.
        (
            "host-kill-outranks-a-declared-pattern",
            RunClass::Internal,
            RunFacts::ok().killed_from_outside(),
            level_one,
            &declared,
        ),
    ] {
        check(name, want, classify(&planted(facts, output), rules));
    }

    // -- reproduction verification: the cross-run class -----------------------
    // Reached only by comparing a generation with a second run of it; each
    // comparison axis has a twin that differs there alone.
    for (name, want, got) in selftest_class_checks() {
        check(name, want, got);
    }

    // Signature dedup + novelty, from the same structured facts.
    println!("-- signature dedup --");
    // The signature names the inert planes: the same planes in any report
    // order share one signature, and different planes do not.
    let vacuous_signature = |facts: RunFacts| {
        let generation = planted(facts, "");
        signature(classify(&generation, &no_rules), &generation)
    };
    let dns_fs = vacuous_signature(RunFacts::ok().vacuous("dns").vacuous("fs"));
    let fs_dns = vacuous_signature(RunFacts::ok().vacuous("fs").vacuous("dns"));
    let dns = vacuous_signature(RunFacts::ok().vacuous("dns"));
    let fs = vacuous_signature(RunFacts::ok().vacuous("fs"));
    if dns_fs == fs_dns && dns != fs && dns != dns_fs {
        println!(
            "  ok   vacuous-signature-names-the-planes    -> {}",
            dns_fs.shape
        );
    } else {
        println!(
            "  FAIL vacuous-signature-names-the-planes    -> {dns_fs:?} {fs_dns:?} {dns:?} {fs:?}"
        );
        failures += 1;
    }
    // A guest finding recovered from under a recorder failure keeps the guest's
    // own shape, plus the standing note that its trace was never written — so
    // the printed `reproduce` command cannot promise a replay that has no
    // artifact behind it.
    let unusable = signature(
        RunClass::Failure,
        &planted(
            RunFacts::ok().exit(101).trace_unusable(),
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
        RunClass::Liveness,
        &planted(
            RunFacts::ok().exit(1).finding("liveness", "no_progress"),
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600",
        ),
    );
    let b = signature(
        RunClass::Liveness,
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
        RunClass::Violation,
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
        RunClass::Violation,
        &planted(RunFacts::ok().verdict("violation", "lost-update"), ""),
    );
    if c.key() != other.key() {
        println!("  ok   verdict-label-distinguishes           -> ok");
    } else {
        println!("  FAIL verdict-label-distinguishes");
        failures += 1;
    }
    // A policy bug-depth annotation distinguishes otherwise-identical findings.
    let at_depth = |depth: u64| {
        let mut generation = planted(RunFacts::ok().verdict("violation", "x"), "");
        generation.bug_depth = Some(depth);
        signature(RunClass::Violation, &generation)
    };
    let (shallow, deep) = (at_depth(1), at_depth(5));
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
        RunClass::Failure,
        &GenerationFacts {
            facts: RunFacts::ok().exit(1),
            output: format!("\nError: AlreadyInstalled\n{supervisor_note}\n"),
            guest_output: None,
            stop_detail: None,
            result_line: Some("Error: AlreadyInstalled".to_string()),
            exact_verdicts: Vec::new(),
            bug_depth: None,
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
            RunClass::Failure,
            &GenerationFacts {
                facts: RunFacts::ok().exit(1),
                output: format!(
                    "{guest_error}\n{}{supervisor_block}",
                    reports(activated, edges)
                ),
                // What the run verb's last-stderr-line fallback actually returns
                // for this guest: the runtime's report, not the guest's finding.
                guest_output: None,
                stop_detail: None,
                result_line: reports(activated, edges)
                    .lines()
                    .next_back()
                    .map(str::to_string),
                exact_verdicts: Vec::new(),
                bug_depth: None,
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
        "PATINA_COVERAGE_REPORT edges=9",
        "PATINA_LIFECYCLE setup_complete",
        "PATINA_LIFECYCLE_EVENT label=x",
        // The supervisor's restart summary carries both incarnations' host
        // pids, which differ on every run of one generation.
        "PATINA_CRASH_RESTART kind=machine host_pid0=41 host_pid1=42 result=restarted",
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
        "PATINA_BUGGIFY_DUPLICATE_LABEL label=x",
        "PATINA_CRASH_REPLAY_DIVERGENCE kind=machine the replay crashed after 9 operations",
        "patina: campaign generation exceeded timeout_secs=5",
        // Fail-closed refusals: patina's own lines, but they ARE the cause of
        // death, and `output.rs`'s `REFUSAL_CLASSES` structures only some of
        // them — the rest reach a signature only through this fallback.
        "patina: epoll_pwait with a signal mask is not modeled; failing closed",
        "patina: always! invariant violated: label=page_should_be_loaded",
        "patina: step budget of 100 boundary operations was exhausted",
        "patina: the deterministic runtime failed to initialize: fingerprint mismatch",
        "patina: interposed call before deterministic runtime initialization",
        "patina: could not compile guest",
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
        RunClass::Failure,
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
            RunClass::Internal,
            &planted(RunFacts::ok().killed_from_outside(), tail),
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
            RunClass::Internal,
            &planted(
                RunFacts::ok().stopped(RunClass::Internal, crate::output::TRACE_UNAVAILABLE_STOP),
                tail,
            ),
        )
    };
    let first_loss = channel_lost(
        "PATINA_INFRA native_run trace=incomplete trace_path=\"a/generation-1.patina\"          reason=\"failed to open trace a/.generation-1.patina.tmp.11.0\"\n",
    );
    if first_loss.shape == format!("stop reason={}", crate::output::TRACE_UNAVAILABLE_STOP)
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
        RunClass::Timeout,
        &planted(
            RunFacts::ok().no_envelope().timed_out().signal(SIGKILL),
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
        RunClass::Crash,
        &planted(
            RunFacts::ok().signal(11),
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
            RunClass::Crash,
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
         PATINA_INFRA native_run trace=incomplete reason=\"record finalization did not \
complete\"\n",
    );
    if infra_abort
        .shape
        .starts_with("guest_abort unattributed PATINA_INFRA native_run trace=incomplete")
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
    // A deterministic fault, observed and then reproduced: the supervisor's
    // marker names each run's own trace and scratch file, and neither may reach
    // the evidence.
    let faulted = |trace: &str, scratch: &str| {
        let marker = format!(
            "PATINA_INFRA native_run trace=incomplete trace_path=\"out/traces/{trace}\" \
reason=\"incomplete trace out/traces/.{trace}.tmp.{scratch}: empty trace file\""
        );
        let generation = planted(RunFacts::ok().signal(11), &format!("{marker}\n"));
        (
            signature(RunClass::Crash, &generation).key(),
            super::classify::primary_finding(RunClass::Crash, &generation),
        )
    };
    let observed = faulted("generation-0.patina", "3f19a522fbd5938d");
    let reproduced = faulted("generation-0.verify.patina", "79f652e981513a58");
    if observed == reproduced && observed.1.contains("signal=SIGSEGV") {
        println!(
            "  ok   fault-marker-paths-are-not-evidence      -> {}",
            observed.1
        );
    } else {
        println!(
            "  FAIL fault-marker-paths-are-not-evidence      -> {observed:?} vs {reproduced:?}"
        );
        failures += 1;
    }
    // A cooperative `abort_intent` verdict still wins over any recovered text.
    let claimed = signature(
        RunClass::Crash,
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
        RunClass::Timeout,
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
                              waiver: bool,
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
    coverage_check("sometimes-met-passes", &met, false, CoverageGate::Pass, 0);
    coverage_check(
        "sometimes-unmet-fails",
        &unmet,
        false,
        CoverageGate::Fail,
        1,
    );
    coverage_check(
        "sometimes-unmet-waived",
        &unmet,
        true,
        CoverageGate::Waived,
        1,
    );
    let declared_reachable =
        declared_reachable_fixture().expect("declared reachable fixture parses");
    coverage_check(
        "declared-reachable-unreached-fails",
        &declared_reachable,
        false,
        CoverageGate::Fail,
        1,
    );

    println!("-- native edge coverage store --");
    for (name, ok, detail) in crate::coverage::detectors::campaign_detector_selftest() {
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

    println!("-- clean-rerun sampling (reproduction verification) --");
    for (name, ok, detail) in selftest_sampling() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    assert_eq!(
        failures, 0,
        "failing checks are marked FAIL in the output above"
    );
}

fn coverage_fixture(satisfied: bool) -> Result<CoverageTally, String> {
    let mut tally = CoverageTally::default();
    let site = |label: &str, kind: &str, line: u32, fires: u64, satisfied: bool| {
        serde_json::json!({"sites": [{
            "label": label, "kind": kind, "site": format!("src/main.rs:{line}"),
            "active": fires > 0, "evals": if fires > 0 { 1 } else { 4 }, "fires": fires,
            "reachable": true, "sometimes_satisfied": satisfied, "always_violated": false,
            "knob": null,
        }]})
    };
    tally.observe_generation(0, 100, Some(&site("oracle", "sometimes", 10, 0, satisfied)))?;
    tally.observe_generation(1, 101, Some(&site("faulty", "fault", 11, 1, false)))?;
    Ok(tally)
}

fn declared_reachable_fixture() -> Result<CoverageTally, String> {
    let mut tally = CoverageTally::default();
    tally.observe_generation(
        0,
        200,
        Some(&serde_json::json!({"declared_sites": [
            {"label": "never", "kind": "reachable", "site": "src/main.rs:12"}
        ]})),
    )?;
    Ok(tally)
}
