//! Tests for cooperative fault sites, verdicts, and application oracles.

use crate::buggify::{Buggify, BuggifyKind, SiteOutcome, label_hash};
use crate::config::{BuggifyConfig, RuntimeConfig};
use crate::{Context, DEFAULT_BUGGIFY_CUTOFF_NANOS, DEFAULT_BUGGIFY_FIRE_PERMILLE, VerdictKind};
use patina_dst_abi::Operation;

use patina_dst_trace::TraceBundle;
use tempfile::tempdir;

fn buggify_context(seed: u64, config: BuggifyConfig) -> Context {
    Context::from_config(RuntimeConfig::seeded(seed).with_buggify(config)).unwrap()
}

const BUGGIFY_ALL_ACTIVE: BuggifyConfig = BuggifyConfig {
    enabled: true,
    fire_permille: DEFAULT_BUGGIFY_FIRE_PERMILLE,
    activation_permille: 1000,
    cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
    after_setup: false,
};

#[test]
fn buggify_activation_is_a_deterministic_function_of_seed_and_label() {
    // Same (seed, label, permille) always agrees; the realized fraction of
    // active sites tracks the activation per-mille.
    let buggify = Buggify::new(
        BuggifyConfig {
            enabled: true,
            activation_permille: 250,
            ..BuggifyConfig::default()
        },
        7,
    );
    let mut active = 0;
    for index in 0..2000 {
        let hash = label_hash(&format!("site-{index}"));
        let decision = buggify.label_is_active(hash);
        assert_eq!(
            decision,
            buggify.label_is_active(hash),
            "activation is stable"
        );
        if decision {
            active += 1;
        }
    }
    // ~25% of 2000, generous band for a 2000-sample draw.
    assert!(
        (400..=600).contains(&active),
        "activation fraction off: {active}"
    );

    // A different seed reshuffles which labels are active.
    let other = Buggify::new(
        BuggifyConfig {
            enabled: true,
            activation_permille: 250,
            ..BuggifyConfig::default()
        },
        8,
    );
    let differ = (0..2000).any(|index| {
        let hash = label_hash(&format!("site-{index}"));
        buggify.label_is_active(hash) != other.label_is_active(hash)
    });
    assert!(differ, "distinct seeds must reshuffle activation");
}

#[test]
fn buggify_firing_prf_is_deterministic_and_seed_varying() {
    let fire_pattern = |seed: u64| {
        let mut context = buggify_context(seed, BUGGIFY_ALL_ACTIVE);
        (0..40)
            .map(|_| {
                matches!(
                    context
                        .buggify_evaluate("commit-early-return", "f.rs:1", None)
                        .unwrap(),
                    SiteOutcome::Fire
                )
            })
            .collect::<Vec<_>>()
    };
    // Byte-identical across two fresh contexts at the same seed.
    assert_eq!(fire_pattern(5), fire_pattern(5));
    // Some firings occurred (fire_permille = 250 over 40 evals).
    assert!(
        fire_pattern(5).iter().any(|fired| *fired),
        "no firing at seed 5"
    );
    // A different seed yields a different firing pattern.
    assert_ne!(fire_pattern(5), fire_pattern(6));
}

#[test]
fn buggify_duplicate_label_is_detected() {
    let mut context = buggify_context(1, BUGGIFY_ALL_ACTIVE);
    // Same label, same call site: fine (re-evaluation).
    assert_ne!(
        context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
        SiteOutcome::DuplicateLabel
    );
    assert_ne!(
        context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
        SiteOutcome::DuplicateLabel
    );
    // Same label at a DIFFERENT call site: fatal duplicate.
    assert_eq!(
        context.buggify_evaluate("dup", "b.rs:9", None).unwrap(),
        SiteOutcome::DuplicateLabel
    );
    // A collision across macro kinds is caught too.
    assert_eq!(
        context.always_check("dup", "c.rs:3", true).unwrap(),
        SiteOutcome::DuplicateLabel
    );
}

#[test]
fn static_site_declarations_do_not_register_or_record_decisions() {
    let mut context = buggify_context(3, BuggifyConfig::default());
    context
        .declare_static_site("never", "src/main.rs:9", BuggifyKind::Reachable)
        .unwrap();
    let diag = context.buggify_diagnostics();
    assert!(!diag.enabled);
    assert_eq!(diag.sites_registered, 0);
    assert_eq!(diag.declared_sites.len(), 1);
    assert_eq!(diag.declared_sites[0].label, "never");
    assert_eq!(diag.declared_sites[0].kind, BuggifyKind::Reachable);
    assert_eq!(context.buggify.to_record(), None);
}

#[test]
fn static_site_declaration_conflict_is_a_duplicate_label_not_a_config_error() {
    let mut context = buggify_context(3, BuggifyConfig::default());
    assert_eq!(
        context
            .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Fault)
            .unwrap(),
        SiteOutcome::Ok
    );
    // Re-declaring the identical site (a second link unit, same literal) is
    // idempotent, not a duplicate.
    assert_eq!(
        context
            .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Fault)
            .unwrap(),
        SiteOutcome::Ok
    );
    assert_eq!(
        context
            .declare_static_site("dup", "src/main.rs:4", BuggifyKind::Fault)
            .unwrap(),
        SiteOutcome::DuplicateLabel
    );
    assert_eq!(
        context
            .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Sometimes)
            .unwrap(),
        SiteOutcome::DuplicateLabel
    );
    // Malformed declarations stay hard errors, distinct from a duplicate.
    assert!(
        context
            .declare_static_site("empty-site", "", BuggifyKind::Reachable)
            .is_err()
    );
    assert_eq!(context.buggify_diagnostics().declared_sites.len(), 1);
}

#[test]
fn buggify_disabled_is_inert_and_records_nothing() {
    let mut context = buggify_context(3, BuggifyConfig::default());
    for _ in 0..100 {
        assert_eq!(
            context.buggify_evaluate("never", "x.rs:1", None).unwrap(),
            SiteOutcome::Ok
        );
    }
    // always! still fires its invariant even with buggify disabled.
    assert_eq!(
        context.always_check("inv", "x.rs:2", false).unwrap(),
        SiteOutcome::AlwaysViolation
    );
    let diag = context.buggify_diagnostics();
    assert!(!diag.enabled);
    assert_eq!(diag.total_firings, 0);
    assert_eq!(context.buggify.to_record(), None);
}

#[test]
fn buggify_fingerprint_requires_enabled_config() {
    // Class-level pairing for SDK buggify value-form point pins: a native
    // `+buggify` compatibility fingerprint without an armed SDK config is a
    // vacuous coverage claim and must fail before any trace can be recorded.
    let directory = tempfile::tempdir().unwrap();
    let trace = directory.path().join("vacuous-buggify.patina");
    let error = match Context::from_config(RuntimeConfig::record(7, &trace, "fp+buggify")) {
        Ok(_) => panic!("+buggify fingerprint without buggify config must fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("fingerprint declares +buggify but buggify is not enabled"),
        "{error}"
    );
}

#[test]
fn buggify_knob_is_deterministic_and_in_range() {
    let mut a = buggify_context(9, BUGGIFY_ALL_ACTIVE);
    let mut b = buggify_context(9, BUGGIFY_ALL_ACTIVE);
    let va = a
        .buggify_knob("batch", "k.rs:1", 10, 1, 100)
        .unwrap()
        .unwrap();
    let vb = b
        .buggify_knob("batch", "k.rs:1", 10, 1, 100)
        .unwrap()
        .unwrap();
    assert_eq!(va, vb, "knob is deterministic per seed+label");
    assert!((1..=100).contains(&va), "knob out of range: {va}");
    // Disabled / inactive returns the clamped default.
    let mut off = buggify_context(9, BuggifyConfig::default());
    assert_eq!(
        off.buggify_knob("batch", "k.rs:1", 10, 1, 100)
            .unwrap()
            .unwrap(),
        10
    );
}

#[test]
fn buggify_cutoff_suppresses_firing_after_the_window() {
    let mut context = buggify_context(
        5,
        BuggifyConfig {
            enabled: true,
            fire_permille: 1000,
            activation_permille: 1000,
            cutoff_nanos: 1_000,
            after_setup: false,
        },
    );
    // Before the cutoff (virtual time 0) an always-fire site fires.
    assert_eq!(
        context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
        SiteOutcome::Fire
    );
    // Advance virtual time past the cutoff, then firing is suppressed.
    context.sleep_for(2_000).unwrap();
    assert_eq!(
        context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
        SiteOutcome::Ok
    );
    assert!(context.buggify_diagnostics().cutoff_suppressed >= 1);
}

#[test]
fn buggify_after_setup_gates_firing_and_flags_never_called() {
    let config = BuggifyConfig {
        enabled: true,
        fire_permille: 1000,
        activation_permille: 1000,
        cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
        after_setup: true,
    };
    // Before setup_complete, an always-fire site stays inert.
    let mut context = buggify_context(2, config);
    assert_eq!(
        context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
        SiteOutcome::Ok,
        "site must be inert before setup_complete"
    );
    // The site is still marked reachable (coverage) even while gated.
    assert!(
        context
            .buggify_diagnostics()
            .sites
            .iter()
            .any(|s| s.reachable && s.site == "g.rs:1")
    );
    // A run that never reaches setup_complete is a declared-but-never-called
    // violation.
    assert!(context.buggify_setup_violation());
    // After setup_complete, firing arms.
    context.lifecycle_setup_complete();
    assert_eq!(
        context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
        SiteOutcome::Fire
    );
    assert!(!context.buggify_setup_violation());
}

#[test]
fn buggify_rng_is_seed_deterministic() {
    let mut a = buggify_context(11, BuggifyConfig::default());
    let mut b = buggify_context(11, BuggifyConfig::default());
    let seq_a: Vec<u64> = (0..8).map(|_| a.buggify_rng()).collect();
    let seq_b: Vec<u64> = (0..8).map(|_| b.buggify_rng()).collect();
    assert_eq!(seq_a, seq_b);
    let mut c = buggify_context(12, BuggifyConfig::default());
    let seq_c: Vec<u64> = (0..8).map(|_| c.buggify_rng()).collect();
    assert_ne!(seq_a, seq_c);
}

#[test]
fn verdicts_are_recorded_queued_and_drained_once() {
    let mut context = buggify_context(11, BuggifyConfig::default());
    let first = context
        .verdict(VerdictKind::Pass, "queue drained", "")
        .unwrap();
    let second = context
        .verdict(VerdictKind::AbortIntent, "checksum", "{\"page\":7}")
        .unwrap();
    assert_eq!((first.seq, second.seq), (0, 1));
    assert_eq!(context.verdicts().len(), 2);
    // The queued lines are exactly the records, and draining is a move: a
    // second drain yields nothing, so no embedder can double-print them.
    let lines = context.take_pending_diagnostics();
    assert_eq!(
        lines,
        vec![first.marker_line(), second.marker_line()],
        "queued diagnostics must be the verdict marker lines in call order"
    );
    assert!(context.take_pending_diagnostics().is_empty());
    assert_eq!(
        lines[0],
        "PATINA_VERDICT seq=0 kind=pass label=queue\\sdrained detail="
    );
    // The reported set survives the drain: draining is a print queue, not the
    // record of what happened.
    assert_eq!(context.verdicts().len(), 2);
}

#[test]
fn always_violation_lowers_to_a_violation_verdict() {
    let mut context = buggify_context(5, BuggifyConfig::default());
    assert_eq!(
        context.always_check("inv", "src/main.rs:9", true).unwrap(),
        SiteOutcome::Ok
    );
    assert!(
        context.verdicts().is_empty(),
        "a satisfied always! must report nothing"
    );
    assert_eq!(
        context.always_check("inv", "src/main.rs:9", false).unwrap(),
        SiteOutcome::AlwaysViolation
    );
    let verdict = context.verdicts().last().expect("violation verdict");
    assert_eq!(verdict.kind, VerdictKind::Violation);
    assert_eq!(verdict.label, "inv");
    assert_eq!(verdict.detail, "src/main.rs:9");
}

#[test]
fn verdict_stream_records_replays_and_refuses_a_divergent_replay() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("verdicts.patina");

    let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
    context.entropy_bytes(4).unwrap();
    context
        .verdict(VerdictKind::Pass, "phase-one", "a")
        .unwrap();
    context
        .verdict(VerdictKind::Violation, "two-leaders", "{\"term\":4}")
        .unwrap();
    context.finish().unwrap();

    // The verdicts are trace events, not just diagnostics.
    let bundle = TraceBundle::load(&trace).unwrap();
    let recorded: Vec<_> = bundle
        .resolved_timeline("main")
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.operation {
            Operation::Verdict {
                verdict_kind,
                label,
                ..
            } => Some((verdict_kind, label)),
            _ => None,
        })
        .collect();
    assert_eq!(
        recorded,
        vec![
            (VerdictKind::Pass, "phase-one".to_string()),
            (VerdictKind::Violation, "two-leaders".to_string()),
        ]
    );

    // Replaying the same verdict stream reconciles cleanly.
    let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
    replay.entropy_bytes(4).unwrap();
    replay.verdict(VerdictKind::Pass, "phase-one", "a").unwrap();
    replay
        .verdict(VerdictKind::Violation, "two-leaders", "{\"term\":4}")
        .unwrap();
    replay.finish().unwrap();

    // A replay whose verdict stream diverges — same labels, different kind —
    // fails closed like any other operation mismatch rather than being
    // reconciled away.
    let mut diverged = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
    diverged.entropy_bytes(4).unwrap();
    let error = diverged
        .verdict(VerdictKind::Violation, "phase-one", "a")
        .expect_err("a diverging verdict must be refused");
    let message = error.to_string();
    assert!(
        message.contains("mismatch"),
        "expected an operation mismatch, got: {message}"
    );
}

#[test]
fn buggify_record_replay_reproduces_decisions_without_re_supplying_flags() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("buggify.patina");
    let config = BuggifyConfig {
        enabled: true,
        fire_permille: 500,
        activation_permille: 1000,
        cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
        after_setup: false,
    };

    // Record: interleave a recorded entropy op with buggify evaluations and a
    // fired delay (which records a SleepUntil), then finalize the trace.
    let mut recorded_fires = Vec::new();
    let mut context =
        Context::from_config(RuntimeConfig::record(3, &trace, "fp").with_buggify(config)).unwrap();
    context.entropy_bytes(4).unwrap();
    for _ in 0..20 {
        recorded_fires.push(matches!(
            context.buggify_evaluate("s", "r.rs:1", None).unwrap(),
            SiteOutcome::Fire
        ));
        let _ = context.buggify_delay("d", "r.rs:2").unwrap();
    }
    context.finish().unwrap();

    // Replay WITHOUT re-supplying buggify flags: the trace's recorded config
    // is authoritative and the pure-function decisions must reproduce exactly.
    let mut replay_fires = Vec::new();
    let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
    replay.entropy_bytes(4).unwrap();
    for _ in 0..20 {
        replay_fires.push(matches!(
            replay.buggify_evaluate("s", "r.rs:1", None).unwrap(),
            SiteOutcome::Fire
        ));
        let _ = replay.buggify_delay("d", "r.rs:2").unwrap();
    }
    // No divergence at finalization means every recorded op (entropy +
    // delay-driven SleepUntil) was consumed in the same order.
    replay.finish().unwrap();

    assert_eq!(recorded_fires, replay_fires);
    assert!(
        recorded_fires.iter().any(|fired| *fired),
        "expected some firing"
    );
}
