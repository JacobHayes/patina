//! Tests for seeded fault-class selection and fingerprint component retraction.

use crate::config::{BuggifyConfig, FaultConfig, RuntimeConfig};
use crate::reports::swarm_report_line;
use crate::swarm::apply_swarm_mask;
use crate::{Context, FINGERPRINT_BUGGIFY, FaultKnob, Masks, SWARM_CLASSES};

use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

use tempfile::tempdir;

use crate::config::tests::every_fault_knob_enabled;

#[test]
fn swarm_masks_a_subset_and_records_candidates_and_selection() {
    let directory = tempdir().unwrap();
    // Enable several fault classes plus buggify, then record under swarm.
    let build = |seed: u64| {
        let trace = directory.path().join(format!("swarm-{seed}.patina"));
        let config = RuntimeConfig::record(seed, &trace, "fp")
            .with_machine_crash_permille(1)
            .with_crash_supervisor()
            .with_fs_error_permille(100)
            .with_fs_short_permille(200)
            .with_net_drop_permille(100)
            .with_sleep_jitter_nanos(1, 2)
            .with_buggify(BuggifyConfig {
                enabled: true,
                ..BuggifyConfig::default()
            })
            .with_swarm(true);
        let context = Context::from_config(config).unwrap();
        context.finish().unwrap();
        patina_dst_trace::TraceBundle::load(&trace).unwrap()
    };
    let bundle = build(1);
    let swarm = bundle.metadata.swarm.expect("swarm recorded");
    // All six enabled classes are candidates.
    assert_eq!(
        swarm.candidate_classes,
        vec![
            "crash",
            "fs_error",
            "fs_short",
            "sleep_jitter",
            "net_drop",
            FINGERPRINT_BUGGIFY
        ]
    );
    // The selected subset is a subset of candidates and reflects the applied
    // (masked) config: exactly the classes that survived masking.
    for class in &swarm.selected_classes {
        assert!(swarm.candidate_classes.contains(class));
    }
    let faults = bundle.metadata.faults;
    assert_eq!(
        faults.machine_crash_permille > 0,
        swarm.selected_classes.iter().any(|c| c == "crash")
    );
    assert_eq!(
        bundle.metadata.buggify.is_some(),
        swarm
            .selected_classes
            .iter()
            .any(|c| c == FINGERPRINT_BUGGIFY)
    );

    // Across seeds the selected subset actually varies (swarm testing).
    let subsets: std::collections::BTreeSet<Vec<String>> = (100..112)
        .map(|seed| build(seed).metadata.swarm.unwrap().selected_classes)
        .collect();
    assert!(
        subsets.len() > 1,
        "swarm subset must vary across seeds: {subsets:?}"
    );
}

/// `--swarm` on a run with no fault class enabled is an inert knob: the draw
/// has nothing to keep or drop, the run explores what a plain run explores,
/// and the report must SAY so rather than reading like covered swarm
/// exploration.
#[test]
fn swarm_with_no_enabled_fault_class_reports_vacuous() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("swarm-vacuous.patina");
    let config = RuntimeConfig::record(3, &trace, "fp").with_swarm(true);
    let context = Context::from_config(config).unwrap();
    context.finish().unwrap();
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let swarm = bundle.metadata.swarm.expect("swarm recorded");
    assert!(swarm.candidate_classes.is_empty());
    assert!(swarm.is_vacuous());
    assert_eq!(
        swarm_report_line(&swarm),
        "PATINA_SWARM_REPORT candidates=0 selected=0 deselected=0 vacuous=1"
    );

    // A live candidate set is NOT vacuous, even when the draw drops all of it:
    // exploring the empty subset of a real candidate set is a legitimate draw.
    let all_dropped = patina_dst_trace::SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string(), FINGERPRINT_BUGGIFY.to_string()],
        selected_classes: Vec::new(),
    };
    assert_eq!(
        swarm_report_line(&all_dropped),
        "PATINA_SWARM_REPORT candidates=2 selected=0 deselected=2 vacuous=0 \
class=crash|0 class=buggify|0"
    );
}

#[test]
fn swarm_class_table_covers_every_current_fault_field() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("swarm-coverage.patina");
    let mut config = RuntimeConfig::record(9, &trace, "fp")
        .with_buggify(BuggifyConfig {
            enabled: true,
            ..BuggifyConfig::default()
        })
        .with_swarm(true);
    config.faults = every_fault_knob_enabled();
    let context = Context::from_config(config).unwrap();
    context.finish().unwrap();
    let swarm = patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .metadata
        .swarm
        .expect("swarm recorded");

    // The recorded candidate ORDER, written out by hand on purpose: it is
    // the one thing about `SWARM_CLASSES` that a trace can see, so deriving
    // it from the table would leave a reordered table ungated. That a class
    // EXISTS for every masked knob is guaranteed by the generated masks and
    // their compile-time ownership checks.
    assert_eq!(
        swarm.candidate_classes,
        vec![
            "crash",
            "fs_error",
            "fs_short",
            "fs_latency",
            "dns_fail",
            "dns_latency",
            "sleep_jitter",
            "net_jitter",
            "net_drop",
            "net_latency",
            "net_duplicate",
            "net_connect_refuse",
            "net_reset",
            "net_partition",
            "net_tcp_buffer",
            "entropy_fail",
            FINGERPRINT_BUGGIFY,
            "epoch_jump",
            "custom_op_fail",
        ]
    );
}

/// Each swarm row must be wired to ITS OWN knobs: a config with exactly one
/// knob set offers exactly that knob's class as the only candidate, and a
/// deselected class leaves no residue behind. A row copy-pasted onto a
/// neighbouring field — the likeliest mistake when a domain grows its fourth
/// knob — shows up here. Driven off [`FaultKnob::ALL`] rather than a sample
/// list, so a new knob is covered the day it exists.
#[test]
fn each_swarm_class_is_wired_to_its_own_fault_knobs() {
    for knob in FaultKnob::ALL {
        // The class that MASKS the knob, which is not always the class the
        // knob declares: `--dns-entry` is masked by nothing at all.
        let masking = SWARM_CLASSES
            .iter()
            .find(|class| matches!(class.masks, Masks::Knobs(knobs) if knobs.contains(knob)));
        let mut config = RuntimeConfig::seeded(1).with_swarm(true);
        knob.set_sample(&mut config.faults);
        let record = apply_swarm_mask(&mut config);

        let Some(class) = masking else {
            assert!(
                record.candidate_classes.is_empty(),
                "{knob:?} is masked by no class but offered {:?}",
                record.candidate_classes
            );
            continue;
        };
        assert_eq!(
            record.candidate_classes,
            vec![class.token.to_string()],
            "{} must be the only candidate {knob:?} offers",
            class.token
        );
        if record.selected_classes.is_empty() {
            assert_eq!(
                config.faults,
                FaultConfig::default(),
                "a deselected {} must leave no residue",
                class.token
            );
        }
    }
}

/// The lowest seed for which swarm's `buggify` coin comes up the given way,
/// so the coherence tests below name a real deselecting/selecting generation
/// instead of hard-coding a seed that a coin change would silently invert.
fn seed_where_buggify_is(selected: bool) -> u64 {
    (0..1024)
        .find(|seed| {
            let mut rng = SplitMix64::new(domain_seed(*seed, fault_domain::SWARM_BUGGIFY));
            (rng.next_u64() & 1 == 1) == selected
        })
        .expect("some seed in 0..1024 draws each way")
}

/// A harness keeps asking for buggify in code on replay. When the recording's
/// swarm draw deselected it, the replay must accept the request and run with
/// buggify disarmed, exactly as recorded, rather than refuse the configuration.
#[test]
fn replay_accepts_a_buggify_request_the_recording_swarm_deselected() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("swarm-replay.patina");
    let seed = seed_where_buggify_is(false);
    let armed = BuggifyConfig {
        enabled: true,
        ..BuggifyConfig::default()
    };
    Context::from_config(
        RuntimeConfig::record(seed, &trace, "fp")
            .with_buggify(armed)
            .with_swarm(true),
    )
    .unwrap()
    .finish()
    .unwrap();
    let replay = Context::from_config(
        RuntimeConfig::replay(&trace, "fp")
            .with_buggify(armed)
            .with_swarm(true),
    )
    .expect("the same configuration must replay its own deselected recording");
    replay.finish().unwrap();
}

/// The bug behind SlateDB feedback item 9. A `--swarm` generation whose seed
/// deselects `buggify` used to keep `+buggify` in its fingerprint while
/// disarming the buggify config, which the coherence guard then (correctly)
/// refused — so a legitimate masked generation aborted. Masking now retracts
/// the component, and the whole declared state stays truthful.
#[test]
fn swarm_deselecting_buggify_leaves_no_buggify_in_the_fingerprint() {
    let directory = tempdir().unwrap();
    let record = |seed: u64| {
        let trace = directory.path().join(format!("swarm-fp-{seed}.patina"));
        let config = RuntimeConfig::record(seed, &trace, "fp")
            .with_buggify(BuggifyConfig {
                enabled: true,
                fire_permille: 372,
                ..BuggifyConfig::default()
            })
            .with_swarm(true);
        // RED before the fix: this `build` returned the "+buggify but buggify
        // is not enabled" refusal on a deselecting seed.
        let context = Context::from_config(config).expect("masked run must build");
        context.finish().unwrap();
        patina_dst_trace::TraceBundle::load(&trace).unwrap()
    };

    // Deselected: the component is gone, no buggify config is recorded, and
    // the swarm record still names buggify as a candidate — so the trace says
    // "asked for, dropped here", not "never asked for".
    let dropped = record(seed_where_buggify_is(false));
    assert_eq!(dropped.metadata.fingerprint, "fp+swarm");
    assert_eq!(dropped.metadata.buggify, None);
    let swarm = dropped.metadata.swarm.as_ref().expect("swarm recorded");
    assert!(swarm.was_candidate(FINGERPRINT_BUGGIFY));
    assert!(swarm.deselected(FINGERPRINT_BUGGIFY));
    assert_eq!(swarm.deselected_classes(), vec![FINGERPRINT_BUGGIFY]);
    dropped.validate().expect("masked trace must validate");

    // Selected: nothing changes — the component and the config both stand.
    let kept = record(seed_where_buggify_is(true));
    assert_eq!(kept.metadata.fingerprint, "fp+buggify+swarm");
    assert_eq!(
        kept.metadata
            .buggify
            .as_ref()
            .expect("buggify recorded")
            .fire_permille,
        372
    );
    let swarm = kept.metadata.swarm.as_ref().expect("swarm recorded");
    assert!(!swarm.deselected(FINGERPRINT_BUGGIFY));
    kept.validate().expect("selected trace must validate");
}

/// A dropped class leaves NO residue in the configuration: the whole buggify
/// config resets, so a masked run reports the same numbers a run that never
/// asked for buggify reports. The requested-but-dropped fact is carried by
/// `swarm_deselected`, not by leftover permilles — which is what made the
/// original `enabled=0 fire_permille=372` line read like a broken flag.
#[test]
fn swarm_deselection_clears_the_class_config_and_is_reported_distinctly() {
    let requested = || {
        RuntimeConfig::seeded(seed_where_buggify_is(false))
            .with_buggify(BuggifyConfig {
                enabled: true,
                fire_permille: 372,
                activation_permille: 900,
                ..BuggifyConfig::default()
            })
            .with_swarm(true)
    };
    let mut masked = requested();
    let record = apply_swarm_mask(&mut masked);
    assert!(record.deselected(FINGERPRINT_BUGGIFY));
    assert_eq!(masked.buggify, BuggifyConfig::default());

    // `swarm_deselected` is what separates the two `enabled=0` states.
    let context = Context::from_config(requested()).unwrap();
    let diagnostics = context.buggify_diagnostics();
    assert!(!diagnostics.enabled);
    assert!(diagnostics.swarm_deselected);

    let never_asked = Context::from_config(RuntimeConfig::seeded(0)).unwrap();
    let diagnostics = never_asked.buggify_diagnostics();
    assert!(!diagnostics.enabled);
    assert!(!diagnostics.swarm_deselected);
}

/// Every class's coin must come from `domain_seed` with the label the table
/// declares — not from the root seed, and not from a neighbour's label, which
/// would make two classes select and deselect together forever. Recomputed
/// straight from [`SWARM_CLASSES`], so a class added to the table is covered
/// without touching this test, and a class whose coin is rewired to a
/// different label fails immediately.
#[test]
fn swarm_class_coins_use_the_domain_seed_registry() {
    let seed = 42;
    let mut config = RuntimeConfig::seeded(seed)
        .with_buggify(BuggifyConfig {
            enabled: true,
            ..BuggifyConfig::default()
        })
        .with_swarm(true);
    config.faults = every_fault_knob_enabled();

    let expected: Vec<String> = SWARM_CLASSES
        .iter()
        .filter_map(|class| {
            let mut rng = SplitMix64::new(domain_seed(seed, class.domain));
            (rng.next_u64() & 1 == 1).then(|| class.token.to_string())
        })
        .collect();
    assert!(
        !expected.is_empty() && expected.len() < SWARM_CLASSES.len(),
        "seed {seed} must select SOME classes and drop others for this to prove anything"
    );

    let swarm = apply_swarm_mask(&mut config);
    assert_eq!(swarm.selected_classes, expected);
}
