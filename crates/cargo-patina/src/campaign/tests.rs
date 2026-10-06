//! Tests for campaign generation derivation and invocation flags.

use super::*;
use crate::help;
use patina_dst_runtime::FaultKnob;
use std::collections::{BTreeMap, BTreeSet};

/// The starvation sweep is the campaign's one adversarial-deferral knob, so
/// its three sub-values must (a) be a pure function of the generation, (b)
/// actually MOVE across generations — a sweep pinned to one configuration
/// explores nothing — and (c) stay inside the ranges the run parser and the
/// scheduler's liveness bound accept.
#[test]
fn the_starvation_sweep_is_deterministic_and_actually_sweeps() {
    let spec = CampaignSpec {
        starve: true,
        ..CampaignSpec::default()
    };
    let value = |flags: &[String], name: &str| -> u64 {
        let at = flags
            .iter()
            .position(|flag| flag == name || flag.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} missing from {flags:?}"));
        let text = flags[at]
            .strip_prefix(&format!("{name}="))
            .map(str::to_string)
            .unwrap_or_else(|| flags[at + 1].clone());
        text.parse().expect("an integer starvation value")
    };
    let mut seen: BTreeMap<(u64, u64, u64), u64> = BTreeMap::new();
    for generation in 0..256 {
        let hash = generation_hash(0, generation);
        let flags = derive_flags(&spec, &hash, "native");
        // Pure: the same generation derives the same configuration.
        assert_eq!(
            flags,
            derive_flags(&spec, &generation_hash(0, generation), "native")
        );
        let intervals = value(&flags, "--starve");
        let window = value(&flags, "--starve-window");
        let max_len = value(&flags, "--starve-max-len");
        assert!((1..=8).contains(&intervals), "intervals {intervals}");
        assert!(
            (512..=65_536).contains(&window) && window.is_power_of_two(),
            "window {window}"
        );
        assert!(
            (16..=128).contains(&max_len) && max_len.is_power_of_two(),
            "max_len {max_len}"
        );
        *seen.entry((intervals, window, max_len)).or_default() += 1;
    }
    // The byte is bit-sliced into 8 x 8 x 4 = 256 configurations; 256
    // generations must reach a large fraction of them, not one corner.
    assert!(
        seen.len() > 100,
        "the starvation sweep collapsed to {} configuration(s)",
        seen.len()
    );
    // Off by default: a spec that did not ask for starvation emits none of it.
    let quiet = derive_flags(&CampaignSpec::default(), &generation_hash(0, 3), "native");
    assert!(!quiet.iter().any(|flag| flag.starts_with("--starve")));
    // WASI has no threads to starve, so the native-only gate holds.
    let wasi = derive_flags(&spec, &generation_hash(0, 3), "wasi");
    assert!(!wasi.iter().any(|flag| flag.starts_with("--starve")));
}

#[test]
fn generation_hash_is_pure_and_stable() {
    // Determinism: the same (seed_base, generation) always derives the same seed.
    let a = generation_hash(0, 7);
    let b = generation_hash(0, 7);
    assert_eq!(a, b);
    assert_ne!(generation_hash(0, 7), generation_hash(0, 8));
    assert_ne!(generation_hash(1, 7), generation_hash(0, 7));
}

#[test]
fn native_only_knobs_are_skipped_for_wasi() {
    let spec = CampaignSpec {
        buggify: true,
        swarm: true,
        pct: true,
        faults: true,
        ..CampaignSpec::default()
    };
    let hash = generation_hash(0, 3);
    let wasi = derive_flags(&spec, &hash, "wasi");
    assert!(!wasi.iter().any(|f| f == "--swarm"));
    assert!(!wasi.iter().any(|f| f.starts_with("--sched-pct")));
    assert!(wasi.iter().any(|f| f.starts_with("--buggify=")));
    let native = derive_flags(&spec, &hash, "native");
    assert!(native.iter().any(|f| f == "--swarm"));
    assert!(native.iter().any(|f| f.starts_with("--sched-pct")));
    // Every knob `--faults` bands must reach BOTH families: a band that
    // exists only on one family halves the exploration silently.
    for banded in [
        "--fs-error-permille",
        "--fs-short-permille",
        "--fs-latency-nanos",
        "--net-drop-permille",
        "--net-latency-nanos",
        "--sleep-jitter-nanos",
    ] {
        assert!(wasi.iter().any(|f| f == banded), "wasi lacks {banded}");
        assert!(native.iter().any(|f| f == banded), "native lacks {banded}");
    }
}

/// The scale dampens INTENSITY and nothing else. The TCP buffer shape band is
/// actively wrong to scale: `--net-tcp-buffer-bytes` is a capacity whose SMALL
/// end is the harsh one, so multiplying it down would make a rare-fault
/// campaign harsher than the default it was asked to be gentler than.
/// Crash/torn-write placement is not drawn at all.
#[test]
fn the_fault_scale_leaves_the_tcp_buffer_shape_band_alone() {
    let at = |permille: u64, generation: u64| {
        derive_flags(
            &CampaignSpec {
                faults: true,
                fault_scale_permille: permille,
                ..CampaignSpec::default()
            },
            &generation_hash(0, generation),
            "native",
        )
    };
    let value = |flags: &[String], name: &str| {
        flags
            .iter()
            .position(|f| f == name)
            .map(|index| flags[index + 1].clone())
    };
    for generation in 0..64 {
        let full = at(FAULT_SCALE_FULL, generation);
        let low = at(1, generation);
        assert_eq!(
            value(&full, "--net-tcp-buffer-bytes"),
            value(&low, "--net-tcp-buffer-bytes"),
            "generation {generation}: the TCP buffer capacity must not be scaled — \
                 a smaller buffer is the HARSHER setting"
        );
    }
}

/// The direction pin, and the reason this dial needed one where the fault
/// dial needed only a "left alone" list. `--starve` (how many holds) and
/// `--starve-max-len` (how long a hold, and the scheduler's aging cap) are
/// monotone in harshness, so they dampen. `--starve-window` is NOT: it is
/// where the holds land, and which end of it hurts depends on the guest's own
/// schedule. Measured on `turso_stress`, a window of 512 puts every hold in
/// the startup prefix where the policy defers nothing at all (`starve_events=0`,
/// run completes), while the same shaped holds at 65536 land in the
/// concurrent phase and wedge the run. A uniform multiply would have
/// concentrated every hold into a prefix, and dilating it would have pushed
/// the starts past the end of a short guest's schedule and made the plane
/// inert rather than rare — neither is right for both. So the window keeps
/// its full log sweep at every scale, and an edit that "just scales
/// everything" has to argue with this test.
#[test]
fn the_starve_scale_leaves_the_placement_window_alone() {
    let at = |permille: u64, generation: u64| {
        derive_flags(
            &CampaignSpec {
                starve: true,
                starve_scale_permille: permille,
                ..CampaignSpec::default()
            },
            &generation_hash(0, generation),
            "native",
        )
    };
    let value = |flags: &[String], name: &str| -> Option<u64> {
        let inline = format!("{name}=");
        let at = flags
            .iter()
            .position(|flag| flag == name || flag.starts_with(&inline))?;
        flags[at]
            .strip_prefix(&inline)
            .map(str::to_string)
            .or_else(|| flags.get(at + 1).cloned())?
            .parse()
            .ok()
    };
    let mut compared = 0;
    let mut windows: BTreeSet<u64> = BTreeSet::new();
    let mut shortened = 0;
    let mut fewer = 0;
    for generation in 0..256 {
        let full = at(STARVE_SCALE_FULL, generation);
        let low = at(100, generation);
        assert!(
            value(&full, "--starve").is_some(),
            "generation {generation}: full scale must starve every generation, as it always has"
        );
        let Some(low_window) = value(&low, "--starve-window") else {
            continue; // the gate closed this generation
        };
        compared += 1;
        windows.insert(low_window);
        assert_eq!(
            Some(low_window),
            value(&full, "--starve-window"),
            "generation {generation}: the start window is placement, not intensity — \
                 scaling it DOWN concentrates the holds a gentler campaign asked to spread, and \
                 scaling it UP pushes them past a short guest's schedule entirely"
        );
        let (low_len, full_len) = (
            value(&low, "--starve-max-len").expect("a gated generation has a hold length"),
            value(&full, "--starve-max-len").expect("full scale always holds"),
        );
        assert!(
            low_len <= full_len && low_len >= 1,
            "generation {generation}: the hold length must dampen toward, but never past, one \
                 decision — got {low_len} from {full_len}"
        );
        shortened += u64::from(low_len < full_len);
        let (low_count, full_count) = (
            value(&low, "--starve").expect("a gated generation has intervals"),
            value(&full, "--starve").expect("full scale always starves"),
        );
        assert!(
            low_count <= full_count && low_count >= 1,
            "generation {generation}: the interval count must dampen toward, but never past, \
                 one hold — got {low_count} from {full_count}"
        );
        fewer += u64::from(low_count < full_count);
    }
    assert!(
        compared > 8 && windows.len() > 2,
        "the dampened sweep left too little to prove anything: {compared} starving \
             generation(s) over {} distinct window(s)",
        windows.len()
    );
    assert!(
        shortened > 0 && fewer > 0,
        "nothing was actually dampened: {shortened} shorter hold(s), {fewer} smaller count(s)"
    );
}

#[test]
fn campaign_fault_bands_do_not_emit_crash_restart() {
    let spec = CampaignSpec {
        faults: true,
        ..CampaignSpec::default()
    };
    for family in ["native", "wasi", "cargo"] {
        for generation in 0..64 {
            let flags = derive_flags(&spec, &generation_hash(0, generation), family);
            assert!(
                !flags
                    .iter()
                    .any(|f| f == "--fs-crash-at" || f == "--fs-torn-granularity"),
                "{family} generation {generation} unexpectedly emitted crash restart flags: {flags:?}"
            );
        }
    }
}

// The generation hash is one 32-byte namespace shared by every seed-derived
// band. Two bands drawing from the same byte would lock their knobs together:
// the campaign would sweep a diagonal of the pair's space instead of the
// square, so a bug that needs an off-diagonal combination stays unreachable at
// EVERY generation while the reports still look healthy. No run surfaces that,
// which is why it is gated structurally rather than left to review.
//
// Class-level pairing: `gen_byte` is the one claims table every band indexes
// through, and these two tests are its halves. This one proves the claims are
// disjoint and in range; `every_generation_hash_read_goes_through_a_claim`
// proves no band bypassed the table with a literal index. A new colliding band
// has to fail one of them.
/// Every claim in the campaign, assembled from the knob table plus the
/// exploration bands no knob owns. A knob cannot go missing from this list:
/// it is derived from [`FaultKnob::ALL`], so a new variant arrives here as
/// soon as `campaign_band` gives it a byte.
fn every_claim() -> Vec<(String, usize)> {
    let mut claims: Vec<(String, usize)> = gen_byte::EXPLORATION_CLAIMS
        .iter()
        .map(|(name, index)| ((*name).to_string(), *index))
        .collect();
    for knob in FaultKnob::ALL {
        for index in campaign_band(*knob).unwrap_or(&[]) {
            claims.push((format!("{:?}", knob), *index));
        }
    }
    claims
}

#[test]
fn generation_byte_claims_are_disjoint() {
    let claims = every_claim();
    let mut claimed: BTreeMap<usize, String> = BTreeMap::new();
    for (name, index) in &claims {
        assert!(
            *index < GEN_BAND_BYTES,
            "the {name} band claims generation byte {index}, past the {GEN_BAND_BYTES}-byte \
                 band material"
        );
        assert!(
            !gen_byte::SEED.contains(index),
            "the {name} band claims generation byte {index}, which is inside the seed slice \
                 {:?} — its draw would be correlated with the child run's seed",
            gen_byte::SEED
        );
        if let Some(other) = claimed.insert(*index, name.clone()) {
            panic!(
                "the {name} and {other} bands both claim generation byte {index}; their knobs \
                     would be correlated in every generation. Claim a free byte instead (33..64, \
                     in the extension block)."
            );
        }
    }
    assert_eq!(
        claimed.len(),
        claims.len(),
        "the claims table lost a row to a duplicate index"
    );
}

/// The campaign bands and the CLI registry are two views of one set. A band
/// drawn for a knob the registry does not declare would be emitted onto a
/// child `run` that refuses it, and this is also where the knobs the campaign
/// leaves INERT are counted — pinned, so a new one is a deliberate decision
/// and a fixed one shows up as a failure telling you to update the list.
#[test]
fn the_campaign_bands_exactly_the_knobs_it_claims_to() {
    let banded: Vec<&str> = FaultKnob::ALL
        .iter()
        .filter(|knob| campaign_band(**knob).is_some())
        .map(|knob| knob.meta().flag)
        .collect();
    assert_eq!(
        banded,
        vec![
            "--fs-error-permille",
            "--fs-short-permille",
            "--fs-latency-nanos",
            "--sleep-jitter-nanos",
            "--net-jitter-nanos",
            "--net-drop-permille",
            "--net-latency-nanos",
            "--net-duplicate-permille",
            "--net-connect-refuse-permille",
            "--net-reset-permille",
            "--net-tcp-buffer-bytes",
            "--entropy-fail-permille",
            "--epoch-jump-nanos",
            "--custom-op-fail-permille",
            "--dns-fail-permille",
            "--dns-latency-nanos",
        ]
    );
    // The complement, spelled out: every knob a `--faults` campaign never
    // draws. Each one MUST carry a `BAND_WAIVERS` entry —
    // `every_unbanded_knob_is_waived` is the gate that makes growing this
    // list silently (a knob with neither a band nor a waiver) impossible.
    let inert: Vec<&str> = FaultKnob::ALL
        .iter()
        .filter(|knob| campaign_band(**knob).is_none())
        .map(|knob| knob.meta().flag)
        .collect();
    assert_eq!(
        inert,
        vec![
            "--fs-crash-at",
            "--fs-torn-granularity",
            "--net-partition",
            "--dns-entry"
        ]
    );
}

/// The band-or-waiver gate: every `FaultKnob` must have EITHER a real
/// `campaign_band` OR a `BAND_WAIVERS` entry with a reason — never neither
/// (a silently forgotten knob) and never both (a stale waiver nobody
/// removed when the knob was later banded). Compile-adjacent, because a new
/// `FaultKnob` variant reaches this loop through `FaultKnob::ALL` the moment
/// it exists, without needing its own follow-up test.
#[test]
fn every_unbanded_knob_is_waived() {
    let waived: BTreeMap<FaultKnob, &str> = BAND_WAIVERS.iter().copied().collect();
    assert_eq!(
        waived.len(),
        BAND_WAIVERS.len(),
        "two BAND_WAIVERS entries name the same knob"
    );
    for knob in FaultKnob::ALL {
        match (campaign_band(*knob), waived.get(knob)) {
            (Some(_), None) => {}
            (None, Some(reason)) => assert!(
                !reason.is_empty(),
                "{knob:?}'s BAND_WAIVERS reason is empty"
            ),
            (None, None) => panic!(
                "{knob:?} has no campaign_band and no BAND_WAIVERS entry — give it a band, \
                     or waive it with a one-line reason"
            ),
            (Some(_), Some(_)) => panic!(
                "{knob:?} has both a campaign_band and a BAND_WAIVERS entry — drop the \
                     waiver, it is now banded"
            ),
        }
    }
}

#[test]
fn the_dns_band_rides_on_the_host_table_and_never_reaches_wasi() {
    let bare = CampaignSpec {
        faults: true,
        ..CampaignSpec::default()
    };
    let hash = generation_hash(0, 3);
    // No host table: no DNS flags at all. Every name a guest looks up is
    // NXDOMAIN by semantics, so a banded knob could not fire — and an inert
    // knob is worse than an absent one, because the report reads clean.
    let without = derive_flags(&bare, &hash, "native");
    assert!(
        !without.iter().any(|f| f.starts_with("--dns-")),
        "a table-free campaign must not band DNS knobs: {without:?}"
    );

    let spec = CampaignSpec {
        dns_entries: vec!["db.internal=10.0.0.5".into()],
        ..bare
    };
    let native = derive_flags(&spec, &hash, "native");
    for banded in ["--dns-entry", "--dns-fail-permille", "--dns-latency-nanos"] {
        assert!(native.iter().any(|f| f == banded), "native lacks {banded}");
    }
    let index = native
        .iter()
        .position(|f| f == "--dns-entry")
        .expect("host table");
    assert_eq!(native[index + 1], "db.internal=10.0.0.5");
    // wasip1 has no resolution surface: the WASI `run` parser refuses these
    // flags, so banding them would turn every generation into a refusal.
    let wasi = derive_flags(&spec, &hash, "wasi");
    assert!(
        !wasi.iter().any(|f| f.starts_with("--dns-")),
        "the WASI family must never receive DNS flags: {wasi:?}"
    );
}

#[test]
fn the_dns_band_varies_the_failure_rate_and_latency_across_generations() {
    let spec = CampaignSpec {
        faults: true,
        dns_entries: vec!["db.internal=10.0.0.5".into()],
        ..CampaignSpec::default()
    };
    let mut rates = BTreeSet::new();
    let mut latencies = BTreeSet::new();
    for generation in 0..64 {
        let flags = derive_flags(&spec, &generation_hash(0, generation), "native");
        let value = |name: &str| {
            let index = flags.iter().position(|f| f == name).expect("banded knob");
            flags[index + 1].clone()
        };
        let rate: u64 = value("--dns-fail-permille").parse().expect("permille");
        assert!(rate <= 100, "failure rate {rate} outside the [0, 100] band");
        rates.insert(rate);
        latencies.insert(value("--dns-latency-nanos"));
    }
    assert!(rates.len() > 8, "DNS failure rate barely varied: {rates:?}");
    assert!(
        latencies.len() > 8,
        "DNS latency barely varied: {latencies:?}"
    );
}

// The native harness/pre-run-gate surface a campaign forwards verbatim. A
// guest that needs `--harness` or the gate hatch is not "a campaign that
// reports failures" — it is a campaign that cannot run at all, every
// generation refused identically, so the forwarding is what makes the sweep
// possible.
#[test]
fn the_native_invocation_surface_is_forwarded_to_every_generation_and_never_to_wasi() {
    let spec = CampaignSpec {
        harness: true,
        allow_symbols: vec!["semaphore_wait".into(), "semaphore_signal".into()],
        allow_unsupported_symbols: Some("all".into()),
        ..CampaignSpec::default()
    };
    for generation in 0..8 {
        let native = derive_flags(&spec, &generation_hash(0, generation), "native");
        assert!(
            native.iter().any(|f| f == "--harness"),
            "generation {generation} lost --harness: {native:?}"
        );
        let allowed: Vec<&String> = native
            .iter()
            .enumerate()
            .filter(|(index, _)| *index > 0 && native[index - 1] == "--allow")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            allowed,
            vec!["semaphore_wait", "semaphore_signal"],
            "the allow list must be forwarded whole and in order: {native:?}"
        );
        let index = native
            .iter()
            .position(|f| f == "--allow-unsupported-symbols")
            .expect("the gate hatch");
        assert_eq!(native[index + 1], "all");
    }
    // No WASI harness family and no WASI pre-run gate: the WASI `run` parser
    // refuses all three, so forwarding them would turn every generation into a
    // usage error. The artifact is refused upstream; this is belt and braces.
    let wasi = derive_flags(&spec, &generation_hash(0, 0), "wasi");
    for flag in ["--harness", "--allow", "--allow-unsupported-symbols"] {
        assert!(
            !wasi.iter().any(|f| f == flag),
            "the WASI family must never receive {flag}: {wasi:?}"
        );
    }
    // A spec that asks for none of it forwards none of it.
    let bare = derive_flags(&CampaignSpec::default(), &generation_hash(0, 0), "native");
    for flag in ["--harness", "--allow", "--allow-unsupported-symbols"] {
        assert!(!bare.iter().any(|f| f == flag), "unasked-for {flag}");
    }
}

// The forwarded flags must be spelled exactly as `run <BINARY>` declares them.
// Campaign builds each child flag through `push_run_flag`, which reads RUN's
// arity, so a campaign row that disagreed with run's would emit a value shape
// the child rejects — in every generation, as an INFRA storm rather than a
// parse error here.
#[test]
fn the_forwarded_flags_match_the_run_registry_rows() {
    let campaign = help::verb("campaign").expect("`campaign` is registered");
    let run = help::verb("run").expect("`run` is registered");
    for name in [
        "--harness",
        "--allow",
        "--allow-unsupported-symbols",
        "--compute-watchdog-ms",
    ] {
        let ours = campaign
            .family_flags(help::Family::Sole)
            .find(|flag| flag.name == name)
            .unwrap_or_else(|| panic!("campaign must register {name}"));
        let theirs = run
            .family_flags(help::Family::Native)
            .find(|flag| flag.name == name)
            .unwrap_or_else(|| panic!("run <BINARY> must register {name}"));
        assert_eq!(
            ours.value.grammar(),
            theirs.value.grammar(),
            "{name} grammar differs from run's"
        );
        assert_eq!(
            ours.value.placeholder(),
            theirs.value.placeholder(),
            "{name} value shape differs from run's"
        );
        assert_eq!(
            ours.repeatable, theirs.repeatable,
            "{name} repeatability differs from run's"
        );
    }
}
