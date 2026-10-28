//! Tests for campaign generation derivation and invocation flags.

use super::*;
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
fn native_only_knobs_are_skipped_for_wasi() {
    let spec = CampaignSpec {
        buggify: true,
        swarm: true,
        pct: true,
        faults: FaultPlanes::ALL,
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
    // Crash restart rides on a declared reach, not on `--faults`: a spec
    // without one never arms a crash point it cannot know the guest reaches.
    for family in ["native", "wasi", "cargo"] {
        for generation in 0..64 {
            let flags = derive_flags(&spec, &generation_hash(0, generation), family);
            assert!(
                !flags
                    .iter()
                    .any(|f| f == "--fs-crash-at" || f == "--fs-torn-granularity"),
                "{family} generation {generation} emitted crash restart flags: {flags:?}"
            );
        }
    }
}

/// A declared crash reach arms one crash point per native generation, always
/// at or before a declared point (so the run reaches it), and the draws
/// actually move: across generations both declared ops, many ordinals, and
/// both torn-write granularities appear. Other families never get one.
#[test]
fn a_declared_crash_reach_draws_reachable_points_on_native_only() {
    let reach =
        ["write:32", "close:3"].map(|point| patina_dst_runtime::CrashPoint::parse(point).unwrap());
    let spec = CampaignSpec {
        fs_crash_reach: reach.to_vec(),
        ..CampaignSpec::default()
    };
    let value = |flags: &[String], name: &str| -> String {
        let at = flags.iter().position(|flag| flag == name);
        flags[at.unwrap_or_else(|| panic!("{name} missing from {flags:?}")) + 1].clone()
    };
    let mut points = BTreeSet::new();
    let mut torn = BTreeSet::new();
    for generation in 0..128 {
        let hash = generation_hash(0, generation);
        let flags = derive_flags(&spec, &hash, "native");
        assert_eq!(flags, derive_flags(&spec, &hash, "native"));
        let point = patina_dst_runtime::CrashPoint::parse(&value(&flags, "--fs-crash-at")).unwrap();
        let bound = reach.iter().find(|bound| bound.op == point.op).unwrap();
        assert!(
            (1..=bound.ordinal).contains(&point.ordinal),
            "{point} lies past the declared {bound}"
        );
        points.insert(point.to_string());
        torn.insert(value(&flags, "--fs-torn-granularity"));
        for family in ["wasi", "cargo"] {
            assert!(
                !derive_flags(&spec, &hash, family)
                    .iter()
                    .any(|f| f == "--fs-crash-at" || f == "--fs-torn-granularity"),
                "{family} generation {generation} armed a crash"
            );
        }
    }
    assert!(points.iter().any(|p| p.starts_with("write:")));
    assert!(points.iter().any(|p| p.starts_with("close:")));
    assert!(
        points.len() > reach.len(),
        "ordinals never moved: {points:?}"
    );
    assert_eq!(torn, BTreeSet::from(["block".into(), "byte".into()]));
}

/// `--faults=PLANE,...` emits exactly the selected planes' knobs, at the values
/// an every-plane campaign draws for the same generation, and leaves the rest of
/// the generation alone: the host table and `--swarm` still ride along, so swarm
/// masks within the subset.
#[test]
fn a_plane_subset_draws_exactly_its_planes_at_the_every_plane_values() {
    let spec = |faults| CampaignSpec {
        faults,
        swarm: true,
        dns_entries: vec!["db.internal=10.0.0.5".into()],
        ..CampaignSpec::default()
    };
    let knob_of = |token: &str| {
        let name = token.split_once('=').map_or(token, |(name, _)| name);
        FaultKnob::ALL
            .iter()
            .copied()
            .find(|knob| knob.meta().flag == name)
    };
    // A plane is its knobs' flag prefix: the oracle, independent of the
    // selection logic under test.
    let in_plane = |knob: FaultKnob, plane: FaultPlane| {
        knob.meta()
            .flag
            .starts_with(&format!("--{}-", plane.name()))
    };
    // The every-plane flags with the unselected planes' knobs (and any space-form
    // value after one) removed. The host table is workload, not a plane's knob.
    let restrict = |flags: Vec<String>, subset: FaultPlanes| {
        let mut kept = Vec::new();
        let mut tokens = flags.into_iter().peekable();
        while let Some(token) = tokens.next() {
            let dropped = knob_of(&token).is_some_and(|knob| {
                knob != FaultKnob::DnsEntry && !subset.planes().any(|plane| in_plane(knob, plane))
            });
            let spaced_value =
                !token.contains('=') && tokens.peek().is_some_and(|next| !next.starts_with("--"));
            if !dropped {
                kept.push(token);
            } else if spaced_value {
                tokens.next();
            }
        }
        kept
    };
    let mut subsets: Vec<FaultPlanes> = FaultPlane::ALL
        .into_iter()
        .map(|plane| FaultPlanes::from_names([plane.name()]).unwrap())
        .collect();
    subsets.push(FaultPlanes::from_names(["net", "sleep"]).unwrap());
    for subset in subsets {
        let mut drawn = BTreeSet::new();
        for generation in 0..32 {
            let hash = generation_hash(0, generation);
            let flags = derive_flags(&spec(subset), &hash, "native");
            assert_eq!(
                flags,
                restrict(
                    derive_flags(&spec(FaultPlanes::ALL), &hash, "native"),
                    subset
                ),
                "--faults={} generation {generation}",
                subset.cli_list()
            );
            assert!(flags.iter().any(|flag| flag == "--swarm"));
            drawn.extend(flags.iter().filter_map(|flag| knob_of(flag)));
        }
        for plane in subset.planes() {
            assert!(
                drawn
                    .iter()
                    .any(|knob| *knob != FaultKnob::DnsEntry && in_plane(*knob, plane)),
                "--faults={} drew nothing from {plane:?}",
                subset.cli_list()
            );
        }
    }
}

/// The scale dampens INTENSITY and nothing else. The TCP buffer shape band is
/// actively wrong to scale: `--net-tcp-buffer-bytes` is a capacity whose SMALL
/// end is the harsh one, so multiplying it down would make a rare-fault
/// campaign harsher than the default it was asked to be gentler than.
/// Crash placement comes from the spec's declared reach, not the scale.
#[test]
fn the_fault_scale_leaves_the_tcp_buffer_shape_band_alone() {
    let at = |permille: u64, generation: u64| {
        derive_flags(
            &CampaignSpec {
                faults: FaultPlanes::ALL,
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

#[test]
fn the_dns_band_rides_on_the_host_table_and_never_reaches_wasi() {
    let bare = CampaignSpec {
        faults: FaultPlanes::ALL,
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
    // The band actually varies the failure rate and latency per generation.
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
        address_layout: Some(patina_dst_trace::AddressLayout::Randomized),
        ..CampaignSpec::default()
    };
    for generation in 0..8 {
        let native = derive_flags(&spec, &generation_hash(0, generation), "native");
        for flag in ["--harness", "--allow-randomized-address-layout"] {
            assert!(
                native.iter().any(|f| f == flag),
                "generation {generation} lost {flag}: {native:?}"
            );
        }
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
    for flag in [
        "--harness",
        "--allow",
        "--allow-unsupported-symbols",
        "--allow-randomized-address-layout",
    ] {
        assert!(
            !wasi.iter().any(|f| f == flag),
            "the WASI family must never receive {flag}: {wasi:?}"
        );
    }
    // A spec that asks for none of it forwards none of it.
    let bare = derive_flags(&CampaignSpec::default(), &generation_hash(0, 0), "native");
    for flag in [
        "--harness",
        "--allow",
        "--allow-unsupported-symbols",
        "--allow-randomized-address-layout",
    ] {
        assert!(!bare.iter().any(|f| f == flag), "unasked-for {flag}");
    }
}
