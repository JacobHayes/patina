//! Tests for campaign generation derivation and invocation flags.

use super::*;
use std::collections::BTreeSet;

/// A knob the spec excludes is emitted by no generation, and excluding it
/// leaves every other flag exactly as the unexcluded campaign derives it.
#[test]
fn an_excluded_knob_is_never_drawn_and_leaves_the_rest_alone() {
    let net = CampaignSpec {
        faults: FaultPlanes::from_names(["net"]).unwrap(),
        ..CampaignSpec::default()
    };
    let excluded = CampaignSpec {
        exclude_knobs: [FaultKnob::NetResetPermille].into(),
        ..net.clone()
    };
    let reset = FaultKnob::NetResetPermille.meta().flag;
    let mut drawn_when_included = false;
    for generation in 0..64 {
        let hash = generation_hash(0, generation);
        let mut expected = derive_flags(&net, &hash);
        if let Some(at) = expected.iter().position(|flag| flag == reset) {
            drawn_when_included = true;
            expected.drain(at..at + 2);
        }
        assert_eq!(derive_flags(&excluded, &hash), expected);
    }
    assert!(drawn_when_included, "the net plane never drew {reset}");
}

#[test]
fn spec_knobs_reach_every_generation() {
    let spec = CampaignSpec {
        buggify: true,
        swarm: true,
        pct: true,
        faults: FaultPlanes::ALL,
        ..CampaignSpec::default()
    };
    let hash = generation_hash(0, 3);
    let native = derive_flags(&spec, &hash);
    assert!(native.iter().any(|f| f == "--swarm"));
    assert!(native.iter().any(|f| f.starts_with("--sched-pct")));
    assert!(native.iter().any(|f| f.starts_with("--buggify=")));
    // Every knob `--faults` bands reaches the generation.
    for banded in [
        "--fs-error-permille",
        "--fs-short-permille",
        "--fs-latency-nanos",
        "--net-drop-permille",
        "--net-latency-nanos",
        "--sleep-jitter-nanos",
        "--machine-crash-permille",
        "--process-crash-permille",
    ] {
        assert!(native.iter().any(|f| f == banded), "native lacks {banded}");
    }
}

/// The crash plane draws a machine-crash and a process-crash rate per
/// generation, independently: across generations each rate takes several
/// values within the per-mille range, and they do not move in lockstep.
/// Excluding one leaves the other.
#[test]
fn the_crash_plane_draws_two_independent_moving_rates() {
    let spec = CampaignSpec {
        faults: FaultPlanes::from_names(["crash"]).unwrap(),
        ..CampaignSpec::default()
    };
    let value = |flags: &[String], name: &str| -> String {
        let at = flags.iter().position(|flag| flag == name);
        flags[at.unwrap_or_else(|| panic!("{name} missing from {flags:?}")) + 1].clone()
    };
    let mut machine_rates = BTreeSet::new();
    let mut process_rates = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for generation in 0..128 {
        let hash = generation_hash(0, generation);
        let flags = derive_flags(&spec, &hash);
        assert_eq!(flags, derive_flags(&spec, &hash));
        let machine: u16 = value(&flags, "--machine-crash-permille").parse().unwrap();
        let process: u16 = value(&flags, "--process-crash-permille").parse().unwrap();
        for rate in [machine, process] {
            assert!((1..=1000).contains(&rate), "{rate}");
        }
        machine_rates.insert(machine);
        process_rates.insert(process);
        pairs.insert((machine, process));
    }
    assert!(machine_rates.len() > 2, "the machine rate never moved");
    assert!(process_rates.len() > 2, "the process rate never moved");
    assert!(
        pairs.len() > machine_rates.len(),
        "the two rates moved in lockstep: {pairs:?}"
    );
    let machine_only = CampaignSpec {
        exclude_knobs: [FaultKnob::ProcessCrashPermille].into(),
        ..spec
    };
    let flags = derive_flags(&machine_only, &generation_hash(0, 0));
    assert!(flags.iter().any(|flag| flag == "--machine-crash-permille"));
    assert!(!flags.iter().any(|flag| flag == "--process-crash-permille"));
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
    // A plane is a word of its knobs' flags: the oracle, independent of the
    // selection logic under test.
    let in_plane = |knob: FaultKnob, plane: FaultPlane| {
        knob.meta()
            .flag
            .trim_start_matches("--")
            .split('-')
            .any(|word| word == plane.name())
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
            let flags = derive_flags(&spec(subset), &hash);
            assert_eq!(
                flags,
                restrict(derive_flags(&spec(FaultPlanes::ALL), &hash), subset),
                "--faults={subset:?} generation {generation}"
            );
            assert!(flags.iter().any(|flag| flag == "--swarm"));
            drawn.extend(flags.iter().filter_map(|flag| knob_of(flag)));
        }
        for plane in subset.planes() {
            assert!(
                drawn
                    .iter()
                    .any(|knob| *knob != FaultKnob::DnsEntry && in_plane(*knob, plane)),
                "--faults={subset:?} drew nothing from {plane:?}"
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
fn the_dns_band_rides_on_the_host_table() {
    let bare = CampaignSpec {
        faults: FaultPlanes::ALL,
        ..CampaignSpec::default()
    };
    let hash = generation_hash(0, 3);
    // No host table: no DNS flags at all. Every name a guest looks up is
    // NXDOMAIN by semantics, so a banded knob could not fire — and an inert
    // knob is worse than an absent one, because the report reads clean.
    let without = derive_flags(&bare, &hash);
    assert!(
        !without.iter().any(|f| f.starts_with("--dns-")),
        "a table-free campaign must not band DNS knobs: {without:?}"
    );

    let spec = CampaignSpec {
        dns_entries: vec!["db.internal=10.0.0.5".into()],
        ..bare
    };
    let native = derive_flags(&spec, &hash);
    for banded in ["--dns-entry", "--dns-fail-permille", "--dns-latency-nanos"] {
        assert!(native.iter().any(|f| f == banded), "native lacks {banded}");
    }
    let index = native
        .iter()
        .position(|f| f == "--dns-entry")
        .expect("host table");
    assert_eq!(native[index + 1], "db.internal=10.0.0.5");
    // The band actually varies the failure rate and latency per generation.
    let mut rates = BTreeSet::new();
    let mut latencies = BTreeSet::new();
    for generation in 0..64 {
        let flags = derive_flags(&spec, &generation_hash(0, generation));
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

// The native pre-run-gate surface a campaign forwards verbatim. A
// guest that needs the gate hatch is not "a campaign that
// reports failures" — it is a campaign that cannot run at all, every
// generation refused identically, so the forwarding is what makes the sweep
// possible.
#[test]
fn the_native_invocation_surface_is_forwarded_to_every_generation() {
    let spec = CampaignSpec {
        allow_symbols: vec!["semaphore_wait".into(), "semaphore_signal".into()],
        allow_unsupported_symbols: Some("all".into()),
        address_layout: Some(patina_dst_trace::AddressLayout::Randomized),
        ..CampaignSpec::default()
    };
    for generation in 0..8 {
        let native = derive_flags(&spec, &generation_hash(0, generation));
        assert!(
            native
                .iter()
                .any(|f| f == "--allow-randomized-address-layout"),
            "generation {generation} lost the address layout: {native:?}"
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
    // A spec that asks for none of it forwards none of it.
    let bare = derive_flags(&CampaignSpec::default(), &generation_hash(0, 0));
    for flag in [
        "--allow",
        "--allow-unsupported-symbols",
        "--allow-randomized-address-layout",
    ] {
        assert!(!bare.iter().any(|f| f == flag), "unasked-for {flag}");
    }
}
