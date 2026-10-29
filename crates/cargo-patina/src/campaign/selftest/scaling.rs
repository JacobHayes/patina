//! Fault-intensity campaign detectors.

use super::super::repro::reproduce_command;
use super::super::state::{spec_from_state_json, spec_to_json};
use super::super::{
    CampaignSpec, FAULT_SCALE_FULL, FaultPlanes, derive_flags, generation_hash, parse,
    scale_intensity,
};
use std::ffi::OsString;
use std::path::Path;

/// The `--fault-scale-permille` checks, in the same `(name, ok, detail)` shape
/// as the coverage/guided detectors.
///
/// The flag exists to make the fault plane RARER, and a knob that changes the
/// sweep is only safe because four properties hold: the scaled draw is a pure
/// function of the generation, the setting is recorded in the out-dir spec, a
/// continuation cannot change it out from under a half-finished campaign, and the
/// scaled values reach the reproduce command.
pub(super) fn fault_scale_selftest() -> Vec<(&'static str, bool, String)> {
    let mut out: Vec<(&'static str, bool, String)> = Vec::new();
    let scaled = |permille: u64| CampaignSpec {
        faults: FaultPlanes::ALL,
        custom_op_faults: true,
        fault_scale_permille: permille,
        ..CampaignSpec::default()
    };
    const LOW: u64 = 10; // a hundredfold rarer

    // (1) PURITY. The whole campaign contract: the same spec and the same
    // generation derive the same flags, always, and different generations still
    // differ (a scale that collapsed the sweep to one configuration would satisfy
    // determinism while exploring nothing).
    let spec = scaled(LOW);
    let mut stable = true;
    let mut distinct: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    for generation in 0..16u64 {
        let hash = generation_hash(0, generation);
        let first = derive_flags(&spec, &hash);
        let second = derive_flags(&spec, &generation_hash(0, generation));
        stable &= first == second;
        distinct.insert(first);
    }
    out.push((
        "scaled-knobs-are-pure-in-the-generation",
        stable && distinct.len() > 8,
        format!("stable={stable} distinct_configurations={}", distinct.len()),
    ));

    // (2) THE DEFAULT IS UNCHANGED. The identity is arithmetic, not a special
    // case: `scale_intensity` at full scale is `v` for every `v`, and an explicit
    // full-scale spec derives byte-for-byte what the default spec derives.
    let identity = (0..=2000u64)
        .chain([10_000, 2_550_000, 255_000_000_000])
        .all(|value| scale_intensity(value, FAULT_SCALE_FULL) == value);
    let full = scaled(FAULT_SCALE_FULL);
    let mut default_spec = full.clone();
    default_spec.fault_scale_permille = CampaignSpec::default().fault_scale_permille;
    let unchanged = (0..32u64).all(|generation| {
        let hash = generation_hash(0, generation);
        derive_flags(&full, &hash) == derive_flags(&default_spec, &hash)
    });
    out.push((
        "full-scale-leaves-the-default-bands-alone",
        identity && unchanged,
        format!("identity={identity} default_matches_explicit_1000={unchanged}"),
    ));

    // (3) IT ACTUALLY DAMPENS. The point of the flag: the summed injected rate
    // across a sweep must fall by roughly the scale. Crash-restart is not part of
    // the campaign band.
    let rate_of = |spec: &CampaignSpec| -> u64 {
        let mut total = 0;
        for generation in 0..256u64 {
            let flags = derive_flags(spec, &generation_hash(0, generation));
            for knob in [
                "--fs-error-permille",
                "--fs-short-permille",
                "--net-drop-permille",
                "--entropy-fail-permille",
            ] {
                if let Some(index) = flags.iter().position(|f| f == knob) {
                    total += flags[index + 1].parse::<u64>().unwrap_or(0);
                }
            }
        }
        total
    };
    let full_rate = rate_of(&full);
    let low_rate = rate_of(&spec);
    let dampened = low_rate * 50 < full_rate;
    out.push((
        "a-low-scale-makes-the-fault-plane-rare",
        dampened,
        format!("summed permille {full_rate} -> {low_rate}; crash-restart band suspended"),
    ));

    // (4) RECORDED IN THE OUT-DIR SPEC, and round-tripped losslessly through the
    // canonical-form gate `--resume`/`--extend` reload through. The default is
    // recorded by ABSENCE.
    let json = spec_to_json(&spec);
    let recorded = json.get("fault_scale_permille") == Some(&serde_json::Value::from(LOW));
    let round_trip = spec_from_state_json(&json).map(|back| back.fault_scale_permille);
    let default_absent = spec_to_json(&CampaignSpec::default())
        .get("fault_scale_permille")
        .is_none();
    out.push((
        "fault-scale-is-recorded-in-the-spec",
        recorded && round_trip.as_ref().ok() == Some(&LOW) && default_absent,
        format!("recorded={recorded} reloaded={round_trip:?} default_key_absent={default_absent}"),
    ));

    // (5) REFUSED ON A CONTINUATION. The recorded spec is authoritative: changing
    // the fault scale halfway through would make the second half of a campaign a
    // different experiment wearing the same out-dir.
    let refused = |arguments: &[&str]| -> Option<String> {
        parse(arguments.iter().map(OsString::from).collect())
            .err()
            .map(|error| error.to_string())
    };
    let on_extend = refused(&["--extend", "3", "--fault-scale-permille", "10"]);
    let on_resume = refused(&["--resume", "--fault-scale-permille", "10"]);
    let fresh_ok = parse(
        ["art", "--faults", "--fault-scale-permille", "10"]
            .iter()
            .map(OsString::from)
            .collect(),
    )
    .map(|invocation| invocation.spec.fault_scale_permille);
    out.push((
        "continuations-refuse-a-changed-fault-scale",
        on_extend.is_some() && on_resume.is_some() && fresh_ok.as_ref().ok() == Some(&LOW),
        format!(
            "extend={} resume={} fresh={fresh_ok:?}",
            on_extend.is_some(),
            on_resume.is_some()
        ),
    ));

    // (6) IN THE REPRODUCE COMMAND. The scale is not a separate token to re-supply
    // — it is BAKED INTO the per-generation knob values, so the printed
    // `cargo patina run … --fs-error-permille N …` re-runs the scaled generation
    // exactly. That is stronger than echoing the flag: the reproduce command
    // cannot disagree with the generation it reproduces.
    let hash = generation_hash(0, 3);
    let flags = derive_flags(&spec, &hash);
    let line = reproduce_command(
        Path::new("art"),
        7,
        &flags,
        &[],
        &[],
        None,
        "campaign-gen-3.trace",
    );
    let carried = flags
        .chunks(2)
        .filter(|pair| pair.len() == 2 && pair[0].ends_with("-permille"))
        .all(|pair| line.contains(&format!("{} {}", pair[0], pair[1])));
    let differs = line != {
        let full_flags = derive_flags(&full, &hash);
        reproduce_command(
            Path::new("art"),
            7,
            &full_flags,
            &[],
            &[],
            None,
            "campaign-gen-3.trace",
        )
    };
    out.push((
        "reproduce-command-carries-the-scaled-knobs",
        carried && differs,
        format!("every_scaled_permille_present={carried} differs_from_full_scale={differs}"),
    ));

    out
}
