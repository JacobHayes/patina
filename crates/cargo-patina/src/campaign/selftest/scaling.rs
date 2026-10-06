//! Fault- and starvation-intensity campaign selftest detectors.

use super::super::repro::reproduce_command;
use super::super::state::{spec_from_state_json, spec_to_json};
use super::super::{
    CampaignSpec, FAULT_SCALE_FULL, STARVE_SCALE_FULL, derive_flags, generation_bands,
    generation_hash, parse, scale_intensity, starve_band_fires,
};
use std::ffi::OsString;
use std::path::Path;

/// The `--fault-scale-permille` checks the classifier selftest runs, in the same
/// `(name, ok, detail)` shape as the coverage/depth/guided detector selftests.
///
/// The flag exists to make the fault plane RARER, and a knob that changes the
/// sweep is only safe because four properties hold: the scaled draw is a pure
/// function of the generation, the setting is recorded in the out-dir spec, a
/// continuation cannot change it out from under a half-finished campaign, and the
/// scaled values reach the reproduce command. Each is checked here rather than
/// only in `#[cfg(test)]`, so `campaign --selftest` proves them against the
/// shipped binary the operator is actually running.
pub(super) fn fault_scale_selftest() -> Vec<(&'static str, bool, String)> {
    let mut out: Vec<(&'static str, bool, String)> = Vec::new();
    let scaled = |permille: u64| CampaignSpec {
        faults: true,
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
        let first = derive_flags(&spec, &hash, "native");
        let second = derive_flags(&spec, &generation_hash(0, generation), "native");
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
    // full-scale spec derives byte-for-byte what the default spec derives — which
    // is what makes every campaign recorded before this flag existed still
    // reproduce.
    let identity = (0..=2000u64)
        .chain([10_000, 2_550_000, 255_000_000_000])
        .all(|value| scale_intensity(value, FAULT_SCALE_FULL) == value);
    let full = scaled(FAULT_SCALE_FULL);
    let mut default_spec = full.clone();
    default_spec.fault_scale_permille = CampaignSpec::default().fault_scale_permille;
    let unchanged = (0..32u64).all(|generation| {
        let hash = generation_hash(0, generation);
        derive_flags(&full, &hash, "native") == derive_flags(&default_spec, &hash, "native")
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
            let flags = derive_flags(spec, &generation_hash(0, generation), "native");
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
    // recorded by ABSENCE, so an out-dir written before this flag existed still
    // passes that gate.
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
    let flags = derive_flags(&spec, &hash, "native");
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
        let full_flags = derive_flags(&full, &hash, "native");
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

/// The `--starve-scale-permille` checks the classifier selftest runs, in the
/// same `(name, ok, detail)` shape as [`fault_scale_selftest`].
///
/// The same four properties any sweep-changing knob has to hold — the scaled
/// draw is a pure function of the generation, the setting is recorded in the
/// out-dir spec, a continuation cannot change it under a half-finished
/// campaign, and the scaled values reach the reproduce command — plus the one
/// this dial has and the fault dial did not: each axis moves in the RIGHT
/// DIRECTION, including the one that is deliberately not moved at all. Proved
/// here rather than only under `#[cfg(test)]`, so `campaign --selftest` proves
/// them against the shipped binary the operator is actually running.
pub(super) fn starve_scale_selftest() -> Vec<(&'static str, bool, String)> {
    let mut out: Vec<(&'static str, bool, String)> = Vec::new();
    let scaled = |permille: u64| CampaignSpec {
        starve: true,
        starve_scale_permille: permille,
        ..CampaignSpec::default()
    };
    const LOW: u64 = 100; // a tenth as intense
    // `--starve` is an optional-value flag, so it renders as one `--starve=N`
    // token while its two companions render as a name/value pair; read both
    // forms, the way the sweep's own test does.
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

    // (1) PURITY. The campaign contract: the same spec and the same generation
    // derive the same policy, always, and the sweep still sweeps — a scale that
    // collapsed every gated generation onto one configuration would be
    // deterministic while exploring nothing.
    let spec = scaled(LOW);
    let mut stable = true;
    let mut distinct: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    for generation in 0..64u64 {
        let hash = generation_hash(0, generation);
        let first = derive_flags(&spec, &hash, "native");
        let second = derive_flags(&spec, &generation_hash(0, generation), "native");
        stable &= first == second;
        distinct.insert(
            first
                .iter()
                .filter(|flag| flag.starts_with("--starve"))
                .cloned()
                .collect(),
        );
    }
    out.push((
        "scaled-starvation-is-pure-in-the-generation",
        stable && distinct.len() > 2,
        format!("stable={stable} distinct_policies={}", distinct.len()),
    ));

    // (2) THE DEFAULT IS UNCHANGED, arithmetically rather than by a special
    // case: the gate is unconditionally open at full scale and `scale_intensity`
    // is the identity there, so an explicit 1000 derives byte for byte what the
    // default derives — which is what keeps every campaign recorded before this
    // flag existed reproducible.
    let full = scaled(STARVE_SCALE_FULL);
    let mut default_spec = full.clone();
    default_spec.starve_scale_permille = CampaignSpec::default().starve_scale_permille;
    let gate_open = (0..256u64).all(|generation| {
        starve_band_fires(
            &generation_bands(&generation_hash(0, generation)),
            STARVE_SCALE_FULL,
        )
    });
    let unchanged = (0..64u64).all(|generation| {
        let hash = generation_hash(0, generation);
        derive_flags(&full, &hash, "native") == derive_flags(&default_spec, &hash, "native")
    });
    out.push((
        "full-scale-leaves-the-default-policy-alone",
        gate_open && unchanged,
        format!("gate_open_every_generation={gate_open} default_matches_explicit_1000={unchanged}"),
    ));

    // (3) IT ACTUALLY DAMPENS, on the axis that matters most: how many
    // generations starve at all. Every generation starves at full scale; at a
    // tenth of it roughly a tenth do — and the ones that do hold fewer tasks for
    // fewer decisions.
    let census = |spec: &CampaignSpec| -> (usize, u64, u64) {
        let mut starving = 0;
        let mut intervals = 0;
        let mut max_len = 0;
        for generation in 0..256u64 {
            let flags = derive_flags(spec, &generation_hash(0, generation), "native");
            if let Some(count) = value(&flags, "--starve") {
                starving += 1;
                intervals += count;
                max_len += value(&flags, "--starve-max-len").unwrap_or(0);
            }
        }
        (starving, intervals, max_len)
    };
    let (full_gens, full_intervals, full_len) = census(&full);
    let (low_gens, low_intervals, low_len) = census(&spec);
    let dampened = full_gens == 256
        && (8..56).contains(&low_gens)
        && low_intervals * 4 < full_intervals
        && low_len * 4 < full_len;
    out.push((
        "a-low-scale-makes-starvation-rare-and-short",
        dampened,
        format!(
            "starving generations {full_gens} -> {low_gens} (of 256), summed intervals \
             {full_intervals} -> {low_intervals}, summed max-len {full_len} -> {low_len}"
        ),
    ));

    // (4) EACH AXIS MOVES ITS OWN WAY. Two are dampened because their harshness
    // is monotone in them; the START WINDOW is not touched at all, because its
    // harshness is not — see [`CampaignSpec::starve_scale_permille`]. A future
    // "just scale everything uniformly" edit has to fail this to land.
    let mid = scaled(500);
    let mut directions = true;
    let mut compared = 0;
    for generation in 0..256u64 {
        let hash = generation_hash(0, generation);
        let full_flags = derive_flags(&full, &hash, "native");
        let mid_flags = derive_flags(&mid, &hash, "native");
        if value(&mid_flags, "--starve").is_none() {
            continue; // the gate closed this generation at the lower scale
        }
        compared += 1;
        directions &= value(&mid_flags, "--starve") <= value(&full_flags, "--starve");
        directions &=
            value(&mid_flags, "--starve-max-len") <= value(&full_flags, "--starve-max-len");
        directions &= value(&mid_flags, "--starve-window") == value(&full_flags, "--starve-window");
        directions &= value(&mid_flags, "--starve-max-len").unwrap_or(0) >= 1;
    }
    out.push((
        "each-starvation-axis-scales-in-its-own-direction",
        directions && compared > 32,
        format!(
            "generations_compared={compared} \
             count_and_length_down_window_untouched={directions}"
        ),
    ));

    // (5) RECORDED IN THE OUT-DIR SPEC, and round-tripped losslessly through the
    // canonical-form gate `--resume`/`--extend` reload through. The default is
    // recorded by ABSENCE, so an out-dir written before this flag existed still
    // passes that gate.
    let json = spec_to_json(&spec);
    let recorded = json.get("starve_scale_permille") == Some(&serde_json::Value::from(LOW));
    let round_trip = spec_from_state_json(&json).map(|back| back.starve_scale_permille);
    let default_absent = spec_to_json(&CampaignSpec::default())
        .get("starve_scale_permille")
        .is_none();
    out.push((
        "starve-scale-is-recorded-in-the-spec",
        recorded && round_trip.as_ref().ok() == Some(&LOW) && default_absent,
        format!("recorded={recorded} reloaded={round_trip:?} default_key_absent={default_absent}"),
    ));

    // (6) REFUSED ON A CONTINUATION. Changing the starvation intensity halfway
    // through would make the second half of a campaign a different experiment
    // wearing the same out-dir.
    let refused =
        |arguments: &[&str]| parse(arguments.iter().map(OsString::from).collect()).is_err();
    let on_extend = refused(&["--extend", "3", "--starve-scale-permille", "100"]);
    let on_resume = refused(&["--resume", "--starve-scale-permille", "100"]);
    let fresh_ok = parse(
        ["art", "--starve", "--starve-scale-permille", "100"]
            .iter()
            .map(OsString::from)
            .collect(),
    )
    .map(|invocation| invocation.spec.starve_scale_permille);
    out.push((
        "continuations-refuse-a-changed-starve-scale",
        on_extend && on_resume && fresh_ok.as_ref().ok() == Some(&LOW),
        format!("extend={on_extend} resume={on_resume} fresh={fresh_ok:?}"),
    ));

    // (7) IN THE REPRODUCE COMMAND. The scale is not a token to re-supply — it
    // is BAKED INTO the policy the generation runs, so the printed `cargo patina
    // run … --starve N --starve-window N --starve-max-len N` replays the scaled
    // generation exactly. The gated-off half matters just as much: a generation
    // the gate closed prints no starvation flags at all, rather than a policy it
    // never ran.
    let line = |spec: &CampaignSpec, generation: u64| {
        let flags = derive_flags(spec, &generation_hash(0, generation), "native");
        let text = reproduce_command(
            Path::new("art"),
            7,
            &flags,
            &[],
            &[],
            None,
            "campaign-gen.trace",
        );
        (text, flags)
    };
    let starves = |generation: u64| {
        value(
            &derive_flags(&spec, &generation_hash(0, generation), "native"),
            "--starve",
        )
        .is_some()
    };
    let starving = (0..256u64).find(|generation| starves(*generation));
    let quiet = (0..256u64).find(|generation| !starves(*generation));
    let carried = starving.is_some_and(|generation| {
        let (text, flags) = line(&spec, generation);
        let (full_text, _) = line(&full, generation);
        // Every starvation token the generation derived appears verbatim, in the
        // exact rendering the child `run` parser accepts.
        let mut tokens = flags
            .iter()
            .enumerate()
            .filter(|(_, flag)| flag.starts_with("--starve"));
        tokens.all(|(index, flag)| {
            let rendered = if flag.contains('=') {
                flag.clone()
            } else {
                format!("{flag} {}", flags[index + 1])
            };
            text.contains(&rendered)
        }) && text != full_text
    });
    let silent = quiet.is_some_and(|generation| !line(&spec, generation).0.contains("--starve"));
    out.push((
        "reproduce-command-carries-the-scaled-policy",
        carried && silent,
        format!(
            "scaled_generation={starving:?} carries_its_policy={carried} \
             ungated_generation={quiet:?} prints_none={silent}"
        ),
    ));

    out
}
