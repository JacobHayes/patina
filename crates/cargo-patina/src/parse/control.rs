//! Fault, schedule, liveness, and replay control-plane decoding.

use super::*;

/// The control-plane payload for one repeatable knob's whole value set.
///
/// A repeatable knob carries a SET rather than one value: the control plane
/// takes the whole set as one encoded variable, while a child `run` command line
/// takes the flag once per element. Both shapes hang off the same
/// [`FaultKnob`] table, so neither has to be special-cased at a call site — the
/// bug that was live for `--dns-entry`, which `test`'s native-harness family
/// advertised and never forwarded, so every lookup in a harness run went
/// NXDOMAIN as if no table had been supplied.
pub(crate) fn repeatable_payload(knob: FaultKnob, values: &[String]) -> Result<String, CliError> {
    use patina_dst_runtime::RepeatableFormat;
    match knob.meta().plumbing {
        Plumbing::Repeatable(RepeatableFormat::DnsEntries) => encode_dns_entries(values),
        Plumbing::Repeatable(RepeatableFormat::AddressPairs) => encode_net_partitions(values),
        Plumbing::Repeatable(RepeatableFormat::FsErrorTargets) => encode_fs_error_targets(values),
        Plumbing::Scalar => Err(CliError(format!(
            "{} is not a repeatable knob",
            knob.meta().flag
        ))),
    }
}

/// The DNS host table as the JSON object the runtime's control plane carries.
fn encode_dns_entries(values: &[String]) -> Result<String, CliError> {
    let entries: BTreeMap<String, String> = values
        .iter()
        .map(|value| {
            let (name, address) = values::dns_entry("--dns-entry", value).map_err(CliError)?;
            Ok((name.to_string(), address.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&entries)
        .map_err(|error| CliError(format!("failed to encode the DNS host table: {error}")))
}

/// The targets as the JSON array of canonical spellings the control plane
/// carries.
fn encode_fs_error_targets(values: &[String]) -> Result<String, CliError> {
    let targets: Vec<String> = values
        .iter()
        .map(|value| {
            values::fs_error_target("--fs-error-at", value)
                .map(|target| target.to_string())
                .map_err(CliError)
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&targets)
        .map_err(|error| CliError(format!("failed to encode the fs error targets: {error}")))
}

/// The partition set as the JSON array of pairs the control plane carries.
fn encode_net_partitions(values: &[String]) -> Result<String, CliError> {
    let pairs: Vec<(String, String)> = values
        .iter()
        .map(|value| {
            let (left, right) = values::address_pair("--net-partition", value).map_err(CliError)?;
            Ok((left.to_string(), right.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&pairs)
        .map_err(|error| CliError(format!("failed to encode the network partitions: {error}")))
}

/// Every fault knob this invocation set, read straight off [`FaultKnob::ALL`].
/// Repeatable values are encoded here as well as forwarded, so a malformed one is
/// reported before anything is built or run.
pub(crate) fn knobs_of(args: &cli::Args) -> Result<KnobValues, CliError> {
    let mut values = BTreeMap::new();
    for knob in FaultKnob::ALL {
        let meta = knob.meta();
        let texts: Vec<String> = match meta.plumbing {
            Plumbing::Scalar => args.string(meta.flag).into_iter().collect(),
            Plumbing::Repeatable(_) => args
                .texts(meta.flag)
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        if texts.is_empty() {
            continue;
        }
        if matches!(meta.plumbing, Plumbing::Repeatable(_)) {
            repeatable_payload(*knob, &texts)?;
        }
        values.insert(*knob, texts);
    }
    Ok(KnobValues(values))
}

/// The `PATINA_*` control-plane pairs carrying this invocation's knobs to the
/// guest, in [`FaultKnob::ALL`] order, unset knobs omitted so a run that
/// configured none sets nothing. The native and cargo subprocesses receive them
/// as real environment variables, so both families apply the identical protocol
/// the native shim reads.
pub(crate) fn knob_env_pairs(knobs: &KnobValues) -> Result<Vec<(&'static str, String)>, CliError> {
    let mut pairs = Vec::new();
    for knob in FaultKnob::ALL {
        let values = knobs.get(*knob);
        if values.is_empty() {
            continue;
        }
        let meta = knob.meta();
        let payload = match meta.plumbing {
            Plumbing::Scalar => values[0].clone(),
            Plumbing::Repeatable(_) => repeatable_payload(*knob, values)?,
        };
        pairs.push((meta.env, payload));
    }
    Ok(pairs)
}

/// This invocation's knobs as `(flag, value)` pairs — a repeatable flag repeated
/// once per element — for re-emission onto a child `run` command line.
pub(crate) fn knob_flag_pairs(knobs: &KnobValues) -> Vec<(&'static str, &String)> {
    FaultKnob::ALL
        .iter()
        .flat_map(|knob| {
            knobs
                .get(*knob)
                .iter()
                .map(move |value| (knob.meta().flag, value))
        })
        .collect()
}

/// Every `PATINA_*` variable a fault knob can arrive on, for the scrub that keeps
/// an ambient environment from perturbing a run that requested no faults.
pub(crate) fn knob_env_vars() -> impl Iterator<Item = &'static str> {
    FaultKnob::ALL.iter().map(|knob| knob.meta().env)
}

/// The cooperative-SUT (buggify) knobs, or `None` when buggify was not enabled.
/// Any of the four flags enables it — the three detail knobs each imply
/// `--buggify`, as their help says.
pub(super) fn buggify_of(args: &cli::Args) -> Option<NativeBuggify> {
    let fire = args.text("--buggify");
    let activation = args.string("--buggify-activation-permille");
    let cutoff = args.string("--buggify-cutoff-nanos");
    let after_setup = args.flag("--buggify-after-setup");
    if fire.is_none() && activation.is_none() && cutoff.is_none() && !after_setup {
        return None;
    }
    Some(NativeBuggify {
        // A bare `--buggify` supplies no per-mille; the runtime default applies.
        fire_permille: fire.filter(|value| !value.is_empty()).map(str::to_string),
        activation_permille: activation,
        cutoff_nanos: cutoff,
        after_setup,
    })
}

/// The exploration scheduling knobs. The inert-knob rule (`--sched-pct-steps`
/// without `--sched-pct`, and so on) is declared in the registry and enforced
/// generically by the parser, so it is not repeated here.
pub(super) fn schedule_of(args: &cli::Args) -> NativeSchedule {
    NativeSchedule {
        pct: args.string("--sched-pct"),
        pct_steps: args.string("--sched-pct-steps"),
        starve: args.string("--starve"),
        starve_max_len: args.string("--starve-max-len"),
        starve_window: args.string("--starve-window"),
        swarm: args.flag("--swarm"),
        yield_stride: args.u32("--yield-stride").unwrap_or(0),
    }
}

/// The liveness-watchdog knobs.
pub(super) fn liveness_of(args: &cli::Args) -> NativeLiveness {
    NativeLiveness {
        compute_watchdog_ms: None,
        watchdog: args.string("--liveness-watchdog"),
        converge: args.string("--converge-within"),
        heal_after: args.string("--heal-after"),
    }
}

/// The pre-run gate's allow list.
pub(super) fn allow_of(args: &cli::Args) -> BTreeSet<String> {
    args.texts("--allow")
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The unsupported-symbol escape hatch, default-deny.
pub(super) fn unsupported_policy_of(args: &cli::Args) -> UnsupportedPolicy {
    match args.text("--allow-unsupported-symbols") {
        None => UnsupportedPolicy::Deny,
        Some(value) => {
            match values::unsupported_symbols("--allow-unsupported-symbols", value)
                .expect("validated by the registry grammar")
            {
                None => UnsupportedPolicy::All,
                Some(symbols) => {
                    UnsupportedPolicy::Only(symbols.into_iter().map(str::to_string).collect())
                }
            }
        }
    }
}

/// A repeatable `KEY=VALUE` flag as a map. The grammar already guaranteed a
/// non-empty key; uniqueness is the cross-value rule that remains.
pub(super) fn key_values(
    args: &cli::Args,
    flag: &str,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut map = BTreeMap::new();
    for entry in args.texts(flag) {
        let (key, value) = entry.split_once('=').expect("KEY=VALUE grammar");
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(CliError::usage(format!(
                "{flag} keys must be non-empty and unique"
            )));
        }
    }
    Ok(map)
}

/// The `--timeline` selector, defaulting to `main`.
pub(super) fn timeline_or_main(args: &cli::Args) -> String {
    args.string("--timeline")
        .unwrap_or_else(|| "main".to_string())
}

/// Every `PATINA_BUGGIFY*` control-plane variable, for the scrub that keeps an
/// ambient environment from enabling buggify in a run that did not ask for it.
pub(crate) const BUGGIFY_ENV_VARS: &[&str] = &[
    ENV_BUGGIFY,
    ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_CUTOFF,
    ENV_BUGGIFY_AFTER_SETUP,
];

/// The cooperative-SUT (buggify) control-plane pairs the native and cargo
/// families forward to their subprocess. Presence of `PATINA_BUGGIFY` (its value, possibly empty, being the firing
/// per-mille) enables buggify; the optional knobs follow.
pub(crate) fn buggify_env_pairs(buggify: &NativeBuggify) -> Vec<(&'static str, String)> {
    let mut pairs = vec![(
        ENV_BUGGIFY,
        buggify.fire_permille.clone().unwrap_or_default(),
    )];
    if let Some(value) = &buggify.activation_permille {
        pairs.push((ENV_BUGGIFY_ACTIVATION, value.clone()));
    }
    if let Some(value) = &buggify.cutoff_nanos {
        pairs.push((ENV_BUGGIFY_CUTOFF, value.clone()));
    }
    if buggify.after_setup {
        pairs.push((ENV_BUGGIFY_AFTER_SETUP, "1".to_string()));
    }
    pairs
}

/// The exploration scheduling-policy and swarm control-plane pairs. Presence of
/// `PATINA_SCHED_PCT` enables PCT (its value, possibly empty, being the bug
/// depth); `PATINA_SCHED_STARVE` enables starvation; `PATINA_SWARM` enables
/// swarm fault-class selection. Mirrors [`knob_env_pairs`]: the native family
/// forwards them to its subprocess through the same protocol.
pub(crate) fn schedule_env_pairs(schedule: &NativeSchedule) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(depth) = &schedule.pct {
        pairs.push((ENV_SCHED_PCT, depth.clone()));
        if let Some(steps) = &schedule.pct_steps {
            pairs.push((ENV_SCHED_PCT_STEPS, steps.clone()));
        }
    }
    if let Some(count) = &schedule.starve {
        pairs.push((ENV_SCHED_STARVE, count.clone()));
        if let Some(len) = &schedule.starve_max_len {
            pairs.push((ENV_SCHED_STARVE_MAX_LEN, len.clone()));
        }
        if let Some(window) = &schedule.starve_window {
            pairs.push((ENV_SCHED_STARVE_WINDOW, window.clone()));
        }
    }
    if schedule.swarm {
        pairs.push((ENV_SWARM, "1".to_string()));
    }
    if schedule.yield_stride != 0 {
        pairs.push((ENV_SCHED_YIELD_STRIDE, schedule.yield_stride.to_string()));
    }
    pairs
}

/// The liveness-watchdog control-plane pairs, mirroring [`schedule_env_pairs`]:
/// the native family forwards them to its subprocess, which applies them through
/// `apply_liveness_env`.
pub(crate) fn liveness_env_pairs(liveness: &NativeLiveness) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(bound) = &liveness.compute_watchdog_ms {
        pairs.push(("PATINA_COMPUTE_WATCHDOG_MS", bound.clone()));
    }
    if let Some(budget) = &liveness.watchdog {
        pairs.push((ENV_LIVENESS_WATCHDOG, budget.clone()));
    }
    if let Some(budget) = &liveness.converge {
        pairs.push((ENV_CONVERGE_WITHIN, budget.clone()));
        if let Some(heal_after) = &liveness.heal_after {
            pairs.push((ENV_HEAL_AFTER, heal_after.clone()));
        }
    }
    pairs
}
