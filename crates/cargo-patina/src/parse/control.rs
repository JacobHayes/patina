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
    match knob {
        FaultKnob::DnsEntry => encode_dns_entries(values),
        FaultKnob::NetPartition => encode_net_partitions(values),
        // Every other knob is `Plumbing::Scalar` and carries its one value
        // verbatim; the callers filter on plumbing before asking for a payload,
        // and `every_repeatable_knob_has_an_encoder` proves this arm is dead for
        // every knob the table marks repeatable.
        scalar => Err(CliError(format!(
            "{} is not a repeatable knob",
            scalar.meta().flag
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
        // A knob the registry does not give this family is absent, not an error
        // to read: the DNS knobs are a declared WASI exception, and the exception
        // lives in the registry rather than being restated here.
        if !args.registered(meta.flag) {
            continue;
        }
        let texts: Vec<String> = match meta.plumbing {
            Plumbing::Scalar => args.string(meta.flag).into_iter().collect(),
            Plumbing::Repeatable => args
                .texts(meta.flag)
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        if texts.is_empty() {
            continue;
        }
        if meta.plumbing == Plumbing::Repeatable {
            repeatable_payload(*knob, &texts)?;
        }
        values.insert(*knob, texts);
    }
    Ok(KnobValues(values))
}

/// The `PATINA_*` control-plane pairs carrying this invocation's knobs to the
/// guest, in [`FaultKnob::ALL`] order, unset knobs omitted so a run that
/// configured none sets nothing. Used by the WASI in-process runtime (via
/// [`RuntimeConfig::apply_fault_env`]) and by the native and cargo subprocesses
/// (as real environment variables), so every family applies the identical
/// protocol the native shim reads.
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
            Plumbing::Repeatable => repeatable_payload(*knob, values)?,
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

/// Read the guest instrumentation a native `build`/`test` invocation asked for.
///
/// The two instrumentation flags are mutually exclusive by construction, not by
/// convention: `patina_yield.c` and `patina_cov.c` define the same
/// SanitizerCoverage entry points, so linking both would be a duplicate-symbol
/// error at best and a coin flip at worst. Refuse the combination here, where the
/// message can say which one to keep.
pub(super) fn instrumentation_of(args: &cli::Args) -> Result<GuestInstrumentation, CliError> {
    let yield_points = args.flag("--yield-points");
    let coverage_points = args.string("--coverage-points");
    match (yield_points, coverage_points) {
        (true, Some(_)) => Err(CliError::usage(
            "--yield-points and --coverage-points are mutually exclusive: both instrument every \
basic block, and they differ only in what happens there. Use --yield-points for a scheduling point \
at EVERY block (densest, slowest), --coverage-points=N for one every N blocks, or bare \
--coverage-points for edge counters with no added scheduling points.",
        )),
        (true, None) => Ok(GuestInstrumentation::YieldPoints),
        (false, None) => Ok(GuestInstrumentation::None),
        // A bare `--coverage-points` arrives as the empty string: counters only.
        (false, Some(value)) if value.is_empty() => {
            Ok(GuestInstrumentation::CoveragePoints { stride: 0 })
        }
        (false, Some(value)) => {
            // The registry grammar already proved a positive integer; only the
            // u32 ceiling (the C counter's width) is left to check.
            let stride: u32 = value.parse().map_err(|_| {
                CliError::usage(format!(
                    "--coverage-points={value} is out of range; the sampling stride must fit in 32 \
bits"
                ))
            })?;
            Ok(GuestInstrumentation::CoveragePoints { stride })
        }
    }
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

/// The host-supplied inputs a WASI run/replay shares.
pub(super) fn wasi_host_inputs_of(args: &cli::Args) -> Result<WasiHostInputs, CliError> {
    let fuel = args.u64("--fuel");
    let mut sockets = Vec::new();
    let mut socket_fds = BTreeSet::new();
    for entry in args.texts("--socket") {
        let (fd, bind, peer) =
            values::socket("--socket", entry).expect("validated by the registry grammar");
        if !socket_fds.insert(fd) {
            return Err(CliError::usage(
                "--socket requires a unique FD above 3 and non-empty addresses",
            ));
        }
        sockets.push(WasiSocketConfig {
            fd,
            bind: bind.to_string(),
            peer: peer.to_string(),
        });
    }
    let preopens = args
        .texts("--preopen")
        .into_iter()
        .map(|entry| {
            let (guest_path, read_only) =
                values::preopen("--preopen", entry).expect("validated by the registry grammar");
            WasiPreopenConfig {
                guest_path: normalize_cli_preopen_path(guest_path),
                policy: if read_only {
                    MountPolicy::ReadOnly
                } else {
                    MountPolicy::ReadWrite
                },
            }
        })
        .collect();
    Ok(WasiHostInputs {
        fuel,
        arguments: args
            .texts("--arg")
            .into_iter()
            .map(str::to_string)
            .collect(),
        environment: key_values(args, "--env")?,
        sockets,
        preopens,
        resource_limits: WasiResourceLimitOverrides {
            fuel,
            max_memory_pages: args.u32("--max-memory-pages"),
            max_iovecs: args.usize("--max-iovecs"),
            max_io_bytes: args.usize("--max-io-bytes"),
            max_descriptors: args.usize("--max-descriptors"),
            max_preopens: args.usize("--max-preopens"),
            max_path_bytes: args.usize("--max-path-bytes"),
        },
    })
}

/// The timeline/branch selection shared by the Cargo package and WASI replay
/// families, which are the two that support branch-append.
pub(super) fn replay_mode(args: &cli::Args, path: PathBuf) -> Result<Mode, CliError> {
    let timeline = args.string("--timeline");
    let from_sequence = args.u64("--from");
    let branch_seed = args.u64("--branch-seed");
    let branch_id = args.string("--branch-id");
    let parent = args.string("--parent");
    if !args.flag("--branch") {
        if from_sequence.is_some()
            || branch_seed.is_some()
            || branch_id.is_some()
            || parent.is_some()
        {
            return Err(CliError::usage(
                "--from/--branch-seed/--branch-id/--parent require --branch",
            ));
        }
        return Ok(Mode::Replay {
            path,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        });
    }
    if timeline.is_some() {
        return Err(CliError::usage(
            "--timeline selects a timeline to replay and is not valid with --branch",
        ));
    }
    Ok(Mode::Branch {
        path,
        parent: parent.unwrap_or_else(|| "main".into()),
        from_sequence: from_sequence
            .ok_or_else(|| CliError::usage("replay --branch requires --from"))?,
        branch_seed: branch_seed
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-seed"))?,
        branch_id: branch_id
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-id"))?,
    })
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

/// The cooperative-SUT (buggify) control-plane pairs for the in-process WASI
/// runtime, mirroring the env vars the native family forwards to its subprocess.
/// Presence of `PATINA_BUGGIFY` (its value, possibly empty, being the firing
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
/// swarm fault-class selection. Mirrors [`knob_env_pairs`] so the native family
/// forwards them to the subprocess and the WASI/Cargo families to the in-process
/// runtime through the same protocol.
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
    pairs
}

/// The liveness-watchdog control-plane pairs, mirroring [`schedule_env_pairs`] so
/// the native family forwards them to the subprocess and the WASI/Cargo families
/// to the in-process runtime through the same `apply_liveness_env` protocol.
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

fn normalize_cli_preopen_path(path: &str) -> String {
    if !path.starts_with('/') || path.contains('\0') {
        return path.to_owned();
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return path.to_owned(),
            component => components.push(component),
        }
    }
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}
