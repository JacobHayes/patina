//! WASI-family invocation parsing.

use super::*;

/// Thin wrapper: treat the leading argument as an already-built module. Used by
/// unit tests; `run` routing calls [`parse_wasi_run_from`] with a resolved ref.
#[cfg(test)]
pub(crate) fn parse_wasi_run(mut arguments: Vec<OsString>) -> Result<WasiInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "run of a WASI module requires a .wasm path",
        ));
    }
    let module = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_wasi_run_from(module, arguments)
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// The host-supplied inputs a WASI run/replay shares: fuel, guest argv, guest
/// environment, datagram sockets, preopens, and resource-limit overrides. These
/// are genuine host inputs (not recorded semantic state — except `--arg`, which
/// becomes the recorded guest argv), so both `run` and `replay` accept them and
/// they feed the WASI compatibility fingerprint.
#[derive(Default)]
pub(super) struct WasiHostInputs {
    pub(super) fuel: Option<u64>,
    pub(super) arguments: Vec<String>,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) sockets: Vec<WasiSocketConfig>,
    pub(super) preopens: Vec<WasiPreopenConfig>,
    pub(super) resource_limits: WasiResourceLimitOverrides,
}

/// Assemble a [`WasiInvocation`] from a parsed mode, the shared host inputs, and
/// the fault knobs. Shared tail of [`parse_wasi_run_from`] and
/// [`parse_wasi_replay`].
fn wasi_invocation_from(
    module: ArtifactRef,
    mode: Mode,
    inputs: WasiHostInputs,
    step_budget: Option<u64>,
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    liveness: NativeLiveness,
) -> WasiInvocation {
    WasiInvocation {
        module,
        mode,
        fuel: inputs.fuel.unwrap_or(DEFAULT_WASM_FUEL),
        arguments: inputs.arguments,
        environment: inputs.environment,
        sockets: inputs.sockets,
        preopens: inputs.preopens,
        resource_limits: inputs.resource_limits,
        step_budget,
        // Set by `run` only; `replay` restores the recorded epoch.
        realtime_epoch_nanos: None,
        knobs,
        buggify,
        liveness,
    }
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// (an existing `.wasm` or a build-on-the-fly spec). `run` produces a seeded or
/// `--record` run: replaying a recording is the `replay` verb's job, so the
/// replay/branch/timeline flags live there, not here. The seed-driven fault knobs
/// (including `--sleep-jitter-nanos`, honored at the wasip1 host's sleep entry)
/// and the cooperative-SUT (buggify) knobs are accepted and recorded exactly as
/// on the native family.
pub(crate) fn parse_wasi_run_from(
    module: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("run", help::Family::Wasi, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let mode = match args.path("--record") {
        Some(path) => Mode::Record { seed, path },
        None => Mode::Seeded { seed },
    };
    Ok(WasiInvocation {
        realtime_epoch_nanos: realtime_epoch_of(&args),
        ..wasi_invocation_from(
            module,
            mode,
            wasi_host_inputs_of(&args)?,
            args.u64("--budget"),
            knobs_of(&args)?,
            buggify_of(&args),
            liveness_of(&args),
        )
    })
}

/// Parse the WASI `replay <MODULE.wasm> <TRACE>` verb given an already-resolved
/// module reference and trace path. Flag-free for semantics: the seed and fault
/// knobs are restored from the trace, and `--arg` values (the recorded guest
/// argv) are restored and conflict-checked at execution. Only genuine host inputs
/// stay as flags (`--fuel`/`--env`/`--socket`/`--preopen`/resource limits), plus
/// the timeline selector and branch controls the WASI runtime supports.
pub(crate) fn parse_wasi_replay(
    module: ArtifactRef,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("replay", help::Family::Wasi, arguments)?;
    Ok(wasi_invocation_from(
        module,
        replay_mode(&args, trace)?,
        wasi_host_inputs_of(&args)?,
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        None,
        KnobValues::default(),
        None,
        NativeLiveness::default(),
    ))
}

#[cfg(test)]
mod tests;
