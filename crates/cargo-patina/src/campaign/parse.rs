//! Campaign invocation parsing and continuation controls.

use super::spec::DEFAULT_PROGRESS_EVERY;
use super::{AllowUnmetSometimes, CampaignSpec, DEFAULT_OUT_DIR};
use crate::{CliError, cli, help};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CampaignMode {
    Fresh,
    Extend { additional: u64 },
    Resume,
}

/// A parsed `campaign` invocation.
#[derive(Debug)]
pub struct CampaignInvocation {
    pub(super) artifact: Option<PathBuf>,
    pub(super) out_dir: PathBuf,
    pub(super) spec: CampaignSpec,
    pub(super) mode: CampaignMode,
    pub(super) selftest: bool,
    /// A continuation-only host-side timeout override. It does not rewrite the
    /// out-dir's recorded spec; the effective value is recorded on the invocation
    /// audit record.
    pub(super) timeout_secs_override: Option<u64>,
    /// Human-mode progress-heartbeat cadence (generations per
    /// `PATINA_CAMPAIGN_PROGRESS` line). Presentation only — it never affects the
    /// deterministic sweep, so it lives here rather than on [`CampaignSpec`].
    pub(super) progress_every: u64,
    /// Best-effort audit spelling for the invocation record. Output/global flags
    /// stripped before verb parsing are intentionally not reconstructed.
    pub(super) cli: String,
}

// ===========================================================================
// Parsing + dispatch
// ===========================================================================

/// Parse `campaign [--selftest] | campaign <ARTIFACT> [flags] [-- GUEST_ARGS…] |
/// campaign --extend N [--out-dir DIR] | campaign --resume [--out-dir DIR]`.
pub fn parse(mut arguments: Vec<OsString>) -> Result<CampaignInvocation, CliError> {
    let cli_line = campaign_cli(&arguments);

    // Split a trailing `-- GUEST_ARGS…` section (the guest argument vector).
    let mut guest_args: Vec<String> = Vec::new();
    if let Some(position) = arguments.iter().position(|a| a == "--") {
        for arg in arguments.split_off(position).into_iter().skip(1) {
            guest_args.push(
                arg.into_string()
                    .map_err(|_| CliError("campaign guest arguments must be UTF-8".into()))?,
            );
        }
    }

    // `campaign --selftest` proves every classifier class + the signature store.
    if arguments.iter().any(|a| a == "--selftest") {
        return Ok(CampaignInvocation {
            artifact: None,
            out_dir: PathBuf::new(),
            spec: CampaignSpec::default(),
            mode: CampaignMode::Fresh,
            selftest: true,
            timeout_secs_override: None,
            progress_every: DEFAULT_PROGRESS_EVERY,
            cli: cli_line,
        });
    }

    let continuation_requested = has_continuation_flag(&arguments);

    // Options may lead the artifact (`campaign --gens 5 art.wasm`), so locate it
    // registry-arity-aware rather than insisting it be the first token. In
    // continuation mode, the absence of an artifact is intentional; a positional
    // that is present is rejected after parsing so the error names the doctrine.
    let scan = crate::locate_positionals("campaign", &arguments, 1);
    let artifact = scan.positionals.into_iter().next().map(PathBuf::from);
    if artifact.is_none()
        && !continuation_requested
        && let Some(stop) = scan.stop
    {
        crate::reject_stranded_artifact("campaign", &arguments[stop..])?;
    }
    let args = cli::parse("campaign", help::Family::Sole, scan.rest)?;

    // In continuation mode the out-dir's recorded spec is authoritative, so any
    // flag that would change it is refused. The permitted set is the handful of
    // knobs that describe THIS invocation rather than the campaign's shape.
    let mode = match (args.u64("--extend"), args.flag("--resume")) {
        (Some(_), true) => {
            return Err(CliError::usage(
                "--extend and --resume are redundant; choose exactly one continuation mode",
            ));
        }
        (Some(additional), false) => CampaignMode::Extend { additional },
        (None, true) => CampaignMode::Resume,
        (None, false) => CampaignMode::Fresh,
    };
    if !matches!(mode, CampaignMode::Fresh) {
        for flag in help::verb("campaign")
            .expect("`campaign` is registered")
            .family_flags(help::Family::Sole)
        {
            if !CONTINUATION_FLAGS.contains(&flag.name) && args.supplied(flag.name) {
                return Err(reject_continuation_override(flag.name));
            }
        }
    }

    let mut spec = CampaignSpec::default();
    if let Some(path) = args.path("--spec") {
        let shown = path.display();
        let text = fs::read_to_string(&path)
            .map_err(|e| CliError(format!("failed to read campaign spec {shown}: {e}")))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| CliError(format!("campaign spec {shown} is invalid JSON: {e}")))?;
        spec.apply_json(&json)?;
    }
    // A flag overrides the spec regardless of argument order — the same
    // precedence the config layer uses (flag > env > config > default). An
    // ABSENT flag overrides nothing: the switches only ever turn a knob on, so a
    // spec that enables buggify is not silently undone by omitting --buggify.
    spec.buggify |= args.flag("--buggify");
    spec.swarm |= args.flag("--swarm");
    spec.pct |= args.flag("--sched-pct");
    spec.starve |= args.flag("--starve");
    spec.faults |= args.flag("--faults");
    spec.custom_op_faults |= args.flag("--custom-op-faults");
    // A value flag, so — unlike the switches above — it overrides the spec only
    // when actually supplied; an absent flag leaves the spec's scale alone.
    if let Some(value) = args.u64("--fault-scale-permille") {
        spec.fault_scale_permille = value;
    }
    if let Some(value) = args.u64("--starve-scale-permille") {
        spec.starve_scale_permille = value;
    }
    spec.report |= args.flag("--report-failures");
    let dns_entries = args.texts("--dns-entry");
    if !dns_entries.is_empty() {
        spec.dns_entries = dns_entries.into_iter().map(str::to_string).collect();
    }
    spec.harness |= args.flag("--harness");
    let allow_symbols = args.texts("--allow");
    if !allow_symbols.is_empty() {
        spec.allow_symbols = allow_symbols.into_iter().map(str::to_string).collect();
    }
    if let Some(value) = args.text("--allow-unsupported-symbols") {
        spec.allow_unsupported_symbols = Some(value.to_string());
    }
    if let Some(value) = args.u64("--compute-watchdog-ms") {
        spec.compute_watchdog_ms = Some(value);
    }
    if let Some(value) = args.u64("--liveness-watchdog") {
        spec.watchdog_nanos = Some(value);
    }
    if let Some(value) = args.u64("--converge-within") {
        spec.converge_nanos = Some(value);
    }
    if let Some(value) = args.u64("--heal-after") {
        spec.heal_after_nanos = Some(value);
    }

    let out_dir = args
        .path("--out-dir")
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR));
    let progress_every = args
        .u64("--progress-every")
        .unwrap_or(DEFAULT_PROGRESS_EVERY);
    let timeout_secs = args.u64("--timeout-secs");

    if !matches!(mode, CampaignMode::Fresh) {
        if artifact.is_some() {
            return Err(reject_continuation_override("artifact positional"));
        }
        if !guest_args.is_empty() {
            return Err(reject_continuation_override("guest arguments"));
        }
        return Ok(CampaignInvocation {
            artifact: None,
            out_dir,
            spec,
            mode,
            selftest: false,
            timeout_secs_override: timeout_secs,
            progress_every,
            cli: cli_line,
        });
    }

    if let Some(generations) = args.u64("--gens") {
        spec.generations = generations;
    }
    if let Some(seed_start) = args.u64("--seed-start") {
        spec.seed_base = seed_start;
    }
    if let Some(timeout_secs) = timeout_secs {
        spec.timeout_secs = timeout_secs;
    }
    if let Some(value) = args.u64("--plateau-after") {
        spec.plateau_after = value;
    }
    spec.guided |= args.flag("--guided");
    if let Some(value) = args.text("--allow-unmet-sometimes") {
        spec.allow_unmet_sometimes = Some(match value {
            "" => AllowUnmetSometimes::Always,
            generations => AllowUnmetSometimes::BelowGenerations(
                generations
                    .parse()
                    .expect("validated by the registry grammar"),
            ),
        });
    }
    if !guest_args.is_empty() {
        spec.guest_args = guest_args;
    }
    Ok(CampaignInvocation {
        artifact: Some(artifact.ok_or_else(|| {
            CliError::usage(
                "campaign requires an artifact path (a .wasm module or native binary), or --selftest",
            )
        })?),
        out_dir,
        spec,
        mode,
        selftest: false,
        timeout_secs_override: None,
        progress_every,
        cli: cli_line,
    })
}

/// The flags a continuation (`--extend`/`--resume`) still accepts: they describe
/// this invocation, not the campaign's shape, which the recorded spec owns.
const CONTINUATION_FLAGS: &[&str] = &[
    "--extend",
    "--resume",
    "--out-dir",
    "--timeout-secs",
    "--progress-every",
    "--selftest",
];

fn has_continuation_flag(arguments: &[OsString]) -> bool {
    arguments.iter().any(|argument| {
        argument
            .to_str()
            .is_some_and(|text| matches!(cli::split_name(text), "--extend" | "--resume"))
    })
}

fn campaign_cli(arguments: &[OsString]) -> String {
    let mut parts = vec!["campaign".to_string()];
    parts.extend(arguments.iter().map(|arg| cli_arg(arg.as_os_str())));
    parts.join(" ")
}

fn cli_arg(argument: &OsStr) -> String {
    let text = argument.to_string_lossy();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        format!("{text:?}")
    } else {
        text.into_owned()
    }
}

fn reject_continuation_override(name: &str) -> CliError {
    CliError::usage(format!(
        "{name} cannot be used with --extend/--resume; the out-dir's recorded spec is authoritative; start a new out-dir to change the spec"
    ))
}

#[cfg(test)]
mod tests;
