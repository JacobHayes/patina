//! Campaign invocation parsing and continuation controls.

use super::spec::DEFAULT_PROGRESS_EVERY;
use super::{CampaignSpec, DEFAULT_OUT_DIR, FaultPlane, FaultPlanes, Vary};
use crate::{CliError, cli, help};
use patina_dst_runtime::FaultKnob;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CampaignMode {
    /// An artifact was given: start a campaign in the out-dir, or continue
    /// the one it holds when the command describes the same campaign.
    Fresh,
    /// No artifact: continue the out-dir's recorded campaign as it is,
    /// toward `gens` generations when given.
    Continue { gens: Option<u64> },
}

/// A parsed `campaign` invocation.
#[derive(Debug)]
pub struct CampaignInvocation {
    pub(super) artifact: Option<PathBuf>,
    pub(super) out_dir: PathBuf,
    pub(super) spec: CampaignSpec,
    pub(super) mode: CampaignMode,
    /// A typed `--timeout-secs`. A continuation runs under it without
    /// rewriting the out-dir's recorded spec; the effective value is recorded
    /// on the invocation audit record.
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

/// Parse `campaign <ARTIFACT> [flags] [-- GUEST_ARGS…]`, or the artifact-free
/// continuation `campaign [--out-dir DIR] [--gens N]`.
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

    // Options may lead the artifact (`campaign --gens 5 ./app`), so locate it
    // registry-arity-aware rather than insisting it be the first token.
    let scan = crate::locate_positionals("campaign", &arguments, 1);
    let artifact = scan.positionals.into_iter().next().map(PathBuf::from);
    let args = cli::parse("campaign", help::Family::Sole, scan.rest)?;

    // Without an artifact the command continues the out-dir's recorded
    // campaign, whose spec is authoritative, so any typed flag that would
    // change it is refused. The permitted set is the handful that describe
    // THIS invocation rather than the campaign's shape, and the generation
    // target. An environment default yields to the recorded spec as it yields
    // to a typed flag, so it is ignored here rather than refused.
    let mode = match artifact {
        Some(_) => CampaignMode::Fresh,
        None => CampaignMode::Continue {
            gens: args.u64("--gens").filter(|_| args.typed("--gens")),
        },
    };
    if let CampaignMode::Continue { .. } = mode {
        for flag in help::verb("campaign")
            .expect("`campaign` is registered")
            .family_flags(help::Family::Sole)
        {
            if !CONTINUATION_FLAGS.contains(&flag.name) && args.typed(flag.name) {
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
    // ABSENT flag overrides nothing: a switch only ever turns a setting on, so a
    // spec that enables swarm is not silently undone by omitting --swarm, and a
    // value flag replaces the spec's value only when supplied.
    spec.swarm |= args.flag("--swarm");
    if let Some(names) = args.text("--vary") {
        spec.vary = Vary::from_names(names.split(',')).expect("validated by the registry grammar");
    }
    if let Some(value) = args.u64("--fault-scale-permille") {
        spec.fault_scale_permille = value;
    }
    if args.flag("--no-verify") {
        spec.verify = false;
    }
    let dns_entries = args.texts("--dns-entry");
    if !dns_entries.is_empty() {
        spec.dns_entries = dns_entries.into_iter().map(str::to_string).collect();
    }
    let allow_symbols = args.texts("--allow");
    if !allow_symbols.is_empty() {
        spec.allow_symbols = allow_symbols.into_iter().map(str::to_string).collect();
    }
    if let Some(value) = args.text("--allow-unsupported-symbols") {
        spec.allow_unsupported_symbols = Some(value.to_string());
    }
    if args.flag("--allow-randomized-address-layout") {
        spec.address_layout = Some(patina_dst_trace::AddressLayout::Randomized);
    }
    if let Some(cpus) = args.u32("--cpus") {
        spec.cpus = Some(cpus);
    }
    // A continuation's recorded spec is authoritative, so an environment
    // default (PATINA_MOUNT) is not resolved there, where it would be ignored.
    if let Some(dir) = args.path("--mount").filter(|_| mode == CampaignMode::Fresh) {
        let dir = dir.to_str().ok_or_else(|| {
            CliError(format!(
                "campaign --mount {} is not a UTF-8 path",
                dir.display()
            ))
        })?;
        spec.mount = Some(super::spec::Mount::unresolved(dir)?);
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
    let timeout_secs_override = timeout_secs.filter(|_| args.typed("--timeout-secs"));

    if let CampaignMode::Continue { .. } = mode {
        if !guest_args.is_empty() {
            return Err(reject_continuation_override("guest arguments"));
        }
        return Ok(CampaignInvocation {
            artifact: None,
            out_dir,
            spec,
            mode,
            timeout_secs_override,
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
    spec.allow_unmet_sometimes |= args.flag("--allow-unmet-sometimes");
    if !guest_args.is_empty() {
        spec.guest_args = guest_args;
    }
    // A DNS band rides on the host table, so a subset that names `dns` without
    // one asked for a plane that could never be drawn.
    if spec.vary.faults != FaultPlanes::ALL
        && spec.vary.faults.contains(FaultPlane::Dns)
        && spec.dns_entries.is_empty()
    {
        return Err(CliError::usage(
            "--vary selects the dns plane, but the campaign has no --dns-entry host table, \
             so no DNS fault could be drawn; add --dns-entry NAME=ADDR or leave dns out",
        ));
    }
    validate_exclusions(&spec)?;
    validate_swarm(&spec)?;
    Ok(CampaignInvocation {
        artifact,
        out_dir,
        spec,
        mode,
        timeout_secs_override,
        progress_every,
        cli: cli_line,
    })
}

/// The flags an artifact-free continuation accepts: the generation target,
/// and what describes this invocation rather than the campaign's shape, which
/// the recorded spec owns.
const CONTINUATION_FLAGS: &[&str] = &["--gens", "--out-dir", "--timeout-secs", "--progress-every"];

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
        "{name} needs the artifact: a campaign command without one continues the out-dir's \
         recorded campaign as it is; give the artifact to start or continue a campaign with \
         these settings"
    ))
}

#[cfg(test)]
mod tests;

/// `--swarm` masks the classes a generation enables; with no buggify and no
/// drawn fault knob (crash included) there is nothing to mask, and every
/// generation would explore exactly what a non-swarm one does.
fn validate_swarm(spec: &CampaignSpec) -> Result<(), CliError> {
    let maskable = spec.vary.buggify
        || FaultKnob::ALL
            .iter()
            .any(|knob| spec.vary.faults.draws(*knob) && !spec.exclude_knobs.contains(knob));
    if spec.swarm && !maskable {
        return Err(CliError::usage(
            "--swarm masks fault classes and buggify, but the campaign enables none; \
             add buggify or a fault plane to --vary, or drop --swarm",
        ));
    }
    Ok(())
}

/// An excluded knob must belong to a plane the merged campaign selects: an
/// exclusion from a plane that is never drawn would record a choice that
/// changes nothing.
fn validate_exclusions(spec: &CampaignSpec) -> Result<(), CliError> {
    match spec
        .exclude_knobs
        .iter()
        .find(|knob| !spec.vary.faults.draws(**knob))
    {
        Some(knob) => Err(CliError::usage(format!(
            "the spec excludes {}, but the campaign does not select its fault plane, \
             so the exclusion would change nothing; select the plane with --vary or drop the exclusion",
            knob.meta().flag
        ))),
        None => Ok(()),
    }
}
