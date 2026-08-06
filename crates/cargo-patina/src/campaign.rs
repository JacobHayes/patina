//! `cargo patina campaign` — a config-driven, deterministic fault-and-schedule
//! sweep that generalizes the battle-tested shell campaign machinery
//! (`testbeds/workq/fuzz-sweep.sh`, `testbeds/buggify-campaign.sh`) into a
//! first-class product surface.
//!
//! A campaign runs `generations` independent child `cargo patina run` processes
//! over one artifact. Everything is a pure function of the generation number, so a
//! re-run with the same spec reproduces the same seeds, the same per-generation
//! knobs, the same outcomes, and the same failure signatures — the determinism the
//! `--selftest` and the deterministic-re-run test prove.
//!
//! Per generation:
//!   * the run seed and every randomized knob derive from `SHA-256("patina-campaign
//!     -<seed_base>-<generation>")` (no wall clock, no `$RANDOM`), exactly the fuzz-sweep
//!     scheme;
//!   * the child streams a generalized result contract — `PATINA_RESULT <k=v…>`
//!     and `PATINA_VIOLATION <class> <detail>` (harness-agnostic generalizations of
//!     the existing per-testbed result/violation and `PATINA_SDK_REPORT`
//!     conventions), plus the runtime's own `PATINA_VIOLATION liveness` /
//!     `PATINA_SCHEDULE_POLICY` diagnostics;
//!   * the [`classify`] pure classifier assigns one of seven outcome classes with
//!     the same strictness discipline as fuzz-sweep (an explicit finding is never
//!     downgraded, a nonzero exit is never silently OK, and an unrecognized outcome
//!     lands loudly in `UNCLASSIFIED`);
//!   * a per-failure [`Signature`] (class + normalized violation-detail shape +
//!     policy/bug-depth annotation) is accumulated into a signature store in the
//!     output directory: repeats are deduped, the first occurrence of a novel
//!     signature is flagged and its trace saved with a `cargo patina replay`/re-run
//!     reproduce command.
//!
//! Output is a summary-first human report or a `patina.campaign/v2` JSON envelope
//! (the `patina.result/v1` envelope family extended for a campaign). Both are
//! progressive-disclosure: the envelope carries class counts, deduped signatures,
//! and per-run detail ONLY for novel/failing generations, with pointers to the
//! full on-disk artifacts (the signature store, saved traces, reports); the human
//! stream prints novel/failing generations plus a periodic progress heartbeat
//! rather than one line per generation.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::aux_store::{AuxFoldDecision, fold_decision, validate_resume_watermark};
use crate::coverage::{CampaignCoverageStore, CoverageArtifact, FoldOutcome, top_uncovered_crates};
use crate::sdk_report::{CoverageTally, ExercisedSite};
use crate::{CliError, reject_inline, required_value, set_once, split_opt};

#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// The stable schema identifier for the campaign JSON envelope, extending the
/// `patina.result/v1` family. `v2` is summary-first: `notable_runs` carries only
/// the novel/failing generations (v1's `runs` dumped every generation), and an
/// `artifacts` object points at the full on-disk detail.
const CAMPAIGN_ENVELOPE_SCHEMA: &str = "patina.campaign/v2";
const CAMPAIGN_STATE_SCHEMA: &str = "patina.campaign.state/v1";
const CAMPAIGN_SIGNATURES_SCHEMA: &str = "patina.campaign.signatures/v1";
const DEFAULT_PLATEAU_AFTER: u64 = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowUnmetSometimes {
    Always,
    BelowGenerations(u64),
}

/// The default progress-heartbeat cadence: in human mode, print one
/// `PATINA_CAMPAIGN_PROGRESS` line every this-many generations (on top of the
/// always-printed novel/failing lines). 100 is a deliberate middle ground — at the
/// default 40-generation campaign it yields a clean summary with no heartbeat
/// noise, while a multi-thousand-generation sweep still gets a steady but sparse
/// "still alive" pulse (~1% of the old per-generation line volume). `--progress-every 1`
/// restores the full per-generation stream; `--progress-every 0` silences the heartbeat.
const DEFAULT_PROGRESS_EVERY: u64 = 100;

// ===========================================================================
// Spec
// ===========================================================================

/// A campaign specification. Every field has a default; a `--spec FILE.json`
/// supplies overrides and individual flags override the spec, so a campaign can be
/// driven entirely by flags, entirely by a JSON spec, or a mix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSpec {
    pub generations: u64,
    pub seed_base: u64,
    pub timeout_secs: u64,
    pub guest_args: Vec<String>,
    /// Randomize cooperative-SUT (buggify) activation/fire per generation.
    pub buggify: bool,
    /// Apply seed-derived swarm fault-class selection (native only).
    pub swarm: bool,
    /// Randomize a PCT bug depth per generation (native only).
    pub pct: bool,
    /// Randomize fault knobs (net drop, sleep jitter) per generation.
    pub faults: bool,
    /// Generic liveness-watchdog budget (virtual nanoseconds), applied every
    /// generation when set.
    pub watchdog_nanos: Option<u64>,
    /// Heal-then-converge budget (virtual nanoseconds), applied every generation
    /// when set.
    pub converge_nanos: Option<u64>,
    /// Explicit heal-then-converge arm-time override (virtual nanoseconds).
    pub heal_after_nanos: Option<u64>,
    /// Also write a wave-14 `--report` HTML for each failing generation.
    pub report: bool,
    /// Report native edge-coverage plateau after this many generations without a
    /// new edge; 0 disables the plateau flag.
    pub plateau_after: u64,
    /// Waive the default campaign-level gate for `sometimes!` sites that were
    /// registered but never satisfied.
    pub allow_unmet_sometimes: Option<AllowUnmetSometimes>,
}

impl Default for CampaignSpec {
    fn default() -> Self {
        Self {
            generations: 40,
            seed_base: 0,
            timeout_secs: 60,
            guest_args: Vec::new(),
            buggify: false,
            swarm: false,
            pct: false,
            faults: false,
            watchdog_nanos: None,
            converge_nanos: None,
            heal_after_nanos: None,
            report: false,
            plateau_after: DEFAULT_PLATEAU_AFTER,
            allow_unmet_sometimes: None,
        }
    }
}

impl CampaignSpec {
    /// Merge a JSON spec object over the defaults. Unknown keys are rejected so a
    /// typo in a spec file fails loudly rather than being silently ignored.
    fn apply_json(&mut self, value: &serde_json::Value) -> Result<(), CliError> {
        let object = value
            .as_object()
            .ok_or_else(|| CliError("campaign spec must be a JSON object".into()))?;
        for (key, val) in object {
            match key.as_str() {
                "generations" => self.generations = json_u64(key, val)?,
                "seed_base" => self.seed_base = json_u64(key, val)?,
                "timeout_secs" => self.timeout_secs = json_u64(key, val)?,
                "guest_args" => {
                    let array = val
                        .as_array()
                        .ok_or_else(|| CliError("guest_args must be a JSON array".into()))?;
                    self.guest_args = array
                        .iter()
                        .map(|v| {
                            v.as_str().map(str::to_string).ok_or_else(|| {
                                CliError("guest_args entries must be strings".into())
                            })
                        })
                        .collect::<Result<_, _>>()?;
                }
                "buggify" => self.buggify = json_bool(key, val)?,
                "swarm" => self.swarm = json_bool(key, val)?,
                "pct" => self.pct = json_bool(key, val)?,
                "faults" => self.faults = json_bool(key, val)?,
                "watchdog_nanos" => self.watchdog_nanos = Some(json_u64(key, val)?),
                "converge_nanos" => self.converge_nanos = Some(json_u64(key, val)?),
                "heal_after_nanos" => self.heal_after_nanos = Some(json_u64(key, val)?),
                "report" => self.report = json_bool(key, val)?,
                "plateau_after" => self.plateau_after = json_u64(key, val)?,
                "allow_unmet_sometimes" => {
                    self.allow_unmet_sometimes = Some(json_allow_unmet_sometimes(key, val)?)
                }
                other => {
                    return Err(CliError(format!(
                        "unknown campaign spec key {other:?}; expected generations, seed_base, \
                         timeout_secs, guest_args, buggify, swarm, pct, faults, watchdog_nanos, \
                         converge_nanos, heal_after_nanos, report, plateau_after, or \
                         allow_unmet_sometimes"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn json_u64(key: &str, value: &serde_json::Value) -> Result<u64, CliError> {
    value
        .as_u64()
        .ok_or_else(|| CliError(format!("campaign spec {key:?} must be an unsigned integer")))
}

fn json_bool(key: &str, value: &serde_json::Value) -> Result<bool, CliError> {
    value
        .as_bool()
        .ok_or_else(|| CliError(format!("campaign spec {key:?} must be a boolean")))
}

fn json_allow_unmet_sometimes(
    key: &str,
    value: &serde_json::Value,
) -> Result<AllowUnmetSometimes, CliError> {
    if value.as_bool() == Some(true) {
        return Ok(AllowUnmetSometimes::Always);
    }
    if let Some(value) = value.as_u64() {
        if value == 0 {
            return Err(CliError(format!(
                "campaign spec {key:?} must be true or a positive unsigned integer"
            )));
        }
        return Ok(AllowUnmetSometimes::BelowGenerations(value));
    }
    Err(CliError(format!(
        "campaign spec {key:?} must be true or a positive unsigned integer"
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CampaignMode {
    Fresh,
    Extend { additional: u64 },
    Resume,
}

/// A parsed `campaign` invocation.
#[derive(Debug)]
pub struct CampaignInvocation {
    artifact: Option<PathBuf>,
    out_dir: PathBuf,
    spec: CampaignSpec,
    mode: CampaignMode,
    selftest: bool,
    /// A continuation-only host-side timeout override. It does not rewrite the
    /// out-dir's recorded spec; the effective value is recorded on the invocation
    /// audit record.
    timeout_secs_override: Option<u64>,
    /// Human-mode progress-heartbeat cadence (generations per
    /// `PATINA_CAMPAIGN_PROGRESS` line). Presentation only — it never affects the
    /// deterministic sweep, so it lives here rather than on [`CampaignSpec`].
    progress_every: u64,
    /// Best-effort audit spelling for the invocation record. Output/global flags
    /// stripped before verb parsing are intentionally not reconstructed.
    cli: String,
}

// ===========================================================================
// Parsing + dispatch
// ===========================================================================

/// Parse `campaign [--selftest] | campaign <ARTIFACT> [flags] [-- GUEST_ARGS…] |
/// campaign --extend N [--out-dir DIR] | campaign --resume [--out-dir DIR]`.
pub fn parse(mut arguments: Vec<OsString>) -> Result<CampaignInvocation, CliError> {
    let cli = campaign_cli(&arguments);

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
            cli,
        });
    }

    let continuation_requested = has_continuation_flag(&arguments);

    // Options may lead the artifact (`campaign --gens 5 art.wasm`), so locate it
    // registry-arity-aware rather than insisting it be the first token. In
    // continuation mode, the absence of an artifact is intentional; a positional
    // that is present is rejected after parsing so the error names the doctrine.
    let scan = crate::locate_positionals("campaign", &arguments, 1);
    let artifact = scan.positionals.into_iter().next().map(PathBuf::from);
    if artifact.is_none() && !continuation_requested {
        if let Some(stop) = scan.stop {
            crate::reject_stranded_artifact("campaign", &arguments[stop..])?;
            return Err(CliError::usage(format!(
                "unsupported option {:?} for `campaign`; campaign requires an artifact path (a .wasm module or native binary), or --selftest",
                arguments[stop].to_string_lossy()
            )));
        }
        return Err(CliError::usage(
            "campaign requires an artifact path (a .wasm module or native binary), or --selftest",
        ));
    }
    let arguments = scan.rest;
    let mut spec = CampaignSpec::default();
    let mut out_dir: Option<PathBuf> = None;
    // Scalar overrides shadow the spec until the loop ends: duplicates are
    // rejected via `set_once`, and a flag overrides `--spec` regardless of
    // argument order (previously a flag preceding `--spec` was silently
    // overwritten by the spec file).
    let mut generations: Option<u64> = None;
    let mut seed_start: Option<u64> = None;
    let mut timeout_secs: Option<u64> = None;
    let mut spec_path: Option<String> = None;
    let mut progress_every: Option<u64> = None;
    let mut plateau_after: Option<u64> = None;
    let mut allow_unmet_sometimes: Option<AllowUnmetSometimes> = None;
    let mut extend: Option<u64> = None;
    let mut resume: Option<()> = None;

    let mut index = 0;
    while index < arguments.len() {
        let text = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("campaign options must be valid UTF-8"))?;
        let opt = split_opt(text);
        match opt.name {
            "--extend" => {
                let value =
                    parse_u64_flag("--extend", required_value(opt, &arguments, &mut index)?)?;
                set_once(&mut extend, value, "--extend")?;
            }
            "--resume" => {
                reject_inline(opt)?;
                set_once(&mut resume, (), "--resume")?;
            }
            "--spec" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--spec"));
                }
                let path = required_value(opt, &arguments, &mut index)?.to_string();
                set_once(&mut spec_path, path.clone(), "--spec")?;
                let text = fs::read_to_string(&path)
                    .map_err(|e| CliError(format!("failed to read campaign spec {path}: {e}")))?;
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| CliError(format!("campaign spec {path} is invalid JSON: {e}")))?;
                spec.apply_json(&json)?;
            }
            "--out-dir" => {
                let path = PathBuf::from(required_value(opt, &arguments, &mut index)?);
                set_once(&mut out_dir, path, "--out-dir")?;
            }
            "--gens" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--gens"));
                }
                let value = parse_u64_flag("--gens", required_value(opt, &arguments, &mut index)?)?;
                set_once(&mut generations, value, "--gens")?;
            }
            "--seed-start" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--seed-start"));
                }
                let value =
                    parse_u64_flag("--seed-start", required_value(opt, &arguments, &mut index)?)?;
                set_once(&mut seed_start, value, "--seed-start")?;
            }
            "--timeout-secs" => {
                let value = parse_u64_flag(
                    "--timeout-secs",
                    required_value(opt, &arguments, &mut index)?,
                )?;
                set_once(&mut timeout_secs, value, "--timeout-secs")?;
            }
            "--progress-every" => {
                let value = parse_u64_flag(
                    "--progress-every",
                    required_value(opt, &arguments, &mut index)?,
                )?;
                set_once(&mut progress_every, value, "--progress-every")?;
            }
            "--plateau-after" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--plateau-after"));
                }
                let value = parse_u64_flag(
                    "--plateau-after",
                    required_value(opt, &arguments, &mut index)?,
                )?;
                set_once(&mut plateau_after, value, "--plateau-after")?;
            }
            "--allow-unmet-sometimes" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--allow-unmet-sometimes"));
                }
                let value = parse_allow_unmet_sometimes_flag(opt)?;
                set_once(&mut allow_unmet_sometimes, value, "--allow-unmet-sometimes")?;
            }
            "--buggify" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--buggify"));
                }
                reject_inline(opt)?;
                spec.buggify = true;
            }
            "--swarm" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--swarm"));
                }
                reject_inline(opt)?;
                spec.swarm = true;
            }
            "--sched-pct" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--sched-pct"));
                }
                reject_inline(opt)?;
                spec.pct = true;
            }
            "--faults" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--faults"));
                }
                reject_inline(opt)?;
                spec.faults = true;
            }
            "--report" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--report"));
                }
                reject_inline(opt)?;
                spec.report = true;
            }
            "--liveness-watchdog" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--liveness-watchdog"));
                }
                let value = parse_u64_flag(
                    "--liveness-watchdog",
                    required_value(opt, &arguments, &mut index)?,
                )?;
                set_once(&mut spec.watchdog_nanos, value, "--liveness-watchdog")?;
            }
            "--converge-within" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--converge-within"));
                }
                let value = parse_u64_flag(
                    "--converge-within",
                    required_value(opt, &arguments, &mut index)?,
                )?;
                set_once(&mut spec.converge_nanos, value, "--converge-within")?;
            }
            "--heal-after" => {
                if continuation_requested {
                    return Err(reject_continuation_override("--heal-after"));
                }
                let value =
                    parse_u64_flag("--heal-after", required_value(opt, &arguments, &mut index)?)?;
                set_once(&mut spec.heal_after_nanos, value, "--heal-after")?;
            }
            other => {
                return Err(CliError::usage(format!(
                    "unsupported option {other:?} for `campaign`"
                )));
            }
        }
        index += 1;
    }

    let mode = match (extend, resume.is_some()) {
        (Some(_), true) => {
            return Err(CliError::usage(
                "--extend and --resume are redundant; choose exactly one continuation mode",
            ));
        }
        (Some(0), false) => {
            return Err(CliError::usage(
                "--extend 0 is redundant; use --resume to finish an interrupted campaign or --extend N with N > 0",
            ));
        }
        (Some(additional), false) => CampaignMode::Extend { additional },
        (None, true) => CampaignMode::Resume,
        (None, false) => CampaignMode::Fresh,
    };

    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("patina-campaign-out"));
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
            progress_every: progress_every.unwrap_or(DEFAULT_PROGRESS_EVERY),
            cli,
        });
    }

    if let Some(generations) = generations {
        spec.generations = generations;
    }
    if let Some(seed_start) = seed_start {
        spec.seed_base = seed_start;
    }
    if let Some(timeout_secs) = timeout_secs {
        spec.timeout_secs = timeout_secs;
    }
    if let Some(value) = plateau_after {
        spec.plateau_after = value;
    }
    if let Some(value) = allow_unmet_sometimes {
        spec.allow_unmet_sometimes = Some(value);
    }
    if !guest_args.is_empty() {
        spec.guest_args = guest_args;
    }
    let artifact = artifact.ok_or_else(|| {
        CliError::usage(
            "campaign requires an artifact path (a .wasm module or native binary), or --selftest",
        )
    })?;
    Ok(CampaignInvocation {
        artifact: Some(artifact),
        out_dir,
        spec,
        mode,
        selftest: false,
        timeout_secs_override: None,
        progress_every: progress_every.unwrap_or(DEFAULT_PROGRESS_EVERY),
        cli,
    })
}

fn has_continuation_flag(arguments: &[OsString]) -> bool {
    arguments.iter().any(|argument| {
        argument
            .to_str()
            .is_some_and(|text| matches!(split_opt(text).name, "--extend" | "--resume"))
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

fn parse_u64_flag(name: &str, value: &str) -> Result<u64, CliError> {
    value
        .parse()
        .map_err(|_| CliError::usage(format!("{name} must be an unsigned integer; got {value:?}")))
}

fn parse_positive_u64_flag(name: &str, value: &str) -> Result<u64, CliError> {
    let value = parse_u64_flag(name, value)?;
    if value == 0 {
        return Err(CliError::usage(format!(
            "{name} must be a positive unsigned integer; got 0"
        )));
    }
    Ok(value)
}

fn parse_allow_unmet_sometimes_flag(opt: crate::Opt<'_>) -> Result<AllowUnmetSometimes, CliError> {
    match opt.inline {
        Some(value) => Ok(AllowUnmetSometimes::BelowGenerations(
            parse_positive_u64_flag("--allow-unmet-sometimes", value)?,
        )),
        None => Ok(AllowUnmetSometimes::Always),
    }
}

/// Route the `campaign` verb.
pub fn execute(invocation: CampaignInvocation) -> Result<i32, CliError> {
    if invocation.selftest {
        return selftest();
    }
    run_campaign(invocation)
}

// ===========================================================================
// Classifier (pure) + signatures
// ===========================================================================

/// The per-generation outcome classes, in descending severity. An explicit
/// finding is never downgraded, and a nonzero exit is never silently OK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignClass {
    /// The run completed clean (exit 0, no finding markers).
    Ok,
    /// A system-under-test safety/assertion violation: `PATINA_VIOLATION`,
    /// `PATINA_ALWAYS_VIOLATION`, a testbed violation marker, `BUG_CAUGHT`, or a
    /// guest panic.
    Violation,
    /// A liveness-watchdog violation (`PATINA_VIOLATION liveness`/`converge`): a
    /// virtual-time no-progress wedge.
    Liveness,
    /// Patina fail-closed refusal: a fingerprint/trace mismatch, a duplicate
    /// buggify label, a declared-but-never-called setup gate, a runtime that
    /// refused to initialize, or a bare shim SIGABRT.
    FailClosedAbort,
    /// The `--starve` supervisor stall backstop killed a wedged run (exit 111).
    StarvationStall,
    /// Harness/build infrastructure failure (cargo/build/signal/OOM), not a SUT
    /// finding.
    Infra,
    /// A nonzero exit that matched no class above — an unknown/unparseable outcome.
    /// Loud and always a failure, so a novel failure mode is surfaced for triage
    /// rather than silently dropped or mislabeled.
    Unclassified,
}

impl CampaignClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            CampaignClass::Ok => "OK",
            CampaignClass::Violation => "VIOLATION",
            CampaignClass::Liveness => "LIVENESS",
            CampaignClass::FailClosedAbort => "FAIL_CLOSED_ABORT",
            CampaignClass::StarvationStall => "STARVATION_STALL",
            CampaignClass::Infra => "INFRA",
            CampaignClass::Unclassified => "UNCLASSIFIED",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "OK" => Some(CampaignClass::Ok),
            "VIOLATION" => Some(CampaignClass::Violation),
            "LIVENESS" => Some(CampaignClass::Liveness),
            "FAIL_CLOSED_ABORT" => Some(CampaignClass::FailClosedAbort),
            "STARVATION_STALL" => Some(CampaignClass::StarvationStall),
            "INFRA" => Some(CampaignClass::Infra),
            "UNCLASSIFIED" => Some(CampaignClass::Unclassified),
            _ => None,
        }
    }

    /// Whether this class is a failure the campaign must surface (everything but
    /// `OK`).
    pub const fn is_failure(&self) -> bool {
        !matches!(self, CampaignClass::Ok)
    }
}

const INFRA_MARKERS: &[&str] = &[
    "PATINA_INFRA",
    "incomplete trace",
    "cargo-patina:",
    "Cargo process terminated",
    "terminated by a signal",
    "could not compile",
    "No such file or directory",
    "native-build failed",
    "Resource temporarily unavailable",
    "Cannot allocate memory",
    "failed to execute child process",
];

/// Patina *refusal* markers — the deterministic runtime / shim declined to run or
/// continue (a configuration/fingerprint/audit fail-close), as opposed to a
/// system-under-test invariant violation.
const FAIL_CLOSED_MARKERS: &[&str] = &[
    "PATINA_BUGGIFY_DUPLICATE_LABEL",
    "PATINA_BUGGIFY_SETUP_NEVER_CALLED",
    "fingerprint mismatch",
    "trace operation mismatch",
    "operation mismatch",
    "the deterministic runtime failed to initialize",
    "must run under `cargo patina run`",
    "unsupported-import",
    "unknown-import",
];

/// System-under-test invariant/safety violations (a real bug), including a Patina
/// `always!` abort and a guest panic.
const VIOLATION_MARKERS: &[&str] = &[
    "PATINA_VIOLATION",
    "PATINA_ALWAYS_VIOLATION",
    "WORKQ_VIOLATION",
    "BUG_CAUGHT",
    "panicked at",
];

/// The exit code a raw SIGABRT surfaces as (128 + SIGABRT(6)). The native shim
/// aborts fail-closed via `std::process::abort()` on a fatal refusal it cannot
/// safely continue past; a SIGABRT that carries no system-under-test finding is a
/// fail-closed abort, distinct from a generic nonzero failure.
const SIGABRT_EXIT: i32 = 134;

/// Classify one generation's outcome from its exit code and captured streams.
/// Ordering encodes severity: an explicit finding wins over exit-code heuristics,
/// a nonzero exit is never silently OK, and anything unrecognized lands LOUDLY in
/// [`CampaignClass::Unclassified`] rather than being downgraded to a benign class.
pub fn classify(exit_code: i32, stdout: &str, stderr: &str) -> CampaignClass {
    let combined = format!("{stdout}\n{stderr}");
    let has = |needles: &[&str]| needles.iter().any(|n| combined.contains(n));

    // 1. Liveness is its own class (a "never converges" wedge). Emitted per the
    //    interface contract as `PATINA_VIOLATION liveness …` / `… converge …`.
    if combined.contains("PATINA_VIOLATION liveness ")
        || combined.contains("PATINA_VIOLATION converge ")
    {
        return CampaignClass::Liveness;
    }
    // 2. A system-under-test safety/assertion violation — fires even on exit 0 (a
    //    violated invariant is a bug however the process exited), and is
    //    distinguished from a Patina refusal below.
    if has(VIOLATION_MARKERS) {
        return CampaignClass::Violation;
    }
    // 3. Patina fail-closed refusal: a shim fatal-abort refusal line, or a raw
    //    SIGABRT carrying no SUT finding (checked after the SUT-violation markers,
    //    so an `always!` abort stays a VIOLATION). Its own class, never a generic
    //    failure.
    if has(FAIL_CLOSED_MARKERS) || exit_code == SIGABRT_EXIT {
        return CampaignClass::FailClosedAbort;
    }
    // 4. The `--starve` supervisor stall backstop.
    if exit_code == STARVATION_STALL_EXIT || combined.contains("patina: starvation stall") {
        return CampaignClass::StarvationStall;
    }
    // 5. Harness/build infrastructure — only when there is no SUT finding above.
    if has(INFRA_MARKERS) {
        return CampaignClass::Infra;
    }
    // 6. A clean exit with no finding markers is OK.
    if exit_code == 0 {
        return CampaignClass::Ok;
    }
    // 7. A nonzero exit that matched no class above is UNCLASSIFIED — surfaced
    //    loudly for triage, never silently dropped as OK or mislabeled.
    CampaignClass::Unclassified
}

/// The distinct exit code the native supervisor returns for a `--starve` stall,
/// mirrored here for the classifier (kept in sync with `lib.rs`).
const STARVATION_STALL_EXIT: i32 = 111;

/// A per-failure signature: the outcome class plus a normalized shape of the
/// primary finding line (digits/hex collapsed so run-specific values do not
/// fragment a signature) plus any policy/bug-depth annotation. Two failures with
/// the same signature are "the same bug"; a never-before-seen signature is NOVEL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub class: CampaignClass,
    pub shape: String,
    pub policy: String,
}

impl Signature {
    /// The stable dedup key.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.class.as_str(), self.shape, self.policy)
    }
}

/// Build a signature from a classified generation's streams.
pub fn signature(class: CampaignClass, stdout: &str, stderr: &str) -> Signature {
    let shape = normalize_shape(&primary_finding_line(class, stdout, stderr));
    let policy = policy_annotation(stdout, stderr);
    Signature {
        class,
        shape,
        policy,
    }
}

/// The single most representative finding line for the class.
fn primary_finding_line(class: CampaignClass, stdout: &str, stderr: &str) -> String {
    let lines: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
    let prefixes: &[&str] = match class {
        CampaignClass::Liveness => &["PATINA_VIOLATION liveness ", "PATINA_VIOLATION converge "],
        CampaignClass::Violation => &[
            "PATINA_VIOLATION",
            "PATINA_ALWAYS_VIOLATION",
            "WORKQ_VIOLATION",
            "BUG_CAUGHT",
        ],
        CampaignClass::FailClosedAbort => &[
            "PATINA_BUGGIFY_DUPLICATE_LABEL",
            "PATINA_BUGGIFY_SETUP_NEVER_CALLED",
            "fingerprint mismatch",
            "the deterministic runtime failed to initialize",
        ],
        CampaignClass::StarvationStall => &["patina: starvation stall"],
        CampaignClass::Infra => &[
            "patina: campaign generation exceeded timeout",
            "cargo-patina:",
        ],
        CampaignClass::Ok | CampaignClass::Unclassified => &[],
    };
    for prefix in prefixes {
        if let Some(line) = lines.iter().find(|l| l.trim().contains(prefix)) {
            return line.trim().to_string();
        }
    }
    // Fallbacks: a panic line, else the last non-empty stderr line.
    if let Some(line) = lines.iter().find(|l| l.contains("panicked at")) {
        return line.trim().to_string();
    }
    stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

/// Collapse run-specific values (digit and hex runs) so a signature captures the
/// *shape* of a finding, not its exact numbers — `elapsed_nanos=400` and
/// `elapsed_nanos=920` share one signature.
fn normalize_shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            // Collapse a maximal run of ASCII digits to a single '#'.
            out.push('#');
            while chars.peek().is_some_and(|n| n.is_ascii_digit()) {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract the exploration-policy bug-depth annotation, if the run emitted one, so
/// two failures found at different interleaving depths are distinguished.
fn policy_annotation(stdout: &str, stderr: &str) -> String {
    for line in stdout.lines().chain(stderr.lines()) {
        let line = line.trim();
        if line.starts_with("PATINA_SCHEDULE_POLICY") {
            if let Some(depth) = line
                .split_whitespace()
                .find_map(|token| token.strip_prefix("bug_depth="))
            {
                return format!("bug_depth={depth}");
            }
        }
    }
    String::new()
}

// ===========================================================================
// Signature store
// ===========================================================================

/// One accumulated failure signature and its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SignatureRecord {
    class: CampaignClass,
    shape: String,
    policy: String,
    first_seen_gen: u64,
    count: u64,
    seed: u64,
    reproduce: String,
    trace: Option<String>,
    report: Option<String>,
}

impl SignatureRecord {
    fn to_json(&self, key: &str) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("signature".into(), key.into());
        map.insert("class".into(), self.class.as_str().into());
        map.insert("shape".into(), self.shape.clone().into());
        if !self.policy.is_empty() {
            map.insert("policy".into(), self.policy.clone().into());
        }
        map.insert("first_seen_gen".into(), self.first_seen_gen.into());
        map.insert("count".into(), self.count.into());
        map.insert("seed".into(), self.seed.into());
        map.insert("reproduce".into(), self.reproduce.clone().into());
        if let Some(trace) = &self.trace {
            map.insert("trace".into(), trace.clone().into());
        }
        if let Some(report) = &self.report {
            map.insert("report".into(), report.clone().into());
        }
        serde_json::Value::Object(map)
    }

    fn from_json(value: &serde_json::Value) -> Result<(String, Self), String> {
        let object = value
            .as_object()
            .ok_or_else(|| "signature record must be an object".to_string())?;
        let key = json_required_str(object, "signature")?.to_string();
        let class_text = json_required_str(object, "class")?;
        let class = CampaignClass::parse(class_text)
            .ok_or_else(|| format!("unknown campaign class {class_text:?}"))?;
        let shape = json_required_str(object, "shape")?.to_string();
        let policy = json_optional_str(object, "policy")?.unwrap_or_default();
        let record = SignatureRecord {
            class,
            shape,
            policy,
            first_seen_gen: json_required_u64(object, "first_seen_gen")?,
            count: json_required_u64(object, "count")?,
            seed: json_required_u64(object, "seed")?,
            reproduce: json_required_str(object, "reproduce")?.to_string(),
            trace: json_optional_str(object, "trace")?,
            report: json_optional_str(object, "report")?,
        };
        let expected_key = format!(
            "{}|{}|{}",
            record.class.as_str(),
            record.shape,
            record.policy
        );
        if key != expected_key {
            return Err(format!(
                "signature key {key:?} does not match canonical key {expected_key:?}"
            ));
        }
        if record.to_json(&key) != *value {
            return Err("signature record is not in canonical lossless form".to_string());
        }
        Ok((key, record))
    }
}

// ===========================================================================
// Campaign driver
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenerationOutcome {
    generation: u64,
    seed: u64,
    class: CampaignClass,
    flags: Vec<String>,
    novel: bool,
    signature_key: Option<String>,
}

impl GenerationOutcome {
    fn is_notable(&self) -> bool {
        self.novel || self.class.is_failure()
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "generation": self.generation,
            "seed": self.seed,
            "class": self.class.as_str(),
            "novel": self.novel,
            "signature": self.signature_key.clone(),
            "flags": self.flags.clone(),
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "notable run must be an object".to_string())?;
        let class_text = json_required_str(object, "class")?;
        let class = CampaignClass::parse(class_text)
            .ok_or_else(|| format!("unknown campaign class {class_text:?}"))?;
        let flags = object
            .get("flags")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "notable run flags must be an array".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "notable run flags entries must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signature_key = match object.get("signature") {
            Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| "notable run signature must be a string or null".to_string())?
                    .to_string(),
            ),
            None => return Err("notable run missing signature".to_string()),
        };
        let outcome = GenerationOutcome {
            generation: json_required_u64(object, "generation")?,
            seed: json_required_u64(object, "seed")?,
            class,
            flags,
            novel: json_required_bool(object, "novel")?,
            signature_key,
        };
        if outcome.to_json() != *value {
            return Err("notable run is not in canonical lossless form".to_string());
        }
        Ok(outcome)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactIdentity {
    path: String,
    sha256: String,
    family: &'static str,
}

impl ArtifactIdentity {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path.clone(),
            "sha256": self.sha256.clone(),
            "family": self.family,
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "artifact identity must be an object".to_string())?;
        let family_text = json_required_str(object, "family")?;
        let family = parse_artifact_family(family_text)
            .ok_or_else(|| format!("unknown artifact family {family_text:?}"))?;
        let identity = ArtifactIdentity {
            path: json_required_str(object, "path")?.to_string(),
            sha256: json_required_str(object, "sha256")?.to_string(),
            family,
        };
        if identity.to_json() != *value {
            return Err("artifact identity is not in canonical lossless form".to_string());
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InvocationRecord {
    cli: String,
    from_gen: u64,
    gens_run: u64,
    timeout_secs: u64,
    elapsed_secs: u64,
}

impl InvocationRecord {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cli": self.cli.clone(),
            "from_gen": self.from_gen,
            "gens_run": self.gens_run,
            "timeout_secs": self.timeout_secs,
            "elapsed_secs": self.elapsed_secs,
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "invocation record must be an object".to_string())?;
        let record = InvocationRecord {
            cli: json_required_str(object, "cli")?.to_string(),
            from_gen: json_required_u64(object, "from_gen")?,
            gens_run: json_required_u64(object, "gens_run")?,
            timeout_secs: json_required_u64(object, "timeout_secs")?,
            elapsed_secs: json_required_u64(object, "elapsed_secs")?,
        };
        if record.to_json() != *value {
            return Err("invocation record is not in canonical lossless form".to_string());
        }
        Ok(record)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CampaignState {
    artifact: ArtifactIdentity,
    spec: CampaignSpec,
    generations_done: u64,
    classes: BTreeMap<String, u64>,
    signatures: BTreeMap<String, SignatureRecord>,
    notable_runs: Vec<GenerationOutcome>,
    invocations: Vec<InvocationRecord>,
}

impl CampaignState {
    fn fresh(artifact: ArtifactIdentity, spec: CampaignSpec) -> Self {
        Self {
            artifact,
            spec,
            generations_done: 0,
            classes: BTreeMap::new(),
            signatures: BTreeMap::new(),
            notable_runs: Vec::new(),
            invocations: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": CAMPAIGN_STATE_SCHEMA,
            "artifact": self.artifact.to_json(),
            "spec": spec_to_json(&self.spec),
            "generations_done": self.generations_done,
            "classes": self.classes.clone(),
            "signatures": signatures_to_json(&self.signatures),
            "notable_runs": self.notable_runs.iter().map(GenerationOutcome::to_json).collect::<Vec<_>>(),
            "invocations": self.invocations.iter().map(InvocationRecord::to_json).collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "campaign state must be a JSON object".to_string())?;
        let schema = json_required_str(object, "schema")?;
        if schema != CAMPAIGN_STATE_SCHEMA {
            return Err(format!("unsupported schema {schema:?}"));
        }
        let artifact = ArtifactIdentity::from_json(
            object
                .get("artifact")
                .ok_or_else(|| "campaign state missing artifact".to_string())?,
        )?;
        let spec = spec_from_state_json(
            object
                .get("spec")
                .ok_or_else(|| "campaign state missing spec".to_string())?,
        )?;
        let generations_done = json_required_u64(object, "generations_done")?;
        let classes = parse_class_counts(
            object
                .get("classes")
                .ok_or_else(|| "campaign state missing classes".to_string())?,
        )?;
        let signatures = parse_signature_records(
            object
                .get("signatures")
                .ok_or_else(|| "campaign state missing signatures".to_string())?,
        )?;
        let notable_runs = parse_notable_runs(
            object
                .get("notable_runs")
                .ok_or_else(|| "campaign state missing notable_runs".to_string())?,
        )?;
        let invocations = parse_invocations(
            object
                .get("invocations")
                .ok_or_else(|| "campaign state missing invocations".to_string())?,
        )?;
        let state = CampaignState {
            artifact,
            spec,
            generations_done,
            classes,
            signatures,
            notable_runs,
            invocations,
        };
        state.validate()?;
        if state.to_json() != *value {
            return Err("campaign state is not in canonical lossless form".to_string());
        }
        Ok(state)
    }

    fn validate(&self) -> Result<(), String> {
        if self.generations_done > self.spec.generations {
            return Err(format!(
                "generations_done={} exceeds target generations={}",
                self.generations_done, self.spec.generations
            ));
        }
        let counted: u64 = self.classes.values().sum();
        if counted != self.generations_done {
            return Err(format!(
                "class histogram counts {counted} generations but cursor is {}",
                self.generations_done
            ));
        }
        let signature_total: u64 = self.signatures.values().map(|record| record.count).sum();
        let failures = class_counts_failures(&self.classes);
        if signature_total != failures {
            return Err(format!(
                "signature counts {signature_total} failures but class histogram has {failures}"
            ));
        }
        for run in &self.notable_runs {
            if run.generation >= self.generations_done {
                return Err(format!(
                    "notable run generation {} is beyond cursor {}",
                    run.generation, self.generations_done
                ));
            }
            if !run.is_notable() {
                return Err(format!(
                    "non-notable OK generation {} was persisted as notable",
                    run.generation
                ));
            }
        }
        Ok(())
    }
}

fn json_required_str<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn json_optional_str(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_string()))
            .ok_or_else(|| format!("{key} must be a string")),
        None => Ok(None),
    }
}

fn json_required_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn json_required_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn spec_to_json(spec: &CampaignSpec) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("generations".into(), spec.generations.into());
    map.insert("seed_base".into(), spec.seed_base.into());
    map.insert("timeout_secs".into(), spec.timeout_secs.into());
    map.insert("guest_args".into(), spec.guest_args.clone().into());
    map.insert("buggify".into(), spec.buggify.into());
    map.insert("swarm".into(), spec.swarm.into());
    map.insert("pct".into(), spec.pct.into());
    map.insert("faults".into(), spec.faults.into());
    if let Some(value) = spec.watchdog_nanos {
        map.insert("watchdog_nanos".into(), value.into());
    }
    if let Some(value) = spec.converge_nanos {
        map.insert("converge_nanos".into(), value.into());
    }
    if let Some(value) = spec.heal_after_nanos {
        map.insert("heal_after_nanos".into(), value.into());
    }
    map.insert("report".into(), spec.report.into());
    map.insert("plateau_after".into(), spec.plateau_after.into());
    if let Some(value) = spec.allow_unmet_sometimes {
        map.insert("allow_unmet_sometimes".into(), allow_unmet_to_json(value));
    }
    serde_json::Value::Object(map)
}

fn allow_unmet_to_json(value: AllowUnmetSometimes) -> serde_json::Value {
    match value {
        AllowUnmetSometimes::Always => serde_json::Value::Bool(true),
        AllowUnmetSometimes::BelowGenerations(min) => serde_json::Value::from(min),
    }
}

fn spec_from_state_json(value: &serde_json::Value) -> Result<CampaignSpec, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "spec must be an object".to_string())?;
    for key in [
        "generations",
        "seed_base",
        "timeout_secs",
        "guest_args",
        "buggify",
        "swarm",
        "pct",
        "faults",
        "report",
        "plateau_after",
    ] {
        if !object.contains_key(key) {
            return Err(format!("spec missing required key {key:?}"));
        }
    }
    let mut spec = CampaignSpec::default();
    spec.apply_json(value).map_err(|error| error.to_string())?;
    if spec_to_json(&spec) != *value {
        return Err("spec is not in canonical lossless form".to_string());
    }
    Ok(spec)
}

fn signatures_to_json(signatures: &BTreeMap<String, SignatureRecord>) -> Vec<serde_json::Value> {
    signatures
        .iter()
        .map(|(key, record)| record.to_json(key))
        .collect()
}

fn parse_signature_records(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, SignatureRecord>, String> {
    let entries = value
        .as_array()
        .ok_or_else(|| "signatures must be an array".to_string())?;
    let mut signatures = BTreeMap::new();
    for entry in entries {
        let (key, record) = SignatureRecord::from_json(entry)?;
        if signatures.insert(key.clone(), record).is_some() {
            return Err(format!("duplicate signature record {key:?}"));
        }
    }
    Ok(signatures)
}

fn parse_notable_runs(value: &serde_json::Value) -> Result<Vec<GenerationOutcome>, String> {
    value
        .as_array()
        .ok_or_else(|| "notable_runs must be an array".to_string())?
        .iter()
        .map(GenerationOutcome::from_json)
        .collect()
}

fn parse_invocations(value: &serde_json::Value) -> Result<Vec<InvocationRecord>, String> {
    value
        .as_array()
        .ok_or_else(|| "invocations must be an array".to_string())?
        .iter()
        .map(InvocationRecord::from_json)
        .collect()
}

fn parse_class_counts(value: &serde_json::Value) -> Result<BTreeMap<String, u64>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "classes must be an object".to_string())?;
    let mut classes = BTreeMap::new();
    for (class, count) in object {
        CampaignClass::parse(class).ok_or_else(|| format!("unknown campaign class {class:?}"))?;
        let count = count
            .as_u64()
            .ok_or_else(|| format!("class count for {class:?} must be an unsigned integer"))?;
        classes.insert(class.clone(), count);
    }
    Ok(classes)
}

fn class_counts_failures(class_counts: &BTreeMap<String, u64>) -> u64 {
    class_counts
        .iter()
        .filter_map(|(class, count)| {
            CampaignClass::parse(class)
                .filter(CampaignClass::is_failure)
                .map(|_| *count)
        })
        .sum()
}

#[derive(Debug)]
enum EdgeCoverageState {
    Active(Box<CampaignCoverageStore>),
    Unavailable {
        reason: &'static str,
        hint: Option<&'static str>,
    },
}

impl EdgeCoverageState {
    fn active_mut(&mut self) -> Option<&mut CampaignCoverageStore> {
        match self {
            Self::Active(store) => Some(store.as_mut()),
            Self::Unavailable { .. } => None,
        }
    }

    fn active(&self) -> Option<&CampaignCoverageStore> {
        match self {
            Self::Active(store) => Some(store.as_ref()),
            Self::Unavailable { .. } => None,
        }
    }

    fn unavailable(reason: &'static str, hint: Option<&'static str>) -> Self {
        Self::Unavailable { reason, hint }
    }
}

fn initialize_edge_coverage(
    out_dir: &Path,
    state: &CampaignState,
    campaign_generations_done: u64,
) -> Result<EdgeCoverageState, CliError> {
    if state.artifact.family != "native" {
        return Ok(EdgeCoverageState::unavailable(
            "not-native",
            Some("WASI depth arrives in coverage-depth Wave D"),
        ));
    }
    let artifact_path = PathBuf::from(&state.artifact.path);
    if !crate::binary_has_yield_points(&artifact_path)? {
        return Ok(EdgeCoverageState::unavailable(
            "not-instrumented",
            Some("rebuild with cargo patina build --yield-points"),
        ));
    }
    let coverage_dir = out_dir.join("coverage");
    fs::create_dir_all(&coverage_dir).map_err(|error| {
        CliError(format!(
            "failed to create campaign coverage dir {}: {error}",
            coverage_dir.display()
        ))
    })?;
    let artifact = CoverageArtifact {
        path: state.artifact.path.clone(),
        sha256: state.artifact.sha256.clone(),
        family: state.artifact.family.to_string(),
    };
    let fingerprint = campaign_coverage_fingerprint(&state.spec);
    let store = CampaignCoverageStore::load(
        coverage_dir,
        artifact,
        fingerprint,
        state.spec.plateau_after,
        campaign_generations_done,
    )?;
    Ok(EdgeCoverageState::Active(Box::new(store)))
}

fn campaign_coverage_fingerprint(spec: &CampaignSpec) -> String {
    let mut fingerprint = crate::yield_point_fingerprint(crate::DEFAULT_NATIVE_FINGERPRINT, true);
    if spec.buggify {
        fingerprint.push_str("+buggify");
    }
    if spec.pct {
        fingerprint.push_str("+pct");
    }
    if spec.swarm {
        fingerprint.push_str("+swarm");
    }
    fingerprint
}

fn run_campaign(invocation: CampaignInvocation) -> Result<i32, CliError> {
    let CampaignInvocation {
        artifact,
        out_dir,
        spec,
        mode,
        timeout_secs_override,
        progress_every,
        cli,
        ..
    } = invocation;

    let state_path = out_dir.join("campaign-state.json");
    let store_path = out_dir.join("signatures.json");
    let sites_path = out_dir.join("sites.json");

    if !matches!(mode, CampaignMode::Fresh) && !state_path.is_file() {
        return Err(CliError(format!(
            "campaign out-dir {} has no campaign-state.json; nothing recorded to continue",
            out_dir.display()
        )));
    }

    if matches!(mode, CampaignMode::Fresh) {
        fs::create_dir_all(&out_dir)
            .map_err(|e| CliError(format!("failed to create campaign output dir: {e}")))?;
    }
    let _lock = CampaignLock::acquire(&out_dir)?;

    let mut state = match mode {
        CampaignMode::Fresh => {
            if state_path.exists() {
                return Err(CliError(format!(
                    "campaign out-dir {} already contains campaign-state.json; use --extend N or --resume, pick a new --out-dir, or delete the old one",
                    out_dir.display()
                )));
            }
            let artifact = artifact.expect("fresh campaign parser requires an artifact");
            // Resolve the artifact once (build a source on the fly), then sweep the SAME
            // built artifact across every generation — never rebuilt per generation.
            let resolved = crate::resolve_artifact(crate::ArtifactRef::Prebuilt(artifact))?;
            let identity = artifact_identity(&resolved.path)?;
            CampaignState::fresh(identity, spec)
        }
        CampaignMode::Resume | CampaignMode::Extend { .. } => load_campaign_state(&state_path)?,
    };

    let mut coverage = match mode {
        CampaignMode::Fresh => CoverageTally::default(),
        CampaignMode::Resume | CampaignMode::Extend { .. } => {
            load_coverage_tally(&sites_path, state.generations_done)?
        }
    };

    let artifact_path = PathBuf::from(&state.artifact.path);
    verify_artifact_identity(&state.artifact)?;

    if let CampaignMode::Resume = mode {
        if state.generations_done == state.spec.generations {
            return Err(CliError(format!(
                "campaign complete at {}/{}; use --extend N to continue",
                state.generations_done, state.spec.generations
            )));
        }
    }
    if let CampaignMode::Extend { additional } = mode {
        state.spec.generations = state
            .spec
            .generations
            .checked_add(additional)
            .ok_or_else(|| CliError::usage("--extend would overflow the generation target"))?;
    }

    let mut edge_coverage = initialize_edge_coverage(&out_dir, &state, state.generations_done)?;

    let traces_dir = out_dir.join("traces");
    fs::create_dir_all(&traces_dir)
        .map_err(|e| CliError(format!("failed to create traces dir: {e}")))?;

    let self_exe = std::env::current_exe()
        .map_err(|e| CliError(format!("failed to resolve cargo-patina binary path: {e}")))?;

    let json_output = crate::output::options().is_json();
    let full_stream = progress_every == 1;
    let start = std::time::Instant::now();
    let from_gen = state.generations_done;
    let effective_timeout_secs = timeout_secs_override.unwrap_or(state.spec.timeout_secs);
    state.invocations.push(InvocationRecord {
        cli,
        from_gen,
        gens_run: 0,
        timeout_secs: effective_timeout_secs,
        elapsed_secs: 0,
    });
    let invocation_index = state.invocations.len() - 1;

    write_campaign_checkpoint(
        &state_path,
        &store_path,
        &sites_path,
        &state,
        &coverage,
        &edge_coverage,
    )?;

    if !json_output {
        match mode {
            CampaignMode::Fresh => println!(
                "PATINA_CAMPAIGN_START artifact={} family={} generations={} seed_base={} out={}",
                artifact_path.display(),
                state.artifact.family,
                state.spec.generations,
                state.spec.seed_base,
                out_dir.display(),
            ),
            CampaignMode::Extend { .. } | CampaignMode::Resume => println!(
                "PATINA_CAMPAIGN_RESUME out={} done={} target={} artifact={} sha256={}",
                out_dir.display(),
                from_gen,
                state.spec.generations,
                artifact_path.display(),
                state.artifact.sha256,
            ),
        }
        flush_stdout();
    }

    // Human-mode progress disclosure: at cadence 1 every generation prints its
    // per-generation line (the full legacy stream, no separate heartbeat); at any
    // higher cadence only novel/failing generations print a per-generation line,
    // plus a periodic `PATINA_CAMPAIGN_PROGRESS` heartbeat answering "is it still
    // running?". The wall-clock start is used only for the heartbeat's `elapsed_secs`
    // — it never enters a deterministic (`PATINA_CAMPAIGN_GEN`) line.
    let mut failures_so_far = class_counts_failures(&state.classes);
    let mut novel_so_far = state.signatures.len() as u64;

    for generation in from_gen..state.spec.generations {
        let hash = generation_hash(state.spec.seed_base, generation);
        let seed = u64::from_le_bytes(hash[0..8].try_into().expect("32-byte hash"));
        let flags = derive_flags(&state.spec, &hash, state.artifact.family);
        let trace_path = traces_dir.join(format!("generation-{generation}.patina"));
        let _ = fs::remove_file(&trace_path);
        crate::remove_native_trace_scratch(&trace_path);
        let coverage_map_path = edge_coverage
            .active()
            .map(|store| store.generation_covmap_path(generation));

        let (exit, stdout, stderr, timed_out) = run_generation(
            &self_exe,
            &artifact_path,
            seed,
            &flags,
            GenerationFiles {
                trace_path: &trace_path,
                coverage_out: coverage_map_path.as_deref(),
            },
            &state.spec.guest_args,
            effective_timeout_secs,
        )?;
        let _sites_fold = fold_sites_generation(&mut coverage, generation, seed, &stderr)?;
        let _edge_fold = fold_edge_coverage_generation(
            &mut edge_coverage,
            generation,
            coverage_map_path.as_deref(),
        )?;
        // A generation that blew the wall-clock budget was killed: it hung in a way
        // neither the virtual-time watchdog nor the child's own budgets caught
        // (e.g. an uninterposed atomics-only busy loop). Classify it INFRA
        // (inconclusive — harness bound hit), never a silent OK.
        let class = if timed_out {
            CampaignClass::Infra
        } else {
            classify(exit, &stdout, &stderr)
        };
        *state.classes.entry(class.as_str().to_string()).or_insert(0) += 1;

        let mut novel = false;
        let mut signature_key = None;
        if class.is_failure() {
            let sig = signature(class, &stdout, &stderr);
            let key = sig.key();
            signature_key = Some(key.clone());
            // A failure that ran to a clean finish left a valid trace; a mid-run
            // abort (a liveness violation, an always-violation trap) left none. The
            // reproduce command is `replay <trace>` when a valid trace exists, else
            // a deterministic re-run from the recorded seed and knobs.
            let saved_trace = save_failure_trace(&out_dir, &trace_path, generation);
            let reproduce = reproduce_command(
                &artifact_path,
                seed,
                &flags,
                &state.spec.guest_args,
                saved_trace.as_deref(),
            );
            let report = if state.spec.report {
                render_failure_report(
                    &out_dir,
                    saved_trace.as_deref(),
                    &artifact_path,
                    state.artifact.family,
                    generation,
                )
            } else {
                None
            };
            state
                .signatures
                .entry(key.clone())
                .and_modify(|record| record.count += 1)
                .or_insert_with(|| {
                    novel = true;
                    SignatureRecord {
                        class,
                        shape: sig.shape.clone(),
                        policy: sig.policy.clone(),
                        first_seen_gen: generation,
                        count: 1,
                        seed,
                        reproduce,
                        trace: saved_trace,
                        report,
                    }
                });
        }
        // The per-generation record path is transient scratch: a kept failure was
        // already copied into `failures/`, and a clean generation keeps nothing.
        // Remove the scratch file (including an empty abort-reservation file) so the
        // output directory holds only real artifacts.
        let _ = fs::remove_file(&trace_path);
        crate::remove_native_trace_scratch(&trace_path);

        if novel {
            novel_so_far += 1;
        }
        if class.is_failure() {
            failures_so_far += 1;
        }
        let outcome = GenerationOutcome {
            generation,
            seed,
            class,
            flags,
            novel,
            signature_key,
        };
        if outcome.is_notable() {
            state.notable_runs.push(outcome.clone());
        }
        state.generations_done = generation + 1;
        state.invocations[invocation_index].gens_run = state.generations_done - from_gen;
        state.invocations[invocation_index].elapsed_secs = start.elapsed().as_secs();

        if !json_output {
            // Always surface a novel or failing generation; surface an ordinary OK
            // generation only in the full-stream mode. The line format is unchanged
            // (and wall-clock-free) so replay/reproduce consumers and the
            // determinism check stay stable.
            if novel || class.is_failure() || full_stream {
                let tag = if novel { " NOVEL" } else { "" };
                println!(
                    "PATINA_CAMPAIGN_GEN generation={generation} seed={seed} class={}{tag}",
                    class.as_str()
                );
            }
            // Heartbeat every `progress_every` generations (suppressed in the
            // full-stream mode, where each generation already prints a line).
            if !full_stream && progress_every > 0 && (generation + 1) % progress_every == 0 {
                print_progress_heartbeat(ProgressHeartbeatInput {
                    done: generation + 1,
                    total: state.spec.generations,
                    elapsed_secs: start.elapsed().as_secs(),
                    failures: failures_so_far,
                    novel: novel_so_far,
                    class_counts: &state.classes,
                    coverage: &coverage,
                    edge_coverage: &edge_coverage,
                });
            }
            flush_stdout();
        }
        write_campaign_checkpoint(
            &state_path,
            &store_path,
            &sites_path,
            &state,
            &coverage,
            &edge_coverage,
        )?;
    }

    let failures = class_counts_failures(&state.classes);
    let novel_count = state.signatures.len() as u64;
    let coverage_verdict = coverage_verdict(&coverage, state.spec.allow_unmet_sometimes);
    let coverage_failure = coverage_verdict.gate == CoverageGate::Fail;
    let result = if failures == 0 && !coverage_failure {
        "ok"
    } else {
        "failure"
    };
    let exit_code = if failures == 0 && !coverage_failure {
        0
    } else {
        1
    };

    if json_output {
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result,
            exit_code,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            out_dir: &out_dir,
            state_path: &state_path,
            sites_path: &sites_path,
        });
        println!("{envelope}");
    } else {
        print_campaign_summary(CampaignSummaryInput {
            class_counts: &state.classes,
            signatures: &state.signatures,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            artifact_path: &artifact_path,
            failures,
            novel: novel_count,
            generations: state.spec.generations,
            store_path: &store_path,
            sites_path: &sites_path,
        });
        flush_stdout();
    }
    Ok(exit_code)
}

fn fold_sites_generation(
    coverage: &mut CoverageTally,
    generation: u64,
    seed: u64,
    stderr: &str,
) -> Result<AuxFoldDecision, CliError> {
    let decision = fold_decision(
        "campaign sites store",
        "generations_observed",
        coverage.generations_observed,
        generation,
    )?;
    if decision == AuxFoldDecision::Apply {
        coverage
            .observe_generation(generation, seed, stderr)
            .map_err(|error| {
                CliError(format!(
                    "generation {generation} has malformed PATINA_SDK_REPORT: {error}"
                ))
            })?;
    }
    Ok(decision)
}

fn fold_edge_coverage_generation(
    edge_coverage: &mut EdgeCoverageState,
    generation: u64,
    coverage_map_path: Option<&Path>,
) -> Result<Option<FoldOutcome>, CliError> {
    let Some(store) = edge_coverage.active_mut() else {
        return Ok(None);
    };
    let path = coverage_map_path.expect("active coverage has a generation path");
    if store.fold_decision(generation)? == AuxFoldDecision::SkipAlreadyApplied {
        let _ = fs::remove_file(path);
        return Ok(Some(FoldOutcome {
            generation,
            new_edges: 0,
            skipped_by_watermark: true,
        }));
    }
    let len = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if len == 0 {
        return Err(CliError(format!(
            "generation {generation} requested native coverage but did not produce a covmap at {}; refusing a partial coverage campaign",
            path.display()
        )));
    }
    let covmap = crate::coverage::read_covmap(path).map_err(|error| {
        CliError(format!(
            "generation {generation} produced malformed native coverage map {}: {error}",
            path.display()
        ))
    })?;
    let outcome = store.fold_covmap(generation, &covmap)?;
    let _ = fs::remove_file(path);
    Ok(Some(outcome))
}

/// Run one generation as a child `cargo patina run --record` process, capturing
/// its streams. The virtual-time watchdog and the child's own step/fuel budgets
/// bound the *deterministic* run, but a guest can still wedge in a way none of
/// those observe (an uninterposed atomics-only busy loop). `timeout_secs` is a
/// wall-clock backstop: a generation that overruns it is killed and reported (as
/// INFRA), so a single hung generation can never wedge the whole campaign.
///
/// Returns `(exit_code, stdout, stderr, timed_out)`. A signal death (including the
/// timeout kill) has no exit code and surfaces as `-1`.
struct GenerationFiles<'a> {
    trace_path: &'a Path,
    coverage_out: Option<&'a Path>,
}

fn run_generation(
    self_exe: &Path,
    artifact: &Path,
    seed: u64,
    flags: &[String],
    files: GenerationFiles<'_>,
    guest_args: &[String],
    timeout_secs: u64,
) -> Result<(i32, String, String, bool), CliError> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut command = Command::new(self_exe);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .arg("run")
        .arg("--no-config")
        .arg(artifact)
        .arg("--seed")
        .arg(seed.to_string())
        .arg("--record")
        .arg(files.trace_path);
    for flag in flags {
        command.arg(flag);
    }
    if let Some(path) = files.coverage_out {
        command.arg("--coverage-out").arg(path);
    }
    if !guest_args.is_empty() {
        command.arg("--");
        for arg in guest_args {
            command.arg(arg);
        }
    }
    // Keep the child's diagnostics deterministic and machine-parseable. Pin the
    // SDK report on so a user's inherited PATINA_SDK_REPORT=0 cannot make the
    // campaign coverage gate vacuously green.
    crate::config::scrub_child_config_env(&mut command, "run");
    command.env("PATINA_LIVENESS_REPORT", "1");
    command.env("PATINA_SDK_REPORT", "1");
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| CliError(format!("failed to spawn generation run: {e}")))?;

    let mut timed_out = false;
    if timeout_secs > 0 {
        // Poll the child to completion, killing it if it overruns the wall-clock
        // budget. Deterministic guest output is small, so the pipe buffers never
        // fill before the poll observes exit; a genuinely wedged guest is killed at
        // the deadline. `timeout_secs == 0` disables the backstop (poll-free wait).
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            match child
                .try_wait()
                .map_err(|e| CliError(format!("failed to poll generation run: {e}")))?
            {
                Some(_) => break,
                None => {
                    if Instant::now() >= deadline {
                        kill_generation_process_tree(&mut child);
                        timed_out = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| CliError(format!("failed to collect generation run output: {e}")))?;
    let exit = output.status.code().unwrap_or(-1);
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if timed_out {
        // Synthetic marker so the killed generation carries a stable signature.
        stderr.push_str(&format!(
            "\npatina: campaign generation exceeded timeout_secs={timeout_secs}\n"
        ));
    }
    Ok((
        exit,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
        timed_out,
    ))
}

fn kill_generation_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = -(child.id() as i32);
        // SAFETY: `kill` is called with a process-group id created for this
        // generation's child `cargo patina run`, so the supervisor and its guest
        // are killed together on timeout rather than orphaning a spinning guest.
        let rc = unsafe { kill(pgid, SIGKILL) };
        if rc == 0 {
            return;
        }
    }
    let _ = child.kill();
}

/// A typed value for a child `run` flag, rendered to the exact canonical syntax
/// the run parser accepts. Campaign builds every child-flag value through this so
/// it can never emit a value shape the run parser rejects — the general fix for
/// the value-syntax drift class (e.g. `--sleep-jitter-nanos 0:N` vs `0..N`). The
/// generic property test (`registry_value_grammars_match_the_parsers`) proves
/// each rendering is a run-parser-accepted form of its registry [`help::Kind`].
enum RunValue {
    /// A decimal integer (per-mille, count, or nanosecond scalar).
    Int(u64),
    /// An inclusive `lo..hi` nanosecond range (`help::Kind::NanosRange`).
    NanosRange { lo: u64, hi: u64 },
    /// A valueless switch (`help::Kind`-less, `Value::None`).
    Switch,
}

impl RunValue {
    fn render(&self) -> String {
        match self {
            RunValue::Int(value) => value.to_string(),
            RunValue::NanosRange { lo, hi } => format!("{lo}..{hi}"),
            RunValue::Switch => String::new(),
        }
    }
}

/// Push a child `run` flag onto `flags`, rendering the exact CLI syntax the run
/// parser accepts: the run registry decides the value form — an optional-value
/// flag inlines (`--flag=VALUE`), a required-value flag uses the space form
/// (`--flag VALUE`), a switch takes no value — and [`RunValue`] renders the value
/// in its canonical grammar. Routing every child flag through here (rather than
/// hand-formatting strings) makes it structurally impossible for a campaign to
/// emit syntax the child `run` rejects.
fn push_run_flag(flags: &mut Vec<String>, name: &str, value: RunValue) {
    match crate::help::flag_arity("run", name) {
        Some(crate::help::Value::Optional(..)) => flags.push(format!("{name}={}", value.render())),
        Some(crate::help::Value::Required(..)) => {
            flags.push(name.to_string());
            flags.push(value.render());
        }
        // A valueless switch (`--swarm`), or an unregistered name (a programming
        // error the registry drift gate catches): emit the bare flag.
        Some(crate::help::Value::None) | None => flags.push(name.to_string()),
    }
}

/// Derive the per-generation `run` flags from the generation hash. Native-only
/// exploration knobs (`--swarm`, `--sched-pct`) are skipped for a WASI module
/// (single-threaded; the WASI `run` does not accept them).
fn derive_flags(spec: &CampaignSpec, hash: &[u8; 32], family: &'static str) -> Vec<String> {
    let native = family == "native";
    let mut flags = Vec::new();

    if spec.buggify {
        // Activation in [300, 900] permille, fire in [300, 900] permille — a wide
        // seed-varying band that both activates and fires cooperative-SUT sites
        // often enough to exercise a planted bug across a modest campaign, while
        // still leaving clean generations (neither always nor never firing).
        let activation = 300 + (u32::from(hash[8]) * 600 / 255);
        let fire = 300 + (u32::from(hash[9]) * 600 / 255);
        push_run_flag(&mut flags, "--buggify", RunValue::Int(u64::from(fire)));
        push_run_flag(
            &mut flags,
            "--buggify-activation-permille",
            RunValue::Int(u64::from(activation)),
        );
    }
    if spec.faults {
        let drop = u32::from(hash[12]) * 200 / 255; // [0, 200] permille
        push_run_flag(
            &mut flags,
            "--net-drop-permille",
            RunValue::Int(u64::from(drop)),
        );
        let jitter_hi = u64::from(hash[13]) * 10_000; // up to 2.55 ms
        push_run_flag(
            &mut flags,
            "--sleep-jitter-nanos",
            RunValue::NanosRange {
                lo: 0,
                hi: jitter_hi,
            },
        );
    }
    if spec.swarm && native {
        push_run_flag(&mut flags, "--swarm", RunValue::Switch);
    }
    if spec.pct && native {
        let depth = 1 + u32::from(hash[11] % 5); // [1, 5]
        push_run_flag(&mut flags, "--sched-pct", RunValue::Int(u64::from(depth)));
    }
    if let Some(nanos) = spec.watchdog_nanos {
        push_run_flag(&mut flags, "--liveness-watchdog", RunValue::Int(nanos));
    }
    if let Some(nanos) = spec.converge_nanos {
        push_run_flag(&mut flags, "--converge-within", RunValue::Int(nanos));
        if let Some(heal) = spec.heal_after_nanos {
            push_run_flag(&mut flags, "--heal-after", RunValue::Int(heal));
        }
    }
    flags
}

/// `SHA-256("patina-campaign-<seed_base>-<generation>")` — the deterministic per-generation
/// derivation, mirroring the fuzz-sweep scheme (no wall clock / `$RANDOM`).
fn generation_hash(seed_base: u64, generation: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("patina-campaign-{seed_base}-{generation}").as_bytes());
    hasher.finalize().into()
}

fn reproduce_command(
    artifact: &Path,
    seed: u64,
    flags: &[String],
    guest_args: &[String],
    trace: Option<&str>,
) -> String {
    // A valid recorded trace replays flag-free (the trace is authoritative); a
    // traceless failure (a mid-run abort) reproduces by a deterministic re-run.
    if let Some(trace) = trace {
        return format!("cargo patina replay {} {trace}", artifact.display());
    }
    let mut parts = vec![
        "cargo patina run".to_string(),
        artifact.display().to_string(),
        "--seed".to_string(),
        seed.to_string(),
    ];
    parts.extend(flags.iter().cloned());
    if !guest_args.is_empty() {
        parts.push("--".to_string());
        parts.extend(guest_args.iter().cloned());
    }
    parts.join(" ")
}

/// Save a failing generation's trace into `<out>/failures/`, but ONLY when the
/// child wrote a complete, validated bundle. A mid-run abort or timeout never
/// reaches `Context::finish`; an empty/truncated scratch trace is skipped rather
/// than copied forward as a future replay surprise.
fn save_failure_trace(out_dir: &Path, trace_path: &Path, generation: u64) -> Option<String> {
    let bundle = patina_dst_trace::TraceBundle::load(trace_path).ok()?;
    let failures_dir = out_dir.join("failures");
    std::fs::create_dir_all(&failures_dir).ok()?;
    let dest = failures_dir.join(format!("generation-{generation}.patina"));
    bundle.write_atomic(&dest).ok()?;
    Some(dest.display().to_string())
}

/// Best-effort wave-14 `--report` HTML for a failing generation with a trace.
fn render_failure_report(
    out_dir: &Path,
    trace: Option<&str>,
    artifact: &Path,
    family: &'static str,
    generation: u64,
) -> Option<String> {
    let trace = trace?;
    let reports_dir = out_dir.join("reports");
    std::fs::create_dir_all(&reports_dir).ok()?;
    let dest = reports_dir.join(format!("generation-{generation}.html"));
    let html = crate::render::render_trace_file(
        trace,
        &artifact.display().to_string(),
        family,
        "main",
        None,
    )
    .ok()?;
    std::fs::write(&dest, html).ok()?;
    Some(dest.display().to_string())
}

fn parse_artifact_family(value: &str) -> Option<&'static str> {
    match value {
        "native" => Some("native"),
        "wasi" => Some("wasi"),
        _ => None,
    }
}

fn artifact_family_from_bytes(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\0asm") {
        "wasi"
    } else {
        "native"
    }
}

fn artifact_identity(path: &Path) -> Result<ArtifactIdentity, CliError> {
    let bytes = fs::read(path)
        .map_err(|e| CliError(format!("failed to read artifact {}: {e}", path.display())))?;
    Ok(ArtifactIdentity {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
        family: artifact_family_from_bytes(&bytes),
    })
}

fn verify_artifact_identity(recorded: &ArtifactIdentity) -> Result<(), CliError> {
    let path = PathBuf::from(&recorded.path);
    let current = artifact_identity(&path).map_err(|error| {
        CliError(format!(
            "campaign out-dir records artifact {} but it cannot be read: {error}; start a new out-dir if the artifact moved",
            recorded.path
        ))
    })?;
    if current.sha256 != recorded.sha256 {
        return Err(CliError(format!(
            "campaign out-dir records artifact sha256 {} but {} now hashes {}; the artifact changed since this campaign started. Signatures from different builds are not comparable — start a new out-dir for the new build.",
            recorded.sha256, recorded.path, current.sha256
        )));
    }
    if current.family != recorded.family {
        return Err(CliError(format!(
            "campaign out-dir records artifact family {} but {} is now {}; start a new out-dir for the new build",
            recorded.family, recorded.path, current.family
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_campaign_checkpoint(
    state_path: &Path,
    store_path: &Path,
    sites_path: &Path,
    state: &CampaignState,
    coverage: &CoverageTally,
    edge_coverage: &EdgeCoverageState,
) -> Result<(), CliError> {
    // The state cursor is the checkpoint readers poll. Write the derived stores
    // first, then the state file, so an observed advanced cursor has matching
    // signatures/sites/native-coverage artifacts. Native coverage writes before
    // the cursor on purpose: if a crash tears here, generations_applied may be
    // one ahead and resume will re-run then watermark-skip that generation.
    if let Some(store) = edge_coverage.active() {
        store.write_checkpoint()?;
    }
    write_sites_store(sites_path, coverage)?;
    write_signature_store(store_path, &state.signatures)?;
    write_campaign_state(state_path, state)
}

fn write_campaign_state(path: &Path, state: &CampaignState) -> Result<(), CliError> {
    state
        .validate()
        .map_err(|error| CliError(format!("refusing to write invalid campaign state: {error}")))?;
    atomic_write_json(path, &state.to_json(), "campaign state")
}

fn load_campaign_state(path: &Path) -> Result<CampaignState, CliError> {
    let text = fs::read_to_string(path).map_err(|e| {
        CliError(format!(
            "failed to read campaign state {}: {e}",
            path.display()
        ))
    })?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        CliError(format!(
            "campaign state {} is invalid JSON: {e}",
            path.display()
        ))
    })?;
    match CampaignState::from_json(&json) {
        Ok(state) => Ok(state),
        Err(error) if error.starts_with("unsupported schema") => Err(CliError(format!(
            "campaign state {} has {error}; this out-dir was written by a different cargo-patina version; finish it with that version or start a new out-dir",
            path.display()
        ))),
        Err(error) => Err(CliError(format!(
            "campaign state {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))),
    }
}

fn load_coverage_tally(path: &Path, generations_done: u64) -> Result<CoverageTally, CliError> {
    if !path.exists() {
        return Err(CliError(format!(
            "campaign out-dir is missing sites store {} for {} already-recorded generations; refusing to resume partially",
            path.display(),
            generations_done
        )));
    }
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read campaign sites store {}: {error}",
            path.display()
        ))
    })?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    let tally = CoverageTally::from_json(&json).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))
    })?;
    let label = format!("campaign sites store {}", path.display());
    validate_resume_watermark(
        &label,
        "generations_observed",
        tally.generations_observed,
        generations_done,
        "per-generation SDK reports are transient, so refusing to resume with missing sites folds",
    )?;
    Ok(tally)
}

fn write_signature_store(
    path: &Path,
    signatures: &BTreeMap<String, SignatureRecord>,
) -> Result<(), CliError> {
    let store = serde_json::json!({
        "schema": CAMPAIGN_SIGNATURES_SCHEMA,
        "signatures": signatures_to_json(signatures),
    });
    atomic_write_json(path, &store, "signature store")
}

fn write_sites_store(path: &Path, coverage: &CoverageTally) -> Result<(), CliError> {
    atomic_write_json(path, &coverage.to_json(), "campaign sites store")
}

fn atomic_write_json(path: &Path, value: &serde_json::Value, label: &str) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| CliError(format!("failed to serialize {label}: {e}")))?;
    atomic_write(path, text.as_bytes(), label)
}

fn atomic_write(path: &Path, bytes: &[u8], label: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError(format!("{label} path {} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|e| {
        CliError(format!(
            "failed to create {label} dir {}: {e}",
            parent.display()
        ))
    })?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(OsStr::to_str).unwrap_or("json")
    ));
    {
        let mut file = File::create(&tmp).map_err(|e| {
            CliError(format!(
                "failed to create temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
        file.write_all(bytes).map_err(|e| {
            CliError(format!(
                "failed to write temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            CliError(format!(
                "failed to sync temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        CliError(format!(
            "failed to atomically replace {label} {}: {e}",
            path.display()
        ))
    })
}

fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

#[derive(Debug)]
struct CampaignLock {
    _file: File,
}

impl CampaignLock {
    fn acquire(out_dir: &Path) -> Result<Self, CliError> {
        fs::create_dir_all(out_dir)
            .map_err(|e| CliError(format!("failed to create campaign output dir: {e}")))?;
        let path = out_dir.join("campaign.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                CliError(format!(
                    "failed to open campaign lock {}: {e}",
                    path.display()
                ))
            })?;
        acquire_flock(&file, out_dir)?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn acquire_flock(file: &File, out_dir: &Path) -> Result<(), CliError> {
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Err(CliError(format!(
            "another campaign is writing this out-dir: {}",
            out_dir.display()
        )));
    }
    Err(CliError(format!(
        "failed to lock campaign out-dir {}: {error}",
        out_dir.display()
    )))
}

#[cfg(not(unix))]
fn acquire_flock(_file: &File, out_dir: &Path) -> Result<(), CliError> {
    Err(CliError(format!(
        "campaign out-dir locking is unsupported on this platform: {}",
        out_dir.display()
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoverageGate {
    Pass,
    Fail,
    Waived,
}

impl CoverageGate {
    const fn as_str(self) -> &'static str {
        match self {
            CoverageGate::Pass => "pass",
            CoverageGate::Fail => "fail",
            CoverageGate::Waived => "waived",
        }
    }
}

#[derive(Clone, Debug)]
struct CoverageSummary<'a> {
    labels_seen: u64,
    oracle_sites: u64,
    satisfied: u64,
    sometimes_unsatisfied: u64,
    reachable_unreached: u64,
    always_violated: u64,
    unmet: Vec<&'a ExercisedSite>,
}

#[derive(Clone, Debug)]
struct CoverageVerdict<'a> {
    summary: CoverageSummary<'a>,
    gate: CoverageGate,
    waiver: Option<AllowUnmetSometimes>,
}

fn coverage_summary(coverage: &CoverageTally) -> CoverageSummary<'_> {
    let mut summary = CoverageSummary {
        labels_seen: coverage.sites.len() as u64,
        oracle_sites: 0,
        satisfied: 0,
        sometimes_unsatisfied: 0,
        reachable_unreached: 0,
        always_violated: 0,
        unmet: Vec::new(),
    };
    for site in coverage.sites.values() {
        if site.kind == "always" && site.always_violated_runs > 0 {
            summary.always_violated += 1;
        }
        if !site.is_oracle() {
            continue;
        }
        summary.oracle_sites += 1;
        if site.satisfied_gens > 0 {
            summary.satisfied += 1;
        } else {
            if site.kind == "sometimes" {
                summary.sometimes_unsatisfied += 1;
            } else if site.kind == "reachable" {
                summary.reachable_unreached += 1;
            }
            summary.unmet.push(site);
        }
    }
    summary
}

fn coverage_verdict(
    coverage: &CoverageTally,
    waiver: Option<AllowUnmetSometimes>,
) -> CoverageVerdict<'_> {
    let summary = coverage_summary(coverage);
    let gate = if summary.unmet.is_empty() {
        CoverageGate::Pass
    } else if waiver_applies(waiver, coverage.generations_observed) {
        CoverageGate::Waived
    } else {
        CoverageGate::Fail
    };
    CoverageVerdict {
        summary,
        gate,
        waiver,
    }
}

fn waiver_applies(waiver: Option<AllowUnmetSometimes>, generations_observed: u64) -> bool {
    match waiver {
        Some(AllowUnmetSometimes::Always) => true,
        Some(AllowUnmetSometimes::BelowGenerations(min)) => generations_observed < min,
        None => false,
    }
}

fn waiver_json(waiver: Option<AllowUnmetSometimes>) -> serde_json::Value {
    waiver.map_or(serde_json::Value::Null, allow_unmet_to_json)
}

/// Print one human-mode progress heartbeat: enough to answer "is it still running,
/// and how is it going?" without the full per-generation stream. `elapsed_secs` is
/// the only wall-clock-derived field and appears solely on this line (never on a
/// deterministic `PATINA_CAMPAIGN_GEN` line).
struct ProgressHeartbeatInput<'a> {
    done: u64,
    total: u64,
    elapsed_secs: u64,
    failures: u64,
    novel: u64,
    class_counts: &'a BTreeMap<String, u64>,
    coverage: &'a CoverageTally,
    edge_coverage: &'a EdgeCoverageState,
}

fn print_progress_heartbeat(input: ProgressHeartbeatInput<'_>) {
    let mut line = format!(
        "PATINA_CAMPAIGN_PROGRESS generation={}/{} elapsed_secs={} failures={} novel={}",
        input.done, input.total, input.elapsed_secs, input.failures, input.novel
    );
    for (class, count) in input.class_counts {
        line.push_str(&format!(" {class}={count}"));
    }
    let coverage_summary = coverage_summary(input.coverage);
    line.push_str(&format!(
        " sdk_labels={} oracle_sites={} oracle_unmet={}",
        coverage_summary.labels_seen,
        coverage_summary.oracle_sites,
        coverage_summary.unmet.len()
    ));
    append_edge_coverage_progress(&mut line, input.edge_coverage);
    println!("{line}");
}

fn append_edge_coverage_progress(line: &mut String, edge_coverage: &EdgeCoverageState) {
    match edge_coverage {
        EdgeCoverageState::Active(store) => {
            if let Some(meta) = store.meta() {
                line.push_str(&format!(
                    " coverage={}/{} covered_permille={} last_new_edge_gen={} plateau={}",
                    meta.edges_covered,
                    meta.edges_total,
                    meta.covered_permille(),
                    meta.last_new_edge_gen
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    meta.plateaued as u8,
                ));
            } else {
                line.push_str(" coverage=pending");
            }
        }
        EdgeCoverageState::Unavailable { reason, .. } => {
            line.push_str(&format!(" coverage=unavailable reason={reason}"));
        }
    }
}

struct CampaignSummaryInput<'a> {
    class_counts: &'a BTreeMap<String, u64>,
    signatures: &'a BTreeMap<String, SignatureRecord>,
    coverage: &'a CoverageTally,
    coverage_verdict: &'a CoverageVerdict<'a>,
    edge_coverage: &'a EdgeCoverageState,
    artifact_path: &'a Path,
    failures: u64,
    novel: u64,
    generations: u64,
    store_path: &'a Path,
    sites_path: &'a Path,
}

fn print_campaign_summary(input: CampaignSummaryInput<'_>) {
    println!("== campaign summary ==");
    println!(
        "generations={} failures={} novel_signatures={}",
        input.generations, input.failures, input.novel
    );
    for (class, count) in input.class_counts {
        println!("  class {class:<18} {count}");
    }
    if !input.signatures.is_empty() {
        println!("-- failure signatures --");
        for (key, record) in input.signatures {
            println!(
                "  [{}] count={} first_gen={} seed={}",
                record.class.as_str(),
                record.count,
                record.first_seen_gen,
                record.seed
            );
            println!("      signature: {key}");
            println!("      reproduce: {}", record.reproduce);
            if let Some(trace) = &record.trace {
                println!("      trace:     {trace}");
            }
        }
    }
    print_coverage_summary(input.coverage, input.coverage_verdict, input.sites_path);
    print_edge_coverage_summary(input.edge_coverage, input.artifact_path);
    println!("signature store: {}", input.store_path.display());
    let mut complete = format!(
        "PATINA_CAMPAIGN_COMPLETE generations={} failures={} novel={}",
        input.generations, input.failures, input.novel
    );
    append_edge_coverage_complete(&mut complete, input.edge_coverage);
    println!("{complete}");
}

fn print_edge_coverage_summary(edge_coverage: &EdgeCoverageState, artifact_path: &Path) {
    println!("-- coverage (native edges) --");
    match edge_coverage {
        EdgeCoverageState::Unavailable { reason, hint } => {
            println!("coverage=unavailable reason={reason}");
            if let Some(hint) = hint {
                println!("hint: {hint}");
            }
        }
        EdgeCoverageState::Active(store) => {
            if let Some(meta) = store.meta() {
                println!(
                    "edges={}/{} covered_permille={} last_new_edge_gen={} plateau_after={} plateaued={} generations_applied={}",
                    meta.edges_covered,
                    meta.edges_total,
                    meta.covered_permille(),
                    meta.last_new_edge_gen
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    meta.plateau_window,
                    meta.plateaued as u8,
                    meta.generations_applied,
                );
                println!("coverage store: {}", store.dir().display());
                match top_uncovered_crates(artifact_path, store, 5) {
                    Ok(rows) if rows.is_empty() => println!("top_uncovered_crates: none"),
                    Ok(rows) => {
                        println!("top_uncovered_crates:");
                        for (krate, uncovered, total) in rows {
                            println!("  {krate} uncovered={uncovered}/{total}");
                        }
                    }
                    Err(error) => println!("top_uncovered_crates: unavailable ({error})"),
                }
            } else {
                println!("coverage=pending no finalized generation has produced a covmap yet");
                println!("coverage store: {}", store.dir().display());
            }
        }
    }
}

fn append_edge_coverage_complete(line: &mut String, edge_coverage: &EdgeCoverageState) {
    if let EdgeCoverageState::Active(store) = edge_coverage {
        if let Some(meta) = store.meta() {
            line.push_str(&format!(
                " covered_permille={} plateaued={}",
                meta.covered_permille(),
                meta.plateaued as u8,
            ));
        }
    }
}

fn print_coverage_summary(
    coverage: &CoverageTally,
    coverage_verdict: &CoverageVerdict<'_>,
    sites_path: &Path,
) {
    let summary = &coverage_verdict.summary;
    println!("-- coverage (sometimes!/reachable!) --");
    if summary.oracle_sites == 0 {
        println!("coverage: no sometimes!/reachable! sites registered");
    } else {
        println!(
            "oracle_sites={} satisfied={} unmet={}",
            summary.oracle_sites,
            summary.satisfied,
            summary.unmet.len()
        );
        for site in &summary.unmet {
            let waived = if coverage_verdict.gate == CoverageGate::Waived {
                " (waived)"
            } else {
                ""
            };
            println!(
                "  UNMET {} '{}' satisfied_gens=0/{} registered_gens={} evals={}{}",
                site.kind,
                site.label,
                coverage.generations_observed,
                site.registered_gens,
                site.evals,
                waived
            );
        }
    }
    println!("coverage store: {}", sites_path.display());
    println!(
        "PATINA_CAMPAIGN_COVERAGE oracle_sites={} satisfied={} unmet={} gate={}",
        summary.oracle_sites,
        summary.satisfied,
        summary.unmet.len(),
        coverage_verdict.gate.as_str()
    );
}

/// Build the summary-first `patina.campaign/v2` JSON envelope. Progressive
/// disclosure: the top level carries the class-count histogram and the deduped
/// signatures; `notable_runs` holds per-generation detail ONLY for novel and
/// failing generations (the interesting minority — an OK generation adds no
/// triage value and is fully accounted for by `classes`); and `artifacts` points
/// at the full on-disk detail (the state file, signature store, saved failing
/// traces, optional reports) so nothing the v1 all-runs dump exposed becomes
/// unreachable. Pure (returns the `Value`) so the shape is unit-testable without
/// capturing stdout.
struct CampaignEnvelopeInput<'a> {
    result: &'a str,
    exit_code: i32,
    state: &'a CampaignState,
    coverage: &'a CoverageTally,
    coverage_verdict: &'a CoverageVerdict<'a>,
    edge_coverage: &'a EdgeCoverageState,
    out_dir: &'a Path,
    state_path: &'a Path,
    sites_path: &'a Path,
}

fn build_campaign_envelope(input: CampaignEnvelopeInput<'_>) -> serde_json::Value {
    let state = input.state;
    let classes: serde_json::Map<String, serde_json::Value> = state
        .classes
        .iter()
        .map(|(class, count)| (class.clone(), serde_json::Value::from(*count)))
        .collect();
    let signature_json = signatures_to_json(&state.signatures);
    let notable_runs: Vec<serde_json::Value> = state
        .notable_runs
        .iter()
        .map(GenerationOutcome::to_json)
        .collect();
    let failures = class_counts_failures(&state.classes);
    let novel = state.signatures.len() as u64;
    // Machine-readable pointers to the full on-disk detail. `failures` and
    // `reports` are directories that exist only once a failing generation has
    // populated them, so they are announced conditionally rather than promising a
    // path that may not exist.
    let mut artifacts = serde_json::Map::new();
    artifacts.insert("out_dir".into(), input.out_dir.display().to_string().into());
    artifacts.insert(
        "campaign_state".into(),
        input.state_path.display().to_string().into(),
    );
    artifacts.insert(
        "signature_store".into(),
        input
            .out_dir
            .join("signatures.json")
            .display()
            .to_string()
            .into(),
    );
    artifacts.insert(
        "site_coverage".into(),
        input.sites_path.display().to_string().into(),
    );
    if let Some(store) = input.edge_coverage.active() {
        artifacts.insert(
            "coverage_dir".into(),
            store.dir().display().to_string().into(),
        );
    }
    if failures > 0 {
        artifacts.insert(
            "failures_dir".into(),
            input.out_dir.join("failures").display().to_string().into(),
        );
    }
    if state.spec.report && failures > 0 {
        artifacts.insert(
            "reports_dir".into(),
            input.out_dir.join("reports").display().to_string().into(),
        );
    }
    let coverage_json = coverage_envelope_json(
        input.coverage,
        input.coverage_verdict,
        input.edge_coverage,
        Path::new(&state.artifact.path),
    );
    let sdk_sites_json = sdk_sites_summary_json(input.coverage, input.coverage_verdict);
    let mut envelope = serde_json::json!({
        "schema": CAMPAIGN_ENVELOPE_SCHEMA,
        "verb": "campaign",
        "result": input.result,
        "exit_code": input.exit_code,
        "artifact": state.artifact.path.clone(),
        "family": state.artifact.family,
        "generations": state.spec.generations,
        "seed_base": state.spec.seed_base,
        "failures": failures,
        "novel_signatures": novel,
        "classes": classes,
        "signatures": signature_json,
        "notable_runs": notable_runs,
        "invocations": state.invocations.iter().map(InvocationRecord::to_json).collect::<Vec<_>>(),
        "sdk_sites": sdk_sites_json,
        "coverage": coverage_json,
        "artifacts": artifacts,
    });
    if let (Some(object), Some(config)) =
        (envelope.as_object_mut(), crate::config::provenance_json())
    {
        object.insert("config".to_string(), config);
    }
    envelope
}

fn coverage_envelope_json(
    coverage: &CoverageTally,
    verdict: &CoverageVerdict<'_>,
    edge_coverage: &EdgeCoverageState,
    artifact_path: &Path,
) -> serde_json::Value {
    let unmet = verdict
        .summary
        .unmet
        .iter()
        .map(|site| {
            serde_json::json!({
                "label": &site.label,
                "kind": &site.kind,
                "satisfied_gens": site.satisfied_gens,
                "registered_gens": site.registered_gens,
                "generations_observed": coverage.generations_observed,
                "evals": site.evals,
                "waived": verdict.gate == CoverageGate::Waived,
            })
        })
        .collect::<Vec<_>>();
    let edge = edge_coverage_json(edge_coverage, artifact_path);
    serde_json::json!({
        "oracle_sites": verdict.summary.oracle_sites,
        "satisfied": verdict.summary.satisfied,
        "gate": verdict.gate.as_str(),
        "waiver": waiver_json(verdict.waiver),
        "unmet": unmet,
        "edge": edge,
    })
}

fn edge_coverage_json(
    edge_coverage: &EdgeCoverageState,
    artifact_path: &Path,
) -> serde_json::Value {
    match edge_coverage {
        EdgeCoverageState::Unavailable { reason, hint } => serde_json::json!({
            "state": "unavailable",
            "reason": reason,
            "hint": hint,
        }),
        EdgeCoverageState::Active(store) => {
            let Some(meta) = store.meta() else {
                return serde_json::json!({
                    "state": "pending",
                    "coverage_dir": store.dir().display().to_string(),
                });
            };
            let (top_uncovered, top_uncovered_error) =
                match top_uncovered_crates(artifact_path, store, 5) {
                    Ok(rows) => (
                        rows.into_iter()
                            .map(|(krate, uncovered, total)| {
                                serde_json::json!({
                                    "crate": krate,
                                    "uncovered_edges": uncovered,
                                    "edges_total": total,
                                })
                            })
                            .collect::<Vec<_>>(),
                        serde_json::Value::Null,
                    ),
                    Err(error) => (Vec::new(), serde_json::json!(error.to_string())),
                };
            serde_json::json!({
                "state": "available",
                "schema": crate::coverage::CAMPAIGN_COVERAGE_SCHEMA,
                "coverage_dir": store.dir().display().to_string(),
                "edges_total": meta.edges_total,
                "edges_covered": meta.edges_covered,
                "covered_permille": meta.covered_permille(),
                "generations_applied": meta.generations_applied,
                "last_new_edge_gen": meta.last_new_edge_gen,
                "plateau_after": meta.plateau_window,
                "plateaued": meta.plateaued,
                "new_edge_log": meta.new_edge_log.iter().map(|(generation, new_edges)| serde_json::json!([generation, new_edges])).collect::<Vec<_>>(),
                "top_uncovered_crates": top_uncovered,
                "top_uncovered_crates_error": top_uncovered_error,
            })
        }
    }
}

fn sdk_sites_summary_json(
    coverage: &CoverageTally,
    verdict: &CoverageVerdict<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "labels_seen": verdict.summary.labels_seen,
        "generations_observed": coverage.generations_observed,
        "sometimes_unsatisfied": verdict.summary.sometimes_unsatisfied,
        "reachable_unreached": verdict.summary.reachable_unreached,
        "always_violated": verdict.summary.always_violated,
    })
}

// ===========================================================================
// Selftest
// ===========================================================================

/// Prove every classifier class is reachable with planted-outcome fixtures, and
/// that the signature store dedups repeats and flags novel signatures — mirroring
/// the fuzz-sweep `--selftest` discipline.
fn selftest() -> Result<i32, CliError> {
    let mut failures = 0u32;
    let mut check = |name: &str, want: CampaignClass, got: CampaignClass| {
        if want == got {
            println!("  ok   {name:<40} -> {}", got.as_str());
        } else {
            println!(
                "  FAIL {name:<40} -> {} (want {})",
                got.as_str(),
                want.as_str()
            );
            failures += 1;
        }
    };

    println!("== campaign classifier selftest ==");
    check(
        "clean-exit-0",
        CampaignClass::Ok,
        classify(0, "PATINA_RESULT ok=1", ""),
    );
    check(
        "liveness-watchdog-marker",
        CampaignClass::Liveness,
        classify(
            1,
            "",
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600",
        ),
    );
    check(
        "heal-then-converge-marker",
        CampaignClass::Liveness,
        classify(
            2,
            "",
            "PATINA_VIOLATION converge detail=did-not-converge vtime_ns=5000 budget_ns=300 last_fault_vtime_ns=300",
        ),
    );
    check(
        "violation-marker-on-exit-0",
        CampaignClass::Violation,
        classify(
            0,
            "PATINA_RESULT ok=1",
            "PATINA_VIOLATION two-leaders term=4",
        ),
    );
    check(
        "always-violation-not-downgraded",
        CampaignClass::Violation,
        classify(
            0,
            "PATINA_SDK_REPORT enabled=1",
            "PATINA_ALWAYS_VIOLATION label=x",
        ),
    );
    check(
        "guest-panic",
        CampaignClass::Violation,
        classify(101, "", "thread 'main' panicked at src/x.rs:9: boom"),
    );
    check(
        "bare-nonzero-is-unclassified-not-ok",
        CampaignClass::Unclassified,
        classify(2, "", ""),
    );
    check(
        "unknown-nonzero-with-noise-is-unclassified",
        CampaignClass::Unclassified,
        classify(
            7,
            "some guest chatter",
            "an unexpected message with no marker",
        ),
    );
    check(
        "fail-closed-duplicate-label",
        CampaignClass::FailClosedAbort,
        classify(134, "", "PATINA_BUGGIFY_DUPLICATE_LABEL label=same"),
    );
    check(
        "fail-closed-fingerprint",
        CampaignClass::FailClosedAbort,
        classify(
            2,
            "",
            "fingerprint mismatch: trace was recorded for a different build",
        ),
    );
    check(
        "fail-closed-bare-sigabrt",
        CampaignClass::FailClosedAbort,
        classify(134, "", "some shim diagnostic with no SUT marker"),
    );
    // An `always!` abort (SIGABRT + its marker) is a SUT VIOLATION, not a Patina
    // refusal — the marker is checked before the bare-SIGABRT fail-closed rule.
    check(
        "always-violation-sigabrt-is-violation-not-fail-closed",
        CampaignClass::Violation,
        classify(134, "", "PATINA_ALWAYS_VIOLATION label=must-hold"),
    );
    check(
        "starvation-stall-exit-111",
        CampaignClass::StarvationStall,
        classify(
            111,
            "",
            "patina: starvation stall — no scheduler progress in 60s",
        ),
    );
    check(
        "infra-cargo-failure",
        CampaignClass::Infra,
        classify(2, "", "cargo-patina: Cargo process terminated by a signal"),
    );
    // Severity: an explicit finding is never masked by an infra line (the child's
    // supervisor prints `cargo-patina: … terminated by a signal` alongside the
    // guest's flushed liveness marker).
    check(
        "liveness-beats-infra-noise",
        CampaignClass::Liveness,
        classify(
            2,
            "",
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=2 budget_ns=1\ncargo-patina: note",
        ),
    );

    // Signature dedup + novelty.
    println!("-- signature dedup --");
    let a = signature(
        CampaignClass::Liveness,
        "",
        "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600",
    );
    let b = signature(
        CampaignClass::Liveness,
        "",
        "PATINA_VIOLATION liveness detail=no-progress vtime_ns=999999 budget_ns=600",
    );
    if a.key() == b.key() {
        println!(
            "  ok   digit-collapse-dedups-elapsed         -> {}",
            a.key()
        );
    } else {
        println!(
            "  FAIL digit-collapse-dedups-elapsed         -> {} vs {}",
            a.key(),
            b.key()
        );
        failures += 1;
    }
    let c = signature(
        CampaignClass::Violation,
        "",
        "PATINA_VIOLATION two-leaders term=4",
    );
    if a.key() != c.key() {
        println!("  ok   distinct-findings-distinct-signatures -> ok");
    } else {
        println!("  FAIL distinct-findings-distinct-signatures");
        failures += 1;
    }
    // A policy bug-depth annotation distinguishes otherwise-identical findings.
    let shallow = signature(
        CampaignClass::Violation,
        "",
        "PATINA_VIOLATION x\nPATINA_SCHEDULE_POLICY pct=1 bug_depth=1 decisions=10",
    );
    let deep = signature(
        CampaignClass::Violation,
        "",
        "PATINA_VIOLATION x\nPATINA_SCHEDULE_POLICY pct=1 bug_depth=5 decisions=10",
    );
    if shallow.key() != deep.key() {
        println!("  ok   bug-depth-annotation-distinguishes    -> ok");
    } else {
        println!("  FAIL bug-depth-annotation-distinguishes");
        failures += 1;
    }

    println!("-- coverage gate --");
    let mut coverage_check = |name: &str,
                              tally: &CoverageTally,
                              waiver: Option<AllowUnmetSometimes>,
                              want_gate: CoverageGate,
                              want_unmet: usize| {
        let verdict = coverage_verdict(tally, waiver);
        if verdict.gate == want_gate && verdict.summary.unmet.len() == want_unmet {
            println!(
                "  ok   {name:<40} -> gate={} unmet={}",
                verdict.gate.as_str(),
                verdict.summary.unmet.len()
            );
        } else {
            println!(
                "  FAIL {name:<40} -> gate={} unmet={} (want gate={} unmet={})",
                verdict.gate.as_str(),
                verdict.summary.unmet.len(),
                want_gate.as_str(),
                want_unmet
            );
            failures += 1;
        }
    };
    let unmet = coverage_fixture(false).expect("unmet coverage fixture parses");
    let met = coverage_fixture(true).expect("met coverage fixture parses");
    coverage_check("sometimes-met-passes", &met, None, CoverageGate::Pass, 0);
    coverage_check("sometimes-unmet-fails", &unmet, None, CoverageGate::Fail, 1);
    coverage_check(
        "sometimes-unmet-waived-bare",
        &unmet,
        Some(AllowUnmetSometimes::Always),
        CoverageGate::Waived,
        1,
    );
    coverage_check(
        "sometimes-unmet-waived-under-threshold",
        &unmet,
        Some(AllowUnmetSometimes::BelowGenerations(3)),
        CoverageGate::Waived,
        1,
    );
    coverage_check(
        "sometimes-unmet-enforced-at-threshold",
        &unmet,
        Some(AllowUnmetSometimes::BelowGenerations(2)),
        CoverageGate::Fail,
        1,
    );
    let mut malformed = CoverageTally::default();
    match malformed.observe_generation(
        0,
        1,
        "PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-",
    ) {
        Ok(()) => {
            println!("  FAIL malformed-coverage-row-rejected       -> parsed");
            failures += 1;
        }
        Err(error) if error.contains("expected 10 pipe-separated fields") => {
            println!("  ok   malformed-coverage-row-rejected       -> loud error");
        }
        Err(error) => {
            println!("  FAIL malformed-coverage-row-rejected       -> {error}");
            failures += 1;
        }
    }

    println!("-- native edge coverage store --");
    for (name, ok, detail) in crate::coverage::campaign_detector_selftest() {
        if ok {
            println!("  ok   {name:<40} -> {detail}");
        } else {
            println!("  FAIL {name:<40} -> {detail}");
            failures += 1;
        }
    }

    println!();
    if failures == 0 {
        println!("CAMPAIGN SELFTEST PASSED");
        Ok(0)
    } else {
        println!("CAMPAIGN SELFTEST FAILED ({failures} checks)");
        Ok(1)
    }
}

fn coverage_fixture(satisfied: bool) -> Result<CoverageTally, String> {
    let mut tally = CoverageTally::default();
    let bit = if satisfied { 1 } else { 0 };
    tally.observe_generation(
        0,
        100,
        &format!(
            "PATINA_SDK_REPORT enabled=1 site=oracle|sometimes|a0|e4|f0|r1|s{bit}|v0|k-|@src/main.rs:10"
        ),
    )?;
    tally.observe_generation(
        1,
        101,
        "PATINA_SDK_REPORT enabled=1 site=faulty|fault|a1|e1|f1|r1|s0|v0|k-|@src/main.rs:11",
    )?;
    Ok(tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_is_reachable() {
        assert_eq!(classify(0, "", ""), CampaignClass::Ok);
        assert_eq!(
            classify(
                1,
                "",
                "PATINA_VIOLATION liveness detail=no-progress vtime_ns=2 budget_ns=1"
            ),
            CampaignClass::Liveness
        );
        assert_eq!(
            classify(
                2,
                "",
                "PATINA_VIOLATION converge detail=did-not-converge vtime_ns=9 budget_ns=3 last_fault_vtime_ns=3"
            ),
            CampaignClass::Liveness
        );
        assert_eq!(
            classify(0, "", "PATINA_VIOLATION x"),
            CampaignClass::Violation
        );
        assert_eq!(
            classify(2, "", "PATINA_BUGGIFY_DUPLICATE_LABEL label=x"),
            CampaignClass::FailClosedAbort
        );
        assert_eq!(
            classify(111, "", "patina: starvation stall"),
            CampaignClass::StarvationStall
        );
        assert_eq!(
            classify(2, "", "cargo-patina: could not compile foo"),
            CampaignClass::Infra
        );
        // A nonzero exit with no recognized marker is UNCLASSIFIED, never OK.
        assert_eq!(classify(3, "", ""), CampaignClass::Unclassified);
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest().unwrap(), 0);
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
    }

    #[test]
    fn renamed_flags_parse_and_old_spellings_error() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        // New spellings parse and set the right fields; the `=VALUE` form works too.
        let inv = parse(args(&[
            "art",
            "--sched-pct",
            "--seed-start",
            "7",
            "--out-dir",
            "d",
            "--gens=3",
        ]))
        .unwrap();
        assert!(inv.spec.pct);
        assert_eq!(inv.spec.seed_base, 7);
        assert_eq!(inv.out_dir, PathBuf::from("d"));
        assert_eq!(inv.spec.generations, 3);

        // Old spellings are unknown-flag errors (no aliases).
        for old in [
            &["art", "--pct"][..],
            &["art", "--out", "d"][..],
            &["art", "--seed-base", "1"][..],
        ] {
            assert!(parse(args(old)).is_err(), "old spelling {old:?} must error");
        }

        // A leading flag (no artifact) fails closed with the unsupported-option
        // usage error, not a later "failed to read artifact --nonsense".
        assert!(parse(args(&["--nonsense"])).is_err());
        assert!(parse(args(&["--gens", "3"])).is_err());
    }

    #[test]
    fn campaign_locates_the_artifact_around_options() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        // Options may lead the artifact, in any form/order, matching the leading
        // spelling exactly.
        let base = parse(args(&["art.wasm", "--gens", "5", "--seed-start", "2"])).unwrap();
        for spelling in [
            &["--gens", "5", "--seed-start", "2", "art.wasm"][..],
            &["--gens=5", "art.wasm", "--seed-start=2"][..],
        ] {
            let got = parse(args(spelling)).unwrap();
            assert_eq!(got.artifact, base.artifact);
            assert_eq!(got.spec, base.spec);
            assert_eq!(got.out_dir, base.out_dir);
        }
        // A leading UNKNOWN flag with no artifact is the unsupported-option error
        // naming the flag (campaign has no Cargo family to forward to).
        let error = |values: &[&str]| match parse(args(values)) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("expected a usage error for {values:?}"),
        };
        assert!(error(&["--frob"]).contains("--frob"));
        // A real compiled artifact stranded behind an unknown flag is a loud
        // routing error naming both, never a confusing later "failed to read".
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("app.wasm");
        std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
        let m = module.to_str().unwrap();
        let message = error(&["--frob", m]);
        assert!(message.contains("--frob"), "{message}");
        assert!(message.contains(m), "{message}");
    }

    #[test]
    fn sites_fold_is_watermark_idempotent() {
        let stderr = "PATINA_SDK_REPORT enabled=1 \
             site=oracle|sometimes|a1|e3|f2|r1|s1|v0|k-|@src/main.rs:9";
        let mut coverage = CoverageTally::default();
        let first = fold_sites_generation(&mut coverage, 0, 99, stderr).expect("first fold");
        assert_eq!(first, AuxFoldDecision::Apply);
        let after_first = coverage.clone();
        let second = fold_sites_generation(&mut coverage, 0, 99, stderr).expect("watermark skip");
        assert_eq!(second, AuxFoldDecision::SkipAlreadyApplied);
        assert_eq!(
            coverage, after_first,
            "duplicate sites fold must not double-count evals/fires/generation tallies"
        );
        let site = coverage.sites.get("oracle").unwrap();
        assert_eq!(site.evals, 3);
        assert_eq!(site.fires, 2);
        assert_eq!(site.registered_gens, 1);
        assert_eq!(coverage.generations_observed, 1);
    }

    #[test]
    fn sites_load_validates_resume_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.json");
        let coverage = CoverageTally {
            generations_observed: 2,
            ..CoverageTally::default()
        };
        write_sites_store(&path, &coverage).unwrap();

        load_coverage_tally(&path, 1).expect("one-generation tear ahead is resumable");
        load_coverage_tally(&path, 2).expect("aligned cursor is resumable");

        let behind = load_coverage_tally(&path, 3).unwrap_err();
        assert!(
            behind.0.contains("missing sites folds"),
            "unexpected error: {behind}"
        );
        let ahead = load_coverage_tally(&path, 0).unwrap_err();
        assert!(
            ahead
                .0
                .contains("at most one checkpoint-tear generation ahead"),
            "unexpected error: {ahead}"
        );

        let mut bad_schema = coverage.to_json();
        bad_schema["schema"] = "patina.campaign.sites/v999".into();
        fs::write(&path, serde_json::to_string_pretty(&bad_schema).unwrap()).unwrap();
        let schema = load_coverage_tally(&path, 2).unwrap_err();
        assert!(
            schema.0.contains("unsupported schema"),
            "unexpected error: {schema}"
        );

        fs::remove_file(&path).unwrap();
        let missing = load_coverage_tally(&path, 0).unwrap_err();
        assert!(
            missing.0.contains("missing sites store"),
            "unexpected error: {missing}"
        );
    }

    #[test]
    fn envelope_is_summary_first_with_artifact_pointers() {
        // A campaign of four generations: two OK, one failing (non-novel repeat),
        // one novel failing. The v2 envelope must expose the class histogram and
        // deduped signatures, but per-run detail (`notable_runs`) ONLY for the
        // novel/failing generations — the two OK generations are elided.
        let mk = |generation: u64, class: CampaignClass, novel: bool| GenerationOutcome {
            generation,
            seed: generation,
            class,
            flags: Vec::new(),
            novel,
            signature_key: class.is_failure().then(|| "LIVENESS|shape|".to_string()),
        };
        let outcomes = vec![
            mk(0, CampaignClass::Ok, false),
            mk(1, CampaignClass::Liveness, true),
            mk(2, CampaignClass::Ok, false),
            mk(3, CampaignClass::Liveness, false),
        ];
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec {
                generations: 4,
                ..CampaignSpec::default()
            },
        );
        state.classes.insert("OK".to_string(), 2);
        state.classes.insert("LIVENESS".to_string(), 2);
        state.generations_done = 4;
        state.notable_runs = outcomes
            .into_iter()
            .filter(GenerationOutcome::is_notable)
            .collect();
        let coverage = CoverageTally {
            generations_observed: 4,
            ..CoverageTally::default()
        };
        let coverage_verdict = coverage_verdict(&coverage, None);
        let edge_coverage = EdgeCoverageState::unavailable("not-instrumented", None);
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result: "failure",
            exit_code: 1,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            out_dir: Path::new("out"),
            state_path: Path::new("out/campaign-state.json"),
            sites_path: Path::new("out/sites.json"),
        });

        assert_eq!(envelope["schema"], CAMPAIGN_ENVELOPE_SCHEMA);
        assert_eq!(envelope["schema"], "patina.campaign/v2");
        assert_eq!(envelope["classes"]["OK"], 2);
        assert_eq!(envelope["classes"]["LIVENESS"], 2);

        // Only the two novel/failing generations appear in `notable_runs`; the OK
        // generations are represented solely by the class histogram.
        let notable = envelope["notable_runs"].as_array().unwrap();
        assert_eq!(
            notable.len(),
            2,
            "OK generations must be elided: {envelope:#}"
        );
        let gens: Vec<u64> = notable
            .iter()
            .map(|r| r["generation"].as_u64().unwrap())
            .collect();
        assert_eq!(gens, vec![1, 3]);
        assert!(notable.iter().all(|r| r["class"] == "LIVENESS"));

        // Machine-readable pointers keep the full on-disk detail reachable.
        let artifacts = &envelope["artifacts"];
        assert_eq!(artifacts["out_dir"], "out");
        assert!(
            artifacts["campaign_state"]
                .as_str()
                .unwrap()
                .ends_with("campaign-state.json")
        );
        assert!(
            artifacts["signature_store"]
                .as_str()
                .unwrap()
                .ends_with("signatures.json")
        );
        assert!(
            artifacts["failures_dir"]
                .as_str()
                .unwrap()
                .ends_with("failures"),
            "a failing campaign must point at its saved-trace dir: {envelope:#}"
        );
        assert!(
            artifacts["site_coverage"]
                .as_str()
                .unwrap()
                .ends_with("sites.json")
        );
        assert_eq!(envelope["sdk_sites"]["labels_seen"], 0);
        assert_eq!(envelope["coverage"]["gate"], "pass");
        // No `--report`, so no reports pointer is promised.
        assert!(artifacts.get("reports_dir").is_none());
    }

    #[test]
    fn envelope_clean_campaign_omits_failure_pointers() {
        // A clean campaign advertises no failures dir (it is never created).
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec::default(),
        );
        state.classes.insert("OK".to_string(), 1);
        state.generations_done = 1;
        let coverage = CoverageTally {
            generations_observed: 1,
            ..CoverageTally::default()
        };
        let coverage_verdict = coverage_verdict(&coverage, None);
        let edge_coverage = EdgeCoverageState::unavailable("not-instrumented", None);
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result: "ok",
            exit_code: 0,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            out_dir: Path::new("out"),
            state_path: Path::new("out/campaign-state.json"),
            sites_path: Path::new("out/sites.json"),
        });
        assert_eq!(envelope["failures"], 0);
        assert!(envelope["notable_runs"].as_array().unwrap().is_empty());
        assert!(envelope["artifacts"].get("failures_dir").is_none());
    }

    #[test]
    fn progress_every_and_plateau_parse_and_default() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        // Default when unset.
        let inv = parse(args(&["art"])).unwrap();
        assert_eq!(inv.progress_every, DEFAULT_PROGRESS_EVERY);
        assert_eq!(inv.spec.plateau_after, DEFAULT_PLATEAU_AFTER);
        // Both value forms parse; 0 and 1 are accepted (silent / full-stream).
        assert_eq!(
            parse(args(&["art", "--progress-every", "0"]))
                .unwrap()
                .progress_every,
            0
        );
        assert_eq!(
            parse(args(&["art", "--progress-every=1"]))
                .unwrap()
                .progress_every,
            1
        );
        assert_eq!(
            parse(args(&["art", "--plateau-after", "0"]))
                .unwrap()
                .spec
                .plateau_after,
            0
        );
        assert_eq!(
            parse(args(&["art", "--plateau-after=17"]))
                .unwrap()
                .spec
                .plateau_after,
            17
        );
        // Duplicate is rejected (set_once), non-integer is rejected.
        assert!(parse(args(&["art", "--progress-every=1", "--progress-every=2"])).is_err());
        assert!(parse(args(&["art", "--progress-every", "nope"])).is_err());
        assert!(parse(args(&["art", "--plateau-after=1", "--plateau-after=2"])).is_err());
        assert!(parse(args(&["art", "--plateau-after", "nope"])).is_err());
    }

    #[test]
    fn allow_unmet_sometimes_parses_flag_and_spec_shapes() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        let bare = parse(args(&["art", "--allow-unmet-sometimes"])).unwrap();
        assert_eq!(
            bare.spec.allow_unmet_sometimes,
            Some(AllowUnmetSometimes::Always)
        );
        let threshold = parse(args(&["art", "--allow-unmet-sometimes=10"])).unwrap();
        assert_eq!(
            threshold.spec.allow_unmet_sometimes,
            Some(AllowUnmetSometimes::BelowGenerations(10))
        );
        assert!(parse(args(&["art", "--allow-unmet-sometimes=0"])).is_err());
        assert!(
            parse(args(&[
                "art",
                "--allow-unmet-sometimes=1",
                "--allow-unmet-sometimes=2",
            ]))
            .is_err()
        );

        let mut spec = CampaignSpec::default();
        spec.apply_json(&serde_json::json!({"allow_unmet_sometimes": true}))
            .unwrap();
        assert_eq!(
            spec.allow_unmet_sometimes,
            Some(AllowUnmetSometimes::Always)
        );
        spec.apply_json(&serde_json::json!({"allow_unmet_sometimes": 7}))
            .unwrap();
        assert_eq!(
            spec.allow_unmet_sometimes,
            Some(AllowUnmetSometimes::BelowGenerations(7))
        );
        for bad in [
            serde_json::json!({"allow_unmet_sometimes": false}),
            serde_json::json!({"allow_unmet_sometimes": 0}),
            serde_json::json!({"allow_unmet_sometimes": "yes"}),
        ] {
            assert!(CampaignSpec::default().apply_json(&bad).is_err());
        }
    }

    #[test]
    fn continuation_modes_parse_and_reject_resupplied_spec() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        let extend = parse(args(&["--extend", "7", "--out-dir", "d"])).unwrap();
        assert_eq!(extend.artifact, None);
        assert_eq!(extend.mode, CampaignMode::Extend { additional: 7 });
        assert_eq!(extend.out_dir, PathBuf::from("d"));
        let resume = parse(args(&[
            "--resume",
            "--timeout-secs",
            "120",
            "--progress-every",
            "2",
        ]))
        .unwrap();
        assert_eq!(resume.mode, CampaignMode::Resume);
        assert_eq!(resume.timeout_secs_override, Some(120));
        assert_eq!(resume.progress_every, 2);

        assert!(parse(args(&["--extend", "0"])).is_err());
        assert!(parse(args(&["--extend", "1", "--resume"])).is_err());
        assert!(parse(args(&["guest", "--extend", "1"])).is_err());
        assert!(parse(args(&["--extend", "1", "--", "guest-arg"])).is_err());
        for flag in [
            "--gens",
            "--seed-start",
            "--spec",
            "--buggify",
            "--swarm",
            "--sched-pct",
            "--faults",
            "--liveness-watchdog",
            "--converge-within",
            "--heal-after",
            "--report",
            "--allow-unmet-sometimes",
        ] {
            let values: Vec<&str> = match flag {
                "--buggify"
                | "--swarm"
                | "--sched-pct"
                | "--faults"
                | "--report"
                | "--allow-unmet-sometimes" => vec!["--extend", "1", flag],
                _ => vec!["--extend", "1", flag, "1"],
            };
            let message = parse(args(&values)).unwrap_err().to_string();
            assert!(
                message.contains("out-dir's recorded spec is authoritative"),
                "{message}"
            );
            assert!(message.contains(flag), "{message}");
        }
    }

    #[test]
    fn campaign_state_round_trips_byte_stably_and_rejects_corruption() {
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec {
                generations: 3,
                timeout_secs: 9,
                buggify: true,
                watchdog_nanos: Some(5),
                ..CampaignSpec::default()
            },
        );
        state.generations_done = 2;
        state.classes.insert("OK".to_string(), 1);
        state.classes.insert("LIVENESS".to_string(), 1);
        let key = "LIVENESS|PATINA_VIOLATION liveness #|".to_string();
        state.signatures.insert(
            key.clone(),
            SignatureRecord {
                class: CampaignClass::Liveness,
                shape: "PATINA_VIOLATION liveness #".to_string(),
                policy: String::new(),
                first_seen_gen: 1,
                count: 1,
                seed: 42,
                reproduce: "cargo patina run guest --seed 42".to_string(),
                trace: None,
                report: None,
            },
        );
        state.notable_runs.push(GenerationOutcome {
            generation: 1,
            seed: 42,
            class: CampaignClass::Liveness,
            flags: vec!["--liveness-watchdog".to_string(), "5".to_string()],
            novel: true,
            signature_key: Some(key),
        });
        state.invocations.push(InvocationRecord {
            cli: "campaign guest --gens 3".to_string(),
            from_gen: 0,
            gens_run: 2,
            timeout_secs: 9,
            elapsed_secs: 1,
        });
        let pretty = serde_json::to_string_pretty(&state.to_json()).unwrap();
        let parsed_json: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let loaded = CampaignState::from_json(&parsed_json).unwrap();
        assert_eq!(
            pretty,
            serde_json::to_string_pretty(&loaded.to_json()).unwrap(),
            "state serialize -> load -> serialize must be byte-stable"
        );

        let mut bad_schema = parsed_json.clone();
        bad_schema["schema"] = "patina.campaign.state/v999".into();
        assert!(CampaignState::from_json(&bad_schema).is_err());
        let mut bad_class = parsed_json;
        bad_class["classes"] = serde_json::json!({"MYSTERY": 1, "OK": 1});
        assert!(CampaignState::from_json(&bad_class).is_err());
    }

    #[test]
    fn campaign_lock_refuses_a_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let _first = CampaignLock::acquire(dir.path()).unwrap();
        let error = CampaignLock::acquire(dir.path()).unwrap_err().to_string();
        assert!(
            error.contains("another campaign is writing this out-dir")
                || error.contains("failed to lock campaign out-dir"),
            "{error}"
        );
    }

    #[test]
    fn spec_rejects_unknown_keys() {
        let mut spec = CampaignSpec::default();
        let json: serde_json::Value = serde_json::from_str(r#"{"bogus": 1}"#).unwrap();
        assert!(spec.apply_json(&json).is_err());
        let json: serde_json::Value =
            serde_json::from_str(r#"{"generations": 12, "buggify": true}"#).unwrap();
        spec.apply_json(&json).unwrap();
        assert_eq!(spec.generations, 12);
        assert!(spec.buggify);
    }
}
