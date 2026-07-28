//! `cargo patina campaign` — a config-driven, deterministic fault-and-schedule
//! sweep that generalizes the battle-tested shell campaign machinery
//! (`testbeds/raft-harness/fuzz-sweep.sh`, `testbeds/buggify-campaign.sh`) into a
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
//!     the existing `RAFT_RESULT`/`RAFT_VIOLATION`/`PATINA_SDK_REPORT`
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
//! Output is a human summary or a `patina.campaign/v1` JSON envelope (the
//! `patina.result/v1` envelope family extended for a campaign).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::CliError;

/// The stable schema identifier for the campaign JSON envelope, extending the
/// `patina.result/v1` family.
const CAMPAIGN_ENVELOPE_SCHEMA: &str = "patina.campaign/v1";

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
                other => {
                    return Err(CliError(format!(
                        "unknown campaign spec key {other:?}; expected generations, seed_base, \
                         timeout_secs, guest_args, buggify, swarm, pct, faults, watchdog_nanos, \
                         converge_nanos, heal_after_nanos, or report"
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

/// A parsed `campaign` invocation.
pub struct CampaignInvocation {
    artifact: PathBuf,
    out_dir: PathBuf,
    spec: CampaignSpec,
    selftest: bool,
}

// ===========================================================================
// Parsing + dispatch
// ===========================================================================

/// Parse `campaign [--selftest] | campaign <ARTIFACT> [flags] [-- GUEST_ARGS…]`.
pub fn parse(mut arguments: Vec<OsString>) -> Result<CampaignInvocation, CliError> {
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
            artifact: PathBuf::new(),
            out_dir: PathBuf::new(),
            spec: CampaignSpec::default(),
            selftest: true,
        });
    }

    if arguments.is_empty() || arguments[0] == "--" {
        return Err(CliError::usage(
            "campaign requires an artifact path (a .wasm module or native binary), or --selftest",
        ));
    }
    let artifact = PathBuf::from(arguments.remove(0));
    let mut spec = CampaignSpec::default();
    let mut out_dir: Option<PathBuf> = None;

    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("campaign options must be valid UTF-8"))?
            .to_string();
        let mut value_of = |flag: &str| -> Result<String, CliError> {
            index += 1;
            arguments
                .get(index)
                .and_then(|v| v.to_str())
                .map(str::to_string)
                .ok_or_else(|| CliError::usage(format!("{flag} requires a value")))
        };
        match option.as_str() {
            "--spec" => {
                let path = value_of("--spec")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| CliError(format!("failed to read campaign spec {path}: {e}")))?;
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| CliError(format!("campaign spec {path} is invalid JSON: {e}")))?;
                spec.apply_json(&json)?;
            }
            "--out" => out_dir = Some(PathBuf::from(value_of("--out")?)),
            "--gens" | "--generations" => {
                spec.generations = parse_u64_flag("--gens", &value_of("--gens")?)?;
            }
            "--seed-base" => {
                spec.seed_base = parse_u64_flag("--seed-base", &value_of("--seed-base")?)?;
            }
            "--timeout-secs" => {
                spec.timeout_secs = parse_u64_flag("--timeout-secs", &value_of("--timeout-secs")?)?;
            }
            "--buggify" => spec.buggify = true,
            "--swarm" => spec.swarm = true,
            "--pct" => spec.pct = true,
            "--faults" => spec.faults = true,
            "--report" => spec.report = true,
            "--liveness-watchdog" => {
                spec.watchdog_nanos = Some(parse_budget(&mut value_of, "--liveness-watchdog")?);
            }
            "--converge-within" => {
                spec.converge_nanos = Some(parse_budget(&mut value_of, "--converge-within")?);
            }
            "--heal-after" => {
                spec.heal_after_nanos =
                    Some(parse_u64_flag("--heal-after", &value_of("--heal-after")?)?);
            }
            other => {
                return Err(CliError::usage(format!(
                    "unsupported option {other:?} for `campaign`"
                )));
            }
        }
        index += 1;
    }
    if !guest_args.is_empty() {
        spec.guest_args = guest_args;
    }
    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("patina-campaign-out"));
    Ok(CampaignInvocation {
        artifact,
        out_dir,
        spec,
        selftest: false,
    })
}

fn parse_u64_flag(name: &str, value: &str) -> Result<u64, CliError> {
    value
        .parse()
        .map_err(|_| CliError::usage(format!("{name} must be an unsigned integer; got {value:?}")))
}

/// A budget flag accepts an optional value: the next token if it looks numeric,
/// else the runtime default (encoded here as a large virtual-time budget).
fn parse_budget(
    value_of: &mut impl FnMut(&str) -> Result<String, CliError>,
    name: &str,
) -> Result<u64, CliError> {
    let raw = value_of(name)?;
    parse_u64_flag(name, &raw)
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
    /// `PATINA_ALWAYS_VIOLATION`, `RAFT_VIOLATION`, `BUG_CAUGHT`, or a guest panic.
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

    /// Whether this class is a failure the campaign must surface (everything but
    /// `OK`).
    pub const fn is_failure(&self) -> bool {
        !matches!(self, CampaignClass::Ok)
    }
}

const INFRA_MARKERS: &[&str] = &[
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
    "RAFT_VIOLATION",
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
            "RAFT_VIOLATION",
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
#[derive(Clone, Debug)]
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
}

// ===========================================================================
// Campaign driver
// ===========================================================================

struct GenerationOutcome {
    generation: u64,
    seed: u64,
    class: CampaignClass,
    flags: Vec<String>,
    novel: bool,
    signature_key: Option<String>,
}

fn run_campaign(invocation: CampaignInvocation) -> Result<i32, CliError> {
    let CampaignInvocation {
        artifact,
        out_dir,
        spec,
        ..
    } = invocation;

    // Resolve the artifact once (build a source on the fly), then sweep the SAME
    // built artifact across every generation — never rebuilt per generation.
    let resolved = crate::resolve_artifact(crate::ArtifactRef::Prebuilt(artifact.clone()))?;
    let artifact_path = resolved.path.clone();
    let family = artifact_family(&artifact_path)?;

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| CliError(format!("failed to create campaign output dir: {e}")))?;
    let traces_dir = out_dir.join("traces");
    std::fs::create_dir_all(&traces_dir)
        .map_err(|e| CliError(format!("failed to create traces dir: {e}")))?;

    let self_exe = std::env::current_exe()
        .map_err(|e| CliError(format!("failed to resolve cargo-patina binary path: {e}")))?;

    let json_output = crate::output::options().is_json();
    if !json_output {
        println!(
            "PATINA_CAMPAIGN_START artifact={} family={family} generations={} seed_base={} out={}",
            artifact_path.display(),
            spec.generations,
            spec.seed_base,
            out_dir.display(),
        );
    }

    let mut class_counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut signatures: BTreeMap<String, SignatureRecord> = BTreeMap::new();
    let mut outcomes: Vec<GenerationOutcome> = Vec::new();

    for generation in 0..spec.generations {
        let hash = generation_hash(spec.seed_base, generation);
        let seed = u64::from_le_bytes(hash[0..8].try_into().expect("32-byte hash"));
        let flags = derive_flags(&spec, &hash, family);
        let trace_path = traces_dir.join(format!("generation-{generation}.patina"));

        let (exit, stdout, stderr, timed_out) = run_generation(
            &self_exe,
            &artifact_path,
            seed,
            &flags,
            &trace_path,
            &spec.guest_args,
            spec.timeout_secs,
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
        *class_counts.entry(class.as_str()).or_insert(0) += 1;

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
                &spec.guest_args,
                saved_trace.as_deref(),
            );
            let report = if spec.report {
                render_failure_report(
                    &out_dir,
                    saved_trace.as_deref(),
                    &artifact_path,
                    family,
                    generation,
                )
            } else {
                None
            };
            signatures
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
        let _ = std::fs::remove_file(&trace_path);

        if !json_output {
            let tag = if novel { " NOVEL" } else { "" };
            println!(
                "PATINA_CAMPAIGN_GEN generation={generation} seed={seed} class={}{tag}",
                class.as_str()
            );
        }
        outcomes.push(GenerationOutcome {
            generation,
            seed,
            class,
            flags,
            novel,
            signature_key,
        });
    }

    // Persist the signature store.
    let store_path = out_dir.join("signatures.json");
    write_signature_store(&store_path, &signatures)?;

    let failures: u64 = outcomes.iter().filter(|o| o.class.is_failure()).count() as u64;
    let novel_count = outcomes.iter().filter(|o| o.novel).count() as u64;
    let result = if failures == 0 { "ok" } else { "failure" };
    let exit_code = if failures == 0 { 0 } else { 1 };

    if json_output {
        emit_campaign_envelope(
            result,
            exit_code,
            &artifact_path,
            family,
            &spec,
            &class_counts,
            &signatures,
            &outcomes,
            &store_path,
        );
    } else {
        print_campaign_summary(
            &class_counts,
            &signatures,
            failures,
            novel_count,
            spec.generations,
            &store_path,
        );
    }
    Ok(exit_code)
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
fn run_generation(
    self_exe: &Path,
    artifact: &Path,
    seed: u64,
    flags: &[String],
    trace_path: &Path,
    guest_args: &[String],
    timeout_secs: u64,
) -> Result<(i32, String, String, bool), CliError> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut command = Command::new(self_exe);
    command
        .arg("run")
        .arg(artifact)
        .arg("--seed")
        .arg(seed.to_string())
        .arg("--record")
        .arg(trace_path);
    for flag in flags {
        command.arg(flag);
    }
    if !guest_args.is_empty() {
        command.arg("--");
        for arg in guest_args {
            command.arg(arg);
        }
    }
    // Keep the child's diagnostics deterministic and machine-parseable.
    command.env("PATINA_LIVENESS_REPORT", "1");
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
                        let _ = child.kill();
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
        flags.push(format!("--buggify={fire}"));
        flags.push("--buggify-activation-permille".to_string());
        flags.push(activation.to_string());
    }
    if spec.faults {
        let drop = u32::from(hash[12]) * 200 / 255; // [0, 200] permille
        flags.push("--net-drop-permille".to_string());
        flags.push(drop.to_string());
        let jitter_hi = u64::from(hash[13]) * 10_000; // up to 2.55 ms
        flags.push("--sleep-jitter-nanos".to_string());
        flags.push(format!("0:{jitter_hi}"));
    }
    if spec.swarm && native {
        flags.push("--swarm".to_string());
    }
    if spec.pct && native {
        let depth = 1 + u32::from(hash[11] % 5); // [1, 5]
        flags.push(format!("--sched-pct={depth}"));
    }
    if let Some(nanos) = spec.watchdog_nanos {
        flags.push(format!("--liveness-watchdog={nanos}"));
    }
    if let Some(nanos) = spec.converge_nanos {
        flags.push(format!("--converge-within={nanos}"));
        if let Some(heal) = spec.heal_after_nanos {
            flags.push("--heal-after".to_string());
            flags.push(heal.to_string());
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
/// child wrote a valid (non-empty) bundle. A mid-run abort — a liveness violation
/// or an always-violation trap — never reaches `Context::finish`, so it leaves
/// only an empty reservation file; that is not a replayable trace and is skipped.
fn save_failure_trace(out_dir: &Path, trace_path: &Path, generation: u64) -> Option<String> {
    let is_valid = std::fs::metadata(trace_path)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !is_valid {
        return None;
    }
    let failures_dir = out_dir.join("failures");
    std::fs::create_dir_all(&failures_dir).ok()?;
    let dest = failures_dir.join(format!("generation-{generation}.patina"));
    std::fs::copy(trace_path, &dest).ok()?;
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

fn artifact_family(path: &Path) -> Result<&'static str, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError(format!("failed to read artifact {}: {e}", path.display())))?;
    if bytes.starts_with(b"\0asm") {
        Ok("wasi")
    } else {
        Ok("native")
    }
}

fn write_signature_store(
    path: &Path,
    signatures: &BTreeMap<String, SignatureRecord>,
) -> Result<(), CliError> {
    let entries: Vec<serde_json::Value> = signatures
        .iter()
        .map(|(key, record)| record.to_json(key))
        .collect();
    let store = serde_json::json!({
        "schema": "patina.campaign.signatures/v1",
        "signatures": entries,
    });
    let text = serde_json::to_string_pretty(&store)
        .map_err(|e| CliError(format!("failed to serialize signature store: {e}")))?;
    std::fs::write(path, text)
        .map_err(|e| CliError(format!("failed to write signature store: {e}")))
}

fn print_campaign_summary(
    class_counts: &BTreeMap<&'static str, u64>,
    signatures: &BTreeMap<String, SignatureRecord>,
    failures: u64,
    novel: u64,
    generations: u64,
    store_path: &Path,
) {
    println!("== campaign summary ==");
    println!("generations={generations} failures={failures} novel_signatures={novel}");
    for (class, count) in class_counts {
        println!("  class {class:<18} {count}");
    }
    if !signatures.is_empty() {
        println!("-- failure signatures --");
        for (key, record) in signatures {
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
    println!("signature store: {}", store_path.display());
    println!(
        "PATINA_CAMPAIGN_COMPLETE generations={generations} failures={failures} novel={novel}"
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_campaign_envelope(
    result: &str,
    exit_code: i32,
    artifact: &Path,
    family: &'static str,
    spec: &CampaignSpec,
    class_counts: &BTreeMap<&'static str, u64>,
    signatures: &BTreeMap<String, SignatureRecord>,
    outcomes: &[GenerationOutcome],
    store_path: &Path,
) {
    let classes: serde_json::Map<String, serde_json::Value> = class_counts
        .iter()
        .map(|(class, count)| ((*class).to_string(), serde_json::Value::from(*count)))
        .collect();
    let signature_json: Vec<serde_json::Value> = signatures
        .iter()
        .map(|(key, record)| record.to_json(key))
        .collect();
    let generations_json: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "generation": o.generation,
                "seed": o.seed,
                "class": o.class.as_str(),
                "novel": o.novel,
                "signature": o.signature_key,
                "flags": o.flags,
            })
        })
        .collect();
    let failures = outcomes.iter().filter(|o| o.class.is_failure()).count();
    let novel = outcomes.iter().filter(|o| o.novel).count();
    let envelope = serde_json::json!({
        "schema": CAMPAIGN_ENVELOPE_SCHEMA,
        "verb": "campaign",
        "result": result,
        "exit_code": exit_code,
        "artifact": artifact.display().to_string(),
        "family": family,
        "generations": spec.generations,
        "seed_base": spec.seed_base,
        "failures": failures,
        "novel_signatures": novel,
        "classes": classes,
        "signatures": signature_json,
        "signature_store": store_path.display().to_string(),
        "runs": generations_json,
    });
    println!("{envelope}");
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

    println!();
    if failures == 0 {
        println!("CAMPAIGN SELFTEST PASSED");
        Ok(0)
    } else {
        println!("CAMPAIGN SELFTEST FAILED ({failures} checks)");
        Ok(1)
    }
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
