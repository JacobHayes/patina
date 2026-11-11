//! Campaign specification defaults and JSON grammar.

use std::collections::BTreeSet;

use patina_dst_runtime::FaultKnob;

use super::planes::{VARY_NAMES, Vary};
use super::{ClassifyRules, FAULT_SCALE_FULL, RunClass};
use crate::{CliError, help};

pub(super) const DEFAULT_PLATEAU_AFTER: u64 = 200;

/// The default progress-heartbeat cadence: in human mode, print one
/// `PATINA_CAMPAIGN_PROGRESS` line every this-many generations (on top of the
/// always-printed novel/failing lines). 100 is a deliberate middle ground — at the
/// default 40-generation campaign it yields a clean summary with no heartbeat
/// noise, while a multi-thousand-generation sweep still gets a steady but sparse
/// "still alive" pulse (~1% of the old per-generation line volume). `--progress-every 1`
/// restores the full per-generation stream; `--progress-every 0` silences the heartbeat.
pub(super) const DEFAULT_PROGRESS_EVERY: u64 = 100;

// ===========================================================================
// Spec
// ===========================================================================

/// Where a campaign writes when `--out-dir` is not given, and where
/// `minimize --generation` looks for a recorded campaign for the same reason.
pub(crate) const DEFAULT_OUT_DIR: &str = "patina-campaign-out";

/// A campaign specification. Every field has a default; a `--spec FILE.json`
/// supplies overrides and individual flags override the spec, so a campaign can be
/// driven entirely by flags, entirely by a JSON spec, or a mix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSpec {
    pub generations: u64,
    pub seed_base: u64,
    pub timeout_secs: u64,
    pub guest_args: Vec<String>,
    /// Apply seed-derived swarm fault-class selection.
    pub swarm: bool,
    /// What each generation draws (`--vary`): the buggify rates, the PCT
    /// depth, an `--instrument` artifact's yield stride (a log sweep from every
    /// edge to one in 1024; a dense stride multiplies a generation's cost), the
    /// knobs of the selected fault planes.
    ///
    /// A plane subset exists for the guest that needs one plane always off. A
    /// network testbed whose store lives on the simulated disk only because it
    /// is the real store gets nothing from fs faults but failed opens, which end
    /// the generation before it reaches the network behaviour being swept.
    pub vary: Vary,
    /// Knobs of the selected [`Self::vary`] planes that are never drawn,
    /// named by their `run` flag (`"exclude_knobs": ["--net-reset-permille"]`).
    ///
    /// For a guest that models only some of a plane's faults: a pub-sub broker
    /// that treats a lost connection as fatal gets nothing from connection
    /// resets but a run that ends before the fault the campaign is sweeping.
    /// The excluded knob emits no flag in any generation; every other band
    /// draws exactly what it draws without the exclusion, because each reads
    /// its own claimed byte. A name that is not a knob a plane draws, or a knob
    /// whose plane the campaign does not select, is refused rather than
    /// recorded as an exclusion that excludes nothing.
    pub exclude_knobs: BTreeSet<FaultKnob>,
    /// Scale (per-mille) applied to every seed-drawn fault INTENSITY under
    /// [`Self::vary`]: `1000` (the default) leaves the exploration bands exactly
    /// as they have always been, `10` makes every injected fault a hundredfold
    /// rarer.
    ///
    /// WHY A DIAL AT ALL. The bands are tuned for an aggressive sweep: up to 100
    /// per-mille of filesystem operations failed outright and 200 per-mille
    /// short. For a workload that treats the disk as basically working — a
    /// database's own stress harness, say — that is not fault injection, it is a
    /// broken disk: the guest dies on the first injected error, every generation
    /// signature is a different flavour of "startup failed", and the campaign
    /// explores nothing. The rare-fault regime (Antithesis' `unreliable-libc`
    /// being the reference point) is where the workload RUNS to completion and
    /// only unusual paths get exercised. Both are legitimate; only one was
    /// reachable.
    ///
    /// WHY PER-MILLE RATHER THAN A FLOAT. Every rate this scales is already
    /// per-mille, the CLI already has a `[0, 1000]` value grammar to validate it
    /// against, and — the load-bearing reason — the whole derivation stays in
    /// integers. A campaign's central guarantee is that every knob is a pure
    /// function of the generation number; keeping the scale an integer keeps the
    /// arithmetic bit-exact under any rounding mode, and keeps the JSON spec
    /// round-trip exact rather than float-formatted.
    ///
    /// WHAT IT DOES NOT TOUCH, and why (see [`scale_intensity`]): the bands that
    /// pick a fault's SHAPE rather than its intensity. `--net-tcp-buffer-bytes` is
    /// a capacity where a SMALLER value is the harsher one, so scaling it down
    /// would do the opposite of what the operator asked; and
    /// `buggify`/`sched-pct`/`--swarm` configure exploration of the guest's own
    /// cooperative sites rather than injecting an environment fault; and the
    /// crash kind, which is a model.
    pub fault_scale_permille: u64,
    /// The DNS host table (`NAME=ADDR` entries) every generation runs with.
    ///
    /// Part of the campaign's shape rather than a per-generation draw: the names
    /// a guest resolves are its workload, not a fault. It is what makes the
    /// DNS plane non-inert — with no defined name, a guest's lookups
    /// are all NXDOMAIN by semantics and no DNS fault is ever eligible — so the
    /// band is only emitted when this is non-empty.
    pub dns_entries: Vec<String>,
    /// Every generation's pre-run gate `--allow` values, `all` included.
    pub allow_symbols: Vec<String>,
    /// The address layout every generation runs, and every reproduce command
    /// replays, with. `Randomized` (`--allow-randomized-address-layout`) keeps
    /// the host's randomization and qualifies each generation's determinism.
    /// Invocation shape like [`Self::allow_symbols`]. A campaign's state always
    /// records it; `None` before the campaign starts means fixed.
    pub address_layout: Option<patina_dst_trace::AddressLayout>,
    /// The CPU count every generation's guest sees (`--cpus`), forwarded to
    /// every child `run` and every reproduce command. Invocation shape like
    /// [`Self::address_layout`]: a campaign's state always records it (the
    /// default unless the operator chose one).
    pub cpus: Option<u32>,
    /// The host directory every generation's guest filesystem is captured
    /// from (`--mount`), forwarded to every child `run` and every reproduce
    /// command (a replay re-supplies it so the fingerprint can verify the
    /// corpus). Invocation shape like [`Self::cpus`]; stored absolute so the
    /// reproduce commands work from any directory.
    pub mount: Option<Mount>,
    /// Generic liveness-watchdog budget (virtual nanoseconds), applied every
    /// generation when set.
    pub watchdog_nanos: Option<u64>,
    /// Native host-time limit, forwarded unchanged to run and replay.
    pub compute_watchdog_ms: Option<u64>,
    /// Heal-then-converge budget (virtual nanoseconds), applied every generation
    /// when set.
    pub converge_nanos: Option<u64>,
    /// Explicit heal-then-converge arm-time override (virtual nanoseconds).
    pub heal_after_nanos: Option<u64>,
    /// Report native edge-coverage plateau after this many generations without a
    /// new edge; 0 disables the plateau flag.
    pub plateau_after: u64,
    /// Bias generation derivation toward previously productive configurations
    /// (coverage-depth arc, wave E). Changes the generation stream, so it is part
    /// of the persisted spec and cannot be toggled on a continuation.
    pub guided: bool,
    /// Waive the default campaign-level gate for `sometimes!` sites that were
    /// registered but never satisfied.
    pub allow_unmet_sometimes: bool,
    /// Verify reproduction: run each novel finding's reproduce path once before
    /// reporting it, and a seeded sample of clean generations twice, filing a
    /// mismatch as `NONDETERMINISM` (`campaign/verify.rs`). On by default;
    /// `--no-verify` trades the check for the extra child runs it costs. Part of
    /// the campaign's shape, because it decides which class a generation lands
    /// in.
    pub verify: bool,
    /// Per-guest classification rules for a guest that never calls the verdict
    /// ABI (outcome-channel arc §4.3). Core patina is guest-agnostic: a guest's
    /// own marker dialect lives here, in its campaign spec, and nowhere else.
    pub classify: ClassifyRules,
}

impl Default for CampaignSpec {
    fn default() -> Self {
        Self {
            generations: 40,
            seed_base: 0,
            timeout_secs: 60,
            guest_args: Vec::new(),
            swarm: false,
            vary: Vary::default(),
            exclude_knobs: BTreeSet::new(),
            fault_scale_permille: FAULT_SCALE_FULL,
            dns_entries: Vec::new(),
            allow_symbols: Vec::new(),
            address_layout: None,
            cpus: None,
            mount: None,
            watchdog_nanos: None,
            compute_watchdog_ms: None,
            converge_nanos: None,
            heal_after_nanos: None,
            plateau_after: DEFAULT_PLATEAU_AFTER,
            guided: false,
            allow_unmet_sometimes: false,
            verify: true,
            classify: ClassifyRules::default(),
        }
    }
}

impl CampaignSpec {
    /// Merge a JSON spec object over the defaults. Unknown keys are rejected so a
    /// typo in a spec file fails loudly rather than being silently ignored.
    pub(super) fn apply_json(&mut self, value: &serde_json::Value) -> Result<(), CliError> {
        let object = value
            .as_object()
            .ok_or_else(|| CliError("campaign spec must be a JSON object".into()))?;
        for (key, val) in object {
            match key.as_str() {
                "gens" => self.generations = json_u64(key, val)?,
                "seed_start" => self.seed_base = json_u64(key, val)?,
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
                "swarm" => self.swarm = json_bool(key, val)?,
                "vary" => self.vary = json_vary(key, val)?,
                "exclude_knobs" => self.exclude_knobs = json_exclude_knobs(key, val)?,
                "fault_scale_permille" => {
                    // A spec file bypasses the CLI value grammar, so hold it to
                    // the same `[0, 1000]` bound here rather than letting an
                    // out-of-range scale silently amplify the bands past their
                    // tuned ceilings.
                    let value = json_u64(key, val)?;
                    if value > FAULT_SCALE_FULL {
                        return Err(CliError(format!(
                            "campaign spec \"fault_scale_permille\" must be in [0, {FAULT_SCALE_FULL}] \
                             (1000 = the default bands); got {value}"
                        )));
                    }
                    self.fault_scale_permille = value;
                }
                "dns_entry" => {
                    let array = val
                        .as_array()
                        .ok_or_else(|| CliError("dns_entry must be a JSON array".into()))?;
                    self.dns_entries = array
                        .iter()
                        .map(|v| {
                            let entry = v.as_str().ok_or_else(|| {
                                CliError("dns_entry entries must be strings".into())
                            })?;
                            // A spec file bypasses the CLI value grammar, so run
                            // the same validator here: a malformed table must fail
                            // at parse time, not as an opaque child-run refusal in
                            // every generation.
                            crate::values::dns_entry("dns_entry", entry)
                                .map_err(|error| CliError(format!("campaign spec {error}")))?;
                            Ok(entry.to_string())
                        })
                        .collect::<Result<_, CliError>>()?;
                }
                "allow_randomized_address_layout" => {
                    self.address_layout = Some(if json_bool(key, val)? {
                        patina_dst_trace::AddressLayout::Randomized
                    } else {
                        patina_dst_trace::AddressLayout::Fixed
                    });
                }
                "cpus" => {
                    let cpus = json_u64(key, val)?;
                    // A spec file bypasses the CLI value grammar; hold it to the
                    // same one so a bad count fails here rather than in every
                    // generation's child run.
                    crate::values::validate(help::Kind::Cpus, "cpus", &cpus.to_string())
                        .map_err(|error| CliError(format!("campaign spec {error}")))?;
                    self.cpus = Some(cpus as u32);
                }
                // A spec file names a directory; a campaign's recorded state
                // carries the directory and the corpus hash it started from.
                "mount" => {
                    self.mount = Some(match val {
                        serde_json::Value::String(value) => Mount::unresolved(value)?,
                        serde_json::Value::Object(recorded) => {
                            let field = |name: &str| {
                                recorded.get(name).and_then(|v| v.as_str()).ok_or_else(|| {
                                    CliError(format!("mount.{name} must be a string"))
                                })
                            };
                            let hash = field("hash")?;
                            if hash.is_empty() {
                                return Err(CliError("mount.hash must not be empty".into()));
                            }
                            // Omitted for a mount at `/`.
                            let guest = match recorded.get("guest") {
                                None => "/",
                                Some(_) => field("guest")?,
                            };
                            let parsed = Mount::unresolved(&format!("x:{guest}"))
                                .ok()
                                .filter(|parsed| parsed.guest == guest)
                                .ok_or_else(|| {
                                    CliError(format!(
                                        "mount.guest {guest:?} is not a normal absolute directory"
                                    ))
                                })?;
                            Mount {
                                dir: field("dir")?.to_string(),
                                guest: parsed.guest,
                                hash: hash.to_string(),
                            }
                        }
                        _ => return Err(CliError("mount must be a directory path".into())),
                    });
                }
                "allow" => {
                    let array = val
                        .as_array()
                        .ok_or_else(|| CliError("allow must be a JSON array".into()))?;
                    self.allow_symbols = array
                        .iter()
                        .map(|v| {
                            let symbol = v
                                .as_str()
                                .ok_or_else(|| CliError("allow entries must be strings".into()))?;
                            // A spec file bypasses the CLI value grammar; hold it to
                            // the same one so an empty symbol fails here rather than
                            // as an opaque child-run refusal in every generation.
                            crate::values::validate(help::Kind::Symbol, "allow", symbol)
                                .map_err(|error| CliError(format!("campaign spec {error}")))?;
                            Ok(symbol.to_string())
                        })
                        .collect::<Result<_, CliError>>()?;
                }
                "compute_watchdog_ms" => {
                    let bound = json_u64(key, val)?;
                    crate::values::validate(
                        help::Kind::WatchdogMillis,
                        "compute_watchdog_ms",
                        &bound.to_string(),
                    )
                    .map_err(CliError)?;
                    self.compute_watchdog_ms = Some(bound);
                }
                "liveness_watchdog" => self.watchdog_nanos = Some(json_u64(key, val)?),
                "converge_within" => self.converge_nanos = Some(json_u64(key, val)?),
                "heal_after" => self.heal_after_nanos = Some(json_u64(key, val)?),
                "plateau_after" => self.plateau_after = json_u64(key, val)?,
                "guided" => self.guided = json_bool(key, val)?,
                "allow_unmet_sometimes" => self.allow_unmet_sometimes = json_bool(key, val)?,
                "classify" => self.classify = json_classify_rules(val)?,
                "no_verify" => self.verify = !json_bool(key, val)?,
                other => {
                    return Err(CliError(format!(
                        "unknown campaign spec key {other:?}; a key is its campaign flag's name \
                         (gens, seed_start, timeout_secs, swarm, vary, fault_scale_permille, \
                         dns_entry, allow, allow_randomized_address_layout, cpus, mount, \
                         liveness_watchdog, compute_watchdog_ms, converge_within, heal_after, \
                         plateau_after, guided, allow_unmet_sometimes, no_verify), or guest_args, \
                         exclude_knobs or classify"
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

/// `"vary"`: an array of `--vary` dimensions.
fn json_vary(key: &str, value: &serde_json::Value) -> Result<Vary, CliError> {
    let malformed = || {
        CliError(format!(
            "campaign spec {key:?} must be an array of --vary dimensions ({})",
            VARY_NAMES.join(", ")
        ))
    };
    let names = value
        .as_array()
        .ok_or_else(malformed)?
        .iter()
        .map(|name| name.as_str().ok_or_else(malformed))
        .collect::<Result<Vec<_>, _>>()?;
    Vary::from_names(names).map_err(|error| CliError(format!("campaign spec {key:?}: {error}")))
}

/// `"exclude_knobs"`: an array of `run` flags, each a knob some `--vary`
/// plane draws. Whether the campaign selects that plane is checked once the
/// spec and the flags are merged (`parse.rs`).
fn json_exclude_knobs(
    key: &str,
    value: &serde_json::Value,
) -> Result<BTreeSet<FaultKnob>, CliError> {
    let excludable = || {
        FaultKnob::ALL
            .iter()
            .filter(|knob| super::excludable(**knob))
            .map(|knob| knob.meta().flag)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let entries = value.as_array().ok_or_else(|| {
        CliError(format!(
            "campaign spec {key:?} must be an array of fault knob flags ({})",
            excludable()
        ))
    })?;
    entries
        .iter()
        .map(|entry| {
            let name = entry.as_str().unwrap_or_default();
            FaultKnob::ALL
                .iter()
                .copied()
                .find(|knob| knob.meta().flag == name && super::excludable(*knob))
                .ok_or_else(|| {
                    CliError(format!(
                        "campaign spec {key:?} names {entry}, which is not a knob a --vary plane draws; \
                         expected one or more of {}",
                        excludable()
                    ))
                })
        })
        .collect()
}

fn json_bool(key: &str, value: &serde_json::Value) -> Result<bool, CliError> {
    value
        .as_bool()
        .ok_or_else(|| CliError(format!("campaign spec {key:?} must be a boolean")))
}

/// Parse the spec's `classify` object into [`ClassifyRules`].
///
/// Grammar-validated and loud: an unknown class token, a class that could only
/// downgrade a finding (`OK`), an empty rule list, or an empty pattern is a spec
/// error, not a silently inert rule. A rule that cannot fire is exactly the
/// vacuous check this project treats as a bug.
pub(super) fn json_classify_rules(value: &serde_json::Value) -> Result<ClassifyRules, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError("campaign spec \"classify\" must be a JSON object".into()))?;
    let mut rules = ClassifyRules::default();
    for (key, val) in object {
        match key.as_str() {
            "patterns" => {
                for (class, entries) in classify_rule_map(key, val)? {
                    let needles = entries
                        .iter()
                        .map(|entry| {
                            let needle = entry.as_str().ok_or_else(|| {
                                CliError(format!(
                                    "campaign spec \"classify.patterns\" entries for {:?} must be strings",
                                    class.as_str()
                                ))
                            })?;
                            if needle.is_empty() {
                                return Err(CliError(format!(
                                    "campaign spec \"classify.patterns\" entry for {:?} is empty; an empty substring matches every generation",
                                    class.as_str()
                                )));
                            }
                            Ok(needle.to_string())
                        })
                        .collect::<Result<Vec<_>, CliError>>()?;
                    rules.patterns.insert(class, needles);
                }
            }
            "exit_codes" => {
                for (class, entries) in classify_rule_map(key, val)? {
                    let codes = entries
                        .iter()
                        .map(|entry| {
                            entry
                                .as_i64()
                                .map(|code| code as i32)
                                .ok_or_else(|| CliError(format!(
                                    "campaign spec \"classify.exit_codes\" entries for {:?} must be integers",
                                    class.as_str()
                                )))
                        })
                        .collect::<Result<Vec<_>, CliError>>()?;
                    rules.exit_codes.insert(class, codes);
                }
            }
            other => {
                return Err(CliError(format!(
                    "unknown campaign spec \"classify\" key {other:?}; expected patterns or exit_codes"
                )));
            }
        }
    }
    Ok(rules)
}

/// Validate one `classify.<kind>` object: a map of campaign class token to a
/// non-empty array of rules.
fn classify_rule_map(
    kind: &str,
    value: &serde_json::Value,
) -> Result<Vec<(RunClass, Vec<serde_json::Value>)>, CliError> {
    let object = value.as_object().ok_or_else(|| {
        CliError(format!(
            "campaign spec \"classify.{kind}\" must be a JSON object of class -> rules"
        ))
    })?;
    let mut rules = Vec::new();
    for (name, entries) in object {
        let class = RunClass::from_name(name).ok_or_else(|| {
            CliError(format!(
                "campaign spec \"classify.{kind}\" names unknown class {name:?}; expected one of {}",
                RunClass::ALL
                    .iter()
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        if class == RunClass::Ok {
            return Err(CliError(format!(
                "campaign spec \"classify.{kind}\" declares {:?}; declared rules may only ADD a finding, never downgrade one",
                class.as_str()
            )));
        }
        if !class.is_finding() {
            return Err(CliError(format!(
                "campaign spec \"classify.{kind}\" declares {:?}; a declared rule names a finding in the guest ({}), never an outcome that is patina's or the request's",
                class.as_str(),
                RunClass::ALL
                    .iter()
                    .filter(|class| class.is_finding())
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let entries = entries.as_array().ok_or_else(|| {
            CliError(format!(
                "campaign spec \"classify.{kind}\" rules for {:?} must be a JSON array",
                class.as_str()
            ))
        })?;
        if entries.is_empty() {
            return Err(CliError(format!(
                "campaign spec \"classify.{kind}\" rules for {:?} are empty; a rule that cannot fire is a defect, not a default",
                class.as_str()
            )));
        }
        rules.push((class, entries.clone()));
    }
    Ok(rules)
}

/// Serialize [`ClassifyRules`] back to the spec's canonical JSON form.
pub(super) fn classify_rules_to_json(rules: &ClassifyRules) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if !rules.patterns.is_empty() {
        let mut patterns = serde_json::Map::new();
        for (class, needles) in &rules.patterns {
            patterns.insert(class.as_str().to_string(), needles.clone().into());
        }
        map.insert("patterns".into(), serde_json::Value::Object(patterns));
    }
    if !rules.exit_codes.is_empty() {
        let mut codes = serde_json::Map::new();
        for (class, values) in &rules.exit_codes {
            codes.insert(class.as_str().to_string(), values.clone().into());
        }
        map.insert("exit_codes".into(), serde_json::Value::Object(codes));
    }
    serde_json::Value::Object(map)
}

/// A campaign's mounted corpus: the absolute directory every generation and
/// reproduce command names, the guest directory it is captured at (`/` unless
/// `--mount HOST_DIR:GUEST_DIR` named one), and the corpus hash the campaign
/// started from, so a continuation against a corpus that changed is refused
/// rather than mixing two inputs in one campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub dir: String,
    pub guest: String,
    pub hash: String,
}

impl Mount {
    /// A `--mount` value as the operator wrote it, before a fresh campaign
    /// resolves it ([`resolve_mount`]): parsing touches no filesystem.
    pub(crate) fn unresolved(value: &str) -> Result<Self, CliError> {
        let mount = crate::mount::Mount::parse(std::ffi::OsStr::new(value))?;
        Ok(Mount {
            dir: mount.host.to_str().expect("split from UTF-8").to_string(),
            guest: mount.guest,
            hash: String::new(),
        })
    }

    /// The mount a generation's `run` is given.
    pub(crate) fn run_mount(&self) -> crate::mount::Mount {
        crate::mount::Mount {
            host: self.dir.clone().into(),
            guest: self.guest.clone(),
        }
    }

    /// The `--mount` value every child run and reproduce command takes.
    pub(crate) fn arg(&self) -> String {
        self.run_mount()
            .to_arg()
            .into_string()
            .expect("a campaign mount is UTF-8")
    }
}

/// Resolve a fresh campaign's `--mount` to its absolute directory and corpus
/// hash, refusing one that is not a directory before any generation runs.
pub(crate) fn resolve_mount(spec: &mut CampaignSpec) -> Result<(), CliError> {
    if let Some(mount) = &spec.mount {
        spec.mount = Some(absolute_mount(mount)?);
    }
    Ok(())
}

/// A `--mount` as an absolute [`Mount`] with its corpus hash: a relative path
/// would resolve against whichever directory a later continuation or pasted
/// reproduce command runs from.
pub(crate) fn absolute_mount(mount: &Mount) -> Result<Mount, CliError> {
    let dir = &mount.dir;
    let path = std::path::Path::new(dir);
    if !path.is_dir() {
        return Err(CliError(format!(
            "campaign --mount {dir:?} is not a directory"
        )));
    }
    let absolute = std::fs::canonicalize(path)
        .map_err(|error| CliError(format!("campaign --mount {dir:?}: {error}")))?;
    let dir = absolute
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| CliError(format!("campaign --mount {dir:?} is not a UTF-8 path")))?;
    let mut resolved = Mount {
        dir,
        guest: mount.guest.clone(),
        hash: String::new(),
    };
    resolved.hash = crate::native_run::mount_corpus_hash(&resolved.run_mount())?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::super::observe::campaign_coverage_fingerprint;
    use super::super::state::{spec_from_state_json, spec_to_json};
    use super::*;

    /// Every opt-in part of a spec rides the recorded spec, so a continuation
    /// continues the campaign the fresh run started, and is
    /// default-omitted from the JSON.
    #[test]
    fn opt_in_spec_fields_round_trip_and_are_omitted_by_default() {
        let mut classified = CampaignSpec::default();
        classified
            .apply_json(&serde_json::json!({
                "classify": {"patterns": {"violation": ["CORRUPTION"]}}
            }))
            .unwrap();
        let specs = [
            CampaignSpec {
                vary: Vary::from_names(["sched-pct"]).unwrap(),
                ..CampaignSpec::default()
            },
            classified,
            CampaignSpec {
                verify: false,
                ..CampaignSpec::default()
            },
            CampaignSpec {
                vary: Vary::from_names(["faults"]).unwrap(),
                dns_entries: vec!["db.internal=10.0.0.5".into(), "cache=10.0.0.6".into()],
                ..CampaignSpec::default()
            },
            CampaignSpec {
                vary: Vary::from_names(["net", "sleep"]).unwrap(),
                ..CampaignSpec::default()
            },
            CampaignSpec {
                vary: Vary::from_names(["net"]).unwrap(),
                exclude_knobs: [FaultKnob::NetResetPermille, FaultKnob::NetDropPermille].into(),
                ..CampaignSpec::default()
            },
            CampaignSpec {
                vary: Vary::from_names(["crash"]).unwrap(),
                exclude_knobs: [FaultKnob::ProcessCrashPermille].into(),
                ..CampaignSpec::default()
            },
            CampaignSpec {
                allow_symbols: vec!["dlsym".into(), "semaphore_wait".into()],
                address_layout: Some(patina_dst_trace::AddressLayout::Randomized),
                ..CampaignSpec::default()
            },
        ];
        for spec in specs {
            assert_eq!(spec_from_state_json(&spec_to_json(&spec)).unwrap(), spec);
        }
        let bare = spec_to_json(&CampaignSpec::default());
        for key in [
            "classify",
            "no_verify",
            "dns_entry",
            "allow",
            "allow_randomized_address_layout",
            "exclude_knobs",
        ] {
            assert!(bare.get(key).is_none(), "a bare spec must not record {key}");
        }
        // Every plane records as `faults`, whichever way it was named.
        let mut every = bare.clone();
        every["vary"] = serde_json::json!(["faults"]);
        assert_eq!(
            spec_from_state_json(&every).unwrap().vary,
            Vary::from_names(super::super::FaultPlane::ALL.map(super::super::FaultPlane::name))
                .unwrap()
        );
        // The exploration policy is part of the coverage store's compatibility
        // fingerprint, so a PCT campaign never pools coverage with a non-PCT
        // one.
        let exploring = CampaignSpec {
            vary: Vary::from_names(["sched-pct"]).unwrap(),
            ..CampaignSpec::default()
        };
        let instrumented = crate::Instrumentation {
            edge_counters: true,
            yield_hook: true,
        };
        assert_ne!(
            campaign_coverage_fingerprint(&exploring, instrumented),
            campaign_coverage_fingerprint(&CampaignSpec::default(), instrumented)
        );
    }

    /// A spec file bypasses the CLI value grammar, so `apply_json` holds it to
    /// the same grammar and refuses unknown keys, while known keys apply.
    #[test]
    fn a_spec_file_is_grammar_validated() {
        for source in [
            r#"{"bogus": 1}"#,
            r#"{"dns_entry": ["db.internal=nope"]}"#,
            r#"{"allow": [""]}"#,
            r#"{"allow_randomized_address_layout": "randomized"}"#,
            // The keys before they were named after their flags.
            r#"{"generations": 1}"#,
            r#"{"seed_base": 1}"#,
            r#"{"allow_unsupported_symbols": ""}"#,
            r#"{"fs_crash_reach": ["write:3"]}"#,
            r#"{"exclude_knobs": ["--net-bogus-permille"]}"#,
            r#"{"exclude_knobs": ["net-reset-permille"]}"#,
            r#"{"exclude_knobs": "--net-reset-permille"}"#,
            r#"{"exclude_knobs": [7]}"#,
            r#"{"vary": ["bogus"]}"#,
            r#"{"vary": "buggify"}"#,
            r#"{"faults": true}"#,
            // Real knobs that no `--vary` plane draws exclude nothing.
            r#"{"exclude_knobs": ["--net-partition"]}"#,
        ] {
            let json: serde_json::Value = serde_json::from_str(source).unwrap();
            assert!(
                CampaignSpec::default().apply_json(&json).is_err(),
                "{source} must be refused"
            );
        }
        let mut spec = CampaignSpec::default();
        spec.apply_json(&serde_json::json!({
            "gens": 12,
            "vary": ["buggify", "net"],
            "exclude_knobs": ["--net-connect-refuse-permille"],
        }))
        .unwrap();
        assert_eq!(spec.generations, 12);
        assert!(spec.vary.buggify);
        assert_eq!(
            spec.exclude_knobs.into_iter().collect::<Vec<_>>(),
            [FaultKnob::NetConnectRefusePermille]
        );
    }
}
