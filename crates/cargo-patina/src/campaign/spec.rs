//! Campaign specification defaults and JSON grammar.

use super::{CampaignClass, ClassifyRules, FAULT_SCALE_FULL, STARVE_SCALE_FULL};
use crate::{CliError, help};

pub(super) const DEFAULT_PLATEAU_AFTER: u64 = 200;

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
    /// Randomize cooperative-SUT (buggify) activation/fire per generation.
    pub buggify: bool,
    /// Apply seed-derived swarm fault-class selection (native only).
    pub swarm: bool,
    /// Randomize a PCT bug depth per generation (native only).
    pub pct: bool,
    /// Randomize a bounded starvation-interval policy per generation (native
    /// only): how many intervals, how deep into the schedule they may start, and
    /// how long they may last.
    ///
    /// WHY IT IS ITS OWN SWITCH. Starvation is the one exploration policy that
    /// deliberately holds a RUNNABLE task off, which is what several liveness and
    /// lost-wakeup bugs need and what a uniform-random scheduler will not produce
    /// at any seed count. It is also the one policy that can WEDGE a guest whose
    /// synchronization is invisible to the scheduler (an atomics-only spinlock
    /// held across a boundary), so it must be asked for rather than inherited —
    /// the same reason `run` refuses to turn it on implicitly. The supervisor's
    /// stall backstop turns a wedge into a classified `STARVATION_STALL` rather
    /// than a hung campaign.
    pub starve: bool,
    /// Scale (per-mille) applied to the seed-drawn starvation policy under
    /// [`Self::starve`]: `1000` (the default) leaves the sweep exactly as it has
    /// always been; `100` makes a generation starve a tenth as often, with a
    /// tenth as many holds and a tenth the hold length when it does.
    ///
    /// WHY A DIAL AT ALL. Measured over turso's `turso_stress` at 10,000
    /// iterations, four campaigns came out 8 of 15, 1 of 11, 4 of 12 and 5 of 14
    /// generations OK — 60 to 80 per cent of the budget spent on runs the stall
    /// backstop killed before the workload finished. A wedged generation never
    /// reaches the checkpoint and recovery sequences the campaign exists to
    /// exercise, so it is not a harsh sample of the guest, it is no sample at
    /// all. Exactly the shape `--faults` had before
    /// [`Self::fault_scale_permille`]: the aggressive policy is a legitimate
    /// option, and it was wrong only as the ONLY option.
    ///
    /// WHICH AXES SCALE, AND IN WHICH DIRECTION. This is the interesting half,
    /// because the policy's three fields do not all point the same way:
    ///
    /// * HOW OFTEN A GENERATION STARVES AT ALL scales, through
    ///   [`starve_band_fires`], on its own claimed band byte so the decision is
    ///   independent of the policy's shape. It is
    ///   the dominant lever and the honest one: a generation that does not starve
    ///   is still a full sample of the guest under every other knob the campaign
    ///   is sweeping, which is more than a wedged one gives.
    /// * THE INTERVAL COUNT scales DOWN — 8 holds at full scale, 1 at a tenth.
    ///   More holds is unambiguously harsher, so a plain dampen is the right way
    ///   round.
    /// * THE MAXIMUM HOLD LENGTH scales DOWN, floored at one decision. Longer
    ///   holds are harsher, and this is also the scheduler's AGING CAP, so it is
    ///   literally the bound on how long a task can be held off. The floor is not
    ///   cosmetic: `--starve-max-len` is a positive integer, and a zero-length
    ///   hold is not a gentler hold, it is no hold — which is the gate's job to
    ///   express, not this axis's.
    /// * THE START WINDOW IS DELIBERATELY NOT SCALED, and this is the axis a
    ///   naive uniform multiply gets wrong. It is a PLACEMENT axis — WHERE the
    ///   holds land — and which end of it is harsh is a property of the guest,
    ///   not of the dial. Measured on `turso_stress`: at 512 every hold lands in
    ///   the startup prefix, the policy defers nothing at all
    ///   (`starve_events=0`) and the run completes in 26 s; at 65536 the same
    ///   shaped holds land in the concurrent phase and the run never finishes.
    ///   The small end was the GENTLE one there, the opposite of the reading that
    ///   "less is less". For a short guest it inverts again: a large window puts
    ///   starts past the end of the schedule, so the plane goes silently INERT
    ///   rather than rare. Scaling it either way is right for one guest and wrong
    ///   for the other, so it keeps its full log sweep and a dampened campaign
    ///   still explores where a hold lands — the same call
    ///   `--net-tcp-buffer-bytes` got from the fault dial, for a sharper reason.
    ///   Pinned by `the_starve_scale_leaves_the_placement_window_alone`.
    pub starve_scale_permille: u64,
    /// Randomize fault knobs (net drop, sleep jitter) per generation.
    pub faults: bool,
    /// Band the custom-op failure knob (`--custom-op-fail-permille`) under
    /// [`Self::faults`].
    ///
    /// Opt-in for the same reason the DNS band rides on [`Self::dns_entries`]:
    /// a custom operation is fault-eligible only if the GUEST declared a failure
    /// shape for it, so over a guest that declared none the knob provably cannot
    /// fire and every generation would report a vacuous custom-op plane. Whether
    /// the guest declares one is a fact about the guest, which only the operator
    /// can tell the campaign.
    pub custom_op_faults: bool,
    /// Scale (per-mille) applied to every seed-drawn fault INTENSITY under
    /// [`Self::faults`]: `1000` (the default) leaves the exploration bands exactly
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
    /// `--buggify`/`--sched-pct`/`--swarm` configure exploration of the guest's own
    /// cooperative sites rather than injecting an environment fault. Crash/torn
    /// generation is currently suspended altogether because campaign record/replay
    /// cannot yet represent native crash restart lifecycle.
    pub fault_scale_permille: u64,
    /// The DNS host table (`NAME=ADDR` entries) every generation runs with.
    ///
    /// Part of the campaign's shape rather than a per-generation draw: the names
    /// a guest resolves are its workload, not a fault. It is what makes the
    /// `--faults` DNS band non-inert — with no defined name, a guest's lookups
    /// are all NXDOMAIN by semantics and no DNS fault is ever eligible — so the
    /// band is only emitted when this is non-empty.
    pub dns_entries: Vec<String>,
    /// Sweep a `patina-dst-harness` binary: every generation's child `run` gets
    /// `--harness`, so the guest installs and configures the runtime itself.
    ///
    /// Invocation shape rather than a per-generation draw, and — like
    /// [`Self::allow_symbols`] and [`Self::allow_unsupported_symbols`] — a fact the
    /// trace cannot carry, so the reproduce commands re-supply it too. Native only:
    /// there is no WASI harness family.
    pub harness: bool,
    /// Symbols added to every generation's pre-run gate allow list (`--allow`).
    pub allow_symbols: Vec<String>,
    /// The `--allow-unsupported-symbols` policy (`all` or a symbol list) every
    /// generation runs under.
    pub allow_unsupported_symbols: Option<String>,
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
    /// Also write a wave-14 `--report` HTML for each failing generation.
    pub report: bool,
    /// Report native edge-coverage plateau after this many generations without a
    /// new edge; 0 disables the plateau flag.
    pub plateau_after: u64,
    /// Bias generation derivation toward previously productive configurations
    /// (coverage-depth arc, wave E). Changes the generation stream, so it is part
    /// of the persisted spec and cannot be toggled on a continuation.
    pub guided: bool,
    /// Waive the default campaign-level gate for `sometimes!` sites that were
    /// registered but never satisfied.
    pub allow_unmet_sometimes: Option<AllowUnmetSometimes>,
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
            buggify: false,
            swarm: false,
            pct: false,
            starve: false,
            starve_scale_permille: STARVE_SCALE_FULL,
            faults: false,
            custom_op_faults: false,
            fault_scale_permille: FAULT_SCALE_FULL,
            dns_entries: Vec::new(),
            harness: false,
            allow_symbols: Vec::new(),
            allow_unsupported_symbols: None,
            watchdog_nanos: None,
            compute_watchdog_ms: None,
            converge_nanos: None,
            heal_after_nanos: None,
            report: false,
            plateau_after: DEFAULT_PLATEAU_AFTER,
            guided: false,
            allow_unmet_sometimes: None,
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
                "starve" => self.starve = json_bool(key, val)?,
                "starve_scale_permille" => {
                    // A spec file bypasses the CLI value grammar, so hold it to
                    // the same `[0, 1000]` bound here rather than letting an
                    // out-of-range scale amplify the policy past its tuned
                    // ceilings.
                    let value = json_u64(key, val)?;
                    if value > STARVE_SCALE_FULL {
                        return Err(CliError(format!(
                            "campaign spec \"starve_scale_permille\" must be in [0, {STARVE_SCALE_FULL}] \
                             (1000 = the default policy bands); got {value}"
                        )));
                    }
                    self.starve_scale_permille = value;
                }
                "faults" => self.faults = json_bool(key, val)?,
                "custom_op_faults" => self.custom_op_faults = json_bool(key, val)?,
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
                "dns_entries" => {
                    let array = val
                        .as_array()
                        .ok_or_else(|| CliError("dns_entries must be a JSON array".into()))?;
                    self.dns_entries = array
                        .iter()
                        .map(|v| {
                            let entry = v.as_str().ok_or_else(|| {
                                CliError("dns_entries entries must be strings".into())
                            })?;
                            // A spec file bypasses the CLI value grammar, so run
                            // the same validator here: a malformed table must fail
                            // at parse time, not as an opaque child-run refusal in
                            // every generation.
                            crate::values::dns_entry("dns_entries", entry)
                                .map_err(|error| CliError(format!("campaign spec {error}")))?;
                            Ok(entry.to_string())
                        })
                        .collect::<Result<_, CliError>>()?;
                }
                "harness" => self.harness = json_bool(key, val)?,
                "allow_symbols" => {
                    let array = val
                        .as_array()
                        .ok_or_else(|| CliError("allow_symbols must be a JSON array".into()))?;
                    self.allow_symbols = array
                        .iter()
                        .map(|v| {
                            let symbol = v.as_str().ok_or_else(|| {
                                CliError("allow_symbols entries must be strings".into())
                            })?;
                            // A spec file bypasses the CLI value grammar; hold it to
                            // the same one so an empty symbol fails here rather than
                            // as an opaque child-run refusal in every generation.
                            crate::values::validate(help::Kind::Symbol, "allow_symbols", symbol)
                                .map_err(|error| CliError(format!("campaign spec {error}")))?;
                            Ok(symbol.to_string())
                        })
                        .collect::<Result<_, CliError>>()?;
                }
                "allow_unsupported_symbols" => {
                    let value = val.as_str().ok_or_else(|| {
                        CliError("allow_unsupported_symbols must be a string".into())
                    })?;
                    crate::values::validate(
                        help::Kind::UnsupportedSymbols,
                        "allow_unsupported_symbols",
                        value,
                    )
                    .map_err(|error| CliError(format!("campaign spec {error}")))?;
                    self.allow_unsupported_symbols = Some(value.to_string());
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
                "watchdog_nanos" => self.watchdog_nanos = Some(json_u64(key, val)?),
                "converge_nanos" => self.converge_nanos = Some(json_u64(key, val)?),
                "heal_after_nanos" => self.heal_after_nanos = Some(json_u64(key, val)?),
                "report" => self.report = json_bool(key, val)?,
                "plateau_after" => self.plateau_after = json_u64(key, val)?,
                "guided" => self.guided = json_bool(key, val)?,
                "allow_unmet_sometimes" => {
                    self.allow_unmet_sometimes = Some(json_allow_unmet_sometimes(key, val)?)
                }
                "classify" => self.classify = json_classify_rules(val)?,
                other => {
                    return Err(CliError(format!(
                        "unknown campaign spec key {other:?}; expected generations, seed_base, \
                         timeout_secs, guest_args, buggify, swarm, pct, faults, custom_op_faults, \
                         fault_scale_permille, starve, starve_scale_permille, dns_entries, \
                         harness, allow_symbols, allow_unsupported_symbols, watchdog_nanos, \
                         compute_watchdog_ms, converge_nanos, heal_after_nanos, report, plateau_after, guided, \
                         allow_unmet_sometimes, or classify"
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
) -> Result<Vec<(CampaignClass, Vec<serde_json::Value>)>, CliError> {
    let object = value.as_object().ok_or_else(|| {
        CliError(format!(
            "campaign spec \"classify.{kind}\" must be a JSON object of class -> rules"
        ))
    })?;
    let mut rules = Vec::new();
    for (name, entries) in object {
        let class = CampaignClass::parse(name).ok_or_else(|| {
            CliError(format!(
                "campaign spec \"classify.{kind}\" names unknown class {name:?}; expected one of {}",
                CampaignClass::ALL
                    .iter()
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        if class == CampaignClass::Ok {
            return Err(CliError(format!(
                "campaign spec \"classify.{kind}\" declares {:?}; declared rules may only ADD a finding, never downgrade one",
                class.as_str()
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

#[cfg(test)]
mod tests {
    use super::super::observe::campaign_coverage_fingerprint;
    use super::super::state::{spec_from_state_json, spec_to_json};
    use super::*;

    /// Starvation rides the recorded spec (so `--resume` sweeps the same policy)
    /// and is default-omitted from the JSON, so an out-dir written before the key
    /// existed still passes the canonical-form check.
    #[test]
    fn starvation_round_trips_through_the_recorded_spec() {
        let mut spec = CampaignSpec::default();
        spec.apply_json(&serde_json::json!({"starve": true}))
            .unwrap();
        assert!(spec.starve);
        let json = spec_to_json(&spec);
        assert_eq!(json["starve"], serde_json::json!(true));
        assert_eq!(spec_from_state_json(&json).unwrap(), spec);
        assert!(
            spec_to_json(&CampaignSpec::default())
                .get("starve")
                .is_none()
        );
        // The exploration policy is part of the coverage store's compatibility
        // fingerprint, so a starvation campaign never pools coverage with a
        // non-starvation one.
        assert_ne!(
            campaign_coverage_fingerprint(&spec, crate::GuestInstrumentation::YieldPoints),
            campaign_coverage_fingerprint(
                &CampaignSpec::default(),
                crate::GuestInstrumentation::YieldPoints
            )
        );
    }

    /// Declared rules ride the recorded spec, so a `--resume` reclassifies with
    /// the same rules the fresh campaign used.
    #[test]
    fn declared_rules_round_trip_through_the_recorded_spec() {
        let mut spec = CampaignSpec::default();
        spec.apply_json(&serde_json::json!({
            "classify": {"patterns": {"VIOLATION": ["CORRUPTION"]}}
        }))
        .unwrap();
        let json = spec_to_json(&spec);
        assert_eq!(
            json["classify"],
            serde_json::json!({"patterns": {"VIOLATION": ["CORRUPTION"]}})
        );
        assert_eq!(spec_from_state_json(&json).unwrap(), spec);
        // Default-omit: a spec with no declared rules records no key at all.
        assert!(
            spec_to_json(&CampaignSpec::default())
                .get("classify")
                .is_none()
        );
    }

    #[test]
    fn a_dns_host_table_round_trips_through_the_recorded_spec() {
        let spec = CampaignSpec {
            faults: true,
            dns_entries: vec!["db.internal=10.0.0.5".into(), "cache=10.0.0.6".into()],
            ..CampaignSpec::default()
        };
        let json = spec_to_json(&spec);
        assert_eq!(spec_from_state_json(&json).unwrap(), spec);
        // A DNS-free spec records no key at all, so an out-dir written before the
        // key existed still resumes.
        let bare = CampaignSpec::default();
        assert!(
            spec_to_json(&bare).get("dns_entries").is_none(),
            "a table-free spec must not record the key"
        );
        // A spec file bypasses the CLI value grammar, so it is validated here.
        let mut malformed = CampaignSpec::default();
        let json: serde_json::Value =
            serde_json::from_str(r#"{"dns_entries": ["db.internal=nope"]}"#).unwrap();
        let error = malformed.apply_json(&json).unwrap_err();
        assert!(
            error.to_string().contains("dotted-quad"),
            "expected a loud grammar error, got {error}"
        );
    }

    #[test]
    fn the_native_invocation_surface_round_trips_through_the_recorded_spec() {
        let spec = CampaignSpec {
            harness: true,
            allow_symbols: vec!["dlsym".into()],
            allow_unsupported_symbols: Some("semaphore_wait,semaphore_signal".into()),
            ..CampaignSpec::default()
        };
        let json = spec_to_json(&spec);
        assert_eq!(spec_from_state_json(&json).unwrap(), spec);
        // A campaign that forwards none of it records no key at all, so an out-dir
        // written before the keys existed still resumes.
        let bare = spec_to_json(&CampaignSpec::default());
        for key in ["harness", "allow_symbols", "allow_unsupported_symbols"] {
            assert!(bare.get(key).is_none(), "a bare spec must not record {key}");
        }
        // A spec file bypasses the CLI value grammar, so it is validated here.
        for (source, expected) in [
            (r#"{"allow_symbols": [""]}"#, "must not be empty"),
            (
                r#"{"allow_unsupported_symbols": ""}"#,
                "requires `all` or a comma-separated symbol list",
            ),
        ] {
            let json: serde_json::Value = serde_json::from_str(source).unwrap();
            let error = CampaignSpec::default().apply_json(&json).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "expected a loud grammar error for {source}, got {error}"
            );
        }
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
