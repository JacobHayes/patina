//! Cooperative fault sites, verdicts, and application oracles.

use crate::config::BuggifyConfig;
use crate::{Context, FINGERPRINT_BUGGIFY, RuntimeError, VerdictKind};
use patina_dst_abi::{ClockKind, Operation, Outcome, verdict_line};
use patina_dst_rng_seeded::SplitMix64;
use std::collections::BTreeMap;

/// Domain separators for the buggify PRF, so activation, firing, knob, and delay
/// draws for one site never correlate.
mod buggify_domain {
    pub const ACTIVATION: u64 = 0x4143_5449_5641_5445; // "ACTIVATE"
    pub const FIRING: u64 = 0x4649_5249_4e47_5f5f; // "FIRING__"
    pub const KNOB: u64 = 0x4b4e_4f42_5f5f_5f5f; // "KNOB____"
    pub const DELAY: u64 = 0x4445_4c41_595f_5f5f; // "DELAY___"
    pub const RNG: u64 = 0x524e_475f_5f5f_5f5f; // "RNG_____"
}

/// A deterministic 64-bit hash of a site label, stable across builds, platforms,
/// and Rust versions (unlike `DefaultHasher`) so cross-machine replay agrees.
/// FNV-1a over the UTF-8 bytes.
fn label_hash(label: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in label.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A domain-separated deterministic pseudo-random value from a set of 64-bit
/// inputs, built from the specified SplitMix64 finalizer so it needs no state
/// beyond the inputs and reproduces exactly across processes.
fn buggify_prf(inputs: &[u64]) -> u64 {
    let mut acc = 0xa5a5_a5a5_5a5a_5a5a_u64;
    for &value in inputs {
        acc = SplitMix64::new(acc ^ value).next_u64();
        acc = acc.wrapping_add(value.rotate_left(17));
    }
    SplitMix64::new(acc).next_u64()
}

/// What a registered buggify site is used for. Purely descriptive: it drives the
/// `PATINA_SDK_REPORT` categorization and never the firing decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuggifyKind {
    /// `buggify!` / `buggify_with_prob!` — a probabilistic fault trigger.
    Fault,
    /// `buggify_delay!` — a probabilistic deterministic delay.
    Delay,
    /// `buggify_knob!` — a per-run perturbed value.
    Knob,
    /// `always!` — an invariant whose violation is fatal.
    Always,
    /// `sometimes!` — a coverage oracle (should be true at least once).
    Sometimes,
    /// `reachable!` — a coverage oracle (this site should be reached).
    Reachable,
}

impl BuggifyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BuggifyKind::Fault => "fault",
            BuggifyKind::Delay => "delay",
            BuggifyKind::Knob => "knob",
            BuggifyKind::Always => "always",
            BuggifyKind::Sometimes => "sometimes",
            BuggifyKind::Reachable => "reachable",
        }
    }

    pub const fn from_static_site_kind(value: u8) -> Option<Self> {
        match value {
            1 => Some(BuggifyKind::Fault),
            2 => Some(BuggifyKind::Delay),
            3 => Some(BuggifyKind::Knob),
            4 => Some(BuggifyKind::Always),
            5 => Some(BuggifyKind::Sometimes),
            6 => Some(BuggifyKind::Reachable),
            _ => None,
        }
    }
}

/// The result of evaluating a cooperative-SUT site, for the embedder (the native
/// shim) to act on. The runtime never performs process I/O or aborts itself; it
/// returns the signal and the embedder emits the marker line and aborts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteOutcome {
    /// Proceed normally: the buggify site did not fire, or the oracle was noted.
    Ok,
    /// The buggify site fired — the embedder injects the fault / takes the branch.
    Fire,
    /// An `always!` invariant was violated: the violation has already been
    /// reported through the verdict ABI (a `PATINA_VERDICT … kind=violation`
    /// line), and the embedder aborts the run.
    AlwaysViolation,
    /// The label is reused at a different call site: a fatal duplicate. The
    /// embedder emits the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker and aborts.
    DuplicateLabel,
}

/// One verdict a guest reported through the verdict ABI, in call order.
///
/// `seq` is the run-scoped call index (from 0), so a verdict stream is ordered
/// and countable without timestamps. The record is what the trace's
/// [`Operation::Verdict`] event and the `PATINA_VERDICT` marker line both
/// describe; see [`Context::verdict`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictRecord {
    pub seq: u64,
    pub kind: VerdictKind,
    pub label: String,
    pub detail: String,
}

impl VerdictRecord {
    /// The `PATINA_VERDICT` diagnostic line for this verdict (no trailing
    /// newline). Rendered by the shared ABI codec so the producer here and the
    /// `patina.result/v1` envelope's parser cannot drift.
    pub fn marker_line(&self) -> String {
        verdict_line::render(self.seq, self.kind, &self.label, &self.detail)
    }
}

/// One link-time declared cooperative-SUT site, keyed by its unique explicit
/// label. Declarations come from SDK macro linker sections and do not imply that
/// the site was evaluated in this run.
#[derive(Clone, Debug)]
struct BuggifyDeclaredSite {
    site: String,
    kind: BuggifyKind,
}

/// One registered cooperative-SUT site, keyed by its unique explicit label.
#[derive(Clone, Debug)]
struct BuggifySite {
    /// The `file:line` identity captured by the macro, used only to detect a
    /// duplicate label reused at a different call site.
    site: String,
    kind: BuggifyKind,
    /// Per-run activation decision (fault/delay/knob sites). Pure function of
    /// `(seed, label, activation_permille)`.
    active: bool,
    /// Firing-PRF counter, incremented on every evaluation. Advances identically
    /// on record and replay because the same code runs on both.
    eval_count: u64,
    fire_count: u64,
    reachable: bool,
    sometimes_satisfied: bool,
    always_violated: bool,
    knob: Option<i64>,
}

/// End-of-run cooperative-SUT diagnostics, surfaced in `PATINA_SDK_REPORT` and,
/// via the internal buggify trace record, in the trace metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuggifyDiagnostics {
    pub enabled: bool,
    pub fire_permille: u16,
    pub activation_permille: u16,
    pub cutoff_nanos: u64,
    pub cutoff_reached: bool,
    pub sites_registered: u64,
    pub sites_activated: u64,
    pub total_firings: u64,
    pub cutoff_suppressed: u64,
    pub after_setup: bool,
    pub setup_complete: bool,
    /// Whether swarm selection deselected the `buggify` class this generation.
    /// True only when the run asked for buggify AND the seed's swarm draw dropped
    /// it, so `enabled == false && swarm_deselected == true` reads "requested,
    /// masked out this generation" while `enabled == false && swarm_deselected ==
    /// false` reads "never requested".
    pub swarm_deselected: bool,
    /// Link-time declared SDK sites in label order. These rows describe the full
    /// literal-label site universe and do not imply per-run evaluation.
    pub declared_sites: Vec<BuggifyDeclaredSiteReport>,
    /// Per-site rows in label order: (label, site, kind, active, evals, fires,
    /// reachable, sometimes_satisfied, always_violated, knob).
    pub sites: Vec<BuggifySiteReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuggifyDeclaredSiteReport {
    pub label: String,
    /// The `file:line` identity captured by the SDK macro.
    pub site: String,
    pub kind: BuggifyKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuggifySiteReport {
    pub label: String,
    /// The `file:line` identity captured by the SDK macro / WASI import.
    pub site: String,
    pub kind: BuggifyKind,
    pub active: bool,
    pub evals: u64,
    pub fires: u64,
    pub reachable: bool,
    pub sometimes_satisfied: bool,
    pub always_violated: bool,
    pub knob: Option<i64>,
}

/// The cooperative-SUT (buggify) site registry and deterministic decision
/// engine. All randomness derives from the root seed and the site's explicit
/// label through [`buggify_prf`]; nothing is recorded per-evaluation, so replay
/// re-derives every decision from the seed and the trace's recorded config.
pub(super) struct Buggify {
    config: BuggifyConfig,
    seed: u64,
    /// Lifecycle marker state. Firing is not gated on it (see the crate/module
    /// docs on the causal limitation); it is reported and, for a guest that
    /// places its workload sites after the call, marks the setup boundary.
    setup_complete: bool,
    declared_sites: BTreeMap<String, BuggifyDeclaredSite>,
    sites: BTreeMap<String, BuggifySite>,
    rng: SplitMix64,
    cutoff_suppressed: u64,
    /// Set once the cutoff has been observed passed at a firing check.
    cutoff_reached: bool,
}

impl Buggify {
    pub(super) fn new(config: BuggifyConfig, seed: u64) -> Self {
        Self {
            config,
            seed,
            setup_complete: false,
            declared_sites: BTreeMap::new(),
            sites: BTreeMap::new(),
            rng: SplitMix64::new(buggify_prf(&[seed, buggify_domain::RNG])),
            cutoff_suppressed: 0,
            cutoff_reached: false,
        }
    }

    /// Whether a site's label activates it this run. Pure function of the seed,
    /// the label, and the activation per-mille.
    fn label_is_active(&self, label_hash: u64) -> bool {
        (buggify_prf(&[self.seed, label_hash, buggify_domain::ACTIVATION]) % 1000)
            < u64::from(self.config.activation_permille)
    }

    /// Declare a literal-label site discovered from the SDK's link-time table.
    /// This makes a site visible to reports before it is ever evaluated. It does
    /// not compute activation or firing decisions, so unchanged guests keep the
    /// same replay/fingerprint behavior.
    ///
    /// A label declared at two different call sites (or for two different kinds)
    /// is the same fatal duplicate the evaluation path rejects, returned as
    /// [`SiteOutcome::DuplicateLabel`] so the embedder emits the one named
    /// `PATINA_BUGGIFY_DUPLICATE_LABEL` marker. `Err` is reserved for a malformed
    /// declaration (empty label or missing `file:line`).
    fn declare(
        &mut self,
        label: &str,
        site: &str,
        kind: BuggifyKind,
    ) -> Result<SiteOutcome, String> {
        if label.is_empty() {
            return Err("static SDK site label must not be empty".to_string());
        }
        if site.is_empty() {
            return Err(format!(
                "static SDK site {label:?} must carry a file:line identity"
            ));
        }
        match self.declared_sites.get(label) {
            Some(existing) if existing.site != site || existing.kind != kind => {
                return Ok(SiteOutcome::DuplicateLabel);
            }
            Some(_) => return Ok(SiteOutcome::Ok),
            None => {}
        }
        if let Some(existing) = self.sites.get(label) {
            if existing.site != site || existing.kind != kind {
                return Ok(SiteOutcome::DuplicateLabel);
            }
        }
        self.declared_sites.insert(
            label.to_string(),
            BuggifyDeclaredSite {
                site: site.to_string(),
                kind,
            },
        );
        Ok(SiteOutcome::Ok)
    }

    /// Register (or revisit) a site under `label`, returning its stable label
    /// hash. A label reused at a different call `site` (or for a different SDK
    /// kind) is a fatal duplicate (returned as `Err(existing_site)`). On first
    /// registration the activation decision is computed once and frozen.
    fn register(&mut self, label: &str, site: &str, kind: BuggifyKind) -> Result<u64, String> {
        let hash = label_hash(label);
        if let Some(declared) = self.declared_sites.get(label) {
            if declared.site != site || declared.kind != kind {
                return Err(declared.site.clone());
            }
        }
        match self.sites.get(label) {
            Some(existing) if existing.site != site || existing.kind != kind => {
                return Err(existing.site.clone());
            }
            Some(_) => {}
            None => {
                let active = self.label_is_active(hash);
                self.sites.insert(
                    label.to_string(),
                    BuggifySite {
                        site: site.to_string(),
                        kind,
                        active,
                        eval_count: 0,
                        fire_count: 0,
                        reachable: false,
                        sometimes_satisfied: false,
                        always_violated: false,
                        knob: None,
                    },
                );
            }
        }
        Ok(hash)
    }

    /// The firing decision for an active site at its current evaluation, given a
    /// (possibly overridden) firing per-mille. Increments the evaluation counter
    /// as a side effect so consecutive evaluations use independent draws.
    fn fire_draw(hash: u64, seed: u64, eval_count: u64, fire_permille: u16) -> bool {
        (buggify_prf(&[seed, hash, buggify_domain::FIRING, eval_count]) % 1000)
            < u64::from(fire_permille)
    }

    fn diagnostics(&self, cutoff_reached_now: bool) -> BuggifyDiagnostics {
        let mut declared_sites = Vec::with_capacity(self.declared_sites.len());
        for (label, site) in &self.declared_sites {
            declared_sites.push(BuggifyDeclaredSiteReport {
                label: label.clone(),
                site: site.site.clone(),
                kind: site.kind,
            });
        }
        let mut sites = Vec::with_capacity(self.sites.len());
        let mut activated = 0_u64;
        let mut firings = 0_u64;
        for (label, site) in &self.sites {
            if site.active {
                activated += 1;
            }
            firings += site.fire_count;
            sites.push(BuggifySiteReport {
                label: label.clone(),
                site: site.site.clone(),
                kind: site.kind,
                active: site.active,
                evals: site.eval_count,
                fires: site.fire_count,
                reachable: site.reachable,
                sometimes_satisfied: site.sometimes_satisfied,
                always_violated: site.always_violated,
                knob: site.knob,
            });
        }
        BuggifyDiagnostics {
            enabled: self.config.enabled,
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            cutoff_reached: self.cutoff_reached || cutoff_reached_now,
            sites_registered: self.sites.len() as u64,
            sites_activated: activated,
            total_firings: firings,
            cutoff_suppressed: self.cutoff_suppressed,
            after_setup: self.config.after_setup,
            setup_complete: self.setup_complete,
            // The engine has no view of the swarm draw; `Context::buggify_diagnostics`
            // fills this in from the run's swarm record.
            swarm_deselected: false,
            declared_sites,
            sites,
        }
    }

    /// The realized configuration and per-site picks recorded into the trace
    /// metadata, or `None` when buggify is disabled.
    pub(super) fn to_record(&self) -> Option<patina_dst_trace::BuggifyConfigRecord> {
        if !self.config.enabled {
            return None;
        }
        let active_sites = self
            .sites
            .iter()
            .filter(|(_, site)| site.active)
            .map(|(label, _)| label.clone())
            .collect();
        let knobs = self
            .sites
            .iter()
            .filter_map(|(label, site)| site.knob.map(|value| (label.clone(), value)))
            .collect();
        Some(patina_dst_trace::BuggifyConfigRecord {
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            after_setup: self.config.after_setup,
            active_sites,
            knobs,
        })
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`: a harness bug that must fail loudly, not a
    /// silent no-fault run.
    fn setup_violation(&self) -> bool {
        self.config.enabled && self.config.after_setup && !self.setup_complete
    }

    /// Whether firing is currently armed: always, unless gated behind a
    /// setup-complete the guest has not reached yet.
    fn armed(&self) -> bool {
        !self.config.after_setup || self.setup_complete
    }
}

impl Context {
    /// Whether cooperative-SUT fault injection is enabled this run.
    pub const fn buggify_enabled(&self) -> bool {
        self.buggify.config.enabled
    }

    /// Declare one SDK site discovered from a link-time site table. Declarations
    /// make never-reached sites visible in diagnostics but do not evaluate the
    /// site, compute activation, advance counters, or enter the trace.
    ///
    /// Returns [`SiteOutcome::DuplicateLabel`] when the label is already bound to
    /// a different call site or kind — the embedder emits the same
    /// `PATINA_BUGGIFY_DUPLICATE_LABEL` marker the evaluation path uses. `Err`
    /// means the declaration itself is malformed.
    pub fn declare_static_site(
        &mut self,
        label: &str,
        site: &str,
        kind: BuggifyKind,
    ) -> Result<SiteOutcome, RuntimeError> {
        self.buggify.declare(label, site, kind).map_err(|error| {
            RuntimeError::Config(format!("invalid static SDK site declaration: {error}"))
        })
    }

    /// Evaluate a `buggify!` / `buggify_with_prob!` site. `prob_permille`
    /// overrides the run-default firing probability when `Some`. Fires only when
    /// buggify is enabled, the label activated this run, and the virtual clock is
    /// before the damage-control cutoff.
    pub fn buggify_evaluate(
        &mut self,
        label: &str,
        site: &str,
        prob_permille: Option<u16>,
    ) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Fault) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        if now.is_some_and(|now| {
            now.saturating_sub(self.boot_origin_nanos) >= self.buggify.config.cutoff_nanos
        }) {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        let permille = prob_permille.unwrap_or(self.buggify.config.fire_permille);
        if Buggify::fire_draw(hash, self.buggify.seed, eval, permille) {
            self.buggify
                .sites
                .get_mut(label)
                .expect("registered")
                .fire_count += 1;
            Ok(SiteOutcome::Fire)
        } else {
            Ok(SiteOutcome::Ok)
        }
    }

    /// Evaluate a `buggify_delay!` site. On firing, advance the virtual clock by
    /// a seed-derived amount through the recorded `SleepUntil` path — never a real
    /// sleep — so the perturbation reproduces on replay. Returns [`SiteOutcome::Fire`]
    /// when it delayed.
    pub fn buggify_delay(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Delay) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        let now = now.expect("time read when enabled");
        if now.saturating_sub(self.boot_origin_nanos) >= self.buggify.config.cutoff_nanos {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        if !Buggify::fire_draw(
            hash,
            self.buggify.seed,
            eval,
            self.buggify.config.fire_permille,
        ) {
            return Ok(SiteOutcome::Ok);
        }
        // A seed-derived delay in [1ms, 5s], deterministic per (seed, label,
        // eval). Routed through the recorded clock path so replay reproduces it.
        const MIN_DELAY_NANOS: u64 = 1_000_000;
        const MAX_DELAY_NANOS: u64 = 5_000_000_000;
        let span = MAX_DELAY_NANOS - MIN_DELAY_NANOS + 1;
        let delay = MIN_DELAY_NANOS
            + (buggify_prf(&[self.buggify.seed, hash, buggify_domain::DELAY, eval]) % span);
        self.buggify
            .sites
            .get_mut(label)
            .expect("registered")
            .fire_count += 1;
        let deadline = now.saturating_add(delay);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        Ok(SiteOutcome::Fire)
    }

    /// Evaluate a `buggify_knob!` site: return a per-run perturbed value within
    /// `[lo, hi]` (deterministic from seed and label) for an active site under an
    /// enabled run, or `default` otherwise. `Err(())` marks a duplicate label.
    pub fn buggify_knob(
        &mut self,
        label: &str,
        site: &str,
        default: i64,
        lo: i64,
        hi: i64,
    ) -> Result<Result<i64, ()>, RuntimeError> {
        let hash = match self.buggify.register(label, site, BuggifyKind::Knob) {
            Ok(hash) => hash,
            Err(_) => return Ok(Err(())),
        };
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        let enabled = self.buggify.config.enabled;
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        let value = if enabled && entry.active {
            let span = (hi as i128 - lo as i128 + 1) as u128;
            let draw = buggify_prf(&[self.buggify.seed, hash, buggify_domain::KNOB]) as u128;
            (lo as i128 + (draw % span) as i128) as i64
        } else {
            default.clamp(lo, hi)
        };
        entry.knob = Some(value);
        Ok(Ok(value))
    }

    /// Report one guest verdict — the runtime half of the verdict ABI
    /// (`patina_verdict` natively, the `patina_sdk` `verdict` import on WASI, and
    /// this method directly for an in-process cargo-family guest).
    ///
    /// The call is recorded as an [`Operation::Verdict`] boundary event, so a
    /// replay whose verdict stream diverges from the recording fails closed like
    /// any other operation mismatch, and the run's `PATINA_VERDICT` marker line
    /// is queued for the embedder to surface (see `pending_diagnostics`). The
    /// verdict itself has no effect on control flow: a `Violation` does not
    /// abort, and an `AbortIntent` does not abort — it *attributes* an abort the
    /// guest is about to perform itself.
    pub fn verdict(
        &mut self,
        kind: VerdictKind,
        label: &str,
        detail: &str,
    ) -> Result<VerdictRecord, RuntimeError> {
        let operation = Operation::Verdict {
            verdict_kind: kind,
            label: label.to_string(),
            detail: detail.to_string(),
        };
        let expected = self.replay_expected(&operation)?;
        self.reconcile(operation, expected, Outcome::Unit)?;
        let record = VerdictRecord {
            seq: self.verdicts.len() as u64,
            kind,
            label: label.to_string(),
            detail: detail.to_string(),
        };
        self.pending_diagnostics.push(record.marker_line());
        self.verdicts.push(record.clone());
        Ok(record)
    }

    /// Every verdict reported so far, in call order.
    pub fn verdicts(&self) -> &[VerdictRecord] {
        &self.verdicts
    }

    /// Take the diagnostic lines the runtime has queued but not printed. The
    /// embedder calls this after every SDK entry point and writes each line to
    /// its captured stderr; see `Context::pending_diagnostics`.
    pub fn take_pending_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_diagnostics)
    }

    /// Evaluate an `always!` invariant. A false condition is a fatal violation
    /// whenever running under the simulator, independent of buggify being
    /// enabled — the embedder emits the marker and aborts.
    ///
    /// A violation lowers to the verdict ABI: it reports
    /// `VerdictKind::Violation` under the site's label (with the `file:line`
    /// identity as the detail) before returning, so the failure reaches the trace
    /// and the result envelope structurally. This is the SDK-surface lowering
    /// §4.1 of the outcome-channel arc calls for, and it is the violation's ONLY
    /// announcement: the embedders drain the verdict line and abort, printing no
    /// marker of their own.
    pub fn always_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Always)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            return Ok(SiteOutcome::Ok);
        }
        entry.always_violated = true;
        self.verdict(VerdictKind::Violation, label, site)?;
        Ok(SiteOutcome::AlwaysViolation)
    }

    /// Evaluate a `sometimes!` coverage oracle: note the site reached, and
    /// satisfied when `condition` is true at least once across the run.
    pub fn sometimes_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Sometimes)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            entry.sometimes_satisfied = true;
        }
        Ok(SiteOutcome::Ok)
    }

    /// Mark a `reachable!` coverage site reached.
    pub fn reachable_mark(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Reachable)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        Ok(SiteOutcome::Ok)
    }

    /// Draw a deterministic 64-bit value from the buggify entropy stream — the
    /// `patina_dst::rng()` hook, bridged to the root seed. Not recorded: it is a pure
    /// function of the seed and the call count, so replay reproduces it.
    pub fn buggify_rng(&mut self) -> u64 {
        self.buggify.rng.next_u64()
    }

    /// Mark the `patina_dst::lifecycle::setup_complete()` boundary.
    pub fn lifecycle_setup_complete(&mut self) {
        self.buggify.setup_complete = true;
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`. The embedder checks this at finalization and
    /// fails the run loudly — a declared-but-never-called gate is a harness bug,
    /// not a silent no-fault run.
    pub fn buggify_setup_violation(&self) -> bool {
        self.buggify.setup_violation()
    }

    /// End-of-run cooperative-SUT diagnostics. See [`BuggifyDiagnostics`]. Also
    /// emitted to stderr by [`Context::finish`] via `PATINA_SDK_REPORT`.
    pub fn buggify_diagnostics(&mut self) -> BuggifyDiagnostics {
        let cutoff_reached_now = self.buggify.config.enabled
            && self.current_monotonic().is_ok_and(|now| {
                now.saturating_sub(self.boot_origin_nanos) >= self.buggify.config.cutoff_nanos
            });
        // Whether buggify is off because THIS generation's swarm draw dropped it,
        // as opposed to never having been requested. Both report `enabled=0`, and
        // conflating them is what turned a working `--buggify=N` into a phantom
        // bug report; the flag makes the two states distinguishable in one line.
        let swarm_deselected = self
            .swarm
            .as_ref()
            .is_some_and(|swarm| swarm.deselected(FINGERPRINT_BUGGIFY));
        let mut diagnostics = self.buggify.diagnostics(cutoff_reached_now);
        diagnostics.swarm_deselected = swarm_deselected;
        diagnostics
    }
}

#[cfg(test)]
mod tests;
