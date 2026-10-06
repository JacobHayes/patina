//! Control-plane environment parsing and runtime configuration overlays.
// Process-environment reads are confined to configuration, before installation.
#![allow(clippy::disallowed_methods)]
use crate::config::{
    RuntimeConfig, validate_dns_entry, validate_guest_cwd, validate_guest_env, validate_hostname,
    validate_partition,
};

use crate::ENV_FS_TORN_GRANULARITY;
use crate::fs_crash::CrashPoint;

use crate::{
    DEFAULT_CONVERGE_BUDGET_NANOS, DEFAULT_LIVENESS_BUDGET_NANOS, DEFAULT_PCT_DEPTH,
    DEFAULT_PCT_STEPS, DEFAULT_STARVE_INTERVALS, DEFAULT_STARVE_MAX_LEN, DEFAULT_STARVE_WINDOW,
    ENV_BRANCH_FROM, ENV_BRANCH_ID, ENV_BRANCH_SEED, ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF, ENV_CONVERGE_WITHIN, ENV_FACTS, ENV_FACTS_FD,
    ENV_FINGERPRINT, ENV_GUEST_ARGV, ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_GUEST_HOSTNAME,
    ENV_HEAL_AFTER, ENV_LIVENESS_WATCHDOG, ENV_MODE, ENV_PARAMS_JSON, ENV_PARENT_TIMELINE,
    ENV_REALTIME_EPOCH_NANOS, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS, ENV_SCHED_STARVE,
    ENV_SCHED_STARVE_MAX_LEN, ENV_SCHED_STARVE_WINDOW, ENV_SEED, ENV_STEP_BUDGET, ENV_SWARM,
    ENV_TIMELINE, ENV_TRACE, ENV_TRACE_FD, FaultKnob, Plane, RuntimeError, TornGranularity,
};
use patina_dst_sched_det::{PctConfig, StarvationConfig};
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

/// Parse the documented `PATINA_TRACE_FD` variable into a raw descriptor.
///
/// Embedders that can service the descriptor (for example the native shim)
/// use this to build a [`TraceTransport`]; `RuntimeConfig::from_env` uses it
/// to select the transport execution modes.
pub fn trace_fd_from_env() -> Result<Option<i32>, RuntimeError> {
    match env::var(ENV_TRACE_FD) {
        Ok(value) => {
            let fd: i32 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{ENV_TRACE_FD} must be a non-negative descriptor"))
            })?;
            if fd < 0 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} must be a non-negative descriptor"
                )));
            }
            Ok(Some(fd))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(RuntimeError::Config(format!(
            "{ENV_TRACE_FD} must be valid UTF-8"
        ))),
    }
}

fn parse_torn_granularity(value: &str) -> Result<TornGranularity, RuntimeError> {
    match value {
        "block" => Ok(TornGranularity::Block),
        "byte" => Ok(TornGranularity::Byte),
        other => Err(RuntimeError::Config(format!(
            "{ENV_FS_TORN_GRANULARITY} must be block or byte; got {other:?}"
        ))),
    }
}

/// Parse a per-mille probability, requiring an integer in [0, 1000].
fn parse_permille(name: &str, value: &str) -> Result<u16, RuntimeError> {
    let permille: u16 = value
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an integer in [0, 1000]")))?;
    if permille > 1000 {
        return Err(RuntimeError::Config(format!(
            "{name} must be within [0, 1000] per-mille"
        )));
    }
    Ok(permille)
}

/// Parse an inclusive `MIN..MAX` nanosecond range, requiring `MIN <= MAX`.
fn parse_nanos_range(name: &str, value: &str) -> Result<(u64, u64), RuntimeError> {
    let (min_text, max_text) = value.split_once("..").ok_or_else(|| {
        RuntimeError::Config(format!("{name} must be a MIN..MAX range; got {value:?}"))
    })?;
    let min = min_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MIN must be an unsigned integer")))?;
    let max = max_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MAX must be an unsigned integer")))?;
    if min > max {
        return Err(RuntimeError::Config(format!(
            "{name} requires MIN <= MAX; got {value:?}"
        )));
    }
    Ok((min, max))
}

fn parse_seed(value: Option<String>) -> Result<u64, RuntimeError> {
    value.map_or(Ok(0), |value| {
        value.parse().map_err(|_| {
            RuntimeError::Config(format!("{ENV_SEED} must be an unsigned 64-bit integer"))
        })
    })
}

fn required_u64(name: &str) -> Result<u64, RuntimeError> {
    required_string(name)?
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer")))
}

fn required_path(name: &str) -> Result<PathBuf, RuntimeError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}

fn required_string(name: &str) -> Result<String, RuntimeError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}
impl RuntimeConfig {
    /// Apply the DNS host table from a control-plane accessor, mirroring
    /// [`RuntimeConfig::apply_fault_env`]. The table is a JSON object; a
    /// malformed entry fails closed rather than silently resolving nothing.
    ///
    /// Separate from [`RuntimeConfig::apply_fault_env`] because a family may
    /// offer the host table WITHOUT the DNS fault knobs — `campaign` does, since
    /// it draws the knobs per generation — so the two planes are applied
    /// independently. [`Plane`] is where each knob records which one it lands on.
    pub fn apply_dns_env<F>(self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.apply_knob_env(Plane::DnsTable, get)
    }

    /// Apply the fault-injection knobs from a control-plane accessor. Shared by
    /// [`RuntimeConfig::from_env`] (reading the process environment) and the
    /// native shim (reading its scrubbed constructor-time control plane), so both
    /// entry points parse the fault protocol identically and fail closed on any
    /// malformed value. Each knob defaults off when its variable is absent.
    pub fn apply_fault_env<F>(self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.apply_knob_env(Plane::Fault, get)
    }

    /// Read every knob on one configuration plane off the control plane, in
    /// [`FaultKnob::ALL`] order, and layer it onto this configuration. The knob
    /// table decides WHICH variable carries each knob and which plane it lands
    /// on; [`RuntimeConfig::apply_one_knob`] decides how its value is parsed.
    fn apply_knob_env<F>(mut self, plane: Plane, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        for knob in FaultKnob::ALL {
            let meta = knob.meta();
            if meta.plane != plane {
                continue;
            }
            if let Some(value) = get(meta.env) {
                self.apply_one_knob(*knob, &value)?;
            }
        }
        Ok(self)
    }

    /// Parse one knob's control-plane value and apply it. The exhaustive match is
    /// the pairing: a knob added to [`FaultKnob`] has no way into a
    /// configuration until its protocol is written here, so it cannot be
    /// advertised by the CLI, forwarded by a family, and then silently ignored by
    /// the runtime — the silent-inertness class, which looks exactly like a clean
    /// run.
    fn apply_one_knob(&mut self, knob: FaultKnob, value: &str) -> Result<(), RuntimeError> {
        let env = knob.meta().env;
        match knob {
            FaultKnob::FsCrashAt => self.faults.fs.crash_at = Some(CrashPoint::parse(value)?),
            FaultKnob::FsTornGranularity => {
                self.faults.fs.torn_granularity = parse_torn_granularity(value)?;
            }
            FaultKnob::FsErrorPermille => {
                self.faults.fs.error_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsShortPermille => {
                self.faults.fs.short_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsLatencyNanos => {
                self.faults.fs.latency_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::SleepJitterNanos => {
                self.faults.clock.sleep_jitter_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::NetJitterNanos => {
                self.faults.net.jitter_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::NetDropPermille => {
                self.faults.net.drop_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetLatencyNanos => {
                self.faults.net.latency_nanos = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be an unsigned 64-bit integer"))
                })?;
            }
            FaultKnob::NetDuplicatePermille => {
                self.faults.net.duplicate_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetConnectRefusePermille => {
                self.faults.net.connect_refuse_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetResetPermille => {
                self.faults.net.reset_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetPartition => {
                let pairs: Vec<(String, String)> = serde_json::from_str(value)
                    .map_err(|error| RuntimeError::Config(format!("{env} is invalid: {error}")))?;
                for (left, right) in pairs {
                    validate_partition(&left, &right)?;
                    self.faults
                        .net
                        .partitions
                        .insert((left.clone(), right.clone()));
                    self.faults.net.partitions.insert((right, left));
                }
            }
            FaultKnob::NetTcpBufferBytes => {
                let bytes: usize = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be a non-negative machine integer"))
                })?;
                if bytes == 0 {
                    return Err(RuntimeError::Config(format!(
                        "{env} must be greater than zero"
                    )));
                }
                self.faults.net.tcp_buffer_bytes = Some(bytes);
            }
            FaultKnob::DnsEntry => {
                let entries: BTreeMap<String, String> = serde_json::from_str(value)
                    .map_err(|error| RuntimeError::Config(format!("{env} is invalid: {error}")))?;
                for (name, address) in &entries {
                    validate_dns_entry(name, address)?;
                }
                self.dns_entries = entries;
            }
            FaultKnob::DnsFailPermille => {
                self.faults.dns.fail_permille = parse_permille(env, value)?;
            }
            FaultKnob::DnsLatencyNanos => {
                self.faults.dns.latency_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::EntropyFailPermille => {
                self.faults.entropy.fail_permille = parse_permille(env, value)?;
            }
            FaultKnob::CustomOpFailPermille => {
                self.faults.custom_op.fail_permille = parse_permille(env, value)?;
            }
            FaultKnob::EpochJumpNanos => {
                self.faults.clock.epoch_jump_nanos = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be an unsigned 64-bit integer"))
                })?;
            }
        }
        Ok(())
    }

    /// Apply the cooperative-SUT (buggify) knobs from a control-plane accessor,
    /// mirroring [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_BUGGIFY`]
    /// enables buggify; its value (if non-empty) is the per-evaluation firing
    /// per-mille. Activation and cutoff come from their own variables, defaulting
    /// to the FoundationDB defaults. Absence leaves buggify disabled (zero
    /// behavior change).
    pub fn apply_buggify_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let Some(fire) = get(ENV_BUGGIFY) else {
            return Ok(self);
        };
        self.buggify.enabled = true;
        let fire = fire.trim();
        if !fire.is_empty() {
            self.buggify.fire_permille = parse_permille(ENV_BUGGIFY, fire)?;
        }
        if let Some(value) = get(ENV_BUGGIFY_ACTIVATION) {
            self.buggify.activation_permille =
                parse_permille(ENV_BUGGIFY_ACTIVATION, value.trim())?;
        }
        if let Some(value) = get(ENV_BUGGIFY_CUTOFF) {
            self.buggify.cutoff_nanos = value.trim().parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_BUGGIFY_CUTOFF} must be an unsigned 64-bit integer"
                ))
            })?;
        }
        if let Some(value) = get(ENV_BUGGIFY_AFTER_SETUP) {
            self.buggify.after_setup = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// Apply the guest's initial working directory from a control-plane
    /// accessor. Presence of [`ENV_GUEST_CWD`] sets it (validated and
    /// canonicalized); absence leaves it unset (`/`). Shared by
    /// [`RuntimeConfig::from_env`] and the native shim.
    pub fn apply_guest_cwd_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_CWD) {
            self.guest_cwd = Some(validate_guest_cwd(&value)?);
        }
        Ok(self)
    }

    /// Apply the guest's node name from a control-plane accessor. Presence of
    /// [`ENV_GUEST_HOSTNAME`] sets it (validated by [`validate_hostname`]);
    /// absence leaves the default. Shared by [`RuntimeConfig::from_env`] and the
    /// native shim.
    pub fn apply_hostname_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_HOSTNAME) {
            validate_hostname(&value)
                .map_err(|error| RuntimeError::Config(format!("{ENV_GUEST_HOSTNAME}: {error}")))?;
            self.hostname = Some(value);
        }
        Ok(self)
    }

    /// Apply the run's virtual realtime epoch from a control-plane accessor.
    /// Presence of [`ENV_REALTIME_EPOCH_NANOS`] sets it (a decimal `u64` of
    /// nanoseconds; anything else fails closed); absence leaves the default.
    /// Shared by [`RuntimeConfig::from_env`] and the native shim.
    pub fn apply_realtime_epoch_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_REALTIME_EPOCH_NANOS) {
            let nanos = value.trim().parse::<u64>().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_REALTIME_EPOCH_NANOS} must be an unsigned 64-bit count of \
                     nanoseconds since the Unix epoch, got {value:?}"
                ))
            })?;
            self.realtime_epoch_nanos = Some(nanos);
        }
        Ok(self)
    }

    /// Apply the guest program arguments from a control-plane accessor, mirroring
    /// [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_GUEST_ARGV`] sets the
    /// recorded argv from its JSON string-array value; absence leaves it unset
    /// (zero behavior change). Malformed JSON is rejected fail-closed. Shared by
    /// [`RuntimeConfig::from_env`] and the native shim so both entry points parse
    /// the argv protocol identically.
    pub fn apply_guest_argv_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_ARGV) {
            let argv: Vec<String> = serde_json::from_str(&value).map_err(|error| {
                RuntimeError::Config(format!("{ENV_GUEST_ARGV} is invalid: {error}"))
            })?;
            self.guest_argv = Some(argv);
        }
        Ok(self)
    }

    /// Apply deterministic guest environment values from a control-plane
    /// accessor. Presence of [`ENV_GUEST_ENV`] sets the environment from its JSON
    /// object value; absence leaves it empty. Malformed JSON or invalid keys/values
    /// fail closed. Shared by [`RuntimeConfig::from_env`] and the native shim.
    pub fn apply_guest_env_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_ENV) {
            let guest_env: BTreeMap<String, String> =
                serde_json::from_str(&value).map_err(|error| {
                    RuntimeError::Config(format!("{ENV_GUEST_ENV} is invalid: {error}"))
                })?;
            validate_guest_env(&guest_env)?;
            self.guest_env = guest_env;
        }
        Ok(self)
    }

    /// Apply the exploration scheduling-policy knobs from a control-plane
    /// accessor, mirroring [`RuntimeConfig::apply_fault_env`]. Presence of
    /// [`ENV_SCHED_PCT`] enables PCT (its value is the bug depth `d`, empty =
    /// default); presence of [`ENV_SCHED_STARVE`] enables starvation intervals
    /// (its value is the interval count). Absence leaves the default uniform
    /// policy (zero behavior change). Malformed values are rejected fail-closed.
    pub fn apply_schedule_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SCHED_PCT) {
            let value = value.trim();
            let depth = if value.is_empty() {
                DEFAULT_PCT_DEPTH
            } else {
                let depth: u32 = value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} must be an unsigned integer >= 1"
                    ))
                })?;
                if depth < 1 {
                    return Err(RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} bug depth must be >= 1"
                    )));
                }
                depth
            };
            let steps = match get(ENV_SCHED_PCT_STEPS) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT_STEPS} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_PCT_STEPS,
            };
            if steps < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_PCT_STEPS} must be >= 1"
                )));
            }
            self.schedule_policy.pct = Some(PctConfig { depth, steps });
        }
        if let Some(value) = get(ENV_SCHED_STARVE) {
            let value = value.trim();
            let intervals = if value.is_empty() {
                DEFAULT_STARVE_INTERVALS
            } else {
                value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE} must be an unsigned integer >= 1"
                    ))
                })?
            };
            if intervals < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE} interval count must be >= 1"
                )));
            }
            let max_len = match get(ENV_SCHED_STARVE_MAX_LEN) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_MAX_LEN} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_MAX_LEN,
            };
            let window = match get(ENV_SCHED_STARVE_WINDOW) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_WINDOW} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_WINDOW,
            };
            if max_len < 1 || window < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE_MAX_LEN} and {ENV_SCHED_STARVE_WINDOW} must be >= 1 so \
                     intervals are bounded and placeable"
                )));
            }
            self.schedule_policy.starvation = Some(StarvationConfig {
                intervals,
                max_len,
                window,
            });
        }
        Ok(self)
    }

    /// Apply the swarm fault-class-selection knob from a control-plane accessor.
    /// Presence of a truthy [`ENV_SWARM`] enables swarm; a false-y value (or
    /// absence) leaves it off (the existing always-all behavior).
    pub fn apply_swarm_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SWARM) {
            self.swarm = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// Read the facts-document path from the control plane ([`ENV_FACTS`]).
    pub fn apply_facts_env<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_FACTS)
            && !value.trim().is_empty()
        {
            self.facts_path = Some(std::path::PathBuf::from(value));
        }
        self
    }

    /// Apply the end-of-run report-suppression knobs from a control-plane
    /// accessor, mirroring [`RuntimeConfig::apply_fault_env`]. Every [`Report`]'s
    /// variable is resolved here, ONCE, because finalization has no usable view
    /// of the process environment on the native path.
    #[must_use]
    pub fn apply_report_env<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        self.reports = self.reports.applied(get);
        self
    }

    /// Apply the liveness-watchdog knobs from a control-plane accessor. A present
    /// [`ENV_LIVENESS_WATCHDOG`] enables the generic no-progress arm (its value, if
    /// non-empty, being the budget in nanoseconds); [`ENV_CONVERGE_WITHIN`] enables
    /// the heal-then-converge arm; [`ENV_HEAL_AFTER`] overrides its arm-time. A
    /// zero budget is rejected so the watchdog cannot be armed to fire vacuously.
    pub fn apply_liveness_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let parse_budget = |name: &str, value: String, default: u64| -> Result<u64, RuntimeError> {
            let value = value.trim();
            if value.is_empty() {
                return Ok(default);
            }
            let nanos: u64 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer"))
            })?;
            if nanos == 0 {
                return Err(RuntimeError::Config(format!(
                    "{name} budget must be > 0 so the watchdog cannot fire vacuously"
                )));
            }
            Ok(nanos)
        };
        if let Some(value) = get(ENV_LIVENESS_WATCHDOG) {
            self.liveness.no_progress_budget_nanos = Some(parse_budget(
                ENV_LIVENESS_WATCHDOG,
                value,
                DEFAULT_LIVENESS_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_CONVERGE_WITHIN) {
            self.liveness.converge_budget_nanos = Some(parse_budget(
                ENV_CONVERGE_WITHIN,
                value,
                DEFAULT_CONVERGE_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_HEAL_AFTER) {
            let value = value.trim();
            if !value.is_empty() {
                self.liveness.heal_after_nanos = Some(value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_HEAL_AFTER} must be an unsigned 64-bit integer"
                    ))
                })?);
            }
        }
        Ok(self)
    }

    pub fn from_env() -> Result<Self, RuntimeError> {
        let mode = env::var(ENV_MODE).unwrap_or_else(|_| "seeded".into());
        let seed = parse_seed(env::var(ENV_SEED).ok())?;
        let trace_fd = trace_fd_from_env()?;
        if trace_fd.is_some() && env::var_os(ENV_TRACE).is_some_and(|value| !value.is_empty()) {
            return Err(RuntimeError::Config(format!(
                "{ENV_TRACE} and {ENV_TRACE_FD} must not both be set"
            )));
        }
        let config = match (mode.as_str(), trace_fd) {
            ("seeded", None) => Self::seeded(seed),
            ("seeded", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} is only meaningful in record or replay mode"
                )));
            }
            ("record", None) => Self::record(
                seed,
                required_path(ENV_TRACE)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("record", Some(_)) => Self::record_transport(seed, required_string(ENV_FINGERPRINT)?),
            ("replay", None) => Self::replay_timeline(
                required_path(ENV_TRACE)?,
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("replay", Some(_)) => Self::replay_transport_timeline(
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", None) => Self::branch(
                required_path(ENV_TRACE)?,
                env::var(ENV_PARENT_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_u64(ENV_BRANCH_FROM)?,
                required_string(ENV_BRANCH_ID)?,
                required_u64(ENV_BRANCH_SEED)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "branch mode requires a {ENV_TRACE} path; {ENV_TRACE_FD} is unsupported"
                )));
            }
            (value, _) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_MODE} must be seeded, record, replay, or branch; got {value:?}"
                )));
            }
        };
        let mut config = match env::var(ENV_STEP_BUDGET) {
            Ok(value) => config.with_step_budget(value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be an unsigned 64-bit integer"
                ))
            })?),
            Err(env::VarError::NotPresent) => config,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be valid UTF-8"
                )));
            }
        };
        if let Some(value) = env::var_os(ENV_PARAMS_JSON) {
            let value = value.into_string().map_err(|_| {
                RuntimeError::Config(format!("{ENV_PARAMS_JSON} must be valid UTF-8"))
            })?;
            let params: BTreeMap<String, String> =
                serde_json::from_str(&value).map_err(|error| {
                    RuntimeError::Config(format!("{ENV_PARAMS_JSON} is invalid: {error}"))
                })?;
            if params.keys().any(String::is_empty) {
                return Err(RuntimeError::Config(
                    "runtime parameter key must not be empty".into(),
                ));
            }
            config.params = params;
        }
        let config = config.apply_fault_env(|name| env::var(name).ok())?;
        let config = config.apply_dns_env(|name| env::var(name).ok())?;
        let config = config.apply_buggify_env(|name| env::var(name).ok())?;
        let config = config.apply_schedule_env(|name| env::var(name).ok())?;
        let config = config.apply_swarm_env(|name| env::var(name).ok())?;
        let config = config.apply_liveness_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_argv_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_env_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_cwd_env(|name| env::var(name).ok())?;
        let config = config.apply_realtime_epoch_env(|name| env::var(name).ok())?;
        let config = config.apply_hostname_env(|name| env::var(name).ok())?;
        // The report-suppression knobs are resolved HERE, with every other knob,
        // and never again: finalization must not reach for the process
        // environment (see `ReportConfig`).
        let config = config.apply_report_env(|name| env::var(name).ok());
        // The facts channel, resolved with every other knob. A descriptor
        // channel ([`ENV_FACTS_FD`]) is installed by the embedder that owns the
        // descriptor (the native shim), so the two must never both be live.
        if env::var_os(ENV_FACTS_FD).is_some_and(|value| !value.is_empty())
            && env::var_os(ENV_FACTS).is_some_and(|value| !value.is_empty())
        {
            return Err(RuntimeError::Config(format!(
                "{ENV_FACTS} and {ENV_FACTS_FD} must not both be set"
            )));
        }
        let config = config.apply_facts_env(|name| env::var(name).ok());
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;

    use crate::replay::{reconcile_replay_guest_cwd, reconcile_replay_guest_env};
    use crate::{
        ENV_GUEST_ARGV, ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS,
        ENV_SCHED_STARVE, ENV_SCHED_STARVE_MAX_LEN, ENV_SCHED_STARVE_WINDOW, ENV_SWARM,
        RuntimeError,
    };
    use patina_dst_sched_det::{PctConfig, StarvationConfig};
    use std::collections::BTreeMap;

    #[test]
    fn apply_schedule_and_swarm_env_parse_the_control_plane() {
        let vars: BTreeMap<&str, String> = [
            (ENV_SCHED_PCT, "4".to_string()),
            (ENV_SCHED_PCT_STEPS, "123".to_string()),
            (ENV_SCHED_STARVE, "2".to_string()),
            (ENV_SCHED_STARVE_MAX_LEN, "16".to_string()),
            (ENV_SCHED_STARVE_WINDOW, "64".to_string()),
            (ENV_SWARM, "1".to_string()),
        ]
        .into_iter()
        .collect();
        let get = |name: &str| vars.get(name).cloned();
        let config = RuntimeConfig::seeded(0)
            .apply_schedule_env(get)
            .unwrap()
            .apply_swarm_env(get)
            .unwrap();
        let policy = config.schedule_policy();
        assert_eq!(
            policy.pct,
            Some(PctConfig {
                depth: 4,
                steps: 123
            })
        );
        assert_eq!(
            policy.starvation,
            Some(StarvationConfig {
                intervals: 2,
                max_len: 16,
                window: 64
            })
        );
        assert!(config.swarm());

        // A malformed PCT depth fails closed.
        let bad: BTreeMap<&str, String> =
            [(ENV_SCHED_PCT, "abc".to_string())].into_iter().collect();
        assert!(
            RuntimeConfig::seeded(0)
                .apply_schedule_env(|name| bad.get(name).cloned())
                .is_err()
        );
    }

    #[test]
    fn guest_argv_env_parses_a_json_array_and_fails_closed_on_garbage() {
        // A JSON string array sets the recorded argv, preserving order; an empty
        // array is a valid zero-argument recording distinct from absence.
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_ARGV).then(|| value.to_string())
        }
        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map(r#"["--tick-millis","50"]"#))
            .unwrap();
        assert_eq!(
            config.guest_argv(),
            Some(["--tick-millis".to_string(), "50".to_string()].as_slice())
        );
        let empty = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("[]"))
            .unwrap();
        assert_eq!(empty.guest_argv(), Some([].as_slice()));

        // Absent variable leaves argv unset (no behavior change).
        let unset = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(|_| None)
            .unwrap();
        assert_eq!(unset.guest_argv(), None);

        // Malformed JSON is rejected fail-closed rather than silently dropped.
        let error = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("not json"))
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Config(_)), "{error:?}");
    }

    #[test]
    fn guest_cwd_env_validates_canonicalizes_and_reconciles_trace_metadata() {
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_CWD).then(|| value.to_string())
        }
        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_cwd_env(map("/work//sub/./"))
            .unwrap();
        assert_eq!(config.guest_cwd(), Some("/work/sub"));
        let unset = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_cwd_env(|_| None)
            .unwrap();
        assert_eq!(unset.guest_cwd(), None);
        for invalid in ["relative/dir", "", "/a/../b", "/nul\0"] {
            let error = RuntimeConfig::record(0, "/trace", "fp")
                .apply_guest_cwd_env(move |name| {
                    (name == ENV_GUEST_CWD).then(|| invalid.to_string())
                })
                .unwrap_err();
            assert!(
                matches!(error, RuntimeError::Config(_)),
                "{invalid:?}: {error:?}"
            );
        }

        // The trace is authoritative: adopted flag-free, matched when supplied,
        // refused when the supplied value differs; a pre-cwd trace adopts nothing.
        let adopted = reconcile_replay_guest_cwd(&RuntimeConfig::seeded(0), Some("/work")).unwrap();
        assert_eq!(adopted.as_deref(), Some("/work"));
        let matching = RuntimeConfig::seeded(0)
            .with_guest_cwd(Some("/work"))
            .unwrap();
        assert_eq!(
            reconcile_replay_guest_cwd(&matching, Some("/work"))
                .unwrap()
                .as_deref(),
            Some("/work")
        );
        let conflicting = RuntimeConfig::seeded(0)
            .with_guest_cwd(Some("/other"))
            .unwrap();
        assert!(matches!(
            reconcile_replay_guest_cwd(&conflicting, Some("/work")),
            Err(RuntimeError::Config(_))
        ));
        assert_eq!(
            reconcile_replay_guest_cwd(&conflicting, None).unwrap(),
            None
        );
    }

    #[test]
    fn guest_env_env_parses_validates_and_reconciles_trace_metadata() {
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_ENV).then(|| value.to_string())
        }

        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map(r#"{"RUST_LOG":"debug","MODE":"test"}"#))
            .unwrap();
        assert_eq!(config.guest_env()["RUST_LOG"], "debug");
        assert_eq!(config.guest_env()["MODE"], "test");

        let empty = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map("{}"))
            .unwrap();
        assert!(empty.guest_env().is_empty());

        let invalid = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map(r#"{"":"value"}"#))
            .unwrap_err();
        assert!(matches!(invalid, RuntimeError::Config(_)), "{invalid:?}");

        let stored = BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]);
        let adopted = reconcile_replay_guest_env(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .unwrap();
        assert_eq!(adopted, stored);
        reconcile_replay_guest_env(
            &RuntimeConfig::seeded(0).with_guest_env(stored.clone()),
            Some(&stored),
        )
        .unwrap();
        let conflict = RuntimeConfig::seeded(0).with_guest_env(BTreeMap::from([(
            "RUST_LOG".to_string(),
            "trace".to_string(),
        )]));
        assert!(reconcile_replay_guest_env(&conflict, Some(&stored)).is_err());
    }
}
