//! Control-plane parsing: runtime configuration overlays read through an
//! embedder-supplied accessor (the native shim's captured control plane).
use crate::config::{
    RuntimeConfig, validate_cpus, validate_dns_entry, validate_guest_cwd, validate_guest_env,
    validate_hostname, validate_partition,
};

use crate::scheduler::PctConfig;
use crate::{
    DEFAULT_CONVERGE_BUDGET_NANOS, DEFAULT_LIVENESS_BUDGET_NANOS, DEFAULT_PCT_DEPTH,
    DEFAULT_PCT_STEPS, ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, ENV_BUGGIFY_AFTER_SETUP,
    ENV_BUGGIFY_CUTOFF, ENV_CONVERGE_WITHIN, ENV_GUEST_ARGV, ENV_GUEST_CPUS, ENV_GUEST_CWD,
    ENV_GUEST_ENV, ENV_GUEST_HOSTNAME, ENV_HEAL_AFTER, ENV_LIVENESS_WATCHDOG,
    ENV_REALTIME_EPOCH_NANOS, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS, ENV_SCHED_YIELD_STRIDE,
    ENV_SWARM, FaultKnob, Plane, RuntimeError,
};
use std::collections::BTreeMap;

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
            FaultKnob::MachineCrashPermille => {
                self.faults.crash.machine_permille = parse_permille(env, value)?;
            }
            FaultKnob::ProcessCrashPermille => {
                self.faults.crash.process_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsErrorPermille => {
                self.faults.fs.error_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsErrorAt => {
                let spellings: Vec<String> = serde_json::from_str(value)
                    .map_err(|error| RuntimeError::Config(format!("{env} is invalid: {error}")))?;
                for spelling in spellings {
                    let target = spelling
                        .parse()
                        .map_err(|error| RuntimeError::Config(format!("{env}: {error}")))?;
                    self.faults.fs.error_at.insert(target);
                }
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

    /// Apply the virtual machine's CPU count from a control-plane accessor.
    /// Presence of [`ENV_GUEST_CPUS`] sets it (a decimal count
    /// [`validate_cpus`] accepts; anything else fails closed); absence leaves
    /// the default. Shared by [`RuntimeConfig::from_env`] and the native shim.
    pub fn apply_cpus_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_CPUS) {
            let cpus = value.parse::<u32>().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_GUEST_CPUS} must be a decimal CPU count; got {value:?}"
                ))
            })?;
            validate_cpus(cpus)
                .map_err(|error| RuntimeError::Config(format!("{ENV_GUEST_CPUS}: {error}")))?;
            self.cpus = Some(cpus);
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
    /// default). Absence leaves the default uniform
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
        if let Some(value) = get(ENV_SCHED_YIELD_STRIDE) {
            self.yield_stride = value.trim().parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_SCHED_YIELD_STRIDE} must be an unsigned 32-bit integer"
                ))
            })?;
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
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;

    use crate::replay::{reconcile_replay_guest_cwd, reconcile_replay_guest_env};
    use crate::scheduler::PctConfig;
    use crate::{
        ENV_GUEST_ARGV, ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS,
        ENV_SWARM, RuntimeError,
    };
    use std::collections::BTreeMap;

    #[test]
    fn apply_schedule_and_swarm_env_parse_the_control_plane() {
        let vars: BTreeMap<&str, String> = [
            (ENV_SCHED_PCT, "4".to_string()),
            (ENV_SCHED_PCT_STEPS, "123".to_string()),
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
        // refused when the supplied value differs; a trace without one started
        // at `/`, so only `/` matches it.
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
        assert!(reconcile_replay_guest_cwd(&conflicting, None).is_err());
        let root = RuntimeConfig::seeded(0).with_guest_cwd(Some("/")).unwrap();
        assert_eq!(reconcile_replay_guest_cwd(&root, None).unwrap(), None);
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
        let adopted = reconcile_replay_guest_env(&RuntimeConfig::seeded(0), Some(&stored)).unwrap();
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
        // A trace without an environment ran with none: supplying one conflicts.
        assert!(reconcile_replay_guest_env(&conflict, None).is_err());
        assert!(
            reconcile_replay_guest_env(&RuntimeConfig::seeded(0), None)
                .unwrap()
                .is_empty()
        );
    }
}
