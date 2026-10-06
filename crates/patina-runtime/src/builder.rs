//! Runtime construction and deterministic driver assembly.
use crate::ENV_FACTS;

use crate::buggify::Buggify;
use crate::config::{BuggifyConfig, ExecutionMode, FaultConfig, RuntimeConfig, validate_guest_env};
use crate::fs_crash::CrashCounts;
use crate::liveness::{CpuTime, LivenessWatchdog, SpinRescue, resolve_heal_after};
use crate::recording::{Execution, RecordReservation, RecordSink, TraceTransport};
use crate::replay::{
    buggify_record, dns_record, fault_record, guest_env_record, installed_clock_epoch,
    reconcile_replay_boot_origin, reconcile_replay_buggify, reconcile_replay_dns,
    reconcile_replay_faults, reconcile_replay_guest_cwd, reconcile_replay_guest_env,
    reconcile_replay_hostname, reconcile_replay_realtime_epoch, reconcile_replay_schedule_policy,
    reconcile_replay_sud, reconcile_replay_tsc, schedule_policy_record,
    validate_buggify_fingerprint_contract, watchdog_record,
};
use crate::schedule::ScheduleTracker;
use crate::swarm::apply_swarm_mask;
use crate::{Context, FactsSink, RuntimeError, TornGranularity, facts};
use patina_dst_abi::ClockKind;
use patina_dst_driver_api::{ClockDriver, EntropyDriver, FsDriver, NetDriver, SchedulerDriver};
use patina_dst_fs_crash::CrashFs;
use patina_dst_fs_mem::MemFs;
use patina_dst_net_sim::SimNet;
use patina_dst_rng_seeded::{SeededEntropy, SplitMix64, domain_seed, fault_domain};
use patina_dst_sched_det::{DetScheduler, SchedulePolicy};
use patina_dst_time_virtual::VirtualClock;
use patina_dst_trace::{BranchSession, Recorder, Replayer, RunMetadata, TraceBundle};
use patina_dst_wrapper_fault::FaultFs;
use std::collections::BTreeMap;

/// Assembles a [`Context`] from a [`RuntimeConfig`] plus a driver per effect
/// family (filesystem, clock, entropy, scheduler, network).
///
/// [`with_default_drivers`](RuntimeBuilder::with_default_drivers) installs the
/// standard deterministic set; any `with_*` driver call overrides one slot with
/// a caller-supplied implementation of the `patina-dst-driver-api` trait —
/// this is how [`run_with`] callers add latency/fault wrapper drivers or a
/// custom network. [`build`](RuntimeBuilder::build) validates the combination
/// and is the single choke point that wires config-driven fault injection
/// (e.g. the crash filesystem) so a parsed knob can never be silently dropped.
pub struct RuntimeBuilder {
    config: RuntimeConfig,
    install_defaults: bool,
    trace_transport: Option<Box<dyn TraceTransport>>,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
    /// Durable base image for the runtime-built crash/mem filesystem. Callers
    /// that want config-driven crash-consistency (the shim, and any operator
    /// path) supply the image here rather than pre-installing a filesystem, so
    /// `build` is the single choke point that constructs the `CrashFs` from
    /// `config.faults`. A pre-installed `filesystem` and an `fs_image` are
    /// mutually exclusive.
    fs_image: Option<MemFs>,
    clock: Option<Box<dyn ClockDriver>>,
    entropy: Option<Box<dyn EntropyDriver>>,
    scheduler: Option<Box<dyn SchedulerDriver>>,
    network: Option<Box<dyn NetDriver>>,
    /// Byte channel for the run's structured facts document, for embedders whose
    /// guest cannot write a host file directly (the native shim).
    facts_sink: Option<Box<dyn FactsSink>>,
}

impl RuntimeBuilder {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            install_defaults: false,
            trace_transport: None,
            filesystem: None,
            filesystem_is_capture: false,
            fs_image: None,
            clock: None,
            entropy: None,
            scheduler: None,
            network: None,
            facts_sink: None,
        }
    }

    /// Install the byte channel the run's structured facts document is written
    /// to. Mutually exclusive with [`RuntimeConfig::with_facts_path`]: two live
    /// destinations would mean one silently wins, so `build` refuses both.
    pub fn with_facts_sink(mut self, sink: impl FactsSink + 'static) -> Self {
        self.facts_sink = Some(Box::new(sink));
        self
    }

    pub fn with_default_drivers(mut self) -> Self {
        self.install_defaults = true;
        self
    }

    /// Install the byte-level trace channel required by the transport modes.
    pub fn with_trace_transport(mut self, transport: impl TraceTransport + 'static) -> Self {
        self.trace_transport = Some(Box::new(transport));
        self
    }

    pub fn with_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = false;
        self
    }

    /// Supply the durable base image the runtime wraps in its own
    /// config-driven filesystem. When `--fs-crash-at` is configured, `build`
    /// wraps this image in a [`CrashFs`] seeded and torn-write-configured from
    /// `config.faults`; otherwise the image is used directly. This is the path
    /// production callers (the shim) must use so no parsed fault knob can be
    /// silently dropped by a pre-installed filesystem — the crash filesystem is
    /// only ever constructed at the single choke point in `build`.
    pub fn with_fs_image(mut self, image: MemFs) -> Self {
        self.fs_image = Some(image);
        self
    }

    /// Install an explicitly allowlisted host-capture filesystem.
    ///
    /// Replay returns recorded filesystem outcomes without contacting the
    /// host. A branch that reaches an unrecorded filesystem operation fails.
    pub fn with_captured_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = true;
        self
    }

    pub fn with_clock(mut self, driver: impl ClockDriver + 'static) -> Self {
        self.clock = Some(Box::new(driver));
        self
    }

    pub fn with_entropy(mut self, driver: impl EntropyDriver + 'static) -> Self {
        self.entropy = Some(Box::new(driver));
        self
    }

    pub fn with_scheduler(mut self, driver: impl SchedulerDriver + 'static) -> Self {
        self.scheduler = Some(Box::new(driver));
        self
    }

    pub fn with_network(mut self, driver: impl NetDriver + 'static) -> Self {
        self.network = Some(Box::new(driver));
        self
    }

    pub fn build(mut self) -> Result<Context, RuntimeError> {
        if self.config.fingerprint.is_empty() {
            return Err(RuntimeError::Config(
                "runtime compatibility fingerprint must not be empty".into(),
            ));
        }
        validate_guest_env(&self.config.guest_env)?;
        // An explicitly installed clock owns its epoch. Read it now, unrecorded
        // (exactly as `Context::fs_clock` reads realtime), so the trace records
        // the epoch the run really reads and a configured epoch that the
        // installed clock would silently ignore is refused.
        let installed_clock_epoch = match self.clock.as_mut() {
            Some(clock) => Some(installed_clock_epoch(clock.as_mut())?),
            None => None,
        };
        if let (Some(installed), Some(configured)) =
            (installed_clock_epoch, self.config.realtime_epoch_nanos)
        {
            if installed != configured {
                return Err(RuntimeError::Config(format!(
                    "the installed clock runs on realtime epoch {installed} ns but the \
                     configured realtime epoch is {configured} ns; the configured epoch \
                     would be silently ignored. Configure the epoch on the clock or drop \
                     the explicit clock so the runtime builds it."
                )));
            }
        }
        let recorded_realtime_epoch =
            installed_clock_epoch.unwrap_or_else(|| self.config.realtime_epoch_nanos());
        let installed_boot_origin = self
            .clock
            .as_mut()
            .map(|clock| clock.now(ClockKind::Monotonic))
            .transpose()?;
        if let (Some(installed), Some(configured)) =
            (installed_boot_origin, self.config.boot_origin_nanos)
        {
            if installed != configured {
                return Err(RuntimeError::Config(
                    "installed clock conflicts with configured boot origin".into(),
                ));
            }
        }
        let recorded_boot_origin =
            installed_boot_origin.unwrap_or_else(|| self.config.boot_origin_nanos());
        if recorded_boot_origin == 0 || recorded_boot_origin > i64::MAX as u64 {
            return Err(RuntimeError::Config(
                "boot origin must be nonzero and fit signed 64-bit nanoseconds".into(),
            ));
        }

        match self.config.mode {
            ExecutionMode::RecordTransport | ExecutionMode::ReplayTransport { .. } => {
                if self.trace_transport.is_none() {
                    return Err(RuntimeError::Config(
                        "trace transport mode requires an installed trace transport".into(),
                    ));
                }
            }
            _ => {
                if self.trace_transport.is_some() {
                    return Err(RuntimeError::Config(
                        "a trace transport is only usable with transport record/replay modes"
                            .into(),
                    ));
                }
            }
        }
        if matches!(
            self.config.mode,
            ExecutionMode::Seeded | ExecutionMode::Record { .. } | ExecutionMode::RecordTransport
        ) {
            validate_buggify_fingerprint_contract(&self.config)?;
        }

        // Swarm fault-class selection: for a record/seeded run, mask the enabled
        // fault classes down to a seed-derived subset BEFORE any driver or
        // metadata record consumes `self.config.faults`. Not applied on
        // replay/branch, where the trace's recorded (already-masked) fault config
        // is authoritative and re-masking would double-select. The record is
        // attached to the recorder metadata below.
        let mut swarm_record = if self.config.swarm
            && matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ) {
            Some(apply_swarm_mask(&mut self.config))
        } else {
            None
        };

        // A replayed or branched trace supplies its own authoritative fault
        // configuration, applied to `self.config` after the match releases its
        // borrow. `None` leaves the operator-supplied configuration in place.
        let mut replay_fault_override: Option<FaultConfig> = None;
        // Same contract for the cooperative-SUT (buggify) configuration: a
        // replayed/branched trace's recorded config is authoritative.
        let mut replay_buggify_override: Option<BuggifyConfig> = None;
        // Same contract for deterministic guest environment values.
        let mut replay_guest_env_override: Option<BTreeMap<String, String>> = None;
        // Same contract for the guest's initial working directory.
        let mut replay_guest_cwd_override: Option<String> = None;
        // Same contract for clock origins and the node name.
        let mut replay_realtime_epoch_override: Option<u64> = None;
        let mut replay_boot_origin_override = None;
        let mut replay_hostname_override: Option<String> = None;
        let mut replay_dns_override: Option<BTreeMap<String, String>> = None;
        // Same contract for the exploration scheduling policy.
        let mut replay_schedule_override: Option<SchedulePolicy> = None;
        let (execution, root_seed) = match &self.config.mode {
            ExecutionMode::Seeded => (Execution::Seeded, self.config.seed),
            ExecutionMode::Record { path } => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(
                            self.config.seed,
                            self.config.fingerprint.clone(),
                            recorded_realtime_epoch,
                            self.config.hostname(),
                        )
                        .with_boot_origin_nanos(recorded_boot_origin)
                        .with_faults(Some(fault_record(&self.config)))
                        .with_buggify(buggify_record(&self.config))
                        .with_schedule_policy(schedule_policy_record(&self.config))
                        .with_swarm(swarm_record.clone())
                        .with_watchdog(watchdog_record(&self.config))
                        .with_guest_argv(self.config.guest_argv.clone())
                        .with_guest_env(guest_env_record(&self.config))
                        .with_guest_cwd(self.config.guest_cwd.clone())
                        .with_dns(dns_record(&self.config))
                        .with_sud(self.config.sud)
                        .with_tsc(self.config.tsc),
                    )
                    .with_incarnation(self.config.incarnation),
                    sink: RecordSink::Path {
                        path: path.clone(),
                        _reservation: RecordReservation::acquire(path)?,
                    },
                },
                self.config.seed,
            ),
            ExecutionMode::RecordTransport => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(
                            self.config.seed,
                            self.config.fingerprint.clone(),
                            recorded_realtime_epoch,
                            self.config.hostname(),
                        )
                        .with_boot_origin_nanos(recorded_boot_origin)
                        .with_faults(Some(fault_record(&self.config)))
                        .with_buggify(buggify_record(&self.config))
                        .with_schedule_policy(schedule_policy_record(&self.config))
                        .with_swarm(swarm_record.clone())
                        .with_watchdog(watchdog_record(&self.config))
                        .with_guest_argv(self.config.guest_argv.clone())
                        .with_guest_env(guest_env_record(&self.config))
                        .with_guest_cwd(self.config.guest_cwd.clone())
                        .with_dns(dns_record(&self.config))
                        .with_sud(self.config.sud)
                        .with_tsc(self.config.tsc),
                    )
                    .with_incarnation(self.config.incarnation),
                    sink: RecordSink::Transport(
                        self.trace_transport.take().expect("transport was checked"),
                    ),
                },
                self.config.seed,
            ),
            ExecutionMode::Replay { path, timeline } => {
                let replayer = Replayer::open_timeline(path, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                replay_boot_origin_override = Some(reconcile_replay_boot_origin(
                    &self.config,
                    installed_boot_origin,
                    replayer.boot_origin_nanos(),
                )?);
                // The trace's fault configuration is authoritative on replay.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, replayer.guest_env())?;
                replay_guest_cwd_override =
                    reconcile_replay_guest_cwd(&self.config, replayer.guest_cwd())?;
                replay_realtime_epoch_override = Some(reconcile_replay_realtime_epoch(
                    &self.config,
                    installed_clock_epoch,
                    replayer.realtime_epoch_nanos(),
                )?);
                replay_hostname_override = Some(reconcile_replay_hostname(
                    &self.config,
                    replayer.hostname(),
                )?);
                replay_dns_override = reconcile_replay_dns(&self.config, replayer.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                reconcile_replay_sud(&self.config, replayer.sud())?;
                reconcile_replay_tsc(&self.config, replayer.tsc())?;
                // The recording's swarm decision is authoritative and purely
                // descriptive on replay (the trace's already-masked fault/buggify
                // records drive the drivers). Adopting it makes a replay emit the
                // same PATINA_SWARM_REPORT and swarm_deselected the recording did.
                swarm_record = replayer.swarm_config().cloned();
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::ReplayTransport { timeline } => {
                let mut transport = self.trace_transport.take().expect("transport was checked");
                let bytes = transport.read_bundle().map_err(|source| RuntimeError::Io {
                    action: "read trace bundle from trace transport".into(),
                    source,
                })?;
                let bundle = TraceBundle::from_slice(&bytes)?;
                let replayer = Replayer::from_bundle(bundle, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                replay_boot_origin_override = Some(reconcile_replay_boot_origin(
                    &self.config,
                    installed_boot_origin,
                    replayer.boot_origin_nanos(),
                )?);
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, replayer.guest_env())?;
                replay_guest_cwd_override =
                    reconcile_replay_guest_cwd(&self.config, replayer.guest_cwd())?;
                replay_realtime_epoch_override = Some(reconcile_replay_realtime_epoch(
                    &self.config,
                    installed_clock_epoch,
                    replayer.realtime_epoch_nanos(),
                )?);
                replay_hostname_override = Some(reconcile_replay_hostname(
                    &self.config,
                    replayer.hostname(),
                )?);
                replay_dns_override = reconcile_replay_dns(&self.config, replayer.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                reconcile_replay_sud(&self.config, replayer.sud())?;
                reconcile_replay_tsc(&self.config, replayer.tsc())?;
                swarm_record = replayer.swarm_config().cloned();
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::Branch {
                path,
                parent,
                from_sequence,
                branch_id,
                branch_seed,
            } => {
                let reservation = RecordReservation::acquire_branch(path)?;
                let session = BranchSession::open(
                    path,
                    &self.config.fingerprint,
                    parent,
                    *from_sequence,
                    branch_id.clone(),
                    *branch_seed,
                )?;
                replay_boot_origin_override = Some(reconcile_replay_boot_origin(
                    &self.config,
                    installed_boot_origin,
                    session.boot_origin_nanos(),
                )?);
                // A branch replays the parent prefix, so it inherits the parent
                // trace's fault configuration for the replayed drivers.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, session.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, session.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, session.guest_env())?;
                replay_guest_cwd_override =
                    reconcile_replay_guest_cwd(&self.config, session.guest_cwd())?;
                replay_realtime_epoch_override = Some(reconcile_replay_realtime_epoch(
                    &self.config,
                    installed_clock_epoch,
                    session.realtime_epoch_nanos(),
                )?);
                replay_hostname_override =
                    Some(reconcile_replay_hostname(&self.config, session.hostname())?);
                replay_dns_override = reconcile_replay_dns(&self.config, session.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, session.schedule_policy())?;
                // A branch inherits the parent's swarm decision along with its
                // fault configuration; it does not re-draw the mask.
                swarm_record = session.swarm_config().cloned();
                (
                    Execution::Branch {
                        session: Box::new(session),
                        _reservation: reservation,
                    },
                    *branch_seed,
                )
            }
        };

        // Adopt the trace's authoritative fault configuration before any driver
        // is constructed from it, so a flag-free replay rebuilds the same
        // CrashFs/SimNet the recording used.
        if let Some(faults) = replay_fault_override {
            self.config.faults = faults;
        }
        // Adopt the trace's authoritative buggify configuration so a flag-free
        // replay re-derives the same activation and firing decisions.
        if let Some(buggify) = replay_buggify_override {
            self.config.buggify = buggify;
        }
        // Adopt the trace's authoritative guest environment values so a flag-free
        // replay reproduces environment-dependent guest behavior.
        if let Some(guest_env) = replay_guest_env_override {
            self.config.guest_env = guest_env;
        }
        // Likewise the initial working directory, so a flag-free replay
        // resolves the recording's relative paths against the same directory.
        if let Some(guest_cwd) = replay_guest_cwd_override {
            self.config.guest_cwd = Some(guest_cwd);
        }
        // Adopt both clock origins, including for unrecorded filesystem stamps
        // and elapsed-run fault windows. An installed clock owns its epoch, so
        // validate the actual pair rather than an unused configured default.
        if let Some(origin) = replay_boot_origin_override {
            self.config.boot_origin_nanos = Some(origin);
        }
        let boot_origin_nanos = replay_boot_origin_override.unwrap_or(recorded_boot_origin);
        let realtime_epoch = replay_realtime_epoch_override.unwrap_or(recorded_realtime_epoch);
        realtime_epoch
            .checked_add(boot_origin_nanos)
            .filter(|nanos| *nanos <= i64::MAX as u64)
            .ok_or_else(|| {
                RuntimeError::Config("initial realtime must fit signed 64-bit nanoseconds".into())
            })?;
        if let Some(epoch) = replay_realtime_epoch_override {
            self.config.realtime_epoch_nanos = Some(epoch);
        }
        // Likewise the node name, so a flag-free replay's guest reads the name
        // the recording's did.
        if let Some(hostname) = replay_hostname_override {
            self.config.hostname = Some(hostname);
        }
        // Likewise the trace's authoritative DNS host table, so a flag-free
        // replay resolves exactly the names the recording could.
        if let Some(entries) = replay_dns_override {
            self.config.dns_entries = entries;
        }
        // Adopt the trace's authoritative exploration scheduling policy. Replay
        // consumes recorded task selections directly (through `select`), so the
        // policy does not steer replay; adopting it keeps the built scheduler
        // consistent and the reconcile above provides the fail-closed guard.
        if let Some(policy) = replay_schedule_override {
            self.config.schedule_policy = policy;
        }
        validate_buggify_fingerprint_contract(&self.config)?;

        // The crash-consistency filesystem is built HERE, and only here, from
        // `config.faults` — the single choke point that always consumes the
        // parsed crash knobs. Callers pass the durable base image via
        // `with_fs_image`; they must not pre-install the final filesystem, so a
        // knob like `--fs-torn-granularity` can never be silently dropped by a
        // filesystem that bypassed the fault config (the gap this replaced).
        let fs_fault_knobs_set = self.config.faults.fs.crash_at.is_some()
            || self.config.faults.fs.torn_granularity != TornGranularity::default()
            || self.config.faults.fs.error_permille != 0
            || self.config.faults.fs.short_permille != 0;
        if self.filesystem.is_some() {
            // An explicit filesystem (`with_filesystem`/`with_captured_filesystem`)
            // cannot reflect config-driven fs fault knobs, and an accompanying base
            // image would be ignored. Fail closed rather than proceed silently.
            if fs_fault_knobs_set {
                return Err(RuntimeError::Config(
                    "a filesystem was installed explicitly while filesystem fault \
                     knobs (--fs-crash-at / --fs-torn-granularity / \
                     --fs-error-permille / --fs-short-permille) are set; those \
                     knobs would be silently ignored. Supply the durable image via \
                     RuntimeBuilder::with_fs_image so the runtime builds the \
                     filesystem from the fault configuration."
                        .into(),
                ));
            }
            if self.fs_image.is_some() {
                return Err(RuntimeError::Config(
                    "both an explicit filesystem and a base image were provided; \
                     use exactly one"
                        .into(),
                ));
            }
        }
        if self.install_defaults {
            // The base image is ALWAYS wrapped in a config-driven `CrashFs`,
            // whether or not `--fs-crash-at` is set. This preserves the historical
            // always-`CrashFs` behavior the shim relied on: a `CrashFs` is
            // crashable, so imperative callers that trigger `fs_crash()` manually
            // (the C-ABI `patina_init_crash` path, the WASI-host crash probes)
            // keep working. A bare `MemFs` cannot crash — `FsDriver::crash`
            // returns `InvalidState` — so installing one here regressed those
            // paths. An un-crashed `CrashFs` reads/writes identically to its inner
            // `MemFs` and consumes no seeded entropy, so non-crash runs are
            // byte-for-byte unchanged.
            if self.filesystem.is_none() {
                // NOT `unwrap_or_default()`: `MemFs::new()` seeds the root `/`
                // directory, while `MemFs::default()` is ROOTLESS. A caller that
                // uses `with_default_drivers` without `with_fs_image` (e.g.
                // `Context::from_config`) would otherwise get a rootless
                // filesystem and fail every path op with NotFound. Clippy's
                // `unwrap_or_default` suggestion is wrong here because the two
                // constructors are not equivalent.
                #[allow(clippy::unwrap_or_default)]
                let base = self.fs_image.take().unwrap_or_else(MemFs::new);
                let crash_fs = CrashFs::builder()
                    .filesystem(base)
                    .seed(domain_seed(root_seed, fault_domain::FS_CRASH))
                    .torn_granularity(self.config.faults.fs.torn_granularity)
                    .build()
                    .map_err(RuntimeError::Effect)?;
                self.filesystem = Some(Box::new(
                    FaultFs::new(crash_fs, root_seed)
                        .error_permille(self.config.faults.fs.error_permille)
                        .short_permille(self.config.faults.fs.short_permille)
                        .latency_live(self.config.faults.fs.latency_nanos.is_some()),
                ));
            }
            self.clock.get_or_insert_with(|| {
                Box::new(VirtualClock::at(boot_origin_nanos, realtime_epoch))
            });
            self.entropy.get_or_insert_with(|| {
                Box::new(SeededEntropy::new(domain_seed(
                    root_seed,
                    fault_domain::ENTROPY,
                )))
            });
            self.scheduler.get_or_insert_with(|| {
                Box::new(DetScheduler::with_policy(
                    root_seed,
                    self.config.schedule_policy,
                ))
            });
            if self.network.is_none() {
                let net = &self.config.faults.net;
                let mut network = SimNet::builder()
                    .base_latency_nanos(net.latency_nanos)
                    .fault_seed(domain_seed(root_seed, fault_domain::NET_FAULT))
                    .drop_permille(net.drop_permille)
                    .duplicate_permille(net.duplicate_permille)
                    .connect_refuse_permille(net.connect_refuse_permille)
                    .reset_permille(net.reset_permille);
                if let Some((min, max)) = net.jitter_nanos {
                    network = network.jitter_nanos(min, max);
                }
                if let Some(bytes) = net.tcp_buffer_bytes {
                    network = network.tcp_buffer_bytes(bytes);
                }
                for (left, right) in &net.partitions {
                    network = network.partition(left.clone(), right.clone());
                }
                self.network = Some(Box::new(network.build().map_err(RuntimeError::Effect)?));
            }
        }

        // A base image is only ever consumed by the default-driver choke point
        // above. If one survives, `with_fs_image` was used without
        // `with_default_drivers`, so it would be silently dropped — fail closed.
        if self.fs_image.is_some() {
            return Err(RuntimeError::Config(
                "with_fs_image requires with_default_drivers so the runtime can \
                 build the filesystem from it"
                    .into(),
            ));
        }

        // Build the liveness watchdog before the Context literal consumes
        // `self.config` fields. The heal-then-converge arm arms at the fault-window
        // end: an explicit override, else the buggify damage-control cutoff (when
        // buggify is enabled), else run start. Detection is live only on a
        // record/seeded run; a replay consumes the authoritative trace.
        let liveness = LivenessWatchdog::new(
            self.config.liveness,
            resolve_heal_after(&self.config),
            boot_origin_nanos,
            matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ),
        );

        // The facts channel: exactly one destination, or none. Two live
        // destinations would silently drop one document, so refuse.
        let facts = match (self.facts_sink.take(), self.config.facts_path.take()) {
            (None, None) => None,
            (Some(sink), None) => Some(facts::FactsOutput::Sink(sink)),
            (None, Some(path)) => Some(facts::FactsOutput::Path(path)),
            (Some(_), Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "a run-facts sink and a facts path ({ENV_FACTS}) were both installed; use exactly one"
                )));
            }
        };

        let compute_stop = match &execution {
            Execution::Replay(replayer) => replayer.compute_stop(),
            _ => None,
        };
        // Reuse the existing boundary-budget check: healthy scheduling points
        // gain no watchdog counter, clock read, atomic, or additional branch.
        if let Some(stop) = compute_stop {
            self.config.step_budget = Some(
                self.config
                    .step_budget
                    .map_or(stop.steps, |budget| budget.min(stop.steps)),
            );
        }
        Ok(Context {
            compute_stop,
            boot_origin_nanos,
            root_seed,
            compatibility_fingerprint: self.config.fingerprint.clone(),
            step_budget: self.config.step_budget,
            steps: 0,
            params: self.config.params,
            guest_env: self.config.guest_env,
            guest_cwd: self.config.guest_cwd,
            hostname: self
                .config
                .hostname
                .unwrap_or_else(|| patina_dst_syscalls::IDENTITY_HOSTNAME.to_owned()),
            execution,
            filesystem: self.filesystem,
            filesystem_is_capture: self.filesystem_is_capture,
            clock: self.clock,
            entropy: self.entropy,
            scheduler: self.scheduler,
            network: self.network,
            timers: BTreeMap::new(),
            timer_by_task: BTreeMap::new(),
            timer_seq: 0,
            scheduler_tasks: std::collections::BTreeSet::new(),
            parked_tasks: std::collections::BTreeSet::new(),
            rescued: Vec::new(),
            crash_at: self.config.faults.fs.crash_at,
            crash_counts: CrashCounts::default(),
            // A run has one crash selector and incarnation 0 is the one it
            // fires in; every later incarnation starts after it has fired.
            crash_fired: self.config.incarnation > 0,
            incarnation: self.config.incarnation,
            require_crash_selector_reached: self.config.require_crash_selector_reached,
            sleep_jitter_nanos: self.config.faults.clock.sleep_jitter_nanos,
            // Domain-separated seed so sleep-jitter draws do not correlate with
            // the entropy or network-fault streams that also derive from root_seed.
            sleep_jitter_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::SLEEP_JITTER)),
            fs_latency_nanos: self.config.faults.fs.latency_nanos,
            fs_latency_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::FS_LATENCY)),
            fs_latency_eligible_ops: 0,
            fs_latency_applied: 0,
            dns_entries: self.config.dns_entries,
            dns_fail_permille: self.config.faults.dns.fail_permille,
            dns_fault_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::DNS_FAULT)),
            dns_latency_nanos: self.config.faults.dns.latency_nanos,
            dns_latency_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::DNS_LATENCY)),
            dns_report: patina_dst_driver_api::DnsFaultReport::default(),
            entropy_fail_permille: self.config.faults.entropy.fail_permille,
            entropy_fault_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::ENTROPY_FAULT)),
            entropy_report: patina_dst_driver_api::EntropyFaultReport::default(),
            epoch_jump_nanos: self.config.faults.clock.epoch_jump_nanos,
            epoch_jump_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::EPOCH_JUMP)),
            clock_report: patina_dst_driver_api::ClockFaultReport::default(),
            schedule: ScheduleTracker::default(),
            buggify: Buggify::new(self.config.buggify, root_seed),
            verdicts: Vec::new(),
            custom_op: None,
            custom_op_fail_permille: self.config.faults.custom_op.fail_permille,
            custom_op_fault_root: domain_seed(root_seed, fault_domain::CUSTOM_OP_FAULT),
            custom_op_fault_rngs: BTreeMap::new(),
            custom_op_report: patina_dst_driver_api::CustomOpFaultReport::default(),
            pending_diagnostics: Vec::new(),
            liveness,
            swarm: swarm_record,
            reports: self.config.reports,
            facts,
            facts_emitted: false,
            spin: SpinRescue {
                baseline_nanos: boot_origin_nanos,
                ..SpinRescue::default()
            },
            cpu: CpuTime::default(),
            alarm: None,
            cpu_alarm: None,
            recording_flushed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::RuntimeBuilder;
    use crate::config::RuntimeConfig;
    use crate::{Context, RuntimeError};
    use patina_dst_abi::{ClockKind, EffectError, ErrorCode, SendDisposition};
    use patina_dst_driver_api::{EntropyDriver, NetDriver};
    use patina_dst_net_sim::SimNet;
    use patina_dst_rng_seeded::{SeededEntropy, SplitMix64, domain_seed, fault_domain};

    #[test]
    fn default_driver_streams_are_domain_separated() {
        let seed = 7;

        let mut context = Context::from_config(RuntimeConfig::seeded(seed)).unwrap();
        let actual_entropy = context.entropy_bytes(24).unwrap();
        context.finish().unwrap();

        let mut expected_entropy = SeededEntropy::new(domain_seed(seed, fault_domain::ENTROPY));
        let mut expected = [0; 24];
        expected_entropy.fill(&mut expected).unwrap();
        assert_eq!(actual_entropy, expected);

        let mut old_aliased_entropy = SeededEntropy::new(seed);
        let mut old = [0; 24];
        old_aliased_entropy.fill(&mut old).unwrap();
        assert_ne!(
            actual_entropy, old,
            "RED-before-GREEN: old runtime entropy used SplitMix64::new(root_seed)"
        );

        fn runtime_drop_pattern(seed: u64) -> Vec<SendDisposition> {
            let mut context =
                Context::from_config(RuntimeConfig::seeded(seed).with_net_drop_permille(500))
                    .unwrap();
            let tx = context.net_bind("tx").unwrap();
            context.net_bind("rx").unwrap();
            let pattern = (0..64)
                .map(|seq| {
                    context
                        .net_send(tx, "rx", &[seq as u8])
                        .unwrap()
                        .disposition
                })
                .collect();
            context.finish().unwrap();
            pattern
        }

        fn sim_drop_pattern(fault_seed: u64) -> Vec<SendDisposition> {
            let mut net = SimNet::builder()
                .fault_seed(fault_seed)
                .drop_permille(500)
                .build()
                .unwrap();
            let tx = net.bind("tx").unwrap();
            net.bind("rx").unwrap();
            (0..64)
                .map(|seq| net.send(tx, "rx", &[seq as u8], 0).unwrap().disposition)
                .collect()
        }

        let runtime_pattern = runtime_drop_pattern(seed);
        assert_eq!(
            runtime_pattern,
            sim_drop_pattern(domain_seed(seed, fault_domain::NET_FAULT))
        );
        assert_ne!(
            runtime_pattern,
            sim_drop_pattern(seed),
            "RED-before-GREEN: old SimNet fault stream used the root seed directly"
        );

        let jittered = {
            let mut context = Context::from_config(
                RuntimeConfig::seeded(seed).with_sleep_jitter_nanos(500, 1_500),
            )
            .unwrap();
            let start = context.now(ClockKind::Monotonic).unwrap();
            context.sleep_for(1_000).unwrap();
            let elapsed = context.now(ClockKind::Monotonic).unwrap() - start;
            context.finish().unwrap();
            elapsed
        };
        let mut sleep_rng = SplitMix64::new(domain_seed(seed, fault_domain::SLEEP_JITTER));
        let expected_jitter = 500 + (sleep_rng.next_u64() % 1_001);
        assert_eq!(jittered, 1_000 + expected_jitter);
    }

    #[test]
    fn missing_drivers_fail_without_fallback() {
        let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .build()
            .unwrap();
        let error = context.entropy_bytes(1).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Effect(EffectError {
                code: ErrorCode::MissingDriver,
                ..
            })
        ));
    }
}
