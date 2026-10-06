//! Trace metadata conversion and authoritative replay configuration reconciliation.

use crate::config::{
    BuggifyConfig, ClockFaultConfig, CustomOpFaultConfig, DnsFaultConfig, EntropyFaultConfig,
    FaultConfig, FsFaultConfig, NetFaultConfig, RuntimeConfig,
};
use crate::liveness::resolve_heal_after;
use crate::{FINGERPRINT_BUGGIFY, RuntimeError, TornGranularity};
use patina_dst_abi::ClockKind;
use patina_dst_driver_api::ClockDriver;
use patina_dst_sched_det::{PctConfig, SchedulePolicy, StarvationConfig};
use std::collections::BTreeMap;

fn torn_granularity_to_record(granularity: TornGranularity) -> patina_dst_trace::TornGranularity {
    match granularity {
        TornGranularity::Block => patina_dst_trace::TornGranularity::Block,
        TornGranularity::Byte => patina_dst_trace::TornGranularity::Byte,
    }
}

fn torn_granularity_from_record(granularity: patina_dst_trace::TornGranularity) -> TornGranularity {
    match granularity {
        patina_dst_trace::TornGranularity::Block => TornGranularity::Block,
        patina_dst_trace::TornGranularity::Byte => TornGranularity::Byte,
    }
}

/// Serialize the run's liveness-watchdog configuration into the trace metadata.
/// Informational only — NOT a fingerprint input and NOT reconciled on replay,
/// because the watchdog is schedule-invariant. `None` when the watchdog is off.
pub(super) fn watchdog_record(
    config: &RuntimeConfig,
) -> Option<patina_dst_trace::WatchdogConfigRecord> {
    if !config.liveness.is_enabled() {
        return None;
    }
    Some(patina_dst_trace::WatchdogConfigRecord {
        no_progress_budget_nanos: config.liveness.no_progress_budget_nanos,
        converge_budget_nanos: config.liveness.converge_budget_nanos,
        heal_after_nanos: config
            .liveness
            .converge_budget_nanos
            .map(|_| resolve_heal_after(config)),
    })
}

/// Serialize the run's DNS host table into the trace record, or `None` when the
/// run defined no names — an empty table records nothing, so a DNS-free run's
/// metadata is byte-identical to before.
pub(super) fn dns_record(config: &RuntimeConfig) -> Option<patina_dst_trace::DnsConfigRecord> {
    (!config.dns_entries.is_empty()).then(|| patina_dst_trace::DnsConfigRecord {
        entries: config.dns_entries.clone(),
    })
}

/// Serialize the run's effective fault configuration into the trace record so a
/// fault run replays self-contained. `net_latency_nanos` is folded in because it
/// too shapes the recorded operation stream, so a flag-free replay must restore
/// it as well.
pub(super) fn fault_record(config: &RuntimeConfig) -> patina_dst_trace::FaultConfigRecord {
    patina_dst_trace::FaultConfigRecord {
        crash_at: config.faults.fs.crash_at.map(Into::into),
        torn_granularity: torn_granularity_to_record(config.faults.fs.torn_granularity),
        fs_error_permille: config.faults.fs.error_permille,
        fs_short_permille: config.faults.fs.short_permille,
        fs_latency_nanos: config.faults.fs.latency_nanos,
        sleep_jitter_nanos: config.faults.clock.sleep_jitter_nanos,
        net_jitter_nanos: config.faults.net.jitter_nanos,
        net_drop_permille: config.faults.net.drop_permille,
        net_latency_nanos: config.faults.net.latency_nanos,
        net_duplicate_permille: config.faults.net.duplicate_permille,
        net_connect_refuse_permille: config.faults.net.connect_refuse_permille,
        net_reset_permille: config.faults.net.reset_permille,
        net_partitions: config.faults.net.partitions.clone(),
        net_tcp_buffer_bytes: config.faults.net.tcp_buffer_bytes.map(|bytes| bytes as u64),
        dns_fail_permille: config.faults.dns.fail_permille,
        dns_latency_nanos: config.faults.dns.latency_nanos,
        entropy_fail_permille: config.faults.entropy.fail_permille,
        epoch_jump_nanos: config.faults.clock.epoch_jump_nanos,
        custom_op_fail_permille: config.faults.custom_op.fail_permille,
    }
}

/// Rebuild the runtime fault configuration from a recorded trace's authoritative
/// fault metadata.
pub(super) fn fault_config_from_record(
    record: &patina_dst_trace::FaultConfigRecord,
) -> FaultConfig {
    FaultConfig {
        fs: FsFaultConfig {
            crash_at: record.crash_at.map(Into::into),
            torn_granularity: torn_granularity_from_record(record.torn_granularity),
            error_permille: record.fs_error_permille,
            short_permille: record.fs_short_permille,
            latency_nanos: record.fs_latency_nanos,
        },
        net: NetFaultConfig {
            latency_nanos: record.net_latency_nanos,
            jitter_nanos: record.net_jitter_nanos,
            drop_permille: record.net_drop_permille,
            duplicate_permille: record.net_duplicate_permille,
            connect_refuse_permille: record.net_connect_refuse_permille,
            reset_permille: record.net_reset_permille,
            partitions: record.net_partitions.clone(),
            // A recorded buffer size cannot exceed this target's `usize` in any
            // realistic trace, but saturate rather than wrap if one ever does:
            // a wrapped buffer would silently change would-block behavior.
            tcp_buffer_bytes: record
                .net_tcp_buffer_bytes
                .map(|bytes| usize::try_from(bytes).unwrap_or(usize::MAX)),
        },
        clock: ClockFaultConfig {
            sleep_jitter_nanos: record.sleep_jitter_nanos,
            epoch_jump_nanos: record.epoch_jump_nanos,
        },
        dns: DnsFaultConfig {
            fail_permille: record.dns_fail_permille,
            latency_nanos: record.dns_latency_nanos,
        },
        entropy: EntropyFaultConfig {
            fail_permille: record.entropy_fail_permille,
        },
        custom_op: CustomOpFaultConfig {
            fail_permille: record.custom_op_fail_permille,
        },
    }
}

/// Reconcile a recorded trace's authoritative fault configuration with any fault
/// knobs the operator also supplied at replay. The trace is authoritative: when
/// no knobs are supplied (the default), the stored configuration is adopted
/// verbatim so replay is byte-identical; when knobs ARE supplied they must match
/// the recording exactly or replay fails closed rather than silently running a
/// different fault schedule. A pre-metadata trace (`None`) keeps the historical
/// re-supply behavior.
pub(super) fn reconcile_replay_faults(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::FaultConfigRecord>,
) -> Result<Option<FaultConfig>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored_faults = fault_config_from_record(record);
    let supplied_any = config.faults != FaultConfig::default();
    if supplied_any && config.faults != stored_faults {
        return Err(RuntimeError::Config(
            "replay fault knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored_faults))
}

/// The buggify configuration recorded into a trace at build time. `active_sites`
/// and `knobs` are filled in at finalization from the run's realized picks; here
/// they start empty. `None` when buggify is disabled, so a disabled run records
/// no buggify metadata at all and is indistinguishable from an old trace.
pub(super) fn buggify_record(
    config: &RuntimeConfig,
) -> Option<patina_dst_trace::BuggifyConfigRecord> {
    if !config.buggify.enabled {
        return None;
    }
    Some(patina_dst_trace::BuggifyConfigRecord {
        fire_permille: config.buggify.fire_permille,
        activation_permille: config.buggify.activation_permille,
        cutoff_nanos: config.buggify.cutoff_nanos,
        after_setup: config.buggify.after_setup,
        active_sites: Vec::new(),
        knobs: BTreeMap::new(),
    })
}

/// Refuse a run whose fingerprint claims cooperative-SUT coverage the config
/// cannot deliver. This stays exactly as strict as it was for genuine
/// incoherence; a swarm-masked generation passes because [`apply_swarm_mask`] has
/// already retracted [`FINGERPRINT_BUGGIFY`] from the fingerprint, so the run's
/// declared state is truthful rather than merely tolerated.
pub(super) fn validate_buggify_fingerprint_contract(
    config: &RuntimeConfig,
) -> Result<(), RuntimeError> {
    if fingerprint_declares_component(&config.fingerprint, FINGERPRINT_BUGGIFY)
        && !config.buggify.enabled
    {
        return Err(RuntimeError::Config(
            "fingerprint declares +buggify but buggify is not enabled; refusing vacuous SDK buggify coverage"
                .into(),
        ));
    }
    Ok(())
}

fn fingerprint_declares_component(fingerprint: &str, component: &str) -> bool {
    fingerprint.split('+').skip(1).any(|part| part == component)
}

/// Rebuild a [`BuggifyConfig`] from a recorded trace's authoritative buggify
/// metadata.
fn buggify_config_from_record(record: &patina_dst_trace::BuggifyConfigRecord) -> BuggifyConfig {
    BuggifyConfig {
        enabled: true,
        fire_permille: record.fire_permille,
        activation_permille: record.activation_permille,
        cutoff_nanos: record.cutoff_nanos,
        after_setup: record.after_setup,
    }
}

/// Reconcile a recorded trace's authoritative buggify configuration with any
/// buggify knobs the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no knobs the
/// stored config is adopted verbatim (byte-identical replay); supplied knobs
/// must match exactly or replay fails closed. A trace recorded without buggify
/// (`None`) means the operator's configuration stands — and if the operator
/// tries to enable buggify on a non-buggify trace, that is caught earlier by the
/// `+buggify` fingerprint mismatch.
pub(super) fn reconcile_replay_buggify(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::BuggifyConfigRecord>,
) -> Result<Option<BuggifyConfig>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = buggify_config_from_record(record);
    if config.buggify.enabled && config.buggify != stored {
        return Err(RuntimeError::Config(
            "replay buggify knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// Reconcile a recorded trace's authoritative initial working directory with
/// any value supplied to the replaying process. The trace is authoritative: with
/// no value supplied the stored one is adopted; a supplied value must match
/// exactly or replay fails closed. A pre-cwd trace (`None`) keeps the supplied
/// value for embedders.
pub(super) fn reconcile_replay_guest_cwd(
    config: &RuntimeConfig,
    recorded: Option<&str>,
) -> Result<Option<String>, RuntimeError> {
    let Some(stored) = recorded else {
        return Ok(None);
    };
    if config
        .guest_cwd
        .as_deref()
        .is_some_and(|supplied| supplied != stored)
    {
        return Err(RuntimeError::Config(
            "replay --cwd conflicts with the trace's recorded guest working directory; \
             the trace is authoritative, so omit the flag (or supply the matching value)"
                .into(),
        ));
    }
    Ok(Some(stored.to_owned()))
}

/// The realtime epoch an installed clock driver runs on: its realtime reading
/// minus its monotonic one, both read unrecorded (the values are a pure
/// function of the clock's configuration, as `Context::fs_clock` relies on).
pub(super) fn installed_clock_epoch(clock: &mut dyn ClockDriver) -> Result<u64, RuntimeError> {
    let realtime = clock.now(ClockKind::Realtime)?;
    let monotonic = clock.now(ClockKind::Monotonic)?;
    realtime.checked_sub(monotonic).ok_or_else(|| {
        RuntimeError::Config(
            "the installed clock reads realtime behind monotonic, so it has no \
             realtime epoch to record"
                .into(),
        )
    })
}

/// Reconcile the trace's recorded realtime epoch against this run's. The trace
/// is authoritative: an explicitly configured epoch (`--realtime-epoch` /
/// [`ENV_REALTIME_EPOCH_NANOS`]) or an explicitly installed clock on any other
/// epoch is refused rather than replayed with different wall-clock reads. An
/// unconfigured run adopts the recorded epoch, whatever the current default is.
pub(super) fn reconcile_replay_realtime_epoch(
    config: &RuntimeConfig,
    installed_clock_epoch: Option<u64>,
    recorded: u64,
) -> Result<u64, RuntimeError> {
    if let Some(supplied) = config.realtime_epoch_nanos
        && supplied != recorded
    {
        return Err(RuntimeError::Config(format!(
            "replay --realtime-epoch ({supplied} ns) conflicts with the trace's recorded \
                 realtime epoch ({recorded} ns); the trace is authoritative, so omit the \
                 flag (or supply the matching value)"
        )));
    }
    if let Some(installed) = installed_clock_epoch
        && installed != recorded
    {
        return Err(RuntimeError::Config(format!(
            "the installed clock runs on realtime epoch {installed} ns but the trace \
                 was recorded on {recorded} ns; install a clock on the recorded epoch or \
                 let the runtime build it"
        )));
    }
    Ok(recorded)
}

pub(super) fn reconcile_replay_boot_origin(
    config: &RuntimeConfig,
    installed: Option<u64>,
    recorded: u64,
) -> Result<u64, RuntimeError> {
    if recorded == 0
        || recorded > i64::MAX as u64
        || [config.boot_origin_nanos, installed]
            .into_iter()
            .flatten()
            .any(|nanos| nanos != recorded)
    {
        return Err(RuntimeError::Config(format!(
            "boot origin conflicts with the trace's recorded origin ({recorded} ns); the trace is authoritative and the origin must be nonzero and fit signed 64-bit nanoseconds"
        )));
    }
    Ok(recorded)
}

/// Reconcile the trace's recorded node name against this run's. The trace is
/// authoritative: an explicitly configured name (`--hostname` /
/// [`ENV_GUEST_HOSTNAME`]) that differs is refused; an unconfigured run adopts
/// the recorded one.
pub(super) fn reconcile_replay_hostname(
    config: &RuntimeConfig,
    recorded: &str,
) -> Result<String, RuntimeError> {
    if let Some(supplied) = config.hostname.as_deref()
        && supplied != recorded
    {
        return Err(RuntimeError::Config(format!(
            "replay --hostname ({supplied:?}) conflicts with the trace's recorded node \
                 name ({recorded:?}); the trace is authoritative, so omit the flag (or \
                 supply the matching value)"
        )));
    }
    Ok(recorded.to_owned())
}

/// The deterministic guest environment recorded into a trace. `None` when no
/// values were supplied, so env-free runs keep compact old-shape metadata.
pub(super) fn guest_env_record(config: &RuntimeConfig) -> Option<BTreeMap<String, String>> {
    if config.guest_env.is_empty() {
        None
    } else {
        Some(config.guest_env.clone())
    }
}

/// Reconcile a recorded trace's authoritative guest environment with any values
/// supplied to the replaying process. The trace is authoritative: with no values
/// supplied the stored map is adopted verbatim; if values are supplied they must
/// match exactly or replay fails closed. A pre-env trace (`None`) keeps the
/// historical re-supply behavior for embedders.
pub(super) fn reconcile_replay_guest_env(
    config: &RuntimeConfig,
    recorded: Option<&BTreeMap<String, String>>,
) -> Result<Option<BTreeMap<String, String>>, RuntimeError> {
    let Some(stored) = recorded else {
        return Ok(None);
    };
    if !config.guest_env.is_empty() && &config.guest_env != stored {
        return Err(RuntimeError::Config(
            "replay --env values conflict with the trace's recorded guest environment; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored.clone()))
}

/// The exploration scheduling policy recorded into a trace at build time. `None`
/// under the default uniform policy, so a default run records no policy metadata
/// at all and is indistinguishable from an old trace.
pub(super) fn schedule_policy_record(
    config: &RuntimeConfig,
) -> Option<patina_dst_trace::SchedulePolicyRecord> {
    let policy = config.schedule_policy;
    if policy.is_default() {
        return None;
    }
    Some(patina_dst_trace::SchedulePolicyRecord {
        pct: policy.pct.map(|pct| patina_dst_trace::PctPolicyRecord {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: policy
            .starvation
            .map(|starve| patina_dst_trace::StarvationPolicyRecord {
                intervals: starve.intervals,
                max_len: starve.max_len,
                window: starve.window,
            }),
    })
}

/// Rebuild a [`SchedulePolicy`] from a recorded trace's authoritative policy
/// metadata.
fn schedule_policy_from_record(record: &patina_dst_trace::SchedulePolicyRecord) -> SchedulePolicy {
    SchedulePolicy {
        pct: record.pct.map(|pct| PctConfig {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: record.starvation.map(|starve| StarvationConfig {
            intervals: starve.intervals,
            max_len: starve.max_len,
            window: starve.window,
        }),
    }
}

/// Reconcile a recorded trace's authoritative exploration scheduling policy with
/// any policy the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no policy
/// supplied the stored one is adopted verbatim; a conflicting supplied policy
/// fails closed. A trace recorded under the default policy (`None`) leaves the
/// operator's configuration in place — and an operator trying to *enable* a
/// policy on a default trace is caught earlier by the `+pct`/`+starve`
/// fingerprint mismatch.
pub(super) fn reconcile_replay_schedule_policy(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::SchedulePolicyRecord>,
) -> Result<Option<SchedulePolicy>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = schedule_policy_from_record(record);
    if !config.schedule_policy.is_default() && config.schedule_policy != stored {
        return Err(RuntimeError::Config(
            "replay scheduling-policy knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// Reconcile the trace's recorded syscall-user-dispatch state against this
/// replay run's arming, and REFUSE a mismatch UP FRONT (before the first op is
/// replayed) rather than diverging mid-run. A binary with raw inline syscalls
/// can only run armed, so replaying its `sud:true` trace on a kernel without SUD
/// (or replaying a non-SUD trace on a run that armed SUD) cannot reproduce the
/// recorded op-stream — the message names the real situation. `Some(true)` means
/// armed; `None` (absent) means not armed (macOS / non-SUD kernel / standalone /
/// pre-SUD trace). SUD-DESIGN.md §7.3.
pub(super) fn reconcile_replay_sud(
    config: &RuntimeConfig,
    recorded: Option<bool>,
) -> Result<(), RuntimeError> {
    let recorded_armed = recorded == Some(true);
    let now_armed = config.sud == Some(true);
    if recorded_armed && !now_armed {
        return Err(RuntimeError::Config(
            "this trace was recorded under syscall-user-dispatch (SUD), but this run did not arm \
             it — the kernel lacks SUD (arm64 needs the generic-entry kernels; x86_64 needs \
             >= 5.11), or this is macOS. Replay on a matching x86_64 SUD kernel, or rebuild the \
             guest with `--cfg rustix_use_libc` and re-record."
                .into(),
        ));
    }
    if !recorded_armed && now_armed {
        return Err(RuntimeError::Config(
            "this run armed syscall-user-dispatch (SUD), but the trace was recorded WITHOUT it — \
             the two observe raw syscalls at different boundaries, so the recorded op-stream \
             cannot be reproduced. Replay on the kernel/platform the trace was recorded on."
                .into(),
        ));
    }
    Ok(())
}

/// Reconcile the trace's recorded timestamp-counter-trap state against this
/// replay run's arming, and REFUSE a mismatch UP FRONT, for the same reason as
/// [`reconcile_replay_sud`]: an armed run answers `rdtsc`/`rdtscp` from the
/// virtual clock (recording a `ClockNow` op per read), while an unarmed run lets
/// the instruction read the HOST counter — nondeterministically, and without a
/// recorded op. Neither direction can reproduce the other's op-stream, and the
/// unarmed direction is a silent host escape, so both refuse. `Some(true)` means
/// armed; `None` (absent) means not armed (macOS / arm64 / no `PR_SET_TSC` /
/// standalone / a trace predating the trap).
pub(super) fn reconcile_replay_tsc(
    config: &RuntimeConfig,
    recorded: Option<bool>,
) -> Result<(), RuntimeError> {
    let recorded_armed = recorded == Some(true);
    let now_armed = config.tsc == Some(true);
    if recorded_armed && !now_armed {
        return Err(RuntimeError::Config(
            "this trace was recorded with the timestamp-counter trap armed (rdtsc/rdtscp answered \
             from the virtual clock), but this run did not arm it — this is not x86-64 Linux, the \
             kernel lacks PR_SET_TSC, or the guest was built against a shim without the trap. \
             Replay on a matching x86-64 Linux host, or rebuild the guest without the inline \
             counter read and re-record."
                .into(),
        ));
    }
    if !recorded_armed && now_armed {
        return Err(RuntimeError::Config(
            "this run armed the timestamp-counter trap, but the trace was recorded WITHOUT it — \
             the two observe rdtsc/rdtscp at different boundaries (one records a clock read, the \
             other reads the host counter), so the recorded op-stream cannot be reproduced. \
             Replay on the platform the trace was recorded on."
                .into(),
        ));
    }
    Ok(())
}

/// Reconcile a recorded trace's authoritative DNS host table with any table the
/// operator also supplied at replay, exactly like [`reconcile_replay_faults`].
pub(super) fn reconcile_replay_dns(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::DnsConfigRecord>,
) -> Result<Option<BTreeMap<String, String>>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    if !config.dns_entries.is_empty() && config.dns_entries != record.entries {
        return Err(RuntimeError::Config(
            "the supplied DNS host table does not match the one recorded in the trace; the trace \
             is authoritative, so replay without --dns-entry"
                .into(),
        ));
    }
    Ok(Some(record.entries.clone()))
}

#[cfg(test)]
mod tests {
    use crate::config::{BuggifyConfig, RuntimeConfig};
    use crate::fs_crash::{CrashOp, CrashPoint};
    use crate::replay::{
        reconcile_replay_buggify, reconcile_replay_faults, reconcile_replay_schedule_policy,
        reconcile_replay_sud,
    };
    use crate::{RuntimeError, TornGranularity};

    use patina_dst_sched_det::{PctConfig, SchedulePolicy};

    use std::collections::BTreeMap;

    #[test]
    fn reconcile_replay_sud_refuses_a_mismatch_in_both_directions() {
        // Matching states reconcile clean: armed↔armed, and not-armed↔not-armed
        // (the latter covers macOS, non-SUD kernels, and every pre-SUD trace).
        let armed = RuntimeConfig::seeded(0).with_sud(Some(true));
        let unarmed = RuntimeConfig::seeded(0).with_sud(None);
        assert!(reconcile_replay_sud(&armed, Some(true)).is_ok());
        assert!(reconcile_replay_sud(&unarmed, None).is_ok());
        assert!(reconcile_replay_sud(&unarmed, Some(false)).is_ok());

        // RED direction 1: a trace recorded under SUD replayed where SUD did not
        // arm (kernel lacks it / macOS) is refused up front, naming the kernel.
        let err = reconcile_replay_sud(&unarmed, Some(true)).unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("recorded under syscall-user-dispatch"),
            "{text}"
        );
        assert!(
            text.contains("rustix_use_libc") || text.contains("lacks SUD"),
            "{text}"
        );

        // RED direction 2: a run that armed SUD replaying a trace recorded WITHOUT
        // it is refused too — the converse mismatch, never a silent divergence.
        let err = reconcile_replay_sud(&armed, None).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("armed syscall-user-dispatch"), "{text}");
        assert!(text.contains("recorded WITHOUT it"), "{text}");
    }

    #[test]
    fn reconcile_replay_schedule_policy_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::SchedulePolicyRecord {
            pct: Some(patina_dst_trace::PctPolicyRecord {
                depth: 3,
                steps: 100,
            }),
            starvation: None,
        };
        // A default-policy trace (None) yields no override.
        assert_eq!(
            reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored policy verbatim.
        let adopted = reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored policy adopted");
        assert_eq!(adopted.pct.unwrap().depth, 3);
        // A conflicting supplied policy fails closed.
        let conflicting = RuntimeConfig::seeded(0).with_schedule_policy(SchedulePolicy {
            pct: Some(PctConfig {
                depth: 9,
                steps: 100,
            }),
            starvation: None,
        });
        assert!(reconcile_replay_schedule_policy(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn reconcile_replay_buggify_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::BuggifyConfigRecord {
            fire_permille: 250,
            activation_permille: 250,
            cutoff_nanos: 300_000_000_000,
            after_setup: false,
            active_sites: vec!["s".into()],
            knobs: BTreeMap::new(),
        };
        // A trace without buggify yields no override.
        assert_eq!(
            reconcile_replay_buggify(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored config verbatim.
        let adopted = reconcile_replay_buggify(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert!(adopted.enabled);
        assert_eq!(adopted.fire_permille, 250);
        // Conflicting knobs fail closed.
        let conflicting = RuntimeConfig::seeded(0).with_buggify(BuggifyConfig {
            enabled: true,
            fire_permille: 999,
            ..BuggifyConfig::default()
        });
        assert!(reconcile_replay_buggify(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn reconcile_replay_faults_enforces_the_authoritative_trace_contract() {
        use patina_dst_trace::{CrashPointRecord, FaultConfigRecord, FaultCrashOp};

        let stored = FaultConfigRecord {
            crash_at: Some(CrashPointRecord {
                op: FaultCrashOp::Close,
                ordinal: 1,
            }),
            torn_granularity: patina_dst_trace::TornGranularity::Byte,
            fs_error_permille: 111,
            fs_short_permille: 222,
            net_latency_nanos: 500,
            ..FaultConfigRecord::default()
        };

        // A pre-metadata trace (None) yields no override: the operator-supplied
        // configuration is kept, preserving the historical re-supply contract.
        let supplied = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert_eq!(reconcile_replay_faults(&supplied, None).unwrap(), None);

        // Flag-free replay adopts the stored configuration verbatim, so replay is
        // byte-identical without any knobs.
        let faults = reconcile_replay_faults(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert_eq!(
            faults.fs.crash_at,
            Some(CrashPoint {
                op: CrashOp::Close,
                ordinal: 1
            })
        );
        assert_eq!(faults.fs.torn_granularity, TornGranularity::Byte);
        assert_eq!(faults.fs.error_permille, 111);
        assert_eq!(faults.fs.short_permille, 222);
        assert_eq!(faults.net.latency_nanos, 500);

        // Explicit knobs that MATCH the recording are accepted.
        let matching = RuntimeConfig::seeded(0)
            .with_crash_at(CrashOp::Close, 1)
            .with_fs_torn_granularity(TornGranularity::Byte)
            .with_fs_error_permille(111)
            .with_fs_short_permille(222)
            .with_net_latency_nanos(500);
        reconcile_replay_faults(&matching, Some(&stored))
            .unwrap()
            .expect("matching config adopted");

        // Explicit knobs that DIVERGE fail closed before any driver is built.
        let mismatched = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert!(matches!(
            reconcile_replay_faults(&mismatched, Some(&stored)),
            Err(RuntimeError::Config(_))
        ));
    }
}
