//! The virtual machine's CPU count: the default every run has, the explicit
//! override, and its record/replay contract (recorded into the trace,
//! authoritative on replay).

use patina_dst_abi::{ClockKind, DEFAULT_CPUS, MAX_CPUS};
use patina_dst_runtime::{Context, ENV_GUEST_CPUS, RuntimeConfig, RuntimeError, validate_cpus};
use patina_dst_trace::TraceBundle;
use tempfile::tempdir;

/// A count other than the default, so a test can tell the two apart.
const CPUS: u32 = DEFAULT_CPUS + 3;

fn env_with(value: &str) -> impl Fn(&str) -> Option<String> + '_ {
    move |name| (name == ENV_GUEST_CPUS).then(|| value.to_owned())
}

/// Run one boundary operation, so a recording has an operation stream to
/// replay, and answer the count the run's context reports.
fn run(config: RuntimeConfig) -> Result<u32, RuntimeError> {
    let mut context = Context::from_config(config)?;
    context.now(ClockKind::Monotonic).unwrap();
    let cpus = context.cpus();
    context.finish().unwrap();
    Ok(cpus)
}

fn assert_config_refusal<T: std::fmt::Debug>(result: Result<T, RuntimeError>) {
    assert!(
        matches!(result, Err(RuntimeError::Config(_))),
        "expected a configuration refusal, got {result:?}"
    );
}

#[test]
fn cpu_counts_are_bounded_by_the_machine_cap() {
    for accepted in [1, DEFAULT_CPUS, MAX_CPUS] {
        validate_cpus(accepted).unwrap();
        RuntimeConfig::seeded(0).with_cpus(accepted).unwrap();
        RuntimeConfig::seeded(0)
            .apply_cpus_env(env_with(&accepted.to_string()))
            .unwrap();
    }
    for refused in [0, MAX_CPUS + 1] {
        assert!(validate_cpus(refused).is_err(), "{refused}");
        assert_config_refusal(RuntimeConfig::seeded(0).with_cpus(refused));
        assert_config_refusal(
            RuntimeConfig::seeded(0).apply_cpus_env(env_with(&refused.to_string())),
        );
    }
    for malformed in ["", "four", "-1", "4.0", " 4"] {
        assert_config_refusal(RuntimeConfig::seeded(0).apply_cpus_env(env_with(malformed)));
    }
}

#[test]
fn a_replay_adopts_the_recorded_cpu_count_and_refuses_another() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("cpus.patina");
    let recorded = RuntimeConfig::record(3, &path, "cpus-v1")
        .with_cpus(CPUS)
        .unwrap();
    assert_eq!(run(recorded).unwrap(), CPUS);
    assert_eq!(TraceBundle::load(&path).unwrap().metadata.cpus, CPUS);

    // A flag-free replay and a branch both adopt the recorded count; a
    // matching explicit count replays too.
    assert_eq!(run(RuntimeConfig::replay(&path, "cpus-v1")).unwrap(), CPUS);
    let branch =
        Context::from_config(RuntimeConfig::branch(&path, "main", 1, "b1", 9, "cpus-v1")).unwrap();
    assert_eq!(branch.cpus(), CPUS);
    drop(branch);
    let matching = RuntimeConfig::replay(&path, "cpus-v1")
        .with_cpus(CPUS)
        .unwrap();
    assert_eq!(run(matching).unwrap(), CPUS);

    // A conflicting count is refused, directly and through the control plane.
    let conflicting = RuntimeConfig::replay(&path, "cpus-v1")
        .with_cpus(DEFAULT_CPUS)
        .unwrap();
    let Err(RuntimeError::Config(message)) = run(conflicting) else {
        panic!("a replay with another CPU count must be refused");
    };
    assert!(message.contains("--cpus"), "{message}");
    let through_the_control_plane = RuntimeConfig::replay(&path, "cpus-v1")
        .apply_cpus_env(env_with("1"))
        .unwrap();
    assert_config_refusal(run(through_the_control_plane));
}
