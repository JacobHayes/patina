//! The guest's node name: the default every run reports, the explicit
//! override, and its record/replay contract (recorded into the trace,
//! authoritative on replay).

use patina_dst_abi::ClockKind;
use patina_dst_runtime::{
    Context, ENV_GUEST_HOSTNAME, HOSTNAME_MAX_BYTES, RuntimeConfig, RuntimeError, validate_hostname,
};
use patina_dst_syscalls::IDENTITY_HOSTNAME;
use patina_dst_trace::TraceBundle;
use tempfile::tempdir;

const NAME: &str = "db-1.internal";

fn env_with(value: &str) -> impl Fn(&str) -> Option<String> + '_ {
    move |name| (name == ENV_GUEST_HOSTNAME).then(|| value.to_owned())
}

/// A small recorded workload: one boundary operation, so there is an
/// operation stream to replay.
fn record(config: RuntimeConfig) -> String {
    let mut context = Context::from_config(config).unwrap();
    context.now(ClockKind::Monotonic).unwrap();
    let hostname = context.hostname().to_owned();
    context.finish().unwrap();
    hostname
}

fn replay(config: RuntimeConfig) -> Result<String, RuntimeError> {
    let mut context = Context::from_config(config)?;
    context.now(ClockKind::Monotonic).unwrap();
    let hostname = context.hostname().to_owned();
    context.finish().unwrap();
    Ok(hostname)
}

fn assert_config_refusal<T: std::fmt::Debug>(result: Result<T, RuntimeError>) {
    assert!(
        matches!(result, Err(RuntimeError::Config(_))),
        "expected a configuration refusal, got {result:?}"
    );
}

#[test]
fn a_default_runtime_reports_the_identity_hostname() {
    let context = Context::from_config(RuntimeConfig::seeded(0)).unwrap();
    assert_eq!(context.hostname(), IDENTITY_HOSTNAME);
    assert_eq!(RuntimeConfig::seeded(0).hostname(), IDENTITY_HOSTNAME);
}

#[test]
fn a_configured_hostname_overrides_the_default_directly_and_through_the_control_plane() {
    let direct =
        Context::from_config(RuntimeConfig::seeded(0).with_hostname(NAME).unwrap()).unwrap();
    assert_eq!(direct.hostname(), NAME);

    let config = RuntimeConfig::seeded(0)
        .apply_hostname_env(env_with(NAME))
        .unwrap();
    assert_eq!(config.hostname(), NAME);
    assert_eq!(Context::from_config(config).unwrap().hostname(), NAME);

    let unset = RuntimeConfig::seeded(0)
        .apply_hostname_env(|_| None)
        .unwrap();
    assert_eq!(unset.hostname(), IDENTITY_HOSTNAME);
}

#[test]
fn hostnames_follow_the_kernel_length_and_nul_rules() {
    let longest = "h".repeat(HOSTNAME_MAX_BYTES);
    let too_long = "h".repeat(HOSTNAME_MAX_BYTES + 1);
    // Multi-byte text is measured in bytes, as the kernel measures it.
    let wide = "é".repeat(HOSTNAME_MAX_BYTES / 2 + 1);
    for accepted in ["", "patina", longest.as_str()] {
        validate_hostname(accepted).unwrap();
        RuntimeConfig::seeded(0).with_hostname(accepted).unwrap();
        RuntimeConfig::seeded(0)
            .apply_hostname_env(env_with(accepted))
            .unwrap();
    }
    for refused in [too_long.as_str(), wide.as_str(), "a\0b"] {
        assert!(validate_hostname(refused).is_err(), "{refused:?}");
        assert_config_refusal(RuntimeConfig::seeded(0).with_hostname(refused));
        assert_config_refusal(RuntimeConfig::seeded(0).apply_hostname_env(env_with(refused)));
    }
}

#[test]
fn replay_reproduces_a_recorded_hostname_without_resupplying_it() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("hostname.patina");
    assert_eq!(
        record(
            RuntimeConfig::record(3, &path, "hostname-v1")
                .with_hostname(NAME)
                .unwrap()
        ),
        NAME
    );
    assert_eq!(TraceBundle::load(&path).unwrap().metadata.hostname, NAME);

    // Flag-free replay and a branch both adopt the recorded name.
    assert_eq!(
        replay(RuntimeConfig::replay(&path, "hostname-v1")).unwrap(),
        NAME
    );
    let branch = Context::from_config(RuntimeConfig::branch(
        &path,
        "main",
        1,
        "b1",
        9,
        "hostname-v1",
    ))
    .unwrap();
    assert_eq!(branch.hostname(), NAME);
    drop(branch);

    // A matching explicit name replays; a conflicting one is refused.
    let matching = RuntimeConfig::replay(&path, "hostname-v1")
        .with_hostname(NAME)
        .unwrap();
    assert_eq!(replay(matching).unwrap(), NAME);
    let conflicting = RuntimeConfig::replay(&path, "hostname-v1")
        .with_hostname(IDENTITY_HOSTNAME)
        .unwrap();
    assert_config_refusal(replay(conflicting));
}

#[test]
fn a_default_run_records_the_default_hostname() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("default.patina");
    record(RuntimeConfig::record(3, &path, "hostname-v1"));
    assert_eq!(
        TraceBundle::load(&path).unwrap().metadata.hostname,
        IDENTITY_HOSTNAME
    );
}
