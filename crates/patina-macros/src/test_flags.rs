// What `#[patina_dst::test(...)]` accepts: every flag of `patina test` but
// those in NOT_ACCEPTED, by its long name with `_` for `-`. The tool's tests
// include this file and compare it with the flag registry, so the two cannot
// drift.

/// Whether an attribute argument takes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
    /// `name` alone.
    Switch,
    /// `name = value`.
    Value,
}

/// The flags of `patina test` an attribute does not take: the selection of
/// its one test, which the attribute makes itself, and the flags that select
/// or excuse other tests.
#[allow(dead_code)]
pub(crate) const NOT_ACCEPTED: &[&str] = &[
    "--package",
    "--workspace",
    "--lib",
    "--bin",
    "--bins",
    "--test",
    "--tests",
    "--skip-target",
    "--skip",
    "--exact",
    "--include-ignored",
    "--no-run",
    "--accept-unsupported",
];

pub(crate) const TEST_FLAGS: &[(&str, Arity)] = &[
    ("all_features", Arity::Switch),
    ("allow", Arity::Value),
    ("allow_randomized_address_layout", Arity::Switch),
    ("budget", Arity::Value),
    ("buggify", Arity::Switch),
    ("buggify_activation_permille", Arity::Value),
    ("buggify_after_setup", Arity::Switch),
    ("buggify_cutoff_nanos", Arity::Value),
    ("buggify_fire_permille", Arity::Value),
    ("compute_watchdog_ms", Arity::Value),
    ("converge_within", Arity::Value),
    ("cpus", Arity::Value),
    ("dns_entry", Arity::Value),
    ("dns_fail_permille", Arity::Value),
    ("dns_latency_nanos", Arity::Value),
    ("entropy_fail_permille", Arity::Value),
    ("env", Arity::Value),
    ("epoch_jump_nanos", Arity::Value),
    ("features", Arity::Value),
    ("fs_error_at", Arity::Value),
    ("fs_error_permille", Arity::Value),
    ("fs_latency_nanos", Arity::Value),
    ("fs_short_permille", Arity::Value),
    ("heal_after", Arity::Value),
    ("hostname", Arity::Value),
    ("jobs", Arity::Value),
    ("liveness_watchdog", Arity::Value),
    ("machine_crash_permille", Arity::Value),
    ("mount", Arity::Value),
    ("net_connect_refuse_permille", Arity::Value),
    ("net_drop_permille", Arity::Value),
    ("net_duplicate_permille", Arity::Value),
    ("net_jitter_nanos", Arity::Value),
    ("net_latency_nanos", Arity::Value),
    ("net_partition", Arity::Value),
    ("net_reset_permille", Arity::Value),
    ("net_tcp_buffer_bytes", Arity::Value),
    ("no_default_features", Arity::Switch),
    ("no_instrument", Arity::Switch),
    ("param", Arity::Value),
    ("process_crash_permille", Arity::Value),
    ("realtime_epoch", Arity::Value),
    ("release", Arity::Switch),
    ("sched_pct", Arity::Value),
    ("sched_pct_steps", Arity::Value),
    ("seed", Arity::Value),
    ("seeds", Arity::Value),
    ("sleep_jitter_nanos", Arity::Value),
    ("swarm", Arity::Switch),
    ("timeout_secs", Arity::Value),
    ("yield_stride", Arity::Value),
];
