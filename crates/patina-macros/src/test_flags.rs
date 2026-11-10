// What `#[patina_dst::test(...)]` accepts: every flag of `patina test` except
// the two the attribute supplies itself (`--harness-target`, `--exact`), by its
// long name with `_` for `-`. The tool's tests include this file and compare
// it with the flag registry, so the two cannot drift.

/// Whether an attribute argument takes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
    /// `name` alone.
    Switch,
    /// `name = value`.
    Value,
    /// `name` or `name = value`.
    OptionalValue,
}

pub(crate) const TEST_FLAGS: &[(&str, Arity)] = &[
    ("allow_randomized_address_layout", Arity::Switch),
    ("budget", Arity::Value),
    ("buggify", Arity::OptionalValue),
    ("buggify_activation_permille", Arity::Value),
    ("buggify_after_setup", Arity::Switch),
    ("buggify_cutoff_nanos", Arity::Value),
    ("compute_watchdog_ms", Arity::Value),
    ("converge_within", Arity::OptionalValue),
    ("cpus", Arity::Value),
    ("custom_op_fail_permille", Arity::Value),
    ("dns_entry", Arity::Value),
    ("dns_fail_permille", Arity::Value),
    ("dns_latency_nanos", Arity::Value),
    ("entropy_fail_permille", Arity::Value),
    ("epoch_jump_nanos", Arity::Value),
    ("features", Arity::Value),
    ("fs_error_at", Arity::Value),
    ("fs_error_permille", Arity::Value),
    ("fs_latency_nanos", Arity::Value),
    ("fs_short_permille", Arity::Value),
    ("heal_after", Arity::Value),
    ("hostname", Arity::Value),
    ("instrument", Arity::Switch),
    ("liveness_watchdog", Arity::OptionalValue),
    ("machine_crash_permille", Arity::Value),
    ("net_connect_refuse_permille", Arity::Value),
    ("net_drop_permille", Arity::Value),
    ("net_duplicate_permille", Arity::Value),
    ("net_jitter_nanos", Arity::Value),
    ("net_latency_nanos", Arity::Value),
    ("net_partition", Arity::Value),
    ("net_reset_permille", Arity::Value),
    ("net_tcp_buffer_bytes", Arity::Value),
    ("package", Arity::Value),
    ("param", Arity::Value),
    ("process_crash_permille", Arity::Value),
    ("realtime_epoch", Arity::Value),
    ("release", Arity::Switch),
    ("sched_pct", Arity::OptionalValue),
    ("sched_pct_steps", Arity::Value),
    ("seed", Arity::Value),
    ("seeds", Arity::Value),
    ("sleep_jitter_nanos", Arity::Value),
    ("swarm", Arity::Switch),
    ("yield_stride", Arity::Value),
];
