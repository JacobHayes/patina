//! The fault-knob registry: one enum over every seed-driven fault knob, and one
//! metadata table keyed by it.
//!
//! A fault knob used to be hand-wired in six independent places — the CLI
//! registry, the control-plane forwarding table, the domain-seed label registry,
//! the swarm class list, the campaign band table, and the trace record — each
//! pairing enforced only by an after-the-fact drift gate. [`FaultKnob`] makes the
//! COMPILER the pairing: a new variant has no arm in [`FaultKnob::meta`], no
//! `is_set`/`clear` behavior, no campaign band and no vacuity class until each
//! decision is written down, and a decision that is deliberately absent is an
//! explicit `None` rather than an omission.
//!
//! What lives here is the part every crate needs: flag name, control-plane
//! variable, plumbing shape, configuration plane, injection domains, swarm class,
//! and diagnostic report. Two facets deliberately do NOT: a knob's value grammar
//! and families belong to the CLI registry (`cargo-patina/src/help.rs`, the
//! single source for the help text and the parsers alike), and its campaign band
//! and vacuity class belong to `cargo-patina/src/campaign.rs`, which owns the
//! generation-hash layout and the outcome classes. Both are keyed by this enum
//! through exhaustive matches, so the compiler still walks a new knob to them.

use patina_dst_rng_seeded::fault_domain;

use crate::{
    ENV_DNS_ENTRIES, ENV_DNS_FAIL_PERMILLE, ENV_DNS_FAULT_REPORT, ENV_DNS_LATENCY,
    ENV_ENTROPY_FAIL_PERMILLE, ENV_ENTROPY_FAULT_REPORT, ENV_FS_CRASH_AT, ENV_FS_ERROR_PERMILLE,
    ENV_FS_FAULT_REPORT, ENV_FS_LATENCY, ENV_FS_SHORT_PERMILLE, ENV_FS_TORN_GRANULARITY,
    ENV_NET_CONNECT_REFUSE_PERMILLE, ENV_NET_DROP_PERMILLE, ENV_NET_DUPLICATE_PERMILLE,
    ENV_NET_FAULT_REPORT, ENV_NET_JITTER, ENV_NET_LATENCY, ENV_NET_PARTITIONS,
    ENV_NET_RESET_PERMILLE, ENV_NET_TCP_BUFFER_BYTES, ENV_SLEEP_JITTER, FINGERPRINT_BUGGIFY,
    FaultConfig, TornGranularity,
};

/// Every seed-driven fault knob the CLI registry declares, in registry order
/// (`FAULT_FLAGS` then `DNS_FLAGS`).
///
/// The order is load-bearing for the control plane: filtering [`FaultKnob::ALL`]
/// by [`Plumbing`] reproduces the order each family forwards its knobs in. It is
/// deliberately NOT the swarm draw order — that one is trace-visible and is
/// pinned separately by [`SWARM_CLASSES`].
///
/// Cooperative-SUT (buggify) and the scheduling-policy knobs (`--sched-pct`,
/// `--starve`) are not fault knobs and are not variants here: they configure
/// exploration rather than injecting an effect, and carry their own control-plane
/// shapes. `buggify` still appears as a swarm class, which is why [`Masks`]
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultKnob {
    FsCrashAt,
    FsTornGranularity,
    FsErrorPermille,
    FsShortPermille,
    FsLatencyNanos,
    SleepJitterNanos,
    NetJitterNanos,
    NetDropPermille,
    NetLatencyNanos,
    NetDuplicatePermille,
    NetConnectRefusePermille,
    NetResetPermille,
    NetPartition,
    NetTcpBufferBytes,
    EntropyFailPermille,
    DnsEntry,
    DnsFailPermille,
    DnsLatencyNanos,
}

/// How a knob's value reaches a guest over the `PATINA_*` control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plumbing {
    /// One validated raw value, carried verbatim on its own variable. The runtime
    /// re-parses the same protocol string on record and on replay.
    Scalar,
    /// A repeatable flag whose whole SET is carried as one encoded payload, and
    /// which is re-emitted onto a child command line once per element.
    Repeatable,
}

/// Which configuration plane a knob's control-plane variable is applied to.
///
/// Orthogonal to [`Plumbing`]: `--net-partition` is repeatable but lands in
/// [`FaultConfig`], while `--dns-entry` is repeatable and lands on the host
/// table, which a family may offer WITHOUT the DNS fault knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    /// Layered onto [`FaultConfig`] by `RuntimeConfig::apply_fault_env`.
    Fault,
    /// The DNS host table, applied by `RuntimeConfig::apply_dns_env`. Semantic
    /// configuration — the names a guest can resolve are its workload, not a
    /// fault — so it is not a [`FaultConfig`] field at all.
    DnsTable,
}

/// One knob's cross-plane spellings. See [`FaultKnob::meta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnobMeta {
    /// The CLI flag the knob is parsed from. This is the join key to the CLI
    /// registry, which owns the flag's value grammar and families;
    /// `knob_table_covers_every_registry_fault_flag` pins the two together.
    pub flag: &'static str,
    /// The `PATINA_*` control-plane variable carrying it to a guest.
    pub env: &'static str,
    pub plumbing: Plumbing,
    pub plane: Plane,
    /// The `fault_domain` labels the knob's seeded stream(s) derive from. Empty
    /// for a knob that draws nothing (a deterministic setting such as the base
    /// network latency, the partition set, or the TCP buffer size).
    ///
    /// Several knobs SHARE a label on purpose — the crash and torn-write models
    /// are one stream, and SimNet is handed one network seed — and a knob whose
    /// effect exists both in `SimNet` and in the explicit `FaultNet` wrapper
    /// names both. `every_domain_label_is_claimed` pins the label
    /// registry against this column, so a label added without a knob (or a knob
    /// pointed at a label that no longer exists) fails closed.
    pub injection_domains: &'static [&'static str],
    /// The swarm class token this knob belongs to, or `None` for a knob no swarm
    /// class masks. `--fs-torn-granularity` is `None` because the `crash` class
    /// masks it together with `--fs-crash-at`; `--dns-entry` is `None` because
    /// swarm masks faults, not workload.
    pub swarm_class: Option<&'static str>,
    /// The `PATINA_*_REPORT` diagnostic line carrying the knob's per-class
    /// vacuity counters, or `None` for a knob with no rate to judge inert.
    pub report: Option<&'static str>,
}

impl FaultKnob {
    /// Every knob, in registry order.
    ///
    /// Completeness is held by two paired gates rather than by the type system:
    /// `all_is_in_variant_order` pins this list index-for-index against the
    /// discriminants, and `knob_table_covers_every_registry_fault_flag` compares
    /// it to the CLI registry — so a variant added with a registry row but no
    /// entry here fails, and a variant with neither is a knob no CLI can reach.
    /// This is the same pairing `Report::ALL` uses.
    pub const ALL: &'static [Self] = &[
        Self::FsCrashAt,
        Self::FsTornGranularity,
        Self::FsErrorPermille,
        Self::FsShortPermille,
        Self::FsLatencyNanos,
        Self::SleepJitterNanos,
        Self::NetJitterNanos,
        Self::NetDropPermille,
        Self::NetLatencyNanos,
        Self::NetDuplicatePermille,
        Self::NetConnectRefusePermille,
        Self::NetResetPermille,
        Self::NetPartition,
        Self::NetTcpBufferBytes,
        Self::EntropyFailPermille,
        Self::DnsEntry,
        Self::DnsFailPermille,
        Self::DnsLatencyNanos,
    ];

    /// The knob's spellings on every plane it touches. The exhaustive match is
    /// the point: a new variant does not compile until each column is decided,
    /// and a column with nothing to say says `None` out loud.
    #[must_use]
    pub const fn meta(self) -> KnobMeta {
        match self {
            Self::FsCrashAt => KnobMeta {
                flag: "--fs-crash-at",
                env: ENV_FS_CRASH_AT,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::FS_CRASH],
                swarm_class: Some("crash"),
                // A crash fires at a chosen boundary op, not at a rate, so there
                // is no "should have fired N times" judgement to report.
                report: None,
            },
            Self::FsTornGranularity => KnobMeta {
                flag: "--fs-torn-granularity",
                env: ENV_FS_TORN_GRANULARITY,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::FS_CRASH],
                // Masked by the `crash` class together with `--fs-crash-at`: the
                // granularity is inert without a crash point, so selecting one
                // without the other would ship a knob that cannot fire.
                swarm_class: None,
                report: None,
            },
            Self::FsErrorPermille => KnobMeta {
                flag: "--fs-error-permille",
                env: ENV_FS_ERROR_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::FAULT_FS_ERROR],
                swarm_class: Some("fs_error"),
                report: Some(ENV_FS_FAULT_REPORT),
            },
            Self::FsShortPermille => KnobMeta {
                flag: "--fs-short-permille",
                env: ENV_FS_SHORT_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::FAULT_FS_SHORT],
                swarm_class: Some("fs_short"),
                report: Some(ENV_FS_FAULT_REPORT),
            },
            Self::FsLatencyNanos => KnobMeta {
                flag: "--fs-latency-nanos",
                env: ENV_FS_LATENCY,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::FS_LATENCY],
                swarm_class: Some("fs_latency"),
                report: Some(ENV_FS_FAULT_REPORT),
            },
            Self::SleepJitterNanos => KnobMeta {
                flag: "--sleep-jitter-nanos",
                env: ENV_SLEEP_JITTER,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::SLEEP_JITTER],
                swarm_class: Some("sleep_jitter"),
                // The clock plane has no fault report: a sleep that was delayed
                // is indistinguishable from a longer sleep, so there is nothing
                // to count as "applied".
                report: None,
            },
            Self::NetJitterNanos => KnobMeta {
                flag: "--net-jitter-nanos",
                env: ENV_NET_JITTER,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::NET_FAULT],
                swarm_class: Some("net_jitter"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetDropPermille => KnobMeta {
                flag: "--net-drop-permille",
                env: ENV_NET_DROP_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::NET_FAULT, fault_domain::FAULT_NET_DROP],
                swarm_class: Some("net_drop"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetLatencyNanos => KnobMeta {
                flag: "--net-latency-nanos",
                env: ENV_NET_LATENCY,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                // A deterministic base link latency: applied to every delivery
                // rather than drawn, so it derives no stream of its own.
                injection_domains: &[],
                swarm_class: Some("net_latency"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetDuplicatePermille => KnobMeta {
                flag: "--net-duplicate-permille",
                env: ENV_NET_DUPLICATE_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[
                    fault_domain::NET_DUPLICATE,
                    fault_domain::FAULT_NET_DUPLICATE,
                ],
                swarm_class: Some("net_duplicate"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetConnectRefusePermille => KnobMeta {
                flag: "--net-connect-refuse-permille",
                env: ENV_NET_CONNECT_REFUSE_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::NET_CONNECT_REFUSE],
                swarm_class: Some("net_connect_refuse"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetResetPermille => KnobMeta {
                flag: "--net-reset-permille",
                env: ENV_NET_RESET_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::NET_RESET],
                swarm_class: Some("net_reset"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetPartition => KnobMeta {
                flag: "--net-partition",
                env: ENV_NET_PARTITIONS,
                plumbing: Plumbing::Repeatable,
                plane: Plane::Fault,
                // Deterministic (rate 1.0): a datagram across a partition is
                // always dropped, so nothing is drawn.
                injection_domains: &[],
                swarm_class: Some("net_partition"),
                report: Some(ENV_NET_FAULT_REPORT),
            },
            Self::NetTcpBufferBytes => KnobMeta {
                flag: "--net-tcp-buffer-bytes",
                env: ENV_NET_TCP_BUFFER_BYTES,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[],
                swarm_class: Some("net_tcp_buffer"),
                // A capacity setting, not a fault: there is no rate that "should
                // have fired", so no vacuity counter to report.
                report: None,
            },
            Self::EntropyFailPermille => KnobMeta {
                flag: "--entropy-fail-permille",
                env: ENV_ENTROPY_FAIL_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::ENTROPY_FAULT],
                swarm_class: Some("entropy_fail"),
                report: Some(ENV_ENTROPY_FAULT_REPORT),
            },
            Self::DnsEntry => KnobMeta {
                flag: "--dns-entry",
                env: ENV_DNS_ENTRIES,
                plumbing: Plumbing::Repeatable,
                plane: Plane::DnsTable,
                injection_domains: &[],
                swarm_class: None,
                report: None,
            },
            Self::DnsFailPermille => KnobMeta {
                flag: "--dns-fail-permille",
                env: ENV_DNS_FAIL_PERMILLE,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::DNS_FAULT],
                swarm_class: Some("dns_fail"),
                report: Some(ENV_DNS_FAULT_REPORT),
            },
            Self::DnsLatencyNanos => KnobMeta {
                flag: "--dns-latency-nanos",
                env: ENV_DNS_LATENCY,
                plumbing: Plumbing::Scalar,
                plane: Plane::Fault,
                injection_domains: &[fault_domain::DNS_LATENCY],
                swarm_class: Some("dns_latency"),
                report: Some(ENV_DNS_FAULT_REPORT),
            },
        }
    }

    /// Whether the knob is set to something other than its inert default.
    ///
    /// A [`Plane::DnsTable`] knob is not a [`FaultConfig`] field at all, so it
    /// answers `false` here; `dns_table_knobs_are_outside_faultconfig` pins that,
    /// and `RuntimeConfig::dns_entries` is where the host table actually lives.
    #[must_use]
    pub fn is_set(self, faults: &FaultConfig) -> bool {
        match self {
            Self::FsCrashAt => faults.fs.crash_at.is_some(),
            Self::FsTornGranularity => faults.fs.torn_granularity != TornGranularity::default(),
            Self::FsErrorPermille => faults.fs.error_permille != 0,
            Self::FsShortPermille => faults.fs.short_permille != 0,
            Self::FsLatencyNanos => faults.fs.latency_nanos.is_some(),
            Self::SleepJitterNanos => faults.clock.sleep_jitter_nanos.is_some(),
            Self::NetJitterNanos => faults.net.jitter_nanos.is_some(),
            Self::NetDropPermille => faults.net.drop_permille != 0,
            Self::NetLatencyNanos => faults.net.latency_nanos != 0,
            Self::NetDuplicatePermille => faults.net.duplicate_permille != 0,
            Self::NetConnectRefusePermille => faults.net.connect_refuse_permille != 0,
            Self::NetResetPermille => faults.net.reset_permille != 0,
            Self::NetPartition => !faults.net.partitions.is_empty(),
            Self::NetTcpBufferBytes => faults.net.tcp_buffer_bytes.is_some(),
            Self::EntropyFailPermille => faults.entropy.fail_permille != 0,
            Self::DnsEntry => false,
            Self::DnsFailPermille => faults.dns.fail_permille != 0,
            Self::DnsLatencyNanos => faults.dns.latency_nanos.is_some(),
        }
    }

    /// Reset the knob to its inert default, leaving no residue behind — what a
    /// swarm generation does to a class its seed deselected.
    pub fn clear(self, faults: &mut FaultConfig) {
        match self {
            Self::FsCrashAt => faults.fs.crash_at = None,
            Self::FsTornGranularity => faults.fs.torn_granularity = TornGranularity::default(),
            Self::FsErrorPermille => faults.fs.error_permille = 0,
            Self::FsShortPermille => faults.fs.short_permille = 0,
            Self::FsLatencyNanos => faults.fs.latency_nanos = None,
            Self::SleepJitterNanos => faults.clock.sleep_jitter_nanos = None,
            Self::NetJitterNanos => faults.net.jitter_nanos = None,
            Self::NetDropPermille => faults.net.drop_permille = 0,
            Self::NetLatencyNanos => faults.net.latency_nanos = 0,
            Self::NetDuplicatePermille => faults.net.duplicate_permille = 0,
            Self::NetConnectRefusePermille => faults.net.connect_refuse_permille = 0,
            Self::NetResetPermille => faults.net.reset_permille = 0,
            Self::NetPartition => faults.net.partitions.clear(),
            Self::NetTcpBufferBytes => faults.net.tcp_buffer_bytes = None,
            Self::EntropyFailPermille => faults.entropy.fail_permille = 0,
            Self::DnsEntry => {}
            Self::DnsFailPermille => faults.dns.fail_permille = 0,
            Self::DnsLatencyNanos => faults.dns.latency_nanos = None,
        }
    }
}

/// What a swarm class masks when the seed deselects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Masks {
    /// Fault knobs. The class is a candidate when ANY of them is set, and
    /// dropping it clears ALL of them — which is how one class covers a knob and
    /// its modifier (`crash` covers `--fs-crash-at` and `--fs-torn-granularity`).
    Knobs(&'static [FaultKnob]),
    /// Cooperative-SUT configuration, which is not a fault knob: `--buggify` and
    /// its detail knobs configure exploration rather than injecting an effect.
    Buggify,
}

/// One swarm fault-class row: the stable token recorded in the trace, the domain
/// label its coin draws from, the compatibility-fingerprint component its
/// capability declares, and what it masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwarmClass {
    pub token: &'static str,
    pub domain: &'static str,
    /// Retracted from `RuntimeConfig::fingerprint` when the seed deselects the
    /// class, because the fingerprint describes the run that actually happened.
    /// Only `buggify` declares one today.
    pub fingerprint_component: Option<&'static str>,
    pub masks: Masks,
}

/// The swarm classes in DRAW ORDER — the order candidate and selected tokens are
/// recorded in, which makes it trace-visible and therefore load-bearing. Each
/// class draws from its own domain-separated coin, so the order does not affect
/// any decision, only the record.
///
/// Deliberately not [`FaultKnob::ALL`]'s order, and not one row per knob:
/// `crash` covers two knobs, `--dns-entry` has no class, and `buggify` masks
/// configuration no fault knob owns. `swarm_classes_and_knobs_agree` pins this
/// list against the `swarm_class` column so neither side can drift.
pub const SWARM_CLASSES: &[SwarmClass] = &[
    SwarmClass {
        token: "crash",
        domain: fault_domain::SWARM_CRASH,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::FsCrashAt, FaultKnob::FsTornGranularity]),
    },
    SwarmClass {
        token: "fs_error",
        domain: fault_domain::SWARM_FS_ERROR,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::FsErrorPermille]),
    },
    SwarmClass {
        token: "fs_short",
        domain: fault_domain::SWARM_FS_SHORT,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::FsShortPermille]),
    },
    SwarmClass {
        token: "fs_latency",
        domain: fault_domain::SWARM_FS_LATENCY,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::FsLatencyNanos]),
    },
    SwarmClass {
        token: "dns_fail",
        domain: fault_domain::SWARM_DNS_FAIL,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::DnsFailPermille]),
    },
    SwarmClass {
        token: "dns_latency",
        domain: fault_domain::SWARM_DNS_LATENCY,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::DnsLatencyNanos]),
    },
    SwarmClass {
        token: "sleep_jitter",
        domain: fault_domain::SWARM_SLEEP_JITTER,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::SleepJitterNanos]),
    },
    SwarmClass {
        token: "net_jitter",
        domain: fault_domain::SWARM_NET_JITTER,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetJitterNanos]),
    },
    SwarmClass {
        token: "net_drop",
        domain: fault_domain::SWARM_NET_DROP,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetDropPermille]),
    },
    SwarmClass {
        token: "net_latency",
        domain: fault_domain::SWARM_NET_LATENCY,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetLatencyNanos]),
    },
    SwarmClass {
        token: "net_duplicate",
        domain: fault_domain::SWARM_NET_DUPLICATE,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetDuplicatePermille]),
    },
    SwarmClass {
        token: "net_connect_refuse",
        domain: fault_domain::SWARM_NET_CONNECT_REFUSE,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetConnectRefusePermille]),
    },
    SwarmClass {
        token: "net_reset",
        domain: fault_domain::SWARM_NET_RESET,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetResetPermille]),
    },
    SwarmClass {
        token: "net_partition",
        domain: fault_domain::SWARM_NET_PARTITION,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetPartition]),
    },
    SwarmClass {
        token: "net_tcp_buffer",
        domain: fault_domain::SWARM_NET_TCP_BUFFER,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::NetTcpBufferBytes]),
    },
    SwarmClass {
        token: "entropy_fail",
        domain: fault_domain::SWARM_ENTROPY_FAIL,
        fingerprint_component: None,
        masks: Masks::Knobs(&[FaultKnob::EntropyFailPermille]),
    },
    SwarmClass {
        token: "buggify",
        domain: fault_domain::SWARM_BUGGIFY,
        fingerprint_component: Some(FINGERPRINT_BUGGIFY),
        masks: Masks::Buggify,
    },
];

#[cfg(test)]
impl FaultKnob {
    /// Set the knob to a non-default sample value. The exhaustive match drags a
    /// new knob into every gate that starts from "one knob set" — the swarm
    /// coverage list, the per-knob wiring check, and the trace-record coverage
    /// gate — instead of letting it land outside them unnoticed.
    pub(crate) fn set_sample(self, faults: &mut FaultConfig) {
        use crate::{CrashOp, CrashPoint};

        match self {
            Self::FsCrashAt => {
                faults.fs.crash_at = Some(CrashPoint {
                    op: CrashOp::Close,
                    ordinal: 1,
                });
            }
            Self::FsTornGranularity => faults.fs.torn_granularity = TornGranularity::Byte,
            Self::FsErrorPermille => faults.fs.error_permille = 1,
            Self::FsShortPermille => faults.fs.short_permille = 1,
            Self::FsLatencyNanos => faults.fs.latency_nanos = Some((1, 2)),
            Self::SleepJitterNanos => faults.clock.sleep_jitter_nanos = Some((1, 2)),
            Self::NetJitterNanos => faults.net.jitter_nanos = Some((1, 2)),
            Self::NetDropPermille => faults.net.drop_permille = 1,
            Self::NetLatencyNanos => faults.net.latency_nanos = 1,
            Self::NetDuplicatePermille => faults.net.duplicate_permille = 1,
            Self::NetConnectRefusePermille => faults.net.connect_refuse_permille = 1,
            Self::NetResetPermille => faults.net.reset_permille = 1,
            Self::NetPartition => {
                faults
                    .net
                    .partitions
                    .insert(("a".to_string(), "b".to_string()));
                faults
                    .net
                    .partitions
                    .insert(("b".to_string(), "a".to_string()));
            }
            Self::NetTcpBufferBytes => faults.net.tcp_buffer_bytes = Some(4096),
            Self::EntropyFailPermille => faults.entropy.fail_permille = 1,
            Self::DnsEntry => {}
            Self::DnsFailPermille => faults.dns.fail_permille = 1,
            Self::DnsLatencyNanos => faults.dns.latency_nanos = Some((1, 2)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    /// `ALL` is indexed by discriminant, so a reordered or duplicated row would
    /// silently give one knob another's metadata — the same pin `Report::ALL`
    /// carries. Paired with the CLI registry gate in `cargo-patina`, which is
    /// what catches a variant left out of the list entirely.
    #[test]
    fn all_is_in_variant_order() {
        for (index, knob) in FaultKnob::ALL.iter().enumerate() {
            assert_eq!(
                *knob as usize, index,
                "FaultKnob::ALL must be in variant order"
            );
        }
    }

    /// Every column of the table is a distinct spelling of ONE knob, so no two
    /// knobs may share a flag, a control-plane variable, or a swarm token.
    #[test]
    fn every_knob_has_its_own_spellings() {
        let count = FaultKnob::ALL.len();
        let flags: BTreeSet<&str> = FaultKnob::ALL.iter().map(|k| k.meta().flag).collect();
        let envs: BTreeSet<&str> = FaultKnob::ALL.iter().map(|k| k.meta().env).collect();
        assert_eq!(flags.len(), count, "two knobs share a CLI flag");
        assert_eq!(
            envs.len(),
            count,
            "two knobs share a control-plane variable"
        );

        let tokens: Vec<&str> = FaultKnob::ALL
            .iter()
            .filter_map(|k| k.meta().swarm_class)
            .collect();
        assert_eq!(
            tokens.iter().collect::<BTreeSet<_>>().len(),
            tokens.len(),
            "two knobs claim the same swarm class"
        );
    }

    /// The knob table and the swarm class table are two halves of one fact. A
    /// knob that names a class must be masked by exactly that class, and a class
    /// must mask only knobs that name it — so a copy-pasted row or a class token
    /// renamed on one side cannot drift.
    #[test]
    fn swarm_classes_and_knobs_agree() {
        let mut declared: BTreeMap<&str, Vec<FaultKnob>> = BTreeMap::new();
        for knob in FaultKnob::ALL {
            if let Some(token) = knob.meta().swarm_class {
                declared.entry(token).or_default().push(*knob);
            }
        }
        let mut masked: BTreeMap<&str, Vec<FaultKnob>> = BTreeMap::new();
        for class in SWARM_CLASSES {
            match class.masks {
                Masks::Knobs(knobs) => {
                    assert!(!knobs.is_empty(), "{} masks nothing", class.token);
                    masked.insert(class.token, knobs.to_vec());
                }
                // The one class no fault knob owns.
                Masks::Buggify => assert_eq!(class.token, "buggify"),
            }
        }
        assert_eq!(
            masked.keys().collect::<Vec<_>>(),
            declared.keys().collect::<Vec<_>>(),
            "every swarm class must be claimed by a knob, and vice versa"
        );
        // `crash` masks `--fs-torn-granularity` too, which declares no class of
        // its own; every other class masks exactly the knobs that name it.
        for (token, knobs) in &declared {
            let masked = &masked[token];
            for knob in knobs {
                assert!(
                    masked.contains(knob),
                    "{token} does not mask the knob that names it: {knob:?}"
                );
            }
        }
        assert_eq!(
            SWARM_CLASSES
                .iter()
                .map(|class| class.domain)
                .collect::<BTreeSet<_>>()
                .len(),
            SWARM_CLASSES.len(),
            "two swarm classes share a domain label — their coins would be identical"
        );
    }

    /// The pairing behind the domain-label registry: a label declared in
    /// `patina-rng-seeded` but claimed by no knob and no swarm class is a stream
    /// nothing derives — either a knob wired to the wrong label, or a label left
    /// behind by a removed one. Scanned from the source so a label cannot be
    /// added without a home.
    #[test]
    fn every_domain_label_is_claimed() {
        let source = include_str!("../../patina-rng-seeded/src/lib.rs");
        let declared: BTreeSet<&str> = source
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("pub const ")?;
                let (_, value) = rest.split_once(": &str = ")?;
                Some(value.trim().trim_end_matches(';').trim_matches('"'))
            })
            .collect();
        assert!(
            declared.len() > 20,
            "the label scan matched almost nothing — the declaration shape changed"
        );

        let mut claimed: BTreeSet<&str> = FaultKnob::ALL
            .iter()
            .flat_map(|knob| knob.meta().injection_domains.iter().copied())
            .collect();
        claimed.extend(SWARM_CLASSES.iter().map(|class| class.domain));
        // Guest entropy is not a fault knob: it is the run's baseline
        // nondeterminism source, always active and never masked.
        claimed.insert(fault_domain::ENTROPY);
        // The scheduler's own streams are not fault knobs: they are the core
        // selection/exploration-policy generators, always active (default
        // selection) or gated by the schedule-policy config rather than a
        // fault knob, and never masked.
        claimed.insert(fault_domain::SCHED_MAIN);
        claimed.insert(fault_domain::SCHED_PCT);
        claimed.insert(fault_domain::SCHED_STARVE);

        assert_eq!(
            declared, claimed,
            "every fault_domain label needs a knob or swarm class that draws from it (and vice versa)"
        );
    }

    /// A `Plane::DnsTable` knob is semantic configuration, not a `FaultConfig`
    /// field — the claim `is_set` and `clear` make. If one ever grows a fault
    /// field, both would start lying, so pin it.
    #[test]
    fn dns_table_knobs_are_outside_faultconfig() {
        for knob in FaultKnob::ALL {
            if knob.meta().plane != Plane::DnsTable {
                continue;
            }
            let mut faults = FaultConfig::default();
            knob.set_sample(&mut faults);
            assert_eq!(
                faults,
                FaultConfig::default(),
                "{knob:?} is on the DNS table plane but touched FaultConfig"
            );
            assert!(!knob.is_set(&faults));
        }
    }

    /// Every `Plane::Fault` knob's sample must be observable in `FaultConfig`,
    /// which is what makes the coverage gates elsewhere non-vacuous: a knob whose
    /// `set_sample` did nothing would pass them by accident.
    #[test]
    fn every_fault_plane_knob_has_a_live_sample() {
        for knob in FaultKnob::ALL {
            if knob.meta().plane != Plane::Fault {
                continue;
            }
            let mut faults = FaultConfig::default();
            knob.set_sample(&mut faults);
            assert!(knob.is_set(&faults), "{knob:?} has an inert sample value");
            knob.clear(&mut faults);
            assert_eq!(
                faults,
                FaultConfig::default(),
                "{knob:?} left residue behind after clear()"
            );
        }
    }
}
