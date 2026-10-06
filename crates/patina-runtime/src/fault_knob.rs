//! Fault controls: one declaration owns variants, storage and metadata.

use patina_dst_rng_seeded::fault_domain;

use crate::{
    CrashPoint, ENV_CLOCK_FAULT_REPORT, ENV_CUSTOM_OP_FAIL_PERMILLE, ENV_CUSTOMOP_FAULT_REPORT,
    ENV_DNS_ENTRIES, ENV_DNS_FAIL_PERMILLE, ENV_DNS_FAULT_REPORT, ENV_DNS_LATENCY,
    ENV_ENTROPY_FAIL_PERMILLE, ENV_ENTROPY_FAULT_REPORT, ENV_EPOCH_JUMP_NANOS, ENV_FS_CRASH_AT,
    ENV_FS_ERROR_PERMILLE, ENV_FS_FAULT_REPORT, ENV_FS_LATENCY, ENV_FS_SHORT_PERMILLE,
    ENV_FS_TORN_GRANULARITY, ENV_NET_CONNECT_REFUSE_PERMILLE, ENV_NET_DROP_PERMILLE,
    ENV_NET_DUPLICATE_PERMILLE, ENV_NET_FAULT_REPORT, ENV_NET_JITTER, ENV_NET_LATENCY,
    ENV_NET_PARTITIONS, ENV_NET_RESET_PERMILLE, ENV_NET_TCP_BUFFER_BYTES, ENV_SLEEP_JITTER,
    FINGERPRINT_BUGGIFY, TornGranularity,
};

/// How a knob's value reaches a guest over the `PATINA_*` control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plumbing {
    /// One validated raw value, carried verbatim on its own variable. The runtime
    /// re-parses the same protocol string on record and on replay.
    Scalar,
    /// A repeatable flag whose whole SET is carried as one encoded payload, and
    /// which is re-emitted onto a child command line once per element.
    Repeatable(RepeatableFormat),
}

/// Encoding of a repeatable control-plane payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepeatableFormat {
    AddressPairs,
    DnsEntries,
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
    /// The CLI spelling. Help rows derive from ALL through an exhaustive
    /// grammar/prose match, so a knob cannot lack a registry row.
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
    /// names both. Domain labels are shared constants; merely declaring an
    /// unused label has no effect on a run.
    pub injection_domains: &'static [&'static str],
    /// The swarm mask owner, including modifiers sharing their primary knob's
    /// class. Semantic configuration has no owner: swarm masks faults, not workload.
    pub swarm_class: Option<&'static str>,
    /// The `PATINA_*_REPORT` diagnostic line carrying the knob's per-class
    /// vacuity counters, or `None` for a knob with no rate to judge inert.
    pub report: Option<&'static str>,
}

// Fields and knobs cannot be declared independently. Semantic rows have no
// FaultConfig storage and generate inert field operations by construction.
macro_rules! fault_registry {
    (
        configs { $( $config:ident as $group:ident {
            $( $(#[$doc:meta])* $field:ident: $ty:ty => $variant:ident = $index:literal {
                meta: KnobMeta { $($meta:tt)* }, sample: $sample:expr,
            } )+
        } )+ }
        semantic { $( $semantic:ident = $semantic_index:literal => KnobMeta { $($semantic_meta:tt)* }; )+ }
    ) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct FaultConfig { $(pub $group: $config,)+ }
        $(
            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct $config { $( $(#[$doc])* pub $field: $ty, )+ }
        )+
        /// All fault controls, including semantic host-table configuration.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum FaultKnob { $($( $variant = $index, )+)+ $( $semantic = $semantic_index, )+ }
        impl FaultKnob {
            /// Registry order, preserved independently of storage grouping.
            pub const ALL: &'static [Self] = &{
                let mut rows = [$($(Self::$variant,)+)+ $(Self::$semantic,)+];
                let mut i = 0;
                while i < rows.len() {
                    let mut j = i + 1;
                    while j < rows.len() {
                        if (rows[j] as usize) < rows[i] as usize {
                            let saved = rows[i]; rows[i] = rows[j]; rows[j] = saved;
                        }
                        j += 1;
                    }
                    i += 1;
                }
                rows
            };
            #[must_use]
            pub const fn meta(self) -> KnobMeta {
                match self {
                    $($(Self::$variant => KnobMeta { plane: Plane::Fault, $($meta)* },)+)+
                    $(Self::$semantic => KnobMeta { plane: Plane::DnsTable, $($semantic_meta)* },)+
                }
            }
            #[must_use]
            pub fn is_set(self, faults: &FaultConfig) -> bool {
                match self {
                    $($(Self::$variant => faults.$group.$field != <$ty>::default(),)+)+
                    $(Self::$semantic => false,)+
                }
            }
            pub fn clear(self, faults: &mut FaultConfig) {
                match self {
                    $($(Self::$variant => faults.$group.$field = <$ty>::default(),)+)+
                    $(Self::$semantic => {},)+
                }
            }
            #[cfg(test)]
            pub(crate) fn set_sample(self, faults: &mut FaultConfig) {
                match self {
                    $($(Self::$variant => faults.$group.$field = $sample,)+)+
                    $(Self::$semantic => {},)+
                }
            }
        }
    };
}

fault_registry! {
    configs {
        FsFaultConfig as fs {
            /// Inject a filesystem crash after a chosen boundary operation.
            crash_at: Option<CrashPoint> => FsCrashAt = 0 {
                meta: KnobMeta {
                    flag: "--fs-crash-at",
                    env: ENV_FS_CRASH_AT,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::FS_CRASH],
                    swarm_class: Some("crash"),
                    // A crash fires at a chosen boundary op, not at a rate, so there
                    // is no "should have fired N times" judgement to report.
                    report: None,
                },
                sample: Some(crate::CrashPoint { op: crate::CrashOp::Close, ordinal: 1 }),
            }
            /// Granularity at which the injected crash tears the final unsynced write.
            /// Inert without `crash_at`; defaults to whole-block.
            torn_granularity: TornGranularity => FsTornGranularity = 1 {
                meta: KnobMeta {
                    flag: "--fs-torn-granularity",
                    env: ENV_FS_TORN_GRANULARITY,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::FS_CRASH],
                    swarm_class: Some("crash"),
                    report: None,
                },
                sample: TornGranularity::Byte,
            }
            /// Seeded filesystem error probability in per-mille (0..=1000).
            error_permille: u16 => FsErrorPermille = 2 {
                meta: KnobMeta {
                    flag: "--fs-error-permille",
                    env: ENV_FS_ERROR_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::FAULT_FS_ERROR],
                    swarm_class: Some("fs_error"),
                    report: Some(ENV_FS_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Seeded short-read/short-write probability in per-mille (0..=1000).
            short_permille: u16 => FsShortPermille = 3 {
                meta: KnobMeta {
                    flag: "--fs-short-permille",
                    env: ENV_FS_SHORT_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::FAULT_FS_SHORT],
                    swarm_class: Some("fs_short"),
                    report: Some(ENV_FS_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Inclusive `[min, max]` nanoseconds of seeded extra latency applied to
            /// every fault-eligible filesystem operation before it executes.
            latency_nanos: Option<(u64, u64)> => FsLatencyNanos = 4 {
                meta: KnobMeta {
                    flag: "--fs-latency-nanos",
                    env: ENV_FS_LATENCY,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::FS_LATENCY],
                    swarm_class: Some("fs_latency"),
                    report: Some(ENV_FS_FAULT_REPORT),
                },
                sample: Some((1, 2)),
            }
        }
        NetFaultConfig as net {
            /// Base link latency in nanoseconds applied to the default `SimNet` network.
            latency_nanos: u64 => NetLatencyNanos = 8 {
                meta: KnobMeta {
                    flag: "--net-latency-nanos",
                    env: ENV_NET_LATENCY,
                    plumbing: Plumbing::Scalar,
                    // A deterministic base link latency: applied to every delivery
                    // rather than drawn, so it derives no stream of its own.
                    injection_domains: &[],
                    swarm_class: Some("net_latency"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Inclusive `[min, max]` nanoseconds of seeded per-datagram/segment delivery jitter.
            jitter_nanos: Option<(u64, u64)> => NetJitterNanos = 6 {
                meta: KnobMeta {
                    flag: "--net-jitter-nanos",
                    env: ENV_NET_JITTER,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::NET_FAULT],
                    swarm_class: Some("net_jitter"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: Some((1, 2)),
            }
            /// Seeded datagram drop probability in per-mille (0..=1000).
            drop_permille: u16 => NetDropPermille = 7 {
                meta: KnobMeta {
                    flag: "--net-drop-permille",
                    env: ENV_NET_DROP_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::NET_FAULT, fault_domain::FAULT_NET_DROP],
                    swarm_class: Some("net_drop"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Seeded datagram duplication probability in per-mille (0..=1000). A
            /// duplicate is an independent copy with its own jitter draw.
            duplicate_permille: u16 => NetDuplicatePermille = 9 {
                meta: KnobMeta {
                    flag: "--net-duplicate-permille",
                    env: ENV_NET_DUPLICATE_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[
                    fault_domain::NET_DUPLICATE,
                    fault_domain::FAULT_NET_DUPLICATE,
                    ],
                    swarm_class: Some("net_duplicate"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Seeded probability in per-mille (0..=1000) that an otherwise-establishable
            /// TCP connection is refused.
            connect_refuse_permille: u16 => NetConnectRefusePermille = 10 {
                meta: KnobMeta {
                    flag: "--net-connect-refuse-permille",
                    env: ENV_NET_CONNECT_REFUSE_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::NET_CONNECT_REFUSE],
                    swarm_class: Some("net_connect_refuse"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Seeded probability in per-mille (0..=1000) that a fault-eligible
            /// established-stream operation tears the stream down with a reset.
            reset_permille: u16 => NetResetPermille = 11 {
                meta: KnobMeta {
                    flag: "--net-reset-permille",
                    env: ENV_NET_RESET_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::NET_RESET],
                    swarm_class: Some("net_reset"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Statically partitioned address pairs. Both directions of each pair are
            /// blocked: a datagram addressed across it is dropped and a connect across it
            /// is refused. Deterministic (rate 1.0), unlike the seeded knobs above.
            partitions: std::collections::BTreeSet<(String, String)> => NetPartition = 12 {
                meta: KnobMeta {
                    flag: "--net-partition",
                    env: ENV_NET_PARTITIONS,
                    plumbing: Plumbing::Repeatable(RepeatableFormat::AddressPairs),
                    // Deterministic (rate 1.0): a datagram across a partition is
                    // always dropped, so nothing is drawn.
                    injection_domains: &[],
                    swarm_class: Some("net_partition"),
                    report: Some(ENV_NET_FAULT_REPORT),
                },
                sample: std::collections::BTreeSet::from([("a".to_string(), "b".to_string()), ("b".to_string(), "a".to_string())]),
            }
            /// Virtual TCP receive-buffer size in bytes. `None` uses the driver default.
            /// Not a fault: a capacity setting whose smaller values make would-block
            /// behavior — and the guest's backpressure handling — reachable, so it has a
            /// swarm class (an environment shape a generation may or may not adopt) but
            /// no vacuity class (there is no "should have fired N times" rate to judge).
            tcp_buffer_bytes: Option<usize> => NetTcpBufferBytes = 13 {
                meta: KnobMeta {
                    flag: "--net-tcp-buffer-bytes",
                    env: ENV_NET_TCP_BUFFER_BYTES,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[],
                    swarm_class: Some("net_tcp_buffer"),
                    // A capacity setting, not a fault: there is no rate that "should
                    // have fired", so no vacuity counter to report.
                    report: None,
                },
                sample: Some(4096),
            }
        }
        ClockFaultConfig as clock {
            /// Inclusive `[min, max]` nanoseconds of seeded extra latency per guest sleep.
            sleep_jitter_nanos: Option<(u64, u64)> => SleepJitterNanos = 5 {
                meta: KnobMeta {
                    flag: "--sleep-jitter-nanos",
                    env: ENV_SLEEP_JITTER,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::SLEEP_JITTER],
                    swarm_class: Some("sleep_jitter"),
                    // The clock plane has no fault report: a sleep that was delayed
                    // is indistinguishable from a longer sleep, so there is nothing
                    // to count as "applied".
                    report: None,
                },
                sample: Some((1, 2)),
            }
            /// Magnitude in nanoseconds of the seeded signed realtime-epoch jump applied
            /// to each `ClockKind::Realtime` read: an offset drawn uniformly in `[-hi,
            /// hi]`, independently per read. Zero (the default) is off.
            epoch_jump_nanos: u64 => EpochJumpNanos = 15 {
                meta: KnobMeta {
                    flag: "--epoch-jump-nanos",
                    env: ENV_EPOCH_JUMP_NANOS,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::EPOCH_JUMP],
                    swarm_class: Some("epoch_jump"),
                    report: Some(ENV_CLOCK_FAULT_REPORT),
                },
                sample: 1,
            }
        }
        DnsFaultConfig as dns {
            /// Seeded resolution-failure probability in per-mille (0..=1000). On fire, a
            /// second draw picks NXDOMAIN (a stale or deleted record) or a transient
            /// timeout (a slow or unreachable resolver).
            fail_permille: u16 => DnsFailPermille = 18 {
                meta: KnobMeta {
                    flag: "--dns-fail-permille",
                    env: ENV_DNS_FAIL_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::DNS_FAULT],
                    swarm_class: Some("dns_fail"),
                    report: Some(ENV_DNS_FAULT_REPORT),
                },
                sample: 1,
            }
            /// Inclusive `[min, max]` nanoseconds of seeded latency applied before every
            /// eligible resolution.
            latency_nanos: Option<(u64, u64)> => DnsLatencyNanos = 19 {
                meta: KnobMeta {
                    flag: "--dns-latency-nanos",
                    env: ENV_DNS_LATENCY,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::DNS_LATENCY],
                    swarm_class: Some("dns_latency"),
                    report: Some(ENV_DNS_FAULT_REPORT),
                },
                sample: Some((1, 2)),
            }
        }
        EntropyFaultConfig as entropy {
            /// Seeded entropy-request failure probability in per-mille (0..=1000). On
            /// fire, the request returns a deterministic named error instead of bytes.
            fail_permille: u16 => EntropyFailPermille = 14 {
                meta: KnobMeta {
                    flag: "--entropy-fail-permille",
                    env: ENV_ENTROPY_FAIL_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    injection_domains: &[fault_domain::ENTROPY_FAULT],
                    swarm_class: Some("entropy_fail"),
                    report: Some(ENV_ENTROPY_FAULT_REPORT),
                },
                sample: 1,
            }
        }
        CustomOpFaultConfig as custom_op {
            /// Seeded failure probability in per-mille (0..=1000) for custom operations
            /// the guest declared fault-eligible. On fire the operation's `perform`
            /// closure does NOT run and the guest receives the failure it declared,
            /// exactly as if the wrapped effect had failed.
            ///
            /// Applies only to declared-eligible operations: a custom op that declares
            /// no failure shape has no error the runtime could invent for it, and
            /// inventing one would mean handing a guest a value its own type does not
            /// admit.
            fail_permille: u16 => CustomOpFailPermille = 16 {
                meta: KnobMeta {
                    flag: "--custom-op-fail-permille",
                    env: ENV_CUSTOM_OP_FAIL_PERMILLE,
                    plumbing: Plumbing::Scalar,
                    // One label here, but the stream it names is a FAMILY: each
                    // custom-op label draws from its own child stream keyed by this
                    // domain and the label's hash, so arming the knob over one
                    // operation class does not shift another's decisions.
                    injection_domains: &[fault_domain::CUSTOM_OP_FAULT],
                    swarm_class: Some("custom_op_fail"),
                    report: Some(ENV_CUSTOMOP_FAULT_REPORT),
                },
                sample: 1,
            }
        }
    }
    semantic { DnsEntry = 17 => KnobMeta {
            flag: "--dns-entry",
            env: ENV_DNS_ENTRIES,
            plumbing: Plumbing::Repeatable(RepeatableFormat::DnsEntries),
            injection_domains: &[],
            swarm_class: None,
            report: None,
        }; }
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

// Const string comparison for registry validation and mask derivation.
const fn same(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
const fn mask_count(token: &str) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < FaultKnob::ALL.len() {
        if let Some(class) = FaultKnob::ALL[i].meta().swarm_class
            && same(class, token)
        {
            count += 1;
        }
        i += 1;
    }
    count
}
const fn mask_knobs<const N: usize>(token: &str) -> [FaultKnob; N] {
    let mut rows = [FaultKnob::ALL[0]; N];
    let mut index = 0;
    let mut i = 0;
    while i < FaultKnob::ALL.len() {
        let knob = FaultKnob::ALL[i];
        if let Some(class) = knob.meta().swarm_class
            && same(class, token)
        {
            rows[index] = knob;
            index += 1;
        }
        i += 1;
    }
    assert!(index == N && N > 0, "swarm class masks no knobs");
    rows
}

// One token supplies both the trace-visible row and its generated mask.
macro_rules! swarm_class {
    ($token:literal, $domain:expr) => {
        SwarmClass {
            token: $token,
            domain: $domain,
            fingerprint_component: None,
            masks: Masks::Knobs(&mask_knobs::<{ mask_count($token) }>($token)),
        }
    };
}

/// The swarm classes in DRAW ORDER — the order candidate and selected tokens are
/// recorded in, which makes it trace-visible and therefore load-bearing. Each
/// class draws from its own domain-separated coin, so the order does not affect
/// any decision, only the record.
///
/// Deliberately not [`FaultKnob::ALL`]'s order, and not one row per knob:
/// `crash` covers two knobs, `--dns-entry` has no class, and `buggify` masks
/// configuration no fault knob owns. Masks derive from knob metadata; const
/// checks reject unknown class tokens, empty masks and duplicate draw domains.
pub const SWARM_CLASSES: &[SwarmClass] = &[
    swarm_class!("crash", fault_domain::SWARM_CRASH),
    swarm_class!("fs_error", fault_domain::SWARM_FS_ERROR),
    swarm_class!("fs_short", fault_domain::SWARM_FS_SHORT),
    swarm_class!("fs_latency", fault_domain::SWARM_FS_LATENCY),
    swarm_class!("dns_fail", fault_domain::SWARM_DNS_FAIL),
    swarm_class!("dns_latency", fault_domain::SWARM_DNS_LATENCY),
    swarm_class!("sleep_jitter", fault_domain::SWARM_SLEEP_JITTER),
    swarm_class!("net_jitter", fault_domain::SWARM_NET_JITTER),
    swarm_class!("net_drop", fault_domain::SWARM_NET_DROP),
    swarm_class!("net_latency", fault_domain::SWARM_NET_LATENCY),
    swarm_class!("net_duplicate", fault_domain::SWARM_NET_DUPLICATE),
    swarm_class!("net_connect_refuse", fault_domain::SWARM_NET_CONNECT_REFUSE),
    swarm_class!("net_reset", fault_domain::SWARM_NET_RESET),
    swarm_class!("net_partition", fault_domain::SWARM_NET_PARTITION),
    swarm_class!("net_tcp_buffer", fault_domain::SWARM_NET_TCP_BUFFER),
    swarm_class!("entropy_fail", fault_domain::SWARM_ENTROPY_FAIL),
    SwarmClass {
        token: "buggify",
        domain: fault_domain::SWARM_BUGGIFY,
        fingerprint_component: Some(FINGERPRINT_BUGGIFY),
        masks: Masks::Buggify,
    },
    // Appended at the END rather than beside the other clock-domain row
    // (`sleep_jitter`, above): draw order is trace-visible, so a new class
    // never gets inserted where it would shift every later class's position
    // in an existing recorded candidate list.
    swarm_class!("epoch_jump", fault_domain::SWARM_EPOCH_JUMP),
    swarm_class!("custom_op_fail", fault_domain::SWARM_CUSTOM_OP_FAIL),
];

// Unique control-plane spellings and complete mask ownership are build gates.
const _: () = {
    let mut i = 0;
    while i < FaultKnob::ALL.len() {
        let meta = FaultKnob::ALL[i].meta();
        let mut j = i + 1;
        while j < FaultKnob::ALL.len() {
            let other = FaultKnob::ALL[j].meta();
            assert!(!same(meta.flag, other.flag), "duplicate knob flag");
            assert!(
                !same(meta.env, other.env),
                "duplicate knob environment variable"
            );
            j += 1;
        }
        if let Some(token) = meta.swarm_class {
            let mut found = false;
            j = 0;
            while j < SWARM_CLASSES.len() {
                if same(token, SWARM_CLASSES[j].token) {
                    found = true;
                }
                j += 1;
            }
            assert!(found, "knob names an undeclared swarm class");
        }
        i += 1;
    }
    i = 0;
    while i < SWARM_CLASSES.len() {
        let mut j = i + 1;
        while j < SWARM_CLASSES.len() {
            assert!(
                !same(SWARM_CLASSES[i].token, SWARM_CLASSES[j].token),
                "duplicate swarm token"
            );
            assert!(
                !same(SWARM_CLASSES[i].domain, SWARM_CLASSES[j].domain),
                "duplicate swarm domain"
            );
            j += 1;
        }
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

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
