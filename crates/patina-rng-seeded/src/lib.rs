//! SplitMix64 and the seed-derivation helpers every deterministic stream uses.

/// Stable domain labels for root-seed-derived fault and nondeterminism streams.
///
/// These labels are intentionally human-readable and centralized: any runtime
/// stream that derives from the root seed should do so through [`domain_seed`]
/// with one of these labels (or a new label added here), not through ad-hoc XOR
/// constants or by reusing the root seed directly.
pub mod fault_domain {
    /// Guest entropy bytes (`Context::entropy_bytes`, native
    /// `getrandom`/`getentropy`/`CCRandomGenerateBytes` interposers and
    /// `/dev/urandom` reads).
    pub const ENTROPY: &str = "patina.entropy";
    /// SimNet's seeded network fault stream (drop, retransmit, jitter).
    pub const NET_FAULT: &str = "patina.net.fault";
    /// SimNet's seeded datagram-duplication stream. Derived from the net-fault
    /// seed rather than the root seed, like the two labels below: the driver is
    /// handed ONE network seed, and separating its classes below that seed keeps
    /// enabling one class from shifting another class's decisions.
    pub const NET_DUPLICATE: &str = "patina.net.duplicate";
    /// SimNet's seeded TCP connect-refusal stream.
    pub const NET_CONNECT_REFUSE: &str = "patina.net.connect_refuse";
    /// SimNet's seeded TCP stream-reset stream.
    pub const NET_RESET: &str = "patina.net.reset";
    /// Seeded extra latency applied to guest sleeps.
    pub const SLEEP_JITTER: &str = "patina.clock.sleep_jitter";

    /// The deterministic scheduler's default uniform-random task-selection
    /// stream.
    pub const SCHED_MAIN: &str = "patina.sched.main";
    /// The deterministic scheduler's PCT (Probabilistic Concurrency Testing)
    /// priority/change-point stream.
    pub const SCHED_PCT: &str = "patina.sched.pct";

    /// Explicit `FaultNet` wrapper datagram-drop stream.
    pub const FAULT_NET_DROP: &str = "patina.wrapper.fault_net.drop";
    /// Explicit `FaultNet` wrapper datagram-duplication stream.
    pub const FAULT_NET_DUPLICATE: &str = "patina.wrapper.fault_net.duplicate";
    /// Managed/default `FaultFs` filesystem-error stream.
    pub const FAULT_FS_ERROR: &str = "patina.wrapper.fault_fs.error";
    /// Managed/default `FaultFs` short-I/O stream.
    pub const FAULT_FS_SHORT: &str = "patina.wrapper.fault_fs.short";

    /// CrashFs torn-write/crash-model stream.
    pub const FS_CRASH: &str = "patina.fs.crash";
    /// Per-crash-point draw deciding where a crash-restart run crashes.
    pub const CRASH_POINT: &str = "patina.crash.point";
    /// Seeded DNS resolution-fault stream (failure decision and its errno pick).
    pub const DNS_FAULT: &str = "patina.dns.fault";
    /// Context-side per-resolution DNS latency stream.
    pub const DNS_LATENCY: &str = "patina.dns.latency";

    /// Seeded entropy-request failure-decision stream (`--entropy-fail-permille`).
    /// Deliberately separate from [`ENTROPY`]: drawing the fire/no-fire decision
    /// from the guest-visible entropy stream itself would perturb every
    /// non-faulted request's bytes the moment the knob was armed.
    pub const ENTROPY_FAULT: &str = "patina.entropy.fail";

    /// Seeded realtime-epoch jump-offset stream (`--epoch-jump-nanos`). Its own
    /// label rather than riding a clock stream that also exists: there is no
    /// other Context-side realtime stream to share, and a dedicated label keeps
    /// a future clock knob from silently correlating with this one.
    pub const EPOCH_JUMP: &str = "patina.clock.epoch_jump";

    /// Context-side per-operation filesystem latency stream. Latency needs the
    /// clock, so unlike the error/short streams it is drawn by the Context rather
    /// than by a wrapper driver.
    pub const FS_LATENCY: &str = "patina.fs.latency";

    /// Seeded guest custom-operation failure-decision stream
    /// (`--custom-op-fail-permille`). The root of a per-LABEL family of streams
    /// rather than one stream: a custom op's label names an operation class the
    /// guest declared, and two classes sharing a coin would make arming a fault
    /// on one shift the other's decisions. Each label's stream is keyed by this
    /// domain seed and the label's own hash.
    pub const CUSTOM_OP_FAULT: &str = "patina.custom_op.fail";

    /// Keys a restarted incarnation's stream root to its incarnation number
    /// ([`super::incarnation_seed`]), so each boot of a crash-restart run
    /// draws its own streams from the run's seed.
    pub const INCARNATION: &str = "patina.incarnation";
    /// The seeded downtime between a modeled crash and the restarted
    /// incarnation's boot: how far realtime moves on while the machine is down.
    pub const RESTART_DOWNTIME: &str = "patina.clock.restart_downtime";

    /// Swarm per-class coin for the crash knobs.
    pub const SWARM_CRASH: &str = "patina.swarm.crash";
    /// Swarm per-class coin for sleep jitter.
    pub const SWARM_SLEEP_JITTER: &str = "patina.swarm.sleep_jitter";
    /// Swarm per-class coin for network jitter.
    pub const SWARM_NET_JITTER: &str = "patina.swarm.net_jitter";
    /// Swarm per-class coin for filesystem error injection.
    pub const SWARM_FS_ERROR: &str = "patina.swarm.fs_error";
    /// Swarm per-class coin for filesystem short-I/O injection.
    pub const SWARM_FS_SHORT: &str = "patina.swarm.fs_short";
    /// Swarm per-class coin for filesystem operation latency.
    pub const SWARM_FS_LATENCY: &str = "patina.swarm.fs_latency";
    /// Swarm per-class coin for DNS resolution failure.
    pub const SWARM_DNS_FAIL: &str = "patina.swarm.dns_fail";
    /// Swarm per-class coin for DNS resolution latency.
    pub const SWARM_DNS_LATENCY: &str = "patina.swarm.dns_latency";
    /// Swarm per-class coin for network drop.
    pub const SWARM_NET_DROP: &str = "patina.swarm.net_drop";
    /// Swarm per-class coin for network base latency.
    pub const SWARM_NET_LATENCY: &str = "patina.swarm.net_latency";
    /// Swarm per-class coin for datagram duplication.
    pub const SWARM_NET_DUPLICATE: &str = "patina.swarm.net_duplicate";
    /// Swarm per-class coin for TCP connect refusal.
    pub const SWARM_NET_CONNECT_REFUSE: &str = "patina.swarm.net_connect_refuse";
    /// Swarm per-class coin for TCP stream reset.
    pub const SWARM_NET_RESET: &str = "patina.swarm.net_reset";
    /// Swarm per-class coin for the static network partitions.
    pub const SWARM_NET_PARTITION: &str = "patina.swarm.net_partition";
    /// Swarm per-class coin for the virtual TCP receive-buffer size.
    pub const SWARM_NET_TCP_BUFFER: &str = "patina.swarm.net_tcp_buffer";
    /// Swarm per-class coin for cooperative-SUT buggify.
    pub const SWARM_BUGGIFY: &str = "patina.swarm.buggify";
    /// Swarm per-class coin for entropy-request failure injection.
    pub const SWARM_ENTROPY_FAIL: &str = "patina.swarm.entropy_fail";
    /// Swarm per-class coin for the realtime-epoch jump.
    pub const SWARM_EPOCH_JUMP: &str = "patina.swarm.epoch_jump";
    /// Swarm per-class coin for guest custom-operation failure injection.
    pub const SWARM_CUSTOM_OP_FAIL: &str = "patina.swarm.custom_op_fail";
}

/// The specified SplitMix64 stream used by deterministic decision policies.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

/// A stable SplitMix64-style hash of a string label.
///
/// This is platform-independent and order-independent over UTF-8 bytes. It is
/// deliberately not Rust's `DefaultHasher`, whose output is not a stable format.
pub fn splitmix_hash_str(text: &str) -> u64 {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    for byte in text.bytes() {
        state = state
            .wrapping_add(u64::from(byte))
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        state = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state = (state ^ (state >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        state ^= state >> 31;
    }
    state
}

/// A deterministic pseudo-random 64-bit hash of a sequence of 64-bit words.
///
/// Used as the common PRF/finalizer for deriving independent streams from a root
/// seed. It has no state beyond the inputs and reproduces exactly across
/// processes and targets.
pub fn splitmix_hash(inputs: &[u64]) -> u64 {
    let mut acc = 0xa5a5_a5a5_5a5a_5a5a_u64;
    for &value in inputs {
        acc = SplitMix64::new(acc ^ value).next_u64();
        acc = acc.wrapping_add(value.rotate_left(17));
    }
    SplitMix64::new(acc).next_u64()
}

/// Derive a deterministic, domain-separated stream seed from a run root seed.
///
/// This is the shared derivation rule for fault/decision streams: a stream is
/// keyed by the root seed and a stable domain label, so adding one domain cannot
/// perturb or alias another domain's sequence.
pub fn domain_seed(root_seed: u64, domain: &'static str) -> u64 {
    splitmix_hash(&[root_seed, splitmix_hash_str(domain)])
}

/// The root seed one incarnation of a run derives every stream from.
///
/// Incarnation 0, the first boot of every run, uses the run's seed itself. A
/// later incarnation (a native crash restart) uses the run seed keyed
/// by its incarnation number, so its streams are fresh (a restarted process
/// draws new UUIDs, salts and nonces, as a rebooted host would) yet still a
/// pure function of the run's seed, which is what lets replay re-derive them.
pub fn incarnation_seed(run_seed: u64, incarnation: u64) -> u64 {
    match incarnation {
        0 => run_seed,
        incarnation => splitmix_hash(&[
            run_seed,
            splitmix_hash_str(fault_domain::INCARNATION),
            incarnation,
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_seed_separates_root_seed_streams() {
        let entropy_seed = domain_seed(7, fault_domain::ENTROPY);
        let net_seed = domain_seed(7, fault_domain::NET_FAULT);
        let sleep_seed = domain_seed(7, fault_domain::SLEEP_JITTER);
        assert_ne!(entropy_seed, net_seed);
        assert_ne!(entropy_seed, sleep_seed);
        assert_ne!(net_seed, sleep_seed);
        assert_eq!(entropy_seed, domain_seed(7, fault_domain::ENTROPY));
        assert_ne!(entropy_seed, domain_seed(8, fault_domain::ENTROPY));

        // A labelled stream never aliases the bare root-seeded stream.
        let old_root_first = SplitMix64::new(7).next_u64();
        let entropy_first = SplitMix64::new(entropy_seed).next_u64();
        let net_first = SplitMix64::new(net_seed).next_u64();
        assert_ne!(entropy_first, old_root_first);
        assert_ne!(entropy_first, net_first);
    }

    #[test]
    fn each_incarnation_has_its_own_root_from_the_run_seed() {
        assert_eq!(incarnation_seed(7, 0), 7);
        let restarted = incarnation_seed(7, 1);
        assert_ne!(restarted, 7);
        assert_ne!(restarted, incarnation_seed(7, 2));
        assert_ne!(restarted, incarnation_seed(8, 1));
        assert_eq!(restarted, incarnation_seed(7, 1));
    }
}
