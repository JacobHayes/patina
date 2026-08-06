//! A deterministic entropy byte stream and seed-derivation helpers based on SplitMix64.

use patina_dst_driver_api::{DriverResult, EntropyDriver};

/// Stable domain labels for root-seed-derived fault and nondeterminism streams.
///
/// These labels are intentionally human-readable and centralized: any runtime
/// stream that derives from the root seed should do so through [`domain_seed`]
/// with one of these labels (or a new label added here), not through ad-hoc XOR
/// constants or by reusing the root seed directly.
pub mod fault_domain {
    /// Guest entropy bytes (`Context::entropy_bytes`, WASI `random_get`, native
    /// `getrandom`/`getentropy` interposers).
    pub const ENTROPY: &str = "patina.entropy";
    /// SimNet's seeded network fault stream (drop, retransmit, jitter).
    pub const NET_FAULT: &str = "patina.net.fault";
    /// Seeded extra latency applied to guest sleeps.
    pub const SLEEP_JITTER: &str = "patina.clock.sleep_jitter";

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
    /// Seeded DNS resolution-fault stream (failure decision and its errno pick).
    pub const DNS_FAULT: &str = "patina.dns.fault";
    /// Context-side per-resolution DNS latency stream.
    pub const DNS_LATENCY: &str = "patina.dns.latency";

    /// Context-side per-operation filesystem latency stream. Latency needs the
    /// clock, so unlike the error/short streams it is drawn by the Context rather
    /// than by a wrapper driver.
    pub const FS_LATENCY: &str = "patina.fs.latency";

    /// Swarm per-class coin for crash/torn-write knobs.
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
    /// Swarm per-class coin for cooperative-SUT buggify.
    pub const SWARM_BUGGIFY: &str = "patina.swarm.buggify";
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

/// A deterministic entropy source with chunk-independent output.
///
/// Words are generated with SplitMix64 and emitted in little-endian order.
/// Buffered bytes ensure that `fill(3)` followed by `fill(5)` is identical to
/// `fill(8)` for a fresh driver with the same seed.
pub struct SeededEntropy {
    generator: SplitMix64,
    buffered: [u8; 8],
    next_buffered: usize,
}

impl SeededEntropy {
    pub fn new(seed: u64) -> Self {
        Self {
            generator: SplitMix64::new(seed),
            buffered: [0; 8],
            next_buffered: 8,
        }
    }
}

impl EntropyDriver for SeededEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> DriverResult<()> {
        for byte in destination {
            if self.next_buffered == self.buffered.len() {
                self.buffered = self.generator.next_u64().to_le_bytes();
                self.next_buffered = 0;
            }
            *byte = self.buffered[self.next_buffered];
            self.next_buffered += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_driver_api::EntropyDriver;

    use super::*;

    #[test]
    fn splitmix64_has_a_fixed_byte_stream() {
        let mut entropy = SeededEntropy::new(0);
        let mut bytes = [0; 16];
        entropy.fill(&mut bytes).unwrap();
        assert_eq!(
            bytes,
            [
                0xaf, 0xcd, 0x1d, 0x7b, 0x39, 0xa8, 0x20, 0xe2, 0xf4, 0x65, 0xb9, 0xa1, 0x6a, 0x9e,
                0x78, 0x6e,
            ]
        );
    }

    #[test]
    fn output_does_not_depend_on_fill_chunking() {
        let mut whole = SeededEntropy::new(42);
        let mut expected = [0; 19];
        whole.fill(&mut expected).unwrap();

        let mut chunked = SeededEntropy::new(42);
        let mut actual = [0; 19];
        chunked.fill(&mut actual[..3]).unwrap();
        chunked.fill(&mut actual[3..11]).unwrap();
        chunked.fill(&mut actual[11..]).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn different_seeds_change_the_stream() {
        let mut left = SeededEntropy::new(1);
        let mut right = SeededEntropy::new(2);
        let mut left_bytes = [0; 8];
        let mut right_bytes = [0; 8];
        left.fill(&mut left_bytes).unwrap();
        right.fill(&mut right_bytes).unwrap();
        assert_ne!(left_bytes, right_bytes);
    }

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

        // RED-before-GREEN for the historical aliasing class: before Wave A,
        // runtime entropy and SimNet net faults both used `SplitMix64::new(root)`.
        // These first words would therefore have been equal; domain labels make
        // the streams independent while keeping each stream deterministic.
        let old_root_first = SplitMix64::new(7).next_u64();
        let entropy_first = SplitMix64::new(entropy_seed).next_u64();
        let net_first = SplitMix64::new(net_seed).next_u64();
        assert_ne!(entropy_first, old_root_first);
        assert_ne!(entropy_first, net_first);
    }
}
