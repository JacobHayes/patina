//! Network configuration, validation, and construction.

use std::collections::{BTreeMap, BTreeSet};

use crate::{FaultCounts, SimNet};
use patina_dst_abi::{EffectError, ErrorCode};
use patina_dst_driver_api::DriverResult;
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

#[derive(Default)]
pub struct SimNetBuilder {
    base_latency_nanos: u64,
    partitions: BTreeSet<(String, String)>,
    tcp_buffer_bytes: Option<usize>,
    fault_seed: u64,
    jitter_nanos: Option<(u64, u64)>,
    drop_permille: u16,
    duplicate_permille: u16,
    connect_refuse_permille: u16,
    reset_permille: u16,
}

impl SimNetBuilder {
    pub fn base_latency_nanos(mut self, value: u64) -> Self {
        self.base_latency_nanos = value;
        self
    }

    pub fn tcp_buffer_bytes(mut self, value: usize) -> Self {
        self.tcp_buffer_bytes = Some(value);
        self
    }

    /// Seed the deterministic datagram reorder/drop decision stream. Draws are a
    /// pure function of this seed and the exact send sequence, so identical
    /// configurations reproduce identical delivery schedules across record and
    /// replay.
    pub fn fault_seed(mut self, seed: u64) -> Self {
        self.fault_seed = seed;
        self
    }

    /// Add a seeded per-datagram delivery jitter drawn uniformly from the
    /// inclusive `[min, max]` nanosecond range. Because a blocking receiver
    /// delivers the earliest-deadline datagram first, varying per-packet jitter
    /// reorders datagrams relative to their send order — the UDP-reorder fault.
    pub fn jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.jitter_nanos = Some((min, max));
        self
    }

    /// Drop a fraction of datagrams, expressed in per-mille (0..=1000). Each send
    /// draws once against this probability before any jitter draw.
    pub fn drop_permille(mut self, permille: u16) -> Self {
        self.drop_permille = permille;
        self
    }

    /// Deliver a fraction of datagrams TWICE, expressed in per-mille (0..=1000).
    /// The duplicate is an independent copy with its own jitter draw, so the two
    /// arrivals can be separated in time and interleave with other traffic — the
    /// at-least-once delivery hazard an idempotence bug hides behind.
    pub fn duplicate_permille(mut self, permille: u16) -> Self {
        self.duplicate_permille = permille;
        self
    }

    /// Refuse a fraction of otherwise-establishable TCP connections, expressed in
    /// per-mille (0..=1000). Only connects that would have succeeded draw: a
    /// connect with no listener or a full backlog is refused by semantics.
    pub fn connect_refuse_permille(mut self, permille: u16) -> Self {
        self.connect_refuse_permille = permille;
        self
    }

    /// Reset a fraction of established TCP streams, expressed in per-mille
    /// (0..=1000). Each fault-eligible stream operation draws; on a fire the
    /// stream is torn down in BOTH directions and the operation fails with
    /// `ConnectionReset`, exactly as a peer RST does.
    pub fn reset_permille(mut self, permille: u16) -> Self {
        self.reset_permille = permille;
        self
    }

    /// Partition both directions between two exact virtual addresses.
    pub fn partition(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        let left = left.into();
        let right = right.into();
        self.partitions.insert((left.clone(), right.clone()));
        self.partitions.insert((right, left));
        self
    }

    pub fn build(self) -> DriverResult<SimNet> {
        let tcp_buffer_bytes = self.tcp_buffer_bytes.unwrap_or(65_536);
        if tcp_buffer_bytes == 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual TCP receive buffer size must be greater than zero",
            ));
        }
        if let Some((min, max)) = self.jitter_nanos
            && min > max
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual network jitter range requires min <= max",
            ));
        }
        for (name, permille) in [
            ("drop", self.drop_permille),
            ("duplicate", self.duplicate_permille),
            ("connect-refusal", self.connect_refuse_permille),
            ("reset", self.reset_permille),
        ] {
            if permille > 1000 {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "virtual network {name} probability must be within [0, 1000] per-mille"
                    ),
                ));
            }
        }
        Ok(SimNet {
            base_latency_nanos: self.base_latency_nanos,
            partitions: self.partitions,
            bindings: BTreeMap::new(),
            addresses: BTreeMap::new(),
            datagram_peers: BTreeMap::new(),
            datagram_marks: BTreeMap::new(),
            received: BTreeMap::new(),
            packets: Vec::new(),
            next_socket: 1,
            next_packet: 1,
            tcp_buffer_bytes,
            tcp_listeners: BTreeMap::new(),
            tcp_listener_addresses: BTreeMap::new(),
            tcp_endpoints: BTreeMap::new(),
            fault_rng: SplitMix64::new(self.fault_seed),
            // Each class added after the original drop/jitter pair draws from its
            // own domain-separated substream of the same net-fault seed, so
            // enabling one class cannot shift the decisions another class makes —
            // the §1.2 derivation rule applied within the driver.
            duplicate_rng: SplitMix64::new(domain_seed(
                self.fault_seed,
                fault_domain::NET_DUPLICATE,
            )),
            connect_refuse_rng: SplitMix64::new(domain_seed(
                self.fault_seed,
                fault_domain::NET_CONNECT_REFUSE,
            )),
            reset_rng: SplitMix64::new(domain_seed(self.fault_seed, fault_domain::NET_RESET)),
            jitter_nanos: self.jitter_nanos,
            drop_permille: self.drop_permille,
            duplicate_permille: self.duplicate_permille,
            connect_refuse_permille: self.connect_refuse_permille,
            reset_permille: self.reset_permille,
            counts: FaultCounts::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_builder_rejects_invalid_configuration() {
        let jitter_error = SimNet::builder()
            .jitter_nanos(100, 10)
            .build()
            .err()
            .expect("inverted jitter range must be rejected");
        assert_eq!(jitter_error.code, ErrorCode::InvalidInput);
        let drop_error = SimNet::builder()
            .drop_permille(1001)
            .build()
            .err()
            .expect("out-of-range drop probability must be rejected");
        assert_eq!(drop_error.code, ErrorCode::InvalidInput);
    }
}
