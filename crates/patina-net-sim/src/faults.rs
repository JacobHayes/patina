//! Seeded drop, jitter, retransmit, and connection-reset decisions.

use crate::SimNet;
use patina_dst_abi::SocketId;
use patina_dst_rng_seeded::SplitMix64;

/// TCP drop-retransmit backoff. A stream is reliable, so a "dropped" segment is
/// never lost — it is retransmitted after a retransmission timeout that doubles
/// per loss, is capped, and gives up after a bounded number of attempts (the
/// segment then delivers anyway). The base is deliberately small relative to
/// the millisecond-scale application timers a stream app uses, so a fault run
/// perturbs the delivery schedule without starving a liveness deadline.
const TCP_RETRANSMIT_BASE_NANOS: u64 = 200_000;
const TCP_RETRANSMIT_CAP_NANOS: u64 = 2_000_000;
const TCP_MAX_RETRANSMITS: u32 = 6;

impl SimNet {
    /// Draw the seeded drop decision for one datagram. Extreme probabilities are
    /// decision-free so the never-drop default and always-drop config do not
    /// perturb the stream consumed by jitter draws.
    pub(super) fn decide_drop(&mut self) -> bool {
        match self.drop_permille {
            0 => false,
            1000 => true,
            permille => (self.fault_rng.next_u64() % 1000) < u64::from(permille),
        }
    }

    /// Draw one seeded per-mille decision from a class's own stream. Extreme
    /// probabilities are decision-free, so a never-fire default and an
    /// always-fire configuration both leave the stream untouched.
    pub(super) fn permille_fires(rng: &mut SplitMix64, permille: u16) -> bool {
        match permille {
            0 => false,
            1000 => true,
            value => (rng.next_u64() % 1000) < u64::from(value),
        }
    }

    /// Draw the seeded per-datagram delivery jitter in nanoseconds, or zero when
    /// no jitter is configured (decision-free so latency-only configs are
    /// unaffected).
    pub(super) fn draw_jitter(&mut self) -> u64 {
        match self.jitter_nanos {
            None => 0,
            Some((min, max)) if min == max => min,
            Some((min, max)) => {
                let span = max - min + 1;
                min + (self.fault_rng.next_u64() % span)
            }
        }
    }

    /// Seeded fault delivery time for one enqueued TCP segment. TCP is
    /// reliable, so a drop is NOT data loss: it is a retransmit that delays the
    /// segment by an RTO-style backoff (doubling per loss, capped, bounded
    /// attempts), after which it delivers regardless. Per-segment jitter then
    /// adds delivery latency. In-stream ordering is preserved by never letting a
    /// segment's deadline fall before the last already-buffered one (a later
    /// segment can be delayed relative to another connection — reorder across
    /// streams — but never ahead of an earlier byte on its own stream).
    ///
    /// Draws from the same seeded stream as the datagram path, in a fixed order
    /// (drop-retransmit, then jitter), so consumption is a pure function of the
    /// send sequence and reproduces byte-identically across record and replay.
    /// Decision-free configs (drop 0/1000, no jitter, jitter min==max) draw
    /// nothing, so a run with the knobs off never perturbs the stream.
    pub(super) fn draw_tcp_fault_delivery(
        &mut self,
        base_delivery: u64,
        last_delivery: Option<u64>,
    ) -> u64 {
        self.counts.send_ops += 1;
        // The base link latency is applied by the caller (it is part of
        // `base_delivery`); count it here so a send path that skipped it reports
        // zero applications against a live knob rather than looking clean.
        if self.base_latency_nanos > 0 {
            self.counts.latency_applied += 1;
        }
        let mut delivery = base_delivery;
        let mut backoff = TCP_RETRANSMIT_BASE_NANOS;
        let mut retries = 0u32;
        while retries < TCP_MAX_RETRANSMITS && self.decide_drop() {
            delivery = delivery.saturating_add(backoff);
            backoff = backoff.saturating_mul(2).min(TCP_RETRANSMIT_CAP_NANOS);
            retries += 1;
        }
        if retries > 0 {
            self.counts.drops_applied += 1;
        }
        let jitter = self.draw_jitter();
        if jitter > 0 {
            delivery = delivery.saturating_add(jitter);
            self.counts.jitter_applied += 1;
        }
        if let Some(last) = last_delivery {
            delivery = delivery.max(last);
        }
        delivery
    }

    /// Whether an established-stream operation draws a reset this time, counting
    /// the opportunity either way. On a fire BOTH endpoints are torn down — a
    /// reset is not one-sided — and the caller surfaces `ConnectionReset`.
    pub(super) fn decide_reset(&mut self, socket: SocketId) -> bool {
        self.counts.stream_ops += 1;
        if !Self::permille_fires(&mut self.reset_rng, self.reset_permille) {
            return false;
        }
        self.counts.resets_injected += 1;
        let peer = self
            .tcp_endpoints
            .get(&socket)
            .and_then(|endpoint| endpoint.peer);
        for endpoint in [Some(socket), peer].into_iter().flatten() {
            if let Some(endpoint) = self.tcp_endpoints.get_mut(&endpoint) {
                endpoint.reset = true;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests;
