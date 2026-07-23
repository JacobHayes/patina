//! Deterministic delay and jitter around data-plane drivers.

use patina_abi::{
    Datagram, EffectError, ErrorCode, SendReport, ShutdownHow, SocketId, TcpAccepted,
};
use patina_driver_api::{DriverResult, NetDriver};
use patina_rng_seeded::SplitMix64;

/// Adds fixed latency and seeded inclusive jitter to virtual packet delivery.
pub struct LatencyNet<D> {
    inner: D,
    generator: SplitMix64,
    latency_nanos: u64,
    jitter_nanos: u64,
}

impl<D> LatencyNet<D> {
    pub fn new(inner: D, seed: u64) -> Self {
        Self {
            inner,
            generator: SplitMix64::new(seed),
            latency_nanos: 0,
            jitter_nanos: 0,
        }
    }

    pub fn latency_nanos(mut self, value: u64) -> Self {
        self.latency_nanos = value;
        self
    }

    pub fn jitter_nanos(mut self, value: u64) -> Self {
        self.jitter_nanos = value;
        self
    }

    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: NetDriver> NetDriver for LatencyNet<D> {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId> {
        self.inner.bind(address)
    }

    fn validate_send(&self, socket: SocketId, to: &str) -> DriverResult<()> {
        self.inner.validate_send(socket, to)
    }

    fn send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<SendReport> {
        let jitter = match self.jitter_nanos {
            0 => 0,
            u64::MAX => self.generator.next_u64(),
            maximum => self.generator.next_u64() % (maximum + 1),
        };
        let deadline = delivery_nanos
            .checked_add(self.latency_nanos)
            .and_then(|value| value.checked_add(jitter))
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    "virtual latency deadline overflowed",
                )
            })?;
        self.inner.send(socket, to, bytes, deadline)
    }

    fn recv(&mut self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>> {
        self.inner.recv(socket, now_nanos)
    }

    fn next_delivery(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<u64>> {
        // Latency is baked into each packet's delivery time at send, so the
        // inner driver already reflects it; forwarding keeps the added latency
        // visible to a blocking receive that parks on the next delivery.
        self.inner.next_delivery(socket, now_nanos)
    }

    fn tcp_listen(&mut self, address: &str, backlog: usize) -> DriverResult<SocketId> {
        self.inner.tcp_listen(address, backlog)
    }

    fn tcp_accept(
        &mut self,
        listener: SocketId,
        now_nanos: u64,
    ) -> DriverResult<Option<TcpAccepted>> {
        self.inner.tcp_accept(listener, now_nanos)
    }

    fn tcp_connect(&mut self, address: &str, to: &str, now_nanos: u64) -> DriverResult<SocketId> {
        // Handshake latency is deferred in TCP v1; the stream is established
        // synchronously and only data segments receive delivery deadlines.
        self.inner.tcp_connect(address, to, now_nanos)
    }

    fn tcp_send(
        &mut self,
        socket: SocketId,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<usize> {
        let jitter = match self.jitter_nanos {
            0 => 0,
            u64::MAX => self.generator.next_u64(),
            maximum => self.generator.next_u64() % (maximum + 1),
        };
        let deadline = delivery_nanos
            .checked_add(self.latency_nanos)
            .and_then(|value| value.checked_add(jitter))
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    "virtual latency deadline overflowed",
                )
            })?;
        // Per-segment jitter may not reorder a TCP stream: SimNet preserves
        // inbox queue order, so jitter only stretches arrival times.
        self.inner.tcp_send(socket, bytes, deadline)
    }

    fn tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        self.inner.tcp_recv(socket, max_len, now_nanos)
    }

    fn tcp_shutdown(&mut self, socket: SocketId, how: ShutdownHow) -> DriverResult<()> {
        self.inner.tcp_shutdown(socket, how)
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()> {
        self.inner.close(socket)
    }
}

#[cfg(test)]
mod tests {
    use patina_net_sim::SimNet;

    use super::*;

    #[test]
    fn fixed_latency_delays_delivery() {
        let mut net = LatencyNet::new(SimNet::new(), 1).latency_nanos(50);
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        let report = net.send(left, "right", b"later", 10).unwrap();
        assert_eq!(report.delivery_nanos, [60]);
        assert_eq!(net.recv(right, 59).unwrap(), None);
        assert_eq!(net.recv(right, 60).unwrap().unwrap().bytes, b"later");
    }

    #[test]
    fn next_delivery_reflects_the_added_latency() {
        let mut net = LatencyNet::new(SimNet::new(), 1).latency_nanos(50);
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        net.send(left, "right", b"later", 10).unwrap();
        // The blocking-receive parking deadline must include the 50ns latency,
        // otherwise a receiver would re-park at an unchanged clock and deadlock.
        assert_eq!(net.next_delivery(right, 0).unwrap(), Some(60));
        assert_eq!(net.next_delivery(right, 60).unwrap(), None);
    }

    #[test]
    fn tcp_segments_observe_the_added_latency() {
        let mut net = LatencyNet::new(SimNet::new(), 1).latency_nanos(50);
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 10).unwrap();
        let server = net.tcp_accept(listener, 10).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"later", 10).unwrap(), 5);
        assert_eq!(net.next_delivery(server, 0).unwrap(), Some(60));
        assert_eq!(net.tcp_recv(server, 8, 59).unwrap(), None);
        assert_eq!(net.tcp_recv(server, 8, 60).unwrap().unwrap(), b"later");
    }

    #[test]
    fn seeded_jitter_repeats_and_can_reorder_packets() {
        fn delivery_times(seed: u64) -> [u64; 2] {
            let mut net = LatencyNet::new(SimNet::new(), seed).jitter_nanos(100);
            let left = net.bind("left").unwrap();
            net.bind("right").unwrap();
            let first = net.send(left, "right", b"first", 0).unwrap();
            let second = net.send(left, "right", b"second", 0).unwrap();
            [first.delivery_nanos[0], second.delivery_nanos[0]]
        }

        for seed in 0..100 {
            assert_eq!(delivery_times(seed), delivery_times(seed));
        }
        let seed = (0..1_000)
            .find(|seed| {
                let times = delivery_times(*seed);
                times[0] > times[1]
            })
            .expect("a seed in the bounded search should reorder two packets");
        let times = delivery_times(seed);
        assert!(times[0] > times[1]);
    }
}
