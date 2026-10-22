//! Deterministic packet loss and duplication around a network driver.

use patina_dst_abi::{Datagram, SendDisposition, SendReport, ShutdownHow, SocketId, TcpAccepted};
use patina_dst_driver_api::{DriverResult, NetDriver, NetFaultReport, NetReadiness};
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

use crate::permille_fires;

/// Injects seeded packet loss and duplication around another network driver.
pub struct FaultNet<D> {
    inner: D,
    drop_rng: SplitMix64,
    duplicate_rng: SplitMix64,
    drop_permille: u16,
    duplicate_permille: u16,
}

impl<D> FaultNet<D> {
    pub fn new(inner: D, seed: u64) -> Self {
        Self {
            inner,
            drop_rng: SplitMix64::new(domain_seed(seed, fault_domain::FAULT_NET_DROP)),
            duplicate_rng: SplitMix64::new(domain_seed(seed, fault_domain::FAULT_NET_DUPLICATE)),
            drop_permille: 0,
            duplicate_permille: 0,
        }
    }

    /// Drop datagrams with the given per-mille (0..=1000) probability.
    pub fn drop_permille(mut self, permille: u16) -> Self {
        assert!(
            permille <= 1000,
            "FaultNet::drop_permille must be within [0, 1000]"
        );
        self.drop_permille = permille;
        self
    }

    /// Duplicate datagrams with the given per-mille (0..=1000) probability.
    pub fn duplicate_permille(mut self, permille: u16) -> Self {
        assert!(
            permille <= 1000,
            "FaultNet::duplicate_permille must be within [0, 1000]"
        );
        self.duplicate_permille = permille;
        self
    }

    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: NetDriver> NetDriver for FaultNet<D> {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId> {
        self.inner.bind(address)
    }

    fn bind_shared(&mut self, address: &str) -> DriverResult<SocketId> {
        self.inner.bind_shared(address)
    }

    fn mark_datagrams(
        &mut self,
        socket: SocketId,
        tos: u8,
        source: Option<&str>,
    ) -> DriverResult<()> {
        self.inner.mark_datagrams(socket, tos, source)
    }

    fn connect_datagram(
        &mut self,
        socket: SocketId,
        local: &str,
        peer: Option<&str>,
    ) -> DriverResult<()> {
        self.inner.connect_datagram(socket, local, peer)
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
        self.inner.validate_send(socket, to)?;
        if permille_fires(&mut self.drop_rng, self.drop_permille) {
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::DroppedByFault,
            });
        }

        let first = self.inner.send(socket, to, bytes, delivery_nanos)?;
        if !permille_fires(&mut self.duplicate_rng, self.duplicate_permille)
            || first.disposition != SendDisposition::Queued
        {
            return Ok(first);
        }
        let second = self.inner.send(socket, to, bytes, delivery_nanos)?;
        let mut delivery_times = first.delivery_nanos;
        delivery_times.extend(second.delivery_nanos);
        Ok(SendReport {
            written: first.written,
            copies: first.copies + second.copies,
            delivery_nanos: delivery_times,
            disposition: SendDisposition::Queued,
        })
    }

    fn recv(&mut self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>> {
        self.inner.recv(socket, now_nanos)
    }

    fn peek(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>> {
        self.inner.peek(socket, now_nanos)
    }

    fn next_delivery(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<u64>> {
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
        self.inner.tcp_connect(address, to, now_nanos)
    }

    fn tcp_send(
        &mut self,
        socket: SocketId,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<usize> {
        // TCP models a reliable transport; datagram loss/duplication below a
        // stream would break the stream contract. Connection-level TCP faults
        // (refused/reset injection) are future work.
        self.inner.tcp_send(socket, bytes, delivery_nanos)
    }

    fn tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        self.inner.tcp_recv(socket, max_len, now_nanos)
    }

    fn tcp_peek(
        &self,
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        self.inner.tcp_peek(socket, max_len, now_nanos)
    }

    fn tcp_shutdown(&mut self, socket: SocketId, how: ShutdownHow) -> DriverResult<()> {
        self.inner.tcp_shutdown(socket, how)
    }

    fn readiness(&self, socket: SocketId, now_nanos: u64) -> DriverResult<NetReadiness> {
        self.inner.readiness(socket, now_nanos)
    }

    fn fault_report(&self) -> Option<NetFaultReport> {
        self.inner.fault_report()
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()> {
        self.inner.close(socket)
    }
}
