//! DNS and network effects and their seeded fault accounting.

use crate::recording::{
    decode_datagram, decode_optional_bytes, decode_optional_u64, decode_send_report, decode_socket,
    decode_string, decode_tcp_accepted, decode_unit, decode_usize,
};
use crate::{Context, RuntimeError};
use patina_dst_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Operation, Outcome, SendReport, ShutdownHow,
    SocketId, TcpAccepted,
};
use patina_dst_driver_api::{NetDriver, NetReadiness};

/// The resolution a name gets without consulting the host table or the fault
/// knobs: a dotted-quad literal resolves to itself (libc parses a numeric node
/// locally rather than asking a resolver) and `localhost` is the loopback
/// address. Everything else goes through the table.
pub(super) fn builtin_dns_resolution(name: &str) -> Option<String> {
    if name == "localhost" {
        return Some("127.0.0.1".to_string());
    }
    let octets: Vec<&str> = name.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Some(name.to_string());
    }
    None
}

/// The failure a name outside the host table resolves to. Deterministic
/// semantics, not an injected fault.
fn nxdomain(name: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NotFound,
        format!("no virtual DNS entry for {name}"),
    )
}

impl Context {
    /// Resolve a host name to a virtual IPv4 address, as a recorded boundary
    /// operation so a replay reproduces the resolution — including an injected
    /// failure — straight from the trace.
    ///
    /// Three resolution classes, only the last of which the fault knobs touch:
    ///
    /// - **Built-ins**, resolved locally and fault-exempt: a dotted-quad literal
    ///   (libc resolves a numeric node without consulting a resolver) and
    ///   `localhost`.
    /// - **Undefined names**, which are NXDOMAIN. That is SEMANTICS, not a
    ///   fault: it fires at rate 1.0, deterministically, with no knob set. A run
    ///   that resolves only undefined names has had no fault opportunities at
    ///   all, which is why those lookups are not counted as eligible.
    /// - **Defined names**, from the run's host table. These are the
    ///   fault-eligible resolutions: latency applies before the lookup and the
    ///   failure knob can turn one into NXDOMAIN or a transient timeout.
    pub fn dns_resolve(&mut self, name: &str) -> Result<String, RuntimeError> {
        if let Some(builtin) = builtin_dns_resolution(name) {
            return Ok(builtin);
        }
        let defined = self.dns_entries.get(name).cloned();
        if defined.is_some() {
            self.dns_report.resolutions += 1;
            self.apply_dns_latency()?;
        }
        let operation = Operation::DnsResolve { name: name.into() };
        let expected = self.replay_expected(&operation)?;
        let actual = match defined {
            None => Outcome::Error(nxdomain(name)),
            Some(address) => match self.draw_dns_failure() {
                Some(error) => {
                    self.dns_report.failures_injected += 1;
                    Outcome::Error(error)
                }
                None => Outcome::Bytes(address.into_bytes()),
            },
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    /// Delay one eligible resolution by a seeded draw, mirroring
    /// [`Context::apply_fs_latency`] — same decision-point law, same single-site
    /// rule, because name resolution is the other classic reorderer (services
    /// racing on startup lookups).
    fn apply_dns_latency(&mut self) -> Result<(), RuntimeError> {
        let Some((min, max)) = self.dns_latency_nanos else {
            return Ok(());
        };
        let latency = if min == max {
            min
        } else {
            min + (self.dns_latency_rng.next_u64() % (max - min + 1))
        };
        if latency == 0 {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let deadline = now.saturating_add(latency);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        self.dns_report.latency_applied += 1;
        Ok(())
    }

    /// Draw the seeded resolution failure for one eligible lookup, or `None`
    /// when the knob does not fire. Extreme rates are decision-free so the
    /// never-fail default perturbs no stream.
    fn draw_dns_failure(&mut self) -> Option<EffectError> {
        let fires = match self.dns_fail_permille {
            0 => false,
            1000 => true,
            permille => (self.dns_fault_rng.next_u64() % 1000) < u64::from(permille),
        };
        if !fires {
            return None;
        }
        // A second draw picks the failure MODE: a vanished record, or a resolver
        // that did not answer in time. They exercise different guest code —
        // NXDOMAIN is usually terminal, a timeout is what retry discipline is
        // for — so a campaign wants both.
        if self.dns_fault_rng.next_u64() & 1 == 0 {
            Some(EffectError::new(
                ErrorCode::NotFound,
                "injected DNS failure: name does not resolve",
            ))
        } else {
            Some(EffectError::new(
                ErrorCode::Interrupted,
                "injected DNS failure: resolver timed out",
            ))
        }
    }

    /// The end-of-run DNS fault summary, or `None` when neither knob was live.
    /// Filled entirely by the Context: resolution has no driver.
    pub fn dns_fault_report(&self) -> Option<patina_dst_driver_api::DnsFaultReport> {
        if self.dns_fail_permille == 0 && self.dns_latency_nanos.is_none() {
            return None;
        }
        let mut report = self.dns_report;
        report.fail_vacuity_diagnosable = patina_dst_driver_api::vacuity_is_diagnosable(
            report.resolutions,
            self.dns_fail_permille,
        );
        report.latency_vacuity_diagnosable = self.dns_latency_nanos.is_some_and(|range| {
            patina_dst_driver_api::range_vacuity_is_diagnosable(report.resolutions, range)
        });
        Some(report)
    }

    /// The end-of-run network fault summary, or `None` when the installed
    /// network driver models no faults. Owned entirely by the driver — unlike
    /// filesystem and DNS latency, every network knob acts inside the driver —
    /// so the Context merely forwards it. This is what `PATINA_NET_FAULT_REPORT`
    /// prints at finalization; embedders and tests read it directly to assert a
    /// knob was non-vacuous.
    pub fn net_fault_report(&self) -> Option<patina_dst_driver_api::NetFaultReport> {
        self.network.as_ref().and_then(|net| net.fault_report())
    }

    pub fn net_bind(&mut self, address: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetBind {
            address: address.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .bind(address);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    /// Bind one more member of a shared (`SO_REUSEPORT`) binding at `address`.
    pub fn net_bind_shared(&mut self, address: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetBindShared {
            address: address.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .bind_shared(address);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
    ) -> Result<SendReport, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetSend {
            socket,
            to: to.into(),
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .send(socket, to, bytes, now_nanos);
        let actual = match result {
            Ok(report) => Outcome::SendReport(report),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_send_report(&operation, outcome)
    }

    pub fn net_recv(&mut self, socket: SocketId) -> Result<Option<Datagram>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetRecv { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .recv(socket, now_nanos);
        let actual = match result {
            Ok(datagram) => Outcome::Datagram(datagram),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_datagram(&operation, outcome)
    }

    pub fn net_next_delivery(&mut self, socket: SocketId) -> Result<Option<u64>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetNextDelivery { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_ref()
            .expect("driver was checked")
            .next_delivery(socket, now_nanos);
        let actual = match result {
            Ok(deadline) => Outcome::OptionalU64(deadline),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_u64(&operation, outcome)
    }

    /// Level-triggered readiness of `socket`, for a readiness reactor in an
    /// embedder (the native shim). Deliberately UNRECORDED: readiness is a pure
    /// function of the recorded send/recv/shutdown history and the virtual
    /// clock — both reconstructed identically on replay — so a reactor may poll
    /// it every scheduling scan without emitting a boundary op, exactly as pipe
    /// readiness and mutex words carry no trace of their own. Virtual time is
    /// read through [`Self::current_monotonic`], the same unrecorded clock read
    /// the deadlock rescue uses.
    pub fn net_readiness(&mut self, socket: SocketId) -> Result<NetReadiness, RuntimeError> {
        let now_nanos = self.current_monotonic()?;
        Ok(self.network()?.readiness(socket, now_nanos)?)
    }

    /// The datagram a receive on `socket` would take now, left queued
    /// (`MSG_PEEK`). UNRECORDED for the reason [`Self::net_readiness`] is: what
    /// it answers is a function of the recorded history and the clock.
    pub fn net_peek(&mut self, socket: SocketId) -> Result<Option<Datagram>, RuntimeError> {
        let now_nanos = self.current_monotonic()?;
        Ok(self.network()?.peek(socket, now_nanos)?)
    }

    /// What a stream receive on `socket` would take now, left queued
    /// (`MSG_PEEK`). UNRECORDED, as [`Self::net_peek`].
    pub fn net_tcp_peek(
        &mut self,
        socket: SocketId,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let now_nanos = self.current_monotonic()?;
        Ok(self.network()?.tcp_peek(socket, max_len, now_nanos)?)
    }

    fn network(&self) -> Result<&dyn NetDriver, RuntimeError> {
        match self.network.as_deref() {
            Some(network) => Ok(network),
            None => Err(EffectError::missing_driver("network").into()),
        }
    }

    pub fn net_close(&mut self, socket: SocketId) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetClose { socket };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .close(socket);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    pub fn net_tcp_listen(
        &mut self,
        address: &str,
        backlog: usize,
    ) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpListen {
            address: address.into(),
            backlog,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_listen(address, backlog);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_accept(
        &mut self,
        listener: SocketId,
    ) -> Result<Option<TcpAccepted>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpAccept {
            listener,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_accept(listener, now_nanos);
        let actual = match result {
            Ok(accepted) => Outcome::TcpAccepted(accepted),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_tcp_accepted(&operation, outcome)
    }

    pub fn net_tcp_connect(&mut self, address: &str, to: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpConnect {
            address: address.into(),
            to: to.into(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_connect(address, to, now_nanos);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_send(&mut self, socket: SocketId, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpSend {
            socket,
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_send(socket, bytes, now_nanos);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_usize(&operation, outcome)
    }

    pub fn net_tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpRecv {
            socket,
            max_len,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_recv(socket, max_len, now_nanos);
        let actual = match result {
            Ok(bytes) => Outcome::OptionalBytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_bytes(&operation, outcome)
    }

    /// Mark what datagram socket `socket` sends from now on: see
    /// [`NetDriver::mark_datagrams`].
    pub fn net_mark(
        &mut self,
        socket: SocketId,
        tos: u8,
        source: Option<&str>,
    ) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetMark {
            socket,
            tos,
            source: source.map(Into::into),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .mark_datagrams(socket, tos, source);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    /// Pin datagram socket `socket` to `peer` as seen from `local`, or release
    /// it (`None`): see [`NetDriver::connect_datagram`].
    pub fn net_connect(
        &mut self,
        socket: SocketId,
        local: &str,
        peer: Option<&str>,
    ) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetConnect {
            socket,
            local: local.into(),
            peer: peer.map(Into::into),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .connect_datagram(socket, local, peer);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    pub fn net_tcp_shutdown(
        &mut self,
        socket: SocketId,
        how: ShutdownHow,
    ) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpShutdown { socket, how };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_shutdown(socket, how);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;
    use crate::{Context, RuntimeError};
    use patina_dst_abi::ShutdownHow;

    use patina_dst_trace::TraceError;
    use tempfile::tempdir;

    #[test]
    fn tcp_operations_record_and_replay_byte_identically() {
        fn simulation(context: &mut Context) -> Result<(String, Vec<u8>, Vec<u8>), RuntimeError> {
            let listener = context.net_tcp_listen("server", 2)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context
                .net_tcp_accept(listener)?
                .expect("connect queued an accept");
            context.net_tcp_send(client, b"ping")?;
            context.net_tcp_send(accepted.socket, b"pong")?;
            context.net_tcp_shutdown(client, ShutdownHow::Write)?;
            let request = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let eof = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let reply = context.net_tcp_recv(client, 16)?.unwrap();
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)?;
            Ok((accepted.peer, request, [eof, reply].concat()))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp.patina");
        let mut record = Context::from_config(RuntimeConfig::record(10, &path, "tcp-v1")).unwrap();
        let expected = simulation(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert_eq!(simulation(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn tcp_replay_rejects_a_divergent_payload() {
        fn program(context: &mut Context, bytes: &[u8]) -> Result<(), RuntimeError> {
            let listener = context.net_tcp_listen("server", 1)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context.net_tcp_accept(listener)?.unwrap();
            context.net_tcp_send(client, bytes)?;
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp-divergent.patina");
        let mut record = Context::from_config(RuntimeConfig::record(11, &path, "tcp-v1")).unwrap();
        program(&mut record, b"same").unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert!(matches!(
            program(&mut replay, b"different"),
            Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
        ));
    }
}
