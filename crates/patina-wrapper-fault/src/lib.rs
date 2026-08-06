//! Deterministic fault injection around data-plane drivers.

use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, OpenFlags, SeekWhence,
    SendDisposition, SendReport, ShutdownHow, SocketId, TcpAccepted,
};
use patina_dst_driver_api::{
    DriverResult, FsDriver, FsFaultReport, NetDriver, NetFaultReport, NetReadiness,
    vacuity_is_diagnosable,
};
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

/// Injects seeded filesystem errors and short I/O around another filesystem
/// driver. The wrapper sits above durable/crash-model drivers: an injected error
/// returns before the inner filesystem is touched, while a passed-through write
/// is journaled/crash-modeled exactly as the inner driver already does.
pub struct FaultFs<D> {
    inner: D,
    error_rng: SplitMix64,
    short_rng: SplitMix64,
    error_permille: u16,
    short_permille: u16,
    /// Whether the run's Context-side fs-latency knob is live. The wrapper
    /// injects no latency itself — latency needs the clock, which only the
    /// Context owns — but it is the independent observer of the eligible-op
    /// count that the latency vacuity verdict is judged against, so a
    /// latency-only run must still produce a report.
    latency_live: bool,
    /// Read/write operations long enough for a truncation to bind, i.e. the
    /// firing opportunities the short-I/O rate actually saw.
    short_opportunities: u64,
    report: FsFaultReport,
}

impl<D> FaultFs<D> {
    pub fn new(inner: D, seed: u64) -> Self {
        Self {
            inner,
            error_rng: SplitMix64::new(domain_seed(seed, fault_domain::FAULT_FS_ERROR)),
            short_rng: SplitMix64::new(domain_seed(seed, fault_domain::FAULT_FS_SHORT)),
            error_permille: 0,
            short_permille: 0,
            latency_live: false,
            short_opportunities: 0,
            report: FsFaultReport::default(),
        }
    }

    /// Fail eligible filesystem operations with the given per-mille (0..=1000)
    /// probability, choosing from the operation's errno set on each fire.
    pub fn error_permille(mut self, permille: u16) -> Self {
        assert!(
            permille <= 1000,
            "FaultFs::error_permille must be within [0, 1000]"
        );
        self.error_permille = permille;
        self
    }

    /// Truncate reads and writes with the given per-mille (0..=1000)
    /// probability. A fired short I/O request is clamped to at least one byte
    /// and strictly below the caller's requested length.
    pub fn short_permille(mut self, permille: u16) -> Self {
        assert!(
            permille <= 1000,
            "FaultFs::short_permille must be within [0, 1000]"
        );
        self.short_permille = permille;
        self
    }

    /// Declare that the run's Context-side fs-latency knob is live, so the
    /// wrapper reports its eligible-op count even when no wrapper-owned knob is
    /// set. See [`FaultFs::latency_live`]'s field documentation.
    pub fn latency_live(mut self, live: bool) -> Self {
        self.latency_live = live;
        self
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    fn maybe_error(&mut self, op: FsFaultOp) -> Option<EffectError> {
        self.report.eligible_ops += 1;
        if self.error_permille == 0 {
            return None;
        }
        if !permille_fires(&mut self.error_rng, self.error_permille) {
            return None;
        }
        let code = choose_error_code(&mut self.error_rng, op);
        self.report.errors_injected += 1;
        Some(EffectError::new(
            code,
            format!(
                "injected filesystem {} fault during {}",
                code_name(code),
                op.name()
            ),
        ))
    }

    /// Draw a truncated request length for a short-eligible operation, or `None`
    /// when the knob does not fire. The decision is drawn even when an
    /// independent error fault has already fired for this operation; that keeps
    /// the short-I/O stream a pure function of the short knob and short-eligible
    /// op sequence rather than of another domain's fires.
    ///
    /// Counting the fire as APPLIED is left to the caller, which alone knows
    /// whether the truncation bound the result: a read truncated to a length the
    /// file never reached anyway perturbs nothing the guest can observe, and
    /// counting it would let a knob that is inert on the exercised I/O path
    /// report itself as working.
    fn maybe_short_len(&mut self, requested: usize) -> Option<usize> {
        if self.short_permille == 0 || requested <= 1 {
            return None;
        }
        self.short_opportunities += 1;
        if !permille_fires(&mut self.short_rng, self.short_permille) {
            return None;
        }
        Some(1 + (self.short_rng.next_u64() as usize % (requested - 1)))
    }

    /// Count a fired read truncation only when it actually bound the result. A
    /// guest reading into a buffer larger than the file has left keeps getting
    /// every available byte no matter how the request was truncated, and that is
    /// an unobserved fault, not an applied one.
    fn count_short_read(&mut self, short: Option<usize>, bytes: &[u8]) {
        if short == Some(bytes.len()) {
            self.report.shorts_applied += 1;
        }
    }

    /// A fired write truncation is always observable: the caller is told fewer
    /// bytes were written than it asked for.
    fn count_short_write(&mut self, short: Option<usize>) {
        if short.is_some() {
            self.report.shorts_applied += 1;
        }
    }

    fn merged_report(&self) -> FsFaultReport
    where
        D: FsDriver,
    {
        let mut report = self.report;
        report.error_vacuity_diagnosable =
            vacuity_is_diagnosable(report.eligible_ops, self.error_permille);
        report.short_vacuity_diagnosable =
            vacuity_is_diagnosable(self.short_opportunities, self.short_permille);
        if let Some(inner) = self.inner.fault_report() {
            report.eligible_ops += inner.eligible_ops;
            report.error_vacuity_diagnosable |= inner.error_vacuity_diagnosable;
            report.errors_injected += inner.errors_injected;
            report.short_vacuity_diagnosable |= inner.short_vacuity_diagnosable;
            report.shorts_applied += inner.shorts_applied;
            report.latency_vacuity_diagnosable |= inner.latency_vacuity_diagnosable;
            report.latency_applied += inner.latency_applied;
        }
        report
    }
}

impl<D: FsDriver> FsDriver for FaultFs<D> {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        if let Some(error) = self.maybe_error(FsFaultOp::Open {
            allocating: flags.create,
        }) {
            return Err(error);
        }
        self.inner.open(path, flags)
    }

    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        let error = self.maybe_error(FsFaultOp::Read);
        let short = self.maybe_short_len(max_len);
        if let Some(error) = error {
            return Err(error);
        }
        let bytes = self.inner.read(fd, short.unwrap_or(max_len))?;
        self.count_short_read(short, &bytes);
        Ok(bytes)
    }

    fn write(&mut self, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        let error = self.maybe_error(FsFaultOp::Write);
        let short = self.maybe_short_len(bytes.len());
        if let Some(error) = error {
            return Err(error);
        }
        let written = self
            .inner
            .write(fd, &bytes[..short.unwrap_or(bytes.len())])?;
        self.count_short_write(short);
        Ok(written)
    }

    fn read_at(&mut self, fd: Fd, offset: u64, max_len: usize) -> DriverResult<Vec<u8>> {
        let error = self.maybe_error(FsFaultOp::ReadAt);
        let short = self.maybe_short_len(max_len);
        if let Some(error) = error {
            return Err(error);
        }
        let bytes = self.inner.read_at(fd, offset, short.unwrap_or(max_len))?;
        self.count_short_read(short, &bytes);
        Ok(bytes)
    }

    fn write_at(&mut self, fd: Fd, offset: u64, bytes: &[u8]) -> DriverResult<usize> {
        let error = self.maybe_error(FsFaultOp::WriteAt);
        let short = self.maybe_short_len(bytes.len());
        if let Some(error) = error {
            return Err(error);
        }
        let written = self
            .inner
            .write_at(fd, offset, &bytes[..short.unwrap_or(bytes.len())])?;
        self.count_short_write(short);
        Ok(written)
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        self.inner.close(fd)
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        self.inner.seek(fd, offset, whence)
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        self.inner.dup(fd)
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        if let Some(error) = self.maybe_error(FsFaultOp::Metadata) {
            return Err(error);
        }
        self.inner.metadata(path)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        if let Some(error) = self.maybe_error(FsFaultOp::FdMetadata) {
            return Err(error);
        }
        self.inner.fd_metadata(fd)
    }

    fn create_directory(&mut self, path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::CreateDirectory) {
            return Err(error);
        }
        self.inner.create_directory(path)
    }

    fn remove_file(&mut self, path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::RemoveFile) {
            return Err(error);
        }
        self.inner.remove_file(path)
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Sync) {
            return Err(error);
        }
        self.inner.sync(fd)
    }

    fn set_len(&mut self, fd: Fd, len: u64) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetLen) {
            return Err(error);
        }
        self.inner.set_len(fd, len)
    }

    fn set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimes) {
            return Err(error);
        }
        self.inner.set_times(fd, atime_nanos, mtime_nanos)
    }

    fn set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimesByPath) {
            return Err(error);
        }
        self.inner.set_times_by_path(path, atime_nanos, mtime_nanos)
    }

    fn read_directory(&mut self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        if let Some(error) = self.maybe_error(FsFaultOp::ReadDirectory) {
            return Err(error);
        }
        self.inner.read_directory(path)
    }

    fn remove_directory(&mut self, path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::RemoveDirectory) {
            return Err(error);
        }
        self.inner.remove_directory(path)
    }

    fn rename(&mut self, from: &str, to: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Rename) {
            return Err(error);
        }
        self.inner.rename(from, to)
    }

    fn link(&mut self, from: &str, to: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Link) {
            return Err(error);
        }
        self.inner.link(from, to)
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Symlink) {
            return Err(error);
        }
        self.inner.symlink(target, link_path)
    }

    fn read_link(&mut self, path: &str) -> DriverResult<String> {
        if let Some(error) = self.maybe_error(FsFaultOp::ReadLink) {
            return Err(error);
        }
        self.inner.read_link(path)
    }

    fn crash(&mut self) -> DriverResult<()> {
        self.inner.crash()
    }

    /// Report whenever a knob was live, so the run is self-describing about what
    /// the fault plane did. Deciding whether the numbers are worth printing —
    /// and whether they are vacuous — belongs to the consumer.
    fn fault_report(&self) -> Option<FsFaultReport> {
        let modeled = self.error_permille != 0 || self.short_permille != 0 || self.latency_live;
        (modeled || self.inner.fault_report().is_some()).then(|| self.merged_report())
    }
}

#[derive(Clone, Copy, Debug)]
enum FsFaultOp {
    Open { allocating: bool },
    Read,
    Write,
    ReadAt,
    WriteAt,
    Metadata,
    FdMetadata,
    CreateDirectory,
    RemoveFile,
    Sync,
    SetLen,
    SetTimes,
    SetTimesByPath,
    ReadDirectory,
    RemoveDirectory,
    Rename,
    Link,
    Symlink,
    ReadLink,
}

impl FsFaultOp {
    fn name(self) -> &'static str {
        match self {
            FsFaultOp::Open { .. } => "open",
            FsFaultOp::Read => "read",
            FsFaultOp::Write => "write",
            FsFaultOp::ReadAt => "read_at",
            FsFaultOp::WriteAt => "write_at",
            FsFaultOp::Metadata => "metadata",
            FsFaultOp::FdMetadata => "fd_metadata",
            FsFaultOp::CreateDirectory => "create_directory",
            FsFaultOp::RemoveFile => "remove_file",
            FsFaultOp::Sync => "sync",
            FsFaultOp::SetLen => "set_len",
            FsFaultOp::SetTimes => "set_times",
            FsFaultOp::SetTimesByPath => "set_times_by_path",
            FsFaultOp::ReadDirectory => "read_directory",
            FsFaultOp::RemoveDirectory => "remove_directory",
            FsFaultOp::Rename => "rename",
            FsFaultOp::Link => "link",
            FsFaultOp::Symlink => "symlink",
            FsFaultOp::ReadLink => "read_link",
        }
    }

    fn can_no_space(self) -> bool {
        match self {
            FsFaultOp::Open { allocating } => allocating,
            FsFaultOp::Write
            | FsFaultOp::WriteAt
            | FsFaultOp::CreateDirectory
            | FsFaultOp::SetLen
            | FsFaultOp::Rename
            | FsFaultOp::Link
            | FsFaultOp::Symlink => true,
            FsFaultOp::Read
            | FsFaultOp::ReadAt
            | FsFaultOp::Metadata
            | FsFaultOp::FdMetadata
            | FsFaultOp::RemoveFile
            | FsFaultOp::Sync
            | FsFaultOp::SetTimes
            | FsFaultOp::SetTimesByPath
            | FsFaultOp::ReadDirectory
            | FsFaultOp::RemoveDirectory
            | FsFaultOp::ReadLink => false,
        }
    }

    fn can_interrupt(self) -> bool {
        matches!(
            self,
            FsFaultOp::Read
                | FsFaultOp::Write
                | FsFaultOp::ReadAt
                | FsFaultOp::WriteAt
                | FsFaultOp::Sync
        )
    }
}

fn choose_error_code(rng: &mut SplitMix64, op: FsFaultOp) -> ErrorCode {
    let mut choices = [ErrorCode::Io, ErrorCode::Io, ErrorCode::Io];
    let mut len = 1usize;
    if op.can_no_space() {
        choices[len] = ErrorCode::NoSpace;
        len += 1;
    }
    if op.can_interrupt() {
        choices[len] = ErrorCode::Interrupted;
        len += 1;
    }
    choices[rng.next_u64() as usize % len]
}

fn code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Io => "io",
        ErrorCode::NoSpace => "no_space",
        ErrorCode::Interrupted => "interrupted",
        _ => "unexpected",
    }
}

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

fn permille_fires(rng: &mut SplitMix64, permille: u16) -> bool {
    match permille {
        0 => false,
        1000 => true,
        value => (rng.next_u64() % 1000) < u64::from(value),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use patina_dst_fs_mem::MemFs;
    use patina_dst_net_sim::SimNet;

    use super::*;

    fn fs_with_open_file() -> (MemFs, Fd) {
        let mut fs = MemFs::new();
        let fd = fs
            .open("/file", OpenFlags::create_truncate_write())
            .unwrap();
        (fs, fd)
    }

    fn short_write_len(seed: u64) -> usize {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, seed).short_permille(1000);
        fs.write(fd, b"abcdef").unwrap()
    }

    #[test]
    fn fs_short_io_is_seed_deterministic_and_observable() {
        for seed in 0..64 {
            assert_eq!(short_write_len(seed), short_write_len(seed), "seed {seed}");
        }
        let written = short_write_len(4);
        assert!((1..6).contains(&written), "written={written}");
        let varied = (0..16).map(short_write_len).collect::<BTreeSet<_>>();
        assert!(
            varied.len() > 1,
            "different seeds should choose different short lengths: {varied:?}"
        );
    }

    #[test]
    fn fs_error_injection_can_choose_write_errno_set() {
        let mut seen = Vec::new();
        for seed in 0..256 {
            let (inner, fd) = fs_with_open_file();
            let mut fs = FaultFs::new(inner, seed).error_permille(1000);
            let error = fs.write(fd, b"x").unwrap_err();
            seen.push(error.code);
        }
        assert!(seen.contains(&ErrorCode::Io), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::NoSpace), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::Interrupted), "seen={seen:?}");
    }

    #[test]
    fn fs_short_read_at_preserves_the_cursor() {
        let mut inner = MemFs::new();
        let fd = inner
            .open(
                "/file",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: true,
                    append: false,
                    exclusive: false,
                },
            )
            .unwrap();
        inner.write(fd, b"abcdef").unwrap();
        inner.seek(fd, 2, SeekWhence::Start).unwrap();

        let mut fs = FaultFs::new(inner, 3).short_permille(1000);
        let positional = fs.read_at(fd, 0, 6).unwrap();
        assert!(!positional.is_empty() && positional.len() < 6);
        let mut inner = fs.into_inner();
        assert_eq!(inner.read(fd, 2).unwrap(), b"cd");
    }

    #[test]
    fn fs_fault_report_is_per_class() {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        for _ in 0..5 {
            let written = fs.write(fd, b"abcdef").unwrap();
            assert!((1..6).contains(&written), "written={written}");
        }
        let report = fs.fault_report().unwrap();
        assert_eq!(report.eligible_ops, 5);
        // The error class stayed off, so it can never be reported as vacuous on
        // the back of the short class's traffic.
        assert!(!report.error_vacuity_diagnosable);
        assert_eq!(report.errors_injected, 0);
        assert!(report.short_vacuity_diagnosable);
        assert_eq!(report.shorts_applied, 5);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn fs_vacuity_ignores_rates_too_low_to_expect_a_fire() {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, 1).short_permille(1);
        for _ in 0..10 {
            assert_eq!(fs.write(fd, b"abcdef").unwrap(), 6);
        }
        let report = fs.fault_report().unwrap();
        // Ten draws at one per-mille expect 0.01 fires: zero applied shorts is
        // ordinary sampling, and calling it vacuous would fail healthy runs.
        assert_eq!(report.shorts_applied, 0);
        assert!(!report.short_vacuity_diagnosable);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn fs_short_reads_that_bind_nothing_are_vacuous() {
        let mut inner = MemFs::new();
        let fd = inner
            .open(
                "/file",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: true,
                    append: false,
                    exclusive: false,
                },
            )
            .unwrap();
        inner.write(fd, b"abcdef").unwrap();

        // A guest reading into a buffer far larger than the file has left never
        // observes the truncation, so the knob is inert on this I/O path however
        // often it fires — the silent-inertness signature the report exists for.
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        for _ in 0..5 {
            assert_eq!(fs.read_at(fd, 0, 8192).unwrap(), b"abcdef");
        }
        let report = fs.fault_report().unwrap();
        assert!(report.short_vacuity_diagnosable);
        assert_eq!(report.shorts_applied, 0);
        assert!(report.is_vacuous());
    }

    fn decisions(seed: u64) -> Vec<(SendDisposition, usize)> {
        let mut net = FaultNet::new(SimNet::new(), seed)
            .drop_permille(333)
            .duplicate_permille(500);
        let left = net.bind("left").unwrap();
        net.bind("right").unwrap();
        (0..100)
            .map(|index| {
                let report = net.send(left, "right", &[index as u8], index).unwrap();
                (report.disposition, report.copies)
            })
            .collect()
    }

    #[test]
    fn the_same_seed_selects_the_same_fault_locations() {
        for seed in 0..100 {
            assert_eq!(decisions(seed), decisions(seed), "seed {seed}");
        }
        let decisions = decisions(9);
        assert!(
            decisions
                .iter()
                .any(|(disposition, _)| *disposition == SendDisposition::DroppedByFault)
        );
        assert!(decisions.iter().any(|(_, copies)| *copies == 2));
    }

    #[test]
    fn duplicated_packets_are_observable_at_the_receiver() {
        let mut net = FaultNet::new(SimNet::new(), 1).duplicate_permille(1000);
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        let report = net.send(left, "right", b"twice", 0).unwrap();
        assert_eq!(report.copies, 2);
        assert_eq!(net.recv(right, 0).unwrap().unwrap().bytes, b"twice");
        assert_eq!(net.recv(right, 0).unwrap().unwrap().bytes, b"twice");
    }

    #[test]
    fn tcp_passes_through_fault_injection_unchanged() {
        let mut net = FaultNet::new(SimNet::new(), 1).drop_permille(1000);
        let udp_left = net.bind("udp-left").unwrap();
        let udp_right = net.bind("udp-right").unwrap();
        assert_eq!(
            net.send(udp_left, "udp-right", b"lost", 0)
                .unwrap()
                .disposition,
            SendDisposition::DroppedByFault
        );
        assert_eq!(net.recv(udp_right, 0).unwrap(), None);

        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"reliable", 0).unwrap(), 8);
        assert_eq!(net.tcp_recv(server, 16, 0).unwrap().unwrap(), b"reliable");
    }

    #[test]
    fn drop_duplicate_and_fs_faults_use_separate_domain_streams() {
        let drop_first = {
            let mut rng = SplitMix64::new(domain_seed(3, fault_domain::FAULT_NET_DROP));
            rng.next_u64()
        };
        let duplicate_first = {
            let mut rng = SplitMix64::new(domain_seed(3, fault_domain::FAULT_NET_DUPLICATE));
            rng.next_u64()
        };
        let fs_error_first = {
            let mut rng = SplitMix64::new(domain_seed(3, fault_domain::FAULT_FS_ERROR));
            rng.next_u64()
        };
        let fs_short_first = {
            let mut rng = SplitMix64::new(domain_seed(3, fault_domain::FAULT_FS_SHORT));
            rng.next_u64()
        };
        let mut unique = BTreeSet::new();
        unique.insert(drop_first);
        unique.insert(duplicate_first);
        unique.insert(fs_error_first);
        unique.insert(fs_short_first);
        assert_eq!(unique.len(), 4);
    }
}
