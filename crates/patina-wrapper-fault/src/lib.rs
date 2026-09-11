//! Deterministic fault injection around data-plane drivers.

use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, Fd, FsClock, FsDirectoryEntry, FsMetadata, OpenFlags,
    SeekWhence, SendDisposition, SendReport, ShutdownHow, SocketId, TcpAccepted,
};
use patina_dst_driver_api::{
    DriverResult, FsDriver, FsFaultOpKind, FsFaultReport, NetDriver, NetFaultReport, NetReadiness,
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
        self.report.errors_by_op.record(op.kind());
        Some(EffectError::new(
            code,
            format!(
                "injected filesystem {} fault during {}",
                code_name(code),
                op.kind().name()
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
    fn count_short_read(&mut self, kind: FsFaultOpKind, short: Option<usize>, bytes: &[u8]) {
        if short == Some(bytes.len()) {
            self.count_short(kind);
        }
    }

    /// A fired write truncation is always observable: the caller is told fewer
    /// bytes were written than it asked for.
    fn count_short_write(&mut self, kind: FsFaultOpKind, short: Option<usize>) {
        if short.is_some() {
            self.count_short(kind);
        }
    }

    /// The one place an applied truncation is booked, so the scalar counter and
    /// the per-kind breakdown cannot disagree about how many landed.
    fn count_short(&mut self, kind: FsFaultOpKind) {
        self.report.shorts_applied += 1;
        self.report.shorts_by_op.record(kind);
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
            report.errors_by_op.merge(&inner.errors_by_op);
            report.short_vacuity_diagnosable |= inner.short_vacuity_diagnosable;
            report.shorts_applied += inner.shorts_applied;
            report.shorts_by_op.merge(&inner.shorts_by_op);
            report.latency_vacuity_diagnosable |= inner.latency_vacuity_diagnosable;
            report.latency_applied += inner.latency_applied;
        }
        report
    }
}

impl<D: FsDriver> FsDriver for FaultFs<D> {
    fn open(&mut self, clock: FsClock, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        if let Some(error) = self.maybe_error(FsFaultOp::Open {
            allocating: flags.create,
        }) {
            return Err(error);
        }
        self.inner.open(clock, path, flags)
    }

    fn read(&mut self, clock: FsClock, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        let error = self.maybe_error(FsFaultOp::Read);
        let short = self.maybe_short_len(max_len);
        if let Some(error) = error {
            return Err(error);
        }
        let bytes = self.inner.read(clock, fd, short.unwrap_or(max_len))?;
        self.count_short_read(FsFaultOpKind::Read, short, &bytes);
        Ok(bytes)
    }

    fn write(&mut self, clock: FsClock, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        let error = self.maybe_error(FsFaultOp::Write);
        let short = self.maybe_short_len(bytes.len());
        if let Some(error) = error {
            return Err(error);
        }
        let written = self
            .inner
            .write(clock, fd, &bytes[..short.unwrap_or(bytes.len())])?;
        self.count_short_write(FsFaultOpKind::Write, short);
        Ok(written)
    }

    fn read_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> DriverResult<Vec<u8>> {
        let error = self.maybe_error(FsFaultOp::ReadAt);
        let short = self.maybe_short_len(max_len);
        if let Some(error) = error {
            return Err(error);
        }
        let bytes = self
            .inner
            .read_at(clock, fd, offset, short.unwrap_or(max_len))?;
        self.count_short_read(FsFaultOpKind::ReadAt, short, &bytes);
        Ok(bytes)
    }

    fn write_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        let error = self.maybe_error(FsFaultOp::WriteAt);
        let short = self.maybe_short_len(bytes.len());
        if let Some(error) = error {
            return Err(error);
        }
        let written =
            self.inner
                .write_at(clock, fd, offset, &bytes[..short.unwrap_or(bytes.len())])?;
        self.count_short_write(FsFaultOpKind::WriteAt, short);
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

    /// The same `fstat` the descriptor form is, addressed by node — so it draws
    /// from the same fault op rather than becoming a metadata read no injected
    /// failure can ever reach.
    fn inode_metadata(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        if let Some(error) = self.maybe_error(FsFaultOp::FdMetadata) {
            return Err(error);
        }
        self.inner.inode_metadata(ino)
    }

    fn create_directory(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::CreateDirectory) {
            return Err(error);
        }
        self.inner.create_directory(clock, path, mode)
    }

    fn remove_file(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::RemoveFile) {
            return Err(error);
        }
        self.inner.remove_file(clock, path)
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Sync) {
            return Err(error);
        }
        self.inner.sync(fd)
    }

    fn set_len(&mut self, clock: FsClock, fd: Fd, len: u64) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetLen) {
            return Err(error);
        }
        self.inner.set_len(clock, fd, len)
    }

    /// The same truncation the descriptor form is, addressed by name — so it
    /// draws from the same fault op.
    fn set_len_by_path(&mut self, clock: FsClock, path: &str, len: u64) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetLen) {
            return Err(error);
        }
        self.inner.set_len_by_path(clock, path, len)
    }

    /// A length/space change like `set_len` (it can consume space, so it can
    /// fail `ENOSPC`), so it draws from the same fault op.
    fn allocate(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        len: u64,
        zero: bool,
        keep_size: bool,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetLen) {
            return Err(error);
        }
        self.inner.allocate(clock, fd, offset, len, zero, keep_size)
    }

    fn set_times(
        &mut self,
        clock: FsClock,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimes) {
            return Err(error);
        }
        self.inner.set_times(clock, fd, atime_nanos, mtime_nanos)
    }

    fn set_inode_times(
        &mut self,
        clock: FsClock,
        ino: u64,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimes) {
            return Err(error);
        }
        self.inner
            .set_inode_times(clock, ino, atime_nanos, mtime_nanos)
    }

    fn set_times_by_path(
        &mut self,
        clock: FsClock,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimesByPath) {
            return Err(error);
        }
        self.inner
            .set_times_by_path(clock, path, atime_nanos, mtime_nanos)
    }

    fn read_directory(
        &mut self,
        clock: FsClock,
        path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        if let Some(error) = self.maybe_error(FsFaultOp::ReadDirectory) {
            return Err(error);
        }
        self.inner.read_directory(clock, path)
    }

    /// The same listing the path form is, addressed by descriptor — so it draws
    /// from the same fault op rather than becoming a directory read no injected
    /// failure can ever reach.
    fn read_directory_fd(&mut self, clock: FsClock, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        if let Some(error) = self.maybe_error(FsFaultOp::ReadDirectory) {
            return Err(error);
        }
        self.inner.read_directory_fd(clock, fd)
    }

    fn remove_directory(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::RemoveDirectory) {
            return Err(error);
        }
        self.inner.remove_directory(clock, path)
    }

    fn rename(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Rename) {
            return Err(error);
        }
        self.inner.rename(clock, from, to)
    }

    fn link(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Link) {
            return Err(error);
        }
        self.inner.link(clock, from, to)
    }

    /// Shares the namespace-creation fault kind with `create_directory`: both
    /// are "a new name appears in a directory", which is the failure the
    /// injector is modeling.
    fn make_fifo(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::CreateDirectory) {
            return Err(error);
        }
        self.inner.make_fifo(clock, path, mode)
    }

    fn symlink(&mut self, clock: FsClock, target: &str, link_path: &str) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::Symlink) {
            return Err(error);
        }
        self.inner.symlink(clock, target, link_path)
    }

    fn read_link(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        if let Some(error) = self.maybe_error(FsFaultOp::ReadLink) {
            return Err(error);
        }
        self.inner.read_link(clock, path)
    }

    fn set_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimesByPath) {
            return Err(error);
        }
        self.inner.set_mode(clock, path, mode)
    }

    fn set_fd_mode(&mut self, clock: FsClock, fd: Fd, mode: u32) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimes) {
            return Err(error);
        }
        self.inner.set_fd_mode(clock, fd, mode)
    }

    /// Never fault-eligible: this is the name lookup inside a `*at` call, not a
    /// trip to storage, and no real `openat` fails because the kernel could not
    /// say where a descriptor's inode lives.
    /// The same `fchmod` the descriptor form is, addressed by node — so it draws
    /// from the same fault op.
    fn set_inode_mode(&mut self, clock: FsClock, ino: u64, mode: u32) -> DriverResult<()> {
        if let Some(error) = self.maybe_error(FsFaultOp::SetTimes) {
            return Err(error);
        }
        self.inner.set_inode_mode(clock, ino, mode)
    }

    /// Taking or dropping a node reference is the bookkeeping half of an open
    /// and a close, not a trip to storage: like `fd_path` it carries no injected
    /// failure, because a kernel has nowhere to fail it either.
    fn retain_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.inner.retain_inode(ino)
    }

    fn release_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.inner.release_inode(ino)
    }

    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        self.inner.fd_path(fd)
    }

    fn crash(&mut self) -> DriverResult<()> {
        self.inner.crash()
    }

    fn crash_and_export_restart_snapshot(&mut self) -> DriverResult<Vec<u8>> {
        self.inner.crash_and_export_restart_snapshot()
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
    /// The reported kind. The wrapper's own enum carries the extra facts fault
    /// selection needs (whether an `open` allocates), while the report's kind is
    /// the shared vocabulary — one name table, so an error message and a
    /// breakdown row can never spell the same operation differently.
    fn kind(self) -> FsFaultOpKind {
        match self {
            FsFaultOp::Open { .. } => FsFaultOpKind::Open,
            FsFaultOp::Read => FsFaultOpKind::Read,
            FsFaultOp::Write => FsFaultOpKind::Write,
            FsFaultOp::ReadAt => FsFaultOpKind::ReadAt,
            FsFaultOp::WriteAt => FsFaultOpKind::WriteAt,
            FsFaultOp::Metadata => FsFaultOpKind::Metadata,
            FsFaultOp::FdMetadata => FsFaultOpKind::FdMetadata,
            FsFaultOp::CreateDirectory => FsFaultOpKind::CreateDirectory,
            FsFaultOp::RemoveFile => FsFaultOpKind::RemoveFile,
            FsFaultOp::Sync => FsFaultOpKind::Sync,
            FsFaultOp::SetLen => FsFaultOpKind::SetLen,
            FsFaultOp::SetTimes => FsFaultOpKind::SetTimes,
            FsFaultOp::SetTimesByPath => FsFaultOpKind::SetTimesByPath,
            FsFaultOp::ReadDirectory => FsFaultOpKind::ReadDirectory,
            FsFaultOp::RemoveDirectory => FsFaultOpKind::RemoveDirectory,
            FsFaultOp::Rename => FsFaultOpKind::Rename,
            FsFaultOp::Link => FsFaultOpKind::Link,
            FsFaultOp::Symlink => FsFaultOpKind::Symlink,
            FsFaultOp::ReadLink => FsFaultOpKind::ReadLink,
        }
    }

    /// Whether this operation can consume space, and so can plausibly fail
    /// `ENOSPC`. `Sync` is here because a filesystem with delayed allocation
    /// does the allocation at writeback: `fsync(2)` ERRORS lists `ENOSPC`
    /// explicitly, and a database's durability path meeting a full disk at
    /// fsync — not at write — is the canonical storage failure it must handle.
    /// `unlink(2)`/`rmdir(2)` are deliberately absent: neither lists `ENOSPC`,
    /// and removing a name does not allocate.
    fn can_no_space(self) -> bool {
        match self {
            FsFaultOp::Open { allocating } => allocating,
            FsFaultOp::Write
            | FsFaultOp::WriteAt
            | FsFaultOp::Sync
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
            | FsFaultOp::SetTimes
            | FsFaultOp::SetTimesByPath
            | FsFaultOp::ReadDirectory
            | FsFaultOp::RemoveDirectory
            | FsFaultOp::ReadLink => false,
        }
    }

    /// Whether a signal can land mid-operation and surface as `EINTR`. The
    /// data-plane calls and `fsync(2)` list it; `open(2)`'s `EINTR` is scoped to
    /// blocking opens of slow devices and FIFOs, which this filesystem does not
    /// model, so a regular-file open is not interruptible here.
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

/// Pick the errno an injected failure reports, from the set the operation could
/// actually produce on a real filesystem.
///
/// The point of a failure simulator is to inject failures the environment can
/// actually produce: a guest is entitled to treat an impossible errno as a bug
/// of its own and die on it, so an implausible injection is not a finding, it is
/// noise crowding real findings out of a campaign. Two rules follow.
///
/// **Never an error the syscall cannot return.** The per-operation predicates
/// above are checked against the Linux man-page ERRORS sections (`fsync(2)`,
/// `write(2)`, `read(2)`, `open(2)`, `rename(2)`, `unlink(2)`, `mkdir(2)`,
/// `link(2)`, `symlink(2)`, `ftruncate(2)`, `stat(2)`) and POSIX.1-2017, which
/// is where `EIO` comes from for the metadata and namespace calls whose Linux
/// pages omit it. The resulting sets, in the vocabulary of the errno an
/// `unreliable-libc`-style shim injects:
///
/// | operation                         | injected                       |
/// |-----------------------------------|--------------------------------|
/// | read, pread                       | `EIO`, `EINTR`                 |
/// | write, pwrite                     | `EIO`, `ENOSPC`, `EINTR`       |
/// | fsync                             | `EIO`, `ENOSPC`, `EINTR`       |
/// | open (creating)                   | `EIO`, `ENOSPC`                |
/// | open (existing), stat, fstat      | `EIO`                          |
/// | ftruncate                         | `EIO`, `ENOSPC`                |
/// | mkdir, rename, link, symlink      | `EIO`, `ENOSPC`                |
/// | unlink, rmdir, readdir, readlink  | `EIO`                          |
/// | utimensat                         | `EIO`                          |
///
/// **Never an error that indicts the CALLER rather than the storage.** `EBADF`,
/// `EFAULT` and `EINVAL` say the program passed a bad descriptor, pointer or
/// argument; no disk failure produces one, and injecting one asks the guest to
/// tolerate its own impossible bug. They are unreachable here by construction:
/// [`ErrorCode::Io`], [`ErrorCode::NoSpace`] and [`ErrorCode::Interrupted`] are
/// the only codes this function can return. (`EDQUOT` and `EMFILE`/`ENFILE`
/// would also be plausible for the write and open sets, but the driver ABI has
/// no code for them and `ENOSPC` already exercises the same guest paths.)
///
/// The choice is a pure function of the fault RNG's seeded stream and the
/// operation, so a seed reproduces the same errno at the same fire.
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
            .open(FsClock::EPOCH, "/file", OpenFlags::create_truncate_write())
            .unwrap();
        (fs, fd)
    }

    fn short_write_len(seed: u64) -> usize {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, seed).short_permille(1000);
        fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap()
    }

    struct RestartSnapshotDriver;

    impl FsDriver for RestartSnapshotDriver {
        fn open(&mut self, _clock: FsClock, _path: &str, _flags: OpenFlags) -> DriverResult<Fd> {
            Err(EffectError::new(ErrorCode::Denied, "unused"))
        }

        fn read(&mut self, _clock: FsClock, _fd: Fd, _max_len: usize) -> DriverResult<Vec<u8>> {
            Err(EffectError::new(ErrorCode::Denied, "unused"))
        }

        fn write(&mut self, _clock: FsClock, _fd: Fd, _bytes: &[u8]) -> DriverResult<usize> {
            Err(EffectError::new(ErrorCode::Denied, "unused"))
        }

        fn close(&mut self, _fd: Fd) -> DriverResult<()> {
            Err(EffectError::new(ErrorCode::Denied, "unused"))
        }

        fn crash_and_export_restart_snapshot(&mut self) -> DriverResult<Vec<u8>> {
            Ok(b"snapshot".to_vec())
        }
    }

    #[test]
    fn restart_snapshot_export_forwards_through_fault_wrapper() {
        let mut fs = FaultFs::new(RestartSnapshotDriver, 1).error_permille(1000);
        assert_eq!(fs.crash_and_export_restart_snapshot().unwrap(), b"snapshot");
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
            let error = fs.write(FsClock::EPOCH, fd, b"x").unwrap_err();
            seen.push(error.code);
        }
        assert!(seen.contains(&ErrorCode::Io), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::NoSpace), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::Interrupted), "seen={seen:?}");
    }

    /// `fsync(2)` ERRORS lists `ENOSPC`: with delayed allocation the disk-full
    /// condition surfaces at writeback, not at `write`. A model that could only
    /// fail fsync with `EIO` never exercises the guest's most important
    /// durability-path branch.
    #[test]
    fn fsync_can_report_a_full_disk() {
        let mut seen = Vec::new();
        for seed in 0..256 {
            let (inner, fd) = fs_with_open_file();
            let mut fs = FaultFs::new(inner, seed).error_permille(1000);
            seen.push(fs.sync(fd).unwrap_err().code);
        }
        assert!(seen.contains(&ErrorCode::NoSpace), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::Io), "seen={seen:?}");
        assert!(seen.contains(&ErrorCode::Interrupted), "seen={seen:?}");
    }

    /// The injected set must never contain a code that indicts the CALLER
    /// (`EBADF`, `EFAULT`, `EINVAL` at the POSIX boundary): no storage failure
    /// produces one, so a guest that dies on it is right to, and every
    /// generation that hits it is noise rather than a finding. This walks every
    /// fault-eligible operation rather than trusting the three-code enum to stay
    /// three codes.
    #[test]
    fn no_operation_injects_an_error_that_blames_the_caller() {
        let caller_faults = [
            ErrorCode::InvalidHandle,
            ErrorCode::InvalidInput,
            ErrorCode::NotFound,
            ErrorCode::Denied,
            ErrorCode::NotReadable,
            ErrorCode::NotWritable,
        ];
        // Every fault-eligible operation, `open` in both of its shapes. Pinned
        // against the shared kind table below so a new operation cannot slip in
        // untested.
        const ALL_FAULT_OPS: [FsFaultOp; 20] = [
            FsFaultOp::Open { allocating: true },
            FsFaultOp::Open { allocating: false },
            FsFaultOp::Read,
            FsFaultOp::Write,
            FsFaultOp::ReadAt,
            FsFaultOp::WriteAt,
            FsFaultOp::Metadata,
            FsFaultOp::FdMetadata,
            FsFaultOp::CreateDirectory,
            FsFaultOp::RemoveFile,
            FsFaultOp::Sync,
            FsFaultOp::SetLen,
            FsFaultOp::SetTimes,
            FsFaultOp::SetTimesByPath,
            FsFaultOp::ReadDirectory,
            FsFaultOp::RemoveDirectory,
            FsFaultOp::Rename,
            FsFaultOp::Link,
            FsFaultOp::Symlink,
            FsFaultOp::ReadLink,
        ];
        let covered: BTreeSet<&str> = ALL_FAULT_OPS.iter().map(|op| op.kind().name()).collect();
        let declared: BTreeSet<&str> = FsFaultOpKind::ALL.iter().map(|kind| kind.name()).collect();
        assert_eq!(
            covered, declared,
            "every fault-eligible kind must be walked"
        );

        let mut rng = SplitMix64::new(0x5eed);
        for op in ALL_FAULT_OPS {
            for _ in 0..512 {
                let code = choose_error_code(&mut rng, op);
                assert!(
                    !caller_faults.contains(&code),
                    "{:?} injected {code:?}",
                    op.kind().name()
                );
                // And only from the set the operation could actually return.
                let allowed = code == ErrorCode::Io
                    || (code == ErrorCode::NoSpace && op.can_no_space())
                    || (code == ErrorCode::Interrupted && op.can_interrupt());
                assert!(allowed, "{} injected {code:?}", op.kind().name());
            }
        }
    }

    #[test]
    fn fs_short_read_at_preserves_the_cursor() {
        let mut inner = MemFs::new();
        let fd = inner
            .open(
                FsClock::EPOCH,
                "/file",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: true,
                    append: false,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
                },
            )
            .unwrap();
        inner.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
        inner.seek(fd, 2, SeekWhence::Start).unwrap();

        let mut fs = FaultFs::new(inner, 3).short_permille(1000);
        let positional = fs.read_at(FsClock::EPOCH, fd, 0, 6).unwrap();
        assert!(!positional.is_empty() && positional.len() < 6);
        let mut inner = fs.into_inner();
        assert_eq!(inner.read(FsClock::EPOCH, fd, 2).unwrap(), b"cd");
    }

    #[test]
    fn fs_fault_report_is_per_class() {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        for _ in 0..5 {
            let written = fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
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

    /// Every fault-eligible operation must attribute its injected error to its
    /// OWN kind, and the breakdown must account for every counted effect. Two
    /// drift classes this catches: a new eligible operation whose `kind()` arm
    /// copies a neighbour's (its errors are then reported under the wrong op,
    /// and the neighbour looks better covered than it is), and a counted effect
    /// booked into the scalar without an attribution (the breakdown silently
    /// under-reports). The operation list is driven off `FsFaultOpKind::ALL`, so
    /// a kind added without a call site here fails rather than going untested.
    #[test]
    fn every_fault_eligible_operation_attributes_its_own_kind() {
        let fd = Fd(0);
        // Errors fire before the inner filesystem is touched, so an empty MemFs
        // and a synthetic fd exercise every arm.
        let drive = |fs: &mut FaultFs<MemFs>, kind: FsFaultOpKind| match kind {
            FsFaultOpKind::Open => fs
                .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
                .err(),
            FsFaultOpKind::Read => fs.read(FsClock::EPOCH, fd, 8).err(),
            FsFaultOpKind::Write => fs.write(FsClock::EPOCH, fd, b"abcdef").err(),
            FsFaultOpKind::ReadAt => fs.read_at(FsClock::EPOCH, fd, 0, 8).err(),
            FsFaultOpKind::WriteAt => fs.write_at(FsClock::EPOCH, fd, 0, b"abcdef").err(),
            FsFaultOpKind::Metadata => fs.metadata("/f").err(),
            FsFaultOpKind::FdMetadata => fs.fd_metadata(fd).err(),
            FsFaultOpKind::CreateDirectory => {
                fs.create_directory(FsClock::EPOCH, "/d", 0o777).err()
            }
            FsFaultOpKind::RemoveFile => fs.remove_file(FsClock::EPOCH, "/f").err(),
            FsFaultOpKind::Sync => fs.sync(fd).err(),
            FsFaultOpKind::SetLen => fs.set_len(FsClock::EPOCH, fd, 1).err(),
            FsFaultOpKind::SetTimes => fs.set_times(FsClock::EPOCH, fd, Some(1), Some(1)).err(),
            FsFaultOpKind::SetTimesByPath => fs
                .set_times_by_path(FsClock::EPOCH, "/f", Some(1), Some(1))
                .err(),
            FsFaultOpKind::ReadDirectory => fs.read_directory(FsClock::EPOCH, "/").err(),
            FsFaultOpKind::RemoveDirectory => fs.remove_directory(FsClock::EPOCH, "/d").err(),
            FsFaultOpKind::Rename => fs.rename(FsClock::EPOCH, "/f", "/g").err(),
            FsFaultOpKind::Link => fs.link(FsClock::EPOCH, "/f", "/g").err(),
            FsFaultOpKind::Symlink => fs.symlink(FsClock::EPOCH, "/f", "/g").err(),
            FsFaultOpKind::ReadLink => fs.read_link(FsClock::EPOCH, "/f").err(),
        };

        for kind in FsFaultOpKind::ALL {
            let mut fs = FaultFs::new(MemFs::new(), 1).error_permille(1000);
            let error = drive(&mut fs, kind)
                .unwrap_or_else(|| panic!("{} must be fault-eligible at rate 1000", kind.name()));
            assert!(
                error.message.contains(kind.name()),
                "{}: injected error names another operation: {}",
                kind.name(),
                error.message
            );
            let report = fs.fault_report().unwrap();
            assert_eq!(report.errors_injected, 1, "{}", kind.name());
            assert_eq!(
                report.errors_by_op.get(kind),
                1,
                "{} attributed its error elsewhere: {}",
                kind.name(),
                report.errors_by_op
            );
            assert_eq!(
                report.errors_by_op.total(),
                report.errors_injected,
                "{}: breakdown must account for every counted error",
                kind.name()
            );
        }

        // The short class over a mixed read/write workload: its breakdown must
        // add up too, and may only name truncatable kinds.
        let mut inner = MemFs::new();
        let fd = inner
            .open(
                FsClock::EPOCH,
                "/file",
                OpenFlags {
                    read: true,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        for _ in 0..4 {
            fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
            fs.write_at(FsClock::EPOCH, fd, 0, b"abcdef").unwrap();
            fs.read_at(FsClock::EPOCH, fd, 0, 4).unwrap();
        }
        let report = fs.fault_report().unwrap();
        assert_eq!(report.shorts_by_op.total(), report.shorts_applied);
        assert!(report.shorts_applied > 0);
        for (kind, _) in report.shorts_by_op.nonzero() {
            assert!(
                matches!(
                    kind,
                    FsFaultOpKind::Read
                        | FsFaultOpKind::Write
                        | FsFaultOpKind::ReadAt
                        | FsFaultOpKind::WriteAt
                ),
                "{} is not truncatable yet absorbed a short",
                kind.name()
            );
        }
    }

    #[test]
    fn fs_vacuity_ignores_rates_too_low_to_expect_a_fire() {
        let (inner, fd) = fs_with_open_file();
        let mut fs = FaultFs::new(inner, 1).short_permille(1);
        for _ in 0..10 {
            assert_eq!(fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap(), 6);
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
                FsClock::EPOCH,
                "/file",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: true,
                    append: false,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
                },
            )
            .unwrap();
        inner.write(FsClock::EPOCH, fd, b"abcdef").unwrap();

        // A guest reading into a buffer far larger than the file has left never
        // observes the truncation, so the knob is inert on this I/O path however
        // often it fires — the silent-inertness signature the report exists for.
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        for _ in 0..5 {
            assert_eq!(fs.read_at(FsClock::EPOCH, fd, 0, 8192).unwrap(), b"abcdef");
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
