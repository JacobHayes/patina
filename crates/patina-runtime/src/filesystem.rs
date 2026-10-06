//! Filesystem effects, timestamps, file helpers, and crash injection.

use crate::fs_crash::CrashOp;
use crate::recording::{
    Execution, FilesystemExpected, MAX_READ_FILE_BYTES, READ_CHUNK_SIZE, decode_bytes,
    decode_directory_entries, decode_handle, decode_metadata, decode_string, decode_u64,
    decode_unit, decode_usize,
};
use crate::{Context, RuntimeError};
use patina_dst_abi::{
    AtimePolicy, ClockKind, EffectError, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry,
    FsMetadata, FsNode, OpenFlags, Operation, Outcome, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::FsDriver;

/// Timestamp request; NOW is resolved after filesystem latency, before recording.
#[derive(Clone, Copy, Debug)]
pub enum FsTime {
    Omit,
    Now,
    /// Signed nanoseconds since the epoch; the filesystem truncates them to
    /// its range.
    Nanos(i128),
}

impl FsTime {
    fn resolve(self, clock: FsClock) -> Option<i128> {
        match self {
            Self::Omit => None,
            Self::Now => Some(i128::from(clock.now_nanos)),
            Self::Nanos(n) => Some(n),
        }
    }
}

impl From<Option<i128>> for FsTime {
    fn from(value: Option<i128>) -> Self {
        value.map_or(Self::Omit, Self::Nanos)
    }
}

impl Context {
    /// Delay one fault-eligible filesystem operation by a seeded draw from the
    /// configured `[min, max]` range, before the operation executes. Latency is
    /// the one fs fault that needs the clock, so it lives here rather than in the
    /// `FaultFs` wrapper — and here ONLY: no embedder adds a second site, or the
    /// same guest operation would be delayed twice in one family and once in the
    /// other.
    ///
    /// The decision-point law: a draw is consumed if and only if the knob is live
    /// and the range is not a single decision-free value, so a run without the
    /// knob is byte-identical and a fixed `N..N` latency perturbs no stream.
    /// Applying it before the operation means the op is slow and THEN fails when
    /// error injection also fires, and virtual time has already advanced when the
    /// I/O result lands — which is what reorders fs completions against timers.
    fn apply_fs_latency(&mut self) -> Result<(), RuntimeError> {
        let Some((min, max)) = self.fs_latency_nanos else {
            return Ok(());
        };
        self.fs_latency_eligible_ops += 1;
        let latency = if min == max {
            min
        } else {
            min + (self.fs_latency_rng.next_u64() % (max - min + 1))
        };
        if latency == 0 {
            return Ok(());
        }
        // Read the clock UNRECORDED (as the timer rescue does): the recorded
        // effect is the sleep itself, so an fs op under this knob costs one extra
        // trace op rather than two, and the driver's monotonic value is
        // maintained identically on record and replay by that same sleep.
        let now = self.current_monotonic()?;
        let deadline = now.saturating_add(latency);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        self.fs_latency_applied += 1;
        Ok(())
    }

    /// The end-of-run filesystem fault summary: the driver's own per-class
    /// counters merged with the Context's fs-latency counters. `None` when no
    /// filesystem fault class was live at all. This is what
    /// `PATINA_FS_FAULT_REPORT` prints at finalization; embedders and tests read
    /// it directly to assert a knob was non-vacuous.
    ///
    /// Eligible-op count prefers the driver's, because the driver and the Context
    /// observe the same operation stream independently: eligible traffic the
    /// driver saw that the Context never delayed is a filesystem path that
    /// bypassed the latency choke point, and the latency verdict is judged
    /// against that larger count precisely so the bypass shows up as vacuity
    /// rather than as silence.
    pub fn fs_fault_report(&self) -> Option<patina_dst_driver_api::FsFaultReport> {
        let driver = self.filesystem.as_ref().and_then(|fs| fs.fault_report());
        if driver.is_none() && self.fs_latency_nanos.is_none() {
            return None;
        }
        let mut report = driver.unwrap_or_default();
        report.eligible_ops = report.eligible_ops.max(self.fs_latency_eligible_ops);
        report.latency_applied = self.fs_latency_applied;
        report.latency_vacuity_diagnosable = self.fs_latency_nanos.is_some_and(|range| {
            patina_dst_driver_api::range_vacuity_is_diagnosable(report.eligible_ops, range)
        });
        Some(report)
    }

    /// The clock every reading or mutating filesystem operation is handed:
    /// virtual realtime read UNRECORDED (the driver's value is a pure function
    /// of the recorded sleeps, so it reproduces on replay exactly as
    /// [`Self::current_monotonic`] does, and an fs op costs no extra trace op)
    /// under the fixed relatime policy. A missing clock is a named refusal.
    fn fs_clock(&mut self) -> Result<FsClock, RuntimeError> {
        let now_nanos = self
            .clock
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("clock"))?
            .now(ClockKind::Realtime)?;
        Ok(FsClock {
            now_nanos,
            atime: AtimePolicy::Relatime,
        })
    }

    /// The instant [`Self::fs_clock`] would hand a filesystem operation now,
    /// for a kernel object that lives outside the filesystem driver (a pipe's
    /// pipefs inode, a System V IPC object, stamped by the native shim).
    /// Unrecorded for the same reason the filesystem's own reads are.
    pub fn fs_time_unrecorded(&mut self) -> Result<u64, RuntimeError> {
        Ok(self.fs_clock()?.now_nanos)
    }

    pub fn fs_open(&mut self, path: &str, flags: OpenFlags) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsOpen {
            path: path.into(),
            flags,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .open(clock, path, flags);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_handle(&operation, outcome);
        if decoded.is_ok() {
            self.maybe_inject_crash(CrashOp::Open)?;
        }
        decoded
    }

    pub fn fs_read(&mut self, fd: Fd, max_len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsRead { fd, max_len };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read(clock, fd, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    pub fn fs_write(&mut self, fd: Fd, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsWrite {
            fd,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write(clock, fd, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        if decoded.is_ok() {
            self.maybe_inject_crash(CrashOp::Write)?;
        }
        decoded
    }

    /// Positional read (`pread`): read at an explicit offset without moving the
    /// file cursor. Recorded as [`Operation::FsReadAt`], distinct from a cursor
    /// read, and -- like a cursor read -- fires no crash-injection boundary.
    pub fn fs_read_at(
        &mut self,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadAt {
            fd,
            offset,
            max_len,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_at(clock, fd, offset, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    /// Positional write (`pwrite`): write at an explicit offset without moving
    /// the file cursor. Recorded as [`Operation::FsWriteAt`] and counts toward
    /// the `write` crash ordinal, so `--fs-crash-at write:N` fires on a guest's
    /// positional page writes.
    pub fn fs_write_at(
        &mut self,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsWriteAt {
            fd,
            offset,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write_at(clock, fd, offset, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        if decoded.is_ok() {
            self.maybe_inject_crash(CrashOp::Write)?;
        }
        decoded
    }

    /// The cursor of filesystem handle `fd`, read UNRECORDED: it is a pure
    /// function of the recorded operations the driver executed, and the driver
    /// executes every one of them again on replay, so it reproduces without a
    /// trace op of its own (the native shim's page cache asks where a cursor
    /// write landed). A host-capture replay executes no driver, so there it is
    /// the recorded seek.
    pub fn fs_cursor_unrecorded(&mut self, fd: Fd) -> Result<u64, RuntimeError> {
        if self.filesystem_is_capture {
            return self.fs_seek(fd, 0, SeekWhence::Current);
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .seek(fd, 0, SeekWhence::Current)?)
    }

    /// The metadata of the entry filesystem handle `fd` is open on, read
    /// UNRECORDED as [`Self::fs_cursor_unrecorded`] is: the driver executes
    /// every operation that shaped it again on replay. It is bookkeeping, not
    /// a guest operation, so it costs no latency and is never faulted
    /// ([`FsDriver::fd_metadata_unfaulted`]): the native shim's page cache asks
    /// which file a handle's bytes belong to, its fs notifications which inode
    /// a handle is on, and `cachestat` how many pages a file has.
    pub fn fs_fd_metadata_unrecorded(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem_is_capture {
            return self.fs_fd_metadata(fd);
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .fd_metadata_unfaulted(fd)?)
    }

    /// How many of pages `first..=last` of `fd`'s file are dirty (written
    /// since their last durability point), read UNRECORDED and never faulted
    /// as [`Self::fs_fd_metadata_unrecorded`] is (`cachestat`). A
    /// host-capture replay executes no driver and has no answer.
    pub fn fs_dirty_pages_unrecorded(
        &mut self,
        fd: Fd,
        first: u64,
        last: u64,
    ) -> Result<u64, RuntimeError> {
        if self.filesystem_is_capture {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "a host-capture replay does not model dirty pages",
            )
            .into());
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .dirty_pages(fd, first, last)?)
    }

    /// The metadata of the entry at canonical `path`, read UNRECORDED and
    /// never faulted as [`Self::fs_fd_metadata_unrecorded`] is: the directory
    /// an fs notification is reported to, looked up inside the call that
    /// caused it.
    pub fn fs_metadata_unrecorded(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem_is_capture {
            return self.fs_metadata(path);
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .metadata_unfaulted(path)?)
    }

    /// Where filesystem handle `fd`'s node is now ([`Self::fs_fd_path`]),
    /// read UNRECORDED and never faulted as [`Self::fs_fd_metadata_unrecorded`]
    /// is: after an in-process crash rebuilt the image, the native shim's fs
    /// notifications look up again the name each descriptor holds.
    pub fn fs_fd_path_unrecorded(&mut self, fd: Fd) -> Result<String, RuntimeError> {
        if self.filesystem_is_capture {
            return self.fs_fd_path(fd);
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .fd_path(fd)?)
    }

    /// The page cache's write-back: what a shared mapping of `fd`'s file
    /// stored, written into the file ([`Operation::FsWriteBackAt`]). Not a
    /// guest operation, so no modeled latency; it is storage traffic, so it
    /// counts toward the `write` crash ordinal like any other write.
    pub fn fs_write_back_at(
        &mut self,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsWriteBackAt {
            fd,
            offset,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write_back_at(clock, fd, offset, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        if decoded.is_ok() {
            self.maybe_inject_crash(CrashOp::Write)?;
        }
        decoded
    }

    /// `memfd_create`: a nameless regular file on a new read-write handle
    /// ([`Operation::FsCreateAnonymous`]). No storage is touched, so no
    /// modeled latency.
    pub fn fs_create_anonymous(
        &mut self,
        name: &str,
        mode: u32,
        seals: u32,
        huge_page: u64,
    ) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsCreateAnonymous {
            name: name.into(),
            mode,
            seals,
            huge_page,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .create_anonymous(clock, name, mode, seals, huge_page);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_handle(&operation, outcome)
    }

    /// `F_GET_SEALS` ([`Operation::FsSeals`]).
    pub fn fs_seals(&mut self, fd: Fd) -> Result<u32, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsSeals { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => {
                return decode_u64(&operation, outcome).map(|seals| seals as u32);
            }
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .seals(fd);
        let actual = match result {
            Ok(seals) => Outcome::U64(u64::from(seals)),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_u64(&operation, outcome).map(|seals| seals as u32)
    }

    /// `F_ADD_SEALS` ([`Operation::FsAddSeals`]).
    pub fn fs_add_seals(
        &mut self,
        fd: Fd,
        seals: u32,
        writably_mapped: bool,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(
            Operation::FsAddSeals {
                fd,
                seals,
                writably_mapped,
            },
            |filesystem| filesystem.add_seals(fd, seals, writably_mapped),
        )
    }

    pub fn fs_close(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsClose { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .close(fd);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_unit(&operation, outcome);
        if decoded.is_ok() {
            self.maybe_inject_crash(CrashOp::Close)?;
        }
        decoded
    }

    pub fn fs_dup(&mut self, fd: Fd) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsDup { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .dup(fd);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_handle(&operation, outcome)
    }

    pub fn fs_seek(
        &mut self,
        fd: Fd,
        offset: i64,
        whence: SeekWhence,
    ) -> Result<u64, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsSeek { fd, offset, whence };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_u64(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .seek(fd, offset, whence);
        let actual = match result {
            Ok(position) => Outcome::U64(position),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_u64(&operation, outcome)
    }

    pub fn fs_metadata(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsMetadata { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .metadata(path);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_fd_metadata(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsFdMetadata { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .fd_metadata(fd);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    /// `mkdir`: create a directory at the caller's requested mode. The driver
    /// applies the modeled umask, exactly as the kernel applies the process
    /// umask.
    /// `fstat` on a descriptor the filesystem does not hold: a FIFO endpoint is
    /// a pipe, and its node identity is all the deterministic filesystem gave
    /// it. Reading the LIVE entry through the inode is what makes a `chmod`
    /// after the open visible here, exactly as it is through a regular file's
    /// descriptor. Latency and fault eligibility match
    /// [`DeterministicContext::fs_fd_metadata`] because this IS that `fstat`,
    /// not an extra lookup beside it.
    pub fn fs_inode_metadata(&mut self, ino: u64) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsInodeMetadata { ino };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .inode_metadata(ino);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_create_directory(&mut self, path: &str, mode: u32) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsCreateDirectory {
                path: path.into(),
                mode,
            },
            |filesystem, clock| filesystem.create_directory(clock, path, mode),
        )
    }

    /// `mkfifo`: create a named pipe. The NAME is filesystem state and is
    /// recorded like every other namespace mutation; the bytes that later flow
    /// through the FIFO are not filesystem state at all, so nothing about them
    /// crosses this boundary.
    pub fn fs_make_fifo(&mut self, path: &str, mode: u32) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsMakeFifo {
                path: path.into(),
                mode,
            },
            |filesystem, clock| filesystem.make_fifo(clock, path, mode),
        )
    }

    pub fn fs_remove_file(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsRemoveFile { path: path.into() },
            |filesystem, clock| filesystem.remove_file(clock, path),
        )
    }

    pub fn fs_sync(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        let result =
            self.filesystem_unit(Operation::FsSync { fd }, |filesystem| filesystem.sync(fd));
        if result.is_ok() {
            self.maybe_inject_crash(CrashOp::Sync)?;
        }
        result
    }

    pub fn fs_set_len(&mut self, fd: Fd, len: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(Operation::FsSetLength { fd, len }, |filesystem, clock| {
            filesystem.set_len(clock, fd, len)
        })
    }

    /// `truncate(2)`: a file's length by name, resolved and permission-checked
    /// by the driver as a kernel does on the path.
    pub fn fs_set_len_by_path(&mut self, path: &str, len: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsSetLengthByPath {
                path: path.into(),
                len,
            },
            |filesystem, clock| filesystem.set_len_by_path(clock, path, len),
        )
    }

    /// `fallocate(2)` over a regular file: one recorded operation whatever the
    /// range, so a gigabyte reservation or hole costs one trace event, never a
    /// zero-filled payload.
    pub fn fs_allocate(
        &mut self,
        fd: Fd,
        offset: u64,
        len: u64,
        mode: FsAllocateMode,
        keep_size: bool,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsAllocate {
                fd,
                offset,
                len,
                mode,
                keep_size,
            },
            |filesystem, clock| filesystem.allocate(clock, fd, offset, len, mode, keep_size),
        )
    }

    pub fn fs_set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> Result<(), RuntimeError> {
        self.fs_set_times_spec(fd, atime_nanos.into(), mtime_nanos.into())
    }

    pub fn fs_set_times_spec(
        &mut self,
        fd: Fd,
        atime: FsTime,
        mtime: FsTime,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let clock = self.fs_clock()?;
        let (atime_nanos, mtime_nanos) = (atime.resolve(clock), mtime.resolve(clock));
        self.filesystem_unit_undelayed(
            Operation::FsSetTimes {
                fd,
                atime_nanos,
                mtime_nanos,
            },
            |fs| fs.set_times(clock, fd, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> Result<(), RuntimeError> {
        self.fs_set_times_by_path_spec(path, atime_nanos.into(), mtime_nanos.into())
    }

    pub fn fs_set_times_by_path_spec(
        &mut self,
        path: &str,
        atime: FsTime,
        mtime: FsTime,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let clock = self.fs_clock()?;
        let (atime_nanos, mtime_nanos) = (atime.resolve(clock), mtime.resolve(clock));
        self.filesystem_unit_undelayed(
            Operation::FsSetTimesByPath {
                path: path.into(),
                atime_nanos,
                mtime_nanos,
            },
            |fs| fs.set_times_by_path(clock, path, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_set_inode_times(
        &mut self,
        ino: u64,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> Result<(), RuntimeError> {
        self.fs_set_inode_times_spec(ino, atime_nanos.into(), mtime_nanos.into())
    }

    pub fn fs_set_inode_times_spec(
        &mut self,
        ino: u64,
        atime: FsTime,
        mtime: FsTime,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let clock = self.fs_clock()?;
        let (atime_nanos, mtime_nanos) = (atime.resolve(clock), mtime.resolve(clock));
        self.filesystem_unit_undelayed(
            Operation::FsSetInodeTimes {
                ino,
                atime_nanos,
                mtime_nanos,
            },
            |fs| fs.set_inode_times(clock, ino, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_read_directory(&mut self, path: &str) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadDirectory { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => {
                return decode_directory_entries(&operation, outcome);
            }
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_directory(clock, path);
        let actual = match result {
            Ok(entries) => Outcome::DirectoryEntries(entries),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_directory_entries(&operation, outcome)
    }

    /// `getdents`/`readdir` on a directory DESCRIPTOR. The access was charged
    /// when the descriptor was opened, so this reads the node the descriptor
    /// holds — which is also why a descriptor opened `O_PATH` cannot list at
    /// all, however permissive the directory's bits are.
    pub fn fs_read_directory_fd(&mut self, fd: Fd) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadDirectoryFd { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => {
                return decode_directory_entries(&operation, outcome);
            }
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_directory_fd(clock, fd);
        let actual = match result {
            Ok(entries) => Outcome::DirectoryEntries(entries),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_directory_entries(&operation, outcome)
    }

    /// `fchmod` through a descriptor the filesystem holds no handle for. Latency
    /// and fault eligibility match [`DeterministicContext::fs_set_fd_mode`],
    /// because this IS that `fchmod`, named by node instead of by descriptor.
    pub fn fs_set_inode_mode(&mut self, ino: u64, mode: u32) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsSetInodeMode { ino, mode },
            |filesystem, clock| filesystem.set_inode_mode(clock, ino, mode),
        )
    }

    /// Take a node reference for a descriptor the filesystem holds no handle
    /// for — a FIFO endpoint. No modeled latency and no fault eligibility, for
    /// the same reason [`DeterministicContext::fs_fd_path`] has none: this is
    /// the reference count inside `open`, not a second trip to storage.
    pub fn fs_retain_inode(&mut self, ino: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(Operation::FsRetainInode { ino }, |filesystem| {
            filesystem.retain_inode(ino)
        })
    }

    /// Drop the reference [`DeterministicContext::fs_retain_inode`] took.
    pub fn fs_release_inode(&mut self, ino: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(Operation::FsReleaseInode { ino }, |filesystem| {
            filesystem.release_inode(ino)
        })
    }

    pub fn fs_remove_directory(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsRemoveDirectory { path: path.into() },
            |filesystem, clock| filesystem.remove_directory(clock, path),
        )
    }

    pub fn fs_rename(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsRename {
                from: from.into(),
                to: to.into(),
            },
            |filesystem, clock| filesystem.rename(clock, from, to),
        )
    }

    /// `renameat2(RENAME_EXCHANGE)`: swap two existing entries atomically.
    pub fn fs_exchange(&mut self, first: &str, second: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsExchange {
                first: first.into(),
                second: second.into(),
            },
            |filesystem, clock| filesystem.exchange(clock, first, second),
        )
    }

    /// `mknod`: the NAME and its node, at the caller's requested mode; a
    /// device other than the whiteout is refused by the driver.
    pub fn fs_make_node(
        &mut self,
        path: &str,
        node: FsNode,
        mode: u32,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsMakeNode {
                path: path.into(),
                node,
                mode,
            },
            |filesystem, clock| filesystem.make_node(clock, path, node, mode),
        )
    }

    /// `renameat2(RENAME_WHITEOUT)`: a rename leaving a whiteout at `from`, as
    /// one change.
    pub fn fs_rename_whiteout(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsRenameWhiteout {
                from: from.into(),
                to: to.into(),
            },
            |filesystem, clock| filesystem.rename_whiteout(clock, from, to),
        )
    }

    /// `sync(2)`/`syncfs(2)`: every change on the volume made durable. A sync,
    /// so it counts toward the `sync` crash ordinal like a descriptor's.
    pub fn fs_sync_all(&mut self) -> Result<(), RuntimeError> {
        let result = self.filesystem_unit(Operation::FsSyncAll, |filesystem| filesystem.sync_all());
        if result.is_ok() {
            self.maybe_inject_crash(CrashOp::Sync)?;
        }
        result
    }

    /// One extended attribute's value (`getxattr` family).
    pub fn fs_get_xattr(
        &mut self,
        target: &XattrTarget,
        name: &str,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.filesystem_bytes(
            Operation::FsGetXattr {
                target: target.clone(),
                name: name.into(),
            },
            |filesystem| filesystem.get_xattr(target, name),
        )
    }

    /// The extended attribute names the caller may see (`listxattr` family),
    /// as the kernel lists them: each name NUL-terminated, back to back.
    pub fn fs_list_xattr(&mut self, target: &XattrTarget) -> Result<Vec<u8>, RuntimeError> {
        self.filesystem_bytes(
            Operation::FsListXattr {
                target: target.clone(),
            },
            |filesystem| {
                filesystem.list_xattr(target).map(|names| {
                    names
                        .into_iter()
                        .flat_map(|name| name.into_bytes().into_iter().chain([0]))
                        .collect()
                })
            },
        )
    }

    /// Set one extended attribute (`setxattr` family).
    pub fn fs_set_xattr(
        &mut self,
        target: &XattrTarget,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsSetXattr {
                target: target.clone(),
                name: name.into(),
                value: value.to_vec(),
                flags,
            },
            |filesystem, clock| filesystem.set_xattr(clock, target, name, value, flags),
        )
    }

    /// Remove one extended attribute (`removexattr` family).
    pub fn fs_remove_xattr(
        &mut self,
        target: &XattrTarget,
        name: &str,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsRemoveXattr {
                target: target.clone(),
                name: name.into(),
            },
            |filesystem, clock| filesystem.remove_xattr(clock, target, name),
        )
    }

    /// The byte-outcome filesystem choke point for fault-eligible reads that
    /// take no clock.
    fn filesystem_bytes(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<Vec<u8>, EffectError>,
    ) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let result = invoke(
            self.filesystem
                .as_mut()
                .expect("driver was checked")
                .as_mut(),
        );
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    pub fn fs_link(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsLink {
                from: from.into(),
                to: to.into(),
            },
            |filesystem, clock| filesystem.link(clock, from, to),
        )
    }

    pub fn fs_symlink(&mut self, target: &str, link_path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsSymlink {
                target: target.into(),
                link_path: link_path.into(),
            },
            |filesystem, clock| filesystem.symlink(clock, target, link_path),
        )
    }

    /// `chmod`: change the permission bits of the entry `path` names. A mode
    /// change is durable state, so it is a recorded boundary operation like
    /// every other namespace mutation.
    pub fn fs_set_mode(&mut self, path: &str, mode: u32) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(
            Operation::FsSetMode {
                path: path.into(),
                mode,
            },
            |filesystem, clock| filesystem.set_mode(clock, path, mode),
        )
    }

    /// `fchmod`: the same change, named by an open descriptor.
    pub fn fs_set_fd_mode(&mut self, fd: Fd, mode: u32) -> Result<(), RuntimeError> {
        self.filesystem_unit_clocked(Operation::FsSetFdMode { fd, mode }, |filesystem, clock| {
            filesystem.set_fd_mode(clock, fd, mode)
        })
    }

    /// Where an open descriptor's filesystem NODE is now.
    ///
    /// `*at` resolution needs a spelling for the directory a descriptor names,
    /// and the honest answer is the node's CURRENT path: a descriptor pins an
    /// inode, so a rename moves the descriptor with it and a symlink planted at
    /// the name it was opened under is never followed. Asking the filesystem is
    /// what makes that true — a name cached beside the descriptor would go
    /// stale exactly when it matters.
    ///
    /// No modeled I/O latency and no fault eligibility: this is the name lookup
    /// the kernel does inside the `*at` call itself, not a second trip to
    /// storage. Charging latency would bill every `*at` twice, and an injected
    /// `EIO` here would be a failure mode no real `openat` has.
    pub fn fs_fd_path(&mut self, fd: Fd) -> Result<String, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsFdPath { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_string(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .fd_path(fd);
        let actual = match result {
            Ok(path) => Outcome::Bytes(path.into_bytes()),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    /// The inode an open descriptor names: the identity record and `flock`
    /// locks key on. No modeled latency and no fault eligibility, for the
    /// reason [`DeterministicContext::fs_fd_path`] has none: a lock is
    /// bookkeeping that does no I/O, and no real `fcntl` or `flock` fails with
    /// an injected `EIO`.
    pub fn fs_fd_ino(&mut self, fd: Fd) -> Result<u64, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsFdIno { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_u64(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .fd_ino(fd);
        let actual = match result {
            Ok(ino) => Outcome::U64(ino),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_u64(&operation, outcome)
    }

    pub fn fs_read_link(&mut self, path: &str) -> Result<String, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadLink { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_string(&operation, outcome),
        };
        let clock = self.fs_clock()?;
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_link(clock, path);
        let actual = match result {
            Ok(target) => Outcome::Bytes(target.into_bytes()),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    /// Convenience: create/truncate `path` and write `bytes` through the
    /// ordinary `fs_open`/`fs_write`/`fs_close` boundary operations.
    pub fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::create_truncate_write())?;
        let written = self.fs_write(fd, bytes)?;
        if written != bytes.len() {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "short virtual write to {path}: wrote {written} of {} bytes",
                    bytes.len()
                ),
            )
            .into());
        }
        self.fs_close(fd)
    }

    /// Convenience: read all of `path` through the ordinary
    /// `fs_open`/`fs_read`/`fs_close` boundary operations.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::read_only())?;
        let mut contents = Vec::new();
        loop {
            let chunk = self.fs_read(fd, READ_CHUNK_SIZE)?;
            if chunk.is_empty() {
                break;
            }
            if contents.len().saturating_add(chunk.len()) > MAX_READ_FILE_BYTES {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual file exceeds read_file limit of {MAX_READ_FILE_BYTES} bytes"),
                )
                .into());
            }
            contents.extend_from_slice(&chunk);
        }
        self.fs_close(fd)?;
        Ok(contents)
    }

    fn filesystem_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<FilesystemExpected, RuntimeError> {
        let expected = self.replay_expected(operation)?;
        if !self.filesystem_is_capture {
            return Ok(FilesystemExpected::Execute(expected));
        }
        if let Some((_, outcome)) = expected {
            return Ok(FilesystemExpected::Captured(outcome));
        }
        if matches!(self.execution, Execution::Branch { .. }) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!(
                    "host-capture replay reached unrecorded filesystem operation {operation:?}"
                ),
            )
            .into());
        }
        Ok(FilesystemExpected::Execute(None))
    }

    fn filesystem_unit_clocked(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver, FsClock) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let clock = self.fs_clock()?;
        self.filesystem_unit_undelayed(operation, |fs| invoke(fs, clock))
    }

    /// The unit-outcome filesystem choke point for FAULT-ELIGIBLE operations:
    /// seeded fs latency applies here, once, before the operation executes.
    pub(super) fn filesystem_unit(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        self.filesystem_unit_undelayed(operation, invoke)
    }

    /// The same choke point without fault latency, for the administrative
    /// operations outside the eligible set (`crash`).
    pub(super) fn filesystem_unit_undelayed(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = invoke(
            self.filesystem
                .as_mut()
                .expect("driver was checked")
                .as_mut(),
        );
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }
}

#[cfg(test)]
pub(super) mod tests;
