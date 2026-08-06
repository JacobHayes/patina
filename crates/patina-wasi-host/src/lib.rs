//! Deterministic WASI Preview 1 host functions and Wasmi guest-memory bridges.
//!
//! Internal crate: the host side of `cargo patina run` for `wasm32-wasip1`
//! guests. It implements the audited WASI Preview 1 import surface — plus the
//! `patina_sdk` module the `patina-dst` macros bridge to — against the same
//! deterministic runtime the native shim drives. The allowlisted surface covers
//! process inputs, clocks, entropy, virtual files, polling, configured
//! datagrams, stdio, and exit. Every other import is rejected before
//! instantiation, so an unmodeled effect is a loud refusal rather than a host
//! escape. Adopters use the CLI; see [ARCHITECTURE.md] for the WASI host design.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::BTreeMap;
use std::fmt;

use patina_dst_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsEntryKind, FsMetadata, OpenFlags, SeekWhence, SocketId,
};
use patina_dst_runtime::{BuggifyKind, Context, RuntimeError, SiteOutcome};
use patina_dst_target::{TargetError, WasiAudit};
use wasmi::{
    AsContextMut, Caller, Config as WasmiConfig, Engine, Error as WasmiError, Extern, Linker,
    Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiClock {
    Realtime,
    Monotonic,
}

/// A deterministic host adapter with no inherited arguments, environment, or
/// stdio. Callers explicitly populate those capabilities.
pub struct Preview1Host {
    context: Context,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    descriptors: BTreeMap<u32, WasiDescriptor>,
    next_descriptor: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    limits: ResourceLimits,
    /// Guest mount points and their access policy, keyed by canonical path.
    mounts: BTreeMap<String, MountPolicy>,
    /// True once an explicit preopen replaced the implicit read-write root.
    explicit_preopens: bool,
    /// Linear-memory limiter installed on the Wasmi store at execution time.
    store_limits: StoreLimits,
    /// Per-import call counts, keyed by the imported function name. Written by
    /// every `define_preview1`/`define_patina_sdk` wrapper and never read by any
    /// host function, so counting cannot perturb the guest: the map is a pure
    /// observation of the same deterministic instruction stream that produces
    /// `WasiExecution::fuel_consumed`.
    hostcalls: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug)]
enum WasiDescriptor {
    File {
        handle: Fd,
        path: String,
        rights: u64,
        inheriting: u64,
        flags: u16,
    },
    Directory {
        path: String,
        handle: Option<Fd>,
        preopen: bool,
        rights: u64,
        inheriting: u64,
    },
    Datagram {
        socket: SocketId,
        peer: String,
        shutdown: bool,
        rights: u64,
        inheriting: u64,
    },
}

#[derive(Clone, Copy, Debug)]
struct WasiPathOpen {
    oflags: u16,
    rights: u64,
    inheriting: u64,
    fdflags: u16,
    follow_symlink: bool,
}

enum WasiSubscription {
    Clock {
        userdata: u64,
        clock: WasiClock,
        deadline: u64,
        absolute: bool,
    },
    FdRead {
        userdata: u64,
        fd: u32,
    },
    FdWrite {
        userdata: u64,
        fd: u32,
    },
}

impl Preview1Host {
    pub fn new(context: Context) -> Self {
        let mut descriptors = BTreeMap::new();
        descriptors.insert(
            3,
            WasiDescriptor::Directory {
                path: "/".into(),
                handle: None,
                preopen: true,
                rights: WASI_DIRECTORY_RIGHTS,
                inheriting: WASI_DIRECTORY_RIGHTS | WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
            },
        );
        let mut mounts = BTreeMap::new();
        mounts.insert("/".to_owned(), MountPolicy::ReadWrite);
        Self {
            context,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            descriptors,
            next_descriptor: 4,
            stdout: Vec::new(),
            stderr: Vec::new(),
            limits: ResourceLimits::default(),
            mounts,
            explicit_preopens: false,
            store_limits: StoreLimits::default(),
            hostcalls: BTreeMap::new(),
        }
    }

    /// Record one call to the imported function `name`. The saturating add keeps
    /// a pathological guest from wrapping the counter around to a smaller depth.
    fn count_hostcall(&mut self, name: &'static str) {
        let entry = self.hostcalls.entry(name).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Replace the default resource ceilings.
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn resource_limits(&self) -> ResourceLimits {
        self.limits
    }

    /// Add a preopened directory with an access policy.
    ///
    /// The first call replaces the implicit read-write `/` root, after which
    /// preopens must be non-overlapping: a nested or duplicate guest path is a
    /// [`WasiHostError::PreopenOverlap`]. Read-only mounts drop namespace and
    /// write rights and are additionally enforced at every mutating host call.
    pub fn with_preopen(
        mut self,
        guest_path: &str,
        policy: MountPolicy,
    ) -> Result<Self, WasiHostError> {
        let guest = normalize_mount_path(guest_path)?;
        if !self.explicit_preopens {
            self.descriptors.retain(|_, descriptor| {
                !matches!(descriptor, WasiDescriptor::Directory { preopen: true, .. })
            });
            self.mounts.clear();
            self.explicit_preopens = true;
        }
        if self.mounts.len() >= self.limits.max_preopens {
            return Err(WasiHostError::TooManyPreopens(self.limits.max_preopens));
        }
        if self.descriptors.len() >= self.limits.max_descriptors {
            return Err(WasiHostError::DescriptorExhausted);
        }
        if let Some(existing) = self
            .mounts
            .keys()
            .find(|existing| mounts_overlap(existing, &guest))
        {
            return Err(WasiHostError::PreopenOverlap {
                existing: existing.clone(),
                requested: guest,
            });
        }
        let mut fd = 3;
        while self.descriptors.contains_key(&fd) {
            fd = fd
                .checked_add(1)
                .ok_or(WasiHostError::DescriptorExhausted)?;
        }
        let (rights, inheriting) = preopen_rights(policy);
        self.descriptors.insert(
            fd,
            WasiDescriptor::Directory {
                path: guest.clone(),
                handle: None,
                preopen: true,
                rights,
                inheriting,
            },
        );
        self.mounts.insert(guest, policy);
        self.next_descriptor = self.next_descriptor.max(
            fd.checked_add(1)
                .ok_or(WasiHostError::DescriptorExhausted)?,
        );
        Ok(self)
    }

    /// The access policy governing a resolved absolute path (longest match).
    fn governing_policy(&self, path: &str) -> MountPolicy {
        self.mounts
            .iter()
            .filter(|(mount, _)| path == mount.as_str() || mount_contains(mount, path))
            .max_by_key(|(mount, _)| mount.len())
            .map(|(_, policy)| *policy)
            .unwrap_or(MountPolicy::ReadWrite)
    }

    /// Fail closed when a mutation targets a read-only mount, independent of
    /// the descriptor rights so it cannot be bypassed through rename, unlink,
    /// set-times, or any other namespace call.
    fn ensure_writable(&self, path: &str) -> Result<(), WasiHostError> {
        match self.governing_policy(path) {
            MountPolicy::ReadWrite => Ok(()),
            MountPolicy::ReadOnly => Err(WasiHostError::ReadOnly),
        }
    }

    fn ensure_writable_fd(&self, fd: u32) -> Result<(), WasiHostError> {
        match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { path, .. }) => self.ensure_writable(path),
            _ => Ok(()),
        }
    }

    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Install an explicitly configured connected datagram descriptor.
    pub fn with_datagram_socket(
        mut self,
        fd: u32,
        bind: &str,
        peer: impl Into<String>,
    ) -> Result<Self, WasiHostError> {
        if fd <= 3 || self.descriptors.contains_key(&fd) {
            return Err(WasiHostError::DescriptorInUse(fd));
        }
        let next = fd
            .checked_add(1)
            .ok_or(WasiHostError::DescriptorExhausted)?;
        let socket = self.context.net_bind(bind)?;
        self.descriptors.insert(
            fd,
            WasiDescriptor::Datagram {
                socket,
                peer: peer.into(),
                shutdown: false,
                rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE | WASI_RIGHT_POLL_FD_READWRITE,
                inheriting: 0,
            },
        );
        self.next_descriptor = self.next_descriptor.max(next);
        Ok(self)
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub fn random_get(&mut self, destination: &mut [u8]) -> Result<(), WasiHostError> {
        let bytes = self.context.entropy_bytes(destination.len())?;
        destination.copy_from_slice(&bytes);
        Ok(())
    }

    pub fn clock_res_get(&self, _clock: WasiClock) -> u64 {
        1
    }

    pub fn clock_time_get(&mut self, clock: WasiClock) -> Result<u64, WasiHostError> {
        let clock = match clock {
            WasiClock::Realtime => ClockKind::Realtime,
            WasiClock::Monotonic => ClockKind::Monotonic,
        };
        self.context.now(clock).map_err(Into::into)
    }

    pub fn sleep_until(
        &mut self,
        clock: WasiClock,
        deadline_nanos: u64,
    ) -> Result<(), WasiHostError> {
        let clock = match clock {
            WasiClock::Realtime => ClockKind::Realtime,
            WasiClock::Monotonic => ClockKind::Monotonic,
        };
        // Apply any configured seeded sleep-latency jitter here, at the single
        // guest-facing sleep entry, so both a direct `nanosleep`-style wait and a
        // `poll_oneoff` clock timeout (which routes through this method) sleep to
        // the same inflated deadline. The draw is owned by the deterministic
        // context (seeded, replayed), so the jittered deadline reproduces exactly;
        // an unjittered run is byte-for-byte unchanged.
        let deadline_nanos = self.context.apply_sleep_jitter(deadline_nanos);
        self.context
            .sleep_until(clock, deadline_nanos)
            .map_err(Into::into)
    }

    /// Implements deterministic writes for stdout (1), stderr (2), and
    /// virtual regular-file descriptors.
    pub fn fd_write(&mut self, fd: u32, buffers: &[&[u8]]) -> Result<usize, WasiHostError> {
        let total = buffers.iter().try_fold(0usize, |written, buffer| {
            written
                .checked_add(buffer.len())
                .ok_or(WasiHostError::OutputSizeOverflow)
        })?;
        match fd {
            1 | 2 => {
                let output = if fd == 1 {
                    &mut self.stdout
                } else {
                    &mut self.stderr
                };
                for buffer in buffers {
                    output.extend_from_slice(buffer);
                }
                Ok(total)
            }
            other => {
                self.ensure_writable_fd(other)?;
                let (handle, append) = self.file_write_handle(other)?;
                if append {
                    self.context.fs_seek(handle, 0, SeekWhence::End)?;
                }
                self.fd_write_positioned(other, buffers)
            }
        }
    }

    fn file_write_handle(&self, fd: u32) -> Result<(Fd, bool), WasiHostError> {
        let (handle, rights, flags) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File {
                handle,
                rights,
                flags,
                ..
            }) => (*handle, *rights, *flags),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_WRITE == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        Ok((handle, flags & WASI_FDFLAG_APPEND != 0))
    }

    fn fd_write_positioned(&mut self, fd: u32, buffers: &[&[u8]]) -> Result<usize, WasiHostError> {
        let (handle, _) = self.file_write_handle(fd)?;
        let total = buffers.iter().try_fold(0usize, |written, buffer| {
            written
                .checked_add(buffer.len())
                .ok_or(WasiHostError::OutputSizeOverflow)
        })?;
        let mut bytes = Vec::with_capacity(total);
        for buffer in buffers {
            bytes.extend_from_slice(buffer);
        }
        self.context.fs_write(handle, &bytes).map_err(Into::into)
    }

    fn fd_fdstat_set_flags(&mut self, fd: u32, fdflags: u16) -> Result<(), WasiHostError> {
        if fdflags & !WASI_FDFLAGS_ALL != 0 {
            return Err(WasiHostError::Runtime(
                EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("unsupported WASI fdflags bits: 0x{fdflags:x}"),
                )
                .into(),
            ));
        }
        match self.descriptors.get_mut(&fd) {
            Some(WasiDescriptor::File { flags, .. }) => {
                *flags = fdflags;
                Ok(())
            }
            _ => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    fn fd_fdstat_set_rights(
        &mut self,
        fd: u32,
        rights: u64,
        inheriting: u64,
    ) -> Result<(), WasiHostError> {
        match self.descriptors.get_mut(&fd) {
            Some(WasiDescriptor::File {
                rights: current,
                inheriting: current_inheriting,
                ..
            })
            | Some(WasiDescriptor::Directory {
                rights: current,
                inheriting: current_inheriting,
                ..
            })
            | Some(WasiDescriptor::Datagram {
                rights: current,
                inheriting: current_inheriting,
                ..
            }) => {
                if rights & !*current != 0 || inheriting & !*current_inheriting != 0 {
                    return Err(WasiHostError::NotCapable(fd));
                }
                *current = rights;
                *current_inheriting = inheriting;
                Ok(())
            }
            None => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    fn fd_renumber(&mut self, from: u32, to: u32) -> Result<(), WasiHostError> {
        let Some(descriptor) = self.descriptors.get(&from) else {
            return Err(WasiHostError::DeniedFd(from));
        };
        if from == to {
            return Ok(());
        }
        if matches!(descriptor, WasiDescriptor::Directory { preopen: true, .. }) {
            return Err(WasiHostError::DeniedFd(from));
        }
        let next = to
            .checked_add(1)
            .ok_or(WasiHostError::DescriptorExhausted)?;
        if self.descriptors.contains_key(&to) {
            self.fd_close(to)?;
        }
        let descriptor = self
            .descriptors
            .remove(&from)
            .expect("source descriptor was checked");
        self.descriptors.insert(to, descriptor);
        self.next_descriptor = self.next_descriptor.max(next);
        Ok(())
    }

    /// OS-scheduling hint. Preview1Host has no cooperative task model, so a
    /// no-op is the deterministic interpretation.
    const fn sched_yield(&self) -> i32 {
        WASI_ERRNO_SUCCESS
    }

    /// No process/signal model exists; report the same errno used for missing
    /// deterministic drivers.
    const fn proc_raise(&self, _signal: u32) -> i32 {
        WASI_ERRNO_NOSYS
    }

    /// Preview 1 has no listen/bind surface, and Patina's socket model only
    /// produces pre-connected datagrams, so no descriptor can be a listening
    /// socket.
    const fn sock_accept(&self, _fd: u32, _flags: u16) -> i32 {
        WASI_ERRNO_NOSYS
    }

    fn filestat_set_times_values(
        &mut self,
        atime_nanos: u64,
        mtime_nanos: u64,
        flags: u16,
    ) -> Result<(Option<u64>, Option<u64>), WasiHostError> {
        if flags & !WASI_FSTFLAGS_ALL != 0
            || flags & WASI_FSTFLAG_ATIM != 0 && flags & WASI_FSTFLAG_ATIM_NOW != 0
            || flags & WASI_FSTFLAG_MTIM != 0 && flags & WASI_FSTFLAG_MTIM_NOW != 0
        {
            return Err(WasiHostError::InvalidInput);
        }
        let now = if flags & (WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM_NOW) != 0 {
            Some(self.clock_time_get(WasiClock::Realtime)?)
        } else {
            None
        };
        let atime = if flags & WASI_FSTFLAG_ATIM != 0 {
            Some(atime_nanos)
        } else if flags & WASI_FSTFLAG_ATIM_NOW != 0 {
            now
        } else {
            None
        };
        let mtime = if flags & WASI_FSTFLAG_MTIM != 0 {
            Some(mtime_nanos)
        } else if flags & WASI_FSTFLAG_MTIM_NOW != 0 {
            now
        } else {
            None
        };
        Ok((atime, mtime))
    }

    fn resolve_path(&self, directory: u32, path: &[u8]) -> Result<String, WasiHostError> {
        if path.len() > self.limits.max_path_bytes {
            return Err(WasiHostError::PathTooLong);
        }
        let root = match self.descriptors.get(&directory) {
            Some(WasiDescriptor::Directory { path, .. }) => path,
            _ => return Err(WasiHostError::DeniedFd(directory)),
        };
        let path = std::str::from_utf8(path).map_err(|_| {
            WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI path is not UTF-8").into(),
            )
        })?;
        if path.contains('\0') {
            return Err(WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI path contains NUL").into(),
            ));
        }
        let mut components = Vec::new();
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    return Err(WasiHostError::Runtime(
                        EffectError::new(
                            ErrorCode::Denied,
                            format!("WASI path escapes its preopened directory: {path:?}"),
                        )
                        .into(),
                    ));
                }
                component => components.push(component),
            }
        }
        let suffix = components.join("/");
        Ok(if root == "/" {
            if suffix.is_empty() {
                "/".into()
            } else {
                format!("/{suffix}")
            }
        } else if suffix.is_empty() {
            root.clone()
        } else {
            format!("{root}/{suffix}")
        })
    }

    fn resolve_symlink_target(
        &self,
        link_path: &str,
        target: &str,
    ) -> Result<String, WasiHostError> {
        if target.starts_with('/') {
            return self.resolve_absolute_path(target);
        }
        let parent = host_parent_path(link_path);
        let joined = if parent == "/" {
            format!("/{target}")
        } else {
            format!("{parent}/{target}")
        };
        self.resolve_absolute_path(&joined)
    }

    fn resolve_absolute_path(&self, path: &str) -> Result<String, WasiHostError> {
        if path == "/" {
            return Ok("/".into());
        }
        self.resolve_path(3, path.as_bytes())
    }

    fn resolve_path_with_terminal_follow(
        &mut self,
        directory: u32,
        path: &[u8],
        follow: bool,
        opening: bool,
    ) -> Result<String, WasiHostError> {
        let path = self.resolve_path(directory, path)?;
        match self.context.fs_metadata(&path) {
            Ok(metadata) if metadata.kind == FsEntryKind::Symlink => {
                if !follow {
                    if opening {
                        return Err(WasiHostError::Loop);
                    }
                    return Ok(path);
                }
                let target = self.context.fs_read_link(&path)?;
                let target = self.resolve_symlink_target(&path, &target)?;
                let metadata = self.context.fs_metadata(&target)?;
                if metadata.kind == FsEntryKind::Symlink {
                    return Err(WasiHostError::Loop);
                }
                Ok(target)
            }
            Ok(_) => Ok(path),
            Err(RuntimeError::Effect(error)) if error.code == ErrorCode::NotFound => Ok(path),
            Err(error) => Err(error.into()),
        }
    }

    fn allocate_descriptor(&mut self, descriptor: WasiDescriptor) -> Result<u32, WasiHostError> {
        if self.descriptors.len() >= self.limits.max_descriptors {
            return Err(WasiHostError::DescriptorExhausted);
        }
        let fd = self.next_descriptor;
        self.next_descriptor = self
            .next_descriptor
            .checked_add(1)
            .ok_or(WasiHostError::DescriptorExhausted)?;
        self.descriptors.insert(fd, descriptor);
        Ok(fd)
    }

    fn path_open(
        &mut self,
        directory: u32,
        path: &[u8],
        options: WasiPathOpen,
    ) -> Result<u32, WasiHostError> {
        let path =
            self.resolve_path_with_terminal_follow(directory, path, options.follow_symlink, true)?;
        let write_intent = options.rights & WASI_RIGHT_FD_WRITE != 0
            || options.oflags & (WASI_OFLAG_CREATE | WASI_OFLAG_TRUNCATE | WASI_OFLAG_EXCLUSIVE)
                != 0;
        if write_intent {
            self.ensure_writable(&path)?;
        }
        if options.oflags & WASI_OFLAG_DIRECTORY != 0 {
            let metadata = self.context.fs_metadata(&path)?;
            if metadata.kind != FsEntryKind::Directory {
                return Err(WasiHostError::Runtime(
                    EffectError::new(ErrorCode::NotDirectory, format!("not a directory: {path}"))
                        .into(),
                ));
            }
            let handle = self.context.fs_open(&path, OpenFlags::read_only())?;
            return self.allocate_descriptor(WasiDescriptor::Directory {
                path,
                handle: Some(handle),
                preopen: false,
                rights: options.rights,
                inheriting: options.inheriting,
            });
        }
        let flags = OpenFlags {
            read: options.rights & WASI_RIGHT_FD_READ != 0,
            write: options.rights & WASI_RIGHT_FD_WRITE != 0,
            create: options.oflags & WASI_OFLAG_CREATE != 0,
            truncate: options.oflags & WASI_OFLAG_TRUNCATE != 0,
            append: options.fdflags & WASI_FDFLAG_APPEND != 0,
            exclusive: options.oflags & WASI_OFLAG_EXCLUSIVE != 0,
        };
        let handle = self.context.fs_open(&path, flags)?;
        self.allocate_descriptor(WasiDescriptor::File {
            handle,
            path,
            rights: options.rights,
            inheriting: options.inheriting,
            flags: options.fdflags,
        })
    }

    fn fd_close(&mut self, fd: u32) -> Result<(), WasiHostError> {
        match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, .. }) => {
                self.context.fs_close(*handle)?;
                self.descriptors.remove(&fd);
                Ok(())
            }
            Some(WasiDescriptor::Directory {
                handle,
                preopen: false,
                ..
            }) => {
                if let Some(handle) = *handle {
                    self.context.fs_close(handle)?;
                }
                self.descriptors.remove(&fd);
                Ok(())
            }
            Some(WasiDescriptor::Datagram {
                socket, shutdown, ..
            }) => {
                if !shutdown {
                    self.context.net_close(*socket)?;
                }
                self.descriptors.remove(&fd);
                Ok(())
            }
            _ => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    fn fd_sync(&mut self, fd: u32) -> Result<(), WasiHostError> {
        let (handle, close_after) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, .. }) => (*handle, false),
            Some(WasiDescriptor::Directory {
                handle: Some(handle),
                ..
            }) => (*handle, false),
            Some(WasiDescriptor::Directory {
                path, handle: None, ..
            }) => {
                let path = path.clone();
                (self.context.fs_open(&path, OpenFlags::read_only())?, true)
            }
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        let synced = self.context.fs_sync(handle);
        if close_after {
            match self.context.fs_close(handle) {
                Err(error)
                    if !matches!(
                        error,
                        RuntimeError::Effect(ref effect)
                            if effect.code == ErrorCode::InvalidHandle
                    ) =>
                {
                    return Err(error.into());
                }
                _ => {}
            }
        }
        synced.map_err(Into::into)
    }

    fn fd_read(&mut self, fd: u32, max_len: usize) -> Result<Vec<u8>, WasiHostError> {
        let (handle, rights) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, rights, .. }) => (*handle, *rights),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_READ == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        self.context.fs_read(handle, max_len).map_err(Into::into)
    }

    fn fd_allocate(&mut self, fd: u32, offset: u64, len: u64) -> Result<(), WasiHostError> {
        let (handle, rights) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, rights, .. }) => (*handle, *rights),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_ALLOCATE == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        self.ensure_writable_fd(fd)?;
        let end = offset.checked_add(len).ok_or_else(|| {
            WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI allocation range overflowed")
                    .into(),
            )
        })?;
        let metadata = self.context.fs_fd_metadata(handle)?;
        if end > metadata.len {
            self.context.fs_set_len(handle, end)?;
        }
        Ok(())
    }

    fn fd_filestat_set_size(&mut self, fd: u32, len: u64) -> Result<(), WasiHostError> {
        let (handle, rights) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, rights, .. }) => (*handle, *rights),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_WRITE == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        self.ensure_writable_fd(fd)?;
        self.context.fs_set_len(handle, len).map_err(Into::into)
    }

    fn fd_filestat_set_times(
        &mut self,
        fd: u32,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), WasiHostError> {
        self.ensure_writable_fd(fd)?;
        let handle = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, .. }) => *handle,
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context
            .fs_set_times(handle, atime_nanos, mtime_nanos)
            .map_err(Into::into)
    }

    fn path_filestat_set_times(
        &mut self,
        directory: u32,
        path: &[u8],
        follow_symlink: bool,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), WasiHostError> {
        let path =
            self.resolve_path_with_terminal_follow(directory, path, follow_symlink, false)?;
        self.ensure_writable(&path)?;
        self.context
            .fs_set_times_by_path(&path, atime_nanos, mtime_nanos)
            .map_err(Into::into)
    }

    fn path_link(
        &mut self,
        old_directory: u32,
        old_path: &[u8],
        new_directory: u32,
        new_path: &[u8],
    ) -> Result<(), WasiHostError> {
        let old_path = self.resolve_path(old_directory, old_path)?;
        let new_path = self.resolve_path(new_directory, new_path)?;
        // Hard links share one inode, so linking a read-only source into a
        // read-write mount would create a writable alias to read-only content.
        self.ensure_writable(&old_path)?;
        self.ensure_writable(&new_path)?;
        self.context
            .fs_link(&old_path, &new_path)
            .map_err(Into::into)
    }

    fn path_symlink(
        &mut self,
        target: &[u8],
        directory: u32,
        link_path: &[u8],
    ) -> Result<(), WasiHostError> {
        let target = std::str::from_utf8(target).map_err(|_| {
            WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI symlink target is not UTF-8")
                    .into(),
            )
        })?;
        if target.contains('\0') {
            return Err(WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI symlink target contains NUL")
                    .into(),
            ));
        }
        let link_path = self.resolve_path(directory, link_path)?;
        self.ensure_writable(&link_path)?;
        self.context
            .fs_symlink(target, &link_path)
            .map_err(Into::into)
    }

    fn path_readlink(&mut self, directory: u32, path: &[u8]) -> Result<String, WasiHostError> {
        let path = self.resolve_path(directory, path)?;
        self.context.fs_read_link(&path).map_err(Into::into)
    }

    fn fd_advise(&self, fd: u32) -> Result<(), WasiHostError> {
        match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { rights, .. }) if rights & WASI_RIGHT_FD_ADVISE != 0 => {
                Ok(())
            }
            Some(WasiDescriptor::File { .. }) => Err(WasiHostError::NotCapable(fd)),
            _ => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    fn fd_seek(&mut self, fd: u32, offset: i64, whence: SeekWhence) -> Result<u64, WasiHostError> {
        let handle = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, .. }) => *handle,
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context
            .fs_seek(handle, offset, whence)
            .map_err(Into::into)
    }

    fn fd_pread(&mut self, fd: u32, max_len: usize, offset: u64) -> Result<Vec<u8>, WasiHostError> {
        let (handle, rights) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, rights, .. }) => (*handle, *rights),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_READ == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        self.context
            .fs_read_at(handle, offset, max_len)
            .map_err(Into::into)
    }

    fn fd_pwrite(
        &mut self,
        fd: u32,
        buffers: &[&[u8]],
        offset: u64,
    ) -> Result<usize, WasiHostError> {
        self.ensure_writable_fd(fd)?;
        let (handle, _) = self.file_write_handle(fd)?;
        let total = buffers.iter().try_fold(0usize, |written, buffer| {
            written
                .checked_add(buffer.len())
                .ok_or(WasiHostError::OutputSizeOverflow)
        })?;
        let mut bytes = Vec::with_capacity(total);
        for buffer in buffers {
            bytes.extend_from_slice(buffer);
        }
        // fd_pwrite is explicitly positioned I/O; it does not consult APPEND,
        // which only affects cursor-based fd_write.
        self.context
            .fs_write_at(handle, offset, &bytes)
            .map_err(Into::into)
    }

    fn fd_metadata(&mut self, fd: u32) -> Result<(FsMetadata, String), WasiHostError> {
        match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, path, .. }) => {
                let metadata = self.context.fs_fd_metadata(*handle)?;
                Ok((metadata, path.clone()))
            }
            Some(WasiDescriptor::Directory { path, handle, .. }) => {
                let path = path.clone();
                let metadata = if let Some(handle) = handle {
                    self.context.fs_fd_metadata(*handle)?
                } else {
                    match self.context.fs_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(RuntimeError::Effect(error)) if error.code == ErrorCode::NotFound => {
                            FsMetadata {
                                kind: FsEntryKind::Directory,
                                len: 0,
                                ino: 0,
                                nlink: 1,
                                atime_nanos: 0,
                                mtime_nanos: 0,
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                Ok((metadata, path))
            }
            _ => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    fn sock_send(&mut self, fd: u32, bytes: &[u8]) -> Result<usize, WasiHostError> {
        let (socket, peer) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::Datagram {
                socket,
                peer,
                shutdown: false,
                ..
            }) => (*socket, peer.clone()),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context
            .net_send(socket, &peer, bytes)
            .map(|report| report.written)
            .map_err(Into::into)
    }

    fn sock_recv(&mut self, fd: u32) -> Result<Option<Vec<u8>>, WasiHostError> {
        let socket = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::Datagram {
                socket,
                shutdown: false,
                ..
            }) => *socket,
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context
            .net_recv(socket)
            .map(|datagram| datagram.map(|datagram| datagram.bytes))
            .map_err(Into::into)
    }

    fn sock_shutdown(&mut self, fd: u32) -> Result<(), WasiHostError> {
        let socket = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::Datagram {
                socket,
                shutdown: false,
                ..
            }) => *socket,
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context.net_close(socket)?;
        match self.descriptors.get_mut(&fd) {
            Some(WasiDescriptor::Datagram { shutdown, .. }) => *shutdown = true,
            _ => unreachable!("datagram descriptor was checked"),
        }
        Ok(())
    }

    fn poll(
        &mut self,
        subscriptions: &[WasiSubscription],
    ) -> Result<Vec<(u64, u8, u64)>, WasiHostError> {
        let mut ready = Vec::new();
        for subscription in subscriptions {
            match *subscription {
                WasiSubscription::FdRead { userdata, fd } => {
                    let bytes = match self.descriptors.get(&fd) {
                        Some(WasiDescriptor::File { rights, .. })
                            if rights & WASI_RIGHT_FD_READ != 0 =>
                        {
                            self.fd_metadata(fd)?.0.len
                        }
                        Some(WasiDescriptor::Datagram {
                            shutdown: false, ..
                        }) => 0,
                        Some(WasiDescriptor::File { .. } | WasiDescriptor::Datagram { .. }) => {
                            return Err(WasiHostError::NotCapable(fd));
                        }
                        _ => return Err(WasiHostError::DeniedFd(fd)),
                    };
                    ready.push((userdata, 1, bytes));
                }
                WasiSubscription::FdWrite { userdata, fd } => {
                    let writable = matches!(fd, 1 | 2)
                        || matches!(
                            self.descriptors.get(&fd),
                            Some(WasiDescriptor::File { rights, .. })
                                if rights & WASI_RIGHT_FD_WRITE != 0
                        )
                        || matches!(
                            self.descriptors.get(&fd),
                            Some(WasiDescriptor::Datagram {
                                shutdown: false,
                                ..
                            })
                        );
                    if !writable {
                        return Err(if fd == 0 || self.descriptors.contains_key(&fd) {
                            WasiHostError::NotCapable(fd)
                        } else {
                            WasiHostError::DeniedFd(fd)
                        });
                    }
                    ready.push((userdata, 2, 0));
                }
                WasiSubscription::Clock { .. } => {}
            }
        }
        if !ready.is_empty() {
            return Ok(ready);
        }

        let mut deadlines = Vec::new();
        let mut earliest: Option<(WasiClock, u64, u64)> = None;
        for subscription in subscriptions {
            if let WasiSubscription::Clock {
                userdata,
                clock,
                deadline,
                absolute,
            } = *subscription
            {
                let now = self.clock_time_get(clock)?;
                let deadline = if absolute {
                    deadline
                } else {
                    now.checked_add(deadline).ok_or_else(|| {
                        WasiHostError::Runtime(
                            EffectError::new(
                                ErrorCode::InvalidInput,
                                "WASI poll clock deadline overflowed",
                            )
                            .into(),
                        )
                    })?
                };
                let wait = deadline.saturating_sub(now);
                if earliest.is_none_or(|(_, _, shortest)| wait < shortest) {
                    earliest = Some((clock, deadline, wait));
                }
                deadlines.push((userdata, clock, deadline));
            }
        }
        let Some((clock, deadline, _)) = earliest else {
            return Err(WasiHostError::Runtime(
                EffectError::new(ErrorCode::InvalidInput, "WASI poll has no subscriptions").into(),
            ));
        };
        self.sleep_until(clock, deadline)?;
        for (userdata, clock, deadline) in deadlines {
            if self.clock_time_get(clock)? >= deadline {
                ready.push((userdata, 0, 0));
            }
        }
        Ok(ready)
    }

    pub const fn proc_exit(&self, code: u32) -> WasiExit {
        WasiExit { code }
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn finish(self) -> Result<(), WasiHostError> {
        self.context.finish().map_err(Into::into)
    }

    fn finish_with_output(self) -> Result<(Vec<u8>, Vec<u8>), WasiHostError> {
        let Self {
            context,
            stdout,
            stderr,
            ..
        } = self;
        // Detect a declared-but-never-reached setup gate before `finish` consumes
        // the context, mirroring the native shim's `patina_shutdown`. The trace is
        // still finalized (the run stays reproducible) and `finish` still emits the
        // `PATINA_SDK_REPORT` line; then the run fails loudly rather than passing as
        // a silent no-fault run.
        let setup_violation = context.buggify_setup_violation();
        context.finish()?;
        if setup_violation {
            // Emit the marker to the real process stderr, as the native shim writes
            // it to fd 2, so the campaign classifier sees the same token regardless
            // of how the caller surfaces the returned error.
            eprintln!("{BUGGIFY_SETUP_NEVER_CALLED_MARKER}");
            return Err(WasiHostError::BuggifySetupNeverCalled);
        }
        Ok((stdout, stderr))
    }
}

const WASI_ERRNO_SUCCESS: i32 = 0;
const WASI_ERRNO_AGAIN: i32 = 6;
const WASI_ERRNO_BADF: i32 = 8;
const WASI_ERRNO_EXIST: i32 = 20;
const WASI_ERRNO_INVAL: i32 = 28;
const WASI_ERRNO_CONNREFUSED: i32 = 14;
const WASI_ERRNO_CONNRESET: i32 = 15;
const WASI_ERRNO_INTR: i32 = 27;
const WASI_ERRNO_IO: i32 = 29;
const WASI_ERRNO_NOTCONN: i32 = 53;
const WASI_ERRNO_PIPE: i32 = 59;
const WASI_ERRNO_ISDIR: i32 = 31;
const WASI_ERRNO_LOOP: i32 = 32;
const WASI_ERRNO_MFILE: i32 = 33;
const WASI_ERRNO_NOENT: i32 = 44;
const WASI_ERRNO_NOSPC: i32 = 51;
const WASI_ERRNO_NOSYS: i32 = 52;
const WASI_ERRNO_NOTDIR: i32 = 54;
const WASI_ERRNO_NOTEMPTY: i32 = 55;
const WASI_ERRNO_OVERFLOW: i32 = 61;
const WASI_ERRNO_NOTCAPABLE: i32 = 76;
const WASI_ERRNO_NAMETOOLONG: i32 = 37;
const WASI_ERRNO_ROFS: i32 = 69;

const WASI_FILETYPE_CHARACTER_DEVICE: u8 = 2;
const WASI_FILETYPE_DIRECTORY: u8 = 3;
const WASI_FILETYPE_REGULAR_FILE: u8 = 4;
const WASI_FILETYPE_SOCKET_DGRAM: u8 = 5;
const WASI_FILETYPE_SYMBOLIC_LINK: u8 = 7;

const SYNTHETIC_STDIO_INO_BASE: u64 = 0xffff_ffff_0000_0000;
const SYNTHETIC_DATAGRAM_INO_BASE: u64 = 0xffff_ffff_1000_0000;

const WASI_RIGHT_FD_READ: u64 = 1 << 1;
const WASI_RIGHT_FD_WRITE: u64 = 1 << 6;
const WASI_RIGHT_FD_ADVISE: u64 = 1 << 7;
const WASI_RIGHT_FD_ALLOCATE: u64 = 1 << 8;
const WASI_RIGHT_POLL_FD_READWRITE: u64 = 1 << 27;
const WASI_RIGHT_PATH_CREATE_DIRECTORY: u64 = 1 << 9;
const WASI_RIGHT_PATH_CREATE_FILE: u64 = 1 << 10;
const WASI_RIGHT_PATH_REMOVE_DIRECTORY: u64 = 1 << 25;
const WASI_RIGHT_PATH_UNLINK_FILE: u64 = 1 << 26;
const WASI_DIRECTORY_RIGHTS: u64 = WASI_RIGHT_PATH_CREATE_DIRECTORY
    | WASI_RIGHT_PATH_CREATE_FILE
    | (1 << 13)
    | (1 << 14)
    | (1 << 18)
    | (1 << 21)
    | WASI_RIGHT_PATH_REMOVE_DIRECTORY
    | WASI_RIGHT_PATH_UNLINK_FILE;
/// Rights that let a directory descriptor mutate the namespace. A read-only
/// preopen drops these from its granted and inheriting rights.
const WASI_DIRECTORY_MUTATION_RIGHTS: u64 = WASI_RIGHT_PATH_CREATE_DIRECTORY
    | WASI_RIGHT_PATH_CREATE_FILE
    | WASI_RIGHT_PATH_REMOVE_DIRECTORY
    | WASI_RIGHT_PATH_UNLINK_FILE;
const WASI_OFLAG_CREATE: u16 = 1 << 0;
const WASI_OFLAG_DIRECTORY: u16 = 1 << 1;
const WASI_OFLAG_EXCLUSIVE: u16 = 1 << 2;
const WASI_OFLAG_TRUNCATE: u16 = 1 << 3;
const WASI_FDFLAG_APPEND: u16 = 1 << 0;
const WASI_FDFLAGS_ALL: u16 = 0x1f;
const WASI_FSTFLAG_ATIM: u16 = 1 << 0;
const WASI_FSTFLAG_ATIM_NOW: u16 = 1 << 1;
const WASI_FSTFLAG_MTIM: u16 = 1 << 2;
const WASI_FSTFLAG_MTIM_NOW: u16 = 1 << 3;
const WASI_FSTFLAGS_ALL: u16 =
    WASI_FSTFLAG_ATIM | WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM | WASI_FSTFLAG_MTIM_NOW;
const MAX_WASI_IOVECS: usize = 1_024;
const MAX_WASI_IO_BYTES: usize = 16 * 1024 * 1024;

/// Size of one WebAssembly linear-memory page.
const WASM_PAGE_BYTES: usize = 64 * 1024;
/// Generous default guest linear-memory cap: 4096 pages (256 MiB).
const DEFAULT_MAX_MEMORY_PAGES: u32 = 4_096;
/// Default ceiling on simultaneously open descriptors (preopens included).
const DEFAULT_MAX_DESCRIPTORS: usize = 1_024;
/// Default ceiling on configured preopened directories.
const DEFAULT_MAX_PREOPENS: usize = 64;
/// Default ceiling on a single guest-supplied path in bytes.
const DEFAULT_MAX_PATH_BYTES: usize = 4_096;

pub const DEFAULT_WASM_FUEL: u64 = 10_000_000;

/// Access policy applied to a preopened directory and everything under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountPolicy {
    /// Reads and metadata are allowed; every mutation is denied.
    ReadOnly,
    /// Full read/write access.
    ReadWrite,
}

/// Deterministic, fail-closed resource ceilings for one guest execution.
///
/// Every limit is enforced as a typed deterministic error or trap, never a
/// silent fallthrough. Defaults are generous but bounded, not unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Wasmi fuel budget for the whole run (also caps CPU work).
    pub fuel: u64,
    /// Maximum guest linear-memory size in 64 KiB pages. Growth past this is a
    /// deterministic trap.
    pub max_memory_pages: u32,
    /// Maximum iovec entries accepted by a single scatter/gather call.
    pub max_iovecs: usize,
    /// Maximum bytes moved by a single read/write/path operation.
    pub max_io_bytes: usize,
    /// Maximum simultaneously open descriptors, preopens included.
    pub max_descriptors: usize,
    /// Maximum configured preopened directories.
    pub max_preopens: usize,
    /// Maximum length in bytes of a single guest-supplied path.
    pub max_path_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_WASM_FUEL,
            max_memory_pages: DEFAULT_MAX_MEMORY_PAGES,
            max_iovecs: MAX_WASI_IOVECS,
            max_io_bytes: MAX_WASI_IO_BYTES,
            max_descriptors: DEFAULT_MAX_DESCRIPTORS,
            max_preopens: DEFAULT_MAX_PREOPENS,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
        }
    }
}

fn build_store_limits(max_memory_pages: u32) -> StoreLimits {
    let bytes = (max_memory_pages as usize).saturating_mul(WASM_PAGE_BYTES);
    StoreLimitsBuilder::new()
        .memory_size(bytes)
        .trap_on_grow_failure(true)
        .build()
}

fn preopen_rights(policy: MountPolicy) -> (u64, u64) {
    match policy {
        MountPolicy::ReadWrite => (
            WASI_DIRECTORY_RIGHTS,
            WASI_DIRECTORY_RIGHTS | WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
        ),
        MountPolicy::ReadOnly => {
            let granted = WASI_DIRECTORY_RIGHTS & !WASI_DIRECTORY_MUTATION_RIGHTS;
            (granted, granted | WASI_RIGHT_FD_READ)
        }
    }
}

/// Whether `child` lies strictly within the `parent` mount.
fn mount_contains(parent: &str, child: &str) -> bool {
    if parent == "/" {
        return child != "/";
    }
    child.starts_with(&format!("{parent}/"))
}

fn mounts_overlap(a: &str, b: &str) -> bool {
    a == b || mount_contains(a, b) || mount_contains(b, a)
}

/// Canonicalize a configured preopen path to an absolute, `..`-free form.
fn normalize_mount_path(path: &str) -> Result<String, WasiHostError> {
    if !path.starts_with('/') {
        return Err(WasiHostError::InvalidPreopen(format!(
            "preopen path must be absolute: {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(WasiHostError::InvalidPreopen(
            "preopen path contains NUL".into(),
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(WasiHostError::InvalidPreopen(format!(
                    "preopen path must not contain '..': {path:?}"
                )));
            }
            value => components.push(value),
        }
    }
    Ok(if components.is_empty() {
        "/".into()
    } else {
        format!("/{}", components.join("/"))
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasiExecution {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub fuel_consumed: u64,
    /// Per-import call counts keyed by imported function name — the hostcall half
    /// of the WASI depth proxy (see `docs/arcs/coverage-depth.md` §5). Like
    /// `fuel_consumed` this is a deterministic function of the executed
    /// instruction stream and is report-only: it never enters the trace, a
    /// fingerprint, or any canonical hash.
    pub hostcalls: BTreeMap<&'static str, u64>,
}

impl WasiExecution {
    /// Total hostcalls across every imported function.
    pub fn hostcalls_total(&self) -> u64 {
        self.hostcalls
            .values()
            .fold(0u64, |total, count| total.saturating_add(*count))
    }
}

/// Execute an audited WASI Preview 1 core module through deterministic host
/// functions. Unsupported imports are rejected before instantiation.
pub fn execute_preview1(
    module_bytes: &[u8],
    host: Preview1Host,
) -> Result<WasiExecution, WasiRunError> {
    let fuel = host.limits.fuel;
    execute_preview1_with_fuel(module_bytes, host, fuel)
}

/// The wasmi engine [`Config`] with every determinism-relevant knob pinned
/// EXPLICITLY rather than inherited from `Config::default()`, so an upstream
/// change to wasmi's defaults can never silently alter guest-observable
/// behavior under a deterministic-replay product. Verified against wasmi
/// 1.1.0; wasmi is a pure interpreter (no JIT), which shapes how the two
/// classic sources of cross-engine float divergence are handled:
///
///   - NaN bit patterns: wasmi computes floats in software (`wasmi_core`), so
///     a NaN-producing op yields the same bits on every run and every host.
///     There is NO NaN-canonicalization knob to set (unlike a JIT engine,
///     which needs one); the `nan_bits_are_deterministic` test pins that this
///     stays true.
///   - relaxed-SIMD: the ONE Wasm proposal whose results are implementation-
///     defined (relaxed FMA / swizzle / lane-select may legally differ across
///     engines) and therefore a determinism hole. It is reachable only under
///     wasmi's `simd` cargo feature, which this workspace deliberately does
///     NOT enable — `Config::wasm_simd`/`wasm_relaxed_simd` are themselves
///     gated behind it, so the nondeterministic code path is compiled out of
///     the engine entirely (a stronger guarantee than a runtime `false`) and
///     SIMD modules are rejected at validation. The `simd_module_is_rejected`
///     test pins that the feature stays off; if it is ever turned on, this
///     config MUST additionally call `config.wasm_relaxed_simd(false)`.
///
/// * `consume_fuel(true)` — bounds CPU work AND makes `fuel_consumed` a
///   deterministic function of the guest's executed instruction stream. wasmi
///   1.x fixed the `fuel_for_copying_values` rounding (`(len/64)*8` ->
///   `(len*8)/64`), so absolute fuel for multi-value copies/calls is slightly
///   higher than under 0.47; that only shifts the fuel-exhaustion trap
///   boundary — `fuel_consumed` is never recorded in the trace or any
///   canonical hash (only stdout/stderr/exit_code plus the deterministic host
///   `Context` drive replay). Within one engine version fuel is fully
///   deterministic.
/// * `floats(true)` — f32/f64 stay enabled (default true in 0.47 and 1.1;
///   pinned so a default flip cannot disable float support out from under a
///   guest).
///
/// All remaining default features (mutable-global, multi-value, multi-memory,
/// sat-float-to-int, sign-extension, bulk-memory, reference-types, tail-call,
/// extended-const, memory64) are byte-for-byte identical between wasmi 0.47.2
/// and 1.1.0 and are all deterministic.
fn deterministic_wasmi_config() -> WasmiConfig {
    let mut config = WasmiConfig::default();
    config.consume_fuel(true);
    config.floats(true);
    config
}

const PATINA_STATIC_SITE_SECTION: &str = "patina_sites";
const PATINA_STATIC_SITE_MAGIC: &[u8; 4] = b"PTS1";
const PATINA_STATIC_SITE_HEADER_LEN: usize = 14;

/// A malformed `patina_sites` custom section is a host-side configuration
/// failure: the module claims Patina SDK sites but cannot describe them.
fn static_site_error(message: String) -> WasiRunError {
    WasiRunError::Host(WasiHostError::from(RuntimeError::Config(message)))
}

fn declare_wasm_static_sites(
    context: &mut Context,
    module_bytes: &[u8],
) -> Result<(), WasiRunError> {
    if module_bytes.len() < 8 || &module_bytes[..4] != b"\0asm" {
        return Ok(());
    }
    let mut cursor = 8;
    while cursor < module_bytes.len() {
        let section_id = module_bytes[cursor];
        cursor += 1;
        let section_size = read_wasm_uleb(module_bytes, &mut cursor)? as usize;
        let section_end = cursor.checked_add(section_size).ok_or_else(|| {
            static_site_error("WASM section size overflows module length".to_string())
        })?;
        if section_end > module_bytes.len() {
            return Err(static_site_error(
                "WASM section extends past end of module".to_string(),
            ));
        }
        if section_id == 0 {
            let mut body_cursor = cursor;
            let name_len = read_wasm_uleb(module_bytes, &mut body_cursor)? as usize;
            let name_end = body_cursor.checked_add(name_len).ok_or_else(|| {
                static_site_error("WASM custom-section name length overflows".to_string())
            })?;
            if name_end > section_end {
                return Err(static_site_error(
                    "WASM custom-section name extends past section".to_string(),
                ));
            }
            let name =
                std::str::from_utf8(&module_bytes[body_cursor..name_end]).map_err(|error| {
                    static_site_error(format!("WASM custom-section name is not UTF-8: {error}"))
                })?;
            if name == PATINA_STATIC_SITE_SECTION {
                parse_wasm_static_site_payload(context, &module_bytes[name_end..section_end])?;
            }
        }
        cursor = section_end;
    }
    Ok(())
}

fn read_wasm_uleb(module_bytes: &[u8], cursor: &mut usize) -> Result<u32, WasiRunError> {
    let mut result = 0_u32;
    let mut shift = 0_u32;
    loop {
        if *cursor >= module_bytes.len() {
            return Err(static_site_error(
                "truncated WASM section length".to_string(),
            ));
        }
        let byte = module_bytes[*cursor];
        *cursor += 1;
        if shift >= 32 {
            return Err(static_site_error(
                "WASM section length exceeds u32".to_string(),
            ));
        }
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 35 {
            return Err(static_site_error(
                "malformed WASM section length".to_string(),
            ));
        }
    }
}

fn parse_wasm_static_site_payload(
    context: &mut Context,
    payload: &[u8],
) -> Result<(), WasiRunError> {
    let mut cursor = 0;
    while cursor < payload.len() {
        if payload.len() - cursor < PATINA_STATIC_SITE_HEADER_LEN {
            return Err(static_site_error(
                "truncated Patina WASM static site record".to_string(),
            ));
        }
        if &payload[cursor..cursor + 4] != PATINA_STATIC_SITE_MAGIC {
            return Err(static_site_error(
                "malformed Patina WASM static site record magic".to_string(),
            ));
        }
        let kind = BuggifyKind::from_static_site_kind(payload[cursor + 4]).ok_or_else(|| {
            static_site_error(format!(
                "Patina WASM static site record has unknown kind {}",
                payload[cursor + 4]
            ))
        })?;
        let flags = payload[cursor + 5];
        if flags != 0 {
            return Err(static_site_error(format!(
                "Patina WASM static site record has unsupported flags {flags}"
            )));
        }
        let label_len = u32::from_le_bytes(
            payload[cursor + 6..cursor + 10]
                .try_into()
                .expect("fixed label length field"),
        ) as usize;
        let site_len = u32::from_le_bytes(
            payload[cursor + 10..cursor + 14]
                .try_into()
                .expect("fixed site length field"),
        ) as usize;
        let label_start = cursor + PATINA_STATIC_SITE_HEADER_LEN;
        let site_start = label_start.checked_add(label_len).ok_or_else(|| {
            static_site_error("Patina WASM static site label length overflows".to_string())
        })?;
        let next = site_start.checked_add(site_len).ok_or_else(|| {
            static_site_error("Patina WASM static site identity length overflows".to_string())
        })?;
        if next > payload.len() {
            return Err(static_site_error(
                "Patina WASM static site record extends past section".to_string(),
            ));
        }
        let label = std::str::from_utf8(&payload[label_start..site_start]).map_err(|error| {
            static_site_error(format!(
                "Patina WASM static site label is not valid UTF-8: {error}"
            ))
        })?;
        let site = std::str::from_utf8(&payload[site_start..next]).map_err(|error| {
            static_site_error(format!(
                "Patina WASM static site identity is not valid UTF-8: {error}"
            ))
        })?;
        let outcome = context
            .declare_static_site(label, site, kind)
            .map_err(|error| static_site_error(error.to_string()))?;
        if outcome == SiteOutcome::DuplicateLabel {
            return Err(WasiRunError::Engine(patina_buggify_fatal(
                "PATINA_BUGGIFY_DUPLICATE_LABEL",
                label,
            )));
        }
        cursor = next;
    }
    Ok(())
}

/// Fail closed on missing depth data. Fuel metering is pinned on for every run
/// and the engine charges the executed instruction stream including the `_start`
/// call, so a guest that ran to completion consumed fuel. Zero means the
/// accounting stopped working — and a zero-valued depth report is
/// indistinguishable from a genuine "did nothing" run, exactly the silent-empty
/// report the coverage/depth arc refuses (`docs/arcs/coverage-depth.md` §10 D1).
fn check_depth_available(fuel_consumed: u64) -> Result<(), WasiRunError> {
    if fuel_consumed == 0 {
        return Err(WasiRunError::Depth(
            "WASI run completed but reported fuel_consumed=0; depth accounting is not recording \
the executed instruction stream (refusing an empty depth report that cannot be told apart from \
zero depth)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn execute_preview1_with_fuel(
    module_bytes: &[u8],
    mut host: Preview1Host,
    fuel: u64,
) -> Result<WasiExecution, WasiRunError> {
    WasiAudit::audit(module_bytes).map_err(WasiRunError::Target)?;
    declare_wasm_static_sites(&mut host.context, module_bytes)?;
    let engine = Engine::new(&deterministic_wasmi_config());
    let module = Module::new(&engine, module_bytes).map_err(WasiRunError::Engine)?;
    let mut linker = Linker::<Preview1Host>::new(&engine);
    define_preview1(&mut linker).map_err(WasiRunError::Engine)?;
    define_patina_sdk(&mut linker).map_err(WasiRunError::Engine)?;
    let mut store = Store::new(&engine, host);
    store.set_fuel(fuel).map_err(WasiRunError::Engine)?;
    let store_limits = build_store_limits(store.data().limits.max_memory_pages);
    store.data_mut().store_limits = store_limits;
    store.limiter(|host| &mut host.store_limits);
    let run_result = (|| {
        // wasmi 1.1 merged the two-step `instantiate(..).start(..)` (InstancePre
        // then run the module's `start` section) into a single call that both
        // instantiates and runs the start function. Observable behavior is
        // unchanged: the guest's `start` section still runs before `_start`.
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(WasiRunError::Engine)?;
        let start = instance
            .get_typed_func::<(), ()>(&store, "_start")
            .map_err(WasiRunError::Engine)?;
        match start.call(&mut store, ()) {
            Ok(()) => Ok(0),
            Err(error) => error
                .i32_exit_status()
                .ok_or_else(|| WasiRunError::Engine(error)),
        }
    })();
    let fuel_consumed = fuel.saturating_sub(
        store
            .get_fuel()
            .expect("fuel metering was enabled on the Wasmi engine"),
    );
    let hostcalls = store.data().hostcalls.clone();
    let output_result = store
        .into_data()
        .finish_with_output()
        .map_err(WasiRunError::Host);
    match (run_result, output_result) {
        (Ok(exit_code), Ok((stdout, stderr))) => {
            check_depth_available(fuel_consumed)?;
            Ok(WasiExecution {
                exit_code,
                stdout,
                stderr,
                fuel_consumed,
                hostcalls,
            })
        }
        (Err(run), Ok((stdout, stderr))) if stdout.is_empty() && stderr.is_empty() => Err(run),
        (Err(run), Ok((stdout, stderr))) => Err(WasiRunError::RunWithOutput {
            run: Box::new(run),
            stdout,
            stderr,
        }),
        (Ok(_), Err(finalize)) => Err(finalize),
        (Err(run), Err(finalize)) => Err(WasiRunError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

fn define_preview1(linker: &mut Linker<Preview1Host>) -> Result<(), WasmiError> {
    const MODULE: &str = "wasi_snapshot_preview1";
    linker.func_wrap(
        MODULE,
        "args_sizes_get",
        |mut caller: Caller<'_, Preview1Host>, count: i32, size: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("args_sizes_get");
            let values = caller.data().arguments.clone();
            write_u32(&mut caller, count, values.len() as u32)?;
            write_u32(&mut caller, size, string_buffer_size(&values)?)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "args_get",
        |mut caller: Caller<'_, Preview1Host>,
         pointers: i32,
         buffer: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("args_get");
            let values = caller.data().arguments.clone();
            write_string_vector(&mut caller, pointers, buffer, &values)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "environ_sizes_get",
        |mut caller: Caller<'_, Preview1Host>, count: i32, size: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("environ_sizes_get");
            let values = environment_strings(caller.data());
            write_u32(&mut caller, count, values.len() as u32)?;
            write_u32(&mut caller, size, string_buffer_size(&values)?)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "environ_get",
        |mut caller: Caller<'_, Preview1Host>,
         pointers: i32,
         buffer: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("environ_get");
            let values = environment_strings(caller.data());
            write_string_vector(&mut caller, pointers, buffer, &values)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "random_get",
        |mut caller: Caller<'_, Preview1Host>,
         pointer: i32,
         length: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("random_get");
            let length = offset(length)?;
            let mut bytes = vec![0; length];
            caller
                .data_mut()
                .random_get(&mut bytes)
                .map_err(host_error)?;
            memory(&caller)?.write(&mut caller, offset(pointer)?, &bytes)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "clock_res_get",
        |mut caller: Caller<'_, Preview1Host>,
         clock: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("clock_res_get");
            let Some(clock) = wasi_clock(clock) else {
                return Ok(28);
            };
            let resolution = caller.data().clock_res_get(clock);
            write_u64(&mut caller, result, resolution)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "clock_time_get",
        |mut caller: Caller<'_, Preview1Host>,
         clock: i32,
         _precision: i64,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("clock_time_get");
            let Some(clock) = wasi_clock(clock) else {
                return Ok(28);
            };
            let now = caller
                .data_mut()
                .clock_time_get(clock)
                .map_err(host_error)?;
            write_u64(&mut caller, result, now)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_advise",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         offset: i64,
         len: i64,
         advice: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_advise");
            if !(0..=5).contains(&advice) {
                return Ok(WASI_ERRNO_INVAL);
            }
            if (offset as u64).checked_add(len as u64).is_none() {
                return Ok(WASI_ERRNO_INVAL);
            }
            match wasi_call(caller.data().fd_advise(fd as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_allocate",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         offset: i64,
         len: i64|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_allocate");
            match wasi_call(
                caller
                    .data_mut()
                    .fd_allocate(fd as u32, offset as u64, len as u64),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_close",
        |mut caller: Caller<'_, Preview1Host>, fd: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_close");
            match wasi_call(caller.data_mut().fd_close(fd as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_fdstat_get",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, result: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_fdstat_get");
            let fd = fd as u32;
            let (filetype, flags, rights, inheriting) = match fd {
                0 => (WASI_FILETYPE_CHARACTER_DEVICE, 0, WASI_RIGHT_FD_READ, 0),
                1 | 2 => (WASI_FILETYPE_CHARACTER_DEVICE, 0, WASI_RIGHT_FD_WRITE, 0),
                _ => match caller.data().descriptors.get(&fd) {
                    Some(WasiDescriptor::File {
                        rights,
                        inheriting,
                        flags,
                        ..
                    }) => (WASI_FILETYPE_REGULAR_FILE, *flags, *rights, *inheriting),
                    Some(WasiDescriptor::Directory {
                        rights, inheriting, ..
                    }) => (WASI_FILETYPE_DIRECTORY, 0, *rights, *inheriting),
                    Some(WasiDescriptor::Datagram {
                        rights, inheriting, ..
                    }) => (WASI_FILETYPE_SOCKET_DGRAM, 0, *rights, *inheriting),
                    None => return Ok(WASI_ERRNO_BADF),
                },
            };
            let mut stat = [0u8; 24];
            stat[0] = filetype;
            stat[2..4].copy_from_slice(&flags.to_le_bytes());
            stat[8..16].copy_from_slice(&rights.to_le_bytes());
            stat[16..24].copy_from_slice(&inheriting.to_le_bytes());
            memory(&caller)?.write(&mut caller, offset(result)?, &stat)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_fdstat_set_flags",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, fdflags: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_fdstat_set_flags");
            let Ok(fdflags) = u16::try_from(fdflags) else {
                return Ok(WASI_ERRNO_INVAL);
            };
            match wasi_call(caller.data_mut().fd_fdstat_set_flags(fd as u32, fdflags))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_fdstat_set_rights",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         rights: i64,
         inheriting: i64|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_fdstat_set_rights");
            match wasi_call(caller.data_mut().fd_fdstat_set_rights(
                fd as u32,
                rights as u64,
                inheriting as u64,
            ))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_filestat_set_size",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, len: i64| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_filestat_set_size");
            match wasi_call(
                caller
                    .data_mut()
                    .fd_filestat_set_size(fd as u32, len as u64),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_filestat_set_times",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         atime_nanos: i64,
         mtime_nanos: i64,
         fst_flags: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_filestat_set_times");
            let Ok(fst_flags) = u16::try_from(fst_flags) else {
                return Ok(WASI_ERRNO_INVAL);
            };
            let (atime_nanos, mtime_nanos) = match caller.data_mut().filestat_set_times_values(
                atime_nanos as u64,
                mtime_nanos as u64,
                fst_flags,
            ) {
                Ok(values) => values,
                Err(WasiHostError::InvalidInput) => return Ok(WASI_ERRNO_INVAL),
                Err(error) => return Err(host_error(error)),
            };
            match wasi_call(caller.data_mut().fd_filestat_set_times(
                fd as u32,
                atime_nanos,
                mtime_nanos,
            ))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_filestat_get",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, result: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_filestat_get");
            let fd = fd as u32;
            let (metadata, filetype) = match fd {
                0..=2 => (
                    FsMetadata {
                        kind: FsEntryKind::File,
                        len: 0,
                        ino: SYNTHETIC_STDIO_INO_BASE + u64::from(fd),
                        nlink: 1,
                        atime_nanos: 0,
                        mtime_nanos: 0,
                    },
                    WASI_FILETYPE_CHARACTER_DEVICE,
                ),
                _ if matches!(
                    caller.data().descriptors.get(&fd),
                    Some(WasiDescriptor::Datagram { .. })
                ) =>
                {
                    (
                        FsMetadata {
                            kind: FsEntryKind::File,
                            len: 0,
                            ino: SYNTHETIC_DATAGRAM_INO_BASE + u64::from(fd),
                            nlink: 1,
                            atime_nanos: 0,
                            mtime_nanos: 0,
                        },
                        WASI_FILETYPE_SOCKET_DGRAM,
                    )
                }
                _ => match wasi_call(caller.data_mut().fd_metadata(fd))? {
                    Ok((metadata, _path)) => {
                        let filetype = wasi_filetype(metadata.kind);
                        (metadata, filetype)
                    }
                    Err(errno) => return Ok(errno),
                },
            };
            write_filestat(&mut caller, result, metadata, filetype)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_prestat_get",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, result: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_prestat_get");
            match caller.data().descriptors.get(&(fd as u32)) {
                Some(WasiDescriptor::Directory {
                    path,
                    preopen: true,
                    ..
                }) => {
                    let mut prestat = [0u8; 8];
                    prestat[4..8].copy_from_slice(&(path.len() as u32).to_le_bytes());
                    memory(&caller)?.write(&mut caller, offset(result)?, &prestat)?;
                    Ok(WASI_ERRNO_SUCCESS)
                }
                _ => Ok(WASI_ERRNO_BADF),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_prestat_dir_name",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         result: i32,
         length: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_prestat_dir_name");
            let name = match caller.data().descriptors.get(&(fd as u32)) {
                Some(WasiDescriptor::Directory {
                    path,
                    preopen: true,
                    ..
                }) => path.clone(),
                _ => return Ok(WASI_ERRNO_BADF),
            };
            if offset(length)? < name.len() {
                return Ok(WASI_ERRNO_INVAL);
            }
            memory(&caller)?.write(&mut caller, offset(result)?, name.as_bytes())?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_read",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         read: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_read");
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let max_len = vectors.iter().try_fold(0usize, |total, (_, length)| {
                total
                    .checked_add(*length)
                    .ok_or_else(|| WasmiError::new("WASI read length overflow"))
            })?;
            let bytes = match wasi_call(caller.data_mut().fd_read(fd as u32, max_len))? {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno),
            };
            let memory = memory(&caller)?;
            let mut cursor = 0usize;
            for (pointer, length) in vectors {
                let end = cursor.saturating_add(length).min(bytes.len());
                memory.write(&mut caller, pointer, &bytes[cursor..end])?;
                cursor = end;
                if cursor == bytes.len() {
                    break;
                }
            }
            write_u32(&mut caller, read, bytes.len() as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_pread",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         file_offset: i64,
         read: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_pread");
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let max_len = vectors.iter().try_fold(0usize, |total, (_, length)| {
                total
                    .checked_add(*length)
                    .ok_or_else(|| WasmiError::new("WASI pread length overflow"))
            })?;
            let bytes = match wasi_call(caller.data_mut().fd_pread(
                fd as u32,
                max_len,
                file_offset as u64,
            ))? {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno),
            };
            let memory = memory(&caller)?;
            let mut cursor = 0usize;
            for (pointer, length) in vectors {
                let end = cursor.saturating_add(length).min(bytes.len());
                memory.write(&mut caller, pointer, &bytes[cursor..end])?;
                cursor = end;
                if cursor == bytes.len() {
                    break;
                }
            }
            write_u32(&mut caller, read, bytes.len() as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_readdir",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         buffer: i32,
         buffer_len: i32,
         cookie: i64,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_readdir");
            let path = match caller.data().descriptors.get(&(fd as u32)) {
                Some(WasiDescriptor::Directory { path, .. }) => path.clone(),
                _ => return Ok(WASI_ERRNO_BADF),
            };
            let entries = match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_read_directory(&path)
                    .map_err(Into::into),
            )? {
                Ok(entries) => entries,
                Err(errno) => return Ok(errno),
            };
            let start = usize::try_from(cookie)
                .map_err(|_| WasmiError::new("negative WASI directory cookie"))?;
            let mut encoded = Vec::new();
            for (index, entry) in entries.iter().enumerate().skip(start) {
                let entry_path = if path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{path}/{}", entry.name)
                };
                let metadata = match wasi_call(
                    caller
                        .data_mut()
                        .context
                        .fs_metadata(&entry_path)
                        .map_err(Into::into),
                )? {
                    Ok(metadata) => metadata,
                    Err(errno) => return Ok(errno),
                };
                let mut dirent = [0u8; 24];
                dirent[0..8].copy_from_slice(&((index + 1) as u64).to_le_bytes());
                dirent[8..16].copy_from_slice(&metadata.ino.to_le_bytes());
                dirent[16..20].copy_from_slice(&(entry.name.len() as u32).to_le_bytes());
                dirent[20] = wasi_filetype(metadata.kind);
                encoded.extend_from_slice(&dirent);
                encoded.extend_from_slice(entry.name.as_bytes());
            }
            let written = encoded.len().min(offset(buffer_len)?);
            memory(&caller)?.write(&mut caller, offset(buffer)?, &encoded[..written])?;
            write_u32(&mut caller, result, written as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_renumber",
        |mut caller: Caller<'_, Preview1Host>, from: i32, to: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_renumber");
            match wasi_call(caller.data_mut().fd_renumber(from as u32, to as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_datasync",
        |mut caller: Caller<'_, Preview1Host>, fd: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_datasync");
            match wasi_call(caller.data_mut().fd_sync(fd as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_sync",
        |mut caller: Caller<'_, Preview1Host>, fd: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_sync");
            match wasi_call(caller.data_mut().fd_sync(fd as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_seek",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         delta: i64,
         whence: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_seek");
            let whence = match whence {
                0 => SeekWhence::Start,
                1 => SeekWhence::Current,
                2 => SeekWhence::End,
                _ => return Ok(WASI_ERRNO_INVAL),
            };
            match wasi_call(caller.data_mut().fd_seek(fd as u32, delta, whence))? {
                Ok(position) => {
                    write_u64(&mut caller, result, position)?;
                    Ok(WASI_ERRNO_SUCCESS)
                }
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_tell",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, result: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_tell");
            match wasi_call(caller.data_mut().fd_seek(fd as u32, 0, SeekWhence::Current))? {
                Ok(position) => {
                    write_u64(&mut caller, result, position)?;
                    Ok(WASI_ERRNO_SUCCESS)
                }
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_create_directory",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         path: i32,
         path_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_create_directory");
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            let path = match wasi_call(caller.data().resolve_path(fd as u32, &bytes))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            if let Err(errno) = wasi_call(caller.data().ensure_writable(&path))? {
                return Ok(errno);
            }
            match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_create_directory(&path)
                    .map_err(Into::into),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_filestat_get",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         flags: i32,
         path: i32,
         path_len: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_filestat_get");
            let Ok(flags) = u32::try_from(flags) else {
                return Ok(WASI_ERRNO_INVAL);
            };
            if flags & !1 != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            let path = match wasi_call(caller.data_mut().resolve_path_with_terminal_follow(
                fd as u32,
                &bytes,
                flags & 1 != 0,
                false,
            ))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            let metadata = match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_metadata(&path)
                    .map_err(Into::into),
            )? {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(errno),
            };
            write_filestat(&mut caller, result, metadata, wasi_filetype(metadata.kind))?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_filestat_set_times",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         flags: i32,
         path: i32,
         path_len: i32,
         atime_nanos: i64,
         mtime_nanos: i64,
         fst_flags: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_filestat_set_times");
            let (Ok(flags), Ok(fst_flags)) = (u32::try_from(flags), u16::try_from(fst_flags))
            else {
                return Ok(WASI_ERRNO_INVAL);
            };
            if flags & !1 != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let (atime_nanos, mtime_nanos) = match caller.data_mut().filestat_set_times_values(
                atime_nanos as u64,
                mtime_nanos as u64,
                fst_flags,
            ) {
                Ok(values) => values,
                Err(WasiHostError::InvalidInput) => return Ok(WASI_ERRNO_INVAL),
                Err(error) => return Err(host_error(error)),
            };
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            match wasi_call(caller.data_mut().path_filestat_set_times(
                fd as u32,
                &bytes,
                flags & 1 != 0,
                atime_nanos,
                mtime_nanos,
            ))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_open",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         directory_flags: i32,
         path: i32,
         path_len: i32,
         oflags: i32,
         rights: i64,
         inheriting: i64,
         fdflags: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_open");
            let (Ok(directory_flags), Ok(oflags), Ok(fdflags)) = (
                u32::try_from(directory_flags),
                u16::try_from(oflags),
                u16::try_from(fdflags),
            ) else {
                return Ok(WASI_ERRNO_INVAL);
            };
            if directory_flags & !1 != 0
                || oflags
                    & !(WASI_OFLAG_CREATE
                        | WASI_OFLAG_DIRECTORY
                        | WASI_OFLAG_EXCLUSIVE
                        | WASI_OFLAG_TRUNCATE)
                    != 0
                || fdflags & !WASI_FDFLAGS_ALL != 0
            {
                return Ok(WASI_ERRNO_INVAL);
            }
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            match wasi_call(caller.data_mut().path_open(
                fd as u32,
                &bytes,
                WasiPathOpen {
                    oflags,
                    rights: rights as u64,
                    inheriting: inheriting as u64,
                    fdflags,
                    follow_symlink: directory_flags & 1 != 0,
                },
            ))? {
                Ok(opened) => {
                    write_u32(&mut caller, result, opened)?;
                    Ok(WASI_ERRNO_SUCCESS)
                }
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_remove_directory",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         path: i32,
         path_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_remove_directory");
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            let path = match wasi_call(caller.data().resolve_path(fd as u32, &bytes))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            if let Err(errno) = wasi_call(caller.data().ensure_writable(&path))? {
                return Ok(errno);
            }
            match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_remove_directory(&path)
                    .map_err(Into::into),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_rename",
        |mut caller: Caller<'_, Preview1Host>,
         from_fd: i32,
         from: i32,
         from_len: i32,
         to_fd: i32,
         to: i32,
         to_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_rename");
            let from_bytes = read_guest_bytes(&caller, from, from_len)?;
            let to_bytes = read_guest_bytes(&caller, to, to_len)?;
            let from = match wasi_call(caller.data().resolve_path(from_fd as u32, &from_bytes))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            let to = match wasi_call(caller.data().resolve_path(to_fd as u32, &to_bytes))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            if let Err(errno) = wasi_call(caller.data().ensure_writable(&from))? {
                return Ok(errno);
            }
            if let Err(errno) = wasi_call(caller.data().ensure_writable(&to))? {
                return Ok(errno);
            }
            match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_rename(&from, &to)
                    .map_err(Into::into),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_link",
        |mut caller: Caller<'_, Preview1Host>,
         old_fd: i32,
         old_flags: i32,
         old_path: i32,
         old_path_len: i32,
         new_fd: i32,
         new_path: i32,
         new_path_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_link");
            let Ok(old_flags) = u32::try_from(old_flags) else {
                return Ok(WASI_ERRNO_INVAL);
            };
            if old_flags & !1 != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let old_path = read_guest_bytes(&caller, old_path, old_path_len)?;
            let new_path = read_guest_bytes(&caller, new_path, new_path_len)?;
            match wasi_call(caller.data_mut().path_link(
                old_fd as u32,
                &old_path,
                new_fd as u32,
                &new_path,
            ))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_symlink",
        |mut caller: Caller<'_, Preview1Host>,
         target: i32,
         target_len: i32,
         fd: i32,
         link_path: i32,
         link_path_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_symlink");
            let target = read_guest_bytes(&caller, target, target_len)?;
            let link_path = read_guest_bytes(&caller, link_path, link_path_len)?;
            match wasi_call(
                caller
                    .data_mut()
                    .path_symlink(&target, fd as u32, &link_path),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_readlink",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         path: i32,
         path_len: i32,
         buffer: i32,
         buffer_len: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_readlink");
            let path = read_guest_bytes(&caller, path, path_len)?;
            let target = match wasi_call(caller.data_mut().path_readlink(fd as u32, &path))? {
                Ok(target) => target,
                Err(errno) => return Ok(errno),
            };
            let copied = target.len().min(offset(buffer_len)?);
            memory(&caller)?.write(&mut caller, offset(buffer)?, &target.as_bytes()[..copied])?;
            write_u32(&mut caller, result, copied as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "path_unlink_file",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         path: i32,
         path_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("path_unlink_file");
            let bytes = read_guest_bytes(&caller, path, path_len)?;
            let path = match wasi_call(caller.data().resolve_path(fd as u32, &bytes))? {
                Ok(path) => path,
                Err(errno) => return Ok(errno),
            };
            if let Err(errno) = wasi_call(caller.data().ensure_writable(&path))? {
                return Ok(errno);
            }
            match wasi_call(
                caller
                    .data_mut()
                    .context
                    .fs_remove_file(&path)
                    .map_err(Into::into),
            )? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_write",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         written: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_write");
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let memory = memory(&caller)?;
            let mut buffers = Vec::with_capacity(vectors.len());
            for (pointer, length) in vectors {
                let mut buffer = vec![0; length];
                memory.read(&caller, pointer, &mut buffer)?;
                buffers.push(buffer);
            }
            let slices = buffers.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let count = match wasi_call(caller.data_mut().fd_write(fd as u32, &slices))? {
                Ok(count) => count,
                Err(errno) => return Ok(errno),
            };
            write_u32(&mut caller, written, count as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "fd_pwrite",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         file_offset: i64,
         written: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("fd_pwrite");
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let memory = memory(&caller)?;
            let mut buffers = Vec::with_capacity(vectors.len());
            for (pointer, length) in vectors {
                let mut buffer = vec![0; length];
                memory.read(&caller, pointer, &mut buffer)?;
                buffers.push(buffer);
            }
            let slices = buffers.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let count = match wasi_call(caller.data_mut().fd_pwrite(
                fd as u32,
                &slices,
                file_offset as u64,
            ))? {
                Ok(count) => count,
                Err(errno) => return Ok(errno),
            };
            write_u32(&mut caller, written, count as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sock_accept",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         _flags: i32,
         _result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sock_accept");
            Ok(caller.data().sock_accept(fd as u32, 0))
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sock_recv",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         flags: i32,
         read: i32,
         result_flags: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sock_recv");
            if flags & !0x3 != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let capacity = vectors.iter().map(|(_, length)| length).sum::<usize>();
            let bytes = match wasi_call(caller.data_mut().sock_recv(fd as u32))? {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return Ok(WASI_ERRNO_AGAIN),
                Err(errno) => return Ok(errno),
            };
            let copied = bytes.len().min(capacity);
            let memory = memory(&caller)?;
            let mut source = 0usize;
            for (pointer, length) in vectors {
                let end = source.saturating_add(length).min(copied);
                memory.write(&mut caller, pointer, &bytes[source..end])?;
                source = end;
                if source == copied {
                    break;
                }
            }
            write_u32(&mut caller, read, copied as u32)?;
            write_u16(&mut caller, result_flags, u16::from(bytes.len() > capacity))?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sock_send",
        |mut caller: Caller<'_, Preview1Host>,
         fd: i32,
         iovecs: i32,
         count: i32,
         flags: i32,
         written: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sock_send");
            if flags != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let vectors = read_iovecs(&caller, iovecs, count)?;
            let memory = memory(&caller)?;
            let capacity = vectors.iter().map(|(_, length)| length).sum::<usize>();
            let mut bytes = Vec::with_capacity(capacity);
            for (pointer, length) in vectors {
                let start = bytes.len();
                bytes.resize(start + length, 0);
                memory.read(&caller, pointer, &mut bytes[start..])?;
            }
            match wasi_call(caller.data_mut().sock_send(fd as u32, &bytes))? {
                Ok(count) => {
                    write_u32(&mut caller, written, count as u32)?;
                    Ok(WASI_ERRNO_SUCCESS)
                }
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sock_shutdown",
        |mut caller: Caller<'_, Preview1Host>, fd: i32, flags: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sock_shutdown");
            if flags == 0 || flags & !0x3 != 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            match wasi_call(caller.data_mut().sock_shutdown(fd as u32))? {
                Ok(()) => Ok(WASI_ERRNO_SUCCESS),
                Err(errno) => Ok(errno),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "poll_oneoff",
        |mut caller: Caller<'_, Preview1Host>,
         input: i32,
         output: i32,
         count: i32,
         result: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("poll_oneoff");
            let count = offset(count)?;
            if count == 0 {
                return Ok(WASI_ERRNO_INVAL);
            }
            let max_iovecs = caller.data().limits.max_iovecs;
            if count > max_iovecs {
                return Err(WasmiError::new(format!(
                    "WASI poll exceeds the {max_iovecs}-subscription limit"
                )));
            }
            let memory = memory(&caller)?;
            let base = offset(input)?;
            let mut subscriptions = Vec::with_capacity(count);
            for index in 0..count {
                let subscription = base
                    .checked_add(index * 48)
                    .ok_or_else(|| WasmiError::new("WASI subscription address overflow"))?;
                let userdata = read_u64(&caller, memory, subscription)?;
                let mut tag = [0u8; 1];
                memory.read(&caller, subscription + 8, &mut tag)?;
                subscriptions.push(match tag[0] {
                    0 => {
                        let clock =
                            wasi_clock(read_u32(&caller, memory, subscription + 16)? as i32)
                                .ok_or_else(|| WasmiError::new("unsupported WASI poll clock"))?;
                        WasiSubscription::Clock {
                            userdata,
                            clock,
                            deadline: read_u64(&caller, memory, subscription + 24)?,
                            absolute: read_u16(&caller, memory, subscription + 40)? & 1 != 0,
                        }
                    }
                    1 => WasiSubscription::FdRead {
                        userdata,
                        fd: read_u32(&caller, memory, subscription + 16)?,
                    },
                    2 => WasiSubscription::FdWrite {
                        userdata,
                        fd: read_u32(&caller, memory, subscription + 16)?,
                    },
                    _ => return Ok(WASI_ERRNO_INVAL),
                });
            }
            let events = match wasi_call(caller.data_mut().poll(&subscriptions))? {
                Ok(events) => events,
                Err(errno) => return Ok(errno),
            };
            let output = offset(output)?;
            for (index, (userdata, event_type, bytes)) in events.iter().enumerate() {
                let pointer = output
                    .checked_add(index * 32)
                    .ok_or_else(|| WasmiError::new("WASI event address overflow"))?;
                let mut event = [0u8; 32];
                event[0..8].copy_from_slice(&userdata.to_le_bytes());
                event[10] = *event_type;
                event[16..24].copy_from_slice(&bytes.to_le_bytes());
                memory.write(&mut caller, pointer, &event)?;
            }
            write_u32(&mut caller, result, events.len() as u32)?;
            Ok(WASI_ERRNO_SUCCESS)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sched_yield",
        |mut caller: Caller<'_, Preview1Host>| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sched_yield");
            Ok(caller.data().sched_yield())
        },
    )?;
    linker.func_wrap(
        MODULE,
        "proc_raise",
        |mut caller: Caller<'_, Preview1Host>, signal: i32| -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("proc_raise");
            Ok(caller.data().proc_raise(signal as u32))
        },
    )?;
    linker.func_wrap(
        MODULE,
        "proc_exit",
        |mut caller: Caller<'_, Preview1Host>, code: i32| -> Result<(), WasmiError> {
            caller.data_mut().count_hostcall("proc_exit");
            Err(WasmiError::i32_exit(code))
        },
    )?;
    Ok(())
}

/// Read a cooperative-SUT label/site string from guest linear memory. Labels are
/// tiny, but they still ride the standard `max_io_bytes` ceiling through
/// [`read_guest_bytes`], and non-UTF-8 is a hard error rather than lossy text so
/// a mislowered call fails closed.
fn read_patina_label(
    caller: &Caller<'_, Preview1Host>,
    pointer: i32,
    length: i32,
) -> Result<String, WasmiError> {
    let bytes = read_guest_bytes(caller, pointer, length)?;
    String::from_utf8(bytes).map_err(|_| WasmiError::new("patina_sdk label is not valid UTF-8"))
}

/// Emit a fatal cooperative-SUT marker and return a trap that terminates the
/// guest with a nonzero exit. Mirrors the native shim's
/// `abort_with_buggify_marker`: the marker is a harness diagnostic, so it goes to
/// the real process stderr (like `PATINA_SDK_REPORT`), where the campaign
/// classifier greps for it — not into the captured guest stream, whose surfacing
/// depends on the run's error path.
fn patina_buggify_fatal(marker: &str, label: &str) -> WasmiError {
    eprintln!("{marker} label={label}");
    WasmiError::new(format!("{marker} label={label}"))
}

/// Shared body for the site-evaluating `patina_sdk` imports: read the label and
/// call site from guest memory, invoke the context method, and map the outcome to
/// `1`=fire / `0`=no, trapping on a fatal always-violation or duplicate label.
/// The runtime side is the SAME [`Context`] buggify subsystem the native shim
/// drives, so activation, PRF firing, the cutoff, and the diagnostics report are
/// reused rather than reimplemented.
fn patina_sdk_site(
    mut caller: Caller<'_, Preview1Host>,
    label_ptr: i32,
    label_len: i32,
    site_ptr: i32,
    site_len: i32,
    invoke: impl FnOnce(&mut Context, &str, &str) -> Result<SiteOutcome, RuntimeError>,
) -> Result<i32, WasmiError> {
    let label = read_patina_label(&caller, label_ptr, label_len)?;
    let site = read_patina_label(&caller, site_ptr, site_len)?;
    let outcome = invoke(&mut caller.data_mut().context, &label, &site)
        .map_err(|error| WasmiError::new(error.to_string()))?;
    match outcome {
        SiteOutcome::Fire => Ok(1),
        SiteOutcome::Ok => Ok(0),
        SiteOutcome::AlwaysViolation => {
            Err(patina_buggify_fatal("PATINA_ALWAYS_VIOLATION", &label))
        }
        SiteOutcome::DuplicateLabel => Err(patina_buggify_fatal(
            "PATINA_BUGGIFY_DUPLICATE_LABEL",
            &label,
        )),
    }
}

/// Define the `patina_sdk` import module: the WASI-side mirror of the native
/// shim's cooperative-SUT C ABI. Every function is backed by the same
/// [`Context`] buggify subsystem, so a guest compiled with `cfg(patina)` sees
/// identical activation/firing/coverage semantics on wasip1 and native. The
/// module is defined unconditionally (like the preview1 imports): when buggify is
/// disabled the sites register lazily and stay inert, exactly as native, so a
/// `patina_sdk`-importing guest run without `--buggify` behaves as all-no-op.
fn define_patina_sdk(linker: &mut Linker<Preview1Host>) -> Result<(), WasmiError> {
    const MODULE: &str = "patina_sdk";
    linker.func_wrap(
        MODULE,
        "is_simulated",
        // The deterministic context is always installed for a WASI run, so this is
        // authoritative `true`; a foreign runtime never resolves the import.
        |mut caller: Caller<'_, Preview1Host>| -> i32 {
            caller.data_mut().count_hostcall("is_simulated");
            1
        },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32,
         prob_permille: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("buggify");
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| {
                    let prob = (prob_permille >= 0).then(|| prob_permille.clamp(0, 1000) as u16);
                    ctx.buggify_evaluate(l, s, prob)
                },
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify_delay",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("buggify_delay");
            patina_sdk_site(caller, label, label_len, site, site_len, |ctx, l, s| {
                ctx.buggify_delay(l, s)
            })
        },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify_knob",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32,
         default: i64,
         lo: i64,
         hi: i64|
         -> Result<i64, WasmiError> {
            caller.data_mut().count_hostcall("buggify_knob");
            let label = read_patina_label(&caller, label, label_len)?;
            let site = read_patina_label(&caller, site, site_len)?;
            match caller
                .data_mut()
                .context
                .buggify_knob(&label, &site, default, lo, hi)
                .map_err(|error| WasmiError::new(error.to_string()))?
            {
                Ok(value) => Ok(value),
                Err(()) => Err(patina_buggify_fatal(
                    "PATINA_BUGGIFY_DUPLICATE_LABEL",
                    &label,
                )),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "always",
        |mut caller: Caller<'_, Preview1Host>,
         condition: i32,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("always");
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| ctx.always_check(l, s, condition != 0),
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sometimes",
        |mut caller: Caller<'_, Preview1Host>,
         condition: i32,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("sometimes");
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| ctx.sometimes_check(l, s, condition != 0),
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "reachable",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("reachable");
            patina_sdk_site(caller, label, label_len, site, site_len, |ctx, l, s| {
                ctx.reachable_mark(l, s)
            })
        },
    )?;
    linker.func_wrap(
        MODULE,
        "rng",
        |mut caller: Caller<'_, Preview1Host>| -> u64 {
            caller.data_mut().count_hostcall("rng");
            caller.data_mut().context.buggify_rng()
        },
    )?;
    linker.func_wrap(
        MODULE,
        "lifecycle_setup_complete",
        |mut caller: Caller<'_, Preview1Host>| -> i32 {
            caller.data_mut().count_hostcall("lifecycle_setup_complete");
            let host = caller.data_mut();
            host.context.lifecycle_setup_complete();
            // Mirror the native shim: the lifecycle marker rides the captured guest
            // stderr stream, flushed to the real stderr at run end.
            host.stderr
                .extend_from_slice(b"PATINA_LIFECYCLE setup_complete\n");
            0
        },
    )?;
    linker.func_wrap(
        MODULE,
        "lifecycle_event",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32|
         -> Result<i32, WasmiError> {
            caller.data_mut().count_hostcall("lifecycle_event");
            let label = read_patina_label(&caller, label, label_len)?;
            let line = format!("PATINA_LIFECYCLE_EVENT label={label}\n");
            caller.data_mut().stderr.extend_from_slice(line.as_bytes());
            Ok(0)
        },
    )?;
    Ok(())
}

fn read_guest_bytes(
    caller: &Caller<'_, Preview1Host>,
    pointer: i32,
    length: i32,
) -> Result<Vec<u8>, WasmiError> {
    let length = offset(length)?;
    let max_io_bytes = caller.data().limits.max_io_bytes;
    if length > max_io_bytes {
        return Err(WasmiError::new(format!(
            "WASI input exceeds the {max_io_bytes}-byte operation limit"
        )));
    }
    let mut bytes = vec![0; length];
    memory(caller)?.read(caller, offset(pointer)?, &mut bytes)?;
    Ok(bytes)
}

fn read_iovecs(
    caller: &Caller<'_, Preview1Host>,
    iovecs: i32,
    count: i32,
) -> Result<Vec<(usize, usize)>, WasmiError> {
    let count = offset(count)?;
    let max_iovecs = caller.data().limits.max_iovecs;
    let max_io_bytes = caller.data().limits.max_io_bytes;
    if count > max_iovecs {
        return Err(WasmiError::new(format!(
            "WASI operation exceeds the {max_iovecs}-iovec limit"
        )));
    }
    let memory = memory(caller)?;
    let base = offset(iovecs)?;
    let mut vectors = Vec::with_capacity(count);
    let mut total = 0usize;
    for index in 0..count {
        let descriptor = base
            .checked_add(index * 8)
            .ok_or_else(|| WasmiError::new("WASI iovec address overflow"))?;
        let pointer = read_u32(caller, memory, descriptor)? as usize;
        let length = read_u32(caller, memory, descriptor + 4)? as usize;
        total = total
            .checked_add(length)
            .ok_or_else(|| WasmiError::new("WASI iovec length overflow"))?;
        if total > max_io_bytes {
            return Err(WasmiError::new(format!(
                "WASI operation exceeds the {max_io_bytes}-byte I/O limit"
            )));
        }
        vectors.push((pointer, length));
    }
    Ok(vectors)
}

fn write_filestat(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    metadata: FsMetadata,
    filetype: u8,
) -> Result<(), WasmiError> {
    let mut stat = [0u8; 64];
    stat[8..16].copy_from_slice(&metadata.ino.to_le_bytes());
    stat[16] = filetype;
    stat[24..32].copy_from_slice(&u64::from(metadata.nlink).to_le_bytes());
    stat[32..40].copy_from_slice(&metadata.len.to_le_bytes());
    stat[40..48].copy_from_slice(&metadata.atime_nanos.to_le_bytes());
    stat[48..56].copy_from_slice(&metadata.mtime_nanos.to_le_bytes());
    // Preview1Host has no separate ctime model, so mirror mtime into ctim.
    stat[56..64].copy_from_slice(&metadata.mtime_nanos.to_le_bytes());
    memory(caller)?.write(caller, offset(pointer)?, &stat)?;
    Ok(())
}

fn host_parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

fn wasi_filetype(kind: FsEntryKind) -> u8 {
    match kind {
        FsEntryKind::File => WASI_FILETYPE_REGULAR_FILE,
        FsEntryKind::Directory => WASI_FILETYPE_DIRECTORY,
        FsEntryKind::Symlink => WASI_FILETYPE_SYMBOLIC_LINK,
    }
}

fn wasi_call<T>(result: Result<T, WasiHostError>) -> Result<Result<T, i32>, WasmiError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(WasiHostError::Runtime(RuntimeError::Effect(error))) => {
            Ok(Err(effect_errno(error.code)))
        }
        Err(WasiHostError::DeniedFd(_)) => Ok(Err(WASI_ERRNO_BADF)),
        Err(WasiHostError::NotCapable(_)) => Ok(Err(WASI_ERRNO_NOTCAPABLE)),
        Err(WasiHostError::OutputSizeOverflow) => Ok(Err(WASI_ERRNO_OVERFLOW)),
        Err(WasiHostError::DescriptorExhausted) => Ok(Err(WASI_ERRNO_MFILE)),
        Err(WasiHostError::InvalidInput) => Ok(Err(WASI_ERRNO_INVAL)),
        Err(WasiHostError::Loop) => Ok(Err(WASI_ERRNO_LOOP)),
        Err(WasiHostError::ReadOnly) => Ok(Err(WASI_ERRNO_ROFS)),
        Err(WasiHostError::PathTooLong) => Ok(Err(WASI_ERRNO_NAMETOOLONG)),
        Err(error) => Err(host_error(error)),
    }
}

fn effect_errno(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::Denied => WASI_ERRNO_NOTCAPABLE,
        ErrorCode::InvalidInput => WASI_ERRNO_INVAL,
        ErrorCode::InvalidHandle => WASI_ERRNO_BADF,
        ErrorCode::MissingDriver => WASI_ERRNO_NOSYS,
        ErrorCode::NotFound => WASI_ERRNO_NOENT,
        ErrorCode::NotReadable | ErrorCode::NotWritable => WASI_ERRNO_BADF,
        ErrorCode::AlreadyExists | ErrorCode::AlreadyBound => WASI_ERRNO_EXIST,
        ErrorCode::IsDirectory => WASI_ERRNO_ISDIR,
        ErrorCode::NotDirectory => WASI_ERRNO_NOTDIR,
        ErrorCode::DirectoryNotEmpty => WASI_ERRNO_NOTEMPTY,
        ErrorCode::Io => WASI_ERRNO_IO,
        ErrorCode::NoSpace => WASI_ERRNO_NOSPC,
        ErrorCode::Interrupted => WASI_ERRNO_INTR,
        ErrorCode::Deadlock | ErrorCode::NoRoute | ErrorCode::InvalidState => WASI_ERRNO_IO,
        ErrorCode::ConnectionRefused => WASI_ERRNO_CONNREFUSED,
        ErrorCode::ConnectionReset => WASI_ERRNO_CONNRESET,
        ErrorCode::BrokenPipe => WASI_ERRNO_PIPE,
        ErrorCode::NotConnected => WASI_ERRNO_NOTCONN,
    }
}

fn environment_strings(host: &Preview1Host) -> Vec<String> {
    host.environment
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn string_buffer_size(values: &[String]) -> Result<u32, WasmiError> {
    values.iter().try_fold(0u32, |size, value| {
        size.checked_add(value.len() as u32 + 1)
            .ok_or_else(|| WasmiError::new("WASI string buffer size overflow"))
    })
}

fn write_string_vector(
    caller: &mut Caller<'_, Preview1Host>,
    pointers: i32,
    buffer: i32,
    values: &[String],
) -> Result<(), WasmiError> {
    let memory = memory(caller)?;
    let pointers = offset(pointers)?;
    let mut cursor = offset(buffer)?;
    for (index, value) in values.iter().enumerate() {
        let pointer_slot = pointers
            .checked_add(index * 4)
            .ok_or_else(|| WasmiError::new("WASI pointer table overflow"))?;
        memory.write(
            caller.as_context_mut(),
            pointer_slot,
            &(cursor as u32).to_le_bytes(),
        )?;
        memory.write(caller.as_context_mut(), cursor, value.as_bytes())?;
        cursor = cursor
            .checked_add(value.len())
            .ok_or_else(|| WasmiError::new("WASI string address overflow"))?;
        memory.write(caller.as_context_mut(), cursor, &[0])?;
        cursor += 1;
    }
    Ok(())
}

fn memory(caller: &Caller<'_, Preview1Host>) -> Result<Memory, WasmiError> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| WasmiError::new("WASI guest does not export memory"))
}

fn read_u32(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u32, WasmiError> {
    let mut bytes = [0; 4];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u16, WasmiError> {
    let mut bytes = [0; 2];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u64, WasmiError> {
    let mut bytes = [0; 8];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u16(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u16,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

fn write_u32(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u32,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

fn write_u64(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u64,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

fn offset(value: i32) -> Result<usize, WasmiError> {
    usize::try_from(value).map_err(|_| WasmiError::new("negative WASI guest pointer or length"))
}

fn wasi_clock(value: i32) -> Option<WasiClock> {
    match value {
        0 => Some(WasiClock::Realtime),
        1 => Some(WasiClock::Monotonic),
        _ => None,
    }
}

fn host_error(error: WasiHostError) -> WasmiError {
    WasmiError::new(error.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasiExit {
    pub code: u32,
}

#[derive(Debug)]
pub enum WasiRunError {
    Target(TargetError),
    Engine(WasmiError),
    Host(WasiHostError),
    /// Depth accounting (fuel / hostcall counters) did not produce data for a
    /// run that executed. Reported rather than papered over so "no depth data"
    /// can never be read as "zero depth".
    Depth(String),
    RunWithOutput {
        run: Box<WasiRunError>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    RunAndFinalize {
        run: Box<WasiRunError>,
        finalize: Box<WasiRunError>,
    },
}

impl fmt::Display for WasiRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(error) => error.fmt(f),
            Self::Engine(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
            Self::Depth(message) => f.write_str(message),
            Self::RunWithOutput {
                run,
                stdout,
                stderr,
            } => {
                write!(f, "{run}")?;
                if !stdout.is_empty() {
                    write!(f, "; stdout: {}", String::from_utf8_lossy(stdout))?;
                }
                if !stderr.is_empty() {
                    write!(f, "; stderr: {}", String::from_utf8_lossy(stderr))?;
                }
                Ok(())
            }
            Self::RunAndFinalize { run, finalize } => {
                write!(
                    f,
                    "WASI execution failed ({run}) and finalization failed ({finalize})"
                )
            }
        }
    }
}

impl std::error::Error for WasiRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Target(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::Host(error) => Some(error),
            Self::Depth(_) => None,
            Self::RunWithOutput { run, .. } => Some(run),
            Self::RunAndFinalize { run, .. } => Some(run),
        }
    }
}

#[derive(Debug)]
pub enum WasiHostError {
    Runtime(RuntimeError),
    DeniedFd(u32),
    NotCapable(u32),
    DescriptorInUse(u32),
    DescriptorExhausted,
    OutputSizeOverflow,
    InvalidInput,
    Loop,
    /// A mutation targeted a read-only preopened mount.
    ReadOnly,
    /// A guest-supplied path exceeded the configured maximum length.
    PathTooLong,
    /// A configured preopen overlaps an existing one (nested or duplicate).
    PreopenOverlap {
        existing: String,
        requested: String,
    },
    /// More preopens were configured than the resource limit allows.
    TooManyPreopens(usize),
    /// A configured preopen path was not a valid absolute path.
    InvalidPreopen(String),
    /// `--buggify-after-setup` was declared but the guest never called
    /// `patina_dst::lifecycle::setup_complete()` — a harness bug, not a silent
    /// no-fault run. Mirrors the native shim's `PATINA_BUGGIFY_SETUP_NEVER_CALLED`.
    BuggifySetupNeverCalled,
}

/// The stderr marker line for the `--buggify-after-setup` gate violation, shared
/// by the [`WasiHostError`] display and the host-side stderr emission so the
/// campaign classifier sees the same token the native shim emits.
const BUGGIFY_SETUP_NEVER_CALLED_MARKER: &str = "PATINA_BUGGIFY_SETUP_NEVER_CALLED --buggify-after-setup was declared but the guest never \
called patina_dst::lifecycle::setup_complete()";

impl fmt::Display for WasiHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::DeniedFd(fd) => write!(f, "WASI fd {fd} is not an allowed deterministic stream"),
            Self::NotCapable(fd) => write!(f, "WASI fd {fd} lacks the required capability"),
            Self::DescriptorInUse(fd) => write!(f, "WASI fd {fd} is already configured"),
            Self::DescriptorExhausted => f.write_str("WASI descriptor table exhausted"),
            Self::OutputSizeOverflow => f.write_str("WASI output size overflowed"),
            Self::InvalidInput => f.write_str("invalid WASI argument"),
            Self::Loop => f.write_str("WASI symlink resolution stopped at a symbolic link"),
            Self::ReadOnly => f.write_str("WASI mutation denied on a read-only preopened mount"),
            Self::PathTooLong => f.write_str("WASI path exceeds the configured maximum length"),
            Self::PreopenOverlap {
                existing,
                requested,
            } => write!(
                f,
                "WASI preopen {requested:?} overlaps the configured mount {existing:?}"
            ),
            Self::TooManyPreopens(limit) => {
                write!(f, "WASI preopens exceed the configured limit of {limit}")
            }
            Self::InvalidPreopen(message) => write!(f, "invalid WASI preopen: {message}"),
            Self::BuggifySetupNeverCalled => f.write_str(BUGGIFY_SETUP_NEVER_CALLED_MARKER),
        }
    }
}

impl std::error::Error for WasiHostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RuntimeError> for WasiHostError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::Operation;
    use patina_dst_runtime::RuntimeConfig;
    use tempfile::tempdir;

    use super::*;

    fn read_stdout_u64s(stdout: &[u8]) -> Vec<u64> {
        stdout
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    /// Encode one `patina_sites` record the way the SDK macro does, so the
    /// duplicate-label mapping below is gated on the real record layout.
    fn static_site_record(kind: u8, label: &str, site: &str) -> Vec<u8> {
        let mut record = PATINA_STATIC_SITE_MAGIC.to_vec();
        record.push(kind);
        record.push(0);
        record.extend_from_slice(&(label.len() as u32).to_le_bytes());
        record.extend_from_slice(&(site.len() as u32).to_le_bytes());
        assert_eq!(record.len(), PATINA_STATIC_SITE_HEADER_LEN);
        record.extend_from_slice(label.as_bytes());
        record.extend_from_slice(site.as_bytes());
        record
    }

    // A link-time site table that binds one label to two call sites is the same
    // fatal duplicate the evaluation path rejects, and must surface the SAME
    // named marker rather than a generic host configuration failure.
    #[test]
    fn wasm_static_site_duplicate_label_reports_the_duplicate_marker() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let mut payload = static_site_record(6, "dup", "src/main.rs:3");
        payload.extend(static_site_record(6, "dup", "src/main.rs:4"));
        let error = parse_wasm_static_site_payload(&mut context, &payload)
            .expect_err("a duplicate link-time label must fail closed");
        assert!(
            error
                .to_string()
                .contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=dup"),
            "expected the named duplicate marker, got: {error}"
        );
    }

    // The same table without a conflict declares the site without evaluating it.
    #[test]
    fn wasm_static_site_table_declares_without_registering() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let payload = static_site_record(6, "never", "src/main.rs:9");
        parse_wasm_static_site_payload(&mut context, &payload).unwrap();
        let diagnostics = context.buggify_diagnostics();
        assert_eq!(diagnostics.sites_registered, 0);
        assert_eq!(diagnostics.declared_sites.len(), 1);
        assert_eq!(diagnostics.declared_sites[0].label, "never");
    }

    fn exercise(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
        let mut random = vec![0; 16];
        host.random_get(&mut random)?;
        host.sleep_until(WasiClock::Monotonic, 25)?;
        assert_eq!(host.clock_time_get(WasiClock::Monotonic)?, 25);
        assert_eq!(host.fd_write(1, &[b"hello", b" wasi"])?, 10);
        Ok(random)
    }

    #[test]
    fn host_capture_is_explicit_and_fail_closed() {
        let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let mut host = Preview1Host::new(context)
            .with_argument("app.wasm")
            .with_environment("MODE", "test");
        exercise(&mut host).unwrap();
        assert_eq!(host.arguments(), ["app.wasm"]);
        assert_eq!(host.environment()["MODE"], "test");
        assert_eq!(host.stdout(), b"hello wasi");
        assert!(matches!(
            host.fd_write(3, &[b"host"]),
            Err(WasiHostError::DeniedFd(3))
        ));
        host.finish().unwrap();
    }

    #[test]
    fn positioned_io_allocation_and_advice_preserve_the_cursor() {
        let context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        let mut host = Preview1Host::new(context);
        let rights = WASI_RIGHT_FD_READ
            | WASI_RIGHT_FD_WRITE
            | WASI_RIGHT_FD_ADVISE
            | WASI_RIGHT_FD_ALLOCATE;
        let fd = host
            .path_open(
                3,
                b"value",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
        host.fd_advise(fd).unwrap();
        host.fd_allocate(fd, 8, 2).unwrap();
        assert_eq!(host.fd_metadata(fd).unwrap().0.len, 10);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
        assert_eq!(host.fd_pwrite(fd, &[b"X"], 1).unwrap(), 1);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
        assert_eq!(host.fd_pread(fd, 3, 0).unwrap(), b"aXc");
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
        host.fd_close(fd).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn fdstat_set_flags_controls_append_for_cursor_writes() {
        let context = Context::from_config(RuntimeConfig::seeded(4)).unwrap();
        let mut host = Preview1Host::new(context);
        let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
        let fd = host
            .path_open(
                3,
                b"value",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Start).unwrap(), 0);
        host.fd_fdstat_set_flags(fd, WASI_FDFLAG_APPEND).unwrap();
        assert!(matches!(
            host.descriptors.get(&fd),
            Some(WasiDescriptor::File { flags, .. }) if *flags == WASI_FDFLAG_APPEND
        ));
        assert_eq!(host.fd_write(fd, &[b"Z"]).unwrap(), 1);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 4);
        assert_eq!(host.fd_pwrite(fd, &[b"X"], 1).unwrap(), 1);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 4);
        assert_eq!(host.fd_pread(fd, 4, 0).unwrap(), b"aXcZ");
        assert!(matches!(
            host.fd_fdstat_set_flags(fd, WASI_FDFLAGS_ALL | 0x20),
            Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
                if error.code == ErrorCode::InvalidInput
        ));
        assert!(matches!(
            host.fd_fdstat_set_flags(99, 0),
            Err(WasiHostError::DeniedFd(99))
        ));
        host.fd_close(fd).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn fdstat_set_rights_only_narrows_file_capabilities() {
        let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        let mut host = Preview1Host::new(context);
        let fd = host
            .path_open(
                3,
                b"rights",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
        assert_eq!(host.fd_seek(fd, 0, SeekWhence::Start).unwrap(), 0);
        host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ, 0)
            .unwrap();
        assert!(matches!(
            host.fd_write(fd, &[b"x"]),
            Err(WasiHostError::NotCapable(closed)) if closed == fd
        ));
        assert_eq!(host.fd_read(fd, 3).unwrap(), b"abc");
        assert!(matches!(
            host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE, 0),
            Err(WasiHostError::NotCapable(closed)) if closed == fd
        ));
        assert!(matches!(
            host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ, WASI_RIGHT_FD_READ),
            Err(WasiHostError::NotCapable(closed)) if closed == fd
        ));
        assert!(matches!(
            host.fd_fdstat_set_rights(99, 0, 0),
            Err(WasiHostError::DeniedFd(99))
        ));
        host.fd_close(fd).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn fd_renumber_moves_descriptors_and_closes_the_target() {
        let context = Context::from_config(RuntimeConfig::seeded(6)).unwrap();
        let mut host = Preview1Host::new(context);
        let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
        let from = host
            .path_open(
                3,
                b"from",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        let to = host
            .path_open(
                3,
                b"to",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        let target_handle = match host.descriptors.get(&to) {
            Some(WasiDescriptor::File { handle, .. }) => *handle,
            _ => unreachable!("path_open creates file descriptors"),
        };
        host.fd_renumber(from, to).unwrap();
        assert!(!host.descriptors.contains_key(&from));
        assert!(matches!(
            host.descriptors.get(&to),
            Some(WasiDescriptor::File { path, .. }) if path == "/from"
        ));
        assert!(matches!(
            host.context.fs_write(target_handle, b"x"),
            Err(RuntimeError::Effect(error)) if error.code == ErrorCode::InvalidHandle
        ));
        assert_eq!(host.fd_write(to, &[b"ok"]).unwrap(), 2);
        host.fd_renumber(to, to).unwrap();
        assert!(matches!(
            host.fd_renumber(99, to),
            Err(WasiHostError::DeniedFd(99))
        ));
        assert!(matches!(
            host.fd_renumber(3, to),
            Err(WasiHostError::DeniedFd(3))
        ));
        host.fd_close(to).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn process_and_scheduler_imports_have_deterministic_local_results() {
        let context = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let host = Preview1Host::new(context);
        assert_eq!(host.sched_yield(), WASI_ERRNO_SUCCESS);
        assert_eq!(host.proc_raise(9), WASI_ERRNO_NOSYS);
        assert_eq!(host.sock_accept(4, 0), WASI_ERRNO_NOSYS);
        host.finish().unwrap();
    }

    #[test]
    fn filestat_set_times_supports_explicit_and_now_values() {
        let context = Context::from_config(RuntimeConfig::seeded(9)).unwrap();
        let mut host = Preview1Host::new(context);
        let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
        let fd = host
            .path_open(
                3,
                b"times",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        host.fd_filestat_set_times(fd, Some(11), Some(22)).unwrap();
        assert_eq!(host.fd_metadata(fd).unwrap().0.atime_nanos, 11);
        assert_eq!(host.fd_metadata(fd).unwrap().0.mtime_nanos, 22);
        host.sleep_until(WasiClock::Realtime, 77).unwrap();
        let (atime, mtime) = host
            .filestat_set_times_values(0, 0, WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM_NOW)
            .unwrap();
        assert_eq!((atime, mtime), (Some(77), Some(77)));
        host.fd_filestat_set_times(fd, atime, mtime).unwrap();
        assert_eq!(host.fd_metadata(fd).unwrap().0.atime_nanos, 77);
        assert!(matches!(
            host.filestat_set_times_values(1, 2, WASI_FSTFLAG_ATIM | WASI_FSTFLAG_ATIM_NOW),
            Err(WasiHostError::InvalidInput)
        ));
        host.path_filestat_set_times(3, b"times", false, Some(33), None)
            .unwrap();
        assert_eq!(host.fd_metadata(fd).unwrap().0.atime_nanos, 33);
        host.fd_close(fd).unwrap();
        host.finish().unwrap();

        let directory = tempdir().unwrap();
        let trace = directory.path().join("set-times-now.patina");
        let context =
            Context::from_config(RuntimeConfig::record(9, &trace, "set-times-now-v1")).unwrap();
        let mut record = Preview1Host::new(context);
        let values = record
            .filestat_set_times_values(0, 0, WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM_NOW)
            .unwrap();
        assert_eq!(values.0, values.1);
        record.finish().unwrap();
        let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
        let clock_now_count = bundle.timelines[0]
            .decisions
            .iter()
            .filter(|event| {
                matches!(
                    event.operation,
                    Operation::ClockNow {
                        clock: ClockKind::Realtime
                    }
                )
            })
            .count();
        assert_eq!(clock_now_count, 1);
    }

    #[test]
    fn links_symlinks_and_terminal_follow_are_deterministic() {
        let context = Context::from_config(RuntimeConfig::seeded(10)).unwrap();
        let mut host = Preview1Host::new(context);
        let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
        let fd = host
            .path_open(
                3,
                b"target",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
        host.fd_close(fd).unwrap();
        host.path_link(3, b"target", 3, b"linked").unwrap();
        let linked = host
            .path_open(
                3,
                b"linked",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )
            .unwrap();
        assert_eq!(host.fd_read(linked, 3).unwrap(), b"abc");
        host.fd_close(linked).unwrap();
        host.path_symlink(b"target", 3, b"link").unwrap();
        assert_eq!(host.path_readlink(3, b"link").unwrap(), "target");
        assert!(matches!(
            host.path_open(
                3,
                b"link",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false
                }
            ),
            Err(WasiHostError::Loop)
        ));
        let followed = host
            .path_open(
                3,
                b"link",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: true,
                },
            )
            .unwrap();
        assert_eq!(host.fd_read(followed, 3).unwrap(), b"abc");
        host.fd_close(followed).unwrap();
        host.path_symlink(b"link", 3, b"link2").unwrap();
        assert!(matches!(
            host.path_open(
                3,
                b"link2",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: true
                }
            ),
            Err(WasiHostError::Loop)
        ));
        host.path_symlink(b"target", 3, b"mid").unwrap();
        assert!(matches!(
            host.path_readlink(3, b"mid/x"),
            Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
                if error.code == ErrorCode::Denied
        ));
        host.finish().unwrap();
    }

    #[test]
    fn new_filesystem_operations_record_and_replay() {
        fn exercise_new_ops(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
            let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
            let fd = host.path_open(
                3,
                b"a",
                WasiPathOpen {
                    oflags: WASI_OFLAG_CREATE,
                    rights,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: false,
                },
            )?;
            host.fd_write(fd, &[b"abc"])?;
            host.fd_filestat_set_times(fd, Some(1), Some(2))?;
            host.fd_close(fd)?;
            host.path_link(3, b"a", 3, b"b")?;
            host.path_symlink(b"b", 3, b"l")?;
            let fd = host.path_open(
                3,
                b"l",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: true,
                },
            )?;
            let bytes = host.fd_read(fd, 3)?;
            host.fd_close(fd)?;
            Ok(bytes)
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("new-fs.patina");
        let context = Context::from_config(RuntimeConfig::record(43, &trace, "new-fs-v1")).unwrap();
        let mut record = Preview1Host::new(context);
        let expected = exercise_new_ops(&mut record).unwrap();
        record.finish().unwrap();

        let context = Context::from_config(RuntimeConfig::replay(&trace, "new-fs-v1")).unwrap();
        let mut replay = Preview1Host::new(context);
        assert_eq!(exercise_new_ops(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn wasm_engine_exercises_symlink_readlink_and_set_times_imports() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_filestat_set_times"
                    (func $fd_filestat_set_times (param i32 i64 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_symlink"
                    (func $path_symlink (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_readlink"
                    (func $path_readlink (param i32 i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "target")
                (data (i32.const 48) "link")
                (func (export "_start")
                    i32.const 3 i32.const 0 i32.const 32 i32.const 6 i32.const 1
                    i64.const 66 i64.const 0 i32.const 0 i32.const 100
                    call $path_open
                    if unreachable end
                    i32.const 100
                    i32.load
                    i64.const 11
                    i64.const 22
                    i32.const 5
                    call $fd_filestat_set_times
                    if unreachable end
                    i32.const 32 i32.const 6 i32.const 3 i32.const 48 i32.const 4
                    call $path_symlink
                    if unreachable end
                    i32.const 3 i32.const 48 i32.const 4 i32.const 80 i32.const 4 i32.const 120
                    call $path_readlink
                    if unreachable end
                    i32.const 120
                    i32.load
                    i32.const 4
                    i32.ne
                    if unreachable end))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(11)).unwrap();
        assert_eq!(
            execute_preview1(&module, Preview1Host::new(context))
                .unwrap()
                .exit_code,
            0
        );
    }

    #[test]
    fn wasm_engine_exercises_fdstat_set_flags_and_renumber_imports() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_fdstat_set_flags"
                    (func $fd_fdstat_set_flags (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_fdstat_get"
                    (func $fd_fdstat_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_renumber"
                    (func $fd_renumber (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\40\00\00\00\01\00\00\00")
                (data (i32.const 32) "wat")
                (data (i32.const 64) "A")
                (func (export "_start")
                    i32.const 3
                    i32.const 0
                    i32.const 32
                    i32.const 3
                    i32.const 1
                    i64.const 66
                    i64.const 0
                    i32.const 0
                    i32.const 100
                    call $path_open
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 1
                    call $fd_fdstat_set_flags
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 104
                    call $fd_fdstat_get
                    if unreachable end
                    i32.const 106
                    i32.load16_u
                    i32.const 1
                    i32.ne
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 8
                    call $fd_renumber
                    if unreachable end
                    i32.const 8
                    i32.const 0
                    i32.const 1
                    i32.const 120
                    call $fd_write
                    if unreachable end))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(8)).unwrap();
        assert_eq!(
            execute_preview1(&module, Preview1Host::new(context))
                .unwrap()
                .exit_code,
            0
        );
    }

    #[test]
    fn wasm_engine_executes_audited_preview1_and_replays_host_effects() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "args_sizes_get"
                    (func $args_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "args_get"
                    (func $args_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "environ_sizes_get"
                    (func $environ_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "environ_get"
                    (func $environ_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get"
                    (func $random_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "clock_res_get"
                    (func $clock_res_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock_time_get (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit"
                    (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\10\00\00\00\05\00\00\00")
                (data (i32.const 16) "hello")
                (func (export "_start")
                    i32.const 200
                    i32.const 204
                    call $args_sizes_get
                    drop
                    i32.const 208
                    i32.const 300
                    call $args_get
                    drop
                    i32.const 220
                    i32.const 224
                    call $environ_sizes_get
                    drop
                    i32.const 228
                    i32.const 400
                    call $environ_get
                    drop
                    i32.const 1
                    i32.const 500
                    call $clock_res_get
                    drop
                    i32.const 1
                    i64.const 1
                    i32.const 508
                    call $clock_time_get
                    drop
                    i32.const 100
                    i32.const 4
                    call $random_get
                    drop
                    i32.const 1
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    call $fd_write
                    drop
                    i32.const 0
                    call $proc_exit))"#,
        )
        .unwrap();
        let directory = tempdir().unwrap();
        let trace = directory.path().join("engine.patina");
        let context = Context::from_config(RuntimeConfig::record(42, &trace, "engine-v1")).unwrap();
        let recorded = execute_preview1(
            &module,
            Preview1Host::new(context)
                .with_argument("probe.wasm")
                .with_environment("MODE", "record"),
        )
        .unwrap();
        assert_eq!(recorded.exit_code, 0);
        assert_eq!(recorded.stdout, b"hello");

        let context = Context::from_config(RuntimeConfig::replay(&trace, "engine-v1")).unwrap();
        let replayed = execute_preview1(
            &module,
            Preview1Host::new(context)
                .with_argument("probe.wasm")
                .with_environment("MODE", "record"),
        )
        .unwrap();
        assert_eq!(replayed, recorded);
    }

    #[test]
    fn configured_wasi_datagrams_use_the_virtual_network() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "sock_send"
                    (func $send (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "sock_recv"
                    (func $recv (param i32 i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "sock_shutdown"
                    (func $shutdown (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\20\00\00\00\05\00\00\00")
                (data (i32.const 8) "\40\00\00\00\05\00\00\00")
                (data (i32.const 32) "hello")
                (func (export "_start")
                    i32.const 4 i32.const 0 i32.const 1 i32.const 0 i32.const 100
                    call $send
                    if unreachable end
                    i32.const 5 i32.const 8 i32.const 1 i32.const 0 i32.const 104 i32.const 108
                    call $recv
                    if unreachable end
                    i32.const 64 i32.load i32.const 1819043176 i32.ne
                    if unreachable end
                    i32.const 68 i32.load8_u i32.const 111 i32.ne
                    if unreachable end
                    i32.const 4 i32.const 3 call $shutdown
                    if unreachable end))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(17)).unwrap();
        let host = Preview1Host::new(context)
            .with_datagram_socket(4, "node-a", "node-b")
            .unwrap()
            .with_datagram_socket(5, "node-b", "node-a")
            .unwrap();
        assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
    }

    #[test]
    fn wasm_instruction_fuel_bounds_modules_without_boundary_calls() {
        let module = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "_start") (loop $forever (br $forever))))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let error =
            execute_preview1_with_fuel(&module, Preview1Host::new(context), 1_000).unwrap_err();
        assert!(matches!(error, WasiRunError::Engine(_)));
        assert!(error.to_string().to_ascii_lowercase().contains("fuel"));
    }

    // R20 engine-determinism knob: the `simd` cargo feature is deliberately off,
    // so a module using a SIMD (v128) instruction must be REJECTED at validation.
    // This keeps relaxed-SIMD — the one Wasm proposal with implementation-defined
    // (nondeterministic) results — out of reach: were the feature ever enabled,
    // relaxed-SIMD is enabled-by-default within it, and this module would load and
    // run with results that could differ across engines/hosts. If this test ever
    // starts failing because SIMD was turned on, `deterministic_wasmi_config` must
    // add `config.wasm_relaxed_simd(false)` before the module is admitted.
    #[test]
    fn simd_module_is_rejected() {
        let module = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "_start")
                    (drop (v128.const i32x4 0 0 0 0))))"#,
        )
        .unwrap();
        let engine = Engine::new(&deterministic_wasmi_config());
        let error = Module::new(&engine, &module)
            .expect_err("a SIMD module must be rejected while the wasmi `simd` feature is off");
        // A validation/decoding rejection, not a silent acceptance.
        let text = error.to_string().to_ascii_lowercase();
        assert!(
            text.contains("simd") || text.contains("v128") || text.contains("feature"),
            "SIMD rejection should name the disabled proposal, got: {error}"
        );
    }

    // R20 engine-determinism knob: wasmi is a pure interpreter with no NaN
    // canonicalization knob, so a NaN-producing float op must yield the SAME bit
    // pattern on every run. Pinning this means an upstream change that (e.g.)
    // introduced canonicalization or nondeterministic NaN bits would fail loudly
    // here rather than silently perturbing guest-observable float results.
    #[test]
    fn nan_bits_are_deterministic() {
        // sqrt(-1) is a canonical NaN source; reinterpret to i64 to observe the
        // exact bit pattern the interpreter produced.
        let module = wat::parse_str(
            r#"(module
                (func (export "nan_bits") (result i64)
                    (i64.reinterpret_f64 (f64.sqrt (f64.const -1)))))"#,
        )
        .unwrap();
        let nan_bits = || -> i64 {
            let engine = Engine::new(&deterministic_wasmi_config());
            let module = Module::new(&engine, &module).unwrap();
            let mut store = Store::new(&engine, ());
            // Fuel metering is on in the pinned config, so the store must be
            // funded before any guest instruction runs.
            store.set_fuel(1_000_000).unwrap();
            let instance = Linker::<()>::new(&engine)
                .instantiate_and_start(&mut store, &module)
                .unwrap();
            instance
                .get_typed_func::<(), i64>(&store, "nan_bits")
                .unwrap()
                .call(&mut store, ())
                .unwrap()
        };
        let first = nan_bits();
        let second = nan_bits();
        assert_eq!(first, second, "NaN bit pattern was not reproducible");
        // It is genuinely a NaN (all exponent bits set, non-zero mantissa), so the
        // determinism is over a real NaN result rather than a trivial constant.
        let bits = first as u64;
        assert_eq!(bits & 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000);
        assert_ne!(bits & 0x000f_ffff_ffff_ffff, 0);
    }

    #[test]
    fn random_and_clock_calls_record_and_replay() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("wasi.patina");
        let context = Context::from_config(RuntimeConfig::record(42, &trace, "wasi-v1")).unwrap();
        let mut record = Preview1Host::new(context);
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();

        let context = Context::from_config(RuntimeConfig::replay(&trace, "wasi-v1")).unwrap();
        let mut replay = Preview1Host::new(context);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    // `Preview1Host::sleep_until` applies the seeded sleep-latency jitter at the
    // single guest-facing sleep entry (which also backs `poll_oneoff` timeouts):
    // the same seed and range wake at the same inflated deadline, a different range
    // changes it, an unjittered run is unchanged, and record/replay reproduces the
    // wake time byte-for-byte.
    #[test]
    fn sleep_jitter_is_deterministic_and_reproduces_on_replay() {
        fn woke_at(seed: u64, range: Option<&str>) -> u64 {
            let mut config = RuntimeConfig::seeded(seed);
            if let Some(range) = range {
                config = config
                    .apply_fault_env(|name| {
                        (name == patina_dst_runtime::ENV_SLEEP_JITTER).then(|| range.to_string())
                    })
                    .unwrap();
            }
            let mut host = Preview1Host::new(Context::from_config(config).unwrap());
            host.sleep_until(WasiClock::Monotonic, 1_000).unwrap();
            host.clock_time_get(WasiClock::Monotonic).unwrap()
        }

        // No jitter: the clock advances exactly to the requested deadline.
        assert_eq!(woke_at(1, None), 1_000);
        // Same seed and range: identical jittered wake, within [1100, 1200].
        let first = woke_at(7, Some("100..200"));
        assert_eq!(first, woke_at(7, Some("100..200")));
        assert!((1_100..=1_200).contains(&first));
        // A different jitter range changes the schedule.
        assert_ne!(first, woke_at(7, Some("500..600")));

        // Record with jitter, then a flag-free replay reproduces the exact wake
        // time: the draw is owned by the deterministic context and restored from
        // the trace's fault configuration.
        let directory = tempdir().unwrap();
        let trace = directory.path().join("jitter.patina");
        let recorded = {
            let config = RuntimeConfig::record(7, &trace, "jitter-v1")
                .apply_fault_env(|name| {
                    (name == patina_dst_runtime::ENV_SLEEP_JITTER).then(|| "100..200".to_string())
                })
                .unwrap();
            let mut host = Preview1Host::new(Context::from_config(config).unwrap());
            host.sleep_until(WasiClock::Monotonic, 1_000).unwrap();
            let now = host.clock_time_get(WasiClock::Monotonic).unwrap();
            host.finish().unwrap();
            now
        };
        let config = RuntimeConfig::replay(&trace, "jitter-v1");
        let mut host = Preview1Host::new(Context::from_config(config).unwrap());
        host.sleep_until(WasiClock::Monotonic, 1_000).unwrap();
        assert_eq!(host.clock_time_get(WasiClock::Monotonic).unwrap(), recorded);
        host.finish().unwrap();
    }

    // The `patina_sdk` host module is backed by the same runtime buggify
    // subsystem as the native shim: an active site fires (the guest exits with the
    // decision), `reachable!` registers a site, and the end-of-run diagnostics
    // report the firing. Instantiated directly (bypassing `WasiAudit`) so this is
    // a focused unit test of `define_patina_sdk`'s wiring.
    #[test]
    fn patina_sdk_module_fires_and_records_diagnostics() {
        let wasm = wat::parse_str(
            r#"(module
                (import "patina_sdk" "buggify"
                    (func $buggify (param i32 i32 i32 i32 i32) (result i32)))
                (import "patina_sdk" "reachable"
                    (func $reachable (param i32 i32 i32 i32) (result i32)))
                (import "patina_sdk" "lifecycle_setup_complete" (func $setup (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "unit-fault")
                (data (i32.const 16) "unit:site")
                (data (i32.const 32) "unit-reach")
                (data (i32.const 48) "unit:reach")
                (func (export "_start")
                    (drop (call $reachable (i32.const 32) (i32.const 10) (i32.const 48) (i32.const 10)))
                    (drop (call $setup))
                    (call $proc_exit
                        (call $buggify (i32.const 0) (i32.const 10)
                            (i32.const 16) (i32.const 9) (i32.const -1)))))"#,
        )
        .unwrap();

        // Enable buggify at full activation and firing so the single site fires.
        let config = RuntimeConfig::seeded(3)
            .apply_buggify_env(|name| match name {
                patina_dst_runtime::ENV_BUGGIFY => Some("1000".to_string()),
                patina_dst_runtime::ENV_BUGGIFY_ACTIVATION => Some("1000".to_string()),
                _ => None,
            })
            .unwrap();

        let mut wasm_config = WasmiConfig::default();
        wasm_config.consume_fuel(true);
        let engine = Engine::new(&wasm_config);
        let module = Module::new(&engine, &wasm).unwrap();
        let mut linker = Linker::<Preview1Host>::new(&engine);
        define_preview1(&mut linker).unwrap();
        define_patina_sdk(&mut linker).unwrap();
        let mut store = Store::new(
            &engine,
            Preview1Host::new(Context::from_config(config).unwrap()),
        );
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate_and_start(&mut store, &module).unwrap();
        let start = instance.get_typed_func::<(), ()>(&store, "_start").unwrap();
        let exit = match start.call(&mut store, ()) {
            Ok(()) => 0,
            Err(error) => error.i32_exit_status().unwrap(),
        };
        assert_eq!(
            exit, 1,
            "an always-active, always-firing buggify site must fire"
        );

        let diagnostics = store.data_mut().context.buggify_diagnostics();
        assert!(diagnostics.enabled);
        assert_eq!(diagnostics.sites_registered, 2);
        assert_eq!(diagnostics.total_firings, 1);
    }

    fn seeded_memfs(files: &[(&str, &[u8])]) -> patina_dst_fs_mem::MemFs {
        let mut fs = patina_dst_fs_mem::MemFs::new();
        for (path, bytes) in files {
            fs = fs.with_file(path, bytes.to_vec()).unwrap();
        }
        fs
    }

    fn seeded_context(seed: u64, files: &[(&str, &[u8])]) -> Context {
        patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::seeded(seed))
            .with_default_drivers()
            .with_filesystem(seeded_memfs(files))
            .build()
            .unwrap()
    }

    fn read_open() -> WasiPathOpen {
        WasiPathOpen {
            oflags: 0,
            rights: WASI_RIGHT_FD_READ,
            inheriting: 0,
            fdflags: 0,
            follow_symlink: true,
        }
    }

    fn create_write_open() -> WasiPathOpen {
        WasiPathOpen {
            oflags: WASI_OFLAG_CREATE,
            rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
            inheriting: 0,
            fdflags: 0,
            follow_symlink: true,
        }
    }

    fn directory_open() -> WasiPathOpen {
        WasiPathOpen {
            oflags: WASI_OFLAG_DIRECTORY,
            rights: 0,
            inheriting: 0,
            fdflags: 0,
            follow_symlink: true,
        }
    }

    #[test]
    fn directory_fd_sync_commits_namespace_durability() {
        let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let mut host = Preview1Host::new(context);
        let tmp = host.path_open(3, b"ns.tmp", create_write_open()).unwrap();
        host.fd_write(tmp, &[b"stable"]).unwrap();
        host.fd_sync(tmp).unwrap();
        host.fd_close(tmp).unwrap();
        host.context.fs_rename("/ns.tmp", "/final").unwrap();

        let root = host.path_open(3, b".", directory_open()).unwrap();
        host.fd_sync(root).unwrap();
        host.fd_close(root).unwrap();
        host.context.fs_crash().unwrap();

        let final_fd = host.path_open(3, b"final", read_open()).unwrap();
        assert_eq!(host.fd_read(final_fd, 16).unwrap(), b"stable");
    }

    #[test]
    fn read_only_preopen_denies_mutations_but_allows_reads() {
        let context = seeded_context(1, &[("/ro/seed", b"data"), ("/ro/old", b"x")]);
        // fd 3 = /ro (read-only), fd 4 = /rw (read-write).
        let mut host = Preview1Host::new(context)
            .with_preopen("/ro", MountPolicy::ReadOnly)
            .unwrap()
            .with_preopen("/rw", MountPolicy::ReadWrite)
            .unwrap();

        // Reads and metadata are allowed.
        let fd = host.path_open(3, b"seed", read_open()).unwrap();
        assert_eq!(host.fd_read(fd, 16).unwrap(), b"data");
        host.fd_close(fd).unwrap();

        // Every mutation kind is denied with EROFS, regardless of requested rights.
        assert!(matches!(
            host.path_open(3, b"created", create_write_open()),
            Err(WasiHostError::ReadOnly)
        ));
        assert!(matches!(
            host.path_open(3, b"seed", create_write_open()),
            Err(WasiHostError::ReadOnly)
        ));
        assert!(matches!(
            host.path_filestat_set_times(3, b"seed", true, Some(1), Some(2)),
            Err(WasiHostError::ReadOnly)
        ));
        assert!(matches!(
            host.path_symlink(b"seed", 3, b"link"),
            Err(WasiHostError::ReadOnly)
        ));
        assert!(matches!(
            host.path_link(3, b"seed", 3, b"hardlink"),
            Err(WasiHostError::ReadOnly)
        ));

        // The sibling read-write mount is unaffected.
        let out = host.path_open(4, b"out", create_write_open()).unwrap();
        assert_eq!(host.fd_write(out, &[b"ok"]).unwrap(), 2);
        host.fd_close(out).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn path_link_denies_read_only_source_alias_bypass() {
        let context = seeded_context(
            12,
            &[
                ("/ro/secret", b"secret"),
                ("/rw/source", b"data"),
                ("/rw/.keep", b""),
            ],
        );
        let mut host = Preview1Host::new(context)
            .with_preopen("/ro", MountPolicy::ReadOnly)
            .unwrap()
            .with_preopen("/rw", MountPolicy::ReadWrite)
            .unwrap();

        assert!(matches!(
            host.path_link(3, b"secret", 4, b"alias"),
            Err(WasiHostError::ReadOnly)
        ));
        let secret = host.path_open(3, b"secret", read_open()).unwrap();
        assert_eq!(host.fd_read(secret, 16).unwrap(), b"secret");
        host.fd_close(secret).unwrap();
        assert!(matches!(
            host.path_open(4, b"alias", read_open()),
            Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
                if error.code == ErrorCode::NotFound
        ));

        host.path_link(4, b"source", 4, b"source-link").unwrap();
        let linked = host.path_open(4, b"source-link", read_open()).unwrap();
        assert_eq!(host.fd_read(linked, 16).unwrap(), b"data");
        host.fd_close(linked).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn fd_filestat_set_size_denies_read_only_mount_even_with_write_right() {
        let context = seeded_context(13, &[("/ro/seed", b"data")]);
        let mut host = Preview1Host::new(context);
        let fd = host
            .path_open(
                3,
                b"ro/seed",
                WasiPathOpen {
                    oflags: 0,
                    rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
                    inheriting: 0,
                    fdflags: 0,
                    follow_symlink: true,
                },
            )
            .unwrap();
        host.mounts.clear();
        host.mounts.insert("/ro".to_owned(), MountPolicy::ReadOnly);

        assert!(matches!(
            host.fd_filestat_set_size(fd, 99),
            Err(WasiHostError::ReadOnly)
        ));
        assert_eq!(host.fd_metadata(fd).unwrap().0.len, 4);
        host.fd_close(fd).unwrap();
        host.finish().unwrap();
    }

    #[test]
    fn wasi_stat_and_readdir_report_hard_link_identity() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "path_filestat_get"
                    (func $path_filestat_get (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_unlink_file"
                    (func $path_unlink_file (param i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_readdir"
                    (func $fd_readdir (param i32 i32 i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "a")
                (data (i32.const 48) "b")
                (func $write8 (param $ptr i32)
                    i32.const 0 local.get $ptr i32.store
                    i32.const 4 i32.const 8 i32.store
                    i32.const 1 i32.const 0 i32.const 1 i32.const 24
                    call $fd_write
                    if unreachable end)
                (func (export "_start")
                    i32.const 3 i32.const 0 i32.const 32 i32.const 1 i32.const 100
                    call $path_filestat_get
                    if unreachable end
                    i32.const 108 call $write8
                    i32.const 124 call $write8
                    i32.const 3 i32.const 0 i32.const 48 i32.const 1 i32.const 200
                    call $path_filestat_get
                    if unreachable end
                    i32.const 208 call $write8
                    i32.const 224 call $write8
                    i32.const 3 i32.const 32 i32.const 1
                    call $path_unlink_file
                    if unreachable end
                    i32.const 3 i32.const 0 i32.const 48 i32.const 1 i32.const 400
                    call $path_filestat_get
                    if unreachable end
                    i32.const 408 call $write8
                    i32.const 424 call $write8
                    i32.const 3 i32.const 500 i32.const 128 i64.const 0 i32.const 700
                    call $fd_readdir
                    if unreachable end
                    i32.const 508 call $write8))"#,
        )
        .unwrap();
        let context = seeded_context(14, &[("/a", b"data")]);
        let mut host = Preview1Host::new(context);
        host.path_link(3, b"a", 3, b"b").unwrap();
        let output = execute_preview1(&module, host).unwrap();
        assert_eq!(output.exit_code, 0);
        let values = read_stdout_u64s(&output.stdout);
        assert_eq!(values.len(), 7);
        let [
            a_ino,
            a_nlink,
            b_ino,
            b_nlink,
            survivor_ino,
            survivor_nlink,
            dirent_ino,
        ] = values.try_into().unwrap();
        assert_eq!(a_ino, b_ino);
        assert_eq!(a_nlink, 2);
        assert_eq!(b_nlink, 2);
        assert_eq!(survivor_ino, b_ino);
        assert_eq!(survivor_nlink, 1);
        assert_eq!(dirent_ino, survivor_ino);
    }

    #[test]
    fn read_only_mount_denies_inline_namespace_calls() {
        // path_create_directory and path_unlink_file run inside the linker and
        // must also honor the read-only mount (EROFS = 69).
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "path_create_directory"
                    (func $mkdir (param i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_unlink_file"
                    (func $unlink (param i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "dir")
                (data (i32.const 16) "file")
                (func (export "_start")
                    (if (i32.ne (call $mkdir (i32.const 3) (i32.const 0) (i32.const 3))
                                (i32.const 69)) (then unreachable))
                    (if (i32.ne (call $unlink (i32.const 3) (i32.const 16) (i32.const 4))
                                (i32.const 69)) (then unreachable))))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let host = Preview1Host::new(context)
            .with_preopen("/ro", MountPolicy::ReadOnly)
            .unwrap();
        assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
    }

    #[test]
    fn nested_and_duplicate_preopens_are_rejected() {
        let nested = Preview1Host::new(seeded_context(2, &[]))
            .with_preopen("/data", MountPolicy::ReadWrite)
            .unwrap()
            .with_preopen("/data/inner", MountPolicy::ReadWrite);
        assert!(matches!(nested, Err(WasiHostError::PreopenOverlap { .. })));

        let duplicate = Preview1Host::new(seeded_context(2, &[]))
            .with_preopen("/data", MountPolicy::ReadWrite)
            .unwrap()
            .with_preopen("/data", MountPolicy::ReadOnly);
        assert!(matches!(
            duplicate,
            Err(WasiHostError::PreopenOverlap { .. })
        ));

        let bad = Preview1Host::new(seeded_context(2, &[]))
            .with_preopen("relative", MountPolicy::ReadWrite);
        assert!(matches!(bad, Err(WasiHostError::InvalidPreopen(_))));
    }

    #[test]
    fn descriptor_and_path_length_limits_are_enforced() {
        let context = seeded_context(3, &[("/a", b"1"), ("/b", b"2"), ("/c", b"3")]);
        let mut host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
            max_descriptors: 3,
            ..ResourceLimits::default()
        });
        // The root preopen occupies one slot, so two opens fit and the third fails.
        let _a = host.path_open(3, b"a", read_open()).unwrap();
        let _b = host.path_open(3, b"b", read_open()).unwrap();
        assert!(matches!(
            host.path_open(3, b"c", read_open()),
            Err(WasiHostError::DescriptorExhausted)
        ));

        let mut host =
            Preview1Host::new(seeded_context(4, &[])).with_resource_limits(ResourceLimits {
                max_path_bytes: 4,
                ..ResourceLimits::default()
            });
        assert!(matches!(
            host.path_open(3, b"toolong", read_open()),
            Err(WasiHostError::PathTooLong)
        ));

        let over = Preview1Host::new(seeded_context(4, &[]))
            .with_resource_limits(ResourceLimits {
                max_preopens: 1,
                ..ResourceLimits::default()
            })
            .with_preopen("/first", MountPolicy::ReadWrite)
            .unwrap()
            .with_preopen("/second", MountPolicy::ReadWrite);
        assert!(matches!(over, Err(WasiHostError::TooManyPreopens(1))));
    }

    #[test]
    fn memory_growth_cap_traps_deterministically_and_is_replayable() {
        let module = wat::parse_str(
            r#"(module
                (memory 1)
                (func (export "_start")
                    (drop (memory.grow (i32.const 100)))))"#,
        )
        .unwrap();

        let capped = || {
            let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
            let host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
                max_memory_pages: 2,
                ..ResourceLimits::default()
            });
            execute_preview1(&module, host)
        };
        // Exceeding the cap is a deterministic trap on every run.
        assert!(matches!(capped(), Err(WasiRunError::Engine(_))));
        assert!(matches!(capped(), Err(WasiRunError::Engine(_))));

        // A generous cap admits the same growth.
        let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        let host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
            max_memory_pages: 256,
            ..ResourceLimits::default()
        });
        assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
    }

    #[test]
    fn multiple_preopens_appear_through_fd_prestat() {
        let module = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_prestat_get"
                    (func $prestat (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (if (i32.ne (call $prestat (i32.const 3) (i32.const 0)) (i32.const 0))
                        (then unreachable))
                    (if (i32.ne (call $prestat (i32.const 4) (i32.const 0)) (i32.const 0))
                        (then unreachable))
                    (if (i32.ne (call $prestat (i32.const 5) (i32.const 0)) (i32.const 8))
                        (then unreachable))))"#,
        )
        .unwrap();
        let context = Context::from_config(RuntimeConfig::seeded(6)).unwrap();
        let host = Preview1Host::new(context)
            .with_preopen("/alpha", MountPolicy::ReadWrite)
            .unwrap()
            .with_preopen("/beta", MountPolicy::ReadOnly)
            .unwrap();
        assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
    }

    #[test]
    fn preopen_policy_reads_and_denials_record_and_replay() {
        fn exercise(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
            let fd = host.path_open(3, b"seed", read_open())?;
            let bytes = host.fd_read(fd, 16)?;
            host.fd_close(fd)?;
            // A denied write leaves no boundary operation in the trace.
            assert!(matches!(
                host.path_open(3, b"seed", create_write_open()),
                Err(WasiHostError::ReadOnly)
            ));
            let out = host.path_open(4, b"out", create_write_open())?;
            host.fd_write(out, &[b"z"])?;
            host.fd_close(out)?;
            Ok(bytes)
        }

        fn host_for(context: Context) -> Preview1Host {
            Preview1Host::new(context)
                .with_preopen("/ro", MountPolicy::ReadOnly)
                .unwrap()
                .with_preopen("/rw", MountPolicy::ReadWrite)
                .unwrap()
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("preopen.patina");
        let record_context =
            patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::record(9, &trace, "preopen-v1"))
                .with_default_drivers()
                .with_filesystem(seeded_memfs(&[("/ro/seed", b"data")]))
                .build()
                .unwrap();
        let mut record = host_for(record_context);
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();

        let replay_context =
            patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::replay(&trace, "preopen-v1"))
                .with_default_drivers()
                .with_filesystem(seeded_memfs(&[("/ro/seed", b"data")]))
                .build()
                .unwrap();
        let mut replay = host_for(replay_context);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    /// A guest whose hostcall mix is fixed by the module text, so the counters
    /// can be asserted exactly rather than "greater than zero". Mutating any
    /// wrapper's counting line drives its row to absent and fails this test.
    fn depth_probe_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $write (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get"
                    (func $random (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "depth\n")
                (func (export "_start")
                    (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 8)))
                    (drop (call $clock (i32.const 1) (i64.const 0) (i32.const 8)))
                    (drop (call $clock (i32.const 1) (i64.const 0) (i32.const 8)))
                    (drop (call $random (i32.const 96) (i32.const 8)))
                    (i32.store (i32.const 0) (i32.const 64))
                    (i32.store (i32.const 4) (i32.const 6))
                    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1)
                        (i32.const 16)))))"#,
        )
        .unwrap()
    }

    fn run_depth_probe(seed: u64) -> WasiExecution {
        let context = Context::from_config(RuntimeConfig::seeded(seed)).unwrap();
        execute_preview1(&depth_probe_module(), Preview1Host::new(context)).unwrap()
    }

    #[test]
    fn hostcall_counters_record_every_import_call_exactly() {
        let execution = run_depth_probe(7);
        assert_eq!(execution.hostcalls.get("clock_time_get"), Some(&3));
        assert_eq!(execution.hostcalls.get("random_get"), Some(&1));
        assert_eq!(execution.hostcalls.get("fd_write"), Some(&1));
        assert_eq!(execution.hostcalls_total(), 5);
        // An import the module never calls must be absent, not zero-valued: the
        // map reports what ran, so "no rows" and "zero depth" stay distinct.
        assert!(!execution.hostcalls.contains_key("fd_read"));
        assert!(
            execution.fuel_consumed > 0,
            "fuel accounting reported nothing for a guest that executed"
        );
    }

    #[test]
    fn depth_is_byte_identical_across_repeat_runs_of_one_seed() {
        let first = run_depth_probe(11);
        let second = run_depth_probe(11);
        assert_eq!(first.fuel_consumed, second.fuel_consumed);
        assert_eq!(first.hostcalls, second.hostcalls);
        // The counters must not perturb the run either: the guest-observable
        // outputs stay identical alongside them.
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(first.exit_code, second.exit_code);
    }

    #[test]
    fn zero_fuel_depth_is_refused_rather_than_reported_as_zero() {
        let error = check_depth_available(0).unwrap_err();
        assert!(matches!(error, WasiRunError::Depth(_)), "got {error:?}");
        assert!(
            error.to_string().contains("fuel_consumed=0"),
            "refusal must name the missing measurement, got: {error}"
        );
        check_depth_available(1).expect("a run that consumed fuel has depth data");
    }
}

/// Source-level convention lint for the depth counters: every imported function
/// defined in `define_preview1`/`define_patina_sdk` must bump the hostcall
/// counter under its OWN name, as the first statement of its wrapper. The
/// counters are per-wrapper by design (there is no interception point in
/// `Linker::func_wrap`), so this lint is what keeps a newly added import from
/// silently dropping out of the depth report.
#[cfg(test)]
mod depth_source_lints {
    #[test]
    fn every_wasi_import_wrapper_counts_its_own_hostcall() {
        let source = include_str!("lib.rs");
        let body = source
            .split_once("fn define_preview1(")
            .expect("definition function")
            .1
            .split_once("\nfn read_guest_bytes(")
            .expect("end of the import definitions")
            .0;
        // Assembled at runtime so this lint's own text cannot satisfy itself.
        let counter = format!("count_{}(\"", "hostcall");
        let mut names: Vec<String> = Vec::new();
        let mut counted: Vec<String> = Vec::new();
        let mut previous = "";
        for line in body.lines() {
            if previous.trim() == "MODULE," {
                if let Some(name) = line
                    .trim()
                    .strip_prefix('"')
                    .and_then(|r| r.split_once('"'))
                {
                    names.push(name.0.to_string());
                }
            }
            if let Some(rest) = line.split_once(&counter) {
                counted.push(
                    rest.1
                        .split_once('"')
                        .expect("counted name is quoted")
                        .0
                        .to_string(),
                );
            }
            previous = line;
        }
        assert!(
            names.len() > 40,
            "the lint failed to find the import table; it found {} names",
            names.len()
        );
        assert_eq!(
            names, counted,
            "every import wrapper must count its own name, in definition order"
        );
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            names.len(),
            "import names must be unique so depth rows cannot silently merge"
        );
    }
}
