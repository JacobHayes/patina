//! Host state, configuration, clocks, stdio, datagrams, polling, and finalization.

use crate::abi::{
    WASI_DIRECTORY_RIGHTS, WASI_ERRNO_NOSYS, WASI_ERRNO_SUCCESS, WASI_RIGHT_FD_READ,
    WASI_RIGHT_FD_WRITE, WASI_RIGHT_POLL_FD_READWRITE,
};
use crate::fs::{mount_contains, mounts_overlap, normalize_mount_path, preopen_rights};
use crate::{
    BUGGIFY_SETUP_NEVER_CALLED_MARKER, MountPolicy, ResourceLimits, WasiExit, WasiHostError,
};
use patina_dst_abi::{ClockKind, EffectError, ErrorCode, Fd, SeekWhence, SocketId};
use patina_dst_runtime::Context;
use std::collections::BTreeMap;
use wasmi::StoreLimits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiClock {
    Realtime,
    Monotonic,
}

/// A deterministic host adapter with no inherited arguments, environment, or
/// stdio. Callers explicitly populate those capabilities.
pub struct Preview1Host {
    pub(super) context: Context,
    pub(super) arguments: Vec<String>,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) descriptors: BTreeMap<u32, WasiDescriptor>,
    pub(super) next_descriptor: u32,
    stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) limits: ResourceLimits,
    /// Guest mount points and their access policy, keyed by canonical path.
    pub(super) mounts: BTreeMap<String, MountPolicy>,
    /// True once an explicit preopen replaced the implicit read-write root.
    explicit_preopens: bool,
    /// Linear-memory limiter installed on the Wasmi store at execution time.
    pub(super) store_limits: StoreLimits,
    /// Per-import call counts, keyed by the imported function name. Written by
    /// every `define_preview1`/`define_patina_sdk` wrapper and never read by any
    /// host function, so counting cannot perturb the guest: the map is a pure
    /// observation of the same deterministic instruction stream that produces
    /// `WasiExecution::fuel_consumed`.
    hostcalls: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug)]
pub(super) enum WasiDescriptor {
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

pub(super) enum WasiSubscription {
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
    pub(super) fn hostcalls(&self) -> &BTreeMap<&'static str, u64> {
        &self.hostcalls
    }

    pub(super) fn count_hostcall(&mut self, claim: crate::imports::HostcallClaim) {
        let entry = self.hostcalls.entry(claim.name()).or_insert(0);
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
    pub(super) fn ensure_writable(&self, path: &str) -> Result<(), WasiHostError> {
        match self.governing_policy(path) {
            MountPolicy::ReadWrite => Ok(()),
            MountPolicy::ReadOnly => Err(WasiHostError::ReadOnly),
        }
    }

    pub(super) fn ensure_writable_fd(&self, fd: u32) -> Result<(), WasiHostError> {
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

    /// OS-scheduling hint. Preview1Host has no cooperative task model, so a
    /// no-op is the deterministic interpretation.
    pub(super) const fn sched_yield(&self) -> i32 {
        WASI_ERRNO_SUCCESS
    }

    /// No process/signal model exists; report the same errno used for missing
    /// deterministic drivers.
    pub(super) const fn proc_raise(&self, _signal: u32) -> i32 {
        WASI_ERRNO_NOSYS
    }

    /// Preview 1 has no listen/bind surface, and Patina's socket model only
    /// produces pre-connected datagrams, so no descriptor can be a listening
    /// socket.
    pub(super) const fn sock_accept(&self, _fd: u32, _flags: u16) -> i32 {
        WASI_ERRNO_NOSYS
    }

    pub(super) fn sock_send(&mut self, fd: u32, bytes: &[u8]) -> Result<usize, WasiHostError> {
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

    pub(super) fn sock_recv(&mut self, fd: u32) -> Result<Option<Vec<u8>>, WasiHostError> {
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

    pub(super) fn sock_shutdown(&mut self, fd: u32) -> Result<(), WasiHostError> {
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

    pub(super) fn poll(
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
                    now.saturating_add(deadline)
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

    pub(super) fn finish_with_output(self) -> Result<(Vec<u8>, Vec<u8>), WasiHostError> {
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

#[cfg(test)]
mod tests;
