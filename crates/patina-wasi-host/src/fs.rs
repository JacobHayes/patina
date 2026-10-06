//! Virtual filesystem descriptors, paths, metadata, and mount capabilities.

use crate::abi::{
    WASI_DIRECTORY_MUTATION_RIGHTS, WASI_DIRECTORY_RIGHTS, WASI_FDFLAG_APPEND, WASI_FDFLAGS_ALL,
    WASI_FSTFLAG_ATIM, WASI_FSTFLAG_ATIM_NOW, WASI_FSTFLAG_MTIM, WASI_FSTFLAG_MTIM_NOW,
    WASI_FSTFLAGS_ALL, WASI_OFLAG_CREATE, WASI_OFLAG_DIRECTORY, WASI_OFLAG_EXCLUSIVE,
    WASI_OFLAG_TRUNCATE, WASI_RIGHT_FD_ADVISE, WASI_RIGHT_FD_ALLOCATE, WASI_RIGHT_FD_READ,
    WASI_RIGHT_FD_WRITE,
};
use crate::host::WasiDescriptor;
use crate::{MountPolicy, Preview1Host, WasiClock, WasiHostError};
use patina_dst_abi::{EffectError, ErrorCode, Fd, FsEntryKind, FsMetadata, OpenFlags, SeekWhence};
use patina_dst_runtime::RuntimeError;

#[derive(Clone, Copy, Debug)]
pub(super) struct WasiPathOpen {
    pub(super) oflags: u16,
    pub(super) rights: u64,
    pub(super) inheriting: u64,
    pub(super) fdflags: u16,
    pub(super) follow_symlink: bool,
}

pub(super) fn preopen_rights(policy: MountPolicy) -> (u64, u64) {
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
pub(super) fn mount_contains(parent: &str, child: &str) -> bool {
    if parent == "/" {
        return child != "/";
    }
    child.starts_with(&format!("{parent}/"))
}

pub(super) fn mounts_overlap(a: &str, b: &str) -> bool {
    a == b || mount_contains(a, b) || mount_contains(b, a)
}

/// Canonicalize a configured preopen path to an absolute, `..`-free form.
pub(super) fn normalize_mount_path(path: &str) -> Result<String, WasiHostError> {
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

fn host_parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

impl Preview1Host {
    pub(super) fn file_write_handle(&self, fd: u32) -> Result<(Fd, bool), WasiHostError> {
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

    pub(super) fn fd_write_positioned(
        &mut self,
        fd: u32,
        buffers: &[&[u8]],
    ) -> Result<usize, WasiHostError> {
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

    pub(super) fn fd_fdstat_set_flags(
        &mut self,
        fd: u32,
        fdflags: u16,
    ) -> Result<(), WasiHostError> {
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

    pub(super) fn fd_fdstat_set_rights(
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

    pub(super) fn fd_renumber(&mut self, from: u32, to: u32) -> Result<(), WasiHostError> {
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

    pub(super) fn filestat_set_times_values(
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

    pub(super) fn resolve_path(
        &self,
        directory: u32,
        path: &[u8],
    ) -> Result<String, WasiHostError> {
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

    pub(super) fn resolve_path_with_terminal_follow(
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

    pub(super) fn path_open(
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
            // Preview 1 has no `O_PATH`: every `path_open` opens the entry, and
            // a directory handle it hands back is a readable one.
            path_only: false,
            // WASI Preview 1's `path_open` has no mode argument and no umask:
            // there is no caller request to carry, so the creation mode is the
            // ordinary `0o666` a POSIX program passes under the default `0o022`
            // umask — the familiar `0o644`. The umask is applied HERE, where a
            // kernel applies the process umask; the driver stores what it is
            // handed.
            mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE & !patina_dst_abi::DEFAULT_UMASK,
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

    pub(super) fn fd_close(&mut self, fd: u32) -> Result<(), WasiHostError> {
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

    pub(super) fn fd_sync(&mut self, fd: u32) -> Result<(), WasiHostError> {
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

    pub(super) fn fd_read(&mut self, fd: u32, max_len: usize) -> Result<Vec<u8>, WasiHostError> {
        let (handle, rights) = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, rights, .. }) => (*handle, *rights),
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        if rights & WASI_RIGHT_FD_READ == 0 {
            return Err(WasiHostError::NotCapable(fd));
        }
        self.context.fs_read(handle, max_len).map_err(Into::into)
    }

    pub(super) fn fd_allocate(
        &mut self,
        fd: u32,
        offset: u64,
        len: u64,
    ) -> Result<(), WasiHostError> {
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

    pub(super) fn fd_filestat_set_size(&mut self, fd: u32, len: u64) -> Result<(), WasiHostError> {
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

    pub(super) fn fd_filestat_set_times(
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
            .fs_set_times(
                handle,
                atime_nanos.map(i128::from),
                mtime_nanos.map(i128::from),
            )
            .map_err(Into::into)
    }

    pub(super) fn path_filestat_set_times(
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
            .fs_set_times_by_path(
                &path,
                atime_nanos.map(i128::from),
                mtime_nanos.map(i128::from),
            )
            .map_err(Into::into)
    }

    pub(super) fn path_link(
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

    pub(super) fn path_symlink(
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

    pub(super) fn path_readlink(
        &mut self,
        directory: u32,
        path: &[u8],
    ) -> Result<String, WasiHostError> {
        let path = self.resolve_path(directory, path)?;
        self.context.fs_read_link(&path).map_err(Into::into)
    }

    pub(super) fn fd_advise(&self, fd: u32) -> Result<(), WasiHostError> {
        match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { rights, .. }) if rights & WASI_RIGHT_FD_ADVISE != 0 => {
                Ok(())
            }
            Some(WasiDescriptor::File { .. }) => Err(WasiHostError::NotCapable(fd)),
            _ => Err(WasiHostError::DeniedFd(fd)),
        }
    }

    pub(super) fn fd_seek(
        &mut self,
        fd: u32,
        offset: i64,
        whence: SeekWhence,
    ) -> Result<u64, WasiHostError> {
        let handle = match self.descriptors.get(&fd) {
            Some(WasiDescriptor::File { handle, .. }) => *handle,
            _ => return Err(WasiHostError::DeniedFd(fd)),
        };
        self.context
            .fs_seek(handle, offset, whence)
            .map_err(Into::into)
    }

    pub(super) fn fd_pread(
        &mut self,
        fd: u32,
        max_len: usize,
        offset: u64,
    ) -> Result<Vec<u8>, WasiHostError> {
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

    pub(super) fn fd_pwrite(
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

    pub(super) fn fd_metadata(&mut self, fd: u32) -> Result<(FsMetadata, String), WasiHostError> {
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
                                blocks: 0,
                                ino: 0,
                                nlink: 1,
                                atime_nanos: 0,
                                mtime_nanos: 0,
                                ctime_nanos: 0,
                                btime_nanos: 0,
                                mode: 0o755,
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
}

#[cfg(test)]
mod tests;
