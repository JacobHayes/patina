//! WASI Preview 1 import registration.

use crate::abi::{
    SYNTHETIC_DATAGRAM_INO_BASE, SYNTHETIC_STDIO_INO_BASE, WASI_ERRNO_AGAIN, WASI_ERRNO_BADF,
    WASI_ERRNO_INVAL, WASI_ERRNO_SUCCESS, WASI_FDFLAGS_ALL, WASI_FILETYPE_CHARACTER_DEVICE,
    WASI_FILETYPE_DIRECTORY, WASI_FILETYPE_REGULAR_FILE, WASI_FILETYPE_SOCKET_DGRAM,
    WASI_OFLAG_CREATE, WASI_OFLAG_DIRECTORY, WASI_OFLAG_EXCLUSIVE, WASI_OFLAG_TRUNCATE,
    WASI_RIGHT_FD_READ, WASI_RIGHT_FD_WRITE, host_error, wasi_call, wasi_clock, wasi_filetype,
};
use crate::fs::WasiPathOpen;
use crate::host::{WasiDescriptor, WasiSubscription};
use crate::memory::{
    environment_strings, memory, offset, read_guest_bytes, read_iovecs, read_u16, read_u32,
    read_u64, string_buffer_size, write_filestat, write_string_vector, write_u16, write_u32,
    write_u64,
};
use crate::{Preview1Host, WasiHostError};
use patina_dst_abi::{FsEntryKind, FsMetadata, SeekWhence};
use wasmi::{Caller, Error as WasmiError, Linker};

pub(super) fn define_preview1(linker: &mut Linker<Preview1Host>) -> Result<(), WasmiError> {
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
                        blocks: 0,
                        ino: SYNTHETIC_STDIO_INO_BASE + u64::from(fd),
                        nlink: 1,
                        atime_nanos: 0,
                        mtime_nanos: 0,
                        ctime_nanos: 0,
                        btime_nanos: 0,
                        mode: 0o644,
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
                            blocks: 0,
                            ino: SYNTHETIC_DATAGRAM_INO_BASE + u64::from(fd),
                            nlink: 1,
                            atime_nanos: 0,
                            mtime_nanos: 0,
                            ctime_nanos: 0,
                            btime_nanos: 0,
                            mode: 0o644,
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
                    // `path_create_directory` carries no mode either; `0o777`
                    // under the default umask, applied here, is the familiar
                    // `0o755`.
                    .fs_create_directory(
                        &path,
                        patina_dst_abi::DEFAULT_DIRECTORY_CREATE_MODE
                            & !patina_dst_abi::DEFAULT_UMASK,
                    )
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

#[cfg(test)]
mod tests;
