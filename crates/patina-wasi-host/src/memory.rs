//! Wasmi guest-memory access and WASI data marshalling.

use crate::Preview1Host;
use crate::abi::wasi_timestamp;
use patina_dst_abi::FsMetadata;
use wasmi::{AsContextMut, Caller, Error as WasmiError, Extern, Memory};

pub(super) fn read_guest_bytes(
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

pub(super) fn read_iovecs(
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

pub(super) fn write_filestat(
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
    stat[40..48].copy_from_slice(&wasi_timestamp(metadata.atime_nanos).to_le_bytes());
    stat[48..56].copy_from_slice(&wasi_timestamp(metadata.mtime_nanos).to_le_bytes());
    stat[56..64].copy_from_slice(&wasi_timestamp(metadata.ctime_nanos).to_le_bytes());
    memory(caller)?.write(caller, offset(pointer)?, &stat)?;
    Ok(())
}

pub(super) fn environment_strings(host: &Preview1Host) -> Vec<String> {
    host.environment
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

pub(super) fn string_buffer_size(values: &[String]) -> Result<u32, WasmiError> {
    values.iter().try_fold(0u32, |size, value| {
        size.checked_add(value.len() as u32 + 1)
            .ok_or_else(|| WasmiError::new("WASI string buffer size overflow"))
    })
}

pub(super) fn write_string_vector(
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

pub(super) fn memory(caller: &Caller<'_, Preview1Host>) -> Result<Memory, WasmiError> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| WasmiError::new("WASI guest does not export memory"))
}

pub(super) fn read_u32(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u32, WasmiError> {
    let mut bytes = [0; 4];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(super) fn read_u16(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u16, WasmiError> {
    let mut bytes = [0; 2];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn read_u64(
    caller: &Caller<'_, Preview1Host>,
    memory: Memory,
    pointer: usize,
) -> Result<u64, WasmiError> {
    let mut bytes = [0; 8];
    memory.read(caller, pointer, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn write_u16(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u16,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

pub(super) fn write_u32(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u32,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

pub(super) fn write_u64(
    caller: &mut Caller<'_, Preview1Host>,
    pointer: i32,
    value: u64,
) -> Result<(), WasmiError> {
    memory(caller)?.write(caller, offset(pointer)?, &value.to_le_bytes())?;
    Ok(())
}

pub(super) fn offset(value: i32) -> Result<usize, WasmiError> {
    usize::try_from(value).map_err(|_| WasmiError::new("negative WASI guest pointer or length"))
}
