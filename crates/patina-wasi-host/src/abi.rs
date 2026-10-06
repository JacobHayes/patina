//! Preview 1 wire constants, file types, and error translation.

use crate::{WasiClock, WasiHostError};
use patina_dst_abi::{ErrorCode, FsEntryKind};
use patina_dst_runtime::RuntimeError;
use wasmi::Error as WasmiError;

pub(super) const WASI_ERRNO_SUCCESS: i32 = 0;

pub(super) const WASI_ERRNO_AGAIN: i32 = 6;

pub(super) const WASI_ERRNO_BADF: i32 = 8;

const WASI_ERRNO_EXIST: i32 = 20;

pub(super) const WASI_ERRNO_INVAL: i32 = 28;

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

pub(super) const WASI_ERRNO_NOSYS: i32 = 52;

const WASI_ERRNO_NOTDIR: i32 = 54;

const WASI_ERRNO_NOTEMPTY: i32 = 55;

const WASI_ERRNO_OVERFLOW: i32 = 61;

const WASI_ERRNO_NOTCAPABLE: i32 = 76;

const WASI_ERRNO_NAMETOOLONG: i32 = 37;

const WASI_ERRNO_ROFS: i32 = 69;

const WASI_ERRNO_2BIG: i32 = 1;

const WASI_ERRNO_FBIG: i32 = 22;

const WASI_ERRNO_BUSY: i32 = 10;

const WASI_ERRNO_NOTSUP: i32 = 58;

const WASI_ERRNO_PERM: i32 = 63;

const WASI_ERRNO_RANGE: i32 = 68;

const WASI_ERRNO_SPIPE: i32 = 70;

const WASI_ERRNO_XDEV: i32 = 75;

const WASI_ERRNO_NXIO: i32 = 60;

/// `filetype::unknown` — the Preview 1 value for a kind its enumeration does
/// not name (there is no FIFO filetype).
const WASI_FILETYPE_UNKNOWN: u8 = 0;

pub(super) const WASI_FILETYPE_CHARACTER_DEVICE: u8 = 2;

pub(super) const WASI_FILETYPE_DIRECTORY: u8 = 3;

pub(super) const WASI_FILETYPE_REGULAR_FILE: u8 = 4;

pub(super) const WASI_FILETYPE_SOCKET_DGRAM: u8 = 5;

const WASI_FILETYPE_SYMBOLIC_LINK: u8 = 7;

pub(super) const SYNTHETIC_STDIO_INO_BASE: u64 = 0xffff_ffff_0000_0000;

pub(super) const SYNTHETIC_DATAGRAM_INO_BASE: u64 = 0xffff_ffff_1000_0000;

pub(super) const WASI_RIGHT_FD_READ: u64 = 1 << 1;

pub(super) const WASI_RIGHT_FD_WRITE: u64 = 1 << 6;

pub(super) const WASI_RIGHT_FD_ADVISE: u64 = 1 << 7;

pub(super) const WASI_RIGHT_FD_ALLOCATE: u64 = 1 << 8;

pub(super) const WASI_RIGHT_POLL_FD_READWRITE: u64 = 1 << 27;

const WASI_RIGHT_PATH_CREATE_DIRECTORY: u64 = 1 << 9;

const WASI_RIGHT_PATH_CREATE_FILE: u64 = 1 << 10;

const WASI_RIGHT_PATH_REMOVE_DIRECTORY: u64 = 1 << 25;

const WASI_RIGHT_PATH_UNLINK_FILE: u64 = 1 << 26;

pub(super) const WASI_DIRECTORY_RIGHTS: u64 = WASI_RIGHT_PATH_CREATE_DIRECTORY
    | WASI_RIGHT_PATH_CREATE_FILE
    | (1 << 13)
    | (1 << 14)
    | (1 << 18)
    | (1 << 21)
    | WASI_RIGHT_PATH_REMOVE_DIRECTORY
    | WASI_RIGHT_PATH_UNLINK_FILE;

/// Rights that let a directory descriptor mutate the namespace. A read-only
/// preopen drops these from its granted and inheriting rights.
pub(super) const WASI_DIRECTORY_MUTATION_RIGHTS: u64 = WASI_RIGHT_PATH_CREATE_DIRECTORY
    | WASI_RIGHT_PATH_CREATE_FILE
    | WASI_RIGHT_PATH_REMOVE_DIRECTORY
    | WASI_RIGHT_PATH_UNLINK_FILE;

pub(super) const WASI_OFLAG_CREATE: u16 = 1 << 0;

pub(super) const WASI_OFLAG_DIRECTORY: u16 = 1 << 1;

pub(super) const WASI_OFLAG_EXCLUSIVE: u16 = 1 << 2;

pub(super) const WASI_OFLAG_TRUNCATE: u16 = 1 << 3;

pub(super) const WASI_FDFLAG_APPEND: u16 = 1 << 0;

pub(super) const WASI_FDFLAGS_ALL: u16 = 0x1f;

pub(super) const WASI_FSTFLAG_ATIM: u16 = 1 << 0;

pub(super) const WASI_FSTFLAG_ATIM_NOW: u16 = 1 << 1;

pub(super) const WASI_FSTFLAG_MTIM: u16 = 1 << 2;

pub(super) const WASI_FSTFLAG_MTIM_NOW: u16 = 1 << 3;

pub(super) const WASI_FSTFLAGS_ALL: u16 =
    WASI_FSTFLAG_ATIM | WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM | WASI_FSTFLAG_MTIM_NOW;

/// A WASI `timestamp` is unsigned nanoseconds: a time before the epoch (only
/// a native guest can set one) reads as the epoch, never wrapped.
pub(super) fn wasi_timestamp(nanos: i128) -> u64 {
    u64::try_from(nanos.max(0)).unwrap_or(u64::MAX)
}

pub(super) fn wasi_filetype(kind: FsEntryKind) -> u8 {
    match kind {
        FsEntryKind::File => WASI_FILETYPE_REGULAR_FILE,
        FsEntryKind::Directory => WASI_FILETYPE_DIRECTORY,
        FsEntryKind::Symlink => WASI_FILETYPE_SYMBOLIC_LINK,
        // Preview 1 has no FIFO filetype: its enumeration stops at the two
        // socket kinds. `UNKNOWN` is the honest answer — it says "this is not a
        // regular file, a directory, or a symlink" without claiming to be a
        // kind it is not. (A `wasip1` guest cannot create one either: no
        // Preview 1 call makes a FIFO, so one can only arrive through a
        // pre-seeded image.)
        FsEntryKind::Fifo => WASI_FILETYPE_UNKNOWN,
        // A socket node's inode says nothing about stream versus datagram, the
        // distinction Preview 1's two socket kinds draw.
        FsEntryKind::Socket => WASI_FILETYPE_UNKNOWN,
        FsEntryKind::CharDevice => WASI_FILETYPE_CHARACTER_DEVICE,
    }
}

pub(super) fn wasi_call<T>(result: Result<T, WasiHostError>) -> Result<Result<T, i32>, WasmiError> {
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
        ErrorCode::NotPermitted => WASI_ERRNO_PERM,
        // Preview 1 has no ENODATA: a missing attribute is a missing entry.
        ErrorCode::NoData => WASI_ERRNO_NOENT,
        ErrorCode::Range => WASI_ERRNO_RANGE,
        ErrorCode::TooBig => WASI_ERRNO_2BIG,
        ErrorCode::Unsupported => WASI_ERRNO_NOTSUP,
        ErrorCode::Busy => WASI_ERRNO_BUSY,
        ErrorCode::IllegalSeek => WASI_ERRNO_SPIPE,
        ErrorCode::CrossDevice => WASI_ERRNO_XDEV,
        ErrorCode::NoSuchPosition => WASI_ERRNO_NXIO,
        ErrorCode::FileTooBig => WASI_ERRNO_FBIG,
    }
}

pub(super) fn wasi_clock(value: i32) -> Option<WasiClock> {
    match value {
        0 => Some(WasiClock::Realtime),
        1 => Some(WasiClock::Monotonic),
        _ => None,
    }
}

pub(super) fn host_error(error: WasiHostError) -> WasmiError {
    WasmiError::new(error.to_string())
}
