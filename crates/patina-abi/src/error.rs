//! Stable effect error categories and diagnostic display.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Stable error categories crossing the effect boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Denied,
    InvalidInput,
    InvalidHandle,
    MissingDriver,
    NotFound,
    NotReadable,
    NotWritable,
    AlreadyExists,
    IsDirectory,
    NotDirectory,
    DirectoryNotEmpty,
    Io,
    NoSpace,
    Interrupted,
    AlreadyBound,
    Deadlock,
    NoRoute,
    InvalidState,
    ConnectionRefused,
    ConnectionReset,
    BrokenPipe,
    NotConnected,
    /// The operation is not permitted for the calling identity (`EPERM`): a
    /// hard link to a directory, a device node, an owner change to someone else.
    NotPermitted,
    /// The named attribute does not exist (`ENODATA`).
    NoData,
    /// A result does not fit the caller's buffer (`ERANGE`: `getcwd`, an xattr
    /// value larger than the buffer offered).
    Range,
    /// An argument is larger than the kernel accepts (`E2BIG`).
    TooBig,
    /// The operation is not supported by this object or filesystem
    /// (`EOPNOTSUPP`): a mode change on a symlink, an unknown xattr namespace.
    Unsupported,
    /// The object is in use (`EBUSY`): removing the root, a mount point.
    Busy,
    /// A positional operation on an object with no position (`ESPIPE`).
    IllegalSeek,
    /// A link or rename across filesystems (`EXDEV`).
    CrossDevice,
    /// No such position (`ENXIO`): a `SEEK_DATA` with no data at or past the
    /// offset, or a `SEEK_DATA`/`SEEK_HOLE` at or past the end of the file.
    NoSuchPosition,
    /// A file would pass its filesystem's size limit (`EFBIG`): a write that
    /// starts at or past it, a truncate or allocation that reaches past it.
    FileTooBig,
}

/// A typed effect failure suitable for traces and user-facing diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectError {
    pub code: ErrorCode,
    pub message: String,
}

impl EffectError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn missing_driver(capability: &str) -> Self {
        Self::new(
            ErrorCode::MissingDriver,
            format!("no {capability} driver is installed"),
        )
    }
}

impl fmt::Display for EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ErrorCodeDisplay(self.code), self.message)
    }
}

impl std::error::Error for EffectError {}

struct ErrorCodeDisplay(ErrorCode);

impl fmt::Display for ErrorCodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self.0 {
            ErrorCode::Denied => "denied",
            ErrorCode::InvalidInput => "invalid_input",
            ErrorCode::InvalidHandle => "invalid_handle",
            ErrorCode::MissingDriver => "missing_driver",
            ErrorCode::NotFound => "not_found",
            ErrorCode::NotReadable => "not_readable",
            ErrorCode::NotWritable => "not_writable",
            ErrorCode::AlreadyExists => "already_exists",
            ErrorCode::IsDirectory => "is_directory",
            ErrorCode::NotDirectory => "not_directory",
            ErrorCode::DirectoryNotEmpty => "directory_not_empty",
            ErrorCode::Io => "io",
            ErrorCode::NoSpace => "no_space",
            ErrorCode::Interrupted => "interrupted",
            ErrorCode::AlreadyBound => "already_bound",
            ErrorCode::Deadlock => "deadlock",
            ErrorCode::NoRoute => "no_route",
            ErrorCode::InvalidState => "invalid_state",
            ErrorCode::ConnectionRefused => "connection_refused",
            ErrorCode::ConnectionReset => "connection_reset",
            ErrorCode::BrokenPipe => "broken_pipe",
            ErrorCode::NotConnected => "not_connected",
            ErrorCode::NotPermitted => "not_permitted",
            ErrorCode::NoData => "no_data",
            ErrorCode::Range => "range",
            ErrorCode::TooBig => "too_big",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Busy => "busy",
            ErrorCode::IllegalSeek => "illegal_seek",
            ErrorCode::CrossDevice => "cross_device",
            ErrorCode::NoSuchPosition => "no_such_position",
            ErrorCode::FileTooBig => "file_too_big",
        };
        f.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_have_stable_display_names() {
        let error = EffectError::missing_driver("filesystem");
        assert_eq!(
            error.to_string(),
            "missing_driver: no filesystem driver is installed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::ConnectionRefused, "dial failed").to_string(),
            "connection_refused: dial failed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::ConnectionReset, "peer reset").to_string(),
            "connection_reset: peer reset"
        );
        assert_eq!(
            EffectError::new(ErrorCode::BrokenPipe, "write closed").to_string(),
            "broken_pipe: write closed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::NotConnected, "no peer").to_string(),
            "not_connected: no peer"
        );
    }
}
