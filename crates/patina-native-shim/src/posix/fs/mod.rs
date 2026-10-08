//! Filesystem ABI adapters; all effects use the existing filesystem model.
use super::{at, cancel, error, model_result, size_result};
#[cfg(target_os = "linux")]
use crate::paths::RESOLVE_EMPTY_PATH;
use crate::paths::{AT_FDCWD, RESOLVE_NOFOLLOW};
use core::ffi::{c_char, c_int};
mod directory;
pub(super) mod metadata;
mod paths;
mod times;
#[cfg(target_os = "linux")]
mod volume;
#[cfg(target_os = "linux")]
mod xattr;

#[cfg(target_os = "linux")]
const AT_EMPTY_PATH: c_int = libc::AT_EMPTY_PATH;
#[cfg(target_os = "macos")]
const AT_EMPTY_PATH: c_int = 0;
#[cfg(target_os = "linux")]
const AT_FLAG_REFUSAL: c_int = libc::EINVAL;
#[cfg(target_os = "macos")]
const AT_FLAG_REFUSAL: c_int = libc::ENOSYS;
