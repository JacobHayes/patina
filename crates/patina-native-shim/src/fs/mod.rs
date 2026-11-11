//! Filesystem open, metadata, directory, and namespace entry points.

use crate::*;

#[cfg(any(target_os = "linux", patina_posix_exports))]
mod dirs;
mod metadata;
mod namespace;
mod open;
#[cfg(any(target_os = "linux", patina_posix_exports))]
mod stat;

#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) use dirs::*;
pub use metadata::*;
pub use namespace::*;
pub use open::*;
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) use stat::*;

/// Tell the supervisor, on the run's facts, that an open or a stat of an
/// absolute path found nothing there (`Context::note_missing_path`): the
/// supervisor checks after the run whether the host has that file, so a test
/// that read a host path the simulated filesystem was never given is flagged
/// as a likely artifact. The guest's answer is unchanged, and nothing it can
/// observe depends on the note. Relative paths and paths that are not UTF-8
/// are not noted.
///
/// # Safety
/// `path` must be null or a readable NUL-terminated string.
unsafe fn note_missing(result: c_int, path: *const c_char) {
    if result != -1 || crate::LAST_ERRNO.with(core::cell::Cell::get) != ENOENT || path.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    let bytes = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    if bytes.first() != Some(&b'/') {
        return;
    }
    // The guest's errno is projected from LAST_ERRNO after this returns; the
    // note's allocation must not be able to change it.
    let errno = crate::LAST_ERRNO.with(core::cell::Cell::get);
    if let Ok(path) = core::str::from_utf8(bytes)
        && let Some(context) = slot().lock().as_mut()
    {
        context.bookkeeping().note_missing_path(path);
    }
    crate::LAST_ERRNO.with(|value| value.set(errno));
}
