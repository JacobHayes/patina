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
