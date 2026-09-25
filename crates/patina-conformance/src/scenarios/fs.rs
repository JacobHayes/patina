//! The filesystem family: files, directories, links and mounts, their
//! metadata, and the libc wrappers over them, in the run directory.
//!
//! Inode identity: an inode label is an identity by number (the comparison
//! labels each `ino` by the event it first appears in), so two objects that
//! share a number read as one. Patina's filesystem does not repeat a number
//! within a run, but the host's does: once an inode's last name and last
//! reference are gone, its number may be handed to the next object created.
//! A stream therefore labels only inodes the kernel keeps distinct: an object
//! whose inode it labeled stays referenced, by a name or a descriptor, until
//! its last creation. A scenario that removes one earlier holds a descriptor
//! on it first (`O_PATH` suffices): a removed inode with a live reference
//! stays allocated.
//!
//! Scoped lookups: a `RESOLVE_BENEATH` or `RESOLVE_IN_ROOT` lookup through
//! `..` answers EAGAIN when any rename or mount on the host races it (v6.8
//! fs/namei.c `handle_dots`), a transient the caller retries. `Probe::openat2`
//! retries that answer unrecorded, as a caller does, and records the final
//! one; a scenario asserts a scoped lookup's settled answer. That is the only
//! lookup the host fails on a system-wide race: elsewhere the kernel retries
//! internally (`d_path`, `d_walk`, the ref-walk fallback on -ECHILD).

pub mod cache;
pub mod chmod;
pub mod copy;
pub mod dirent;
pub mod fifo;
pub mod fortify;
pub mod getdents;
pub mod handles;
pub mod inotify;
pub mod ioctl;
pub mod legacy_paths;
pub mod lfs64;
pub mod libc_io;
pub mod libc_times;
pub mod metadata;
pub mod mount;
pub mod mount_api;
pub mod mount_query;
pub mod names;
pub mod open_tree;
pub mod openat2;
pub mod owner;
pub mod paths;
pub mod posix_fadvise;
pub mod realpath;
pub mod renameat2;
pub mod rw;
pub mod size;
pub mod splice;
pub mod statfs;
pub mod statvfs;
pub mod sync;
pub mod times;
pub mod vectored_io;
pub mod xattr;
