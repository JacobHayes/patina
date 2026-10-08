//! Shared pure computations for the two stat adapters.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::metadata::{
    PATINA_ENTRY_ANON, PATINA_ENTRY_CHAR, PATINA_ENTRY_DIRECTORY, PATINA_ENTRY_FIFO,
    PATINA_ENTRY_SOCKET, PATINA_ENTRY_SYMLINK, PATINA_FS_DEVPTS, PatinaMetadata,
};

/// `st_mode`: file type bits ORed with the node's permission bits.
pub(crate) fn stat_mode(values: &PatinaMetadata) -> libc::mode_t {
    let kind = match values.kind {
        PATINA_ENTRY_ANON => 0,
        PATINA_ENTRY_DIRECTORY => libc::S_IFDIR,
        PATINA_ENTRY_SYMLINK => libc::S_IFLNK,
        PATINA_ENTRY_FIFO => libc::S_IFIFO,
        PATINA_ENTRY_SOCKET => libc::S_IFSOCK,
        PATINA_ENTRY_CHAR => libc::S_IFCHR,
        _ => libc::S_IFREG,
    };
    kind | (values.mode & 0o7777) as libc::mode_t
}

/// `st_blksize`: the virtual volume's 4 KiB block, or devpts' 1 KiB block.
pub(crate) fn stat_blksize(values: &PatinaMetadata) -> u64 {
    if values.fs == PATINA_FS_DEVPTS {
        1024
    } else {
        4096
    }
}
