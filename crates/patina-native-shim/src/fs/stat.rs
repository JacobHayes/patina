//! Shared pure computations for the two stat adapters.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::metadata::{
    PATINA_ENTRY_ANON, PATINA_ENTRY_CHAR, PATINA_ENTRY_DIRECTORY, PATINA_ENTRY_FIFO,
    PATINA_ENTRY_SOCKET, PATINA_ENTRY_SYMLINK, PatinaMetadata,
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

/// The size and capacity of the one deterministic volume every path names: a
/// constant, so it is the same on record and replay and on every host. Each
/// platform's `statfs` describes this volume in its own vocabulary: an
/// ext4-like filesystem on Linux (`src/volume.rs`), an APFS volume on macOS
/// (`src/posix/fs/darwin_volume.rs`).
pub(crate) struct VolumeGeometry {
    /// The block size: `statfs`'s `f_bsize` and every file's `st_blksize`.
    pub(crate) block_size: u32,
    pub(crate) blocks: u64,
    pub(crate) free_blocks: u64,
    pub(crate) files: u64,
    pub(crate) free_files: u64,
}

/// The volume's geometry: 4 GiB of 4 KiB blocks, half of them free, and
/// 2^20 inodes, half of them free.
pub(crate) const VOLUME: VolumeGeometry = VolumeGeometry {
    block_size: 4096,
    blocks: 1 << 20,
    free_blocks: 1 << 19,
    files: 1 << 20,
    free_files: 1 << 19,
};

/// `st_blksize`: the virtual volume's 4 KiB block, or the 1 KiB block of
/// procfs.
pub(crate) fn stat_blksize(values: &PatinaMetadata) -> u64 {
    if is_proc(values.fs) {
        1024
    } else {
        u64::from(VOLUME.block_size)
    }
}

/// Whether `fs` is procfs (Linux).
fn is_proc(fs: u32) -> bool {
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    return fs == super::metadata::PATINA_FS_PROC || fs == super::metadata::PATINA_FS_PROC_OWN;
    #[cfg(not(any(target_os = "linux", patina_posix_exports)))]
    {
        let _ = fs;
        false
    }
}
