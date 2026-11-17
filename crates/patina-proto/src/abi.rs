//! Kernel structure layouts that differ by architecture.

/// `struct stat` as 64-bit words, and its fields by name. The words both layouts share: 0 the
/// device, 1 the inode, 6 the size, 7 the block size (low half), 8 the blocks, 9 to 14 the
/// three times (seconds, nanoseconds). The mode, link count and owner sit differently.
pub mod stat {
    /// x86_64: 144 bytes; `nlink` a word at 2, then `mode`, `uid`, `gid` as 32-bit fields.
    #[cfg(target_arch = "x86_64")]
    pub const WORDS: usize = 18;
    /// arm64 (the generic layout): 128 bytes; `mode`, `nlink`, `uid`, `gid` as 32-bit fields
    /// from byte 16, then `rdev`.
    #[cfg(target_arch = "aarch64")]
    pub const WORDS: usize = 16;

    pub type Stat = [u64; WORDS];

    /// Indexes of `uid` and `gid` as 32-bit fields.
    #[cfg(target_arch = "x86_64")]
    pub const UID32: usize = 7;
    #[cfg(target_arch = "aarch64")]
    pub const UID32: usize = 6;
    pub const GID32: usize = UID32 + 1;

    #[cfg(target_arch = "x86_64")]
    pub fn mode(st: &Stat) -> u32 {
        st[3] as u32
    }
    #[cfg(target_arch = "aarch64")]
    pub fn mode(st: &Stat) -> u32 {
        st[2] as u32
    }

    #[cfg(target_arch = "x86_64")]
    pub fn nlink(st: &Stat) -> u64 {
        st[2]
    }
    #[cfg(target_arch = "aarch64")]
    pub fn nlink(st: &Stat) -> u64 {
        st[2] >> 32
    }

    /// The device number of a device file.
    #[cfg(target_arch = "x86_64")]
    pub fn rdev(st: &Stat) -> u64 {
        st[5]
    }
    #[cfg(target_arch = "aarch64")]
    pub fn rdev(st: &Stat) -> u64 {
        st[4]
    }

    pub fn uid(st: &Stat) -> u32 {
        (st[UID32 / 2] >> (32 * (UID32 % 2))) as u32
    }
    pub fn gid(st: &Stat) -> u32 {
        (st[GID32 / 2] >> (32 * (GID32 % 2))) as u32
    }

    /// A `struct stat` with the given fields, the others 0.
    pub fn new(dev: u64, ino: u64, nlink: u32, mode: u32, uid: u32, gid: u32) -> Stat {
        let mut st = [0u64; WORDS];
        st[0] = dev;
        st[1] = ino;
        #[cfg(target_arch = "x86_64")]
        {
            st[2] = nlink as u64;
            st[3] = mode as u64;
        }
        #[cfg(target_arch = "aarch64")]
        {
            st[2] = mode as u64 | (nlink as u64) << 32;
        }
        st[UID32 / 2] |= (uid as u64) << (32 * (UID32 % 2));
        st[GID32 / 2] |= (gid as u64) << (32 * (GID32 % 2));
        st
    }
}

/// The `open` flags whose values differ by architecture (the others are the same).
pub mod open {
    #[cfg(target_arch = "x86_64")]
    pub const O_DIRECT: u64 = 0o40000;
    #[cfg(target_arch = "x86_64")]
    pub const O_DIRECTORY: u64 = 0o200000;
    #[cfg(target_arch = "x86_64")]
    pub const O_NOFOLLOW: u64 = 0o400000;

    #[cfg(target_arch = "aarch64")]
    pub const O_DIRECTORY: u64 = 0o40000;
    #[cfg(target_arch = "aarch64")]
    pub const O_NOFOLLOW: u64 = 0o100000;
    #[cfg(target_arch = "aarch64")]
    pub const O_DIRECT: u64 = 0o200000;
}
