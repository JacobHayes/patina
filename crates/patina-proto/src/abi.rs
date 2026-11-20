//! Kernel structure layouts and flag values that differ by architecture. Everything else the
//! runtime and the supervisor use from the kernel's ABI (`statx`, `statfs`, `dirent64`,
//! `sigaction`, `siginfo`, `stack_t`, `struct flock`, `msghdr`, `iovec`, `sockaddr`, `rlimit`,
//! `rusage`, `sysinfo`, `timespec`, errno and signal numbers, `ioctl`, `fcntl`, socket and `mmap`
//! constants but `MAP_32BIT`) has one layout and one value on x86_64 and arm64;
//! `files/03-differential`, `files/09-efault` and `net/*` compare with the native kernel on each.

/// `e_machine` of this architecture's executables: `EM_X86_64`, `EM_AARCH64`.
#[cfg(target_arch = "x86_64")]
pub const ELF_MACHINE: u16 = 62;
#[cfg(target_arch = "aarch64")]
pub const ELF_MACHINE: u16 = 183;

/// `struct epoll_event`: `events` (4 bytes) at 0 and `data` (8 bytes) at `DATA`. Packed (12 bytes)
/// on x86_64; naturally aligned (16) elsewhere, where bytes 4 to 8 are padding the kernel
/// neither reads nor writes, so they hold whatever the program left there.
pub mod epoll {
    #[cfg(target_arch = "x86_64")]
    pub const SIZE: u32 = 12;
    #[cfg(target_arch = "x86_64")]
    pub const DATA: u32 = 4;
    #[cfg(target_arch = "aarch64")]
    pub const SIZE: u32 = 16;
    #[cfg(target_arch = "aarch64")]
    pub const DATA: u32 = 8;
    /// No padding: `data` follows `events` directly and ends the record.
    pub const PACKED: bool = DATA == 4 && SIZE == DATA + 8;
}

/// `mmap`'s `MAP_32BIT` (a mapping below 2 GiB): x86_64 only (the generic kernel ignores that
/// bit for a private mapping).
#[cfg(target_arch = "x86_64")]
pub const MAP_32BIT: Option<u64> = Some(0x40);
#[cfg(target_arch = "aarch64")]
pub const MAP_32BIT: Option<u64> = None;

/// The least alternate signal stack `sigaltstack` accepts (the kernel's `MINSIGSTKSZ`).
#[cfg(target_arch = "x86_64")]
pub const MINSIGSTKSZ: u64 = 2048;
#[cfg(target_arch = "aarch64")]
pub const MINSIGSTKSZ: u64 = 5120;

/// `struct stat`. Read only through `Stat`'s accessors: the mode, link count, owner and device
/// number sit differently in the two layouts. The words both share: 0 the device, 1 the inode,
/// 6 the size, 8 the blocks, 9 to 14 the three times (seconds, nanoseconds).
pub mod stat {
    /// x86_64: 144 bytes; `nlink` a word at 2, then `mode`, `uid`, `gid` as 32-bit fields,
    /// `rdev` at word 5.
    #[cfg(target_arch = "x86_64")]
    const WORDS: usize = 18;
    /// arm64 (the generic layout): 128 bytes; `mode`, `nlink`, `uid`, `gid` as 32-bit fields
    /// from byte 16, then `rdev`.
    #[cfg(target_arch = "aarch64")]
    const WORDS: usize = 16;

    /// Bytes of a `struct stat`.
    pub const SIZE: u32 = (WORDS * 8) as u32;

    /// Indexes of `uid` and `gid` as 32-bit fields.
    #[cfg(target_arch = "x86_64")]
    const UID32: usize = 7;
    #[cfg(target_arch = "aarch64")]
    const UID32: usize = 6;
    const GID32: usize = UID32 + 1;

    /// Word offsets of the size, the block size (a word on x86_64; a 32-bit field then
    /// padding on arm64) and the 512-byte block count.
    pub const SIZE_W: usize = 6;
    pub const BLKSIZE: usize = 7;
    pub const BLOCKS: usize = 8;

    /// Word offsets of the access, modification and change times (seconds; nanoseconds follow).
    pub const ATIME: usize = 9;
    pub const MTIME: usize = 11;
    pub const CTIME: usize = 13;

    /// A kernel `struct stat`, by value.
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct Stat([u64; WORDS]);

    impl Stat {
        pub const fn zeroed() -> Stat {
            Stat([0; WORDS])
        }
        /// For the kernel to fill.
        pub fn as_mut_ptr(&mut self) -> *mut u64 {
            self.0.as_mut_ptr()
        }
        pub fn dev(&self) -> u64 {
            self.0[0]
        }
        pub fn ino(&self) -> u64 {
            self.0[1]
        }
        pub fn size(&self) -> u64 {
            self.0[6]
        }
        /// Allocated 512-byte blocks.
        pub fn blocks(&self) -> u64 {
            self.0[BLOCKS]
        }
        #[cfg(target_arch = "x86_64")]
        pub fn mode(&self) -> u32 {
            self.0[3] as u32
        }
        #[cfg(target_arch = "aarch64")]
        pub fn mode(&self) -> u32 {
            self.0[2] as u32
        }
        #[cfg(target_arch = "x86_64")]
        pub fn nlink(&self) -> u64 {
            self.0[2]
        }
        #[cfg(target_arch = "aarch64")]
        pub fn nlink(&self) -> u64 {
            self.0[2] >> 32
        }
        /// The device number of a device file.
        #[cfg(target_arch = "x86_64")]
        pub fn rdev(&self) -> u64 {
            self.0[5]
        }
        #[cfg(target_arch = "aarch64")]
        pub fn rdev(&self) -> u64 {
            self.0[4]
        }
        pub fn uid(&self) -> u32 {
            (self.0[UID32 / 2] >> (32 * (UID32 % 2))) as u32
        }
        pub fn gid(&self) -> u32 {
            (self.0[GID32 / 2] >> (32 * (GID32 % 2))) as u32
        }
        /// A `struct stat` with the given fields, a block size and all three times `secs`
        /// seconds, the others 0.
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            dev: u64,
            ino: u64,
            nlink: u32,
            mode: u32,
            uid: u32,
            gid: u32,
            blksize: u32,
            secs: u64,
        ) -> Stat {
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
            // The block size: a word on x86_64, a 32-bit field (and padding) on arm64.
            st[7] = blksize as u64;
            for t in [ATIME, MTIME, CTIME] {
                st[t] = secs;
            }
            Stat(st)
        }
    }

    /// Set the link count of the `struct stat` at `p` (memory the kernel just filled).
    ///
    /// # Safety
    /// `p` points to a writable `struct stat`.
    pub unsafe fn set_nlink(p: *mut u64, n: u32) {
        #[cfg(target_arch = "x86_64")]
        {
            *p.add(2) = n as u64;
        }
        #[cfg(target_arch = "aarch64")]
        {
            *p.add(2) = (*p.add(2) & 0xffff_ffff) | (n as u64) << 32;
        }
    }

    /// The file type and permission bits of the `struct stat` at `p`.
    ///
    /// # Safety
    /// `p` points to a `struct stat`.
    pub unsafe fn mode_at(p: *const u64) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            *p.add(3) as u32
        }
        #[cfg(target_arch = "aarch64")]
        {
            *p.add(2) as u32
        }
    }

    /// Set the owner of the `struct stat` at `p` (memory the kernel just filled).
    ///
    /// # Safety
    /// `p` points to a writable `struct stat`.
    pub unsafe fn set_owner(p: *mut u8, uid: u32, gid: u32) {
        let ids = p as *mut u32;
        *ids.add(UID32) = uid;
        *ids.add(GID32) = gid;
    }
}

/// The `open` flags whose values differ by architecture (the others are the same).
/// `O_LARGEFILE` (0o100000 on x86_64, 0o400000 on arm64) is not named: a 64-bit kernel sets it
/// on every open file, so it shows in `F_GETFL` and is passed back by `F_SETFL`, and nothing
/// in the runtime tests it.
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
