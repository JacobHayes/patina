//! The memory devices the shim owns: 6.8's `drivers/char/mem.c` nodes
//! `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and `/dev/urandom`,
//! each a root-owned `0666` character device on devtmpfs. Darwin has no
//! `/dev/full`, so there the path names nothing.
//!
//! The resolver recognizes their paths lexically, before the walk, so they
//! exist whether or not the image has a `/dev` (`paths::Virtual::MemDevice`).
//! A descriptor of one is an [`FdKind::MemDevice`](crate::fdtable::FdKind)
//! description whose handle is the device's [`MemDevice::handle`].
//!
//! What each answers ([`read`], [`write`]; `mem.c`'s `null_fops`,
//! `zero_fops` and `full_fops`, `random.c`'s `random_fops` and
//! `urandom_fops`): `null` reads end of file and takes every write; `zero`
//! reads zeros and takes every write; `full` reads zeros and refuses every
//! write (`ENOSPC`); `random` and `urandom` read the run's deterministic
//! entropy, the stream `getrandom` draws. A `random` read is a blocking
//! `getrandom`'s, so it proves the pool ready; a nonblocking one never
//! answers `EAGAIN`, since a pool that is ready by the read is one 6.8 can
//! have. A `urandom` read reads regardless of the pool. Writing to the
//! entropy devices (which feeds the input pool) is not modeled.

use std::ffi::c_void;

#[cfg(any(target_os = "linux", patina_posix_exports))]
use crate::PatinaMetadata;
use crate::entropy::{self, EntropyWait};
use crate::fdtable::Resolved;
use crate::{EBADF, EFAULT, EOVERFLOW, O_READ, O_WRITE, fail, set_errno};

/// `ENOSPC`, what every write to `/dev/full` answers.
#[cfg(target_os = "linux")]
const ENOSPC: i32 = 28;

/// One of the memory devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemDevice {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
}

impl MemDevice {
    /// Every device, in minor-number order.
    pub(crate) const ALL: [MemDevice; 5] = [
        MemDevice::Null,
        MemDevice::Zero,
        MemDevice::Full,
        MemDevice::Random,
        MemDevice::Urandom,
    ];

    /// The path that names it.
    pub(crate) const fn path(self) -> &'static str {
        match self {
            MemDevice::Null => "/dev/null",
            MemDevice::Zero => "/dev/zero",
            MemDevice::Full => "/dev/full",
            MemDevice::Random => "/dev/random",
            MemDevice::Urandom => "/dev/urandom",
        }
    }

    /// Whether the platform has it: Darwin has no `/dev/full`.
    pub(crate) const fn exists(self) -> bool {
        !matches!(self, MemDevice::Full) || cfg!(target_os = "linux")
    }

    /// The device named by the canonical `path`, if one is.
    pub(crate) fn at(path: &str) -> Option<MemDevice> {
        MemDevice::ALL
            .into_iter()
            .find(|device| device.exists() && device.path() == path)
    }

    /// Its descriptor handle: its index in [`MemDevice::ALL`].
    pub(crate) const fn handle(self) -> u64 {
        self as u64
    }

    /// The device a descriptor handle names.
    pub(crate) fn of_handle(handle: u64) -> MemDevice {
        MemDevice::ALL[handle as usize]
    }

    /// The device whose node is devtmpfs's inode `ino`, if one is.
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    pub(crate) fn of_ino(ino: u64) -> Option<MemDevice> {
        MemDevice::ALL
            .into_iter()
            .find(|device| device.ino() == ino)
    }

    /// Whether reads draw entropy.
    pub(crate) const fn draws_entropy(self) -> bool {
        matches!(self, MemDevice::Random | MemDevice::Urandom)
    }

    /// `mem`'s device numbers: major 1, minors 3, 5, 7, 8 and 9.
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    const fn device(self) -> (u32, u32) {
        match self {
            MemDevice::Null => (1, 3),
            MemDevice::Zero => (1, 5),
            MemDevice::Full => (1, 7),
            MemDevice::Random => (1, 8),
            MemDevice::Urandom => (1, 9),
        }
    }

    /// Its inode number on devtmpfs, as the pinned host's nodes read live
    /// (devtmpfs numbers its nodes in the order boot makes them).
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    const fn ino(self) -> u64 {
        match self {
            MemDevice::Null => 5,
            MemDevice::Zero => 7,
            MemDevice::Full => 8,
            MemDevice::Random => 9,
            MemDevice::Urandom => 10,
        }
    }

    /// Its node: a root-owned `0666` character device on devtmpfs, one link,
    /// empty; every time the instant it was first used in the run (boot
    /// makes the nodes; the model keeps the first use).
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    pub(crate) fn metadata(self) -> PatinaMetadata {
        let now = crate::fs_time_unrecorded();
        let made = {
            let mut made = MADE.lock();
            let slot = &mut made[self.handle() as usize];
            if *slot == 0 {
                *slot = now;
            }
            *slot
        };
        let made = crate::PatinaTimestamp::from_nanos(i128::from(made));
        let (major, minor) = self.device();
        PatinaMetadata {
            kind: crate::PATINA_ENTRY_CHAR,
            mode: 0o666,
            nlink: 1,
            fs: crate::PATINA_FS_DEVTMPFS,
            rdev_major: major,
            rdev_minor: minor,
            length: 0,
            blocks: 0,
            ino: self.ino(),
            atime: made,
            mtime: made,
            ctime: made,
            btime: made,
        }
    }
}

/// `read(2)` of the device a description names, after `vfs_read`'s checks
/// (`FMODE_READ`, then the buffer's range) and its `MAX_RW_COUNT` clamp.
/// Zeros are cleared a page at a time (`read_zero`) and entropy is drawn as
/// [`entropy::fill`] draws it, so a copy that faults partway answers the
/// bytes before it, or `EFAULT` when there are none. XNU's `mmrw` and
/// `random_read` return the copy's `EFAULT`, which `dofileread` keeps after
/// partial progress, so a short read there is `EFAULT`.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub(crate) unsafe fn read(resolved: &Resolved, destination: *mut c_void, length: usize) -> isize {
    if resolved.status & O_READ == 0 {
        return fail(EBADF) as isize;
    }
    #[cfg(target_os = "linux")]
    if !crate::uaccess::access_ok(destination as usize, length) {
        return fail(EFAULT) as isize;
    }
    #[cfg(target_os = "linux")]
    let length = length.min(entropy::MAX_RW_COUNT);
    let device = MemDevice::of_handle(resolved.handle);
    // The entropy devices take their boundary point drawing; the others take
    // it here, so a thread looping on one still yields and shows its time.
    if !device.draws_entropy()
        && let Err(errno) = crate::runtime::boundary_point()
    {
        return fail(errno) as isize;
    }
    let filled = match device {
        // End of file before the copy-length check below.
        MemDevice::Null => {
            set_errno(0);
            return 0;
        }
        MemDevice::Zero | MemDevice::Full => zero_fill(destination as usize, length),
        // SAFETY: forwarded from this function's own contract.
        MemDevice::Random => unsafe { entropy::fill(destination, length, EntropyWait::UntilReady) },
        // SAFETY: as above.
        MemDevice::Urandom => unsafe { entropy::fill(destination, length, EntropyWait::Never) },
    };
    match filled {
        #[cfg(target_os = "macos")]
        Ok(written) if written < length => fail(EFAULT) as isize,
        Ok(written) => {
            set_errno(0);
            isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno.get()) as isize,
    }
}

/// Clear `length` guest bytes at `address` a page at a time: the bytes
/// cleared before the first that faults, or `EFAULT` when none were.
fn zero_fill(address: usize, length: usize) -> crate::abi::SysResult<usize> {
    const PAGE: [u8; 4096] = [0; 4096];
    let mut cleared = 0;
    while cleared < length {
        let chunk = (length - cleared).min(PAGE.len());
        let landed = entropy::write_prefix(address.wrapping_add(cleared), &PAGE[..chunk]);
        cleared += landed;
        if landed < chunk {
            break;
        }
    }
    if cleared == 0 && length != 0 {
        return Err(crate::abi::failed(EFAULT));
    }
    Ok(cleared)
}

/// `write(2)` to the device a description names, after `vfs_write`'s checks
/// (`FMODE_WRITE`, then the buffer's range) and its `MAX_RW_COUNT` clamp:
/// `null` and `zero` take every byte unread (`write_null`), `full` refuses
/// them (`write_full`). An entropy device is never open for writing.
pub(crate) fn write(resolved: &Resolved, source: *const c_void, length: usize) -> isize {
    if resolved.status & O_WRITE == 0 {
        return fail(EBADF) as isize;
    }
    #[cfg(target_os = "linux")]
    if !crate::uaccess::access_ok(source as usize, length) {
        return fail(EFAULT) as isize;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = source;
    #[cfg(target_os = "linux")]
    let length = length.min(entropy::MAX_RW_COUNT);
    let device = MemDevice::of_handle(resolved.handle);
    if !device.draws_entropy()
        && let Err(errno) = crate::runtime::boundary_point()
    {
        return fail(errno) as isize;
    }
    match device {
        MemDevice::Null | MemDevice::Zero => {
            set_errno(0);
            isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        #[cfg(target_os = "linux")]
        MemDevice::Full => fail(ENOSPC) as isize,
        device => crate::paths::Virtual::MemDevice(device).unmodeled("a write"),
    }
}

/// When each device's node was made, in nanoseconds on the virtual clock;
/// 0 until first used.
#[cfg(any(target_os = "linux", patina_posix_exports))]
static MADE: crate::SpinMutex<[u64; MemDevice::ALL.len()]> =
    crate::SpinMutex::new([0; MemDevice::ALL.len()]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_device_is_found_at_its_path_and_through_its_handle() {
        for device in MemDevice::ALL.into_iter().filter(|device| device.exists()) {
            assert_eq!(MemDevice::at(device.path()), Some(device));
            assert_eq!(MemDevice::of_handle(device.handle()), device);
            #[cfg(any(target_os = "linux", patina_posix_exports))]
            assert_eq!(MemDevice::of_ino(device.metadata().ino), Some(device));
        }
        assert_eq!(MemDevice::at("/dev/kmsg"), None);
    }
}
