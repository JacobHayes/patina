//! Filesystem metadata, ownership and allocation.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// The `PATINA_ENTRY_*` wire values (`include/patina_native.h`). The C side ORs
/// the corresponding `S_IF*` bit onto the entry's permission bits.
pub(crate) const PATINA_ENTRY_FILE: u32 = 1;
pub(crate) const PATINA_ENTRY_DIRECTORY: u32 = 2;
pub(crate) const PATINA_ENTRY_SYMLINK: u32 = 3;
pub(crate) const PATINA_ENTRY_FIFO: u32 = 4;
pub(crate) const PATINA_ENTRY_SOCKET: u32 = 5;
pub(crate) const PATINA_ENTRY_CHAR: u32 = 6;
/// The anonymous inode's kind (`alloc_anon_inode`: permission bits alone,
/// no file-type bits).
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_ENTRY_ANON: u32 = 7;

pub(crate) fn metadata_kind(kind: FsEntryKind) -> u32 {
    match kind {
        FsEntryKind::File => PATINA_ENTRY_FILE,
        FsEntryKind::Directory => PATINA_ENTRY_DIRECTORY,
        FsEntryKind::Symlink => PATINA_ENTRY_SYMLINK,
        FsEntryKind::Fifo => PATINA_ENTRY_FIFO,
        FsEntryKind::Socket => PATINA_ENTRY_SOCKET,
        FsEntryKind::CharDevice => PATINA_ENTRY_CHAR,
    }
}

/// The `PATINA_FS_*` wire values: which filesystem a node is on. The
/// deterministic volume holds every entry a path can name; an anonymous pipe's
/// node is on pipefs and a socket's on sockfs, as on Linux.
pub(crate) const PATINA_FS_VOLUME: u32 = 0;
pub(crate) const PATINA_FS_PIPEFS: u32 = 1;
pub(crate) const PATINA_FS_SOCKFS: u32 = 2;
/// A namespace file's nsfs inode (`crate::nsfs`): root's, on device 0:4.
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_FS_NSFS: u32 = 3;
/// A memory device's node (`memdev::MemDevice::metadata`): root's, on
/// devtmpfs (0:5).
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_FS_DEVTMPFS: u32 = 4;
/// 6.8's one anonymous inode (`volume::anon_inode_metadata`), which every
/// eventfd, timerfd, signalfd, epoll, inotify and pidfd
/// descriptor is a file on: root's, on anon_inodefs (0:15).
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_FS_ANON_INODE: u32 = 7;
/// A procfs node root owns (`crate::procfs`: its root, `self`, the
/// machine-wide files, init's directory and files), on procfs (0:25).
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_FS_PROC: u32 = 9;
/// A guest process's procfs directory and files: the process's own, so
/// the caller's, on procfs.
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) const PATINA_FS_PROC_OWN: u32 = 10;

/// The `(major, minor)` device a `PATINA_FS_*` filesystem reports through
/// `st_dev`/`stx_dev_*` (`PATINA_*_DEV_*` in `patina_native.h`): the volume is
/// an ext4-like filesystem on block device 8:1, pipefs and sockfs anonymous
/// devices of their own.
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) fn fs_device(fs: u32) -> (u32, u32) {
    match fs {
        PATINA_FS_PIPEFS => (0, 14),
        PATINA_FS_SOCKFS => (0, 8),
        PATINA_FS_NSFS => (0, 4),
        PATINA_FS_DEVTMPFS => (0, 5),
        PATINA_FS_ANON_INODE => (0, 15),
        PATINA_FS_PROC | PATINA_FS_PROC_OWN => (0, 25),
        _ => (8, 1),
    }
}

/// The C face of a metadata record (`struct patina_metadata` in
/// `include/patina_native.h`): what the stat family on both doors fills a
/// `struct stat`/`struct statx` from. Every field is a modeled fact; the owner
/// is not here because it is a property of the one identity the runtime
/// models, read through [`patina_uid`]/[`patina_gid`], never per entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PatinaMetadata {
    /// A `PATINA_ENTRY_*` kind.
    pub kind: u32,
    /// The permission bits (`0o7777`) WITHOUT the file-type bits `kind` carries.
    pub mode: u32,
    pub nlink: u32,
    /// The `PATINA_FS_*` filesystem the node is on, which decides the device
    /// `st_dev` reports.
    pub fs: u32,
    /// A device node's device (`st_rdev`); 0 for any other node.
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub length: u64,
    /// The 512-byte units the node has allocated (`st_blocks`).
    pub blocks: u64,
    pub ino: u64,
    pub atime: PatinaTimestamp,
    pub mtime: PatinaTimestamp,
    pub ctime: PatinaTimestamp,
    pub btime: PatinaTimestamp,
}

/// A timestamp across the C boundary (`struct patina_timestamp`), as the
/// kernel's `timespec64` holds one: signed seconds and nanoseconds in
/// `[0, 1e9)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PatinaTimestamp {
    pub sec: i64,
    pub nsec: i64,
}

mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::PatinaTimestamp {
        sec: i64,
        nsec: i64
    });
    crate::plain!(super::PatinaMetadata {
        kind: u32,
        mode: u32,
        nlink: u32,
        fs: u32,
        rdev_major: u32,
        rdev_minor: u32,
        length: u64,
        blocks: u64,
        ino: u64,
        atime: super::PatinaTimestamp,
        mtime: super::PatinaTimestamp,
        ctime: super::PatinaTimestamp,
        btime: super::PatinaTimestamp,
    });
}

const NANOS_PER_SECOND: i128 = 1_000_000_000;

impl PatinaTimestamp {
    /// Signed nanoseconds since the epoch, split with the nanoseconds never
    /// negative (-1 ns is second -1, nanosecond 999999999).
    pub(crate) fn from_nanos(nanos: i128) -> Self {
        let sec = nanos.div_euclid(NANOS_PER_SECOND);
        Self {
            sec: i64::try_from(sec).unwrap_or(if sec < 0 { i64::MIN } else { i64::MAX }),
            nsec: nanos.rem_euclid(NANOS_PER_SECOND) as i64,
        }
    }

    fn nanos(self) -> i128 {
        i128::from(self.sec) * NANOS_PER_SECOND + i128::from(self.nsec)
    }
}

fn write_metadata(metadata: patina_dst_abi::FsMetadata, out: *mut PatinaMetadata) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: the pointer was checked and is required to be writable by the C
    // ABI contract.
    unsafe {
        out.write(PatinaMetadata {
            kind: metadata_kind(metadata.kind),
            mode: metadata.mode,
            nlink: metadata.nlink,
            fs: PATINA_FS_VOLUME,
            rdev_major: 0,
            rdev_minor: 0,
            length: metadata.len,
            blocks: metadata.blocks,
            ino: metadata.ino,
            atime: PatinaTimestamp::from_nanos(metadata.atime_nanos),
            mtime: PatinaTimestamp::from_nanos(metadata.mtime_nanos),
            ctime: PatinaTimestamp::from_nanos(metadata.ctime_nanos),
            btime: PatinaTimestamp::from_nanos(metadata.btime_nanos),
        });
    }
    0
}

#[unsafe(no_mangle)]
/// The caller's pid, what `getpid` answers on both doors: its process's in
/// the pid namespace's table on Linux (`identity::Process`); on macOS, the
/// one process the run starts.
pub extern "C" fn patina_pid() -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    return crate::identity::Process::current().pid();
    #[cfg(not(target_os = "linux"))]
    return registry::ROOT_PID as i32;
}

#[unsafe(no_mangle)]
/// The caller's parent, what `getppid` answers: the root process's is the
/// pid namespace's init (`registry::INIT_PID`).
pub extern "C" fn patina_ppid() -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    return crate::identity::Process::current().parent();
    #[cfg(not(target_os = "linux"))]
    return registry::INIT_PID as i32;
}

/// Who the caller is, to the rows both OSes answer (the owner `stat`
/// reports, `chown`, `SO_PEERCRED`, a signal's sender): on Linux the virtual
/// credential's ids and supplementary groups (`identity::credential`). macOS
/// has no credential yet; there the caller is the registry's fixed identity
/// in its own group alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caller {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: &'static [u32],
}

impl Caller {
    /// `in_group_p`: whether `gid` is the caller's group or one of its
    /// supplementary groups.
    pub(crate) fn in_group(&self, gid: u32) -> bool {
        gid == self.gid || self.groups.contains(&gid)
    }
}

/// The caller; see [`Caller`].
pub(crate) fn caller() -> Caller {
    #[cfg(target_os = "linux")]
    {
        let credential = identity::credential();
        Caller {
            uid: credential.uid,
            gid: credential.gid,
            groups: credential.groups,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Caller {
            uid: registry::IDENTITY_UID,
            gid: registry::IDENTITY_GID,
            groups: &[registry::IDENTITY_GID],
        }
    }
}

#[unsafe(no_mangle)]
/// The caller's user id ([`caller`]) — what every `st_uid`, the C
/// `getuid`/`geteuid`, and the ownership comparisons read. A guest reading
/// an owner reads this, never a per-entry field: the deterministic
/// filesystem stores no owner because every entry is the caller's.
pub extern "C" fn patina_uid() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    caller().uid
}

#[unsafe(no_mangle)]
/// Entry `index` of the virtual machine's passwd database
/// (`registry::PASSWD`, file order) as its `/etc/passwd` line, or NULL past
/// the last: what the C passwd readers answer from.
pub extern "C" fn patina_passwd_line(index: u32) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    usize::try_from(index)
        .ok()
        .and_then(|index| registry::PASSWD.get(index))
        .map_or(std::ptr::null(), |line| line.as_ptr())
}

#[unsafe(no_mangle)]
/// The caller's group id; see [`patina_uid`].
pub extern "C" fn patina_gid() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    caller().gid
}

/// The virtual machine's node name (`--hostname`), a recorded run fact that
/// both platforms' `uname` report: read from the installed runtime, which a
/// call before installation installs or, from a static constructor that ran
/// before Patina's, refuses by name — never a default a constructor could
/// cache for the whole run.
pub(crate) fn node_name() -> Result<String, c_int> {
    ensure_runtime()?;
    with_context_raw(|context| Ok(context.hostname().to_owned()))
}

#[unsafe(no_mangle)]
/// `uname(3)` on Darwin: the virtual Darwin kernel's self-description
/// (`darwin_identity`) into the caller's `struct utsname`. 0, or -1 with
/// [`patina_errno`] (`EFAULT` for NULL).
///
/// # Safety
/// `out` must be NULL or writable for a Darwin `struct utsname`.
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn patina_uname(out: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if out.is_null() {
        return fail(EFAULT);
    }
    let name = match node_name() {
        Ok(name) => darwin_identity::describe(&name),
        Err(errno) => return fail(errno),
    };
    // SAFETY: `out` was checked non-null and is writable per this function's
    // contract.
    unsafe { out.cast::<darwin_identity::Utsname>().write_unaligned(name) };
    set_errno(0);
    0
}

#[unsafe(no_mangle)]
/// Read the metadata of the entry `(dirfd, path)` resolves to: the guest's
/// own `stat`, the one entry behind `stat`, `lstat`, `fstatat`, `statx`,
/// `access` and every other by-path metadata read on both doors. `flags` are
/// `PATINA_RESOLVE_*`: `NOFOLLOW` names a trailing symlink itself (`lstat`,
/// `AT_SYMLINK_NOFOLLOW`), `EMPTY_PATH` lets an empty path name the base
/// (`AT_EMPTY_PATH` on `AT_FDCWD` is the working directory). Symlinks are
/// walked to the kernel's 40-hop limit. A missing entry is `ENOENT`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `out` to a
/// writable `struct patina_metadata`.
pub unsafe extern "C" fn patina_metadata_at(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    out: *mut PatinaMetadata,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: per this function's contract.
    unsafe { metadata_at(dirfd, path, flags, out, MetadataLookup::Fstat) }
}

/// The guest's `stat` of the canonical `path` the walk resolved: a recorded
/// filesystem operation, charged latency and fault-eligible. It takes no
/// scheduling point: the walk took the call's, so no other task can change
/// what `path` names between the walk and this read.
#[expect(clippy::disallowed_methods, reason = "the guest's own stat(2)")]
fn guest_stat(path: &str) -> Result<patina_dst_abi::FsMetadata, c_int> {
    with_context_raw(|context| context.fs_metadata(path))
}

/// [`patina_metadata_at`] read as `lookup`. The path walk's lookups are the
/// kernel's own (no fault, latency or trace op). [`MetadataLookup::Fstat`]
/// then reads the entry it found as the guest's `stat`, the one recorded,
/// faultable operation of the call. [`MetadataLookup::Inode`] answers from
/// the walk alone, as the kernel reads the in-memory inode namei found
/// (`name_to_handle_at` by path).
///
/// # Safety
/// As [`patina_metadata_at`].
pub(crate) unsafe fn metadata_at(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    out: *mut PatinaMetadata,
    lookup: MetadataLookup,
) -> c_int {
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => {
            return match virtual_metadata(entry, flags & paths::RESOLVE_NOFOLLOW != 0) {
                Some(metadata) => write_patina_metadata(metadata, out),
                None => entry.unmodeled("the metadata"),
            };
        }
        Err(errno) => return fail(errno),
    };
    // What a mapped file's views stored is written back first, so the answer
    // counts it: whether it was, after which the walk's metadata is stale.
    let write_back = || {
        resolved
            .metadata
            .is_some_and(|found| found.kind == FsEntryKind::File && mem::inspecting_ino(found.ino))
    };
    let metadata = match lookup {
        MetadataLookup::Fstat => {
            write_back();
            guest_stat(&resolved.path)
        }
        #[cfg(target_os = "linux")]
        MetadataLookup::Inode => match resolved.metadata {
            None => Err(ENOENT),
            Some(_) if write_back() => {
                with_context_raw(|context| context.fs_metadata_unrecorded(&resolved.path))
            }
            Some(found) => Ok(found),
        },
    };
    match metadata {
        Ok(metadata) => write_metadata(metadata, out),
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `access`/`faccessat`'s answer for the node a record describes, both
/// doors: 0 or the errno. The caller is the one modeled identity: the owner
/// of every volume entry (the owner triad answers), and not root, so a
/// root-owned node (a namespace file's, a memory device) answers from the
/// other triad; asking a namespace file's immutable inode for write access
/// is `EPERM` first (`inode_permission`'s `IS_IMMUTABLE`).
///
/// # Safety
/// `values` must point to a readable record.
pub unsafe extern "C" fn patina_access_answer(values: *const PatinaMetadata, mode: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: readable per this function's contract.
    let values = unsafe { &*values };
    const R_OK: c_int = 4;
    const W_OK: c_int = 2;
    const X_OK: c_int = 1;
    let wanted = [(R_OK, 0o4), (W_OK, 0o2), (X_OK, 0o1)]
        .into_iter()
        .filter(|(flag, _)| mode & flag != 0)
        .fold(0, |wanted, (_, bit)| wanted | bit);
    #[cfg(target_os = "linux")]
    let immutable = values.fs == PATINA_FS_NSFS;
    #[cfg(not(target_os = "linux"))]
    let immutable = false;
    if immutable && mode & W_OK != 0 {
        return EPERM;
    }
    let (uid, gid) = node_owner(values.fs);
    let caller = caller();
    let triad = if uid == caller.uid {
        (values.mode >> 6) & 0o7
    } else if caller.in_group(gid) {
        (values.mode >> 3) & 0o7
    } else {
        values.mode & 0o7
    };
    if triad & wanted != wanted { EACCES } else { 0 }
}

/// The owner `stat` reports for a node on the `PATINA_FS_*` filesystem
/// `fs`, both doors: the caller's ([`caller`]), but for a namespace file's
/// nsfs inode, a memory device and the anonymous inode, which are root's
/// (boot made them), the pseudoterminal
/// multiplexer, root's and the tty group's, and a pseudoterminal's slave
/// node, its opener's (the caller's) and the tty group's.
pub(crate) fn node_owner(fs: u32) -> (u32, u32) {
    let caller = caller();
    match fs {
        #[cfg(target_os = "linux")]
        PATINA_FS_NSFS | PATINA_FS_DEVTMPFS | PATINA_FS_ANON_INODE | PATINA_FS_PROC => (0, 0),
        _ => (caller.uid, caller.gid),
    }
}

#[unsafe(no_mangle)]
/// The C face of [`node_owner`].
///
/// # Safety
/// `uid` and `gid` must be writable.
pub unsafe extern "C" fn patina_node_owner(fs: u32, uid: *mut u32, gid: *mut u32) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (owner, group) = node_owner(fs);
    // SAFETY: writable per this function's contract.
    unsafe {
        uid.write(owner);
        gid.write(group);
    }
}

/// A namespace file's link, read: `<type>:[<inode>]` (`ns_get_name`),
/// truncated to the room given.
#[cfg(target_os = "linux")]
pub(crate) fn read_namespace_link(index: usize, buf: *mut c_char, len: usize) -> isize {
    let target = nsfs::link_target(index);
    let copied = target.len().min(len);
    // SAFETY: the caller checked `buf` writable for `len` bytes (the C ABI
    // of `patina_read_link`).
    unsafe {
        slice::from_raw_parts_mut(buf.cast::<u8>(), len)[..copied]
            .copy_from_slice(&target.as_bytes()[..copied]);
    }
    set_errno(0);
    copied as isize
}

/// A change to the attributes (mode, owner, times, size) of an entry the
/// resolver answers itself, by `operation`: a namespace file's nsfs inode is
/// immutable (`notify_change`: `EPERM`); a memory device and the
/// pseudoterminal multiplexer are root's, so changing their mode is `EPERM`
/// (not the owner, no `CAP_FOWNER`); a devpts name no pair has is `ENOENT`;
/// a procfs node's mode never changes (`proc_setattr`: `EPERM`), and
/// truncating one is `EISDIR` for a directory, `EACCES` for a file (`0444`);
/// anything else about them (a slave node is its opener's to change) is not
/// modeled.
fn virtual_setattr(entry: paths::Virtual, operation: &str) -> c_int {
    #[cfg(target_os = "linux")]
    if let paths::Virtual::Proc(node) = entry {
        return match operation {
            "chmod" => EPERM,
            "truncating" if node.is_directory() => EISDIR,
            "truncating" => EACCES,
            _ => entry.unmodeled(operation),
        };
    }
    let root_owned_device = match entry {
        paths::Virtual::MemDevice(_) => true,
        #[cfg(target_os = "linux")]
        paths::Virtual::Ptmx => true,
        #[cfg(target_os = "linux")]
        paths::Virtual::Namespace(_) | paths::Virtual::Tty | paths::Virtual::Proc(_) => false,
    };
    match entry {
        #[cfg(target_os = "linux")]
        paths::Virtual::Namespace(_) => EPERM,
        _ if root_owned_device
            && operation == "chmod"
            && cfg!(target_os = "linux")
            && !caller_capable(registry::Capability::Fowner) =>
        {
            EPERM
        }
        _ => entry.unmodeled(operation),
    }
}

/// Whether the caller holds `capability` (Linux; the identity has none on
/// Darwin).
fn caller_capable(capability: registry::Capability) -> bool {
    #[cfg(target_os = "linux")]
    return identity::credential().capable(capability);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = capability;
        false
    }
}

/// The metadata of an entry the resolver answers itself, `nofollow` naming
/// the entry itself: a namespace file's nsfs inode (its link, a procfs
/// inode, is not modeled) and, on Linux, a memory device's node and the
/// pseudoterminals' (devpts's root is not modeled); `None` where the model
/// ends.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn virtual_metadata(entry: paths::Virtual, nofollow: bool) -> Option<PatinaMetadata> {
    match entry {
        #[cfg(target_os = "linux")]
        paths::Virtual::MemDevice(device) => Some(device.metadata()),
        #[cfg(not(target_os = "linux"))]
        paths::Virtual::MemDevice(_) => None,
        #[cfg(target_os = "linux")]
        paths::Virtual::Namespace(_) if nofollow => None,
        #[cfg(target_os = "linux")]
        paths::Virtual::Namespace(index) => Some(nsfs::metadata(index)),
        #[cfg(target_os = "linux")]
        paths::Virtual::Ptmx | paths::Virtual::Tty => None,
        #[cfg(target_os = "linux")]
        paths::Virtual::Proc(node) => Some(crate::procfs::metadata(node)),
    }
}

/// Write a record the shim made itself (a namespace file's, a memory
/// device's).
fn write_patina_metadata(metadata: PatinaMetadata, out: *mut PatinaMetadata) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: `out` was checked and is writable per the C ABI contract.
    unsafe { out.write(metadata) };
    set_errno(0);
    0
}

/// Whose read of a descriptor's metadata it is. [`MetadataLookup::Fstat`] is
/// the guest's own `fstat`: a recorded filesystem operation that is charged
/// latency and can fail with an injected error. [`MetadataLookup::Inode`] is
/// the kernel reading the in-memory inode inside another call (`FIOQSIZE`,
/// `name_to_handle_at` on a descriptor, both Linux-only). That read does no
/// storage access, so it is never faulted and records nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetadataLookup {
    Fstat,
    #[cfg(target_os = "linux")]
    Inode,
}

impl MetadataLookup {
    #[expect(
        clippy::disallowed_methods,
        reason = "Fstat is the guest's own fstat(2); Inode reads unrecorded"
    )]
    fn of_fd(
        self,
        context: &mut Context,
        fd: Fd,
    ) -> Result<patina_dst_abi::FsMetadata, RuntimeError> {
        match self {
            Self::Fstat => context.fs_fd_metadata(fd),
            #[cfg(target_os = "linux")]
            Self::Inode => context.fs_fd_metadata_unrecorded(fd),
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "Fstat is the guest's own fstat(2) of a FIFO endpoint's node; Inode reads unrecorded"
    )]
    fn of_inode(
        self,
        context: &mut Context,
        ino: u64,
    ) -> Result<patina_dst_abi::FsMetadata, RuntimeError> {
        match self {
            Self::Fstat => context.fs_inode_metadata(ino),
            #[cfg(target_os = "linux")]
            Self::Inode => context.fs_inode_metadata_unrecorded(ino),
        }
    }
}

#[unsafe(no_mangle)]
/// Read full metadata for a deterministic descriptor: the guest's `fstat`.
///
/// # Safety
/// `out` must point to a writable `struct patina_metadata`.
pub unsafe extern "C" fn patina_fd_metadata_full(raw_fd: c_int, out: *mut PatinaMetadata) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: per this function's contract.
    unsafe { fd_metadata_full(raw_fd, out, MetadataLookup::Fstat) }
}

/// [`patina_fd_metadata_full`] read as `lookup`.
///
/// # Safety
/// `out` must point to a writable `struct patina_metadata`.
pub(crate) unsafe fn fd_metadata_full(
    raw_fd: c_int,
    out: *mut PatinaMetadata,
    lookup: MetadataLookup,
) -> c_int {
    // A FIFO descriptor is a pipe endpoint, not a filesystem descriptor: the
    // filesystem knows the ENTRY but holds no handle to ask about. What the
    // descriptor holds is the NODE, so the filesystem is asked about the inode —
    // which is what makes a `chmod` of the FIFO after the open visible here,
    // exactly as it is through a regular file's descriptor, and what makes a
    // hard-linked FIFO report its real link count.
    //
    // Unlinking the last name does not change that: the endpoint HOLDS a
    // reference on the node, so the filesystem still speaks for it and reports
    // `nlink` 0 with the live mode — which is exactly what a kernel reports for
    // an unlinked-but-open entry. There is no open-time copy to fall back to,
    // because a copy is a stale cache one field over from the cached path.
    if let Some(node) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| lookup.of_inode(context, node)) {
            Ok(metadata) => write_metadata(metadata, out),
            Err(errno) => fail(errno),
        };
    }
    // A namespace file is the namespace's nsfs inode (`O_PATH` too:
    // `fstat` takes it); a memory device, its devtmpfs node.
    #[cfg(target_os = "linux")]
    if let Ok(resolved) = resolve_fd(raw_fd) {
        if matches!(resolved.kind, FdKind::Namespace | FdKind::NamespacePath) {
            return write_patina_metadata(nsfs::metadata(resolved.handle as usize), out);
        }
        if resolved.kind == FdKind::MemDevice {
            let device = crate::memdev::MemDevice::of_handle(resolved.handle);
            return write_patina_metadata(device.metadata(), out);
        }
        if matches!(resolved.kind, FdKind::Proc | FdKind::ProcDir) {
            let node = crate::procfs::node_of(resolved.handle);
            return write_patina_metadata(crate::procfs::metadata(node), out);
        }
        if volume::on_anon_inode(resolved.kind) {
            return write_patina_metadata(volume::anon_inode_metadata(), out);
        }
    }
    // An anonymous pipe end or a socket is on pipefs/sockfs: its node is the
    // shim's own, and answers without a trip to the filesystem.
    if let Some(metadata) = thread::pipe_inode_metadata(raw_fd) {
        if out.is_null() {
            return fail(EINVAL);
        }
        // SAFETY: `out` was checked and is writable per the C ABI contract.
        unsafe { out.write(metadata) };
        set_errno(0);
        return 0;
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    mem::inspecting(fd.0);
    match with_context(|context| lookup.of_fd(context, fd)) {
        Ok(metadata) => write_metadata(metadata, out),
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Change the permission bits of the entry `(dirfd, path)` names (`chmod` /
/// `fchmodat`). `flags` are `PATINA_RESOLVE_*`: without `NOFOLLOW` a trailing
/// symlink resolves and its TARGET changes (the `chmod` and flagless `fchmodat`
/// spellings); with it the link itself is named, which is `EOPNOTSUPP`
/// because Linux gives a symlink no mode of its own to change.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_chmod(
    dirfd: c_int,
    path: *const c_char,
    mode: u32,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => return fail(virtual_setattr(entry, "chmod")),
        Err(errno) => return fail(errno),
    };
    match resolved.metadata.map(|metadata| metadata.kind) {
        None => return fail(ENOENT),
        Some(FsEntryKind::Symlink) => return fail(EOPNOTSUPP),
        Some(
            FsEntryKind::File
            | FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice,
        ) => {}
    }
    match with_context(|context| context.fs_set_mode(&resolved.path, mode)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            fsnotify::on_path(&resolved.path, fsnotify::IN_ATTRIB);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Change the permission bits of the entry an open descriptor names (`fchmod`).
/// A descriptor already names the node, so there is no symlink to resolve.
pub extern "C" fn patina_fchmod(raw_fd: c_int, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // A FIFO endpoint is a pipe, not a filesystem descriptor — so the bits it
    // changes are named by NODE, exactly as its `fstat` reads them by node. That
    // is what keeps `fchmod` working on an entry whose last name is gone.
    if let Some(node) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| context.fs_set_inode_mode(node, mode)) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                fifo_changed(raw_fd, fsnotify::IN_ATTRIB);
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    if thread::pipe_inode_set_mode(raw_fd, mode).is_some() {
        set_errno(0);
        return 0;
    }
    // A namespace file's nsfs inode is root's and immutable
    // (`notify_change`'s `IS_IMMUTABLE`); a procfs node's mode never changes
    // (`proc_setattr`); a memory device is root's (not the owner, no
    // `CAP_FOWNER`).
    #[cfg(target_os = "linux")]
    if let Ok(resolved) = resolve_fd(raw_fd) {
        if matches!(
            resolved.kind,
            FdKind::Namespace | FdKind::Proc | FdKind::ProcDir
        ) {
            return fail(EPERM);
        }
        if resolved.kind == FdKind::MemDevice {
            if caller_capable(registry::Capability::Fowner) {
                let device = crate::memdev::MemDevice::of_handle(resolved.handle);
                paths::Virtual::MemDevice(device).unmodeled("fchmod");
            }
            return fail(EPERM);
        }
        // The one anonymous inode is root's too.
        if volume::on_anon_inode(resolved.kind) {
            if caller_capable(registry::Capability::Fowner) {
                trap_fatal(
                    "fchmod: changing the mode of the anonymous inode every eventfd, timerfd, \
                     signalfd, epoll, inotify and pidfd shares is not modeled",
                );
            }
            return fail(EPERM);
        }
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_fd_mode(fd, mode)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            fsnotify::on_handle(fd, fsnotify::IN_ATTRIB);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

// ---------------------------------------------------------------------------
// Timestamps, ownership and sizes: the entries behind the utimensat, chown,
// truncate and fallocate families on both doors.

/// A time argument as the `utimensat` family spells it: leave the time alone.
pub const TIME_OMIT: u32 = 0;
/// Set the time to the virtual clock's now.
pub const TIME_NOW: u32 = 1;
/// Set the time to the timestamp given beside the kind.
pub const TIME_SET: u32 = 2;

/// Decode requests without sampling NOW (the runtime resolves it after
/// latency); the filesystem truncates a set time to its range.
fn resolve_time_arguments(
    atime_kind: u32,
    atime: PatinaTimestamp,
    mtime_kind: u32,
    mtime: PatinaTimestamp,
) -> Result<(patina_dst_runtime::FsTime, patina_dst_runtime::FsTime), c_int> {
    use patina_dst_runtime::FsTime;
    let pick = |kind, time: PatinaTimestamp| match kind {
        TIME_OMIT => Ok(FsTime::Omit),
        TIME_NOW => Ok(FsTime::Now),
        TIME_SET => Ok(FsTime::Nanos(time.nanos())),
        _ => Err(EINVAL),
    };
    Ok((pick(atime_kind, atime)?, pick(mtime_kind, mtime)?))
}

#[unsafe(no_mangle)]
/// `utimensat(2)` on a `(dirfd, path)`: set the entry's access and
/// modification times (each `PATINA_TIME_OMIT`, `PATINA_TIME_NOW`, or
/// `PATINA_TIME_SET` with its nanoseconds); `ctime` moves whenever either does.
/// `flags` are `PATINA_RESOLVE_*` (`NOFOLLOW` sets a symlink's own times, as
/// `lutimes`/`AT_SYMLINK_NOFOLLOW` do). Both `OMIT` is the kernel's early
/// success: nothing crosses the boundary and no time moves. The one modeled
/// identity owns every entry, so the kernel's owner-or-`w` rule always passes.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn patina_utimensat(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    atime_kind: u32,
    atime: PatinaTimestamp,
    mtime_kind: u32,
    mtime: PatinaTimestamp,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abort_if_init_failed();
    if atime_kind == TIME_OMIT && mtime_kind == TIME_OMIT {
        set_errno(0);
        return 0;
    }
    #[cfg(target_os = "linux")]
    let shown = fsnotify::times_mask(atime_kind != TIME_OMIT, mtime_kind != TIME_OMIT);
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let descriptor =
        if path.is_empty() && flags & paths::RESOLVE_EMPTY_PATH != 0 && dirfd != paths::AT_FDCWD {
            match resolve_fd(dirfd) {
                Ok(descriptor) => Some(descriptor),
                Err(errno) => return fail(errno),
            }
        } else {
            None
        };
    let (atime, mtime) = match resolve_time_arguments(atime_kind, atime, mtime_kind, mtime) {
        Ok(times) => times,
        Err(errno) => return fail(errno),
    };
    if let Some(descriptor) = descriptor {
        let ino = if let Some(ino) = thread::fifo_ino(dirfd) {
            ino
        } else if descriptor.kind.is_fs() {
            match with_context(|context| context.fs_fd_ino(Fd(descriptor.handle))) {
                Ok(ino) => ino,
                Err(errno) => return fail(errno),
            }
        } else {
            return deny(
                "patina: utimensat on a descriptor without a modeled inode; failing closed\n",
            );
        };
        return match with_context(|context| context.fs_set_inode_times_spec(ino, atime, mtime)) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                if descriptor.kind.is_fs() {
                    fsnotify::on_handle(Fd(descriptor.handle), shown);
                } else {
                    fsnotify::fifo_changed(descriptor.handle, shown);
                }
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => {
            return fail(virtual_setattr(entry, "setting the times"));
        }
        Err(errno) => return fail(errno),
    };
    if resolved.metadata.is_none() {
        return fail(ENOENT);
    }
    match with_context(|context| context.fs_set_times_by_path_spec(&resolved.path, atime, mtime)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            fsnotify::on_path(&resolved.path, shown);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `futimens(3)` / `utimensat(fd, NULL, …)`: the same change, on the node an
/// open descriptor holds. An `O_PATH` descriptor is `EBADF` (the kernel's
/// `fdget` never hands one out for this call). A descriptor on something the
/// filesystem holds no node for refuses loudly. Named FIFO endpoints reach
/// their retained inode, including after unlink.
pub extern "C" fn patina_futimens(
    raw_fd: c_int,
    atime_kind: u32,
    atime: PatinaTimestamp,
    mtime_kind: u32,
    mtime: PatinaTimestamp,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abort_if_init_failed();
    if atime_kind == TIME_OMIT && mtime_kind == TIME_OMIT {
        set_errno(0);
        return 0;
    }
    #[cfg(target_os = "linux")]
    let shown = fsnotify::times_mask(atime_kind != TIME_OMIT, mtime_kind != TIME_OMIT);
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let (atime, mtime) = match resolve_time_arguments(atime_kind, atime, mtime_kind, mtime) {
        Ok(times) => times,
        Err(errno) => return fail(errno),
    };
    if let Some(ino) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| context.fs_set_inode_times_spec(ino, atime, mtime)) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                fifo_changed(raw_fd, shown);
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    #[cfg(target_os = "linux")]
    procfs_setattr(&resolved, "futimens");
    if !resolved.kind.is_fs() {
        return deny("patina: futimens on a descriptor without a modeled inode; failing closed\n");
    }
    let fd = Fd(resolved.handle);
    match with_context(|context| context.fs_set_times_spec(fd, atime, mtime)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            fsnotify::on_handle(fd, shown);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// An owner or time change through a procfs descriptor: `proc_setattr`
/// stores it on the node (its `ctime` at least), which the model does not,
/// so it stops the run by name.
#[cfg(target_os = "linux")]
fn procfs_setattr(resolved: &crate::fdtable::Resolved, operation: &str) {
    if matches!(resolved.kind, FdKind::Proc | FdKind::ProcDir) {
        paths::Virtual::Proc(crate::procfs::node_of(resolved.handle)).unmodeled(operation);
    }
}

/// `uid_t`/`gid_t` `-1`: leave the id alone.
const ID_UNCHANGED: u32 = u32::MAX;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o010;

/// The `chown` decision (`chown_ok`/`chgrp_ok`) for `caller`, who owns every
/// entry: a uid that is `-1` or the owner's, and a gid that is `-1` or one
/// of the caller's groups, are what the kernel lets an owner without
/// `CAP_CHOWN` ask for; anything else is `EPERM`. `Ok` carries the mode the
/// kernel would store afterwards — on a non-directory `chown` kills the
/// setuid bit and, when the group may execute, the setgid bit — so the
/// caller writes that mode back through the one mode entry, which is also
/// what moves `ctime`.
fn chown_decision(
    caller: Caller,
    uid: u32,
    gid: u32,
    kind: FsEntryKind,
    mode: u32,
) -> Result<u32, c_int> {
    if (uid != ID_UNCHANGED && uid != caller.uid) || (gid != ID_UNCHANGED && !caller.in_group(gid))
    {
        return Err(EPERM);
    }
    if kind == FsEntryKind::Directory {
        return Ok(mode);
    }
    let mut mode = mode & !S_ISUID;
    if mode & (S_ISGID | S_IXGRP) == S_ISGID | S_IXGRP {
        mode &= !S_ISGID;
    }
    Ok(mode)
}

/// Whether a `chown` shows `IN_ATTRIB` (`fsnotify_change`): an owner or a
/// group was given, or the setuid/setgid bits it kills were set
/// (`ATTR_KILL_SUID` becomes `ATTR_MODE`).
#[cfg(target_os = "linux")]
fn chown_notifies(uid: u32, gid: u32, before: u32, after: u32) -> bool {
    uid != ID_UNCHANGED || gid != ID_UNCHANGED || before != after
}

#[unsafe(no_mangle)]
/// `chown`/`lchown`/`fchownat` on a `(dirfd, path)`; `flags` are
/// `PATINA_RESOLVE_*` (`NOFOLLOW` names a symlink itself, `EMPTY_PATH` lets
/// `AT_EMPTY_PATH` name the base). A symlink keeps its mode and data times,
/// but its own ctime moves.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_chown(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    uid: u32,
    gid: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => {
            return fail(virtual_setattr(entry, "changing the owner"));
        }
        Err(errno) => return fail(errno),
    };
    let Some(metadata) = resolved.metadata else {
        return fail(ENOENT);
    };
    let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
        Ok(mode) => mode,
        Err(errno) => return fail(errno),
    };
    let result = if metadata.kind == FsEntryKind::Symlink {
        with_context(|context| {
            context.fs_set_times_by_path(
                &resolved.path,
                Some(metadata.atime_nanos),
                Some(metadata.mtime_nanos),
            )
        })
    } else {
        with_context(|context| context.fs_set_mode(&resolved.path, mode))
    };
    match result {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            if chown_notifies(uid, gid, metadata.mode, mode) {
                fsnotify::on_path(&resolved.path, fsnotify::IN_ATTRIB);
            }
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `fchown`: the same decision on the node a descriptor holds. `O_PATH` is
/// `EBADF`; descriptors without a modeled inode refuse loudly. The decision
/// reads the in-memory inode's mode, so only the mode write can fail with an
/// injected filesystem error.
pub extern "C" fn patina_fchown(raw_fd: c_int, uid: u32, gid: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if let Some(node) = thread::fifo_ino(raw_fd) {
        let metadata = match with_context(|context| context.fs_inode_metadata_unrecorded(node)) {
            Ok(metadata) => metadata,
            Err(errno) => return fail(errno),
        };
        let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
            Ok(mode) => mode,
            Err(errno) => return fail(errno),
        };
        return match with_context(|context| context.fs_set_inode_mode(node, mode)) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                if chown_notifies(uid, gid, metadata.mode, mode) {
                    fifo_changed(raw_fd, fsnotify::IN_ATTRIB);
                }
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    #[cfg(target_os = "linux")]
    procfs_setattr(&resolved, "fchown");
    if !resolved.kind.is_fs() {
        return deny("patina: fchown on a descriptor without a modeled inode; failing closed\n");
    }
    let fd = Fd(resolved.handle);
    let metadata = match with_context(|context| context.fs_fd_metadata_unrecorded(fd)) {
        Ok(metadata) => metadata,
        Err(errno) => return fail(errno),
    };
    let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
        Ok(mode) => mode,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_fd_mode(fd, mode)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            if chown_notifies(uid, gid, metadata.mode, mode) {
                fsnotify::on_handle(fd, fsnotify::IN_ATTRIB);
            }
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `truncate(2)`: a regular file's length by name (a trailing symlink is
/// followed). A negative length is `EINVAL`, a directory `EISDIR`, any other
/// kind `EINVAL`; the driver charges `w` on the entry.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_truncate(dirfd: c_int, path: *const c_char, length: i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Ok(length) = u64::try_from(length) else {
        return fail(EINVAL);
    };
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, 0) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        // `vfs_truncate`: a character device is no regular file (`EINVAL`,
        // before any permission); the immutable nsfs inode refuses (`EPERM`).
        Ok(paths::Resolution::Virtual(paths::Virtual::MemDevice(_)))
            if cfg!(target_os = "linux") =>
        {
            return fail(EINVAL);
        }
        Ok(paths::Resolution::Virtual(entry)) => {
            return fail(virtual_setattr(entry, "truncating"));
        }
        Err(errno) => return fail(errno),
    };
    let ino = match resolved.metadata {
        None => return fail(ENOENT),
        Some(metadata) => match metadata.kind {
            FsEntryKind::Directory => return fail(EISDIR),
            FsEntryKind::Fifo
            | FsEntryKind::Symlink
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice => return fail(EINVAL),
            FsEntryKind::File => metadata.ino,
        },
    };
    match with_context(|context| context.fs_set_len_by_path(&resolved.path, length)) {
        Ok(()) => {
            mem::resized_ino(ino, length);
            #[cfg(target_os = "linux")]
            fsnotify::on_path(&resolved.path, fsnotify::IN_MODIFY);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `fallocate(2)` mode bits.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;
/// The bits the kernel's `vfs_fallocate` recognizes at all; anything else is
/// `EOPNOTSUPP` before the descriptor is even looked at.
const FALLOC_FL_SUPPORTED: u32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

/// The operation bits of a `fallocate` mode (everything but `KEEP_SIZE`); the
/// kernel accepts at most one of them per call.
const FALLOC_FL_OPERATIONS: u32 = FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

#[unsafe(no_mangle)]
/// `fallocate(2)`, in the kernel's order of refusals: a bad range is
/// `EINVAL`; an unknown bit, two operation bits at once, `PUNCH_HOLE` without
/// `KEEP_SIZE`, or a range-shifting mode with `KEEP_SIZE` is `EOPNOTSUPP`
/// (host-checked: Linux 6.8 answers `EOPNOTSUPP`, not `EINVAL`, for the
/// self-contradictory modes); a descriptor not open for writing (or `O_PATH`)
/// `EBADF`, a pipe `ESPIPE`, a directory `EISDIR`, any other non-file `ENODEV`,
/// a range past the file's filesystem's size limit `EFBIG` (the volume's
/// ext4 limit, a memfd's or secret memory's `MAX_LFS_FILESIZE`). Mode `0` and
/// `KEEP_SIZE` reserve (the file grows to `offset + len` unless `KEEP_SIZE`);
/// `PUNCH_HOLE|KEEP_SIZE` and `ZERO_RANGE` zero the range; the range-shifting
/// modes (`COLLAPSE_RANGE`, `INSERT_RANGE`) and `UNSHARE_RANGE` are
/// `EOPNOTSUPP` after the size limit, as the file's own `fallocate` answers
/// on filesystems without them. One recorded operation whatever the range.
pub extern "C" fn patina_fallocate(raw_fd: c_int, mode: u32, offset: i64, length: i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if offset < 0 || length <= 0 {
        return fail(EINVAL);
    }
    if mode & !FALLOC_FL_SUPPORTED != 0
        || (mode & FALLOC_FL_OPERATIONS).count_ones() > 1
        || (mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0)
        || (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE) != 0
            && mode & FALLOC_FL_KEEP_SIZE != 0)
    {
        return fail(EOPNOTSUPP);
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.kind.is_path_only() || resolved.status & O_WRITE == 0 {
        return fail(EBADF);
    }
    match resolved.kind {
        FdKind::File => {}
        // The standard streams are pipes.
        FdKind::Pipe | FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => return fail(ESPIPE),
        FdKind::Dir => return fail(EISDIR),
        FdKind::OPath | FdKind::MemDevice | FdKind::Socket => return fail(ENODEV),
        #[cfg(target_os = "linux")]
        FdKind::EventFd
        | FdKind::Epoll
        | FdKind::SignalFd
        | FdKind::TimerFd
        | FdKind::Inotify
        | FdKind::Pidfd
        | FdKind::Namespace
        | FdKind::NamespacePath => return fail(ENODEV),
        // Opened read-only, refused above.
        #[cfg(target_os = "linux")]
        FdKind::Proc | FdKind::ProcDir => return fail(EBADF),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => return fail(ENODEV),
    }
    // `vfs_fallocate`: a range past the file's filesystem's size limit is
    // `EFBIG` before any file's own `fallocate` judges the mode: the ext4
    // volume's `s_maxbytes`; `MAX_LFS_FILESIZE` for a memfd (tmpfs,
    // hugetlbfs) or secret memory.
    let (offset, length) = (offset as u64, length as u64);
    #[cfg(target_os = "linux")]
    let volume = resolved.kind == FdKind::File
        && !mem::secret(resolved.handle)
        && mem::anonymous(resolved.handle).is_none();
    #[cfg(not(target_os = "linux"))]
    let volume = resolved.kind == FdKind::File;
    let limit = if volume {
        patina_dst_fs_mem::VOLUME_MAX_BYTES
    } else {
        i64::MAX as u64
    };
    if offset.checked_add(length).is_none_or(|end| end > limit) {
        return fail(EFBIG);
    }
    if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE) != 0 {
        return fail(EOPNOTSUPP);
    }
    // The file's own `fallocate`: a memfd (`shmem_fallocate`,
    // `hugetlbfs_fallocate`) takes only `KEEP_SIZE` and `PUNCH_HOLE`.
    #[cfg(target_os = "linux")]
    if mem::secret(resolved.handle)
        || (mem::anonymous(resolved.handle).is_some()
            && mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0)
    {
        return fail(EOPNOTSUPP);
    }
    let operation = if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        FsAllocateMode::PunchHole
    } else if mode & FALLOC_FL_ZERO_RANGE != 0 {
        FsAllocateMode::ZeroRange
    } else {
        FsAllocateMode::Reserve
    };
    let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
    let fd = Fd(resolved.handle);
    match with_context(|context| context.fs_allocate(fd, offset, length, operation, keep_size)) {
        // ext4_fallocate commits the journal for an `O_SYNC`/`O_DSYNC`
        // description (`f_flags & O_SYNC`) before it returns.
        Ok(())
            if resolved.status & O_SYNC_STATUS != 0
                && let Err(errno) = fs_sync_handle(fd) =>
        {
            fail(errno)
        }
        Ok(()) => {
            #[cfg(target_os = "linux")]
            mem::allocated(fd.0, offset, length, operation, keep_size);
            #[cfg(target_os = "linux")]
            fsnotify::on_file(fd, fsnotify::IN_MODIFY);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[cfg(test)]
mod chown_tests {
    use super::*;

    /// A caller in a supplementary group may give its file to that group,
    /// as `in_group_p` lets it; no other group or owner.
    #[test]
    fn chown_accepts_the_callers_groups_only() {
        let caller = Caller {
            uid: 1000,
            gid: 1000,
            groups: &[1000, 27],
        };
        let decide = |uid, gid| chown_decision(caller, uid, gid, FsEntryKind::File, 0o644);
        assert_eq!(decide(ID_UNCHANGED, 27), Ok(0o644));
        assert_eq!(decide(1000, 1000), Ok(0o644));
        assert_eq!(decide(ID_UNCHANGED, 28), Err(EPERM));
        assert_eq!(decide(1001, ID_UNCHANGED), Err(EPERM));
    }
}
