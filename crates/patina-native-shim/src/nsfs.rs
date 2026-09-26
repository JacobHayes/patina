//! The caller's namespace files, `/proc/self/ns/*` (fs/proc/namespaces.c,
//! fs/nsfs.c), as the pinned 6.8 presents them: each entry is a magic link
//! whose target reads `<type>:[<inode>]` and which opens the namespace's
//! nsfs inode, a root-owned, immutable, `0444` regular file on the nsfs
//! device (0:4). The virtual machine has one namespace of each type, the
//! initial ones, so the inode numbers are the kernel's: the fixed
//! `PROC_*_INIT_INO` for the user, UTS, IPC, pid, cgroup and time
//! namespaces, and for the network and mount namespaces the first two
//! numbers `ns_alloc_inum` hands out at boot (both as 6.8.0-139 answers
//! live).
//!
//! Like `/dev/urandom`, the entries are recognized lexically by the resolver
//! (`paths::resolve`); the virtual machine mounts no procfs, so nothing else
//! of `/proc` exists. An open follows the link: read-only gives a
//! `FdKind::Namespace` description, `O_PATH` a `FdKind::NamespacePath` one
//! (which every operation that takes an opened file refuses, `EBADF`), whose
//! handle is the entry's index in [`ENTRIES`]; what a namespace file refuses,
//! it refuses as nsfs does. `setns` of one is `sud::privileged::setns`.
//!
//! Known differences: `flock` of a namespace file is keyed by description,
//! so two opens of one namespace both take `LOCK_EX` where the kernel's
//! inode key would refuse the second; `poll` of an `O_PATH` one answers
//! `DEFAULT_POLLMASK` (as every `O_PATH` descriptor's does) where the kernel
//! answers `POLLNVAL`. The device and the inode numbers were read live on
//! x86_64 6.8.0-139, not yet on an arm64 6.8.

use crate::{PATINA_ENTRY_FILE, PATINA_FS_NSFS, PatinaMetadata, PatinaTimestamp, SpinMutex};
use linux_raw_sys::general::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME,
    CLONE_NEWUSER, CLONE_NEWUTS,
};

/// One `/proc/self/ns` entry.
pub(crate) struct Entry {
    /// The entry's name in the directory.
    pub(crate) name: &'static str,
    /// The namespace type's name, what the link's target starts with.
    pub(crate) kind: &'static str,
    /// Its `CLONE_NEW*` type, what `setns` checks a type against.
    pub(crate) flag: u32,
    /// The namespace's inode number.
    pub(crate) inum: u64,
}

/// `PROC_*_INIT_INO` (include/linux/proc_ns.h) and the network and mount
/// namespaces' boot-time numbers.
const CGROUP: u64 = 0xEFFF_FFFB;
const IPC: u64 = 0xEFFF_FFFF;
const MNT: u64 = 0xF000_0001;
const NET: u64 = 0xF000_0000;
const PID: u64 = 0xEFFF_FFFC;
const TIME: u64 = 0xEFFF_FFFA;
const USER: u64 = 0xEFFF_FFFD;
const UTS: u64 = 0xEFFF_FFFE;

/// The entries, in the directory's order (fs/proc/namespaces.c `ns_entries`
/// as `readdir` lists them).
pub(crate) const ENTRIES: [Entry; 10] = [
    entry("cgroup", "cgroup", CLONE_NEWCGROUP, CGROUP),
    entry("ipc", "ipc", CLONE_NEWIPC, IPC),
    entry("mnt", "mnt", CLONE_NEWNS, MNT),
    entry("net", "net", CLONE_NEWNET, NET),
    entry("pid", "pid", CLONE_NEWPID, PID),
    entry("pid_for_children", "pid", CLONE_NEWPID, PID),
    entry("time", "time", CLONE_NEWTIME, TIME),
    entry("time_for_children", "time", CLONE_NEWTIME, TIME),
    entry("user", "user", CLONE_NEWUSER, USER),
    entry("uts", "uts", CLONE_NEWUTS, UTS),
];

const fn entry(name: &'static str, kind: &'static str, flag: u32, inum: u64) -> Entry {
    Entry {
        name,
        kind,
        flag,
        inum,
    }
}

/// The directory the entries are in.
const DIRECTORY: &str = "/proc/self/ns/";

/// The entry a canonical absolute path names, by index.
pub(crate) fn entry_at(path: &str) -> Option<usize> {
    let name = path.strip_prefix(DIRECTORY)?;
    ENTRIES.iter().position(|entry| entry.name == name)
}

/// Whether a canonical path names procfs's namespace files other than the
/// caller's own entries: the `/proc/self/ns` directory itself, or the
/// `ns` directory (and anything in it) of `/proc/thread-self` or a process
/// by number. The virtual machine mounts no procfs to answer them.
pub(crate) fn names_procfs(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    let (owner, rest) = rest.split_once('/').unwrap_or((rest, ""));
    let in_ns = rest == "ns" || rest.starts_with("ns/");
    match owner {
        // The caller's own entries are answered, and a name among them that
        // is no entry is `ENOENT` (as nsfs's directory answers); the
        // directory itself is not modeled.
        "self" => rest == "ns",
        "thread-self" => in_ns,
        pid => !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()) && in_ns,
    }
}

/// What the link reads: `<type>:[<inode>]` (`ns_get_name`).
pub(crate) fn link_target(index: usize) -> String {
    let entry = &ENTRIES[index];
    format!("{}:[{}]", entry.kind, entry.inum)
}

/// When each namespace's inode was made, in nanoseconds on the virtual
/// clock, by the index of the first entry naming it; 0 until first used.
static MADE: SpinMutex<[u64; ENTRIES.len()]> = SpinMutex::new([0; ENTRIES.len()]);

/// The instant the namespace's nsfs inode was made: its first use in the
/// run (an open, a `stat`). The kernel makes a fresh inode whenever none is
/// held; the model keeps the first for the whole run.
pub(crate) fn made(index: usize) -> u64 {
    let first = ENTRIES
        .iter()
        .position(|entry| entry.inum == ENTRIES[index].inum)
        .unwrap_or(index);
    let now = crate::fs_time_unrecorded();
    let mut made = MADE.lock();
    if made[first] == 0 {
        made[first] = now;
    }
    made[first]
}

/// The nsfs inode's metadata: a regular file, `0444`, one link, empty,
/// every time the instant it was [`made`].
pub(crate) fn metadata(index: usize) -> PatinaMetadata {
    let made = PatinaTimestamp::from_nanos(i128::from(made(index)));
    PatinaMetadata {
        kind: PATINA_ENTRY_FILE,
        mode: 0o444,
        nlink: 1,
        fs: PATINA_FS_NSFS,
        rdev_major: 0,
        rdev_minor: 0,
        length: 0,
        ino: ENTRIES[index].inum,
        atime: made,
        mtime: made,
        ctime: made,
        btime: PatinaTimestamp::default(),
    }
}

/// `NS_GET_USERNS`, `NS_GET_PARENT`, `NS_GET_NSTYPE`, `NS_GET_OWNER_UID`
/// (`_IO(0xb7, 1..4)`): the namespace ioctls, not modeled.
pub(crate) fn is_ns_ioctl(request: u64) -> bool {
    (0xb701..=0xb704).contains(&request)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The paths, the link targets and the types.
    #[test]
    fn each_entry_names_its_namespace() {
        assert_eq!(entry_at("/proc/self/ns/uts"), Some(9));
        assert_eq!(link_target(9), "uts:[4026531838]");
        assert_eq!(link_target(5), "pid:[4026531836]");
        assert_eq!(entry_at("/proc/self/ns/nosuch"), None);
        assert_eq!(entry_at("/proc/self/ns"), None);
        assert_eq!(entry_at("/proc/self/ns/"), None);
        for (index, entry) in ENTRIES.iter().enumerate() {
            let path = format!("{DIRECTORY}{}", entry.name);
            assert_eq!(entry_at(&path), Some(index));
            assert_eq!(metadata(index).ino, entry.inum);
            // The namespaces the machine has are distinct, but the
            // `_for_children` views of the caller's own.
            let same: Vec<&str> = ENTRIES
                .iter()
                .filter(|other| other.inum == entry.inum)
                .map(|other| other.name)
                .collect();
            assert!(
                same.iter().all(|name| name.starts_with(entry.kind)),
                "{same:?}"
            );
        }
    }

    /// The resolver finds the entries lexically, and applies the walk's
    /// restrictions to the magic link as the kernel does.
    #[test]
    fn the_resolver_names_the_entries_under_the_walks_rules() {
        use crate::paths::*;
        let resolve = |path: &str, flags: u32| match resolve(AT_FDCWD, path, flags) {
            Ok(Resolution::Virtual(entry)) => Ok(entry.path()),
            Ok(Resolution::Volume(resolved)) => {
                panic!("{path} is on the volume: {}", resolved.path)
            }
            Err(errno) => Err(errno),
        };
        let uts = "/proc/self/ns/uts";
        assert_eq!(resolve(uts, 0).as_deref(), Ok(uts));
        assert_eq!(resolve("/proc//self/./ns/uts", 0).as_deref(), Ok(uts));
        assert_eq!(resolve(uts, RESOLVE_NOFOLLOW).as_deref(), Ok(uts));
        assert_eq!(resolve("/proc/self/ns/uts/", 0), Err(crate::ENOTDIR));
        assert_eq!(resolve(uts, RESOLVE_NO_XDEV), Err(crate::EXDEV));
        assert_eq!(resolve(uts, RESOLVE_NO_SYMLINKS), Err(crate::ELOOP));
        assert_eq!(resolve(uts, RESOLVE_NO_MAGICLINKS), Err(crate::ELOOP));
        // The link itself is not followed, so neither restriction applies.
        let link = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NOFOLLOW;
        assert_eq!(resolve(uts, link).as_deref(), Ok(uts));
    }

    /// The spellings of procfs's namespace files the model does not answer
    /// (they stop the run by name), and the ones it does.
    #[test]
    fn other_spellings_of_the_namespace_files_name_procfs() {
        for path in [
            "/proc/self/ns",
            "/proc/thread-self/ns",
            "/proc/thread-self/ns/uts",
            "/proc/2/ns",
            "/proc/2/ns/net",
        ] {
            assert!(names_procfs(path), "{path}");
        }
        for path in [
            "/proc/self/ns/uts",
            "/proc/self/ns/nosuch",
            "/proc/self/maps",
            "/proc/2/maps",
            "/proc/x/ns/uts",
            "/procfs/self/ns",
            "/proc",
        ] {
            assert!(!names_procfs(path), "{path}");
        }
    }
}
