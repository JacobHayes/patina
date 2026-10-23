//! procfs, mounted at `/proc` (fs/proc), as the pinned 6.8 presents the
//! entries the model answers. Every byte is generated from the virtual
//! machine's own state, never the host's, so a read is the same on every
//! host and in a replay:
//!
//! * the root, `/proc` (`0555`, root's): `self`, `net`, the machine-wide
//!   files and a directory per process of the pid namespace
//!   (`identity::processes`: init and the guest), listed in the kernel's
//!   order (the files by name length, then bytes, as `proc_match` keeps
//!   them, `net` among them; then `self`; then the pids, ascending);
//! * `/proc/self`, a symlink (`0777`, root's) to the caller's process, and
//!   `/proc/net`, one to `self/net`;
//! * the machine-wide files (`0444`, root's): `stat`, `uptime`, `vmstat`,
//!   `loadavg` and `meminfo` ([`text`]);
//! * `/proc/<pid>` (`0555`, the process's owner) with its `task` and `net`
//!   directories and its `status` and `stat` (`0444`);
//! * `/proc/<pid>/task` (`0555`, the process's owner), a directory per
//!   thread by id (the thread census's: the live ones, and the leader as a
//!   zombie once it has exited while another lives; init has its one), each
//!   holding the thread's own `status` and `stat`: its name, its state
//!   (sleeping while it waits in a modeled wait), its scheduling and its CPU
//!   time. A thread's directory lists `ENOENT` once the thread has gone,
//!   and its files read `ESRCH`;
//! * `/proc/<pid>/net` (`0555`, the process's owner), the socket tables
//!   (`0444`, root's): `tcp`, `udp`, `tcp6`, `udp6` and `unix` ([`net`]),
//!   each its header with no rows; a read of one while the guest holds a
//!   socket it would list stops the run.
//!
//! A file holds only what the model answers: a keyed line the model has no
//! value for is left out, and `<pid>/stat` stops after the last field it can
//! fill (`starttime`), since the host maps the guest's memory and the model
//! cannot say how much; a thread's stops before `starttime` but for the
//! process's first thread, the model keeping no start for the others. Any
//! other name in procfs is `ENOENT`, as a name no entry has; `thread-self`,
//! a thread's directory by its id at the root, a thread's `ns`, the
//! namespace files by any spelling but `/proc/self/ns/<entry>`
//! (`crate::nsfs`) and an `O_PATH` open stop the run by name.
//!
//! The text is made as `seq_file` makes it: at the first read, and again
//! whenever a read or a seek moves to a position other than where the last
//! read ended (a seek to the start leaves it to the next read); a read takes
//! the bytes from that position, and holds the open while it makes the text,
//! so a close on another thread meanwhile lets the open go only after it.
//! A directory is walked afresh at every `getdents` (a task directory
//! resuming at a thread the last call could not return). The machine's
//! files have
//! `proc_iter_file_ops`' `poll` (always ready, so epoll takes them) and
//! `splice_read` (`sendfile` and `splice` read them); the socket tables
//! have the `poll` alone; a process's files and every directory have
//! neither (`EPERM`, `EINVAL`). A process directory
//! open names its process to `pidfd_send_signal`. A write, a
//! creation or a removal is refused as the kernel refuses an unprivileged
//! caller (the modes above), and the nodes report procfs's metadata: size 0,
//! the procfs device (0:25), the 1 KiB block, every time the instant the
//! node was first used in the run (the root and the links the boot's).
//!
//! The resolver (`paths::resolve`) enters procfs at `/proc`, however the walk
//! reaches it, and leaves it by `..` at its root (`..` elsewhere names the
//! directory a node is in). Known differences: the
//! volume need not hold a `/proc` directory for the mount to be there (a
//! listing of `/` shows one only if the volume has it); the root's listing
//! leaves out `thread-self`, whose lookup stops the run; a process's, a
//! thread's and a `net` directory hold only the entries above, and their
//! link counts only the subdirectories above; the inode numbers of the
//! machine-wide files, `/proc/net` and the socket tables were read live on
//! an x86_64 7.0 host, not on the pinned 6.8, and a process's and a
//! thread's are the model's own; a directory's `d_off` cookies count its
//! entries, as the volume's do.

use crate::fdtable::FdKind;
use crate::identity::Process;
use crate::paths::{SYMLINK_HOPS, Virtual};
use crate::{
    EACCES, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, O_APPEND, O_CREATE, O_DIRECTORY,
    O_EXCLUSIVE, O_NONBLOCK, O_OPENED, O_PATH, O_READ, O_TRUNCATE, O_WRITE, PATINA_ENTRY_DIRECTORY,
    PATINA_ENTRY_FILE, PATINA_ENTRY_SYMLINK, PATINA_FS_PROC, PATINA_FS_PROC_OWN, PatinaMetadata,
    PatinaTimestamp, SpinMutex, fail, install_fd, set_errno,
};
use patina_dst_abi::{FsDirectoryEntry, FsEntryKind};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_int;

mod net;
mod text;

pub(crate) use net::NetFile;

#[cfg(test)]
mod tests;

/// Where procfs is mounted.
pub(crate) const ROOT: &str = "/proc";
/// The name of its mount point in the root directory.
pub(crate) const MOUNT_POINT_NAME: &str = "proc";

/// A procfs node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Node {
    /// procfs's root, [`ROOT`].
    Root,
    /// `/proc/self`, a symlink to the caller's process.
    SelfLink,
    /// `/proc/net`, a symlink to the caller's `net` directory.
    NetLink,
    /// A machine-wide file, `/proc/<name>`.
    Machine(Machine),
    /// A process's directory, `/proc/<pid>`.
    Process(i32),
    /// A file in a process's directory.
    Of(i32, OfProcess),
    /// A process's thread directories, `/proc/<pid>/task`.
    Tasks(i32),
    /// One thread's directory, `/proc/<pid>/task/<tid>`.
    Thread(i32, i32),
    /// A file in a thread's directory.
    OfThread(i32, i32, OfProcess),
    /// A process's `net` directory, `/proc/<pid>/net`.
    Net(i32),
    /// A socket table in it.
    NetFile(i32, NetFile),
}

/// A machine-wide file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Machine {
    Stat,
    Uptime,
    Vmstat,
    Loadavg,
    Meminfo,
}

/// The machine-wide files and their names, in the root's order: by name
/// length, then bytes (`proc_match`).
const MACHINE: [(Machine, &str); 5] = [
    (Machine::Stat, "stat"),
    (Machine::Uptime, "uptime"),
    (Machine::Vmstat, "vmstat"),
    (Machine::Loadavg, "loadavg"),
    (Machine::Meminfo, "meminfo"),
];

/// A file of a process's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OfProcess {
    Status,
    Stat,
}

/// A process directory's files and their names, in its order
/// (`tgid_base_stuff`).
const OF_PROCESS: [(OfProcess, &str); 2] =
    [(OfProcess::Status, "status"), (OfProcess::Stat, "stat")];

/// `PROC_ROOT_INO`.
const ROOT_INO: u64 = 1;
/// `/proc/self`'s inode: the first `proc_alloc_inum` hands out
/// (`proc_self_init`, at the root's creation).
const SELF_INO: u64 = 0xF000_0000;
/// `/proc/net`'s, as the host's `/proc` numbered it (`proc_net_init`).
const NET_LINK_INO: u64 = 0xF000_0003;
/// Where the model numbers the processes' nodes: `get_next_ino` hands the
/// kernel's out as they are made, so any distinct numbers would do.
const PROCESS_INO_BASE: u64 = 0x1_0000;
/// Where it numbers the threads' nodes, past every process's.
const THREAD_INO_BASE: u64 = 1 << 40;
/// The task flags `<pid>/stat` reports (`PF_RANDOMIZE`: each process was
/// executed with address-space randomization, the default persona).
pub(super) const PF_RANDOMIZE: u32 = 0x0040_0000;
/// The flags an exited thread adds: `PF_EXITING` (`exit_signals`),
/// `PF_POSTCOREDUMP` (`coredump_task_exit`) and `PF_NOFREEZE`
/// (`do_task_dead`).
pub(super) const PF_EXITED: u32 = 0x0000_0004 | 0x0000_0008 | 0x0000_8000;

impl Node {
    /// The canonical path that names it.
    pub(crate) fn path(self) -> String {
        match self {
            Node::Root => ROOT.to_owned(),
            Node::SelfLink => format!("{ROOT}/self"),
            Node::NetLink => format!("{ROOT}/net"),
            Node::Machine(file) => format!("{ROOT}/{}", machine_name(file)),
            Node::Process(pid) => format!("{ROOT}/{pid}"),
            Node::Of(pid, file) => format!("{ROOT}/{pid}/{}", of_process_name(file)),
            Node::Tasks(pid) => format!("{ROOT}/{pid}/task"),
            Node::Thread(pid, tid) => format!("{ROOT}/{pid}/task/{tid}"),
            Node::OfThread(pid, tid, file) => {
                format!("{ROOT}/{pid}/task/{tid}/{}", of_process_name(file))
            }
            Node::Net(pid) => format!("{ROOT}/{pid}/net"),
            Node::NetFile(pid, file) => format!("{ROOT}/{pid}/net/{}", net::name(file)),
        }
    }

    /// Whether it is a directory.
    pub(crate) fn is_directory(self) -> bool {
        matches!(
            self,
            Node::Root | Node::Process(_) | Node::Tasks(_) | Node::Thread(..) | Node::Net(_)
        )
    }

    /// The directory `..` names from it: the root's is itself.
    fn parent(self) -> Node {
        match self {
            Node::Of(pid, _) | Node::Tasks(pid) | Node::Net(pid) => Node::Process(pid),
            Node::Thread(pid, _) => Node::Tasks(pid),
            Node::OfThread(pid, tid, _) => Node::Thread(pid, tid),
            Node::NetFile(pid, _) => Node::Net(pid),
            Node::Root | Node::SelfLink | Node::NetLink | Node::Machine(_) | Node::Process(_) => {
                Node::Root
            }
        }
    }

    fn kind(self) -> FsEntryKind {
        match self {
            Node::Root | Node::Process(_) | Node::Tasks(_) | Node::Thread(..) | Node::Net(_) => {
                FsEntryKind::Directory
            }
            Node::SelfLink | Node::NetLink => FsEntryKind::Symlink,
            Node::Machine(_) | Node::Of(..) | Node::OfThread(..) | Node::NetFile(..) => {
                FsEntryKind::File
            }
        }
    }

    /// The `PATINA_FS_*` value its owner reads from: a guest process's
    /// directory and files, its threads' and its `net` directory included,
    /// are the process's (the caller's); everything else, the socket tables
    /// included, is root's.
    fn fs(self) -> u32 {
        match self {
            Node::Process(pid)
            | Node::Of(pid, _)
            | Node::Tasks(pid)
            | Node::Thread(pid, _)
            | Node::OfThread(pid, ..)
            | Node::Net(pid)
                if pid != Process::INIT.pid() =>
            {
                PATINA_FS_PROC_OWN
            }
            _ => PATINA_FS_PROC,
        }
    }

    fn ino(self) -> u64 {
        let process = |pid: i32, slot: u64| PROCESS_INO_BASE + (pid as u64) * 8 + slot;
        let thread = |pid: i32, tid: i32, slot: u64| {
            THREAD_INO_BASE + (((pid as u64) << 22) | tid as u64) * 4 + slot
        };
        match self {
            Node::Root => ROOT_INO,
            Node::SelfLink => SELF_INO,
            Node::NetLink => NET_LINK_INO,
            // As the host's `/proc` numbered them.
            Node::Machine(Machine::Stat) => 4_026_532_024,
            Node::Machine(Machine::Uptime) => 4_026_532_025,
            Node::Machine(Machine::Vmstat) => 4_026_531_858,
            Node::Machine(Machine::Loadavg) => 4_026_532_022,
            Node::Machine(Machine::Meminfo) => 4_026_532_023,
            Node::Process(pid) => process(pid, 0),
            Node::Of(pid, OfProcess::Status) => process(pid, 1),
            Node::Of(pid, OfProcess::Stat) => process(pid, 2),
            Node::Tasks(pid) => process(pid, 3),
            Node::Net(pid) => process(pid, 4),
            Node::NetFile(_, file) => net::ino(file),
            Node::Thread(pid, tid) => thread(pid, tid, 0),
            Node::OfThread(pid, tid, OfProcess::Status) => thread(pid, tid, 1),
            Node::OfThread(pid, tid, OfProcess::Stat) => thread(pid, tid, 2),
        }
    }
}

fn machine_name(file: Machine) -> &'static str {
    MACHINE
        .iter()
        .find(|(each, _)| *each == file)
        .map_or("", |(_, name)| name)
}

fn of_process_name(file: OfProcess) -> &'static str {
    OF_PROCESS
        .iter()
        .find(|(each, _)| *each == file)
        .map_or("", |(_, name)| name)
}

/// A process name as `name_to_int` reads one: decimal digits, no leading
/// zero, below `u32::MAX`.
fn pid_name(name: &str) -> Option<i32> {
    if name.is_empty()
        || (name.len() > 1 && name.starts_with('0'))
        || !name.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    name.parse::<u32>()
        .ok()
        .and_then(|pid| i32::try_from(pid).ok())
}

/// What looking `name` up in directory `dir` finds (`proc_root_lookup`,
/// `proc_tgid_base_lookup`).
fn lookup(dir: Node, name: &str) -> Result<Node, c_int> {
    match dir {
        Node::Root => {
            if name == "self" {
                return Ok(Node::SelfLink);
            }
            if name == "net" {
                return Ok(Node::NetLink);
            }
            if name == "thread-self" {
                Virtual::Proc(Node::Root).unmodeled("a lookup of thread-self in");
            }
            if let Some((file, _)) = MACHINE.iter().find(|(_, each)| *each == name) {
                return Ok(Node::Machine(*file));
            }
            let pid = pid_name(name).ok_or(ENOENT)?;
            match crate::identity::lookup(pid) {
                Some((process, true)) => Ok(Node::Process(process.pid())),
                // `find_task_by_pid_ns` finds a thread too: its directory is
                // hidden from the listing but there.
                Some((_, false)) => crate::trap_fatal(&format!(
                    "{ROOT}/{pid} names a thread of the guest, whose procfs directory is not \
                     modeled; failing closed"
                )),
                None => Err(ENOENT),
            }
        }
        Node::Process(pid) if name == "task" => Ok(Node::Tasks(pid)),
        Node::Process(pid) if name == "net" => Ok(Node::Net(pid)),
        Node::Process(pid) => OF_PROCESS
            .iter()
            .find(|(_, each)| *each == name)
            .map(|(file, _)| Node::Of(pid, *file))
            .ok_or(ENOENT),
        Node::Tasks(pid) => {
            let tid = pid_name(name).ok_or(ENOENT)?;
            if threads(pid).contains(&tid) {
                Ok(Node::Thread(pid, tid))
            } else {
                Err(ENOENT)
            }
        }
        Node::Thread(pid, tid) if name == "ns" => crate::trap_fatal(&format!(
            "{ROOT}/{pid}/task/{tid}/ns, a thread's namespace files, is not modeled; failing \
             closed"
        )),
        Node::Thread(pid, tid) => OF_PROCESS
            .iter()
            .find(|(_, each)| *each == name)
            .map(|(file, _)| Node::OfThread(pid, tid, *file))
            .ok_or(ENOENT),
        Node::Net(pid) => net::NET
            .iter()
            .find(|(_, each)| *each == name)
            .map(|(file, _)| Node::NetFile(pid, *file))
            .ok_or(ENOENT),
        Node::SelfLink
        | Node::NetLink
        | Node::Machine(_)
        | Node::Of(..)
        | Node::OfThread(..)
        | Node::NetFile(..) => Err(ENOTDIR),
    }
}

/// The live threads of process `pid`, by id: init's one, or the guest's
/// as the thread census counts them.
fn threads(pid: i32) -> Vec<i32> {
    if pid == Process::INIT.pid() {
        return vec![pid];
    }
    crate::thread::census()
        .threads
        .iter()
        .map(|thread| thread.tid)
        .collect()
}

/// The node a canonical path in procfs names (a procfs directory
/// descriptor's, as a resolution's base); `None` for a path outside it.
pub(crate) fn node_at(path: &str) -> Option<Node> {
    let rest = path.strip_prefix(ROOT)?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let mut node = Node::Root;
    for name in rest.split('/').filter(|name| !name.is_empty()) {
        node = lookup(node, name).ok()?;
    }
    Some(node)
}

/// Where a walk through procfs ends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Walked {
    /// At a node.
    At(Node),
    /// Out of procfs by `..` at its root: the walk goes on from the root of
    /// the volume with what remains.
    Left,
}

/// Walk `remaining` from `start` as `link_path_walk` does: `.` stays, `..`
/// goes up (out of procfs at its root), a component through a file is
/// `ENOTDIR`, and a link (`self`, `net`) is followed, its target walked from
/// the link's directory (one of the walk's `hops`; `ELOOP` under
/// `no_symlinks`), unless it is the final component and `nofollow`.
pub(crate) fn walk(
    start: Node,
    remaining: &mut VecDeque<String>,
    nofollow: bool,
    no_symlinks: bool,
    hops: &mut usize,
) -> Result<Walked, c_int> {
    let mut node = start;
    while let Some(component) = remaining.pop_front() {
        if !node.is_directory() {
            return Err(ENOTDIR);
        }
        match component.as_str() {
            "." => {}
            ".." if node == Node::Root => return Ok(Walked::Left),
            ".." => node = node.parent(),
            name => {
                if let Node::Process(pid) = node
                    && name == "ns"
                {
                    return namespaces(pid, remaining);
                }
                let next = lookup(node, name)?;
                match link_target(next) {
                    Some(target) if !(nofollow && remaining.is_empty()) => {
                        if no_symlinks {
                            return Err(ELOOP);
                        }
                        *hops += 1;
                        if *hops > SYMLINK_HOPS {
                            return Err(ELOOP);
                        }
                        for component in target.rsplit('/').filter(|name| !name.is_empty()) {
                            remaining.push_front(component.to_owned());
                        }
                    }
                    _ => node = next,
                }
            }
        }
    }
    Ok(Walked::At(node))
}

/// `ns` in process `pid`'s directory. The namespace files the model answers
/// are the caller's, by the spelling `/proc/self/ns/<entry>`, which the
/// resolver recognizes before any walk; a name among them that is no entry
/// is `ENOENT`, as nsfs's directory answers; any other way to them is not
/// modeled.
fn namespaces(pid: i32, remaining: &VecDeque<String>) -> Result<Walked, c_int> {
    if pid == Process::current().pid()
        && remaining.len() == 1
        && let Some(name) = remaining.front()
        && !matches!(name.as_str(), "." | "..")
        && crate::nsfs::entry_at(&format!("/proc/self/ns/{name}")).is_none()
    {
        return Err(ENOENT);
    }
    crate::trap_fatal(&format!(
        "{ROOT}/{pid}/ns reached other than as /proc/self/ns/<entry> is not modeled; failing \
         closed"
    ))
}

/// When each node was first used, in nanoseconds on the virtual clock.
static MADE: SpinMutex<BTreeMap<Node, u64>> = SpinMutex::new(BTreeMap::new());

/// The instant `node`'s inode was made: the root and `self` at the mount
/// (the boot), every other node at its first use in the run (the kernel
/// makes a node's inode at its first lookup and keeps it while it is
/// cached; the model keeps the first).
fn made(node: Node) -> u64 {
    let now = match node {
        Node::Root | Node::SelfLink | Node::NetLink => crate::volume::boot_instant(),
        _ => crate::fs_time_unrecorded(),
    };
    *MADE.lock().entry(node).or_insert(now)
}

/// `node`'s metadata (`proc_root_getattr`, `pid_getattr`,
/// `proc_getattr`): its kind and mode, its owner's filesystem, size 0,
/// every time the instant it was [`made`]. The root's link count is the
/// kernel's `proc_root` count (two, with no subdirectory modeled) plus the
/// processes; a process directory's is two plus its `task` and `net`
/// directories (`pid_entry_nlink` of the entries modeled), `task`'s two
/// plus its threads, and a thread's or a `net` directory's two, with no
/// subdirectory modeled.
pub(crate) fn metadata(node: Node) -> PatinaMetadata {
    let made = PatinaTimestamp::from_nanos(i128::from(made(node)));
    let (kind, mode) = match node.kind() {
        FsEntryKind::Directory => (PATINA_ENTRY_DIRECTORY, 0o555),
        FsEntryKind::Symlink => (PATINA_ENTRY_SYMLINK, 0o777),
        _ => (PATINA_ENTRY_FILE, 0o444),
    };
    let nlink = match node {
        Node::Root => 2 + crate::identity::processes().len() as u32,
        Node::Process(_) => 4,
        Node::Tasks(pid) => 2 + threads(pid).len() as u32,
        Node::Thread(..) | Node::Net(_) => 2,
        _ => 1,
    };
    PatinaMetadata {
        kind,
        mode,
        nlink,
        fs: node.fs(),
        rdev_major: 0,
        rdev_minor: 0,
        length: 0,
        blocks: 0,
        ino: node.ino(),
        atime: made,
        mtime: made,
        ctime: made,
        btime: PatinaTimestamp::default(),
    }
}

/// What a symlink reads: `self`'s target, the caller's pid, and `net`'s,
/// `self/net`; `None` for a node that is no link.
pub(crate) fn link_target(node: Node) -> Option<String> {
    match node {
        Node::SelfLink => Some(Process::current().pid().to_string()),
        Node::NetLink => Some("self/net".to_owned()),
        _ => None,
    }
}

/// A directory's entries now, `.` and `..` first (the root's `..` is itself,
/// the root of its mount), as `proc_root_readdir`, `proc_pident_readdir`,
/// `proc_task_readdir` (the threads by id) and `proc_readdir_de` list them;
/// `ENOENT` for a thread's directory once the thread has gone
/// (`proc_pident_readdir` finds no task).
pub(crate) fn listing(dir: Node) -> Result<Vec<FsDirectoryEntry>, c_int> {
    if let Node::Thread(pid, tid) = dir
        && !threads(pid).contains(&tid)
    {
        return Err(ENOENT);
    }
    let entry = |name: &str, node: Node| FsDirectoryEntry {
        name: name.to_owned(),
        kind: node.kind(),
        ino: node.ino(),
    };
    let mut entries = vec![entry(".", dir), entry("..", dir.parent())];
    match dir {
        Node::Root => {
            let mut files: Vec<(&str, Node)> = MACHINE
                .iter()
                .map(|(file, name)| (*name, Node::Machine(*file)))
                .chain([("net", Node::NetLink)])
                .collect();
            files.sort_by_key(|(name, _)| (name.len(), name.as_bytes()));
            entries.extend(files.into_iter().map(|(name, node)| entry(name, node)));
            entries.push(entry("self", Node::SelfLink));
            for listed in crate::identity::processes() {
                let pid = listed.process.pid();
                entries.push(entry(&pid.to_string(), Node::Process(pid)));
            }
        }
        Node::Process(pid) => {
            entries.push(entry("task", Node::Tasks(pid)));
            entries.push(entry("net", Node::Net(pid)));
            entries.extend(
                OF_PROCESS
                    .iter()
                    .map(|(file, name)| entry(name, Node::Of(pid, *file))),
            );
        }
        Node::Tasks(pid) => {
            for tid in threads(pid) {
                entries.push(entry(&tid.to_string(), Node::Thread(pid, tid)));
            }
        }
        Node::Thread(pid, tid) => entries.extend(
            OF_PROCESS
                .iter()
                .map(|(file, name)| entry(name, Node::OfThread(pid, tid, *file))),
        ),
        Node::Net(pid) => entries.extend(
            net::NET
                .iter()
                .map(|(file, name)| entry(name, Node::NetFile(pid, *file))),
        ),
        Node::SelfLink
        | Node::NetLink
        | Node::Machine(_)
        | Node::Of(..)
        | Node::OfThread(..)
        | Node::NetFile(..) => {}
    }
    Ok(entries)
}

/// How many of `entries`, directory `dir`'s listing now, a `getdents` at
/// `position` passes over before it returns any: `position` of them, but
/// for a thread the last call could not return (`unreturned`), which
/// `proc_task_readdir` resumes at while it lives (`first_tid`'s `f_version`
/// hint), wherever the threads before it have gone.
pub(crate) fn resume(
    dir: Node,
    entries: &[FsDirectoryEntry],
    position: u64,
    unreturned: Option<&[u8]>,
) -> u64 {
    if let (Node::Tasks(_), Some(name)) = (dir, unreturned)
        && position > 2
        && let Some(index) = entries
            .iter()
            .skip(2)
            .position(|entry| entry.name.as_bytes() == name)
    {
        return index as u64 + 2;
    }
    position
}

/// An open procfs node: a file's text and positions, or a directory.
struct Open {
    node: Node,
    /// The text reads serve, made at the first read.
    text: Option<Vec<u8>>,
    /// Where the last read ended (`seq_file`'s `read_pos`).
    read_pos: u64,
    /// The description's position (`f_pos`).
    pos: u64,
    /// The reads under way that made text with the table's lock released:
    /// each holds the open as the kernel's `fdget` holds the file.
    reading: u32,
    /// Whether the description's last reference went while a read was
    /// under way: the last of them lets the open go.
    released: bool,
}

/// The open procfs nodes, by description handle, and the next handle.
static OPENS: SpinMutex<(u64, BTreeMap<u64, Open>)> = SpinMutex::new((1, BTreeMap::new()));

/// An open of `node` (`do_open`'s order): `O_CREAT|O_EXCL` is `EEXIST`;
/// a link itself (under `O_NOFOLLOW`) `ELOOP`; `O_DIRECTORY` on a file
/// `ENOTDIR`; creating or writing a directory (`O_TRUNC` asks for write
/// access) `EISDIR`; writing a file `EACCES` (`0444`, and the caller holds
/// no `CAP_DAC_OVERRIDE`). A read-only open is a [`FdKind::Proc`] or
/// [`FdKind::ProcDir`] description, `O_APPEND`, `O_NONBLOCK` and
/// `O_DIRECTORY` kept as status (`F_GETFL` reports them); an `O_PATH` one
/// is not modeled.
pub(crate) fn open(node: Node, flags: u32, cloexec: bool) -> c_int {
    if flags & O_PATH != 0 {
        Virtual::Proc(node).unmodeled("an O_PATH open");
    }
    if flags & (O_CREATE | O_EXCLUSIVE) == O_CREATE | O_EXCLUSIVE {
        return fail(EEXIST);
    }
    if link_target(node).is_some() {
        return fail(ELOOP);
    }
    let directory = node.is_directory();
    if flags & O_DIRECTORY != 0 && !directory {
        return fail(ENOTDIR);
    }
    let writes = flags & (O_WRITE | O_TRUNCATE) != 0;
    if directory && (writes || flags & O_CREATE != 0) {
        return fail(EISDIR);
    }
    if writes {
        return fail(EACCES);
    }
    let kind = if directory {
        FdKind::ProcDir
    } else {
        FdKind::Proc
    };
    let handle = {
        let mut opens = OPENS.lock();
        let handle = opens.0;
        opens.0 += 1;
        opens.1.insert(
            handle,
            Open {
                node,
                text: None,
                read_pos: 0,
                pos: 0,
                reading: 0,
                released: false,
            },
        );
        handle
    };
    let status = O_READ | O_OPENED | (flags & (O_APPEND | O_NONBLOCK | O_DIRECTORY));
    match install_fd(kind, handle, status, cloexec) {
        Ok(number) => {
            made(node);
            set_errno(0);
            number
        }
        Err(errno) => {
            released(handle);
            fail(errno)
        }
    }
}

/// A procfs description's last reference went: its open goes with it, or
/// with the last read under way on it.
pub(crate) fn released(handle: u64) {
    let mut opens = OPENS.lock();
    match opens.1.get_mut(&handle) {
        Some(open) if open.reading > 0 => open.released = true,
        _ => {
            opens.1.remove(&handle);
        }
    }
}

/// A read's hold on an open while it makes text with the table's lock
/// released ([`locked`]); dropped unspent (the making failed), it lets the
/// open go if the description went meanwhile.
struct Hold(u64);

impl Hold {
    /// Give the hold up under the table's lock the caller holds.
    fn spend(self, open: &mut Open) {
        open.reading -= 1;
        std::mem::forget(self);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut opens = OPENS.lock();
        if let Some(open) = opens.1.get_mut(&self.0) {
            open.reading -= 1;
            if open.released && open.reading == 0 {
                opens.1.remove(&self.0);
            }
        }
    }
}

/// The node a procfs description is open on.
pub(crate) fn node_of(handle: u64) -> Node {
    OPENS
        .lock()
        .1
        .get(&handle)
        .map(|open| open.node)
        .unwrap_or_else(|| crate::trap_fatal("a procfs description without its open node"))
}

/// The inode number of the node a procfs description is open on: what an
/// advisory lock on it is taken on.
pub(crate) fn ino_of(handle: u64) -> u64 {
    node_of(handle).ino()
}

/// Whether a procfs file has a `poll`: the machine's files
/// (`proc_create_single`'s `proc_iter_file_ops`) and the socket tables
/// (`proc_create_net`'s, read through `proc_reg_file_ops`) have
/// `proc_reg_poll`, answering `DEFAULT_POLLMASK`; a process's and a
/// thread's files are `proc_single_file_operations`', with none, so
/// `epoll_ctl` refuses them.
pub(crate) fn polls(handle: u64) -> bool {
    matches!(node_of(handle), Node::Machine(_) | Node::NetFile(..))
}

/// Whether a procfs file has a `splice_read`: only `proc_iter_file_ops`
/// (the machine's files) has one; a splice from any other is `EINVAL`.
pub(crate) fn splices(handle: u64) -> bool {
    matches!(node_of(handle), Node::Machine(_))
}

/// A procfs description's position (`f_pos`).
pub(crate) fn position(handle: u64) -> u64 {
    OPENS
        .lock()
        .1
        .get(&handle)
        .map(|open| open.pos)
        .unwrap_or_else(|| crate::trap_fatal("a procfs description without its open node"))
}

/// Set a procfs description's position, as a transfer moves it (the text is
/// left as it is: a read from anywhere but where the last one ended makes
/// it again).
pub(crate) fn set_position(handle: u64, position: u64) {
    if let Some(open) = OPENS.lock().1.get_mut(&handle) {
        open.pos = position;
    }
}

/// Run `step` on description `handle`'s open under the table's lock, with
/// text made beforehand when it asks for some: `step` answers `None` when
/// it needs text and `fresh` holds none, and the text is made outside the
/// lock (making it reads the clocks and the threads, and takes a scheduling
/// point) before `step` runs again on the open as it is then. So a read or a
/// seek judges and moves the position in one step, with nothing between, as
/// `seq_file` does under its lock. The open is held while the text is made
/// ([`Hold`]): a close on another thread meanwhile lets it go only once the
/// step is done, as the kernel's file outlives its descriptor for a read
/// under way.
fn locked<T>(
    handle: u64,
    mut step: impl FnMut(&mut Open, &mut Option<Vec<u8>>) -> Result<Option<T>, c_int>,
) -> Result<T, c_int> {
    let mut fresh = None;
    let mut hold: Option<Hold> = None;
    loop {
        let node = {
            let mut opens = OPENS.lock();
            let open = opens.1.get_mut(&handle).ok_or(EINVAL)?;
            if let Some(hold) = hold.take() {
                hold.spend(open);
            }
            if let Some(answer) = step(open, &mut fresh).transpose() {
                if open.released && open.reading == 0 {
                    opens.1.remove(&handle);
                }
                return answer;
            }
            open.reading += 1;
            hold = Some(Hold(handle));
            open.node
        };
        fresh = Some(text::generate(node)?);
    }
}

/// Up to `len` bytes of a procfs file's text from position `at` (`pread`)
/// or the description's own (`read`, which moves it past them), handed to
/// `deliver` before the read counts: a delivery that fails (`EFAULT`)
/// leaves the position where it was. The text is made again when the read
/// starts anywhere but where the last one ended ([`Open::wants_text`]); a
/// read of no bytes does nothing (`seq_read_iter`).
fn read_with(
    handle: u64,
    len: usize,
    at: Option<u64>,
    mut deliver: impl FnMut(&[u8]) -> Result<(), c_int>,
) -> Result<Vec<u8>, c_int> {
    locked(handle, |open, fresh| {
        open.read_step(fresh, len, at, &mut deliver)
    })
}

/// [`read_with`] for a transfer, whose bytes go to the shim.
pub(crate) fn read(handle: u64, len: usize, at: Option<u64>) -> Result<Vec<u8>, c_int> {
    read_with(handle, len, at, |_| Ok(()))
}

/// A read of procfs file description `handle` into the guest's
/// `destination` ([`read_with`]): the bytes read, or -1 with the errno
/// (`EFAULT` for a buffer the copy cannot reach, which reads nothing).
pub(crate) fn read_to(
    handle: u64,
    destination: *mut std::ffi::c_void,
    length: usize,
    at: Option<u64>,
) -> isize {
    let copied = read_with(handle, length, at, |bytes| {
        crate::uaccess::write_bytes(destination as usize, bytes)
    });
    match copied {
        Ok(bytes) => {
            set_errno(0);
            bytes.len() as isize
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// `seq_lseek`: `SEEK_SET` and `SEEK_CUR` move the position (`EINVAL` for a
/// negative one, and for any other `whence`); see [`Open::seek_to`].
pub(crate) fn seek(handle: u64, offset: i64, whence: u32) -> Result<u64, c_int> {
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    locked(handle, |open, fresh| {
        let target = match whence {
            SEEK_SET => offset,
            SEEK_CUR => i64::try_from(open.pos)
                .ok()
                .and_then(|pos| pos.checked_add(offset))
                .ok_or(EINVAL)?,
            _ => return Err(EINVAL),
        };
        let target = u64::try_from(target).map_err(|_| EINVAL)?;
        Ok(open.seek_step(fresh, target))
    })
}

impl Open {
    /// One try at a read of `len` bytes at `at` or the position now (a
    /// [`locked`] step): `None` when it wants text and `fresh` holds none,
    /// otherwise what [`serve`](Self::serve) answers.
    fn read_step(
        &mut self,
        fresh: &mut Option<Vec<u8>>,
        len: usize,
        at: Option<u64>,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), c_int>,
    ) -> Result<Option<Vec<u8>>, c_int> {
        let pos = at.unwrap_or(self.pos);
        let text = if self.wants_text(pos, len) {
            match fresh.take() {
                Some(text) => Some(text),
                None => return Ok(None),
            }
        } else {
            None
        };
        self.serve(text, pos, len, at.is_none(), deliver).map(Some)
    }

    /// One try at a seek to `target` (a [`locked`] step): `None` when it
    /// wants text and `fresh` holds none.
    fn seek_step(&mut self, fresh: &mut Option<Vec<u8>>, target: u64) -> Option<u64> {
        let text = if self.stale_after_seek(target) {
            Some(fresh.take()?)
        } else {
            None
        };
        self.seek_to(text, target);
        Some(target)
    }

    /// Whether a read of `len` bytes at `pos` makes the text again: it reads
    /// something, and none is made yet or it starts other than where the
    /// last one ended (`seq_read_iter`'s `traverse`).
    fn wants_text(&self, pos: u64, len: usize) -> bool {
        len != 0 && (self.text.is_none() || pos != self.read_pos)
    }

    /// Whether a seek to `target` makes the text at once: it moves away from
    /// where the last read ended, and not to the start ([`Open::seek_to`]).
    fn stale_after_seek(&self, target: u64) -> bool {
        target != 0 && target != self.read_pos
    }

    /// Serve a read of `len` bytes at `pos` from `fresh` text (made because
    /// the read [`wants_text`](Self::wants_text)) or the kept text, handing
    /// them to `deliver`. Once it takes them, the next read continues where
    /// this one ended, and a `read` (`moves`) moves the position there too;
    /// when it fails, fresh text is kept for a read at `pos` and nothing
    /// moves. A read of no bytes changes nothing.
    fn serve(
        &mut self,
        fresh: Option<Vec<u8>>,
        pos: u64,
        len: usize,
        moves: bool,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), c_int>,
    ) -> Result<Vec<u8>, c_int> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if let Some(fresh) = fresh {
            self.text = Some(fresh);
            self.read_pos = pos;
        }
        let text = self.text.as_deref().unwrap_or_default();
        let start = usize::try_from(pos).unwrap_or(usize::MAX).min(text.len());
        let end = start.saturating_add(len).min(text.len());
        let bytes = text[start..end].to_vec();
        deliver(&bytes)?;
        self.read_pos = pos + bytes.len() as u64;
        if moves {
            self.pos = self.read_pos;
        }
        Ok(bytes)
    }

    /// Move to `target`. A move to where the last read ended keeps the text;
    /// one to the start drops it, for the next read to make (`traverse` of
    /// offset 0 only empties the buffer); one anywhere else takes `fresh`,
    /// made for it.
    fn seek_to(&mut self, fresh: Option<Vec<u8>>, target: u64) {
        if target != self.read_pos {
            self.text = if target == 0 { None } else { fresh };
            self.read_pos = target;
        }
        self.pos = target;
    }
}
