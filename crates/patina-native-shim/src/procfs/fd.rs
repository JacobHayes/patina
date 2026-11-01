//! `/proc/<pid>/fd` (`proc_fd_operations`, `proc_fd_link`): a link per open
//! descriptor of the caller, named by its number, read from the one
//! descriptor table at every lookup and listing, so a closed number (or one
//! reserved for a call still making its object) is `ENOENT` at once.
//!
//! A link is a magic link (`nd_jump_link`): following it lands on what the
//! descriptor holds, not on a lookup of the name it reads. A node of the
//! volume that still has a name is reached by its name now (the
//! filesystem's answer for the descriptor, so a rename moves it); a node
//! with none left, and an object no path names (a socket, a pipe, an
//! anonymous inode), is [`Virtual::Held`]. A memory device, a namespace file
//! and a procfs node are the entries the resolver answers for their paths.

use super::Node;
use crate::fdtable::FdKind;
use crate::paths::Virtual;
use crate::{ENOENT, O_READ, O_WRITE};
use patina_dst_abi::Fd;
use std::ffi::c_int;

/// The open descriptor numbers, ascending (`proc_readfd_common`).
pub(super) fn numbers() -> Vec<c_int> {
    crate::state::fd_table().lock().numbers()
}

/// Whether `number` is open.
pub(super) fn is_open(number: c_int) -> bool {
    crate::resolve_fd(number).is_ok()
}

/// The link's own mode (`tid_fd_update_inode`): `S_IRUSR|S_IXUSR` for a
/// readable description, `S_IWUSR|S_IXUSR` for a writable one, nothing for an
/// `O_PATH` one.
pub(super) fn mode(number: c_int) -> u32 {
    let Ok(resolved) = crate::resolve_fd(number) else {
        return 0;
    };
    if resolved.kind.is_path_only() {
        return 0;
    }
    let mut mode = 0;
    if resolved.status & O_READ != 0 {
        mode |= 0o500;
    }
    if resolved.status & O_WRITE != 0 {
        mode |= 0o300;
    }
    mode
}

/// The volume node a descriptor holds, as a driver handle (`None` for any
/// other object). A FIFO's pipe end holds its node by inode alone.
fn volume_handle(kind: FdKind, handle: u64) -> Option<Fd> {
    kind.is_fs().then_some(Fd(handle))
}

/// What the link reads (`proc_fd_link` + `d_path`): the node's path now, or
/// the pseudo-filesystem's name for an object no path names (`socket:[ino]`,
/// `pipe:[ino]`, `anon_inode:<name>`, a namespace's `<type>:[ino]`).
pub(super) fn text(number: c_int) -> Result<String, c_int> {
    let resolved = crate::resolve_fd(number).map_err(|_| ENOENT)?;
    let link = Virtual::Proc(Node::FdLink(
        crate::identity::Process::current().pid(),
        number,
    ));
    if let Some(fd) = volume_handle(resolved.kind, resolved.handle) {
        return match crate::paths::node_path(fd) {
            Ok(path) => Ok(path),
            // `d_path` names an unlinked node `<its last name> (deleted)`;
            // the filesystem keeps no name for it.
            Err(errno) if errno == ENOENT => {
                link.unmodeled("reading the link of an unlinked node, whose last name is not kept,")
            }
            Err(errno) => Err(errno),
        };
    }
    let anonymous = |name: &str| Ok(format!("anon_inode:{name}"));
    match resolved.kind {
        FdKind::MemDevice => Ok(crate::memdev::MemDevice::of_handle(resolved.handle)
            .path()
            .to_owned()),
        FdKind::Namespace | FdKind::NamespacePath => {
            Ok(crate::nsfs::link_target(resolved.handle as usize))
        }
        FdKind::Proc | FdKind::ProcDir => Ok(super::node_of(resolved.handle).path()),
        FdKind::EventFd => anonymous("[eventfd]"),
        FdKind::TimerFd => anonymous("[timerfd]"),
        FdKind::SignalFd => anonymous("[signalfd]"),
        FdKind::Epoll => anonymous("[eventpoll]"),
        FdKind::Inotify => anonymous("inotify"),
        FdKind::Pidfd => anonymous("[pidfd]"),
        FdKind::Pipe if crate::thread::fifo_ino(number).is_some() => {
            link.unmodeled("reading the link of a FIFO's end, whose node has no path in the model,")
        }
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::Pipe | FdKind::Socket => {
            let metadata = crate::thread::pipe_inode_metadata(number)
                .unwrap_or_else(|| link.unmodeled("reading the link"));
            let family = if metadata.kind == crate::PATINA_ENTRY_SOCKET {
                "socket"
            } else {
                "pipe"
            };
            Ok(format!("{family}:[{}]", metadata.ino))
        }
        FdKind::File | FdKind::Dir | FdKind::OPath => unreachable!("a volume handle"),
    }
}

/// What following the link lands on.
pub(crate) enum Held {
    /// A volume node by its path now.
    Volume(String),
    /// A procfs node: the walk goes on in procfs.
    Proc(Node),
    /// An entry the resolver answers itself, no directory.
    Entry(Virtual),
}

/// What descriptor `number` holds (`proc_fd_get_link`): `ENOENT` once it is
/// closed.
pub(super) fn held(number: c_int) -> Result<Held, c_int> {
    let resolved = crate::resolve_fd(number).map_err(|_| ENOENT)?;
    let pinned = Held::Entry(Virtual::Held(number));
    if let Some(fd) = volume_handle(resolved.kind, resolved.handle) {
        return match crate::paths::node_path(fd) {
            Ok(path) => Ok(Held::Volume(path)),
            // The filesystem keeps no metadata for a removed directory.
            Err(errno) if errno == ENOENT && resolved.kind == FdKind::Dir => {
                Virtual::Held(number).unmodeled("a walk to a removed directory,")
            }
            Err(errno) if errno == ENOENT => Ok(pinned),
            Err(errno) => Err(errno),
        };
    }
    let entry = Held::Entry;
    Ok(match resolved.kind {
        FdKind::MemDevice => entry(Virtual::MemDevice(crate::memdev::MemDevice::of_handle(
            resolved.handle,
        ))),
        FdKind::Namespace | FdKind::NamespacePath => {
            entry(Virtual::Namespace(resolved.handle as usize))
        }
        FdKind::Proc | FdKind::ProcDir => Held::Proc(super::node_of(resolved.handle)),
        _ => pinned,
    })
}

/// The volume node descriptor `number` holds while no name is left to it, as
/// a driver handle; `None` for any other object.
pub(crate) fn unlinked_handle(number: c_int) -> Option<Fd> {
    let resolved = crate::resolve_fd(number).ok()?;
    volume_handle(resolved.kind, resolved.handle)
}
