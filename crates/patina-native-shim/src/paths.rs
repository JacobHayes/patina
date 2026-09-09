//! The one path resolver, the working directory, and the umask: the process
//! state a kernel keeps between a guest's path spelling and the filesystem.
//!
//! Every `patina_*` entry that takes a `(dirfd, path)` pair resolves it HERE,
//! so the C interposers and the SUD rows are two spellings of one resolution:
//! the working directory for `AT_FDCWD`, the descriptor's NODE for a directory
//! descriptor, `.` and `..` applied to the resolved directory (after symlink
//! expansion, as the kernel applies them — never lexically across a link),
//! symlink walking with the kernel's 40-hop `ELOOP` limit, `ENAMETOOLONG` at
//! `PATH_MAX`/`NAME_MAX`, `ENOTDIR` for a component resolved through a
//! non-directory, and the trailing-slash rule. The deterministic filesystem
//! keeps its strict canonical-only contract underneath: it refuses `..` and
//! an intermediate symlink, so what it is handed is always what this resolver
//! produced.
//!
//! The working directory is a NODE, not a name: it is held as a path-only
//! driver handle (what `chdir` opens, what `fchdir` dups) and its name is asked
//! of the filesystem at every use, so a rename of an ancestor moves it and an
//! unlinked working directory answers `ENOENT` from `getcwd`, both as Linux
//! does. The initial directory is `/` unless the run was configured with one
//! (`run --cwd`), which is opened at install so a bad configuration refuses the
//! run rather than failing its first relative path. `chdir`/`fchdir`/`umask`
//! are guest-driven, like `setenv`: derived from control flow, never recorded,
//! reproduced on replay by re-executing the guest.

use std::collections::VecDeque;
use std::ffi::c_int;
use std::sync::atomic::{AtomicU32, Ordering};

use patina_dst_abi::{Fd, FsEntryKind, FsMetadata, OpenFlags};
use patina_dst_runtime::{Context, RuntimeError};

use crate::fdtable::FdKind;
use crate::{EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, SpinMutex, resolve_fd, with_context};

/// Linux `PATH_MAX`: a path (with its terminator) at or past this length is
/// `ENAMETOOLONG`.
pub(crate) const PATH_MAX: usize = 4096;
/// Linux `NAME_MAX`: a single component longer than this is `ENAMETOOLONG`.
pub(crate) const NAME_MAX: usize = 255;
/// The kernel's total symlink budget for one resolution (`MAXSYMLINKS`).
pub(crate) const SYMLINK_HOPS: usize = 40;
/// `AT_FDCWD` on the wire: the Linux value, which the C layer maps its
/// platform's spelling onto (`PATINA_AT_FDCWD` in `patina_native.h`).
pub(crate) const AT_FDCWD: c_int = -100;

/// Do not follow a trailing symlink: the resolution names the LINK itself
/// (`O_NOFOLLOW`, `AT_SYMLINK_NOFOLLOW`, `lstat`, `unlink`, `rename`, ...).
pub(crate) const RESOLVE_NOFOLLOW: u32 = 1 << 0;
/// An empty path names the base itself — the working directory for `AT_FDCWD`,
/// the descriptor's node otherwise (`AT_EMPTY_PATH`, `readlinkat(fd, "")`).
/// Without it an empty path is `ENOENT`.
pub(crate) const RESOLVE_EMPTY_PATH: u32 = 1 << 1;
pub(crate) const RESOLVE_ALL: u32 = RESOLVE_NOFOLLOW | RESOLVE_EMPTY_PATH;

/// The one path that names a device the shim owns rather than a filesystem
/// entry. It is resolved without consulting the driver so the entropy device
/// exists whether or not the image has a `/dev`.
const URANDOM: &str = "/dev/urandom";

/// A resolved path: the canonical absolute path the driver accepts, and the
/// final entry's metadata when it exists (`None` when the final component is
/// missing, which is what a creating call needs to proceed).
pub(crate) struct Resolved {
    pub(crate) path: String,
    pub(crate) metadata: Option<FsMetadata>,
}

/// The default umask every process starts with.
const DEFAULT_UMASK: u32 = 0o022;

static UMASK: AtomicU32 = AtomicU32::new(DEFAULT_UMASK);

/// The process umask, applied by every creating entry before the driver call
/// so the driver stores what the kernel would store.
pub(crate) fn umask() -> u32 {
    UMASK.load(Ordering::Relaxed)
}

/// `umask(2)`: install a new mask (only the permission bits count) and return
/// the previous one.
pub(crate) fn set_umask(mask: u32) -> u32 {
    UMASK.swap(mask & 0o777, Ordering::Relaxed)
}

/// The working directory's driver handle. `None` until first use (the default
/// `/`, opened lazily so a run that never touches a relative path or `getcwd`
/// pays no effect for it) or until install opened a configured directory.
static CWD: SpinMutex<Option<Fd>> = SpinMutex::new(None);

fn cwd_handle() -> Result<Fd, c_int> {
    if let Some(fd) = *CWD.lock() {
        return Ok(fd);
    }
    // The open is a scheduling point, so it runs outside the lock; another
    // task may have opened the root meanwhile, in which case ours is released.
    let fd = with_context(|context| context.fs_open("/", OpenFlags::path_only()))?;
    let existing = {
        let mut guard = CWD.lock();
        match *guard {
            Some(existing) => Some(existing),
            None => {
                *guard = Some(fd);
                None
            }
        }
    };
    match existing {
        Some(existing) => {
            let _ = with_context(|context| context.fs_close(fd));
            Ok(existing)
        }
        None => Ok(fd),
    }
}

/// Where the working directory's node is NOW. `ENOENT` once its last name is
/// gone, exactly as `getcwd(2)` answers for an unlinked directory.
pub(crate) fn cwd_path() -> Result<String, c_int> {
    let fd = cwd_handle()?;
    with_context(|context| context.fs_fd_path(fd))
}

fn replace_cwd(new: Fd) -> Result<(), c_int> {
    let previous = CWD.lock().replace(new);
    if let Some(previous) = previous {
        with_context(|context| context.fs_close(previous))?;
    }
    Ok(())
}

/// `chdir(2)`: the resolved entry must exist, be a directory, and be
/// searchable by the one modeled identity; the node is then held as the new
/// working directory.
pub(crate) fn chdir(dirfd: c_int, path: &str) -> Result<(), c_int> {
    let resolved = resolve(dirfd, path, 0)?;
    let metadata = resolved.metadata.ok_or(ENOENT)?;
    if metadata.kind != FsEntryKind::Directory {
        return Err(ENOTDIR);
    }
    if metadata.mode & 0o100 == 0 {
        return Err(EACCES);
    }
    let fd = with_context(|context| context.fs_open(&resolved.path, OpenFlags::path_only()))?;
    replace_cwd(fd)
}

/// `fchdir(2)`: a directory descriptor (opened plainly or `O_PATH`) becomes the
/// working directory; the shim takes its own reference on the node so the guest
/// closing the number changes nothing.
pub(crate) fn fchdir(guest_fd: c_int) -> Result<(), c_int> {
    let resolved = resolve_fd(guest_fd)?;
    if resolved.kind != FdKind::Dir {
        return Err(ENOTDIR);
    }
    let handle = Fd(resolved.handle);
    let metadata = with_context(|context| context.fs_fd_metadata(handle))?;
    if metadata.mode & 0o100 == 0 {
        return Err(EACCES);
    }
    let duplicate = with_context(|context| context.fs_dup(handle))?;
    replace_cwd(duplicate)
}

/// Open the configured initial working directory at install, on the context
/// directly (there is no installed runtime yet). A path that is not an existing
/// directory refuses the run by name: the alternative — a run whose every
/// relative path answers `ENOENT` — is a misconfiguration the guest cannot
/// distinguish from its own bug.
pub(crate) fn install_cwd(context: &mut Context) -> Result<(), RuntimeError> {
    let Some(path) = context.guest_cwd().map(str::to_owned) else {
        return Ok(());
    };
    let metadata = context.fs_metadata(&path).map_err(|error| {
        RuntimeError::Config(format!(
            "--cwd {path:?} is not a directory in the deterministic filesystem: {error}"
        ))
    })?;
    if metadata.kind != FsEntryKind::Directory {
        return Err(RuntimeError::Config(format!(
            "--cwd {path:?} is not a directory in the deterministic filesystem"
        )));
    }
    let fd = context.fs_open(&path, OpenFlags::path_only())?;
    *CWD.lock() = Some(fd);
    Ok(())
}

/// The metadata of `path`, or `None` when it does not exist. Every other error
/// (a search refusal, a non-directory prefix) is the caller's to report.
fn metadata(path: &str) -> Result<Option<FsMetadata>, c_int> {
    match with_context(|context| context.fs_metadata(path)) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(errno) if errno == ENOENT => Ok(None),
        Err(errno) => Err(errno),
    }
}

fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|component| !component.is_empty())
}

fn join(components: &[String]) -> String {
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

fn child(parent: &[String], name: &str) -> String {
    if parent.is_empty() {
        format!("/{name}")
    } else {
        format!("/{}/{name}", parent.join("/"))
    }
}

/// The path a descriptor's node has now — a directory descriptor for a relative
/// path, any filesystem descriptor for the empty-path form.
fn fd_path(guest_fd: c_int, empty_path: bool) -> Result<String, c_int> {
    let resolved = resolve_fd(guest_fd)?;
    let handle = match resolved.kind {
        FdKind::Dir => Fd(resolved.handle),
        FdKind::File | FdKind::OPath if empty_path => Fd(resolved.handle),
        FdKind::File
        | FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket
        | FdKind::Pipe => return Err(ENOTDIR),
        #[cfg(target_os = "linux")]
        FdKind::EventFd | FdKind::Epoll => return Err(ENOTDIR),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => return Err(ENOTDIR),
    };
    with_context(|context| context.fs_fd_path(handle))
}

enum Step {
    /// The resolution is complete.
    Done(String, Option<FsMetadata>),
    /// A symlink was expanded into the work list; resolve again from the
    /// updated state.
    Again,
}

/// Resolve `(dirfd, path)` to the canonical absolute path the driver accepts.
///
/// The common case costs one driver `metadata`: a spelling without `..` is
/// joined lexically and looked up whole, and only when that lookup cannot
/// answer alone (a missing name — is the parent there? — a refusal, a prefix
/// through a file, a `..`) does the resolver walk the path one component at a
/// time, expanding each symlink it meets exactly where the kernel would.
pub(crate) fn resolve(dirfd: c_int, path: &str, flags: u32) -> Result<Resolved, c_int> {
    if path.len() >= PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    let empty_path = flags & RESOLVE_EMPTY_PATH != 0;
    let base = if path.starts_with('/') {
        "/".to_owned()
    } else if dirfd == AT_FDCWD {
        cwd_path()?
    } else {
        fd_path(dirfd, path.is_empty() && empty_path)?
    };
    if path.is_empty() {
        if !empty_path {
            return Err(ENOENT);
        }
        let metadata = metadata(&base)?;
        return Ok(Resolved {
            path: base,
            metadata,
        });
    }
    if components(path).any(|component| component.len() > NAME_MAX) {
        return Err(ENAMETOOLONG);
    }
    // A trailing `/` (or `/.`) says the final entry must be a directory, and
    // makes a trailing symlink resolve even under NOFOLLOW, as the kernel does.
    let requires_directory = path.ends_with('/') || path.ends_with("/.") || path == ".";
    let nofollow = flags & RESOLVE_NOFOLLOW != 0 && !requires_directory;
    let mut resolved: Vec<String> = components(&base).map(str::to_owned).collect();
    let mut remaining: VecDeque<String> = components(path).map(str::to_owned).collect();
    if !remaining.iter().any(|component| component == "..") {
        let lexical: Vec<String> = resolved
            .iter()
            .chain(remaining.iter().filter(|component| *component != "."))
            .cloned()
            .collect();
        if join(&lexical) == URANDOM {
            return Ok(Resolved {
                path: URANDOM.to_owned(),
                metadata: None,
            });
        }
    }
    let mut hops = 0usize;
    loop {
        let step = if remaining.iter().any(|component| component == "..") {
            walk(&mut resolved, &mut remaining, nofollow, &mut hops)?
        } else {
            match fast(&mut resolved, &mut remaining, nofollow, &mut hops)? {
                Some(step) => step,
                None => walk(&mut resolved, &mut remaining, nofollow, &mut hops)?,
            }
        };
        match step {
            Step::Again => continue,
            Step::Done(path, metadata) => {
                if path.len() >= PATH_MAX {
                    return Err(ENAMETOOLONG);
                }
                if requires_directory
                    && metadata.is_some_and(|metadata| metadata.kind != FsEntryKind::Directory)
                {
                    return Err(ENOTDIR);
                }
                return Ok(Resolved { path, metadata });
            }
        }
    }
}

/// Splice a symlink's target into the work list in place of the link. An
/// absolute target restarts at the root; a relative one continues from the
/// link's directory, which is what `resolved` already holds.
fn expand(
    resolved: &mut Vec<String>,
    remaining: &mut VecDeque<String>,
    link: &str,
    hops: &mut usize,
) -> Result<Step, c_int> {
    *hops += 1;
    if *hops > SYMLINK_HOPS {
        return Err(ELOOP);
    }
    let target = with_context(|context| context.fs_read_link(link))?;
    if target.starts_with('/') {
        resolved.clear();
    }
    for (index, component) in components(&target).enumerate() {
        remaining.insert(index, component.to_owned());
    }
    Ok(Step::Again)
}

/// One lookup of the whole lexical join. `None` when that lookup could not
/// decide the answer and the component walk must.
fn fast(
    resolved: &mut Vec<String>,
    remaining: &mut VecDeque<String>,
    nofollow: bool,
    hops: &mut usize,
) -> Result<Option<Step>, c_int> {
    let names: Vec<String> = remaining
        .iter()
        .filter(|component| *component != ".")
        .cloned()
        .collect();
    let mut full = resolved.clone();
    full.extend(names.iter().cloned());
    let candidate = join(&full);
    match metadata(&candidate) {
        Ok(Some(metadata)) => {
            if metadata.kind == FsEntryKind::Symlink && !nofollow {
                // The link's directory is everything before its name.
                *resolved = full[..full.len() - 1].to_vec();
                remaining.clear();
                return expand(resolved, remaining, &candidate, hops).map(Some);
            }
            remaining.clear();
            Ok(Some(Step::Done(candidate, Some(metadata))))
        }
        Ok(None) => {
            // The name is missing. That is an answer only when its parent is a
            // directory that is there (a creating call proceeds, everything
            // else is ENOENT); otherwise the walk finds which prefix failed.
            if names.is_empty() {
                remaining.clear();
                return Ok(Some(Step::Done(candidate, None)));
            }
            let parent = &full[..full.len() - 1];
            if parent.is_empty() {
                remaining.clear();
                return Ok(Some(Step::Done(candidate, None)));
            }
            match metadata(&join(parent)) {
                Ok(Some(metadata)) if metadata.kind == FsEntryKind::Directory => {
                    remaining.clear();
                    Ok(Some(Step::Done(candidate, None)))
                }
                _ => Ok(None),
            }
        }
        // A refusal (an intermediate symlink the driver declines, a search
        // denial) or a prefix through a non-directory: the walk reproduces the
        // exact errno at the exact component.
        Err(_) => Ok(None),
    }
}

/// The component-wise walk: every prefix is looked up in turn, a symlink is
/// expanded where it stands, `..` pops the resolved directory (never a link's
/// name), and a non-directory prefix is `ENOTDIR`.
fn walk(
    resolved: &mut Vec<String>,
    remaining: &mut VecDeque<String>,
    nofollow: bool,
    hops: &mut usize,
) -> Result<Step, c_int> {
    while let Some(component) = remaining.pop_front() {
        if component == "." {
            continue;
        }
        if component == ".." {
            resolved.pop();
            continue;
        }
        let candidate = child(resolved, &component);
        let is_final = remaining.is_empty();
        let Some(metadata) = metadata(&candidate)? else {
            if is_final {
                return Ok(Step::Done(candidate, None));
            }
            return Err(ENOENT);
        };
        match metadata.kind {
            FsEntryKind::Directory => resolved.push(component),
            FsEntryKind::Symlink if is_final && nofollow => {
                return Ok(Step::Done(candidate, Some(metadata)));
            }
            FsEntryKind::Symlink => return expand(resolved, remaining, &candidate, hops),
            FsEntryKind::File | FsEntryKind::Fifo => {
                if is_final {
                    return Ok(Step::Done(candidate, Some(metadata)));
                }
                return Err(ENOTDIR);
            }
        }
    }
    // Only `.`/`..` were left: the answer is the resolved directory itself.
    let path = join(resolved);
    let metadata = metadata(&path)?;
    Ok(Step::Done(path, metadata))
}
