//! Guest paths resolved before any handler sees them, so the lexical `/proc`, `/sys`,
//! `/dev` policy (`path::policy`) is decided on the path the kernel will actually walk.
//!
//! Before, a symlink on a writable mount (`/work/l -> /proc/1`), or a relative name from a
//! working directory of `/` (`proc/1/fd/3001`), was classified as a plain path and the kernel
//! then followed it into the supervisor's `/proc` entries; checks after the call (by the
//! mount of what was reached) caught some objects but not the supervisor's descriptors,
//! which live on host or anonymous mounts.
//!
//! For each path argument of a call (`path_args`):
//! * a fast check: `openat2(O_PATH, RESOLVE_NO_SYMLINKS)` succeeds only when no symlink is on
//!   the walk (the trailing one too, unless the call does not follow it). Then the lexical
//!   path is the walked path, and the arguments stay as the guest passed them, except that a
//!   relative name whose first component is `proc`, `sys` or `dev` is made absolute (the
//!   working directory or descriptor may be `/`), so the handler's policy sees it;
//! * otherwise a walk in the runtime, component by component, with readlink: symlinks are
//!   expanded (at most 40, then ELOOP), `..` drops the last real component. The walk stops
//!   where it enters `/proc`, `/sys` or `/dev` (not `/dev/shm`, a tmpfs the guest can write):
//!   from there the policy is lexical by design (magic links are named, not followed). The
//!   handler gets the resolved absolute path in place of the guest's (`Call::set_arg`; the
//!   boundary record keeps the guest's arguments), with the descriptor argument `AT_FDCWD`.
//!
//! Only one guest thread runs at a time, so nothing changes between the walk and the call.

use crate::path::{PathBuf, PATH_MAX};
use crate::raw::*;
use crate::trap::Call;

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
use proto::abi::open::O_NOFOLLOW;
const O_PATH: u64 = 0o10000000;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_IN_ROOT: u64 = 0x10;
const MAX_LINKS: u32 = 40;

/// A path argument: descriptor argument (if any), path argument, whether the last
/// component is followed.
#[derive(Clone, Copy)]
struct Arg {
    di: Option<usize>,
    pi: usize,
    follow: bool,
}

fn open_follows(flags: u64) -> bool {
    flags & O_NOFOLLOW == 0 && !(flags & O_CREAT != 0 && flags & O_EXCL != 0)
}

/// The path arguments of a call (calls the table passes or virtualises; denied ones never
/// reach here).
fn path_args(nr: u64, a: &[u64; 6]) -> ([Arg; 2], usize) {
    let p = |di: Option<usize>, pi: usize, follow: bool| Arg { di, pi, follow };
    let x = p(None, 0, false);
    let one = |v: Arg| ([v, x], 1);
    let nf = |f: u64| f & AT_SYMLINK_NOFOLLOW == 0;
    match nr {
        nr::OPEN => one(p(None, 0, open_follows(a[1]))),
        nr::OPENAT => one(p(Some(0), 1, open_follows(a[2]))),
        nr::OPENAT2 => {
            // openat2: the guest's own resolve flags stay in force (RESOLVE_BENEATH and
            // RESOLVE_IN_ROOT refuse absolute paths): such calls are only checked.
            let flags = if a[2] != 0 && a[3] >= 24 {
                crate::guest::get::<u64>(a[2]).unwrap_or(0)
            } else {
                0
            };
            one(p(Some(0), 1, open_follows(flags)))
        }
        nr::CREAT => one(p(None, 0, true)),
        nr::STAT
        | nr::ACCESS
        | nr::CHDIR
        | nr::GETXATTR
        | nr::LISTXATTR
        | nr::SETXATTR
        | nr::REMOVEXATTR
        | nr::STATFS
        | nr::TRUNCATE
        | nr::CHMOD
        | nr::CHOWN
        | nr::UTIME
        | nr::UTIMES
        | nr::EXECVE => one(p(None, 0, true)),
        nr::LSTAT
        | nr::READLINK
        | nr::LGETXATTR
        | nr::LLISTXATTR
        | nr::LSETXATTR
        | nr::LREMOVEXATTR
        | nr::LCHOWN
        | nr::MKDIR
        | nr::MKNOD
        | nr::UNLINK
        | nr::RMDIR => one(p(None, 0, false)),
        nr::NEWFSTATAT => one(p(Some(0), 1, nf(a[3]))),
        nr::STATX => one(p(Some(0), 1, nf(a[2]))),
        nr::READLINKAT => one(p(Some(0), 1, false)),
        nr::FACCESSAT | nr::FCHMODAT | nr::FUTIMESAT => one(p(Some(0), 1, true)),
        nr::FACCESSAT2 | nr::FCHMODAT2 | nr::UTIMENSAT => one(p(Some(0), 1, nf(a[3]))),
        nr::FCHOWNAT => one(p(Some(0), 1, nf(a[4]))),
        nr::EXECVEAT => one(p(Some(0), 1, nf(a[4]))),
        nr::SETXATTRAT | nr::GETXATTRAT | nr::LISTXATTRAT | nr::REMOVEXATTRAT => {
            one(p(Some(0), 1, nf(a[2])))
        }
        nr::MKDIRAT | nr::MKNODAT | nr::UNLINKAT => one(p(Some(0), 1, false)),
        nr::RENAME => ([p(None, 0, false), p(None, 1, false)], 2),
        nr::LINK => ([p(None, 0, false), p(None, 1, false)], 2),
        nr::SYMLINK => one(p(None, 1, false)),
        nr::RENAMEAT | nr::RENAMEAT2 => ([p(Some(0), 1, false), p(Some(2), 3, false)], 2),
        nr::LINKAT => (
            [
                p(Some(0), 1, a[4] & AT_SYMLINK_FOLLOW != 0),
                p(Some(2), 3, false),
            ],
            2,
        ),
        nr::SYMLINKAT => one(p(Some(1), 2, false)),
        _ => ([x, x], 0),
    }
}

/// A call's path buffers (in the trap entry's frame, so they outlive the handler until the
/// call's record is written): the resolved paths a handler is given, and with `--log-paths`
/// the path each walked argument resolves to.
pub struct Paths {
    pub bufs: [PathBuf; 2],
    /// With `--log-paths`: the argument whose walk `bufs[k]` holds, or `NONE`.
    pub logged: [u8; 2],
}

impl Paths {
    pub const NONE: u8 = u8::MAX;
    pub const fn new() -> Paths {
        Paths {
            bufs: [PathBuf::new(), PathBuf::new()],
            logged: [Paths::NONE; 2],
        }
    }
    /// The resolved path of argument `i`, if `--log-paths` kept one.
    pub fn logged(&self, i: usize) -> Option<&[u8]> {
        (0..2)
            .find(|&k| self.logged[k] as usize == i)
            .map(|k| self.bufs[k].as_bytes())
    }
}

/// Prepare every path argument of the call: `call.paths()` holds the resolved paths for as
/// long as the handler runs (and, with `--log-paths`, until the record is written).
/// `Err(errno)`: the walk itself failed (ELOOP, ENOENT on the way, ENOTDIR), which is what
/// the kernel would answer.
pub fn prepare(call: &mut dyn Call) -> Result<(), i64> {
    let nr = call.nr();
    let mut a = [0u64; 6];
    for (i, v) in a.iter_mut().enumerate() {
        *v = call.arg(i);
    }
    let (args, n) = path_args(nr, &a);
    let log = crate::state::config().log_paths != 0;
    // Arguments to replace once the buffers are no longer borrowed: (index, value).
    let mut set = [(usize::MAX, 0u64); 4];
    let mut ns = 0;
    let r = prepare_into(call.paths(), nr, &a, &args[..n], log, &mut set, &mut ns);
    for &(i, v) in &set[..ns] {
        call.set_arg(i, v);
    }
    r
}

fn prepare_into(
    paths: &mut Paths,
    nr: u64,
    a: &[u64; 6],
    args: &[Arg],
    log: bool,
    set: &mut [(usize, u64); 4],
    ns: &mut usize,
) -> Result<(), i64> {
    for (k, arg) in args.iter().enumerate() {
        let p = a[arg.pi];
        if p == 0 {
            continue;
        }
        // A pointer the kernel could not read is its EFAULT, before any walk.
        let s = crate::guest::cstr(p, PATH_MAX)?;
        if s.is_empty() || s.len() >= PATH_MAX {
            continue; // AT_EMPTY_PATH (the descriptor), ENOENT or ENAMETOOLONG from the kernel
        }
        let dirfd = match arg.di {
            Some(i) => a[i] as i32 as i64,
            None => AT_FDCWD,
        };
        let resolve_flags = if nr == nr::OPENAT2 && a[2] != 0 && a[3] >= 24 {
            crate::guest::get::<u64>(a[2] + 16)?
        } else {
            0
        };
        let check_only = resolve_flags != 0;
        // RESOLVE_IN_ROOT walks from the descriptor as its root: the runtime's walk (from `/`)
        // is not the path the call walks, so the log has none.
        let log = log && resolve_flags & RESOLVE_IN_ROOT == 0;
        let out = &mut paths.bufs[k];
        // A directory the policy handed out (`/proc`, `/proc/self/fd`...): a name relative to
        // it is the path it names from `/`, policed and walked as that path; the kernel never
        // walks from the descriptor. With openat2's own resolve flags a relative name (or an
        // absolute one under RESOLVE_IN_ROOT) is refused.
        if let Some(base) = arg.di.and_then(|_| crate::path::dir_base(dirfd)) {
            if check_only && (s[0] != b'/' || resolve_flags & RESOLVE_IN_ROOT != 0) {
                crate::path::refuse(base);
                return Err(-e::ENOENT);
            }
            if s[0] != b'/' {
                let mut j = PathBuf::new();
                if !(push(&mut j, base) && push(&mut j, b"/") && push(&mut j, s)) {
                    return Err(-e::ENAMETOOLONG);
                }
                walk(AT_FDCWD, j.as_bytes(), arg.follow, out)?;
                if log {
                    paths.logged[k] = arg.pi as u8;
                }
                set[*ns] = (arg.pi, out.b.as_ptr() as u64);
                set[*ns + 1] = (arg.di.unwrap(), AT_FDCWD as u64);
                *ns += 2;
                continue;
            }
        }
        match resolve(dirfd, s, arg.follow, out)? {
            Resolved::Same => {
                // Nothing to change for the handler; the log gets the lexical absolute path,
                // which is the walked one (no symlink on the walk, or the kernel answers the
                // call with an error before it is walked).
                if log && crate::path::full(dirfd, s, out) {
                    paths.logged[k] = arg.pi as u8;
                }
                continue;
            }
            Resolved::Path => {}
        }
        if log {
            paths.logged[k] = arg.pi as u8;
        }
        if check_only {
            if crate::path::policy(out.as_bytes()) != crate::path::Kind::Plain {
                crate::path::refuse(out.as_bytes());
                return Err(-e::ENOENT);
            }
            continue;
        }
        set[*ns] = (arg.pi, out.b.as_ptr() as u64);
        *ns += 1;
        if let Some(i) = arg.di {
            set[*ns] = (i, AT_FDCWD as u64);
            *ns += 1;
        }
    }
    Ok(())
}

/// A call that answered `ENOENT` for a file the guest looked for (to run it, open it, stat it
/// or test it): its absolute path is kept for the launcher's hint about paths the sandbox
/// lacks (`proto::vfs::Vfs::missing`).
pub fn note_missing(call: &dyn Call) {
    let nr = call.nr();
    let what = match nr {
        nr::EXECVE | nr::EXECVEAT => proto::vfs::MISSING_EXEC,
        nr::OPEN
        | nr::OPENAT
        | nr::OPENAT2
        | nr::STAT
        | nr::LSTAT
        | nr::NEWFSTATAT
        | nr::STATX
        | nr::ACCESS
        | nr::FACCESSAT
        | nr::FACCESSAT2 => proto::vfs::MISSING_OPEN,
        _ => return,
    };
    let mut a = [0u64; 6];
    for (i, v) in a.iter_mut().enumerate() {
        *v = call.arg(i);
    }
    let (args, n) = path_args(nr, &a);
    if n == 0 || a[args[0].pi] == 0 {
        return;
    }
    let Ok(s) = crate::guest::cstr(a[args[0].pi], PATH_MAX) else {
        return;
    };
    let dirfd = args[0].di.map_or(AT_FDCWD, |i| a[i] as i32 as i64);
    let mut norm = PathBuf::new();
    if crate::path::absolute(dirfd, s, &mut norm) {
        crate::path::missing(what, &norm);
    }
}

enum Resolved {
    /// The guest's arguments name what the kernel will walk, lexically.
    Same,
    /// `out` holds the absolute path to use instead (NUL-terminated).
    Path,
}

fn first_component(s: &[u8]) -> &[u8] {
    let n = s.iter().position(|&c| c == b'/').unwrap_or(s.len());
    &s[..n]
}

fn resolve(dirfd: i64, s: &[u8], follow: bool, out: &mut PathBuf) -> Result<Resolved, i64> {
    // Fast check: nothing on the walk is a symlink.
    let mut c = [0u8; PATH_MAX];
    c[..s.len()].copy_from_slice(s);
    c[s.len()] = 0;
    let how = [
        O_PATH | O_CLOEXEC | if follow { 0 } else { O_NOFOLLOW },
        0,
        RESOLVE_NO_SYMLINKS,
    ];
    let fd = crate::fdlim::transient(|| unsafe {
        sc4(
            nr::OPENAT2,
            dirfd as u64,
            c.as_ptr() as u64,
            how.as_ptr() as u64,
            24,
        )
    });
    let plain = if fd >= 0 {
        unsafe { sc1(nr::CLOSE, fd as u64) };
        true
    } else if fd == -e::ENOENT {
        // A missing last component in a directory reached without symlinks: still plain.
        match s.iter().rposition(|&c| c == b'/') {
            Some(0) => true,
            Some(i) => {
                c[i] = 0;
                let how = [O_PATH | O_CLOEXEC, 0, RESOLVE_NO_SYMLINKS];
                let fd = crate::fdlim::transient(|| unsafe {
                    sc4(
                        nr::OPENAT2,
                        dirfd as u64,
                        c.as_ptr() as u64,
                        how.as_ptr() as u64,
                        24,
                    )
                });
                if fd >= 0 {
                    unsafe { sc1(nr::CLOSE, fd as u64) };
                }
                fd >= 0
            }
            None => true,
        }
    } else if fd == -e::ELOOP || fd == -e::ENOTDIR {
        false
    } else {
        // EBADF, EACCES, ENAMETOOLONG...: the kernel answers the call the same way.
        return Ok(Resolved::Same);
    };
    if plain {
        if s[0] != b'/' && matches!(first_component(s), b"proc" | b"sys" | b"dev" | b".patina") {
            // Policy-relevant only from `/`: make it absolute so the handler's policy sees it.
            if !base_dir(dirfd, out) {
                return Ok(Resolved::Same);
            }
            let mut j = PathBuf::new();
            if !(push(&mut j, out.as_bytes()) && push(&mut j, b"/") && push(&mut j, s)) {
                return Err(-e::ENAMETOOLONG);
            }
            out.n = 0;
            if !push(out, j.as_bytes()) {
                return Err(-e::ENAMETOOLONG);
            }
            out.b[out.n] = 0;
            return Ok(Resolved::Path);
        }
        return Ok(Resolved::Same);
    }
    walk(dirfd, s, follow, out)?;
    Ok(Resolved::Path)
}

fn push(b: &mut PathBuf, s: &[u8]) -> bool {
    if b.n + s.len() >= PATH_MAX {
        return false;
    }
    b.b[b.n..b.n + s.len()].copy_from_slice(s);
    b.n += s.len();
    true
}

/// The real path of `dirfd` (or the working directory).
fn base_dir(dirfd: i64, out: &mut PathBuf) -> bool {
    let r = if dirfd == AT_FDCWD {
        unsafe { sc2(nr::GETCWD, out.b.as_mut_ptr() as u64, PATH_MAX as u64) }
    } else {
        let mut lp = [0u8; 32];
        let pre = b"/proc/self/fd/";
        lp[..pre.len()].copy_from_slice(pre);
        let l = pre.len() + crate::path::fmt_dec(&mut lp[pre.len()..], dirfd as u64);
        lp[l] = 0;
        let r = unsafe {
            sc4(
                nr::READLINKAT,
                AT_FDCWD as u64,
                lp.as_ptr() as u64,
                out.b.as_mut_ptr() as u64,
                PATH_MAX as u64 - 1,
            )
        };
        if r > 0 {
            r + 1
        } else {
            r
        }
    };
    if r <= 0 {
        return false;
    }
    out.n = (r - 1) as usize;
    // A deleted directory reads as "... (deleted)", and a non-directory as what it is: both
    // are refused (the walk cannot start there).
    out.n > 0 && out.b[0] == b'/' && !out.as_bytes().ends_with(b" (deleted)")
}

/// Under `/proc`, `/sys` or `/dev` (but not `/dev/shm`): the policy's own ground.
fn policy_ground(p: &[u8], next: &[u8]) -> bool {
    let under = |q: &[u8]| p == q || (p.len() > q.len() && p.starts_with(q) && p[q.len()] == b'/');
    if under(b"/proc") || under(b"/sys") || under(b"/.patina") {
        return true;
    }
    if p == b"/dev" {
        return next != b"shm";
    }
    under(b"/dev") && !under(b"/dev/shm")
}

/// A whole normalised path on the policy's ground.
fn on_ground(p: &[u8]) -> bool {
    let under = |q: &[u8]| p == q || (p.len() > q.len() && p.starts_with(q) && p[q.len()] == b'/');
    under(b"/proc")
        || under(b"/sys")
        || under(b"/.patina")
        || (under(b"/dev") && p != b"/dev" && !under(b"/dev/shm"))
}

fn is_dir(p: &PathBuf) -> Result<bool, i64> {
    let mut st = proto::abi::stat::Stat::zeroed();
    let r = unsafe {
        sc4(
            nr::NEWFSTATAT,
            AT_FDCWD as u64,
            p.b.as_ptr() as u64,
            st.as_mut_ptr() as u64,
            0,
        )
    };
    if r < 0 {
        return Err(r);
    }
    Ok(st.mode() & 0o170000 == 0o040000)
}

/// Walk `s` from `dirfd` in the runtime; `out` gets the absolute, symlink-free path.
fn walk(dirfd: i64, s: &[u8], follow: bool, out: &mut PathBuf) -> Result<(), i64> {
    // The rest of the path, as a queue: rest[at..len].
    let mut rest = [0u8; 2 * PATH_MAX];
    let mut len = s.len();
    rest[..len].copy_from_slice(s);
    let mut at = 0usize;
    out.n = 0;
    if s[0] == b'/' {
        out.n = 0; // "/" is the empty prefix
    } else {
        if !base_dir(dirfd, out) {
            return Err(if dirfd == AT_FDCWD {
                -e::ENOENT
            } else {
                -e::ENOTDIR
            });
        }
        if !is_dir(&terminated(out))? {
            return Err(-e::ENOTDIR);
        }
        if out.as_bytes() == b"/" {
            out.n = 0;
        }
    }
    let mut links = 0u32;
    let mut t = [0u8; PATH_MAX];
    loop {
        // Next component.
        while at < len && rest[at] == b'/' {
            at += 1;
        }
        if at >= len {
            break;
        }
        let start = at;
        while at < len && rest[at] != b'/' {
            at += 1;
        }
        let mut comp = [0u8; 256];
        let cl = at - start;
        if cl > 255 {
            return Err(-e::ENAMETOOLONG);
        }
        comp[..cl].copy_from_slice(&rest[start..at]);
        let comp = &comp[..cl];
        let mut j = at;
        while j < len && rest[j] == b'/' {
            j += 1;
        }
        let last = j >= len;
        let trailing_slash = last && at < len;
        match comp {
            b"." => {
                if out.n > 0 && !is_dir(&terminated(out))? {
                    return Err(-e::ENOTDIR);
                }
                continue;
            }
            b".." => {
                if out.n > 0 && !is_dir(&terminated(out))? {
                    return Err(-e::ENOTDIR);
                }
                while out.n > 0 && out.b[out.n - 1] != b'/' {
                    out.n -= 1;
                }
                out.n = out.n.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        let keep = out.n;
        if !(push(out, b"/") && push(out, comp)) {
            return Err(-e::ENAMETOOLONG);
        }
        // The policy's ground: the rest is decided lexically by the handler.
        let next = {
            let mut k = j;
            while k < len && rest[k] != b'/' {
                k += 1;
            }
            &rest[j..k]
        };
        if policy_ground(out.as_bytes(), if last { b"" } else { next }) && out.as_bytes() != b"/dev"
        {
            if !last && !(push(out, b"/") && push(out, &rest[j..len])) {
                return Err(-e::ENAMETOOLONG);
            }
            // The policy decides on the lexical path, so the kernel is given that path, never
            // one whose `..` it would resolve differently (after a magic link, or out of the
            // ground and through a symlink there). A path whose `..` leave the ground is
            // walked on from where they lead.
            let mut n = crate::path::PathBuf::new();
            crate::path::normalise(out.as_bytes(), &mut n);
            if on_ground(n.as_bytes()) {
                out.n = 0;
                push(out, n.as_bytes());
                break;
            }
            len = n.n;
            rest[..len].copy_from_slice(n.as_bytes());
            at = 0;
            out.n = 0;
            continue;
        }
        if last && !follow && !trailing_slash {
            break;
        }
        out.b[out.n] = 0;
        let r = unsafe {
            sc4(
                nr::READLINKAT,
                AT_FDCWD as u64,
                out.b.as_ptr() as u64,
                t.as_mut_ptr() as u64,
                PATH_MAX as u64,
            )
        };
        if r >= 0 {
            links += 1;
            if links > MAX_LINKS {
                return Err(-e::ELOOP);
            }
            let tl = r as usize;
            if tl == 0 {
                return Err(-e::ENOENT);
            }
            // rest = target + "/" + rest[at..len]
            let tail = len - at;
            if tl + 1 + tail >= rest.len() {
                return Err(-e::ENAMETOOLONG);
            }
            rest.copy_within(at..len, tl + 1);
            rest[..tl].copy_from_slice(&t[..tl]);
            rest[tl] = b'/';
            len = tl + 1 + tail;
            at = 0;
            // The link itself is not part of the prefix.
            out.n = keep;
            if t[0] == b'/' {
                out.n = 0;
            }
            continue;
        }
        if r == -e::EINVAL {
            continue; // not a symlink
        }
        if r == -e::ENOENT && last {
            break; // a name to create
        }
        return Err(r);
    }
    if out.n == 0 {
        push(out, b"/");
    } else if s.ends_with(b"/") && !out.as_bytes().ends_with(b"/") && !push(out, b"/") {
        return Err(-e::ENAMETOOLONG);
    }
    out.b[out.n] = 0;
    Ok(())
}

fn terminated(p: &PathBuf) -> PathBuf {
    let mut q = PathBuf::new();
    push(&mut q, p.as_bytes());
    q.b[q.n] = 0;
    q
}
