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
const O_NOFOLLOW: u64 = 0o400000;
const O_PATH: u64 = 0o10000000;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const MAX_LINKS: u32 = 40;
const OPENAT2: u64 = 437;
const READLINKAT: u64 = 267;
const NEWFSTATAT: u64 = 262;

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
        2 => one(p(None, 0, open_follows(a[1]))),
        257 => one(p(Some(0), 1, open_follows(a[2]))),
        437 => {
            // openat2: the guest's own resolve flags stay in force (RESOLVE_BENEATH and
            // RESOLVE_IN_ROOT refuse absolute paths): such calls are only checked.
            let flags = if a[2] != 0 && a[3] >= 24 {
                crate::guest::get::<u64>(a[2]).unwrap_or(0)
            } else {
                0
            };
            one(p(Some(0), 1, open_follows(flags)))
        }
        85 => one(p(None, 0, true)),
        4 | 21 | 80 | 191 | 194 | 188 | 197 | 137 | 76 | 90 | 92 | 132 | 235 | 59 => {
            one(p(None, 0, true))
        }
        6 | 89 | 192 | 195 | 189 | 198 | 94 | 83 | 133 | 87 | 84 => one(p(None, 0, false)),
        262 => one(p(Some(0), 1, nf(a[3]))),
        332 => one(p(Some(0), 1, nf(a[2]))),
        267 => one(p(Some(0), 1, false)),
        269 | 268 | 261 => one(p(Some(0), 1, true)),
        439 | 452 | 280 => one(p(Some(0), 1, nf(a[3]))),
        260 => one(p(Some(0), 1, nf(a[4]))),
        322 => one(p(Some(0), 1, nf(a[4]))),
        463..=466 => one(p(Some(0), 1, nf(a[2]))),
        258 | 259 | 263 => one(p(Some(0), 1, false)),
        82 => ([p(None, 0, false), p(None, 1, false)], 2),
        86 => ([p(None, 0, false), p(None, 1, false)], 2),
        88 => one(p(None, 1, false)),
        264 | 316 => ([p(Some(0), 1, false), p(Some(2), 3, false)], 2),
        265 => (
            [
                p(Some(0), 1, a[4] & AT_SYMLINK_FOLLOW != 0),
                p(Some(2), 3, false),
            ],
            2,
        ),
        266 => one(p(Some(1), 2, false)),
        _ => ([x, x], 0),
    }
}

/// Prepare every path argument of the call: `bufs` hold the resolved paths for as long as
/// the handler runs. `Err(errno)`: the walk itself failed (ELOOP, ENOENT on the way,
/// ENOTDIR), which is what the kernel would answer.
pub fn prepare(call: &mut dyn Call, bufs: &mut [PathBuf; 2]) -> Result<(), i64> {
    let nr = call.nr();
    let mut a = [0u64; 6];
    for (i, v) in a.iter_mut().enumerate() {
        *v = call.arg(i);
    }
    let (args, n) = path_args(nr, &a);
    for (k, arg) in args[..n].iter().enumerate() {
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
        let check_only =
            nr == 437 && a[2] != 0 && a[3] >= 24 && crate::guest::get::<u64>(a[2] + 16)? != 0;
        let out = &mut bufs[k];
        match resolve(dirfd, s, arg.follow, out)? {
            Resolved::Same => continue,
            Resolved::Path => {}
        }
        if check_only {
            if crate::path::policy(out.as_bytes()) != crate::path::Kind::Plain {
                crate::path::refuse(out.as_bytes());
                return Err(-e::ENOENT);
            }
            continue;
        }
        call.set_arg(arg.pi, out.b.as_ptr() as u64);
        if let Some(i) = arg.di {
            call.set_arg(i, AT_FDCWD as u64);
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
        59 | 322 => proto::vfs::MISSING_EXEC,
        2 | 257 | 437 | 4 | 6 | 262 | 332 | 21 | 269 | 439 => proto::vfs::MISSING_OPEN,
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
    let fd = unsafe {
        sc4(
            OPENAT2,
            dirfd as u64,
            c.as_ptr() as u64,
            how.as_ptr() as u64,
            24,
        )
    };
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
                let fd = unsafe {
                    sc4(
                        OPENAT2,
                        dirfd as u64,
                        c.as_ptr() as u64,
                        how.as_ptr() as u64,
                        24,
                    )
                };
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
        unsafe { sc2(79, out.b.as_mut_ptr() as u64, PATH_MAX as u64) }
    } else {
        let mut lp = [0u8; 32];
        let pre = b"/proc/self/fd/";
        lp[..pre.len()].copy_from_slice(pre);
        let l = pre.len() + crate::path::fmt_dec(&mut lp[pre.len()..], dirfd as u64);
        lp[l] = 0;
        let r = unsafe {
            sc4(
                READLINKAT,
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

fn is_dir(p: &PathBuf) -> Result<bool, i64> {
    let mut st = [0u64; 18];
    let r = unsafe {
        sc4(
            NEWFSTATAT,
            AT_FDCWD as u64,
            p.b.as_ptr() as u64,
            st.as_mut_ptr() as u64,
            0,
        )
    };
    if r < 0 {
        return Err(r);
    }
    Ok(st[3] as u32 & 0o170000 == 0o040000)
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
            break;
        }
        if last && !follow && !trailing_slash {
            break;
        }
        out.b[out.n] = 0;
        let r = unsafe {
            sc4(
                READLINKAT,
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
