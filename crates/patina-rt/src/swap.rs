//! Path swaps (`path-swap-permille`, `path-swap-at`; `proto::swap`): before a call uses a
//! path that the same process named in one of its last `WINDOW` checks, the runtime may
//! change one component of the checked path in the work tree, as another process with the
//! same uid could between the two calls: it becomes a symlink, another entry of its directory
//! is renamed into its place, or it is renamed away. The swap may be put back right after
//! the call returns (never after an `exec`, which does not return).
//!
//! Every choice is a draw keyed by the use's `seq` (`inject::d`), so the swap is made at the
//! same point with the same result in every run of the seed, and the other fault classes'
//! draws do not move. The mutation is made by the runtime's own calls, in the guest process
//! (so directory permissions and the sticky bit hold as for any process of that uid), through
//! a descriptor of the component's directory opened without following any symlink and
//! checked to be on the work tree: nothing outside it is changed, and a symlink to a path
//! outside is only a name. Each step is a name change recorded like the program's own
//! (`sys::fs::mutate_as_guest`: virtual times, the operation log, a crash point), so replay,
//! `patina log ops` and the crash model see it. The swap is an `Injected` record
//! (`INJ_PATH_SWAP`) naming the path, what it became and the checking call.

use crate::path::{self, Global, PathBuf, PATH_MAX};
use crate::raw::*;
use crate::state::{ctl, thread};
use crate::sys::fs::{fstat_raw, fstatat_raw, mutate_as_guest, AT_FDCWD};
use crate::trap::Call;
use core::sync::atomic::Ordering::Relaxed;
use proto::faults::*;
use proto::rec::hash_bytes;
use proto::swap::*;

const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const O_RDONLY_DIR: u64 = proto::abi::open::O_DIRECTORY | 0o2000000; // O_DIRECTORY | O_CLOEXEC
const O_PATH: u64 = 0o10000000;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RENAME_NOREPLACE: u64 = 1;
const S_IFMT: u64 = 0o170000;
const S_IFDIR: u64 = 0o040000;
const S_IFLNK: u64 = 0o120000;
const NAME_MAX: usize = 255;

/// One path call the process made: the hash and length of its normalised path.
#[derive(Clone, Copy)]
struct Seen {
    h: u64,
    len: usize,
    nr: u64,
    seq: u64,
}

struct Ring {
    e: [Seen; WINDOW],
    /// Entries written so far (the newest is at `(n - 1) % WINDOW`).
    n: usize,
}

/// Per process (a fork copies it, an exec starts empty); the threads of a process share it.
static RING: Global<Ring> = Global::new(Ring {
    e: [Seen {
        h: 0,
        len: 0,
        nr: 0,
        seq: 0,
    }; WINDOW],
    n: 0,
});

fn phash(p: &[u8]) -> u64 {
    hash_bytes(0x7377_6170, p)
}

impl Ring {
    /// The newest entry naming `p` or an ancestor of it.
    fn find(&self, p: &[u8]) -> Option<Seen> {
        (0..self.n.min(WINDOW))
            .map(|k| self.e[(self.n - 1 - k) % WINDOW])
            .find(|s| {
                s.len <= p.len()
                    && (s.len == p.len() || p[s.len] == b'/')
                    && phash(&p[..s.len]) == s.h
            })
    }
    fn push(&mut self, s: Seen) {
        self.e[self.n % WINDOW] = s;
        self.n += 1;
    }
}

/// A name of at most `NAME_MAX` bytes, NUL-terminated.
#[derive(Clone, Copy)]
struct Name {
    b: [u8; NAME_MAX + 1],
    n: usize,
}

impl Name {
    const fn new() -> Name {
        Name {
            b: [0; NAME_MAX + 1],
            n: 0,
        }
    }
    fn of(s: &[u8]) -> Option<Name> {
        let mut x = Name::new();
        if s.is_empty() || s.len() > NAME_MAX {
            return None;
        }
        x.b[..s.len()].copy_from_slice(s);
        x.n = s.len();
        Some(x)
    }
    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
    fn ptr(&self) -> u64 {
        self.b.as_ptr() as u64
    }
}

/// A swap that is to be put back after the call.
pub struct Swap {
    parent: PathBuf,
    name: Name,
    mutation: u64,
    /// The entry the original was renamed to (`n` 0: there was none).
    aside: Name,
    /// The sibling renamed into place (`MUT_RENAME`).
    sibling: Name,
    /// The inode now at `name` (the symlink, or the sibling).
    ino: u64,
}

/// Called for every passed call when a path-swap key is set, before its paths are resolved.
/// Notes the call's paths below the work root; for a use whose path was checked, decides and
/// makes the swap. `Some`: put it back after the call (`after`).
pub fn before(call: &dyn Call) -> Option<Swap> {
    let nr = call.nr();
    let role = role(nr)?;
    let root = crate::state::work_path();
    let (args, n) = path_args(nr);
    let ts = thread();
    let mut noted: [Option<Seen>; 2] = [None, None];
    let mut out = None;
    let mut decided = false;
    for (k, &(di, pi)) in args[..n].iter().enumerate() {
        let p = call.arg(pi);
        if p == 0 {
            continue;
        }
        let Ok(s) = crate::guest::cstr(p, PATH_MAX) else {
            continue;
        };
        let dirfd = di.map_or(AT_FDCWD, |i| call.arg(i) as i32 as i64);
        let mut u = PathBuf::new();
        // A `..` is resolved as text here but by the kernel through whatever precedes it: skip
        // such paths rather than swap a path the call does not reach.
        if s.is_empty()
            || s.split(|&b| b == b'/').any(|c| c == b"..")
            || !path::full(dirfd, s, &mut u)
        {
            continue;
        }
        let u = u.as_bytes();
        if components(u, root).next().is_none() {
            continue;
        }
        if role.uses() && !decided {
            if let Some(chk) = RING.get().find(u) {
                decided = true;
                out = decide(nr, call.guest_args()[0], &u[..chk.len], root, chk);
            }
        }
        noted[k] = role.checks().then_some(Seen {
            h: phash(u),
            len: u.len(),
            nr,
            seq: ts.seq,
        });
    }
    for s in noted.into_iter().flatten() {
        RING.get().push(s);
    }
    out
}

/// An eligible use of `checked` (a path below `root`): count it, and swap when the draw (or
/// `path-swap-at`) says so.
fn decide(nr: u64, a0: u64, checked: &[u8], root: &[u8], chk: Seen) -> Option<Swap> {
    if !crate::inject::active() {
        return None;
    }
    let f = &ctl().faults;
    let cfg = &f.cfg;
    f.eligible(Kind::PathSwap);
    let at = f.eligible[Kind::PathSwap as usize].load(Relaxed);
    if !(cfg.path_swap_at == at || crate::inject::permille(cfg.path_swap_permille, SUB_SWAP_FIRE)) {
        return None;
    }
    // The component: uniform over those below the root.
    let k = components(checked, root).count() as u64;
    let pick = (crate::inject::d(SUB_SWAP_PICK) % k) as usize;
    let c = &checked[..components(checked, root).nth(pick)?];
    let slash = c.iter().rposition(|&b| b == b'/')?;
    let mut parent = PathBuf::new();
    let pdir = if slash == 0 { &b"/"[..] } else { &c[..slash] };
    parent.b[..pdir.len()].copy_from_slice(pdir);
    parent.n = pdir.len();
    let name = Name::of(&c[slash + 1..])?;
    let (m, t, back) = choose(crate::inject::d(SUB_SWAP_HOW));
    // An exec that succeeds does not come back to be put back after.
    let back = back && nr != nr::EXECVE && nr != nr::EXECVEAT;
    let pfd = open_parent(&parent)?;
    let r = swap(pfd, &parent, name, m, t, root);
    unsafe { sc1(nr::CLOSE, pfd as u64) };
    let (mut s, target, mutation, to) = r?;
    s.mutation = mutation;
    note(nr, a0, how(mutation, to, back), chk, c, target.as_bytes());
    back.then_some(s)
}

/// The directory `p` (a normalised absolute path), opened without following a symlink on the
/// way, if it is a directory of the work tree.
fn open_parent(p: &PathBuf) -> Option<i64> {
    let mut z = [0u8; PATH_MAX + 1];
    z[..p.n].copy_from_slice(p.as_bytes());
    let how = [O_PATH | O_RDONLY_DIR, 0, RESOLVE_NO_SYMLINKS];
    let fd = unsafe {
        sc4(
            nr::OPENAT2,
            AT_FDCWD as u64,
            z.as_ptr() as u64,
            how.as_ptr() as u64,
            24,
        )
    };
    if fd < 0 {
        return None;
    }
    match fstat_raw(fd) {
        Some(st) if path::is_work(st.dev()) && st.mode() as u64 & S_IFMT == S_IFDIR => Some(fd),
        _ => {
            unsafe { sc1(nr::CLOSE, fd as u64) };
            None
        }
    }
}

/// The entry of `pfd` other than `not` (and the swap's own names) that the draw picks, in an
/// order that does not depend on the directory's.
fn sibling(pfd: i64, not: &Name) -> Option<Name> {
    let dfd = unsafe {
        sc4(
            nr::OPENAT,
            pfd as u64,
            c".".as_ptr() as u64,
            O_RDONLY_DIR,
            0,
        )
    };
    if dfd < 0 {
        return None;
    }
    let key = crate::inject::d(SUB_SWAP_SIBLING);
    let mut best: Option<(u64, Name)> = None;
    let mut buf = [0u8; 4096];
    loop {
        let r = unsafe {
            sc3(
                nr::GETDENTS64,
                dfd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if r <= 0 {
            break;
        }
        let mut off = 0usize;
        while off + 19 < r as usize {
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let nm = &buf[off + 19..off + reclen];
            let nm = &nm[..nm.iter().position(|&b| b == 0).unwrap_or(nm.len())];
            off += reclen.max(1);
            if nm == b"." || nm == b".." || nm == not.bytes() || nm.starts_with(ASIDE_PREFIX) {
                continue;
            }
            let score = proto::draw::mix64(key ^ phash(nm));
            if best.as_ref().is_none_or(|b| score < b.0) {
                best = Name::of(nm).map(|n| (score, n));
            }
        }
    }
    unsafe { sc1(nr::CLOSE, dfd as u64) };
    best.map(|b| b.1)
}

fn lstat_in(pfd: i64, n: &Name) -> Option<crate::sys::fs::St> {
    fstatat_raw(pfd, n.ptr(), AT_SYMLINK_NOFOLLOW)
}

fn rename_in(pfd: i64, from: &Name, to: &Name) -> bool {
    mutate_as_guest(
        nr::RENAMEAT2,
        [
            pfd as u64,
            from.ptr(),
            pfd as u64,
            to.ptr(),
            RENAME_NOREPLACE,
            0,
        ],
    ) == 0
}

/// Make mutation `m` (or, when it is not possible or fails here, the next one that is) on `name` in
/// `pfd`. Returns the swap, the target to name in the record, and the mutation and target
/// kind made.
fn swap(
    pfd: i64,
    parent: &PathBuf,
    name: Name,
    m: u64,
    t: u64,
    root: &[u8],
) -> Option<(Swap, PathBuf, u64, u64)> {
    let st = lstat_in(pfd, &name);
    let sib = sibling(pfd, &name);
    let mut aside = Name::new();
    {
        let seq = thread().seq;
        let mut b = [0u8; 40];
        b[..ASIDE_PREFIX.len()].copy_from_slice(ASIDE_PREFIX);
        let l = ASIDE_PREFIX.len() + path::fmt_dec(&mut b[ASIDE_PREFIX.len()..], seq);
        aside = Name::of(&b[..l]).unwrap_or(aside);
    }
    let mut s = Swap {
        parent: PathBuf::new(),
        name,
        mutation: 0,
        aside: Name::new(),
        sibling: Name::new(),
        ino: 0,
    };
    s.parent.b[..parent.n].copy_from_slice(parent.as_bytes());
    s.parent.n = parent.n;
    let full = |n: &[u8]| {
        let mut p = PathBuf::new();
        let base = if parent.as_bytes() == b"/" {
            &b""[..]
        } else {
            parent.as_bytes()
        };
        if base.len() + 1 + n.len() < PATH_MAX {
            p.b[..base.len()].copy_from_slice(base);
            p.b[base.len()] = b'/';
            p.b[base.len() + 1..base.len() + 1 + n.len()].copy_from_slice(n);
            p.n = base.len() + 1 + n.len();
        }
        p
    };
    for k in 0..3 {
        let mutation = 1 + (m - 1 + k) % 3;
        match mutation {
            MUT_REMOVE if st.is_some() => {
                if rename_in(pfd, &name, &aside) {
                    s.aside = aside;
                    return Some((s, full(aside.bytes()), MUT_REMOVE, 0));
                }
            }
            MUT_RENAME if sib.is_some() => {
                let sb = sib.unwrap();
                if st.is_some() && !rename_in(pfd, &name, &aside) {
                    continue;
                }
                if !rename_in(pfd, &sb, &name) {
                    if st.is_some() && !rename_in(pfd, &aside, &name) {
                        return None; // the tree is not as the next mutation expects
                    }
                    continue;
                }
                if st.is_some() {
                    s.aside = aside;
                }
                s.sibling = sb;
                s.ino = lstat_in(pfd, &name).map_or(0, |x| x.ino());
                return Some((s, full(sb.bytes()), MUT_RENAME, 0));
            }
            MUT_SYMLINK => {
                let to = if t == TO_SIBLING && sib.is_none() {
                    TO_OUTSIDE
                } else {
                    t
                };
                let mut target = PathBuf::new();
                let tb: &[u8] = match to {
                    TO_SIBLING => sib.as_ref().unwrap().bytes(),
                    TO_DANGLING => DANGLING,
                    _ if st.is_some_and(|x| x.mode() as u64 & S_IFMT == S_IFDIR) => {
                        // The work root's parent.
                        let i = root.iter().rposition(|&b| b == b'/').unwrap_or(0);
                        if i == 0 {
                            b"/"
                        } else {
                            &root[..i]
                        }
                    }
                    _ => OUTSIDE_FILE,
                };
                target.b[..tb.len()].copy_from_slice(tb);
                target.n = tb.len();
                if st.is_some() && !rename_in(pfd, &name, &aside) {
                    continue;
                }
                let r = mutate_as_guest(
                    nr::SYMLINKAT,
                    [target.b.as_ptr() as u64, pfd as u64, name.ptr(), 0, 0, 0],
                );
                if r != 0 {
                    if st.is_some() && !rename_in(pfd, &aside, &name) {
                        return None; // the tree is not as the next mutation expects
                    }
                    continue;
                }
                if st.is_some() {
                    s.aside = aside;
                }
                s.ino = lstat_in(pfd, &name).map_or(0, |x| x.ino());
                return Some((s, target, MUT_SYMLINK, to));
            }
            _ => {}
        }
    }
    None
}

/// Put a swap back after the call, as far as what the call left allows: each step is made
/// only on the entries the swap made, and stops at the first that fails.
pub fn after(s: Swap) {
    let Some(pfd) = open_parent(&s.parent) else {
        return;
    };
    let ours = lstat_in(pfd, &s.name).is_some_and(|x| x.ino() == s.ino);
    let undone = match s.mutation {
        MUT_SYMLINK => {
            ours && lstat_in(pfd, &s.name).is_some_and(|x| x.mode() as u64 & S_IFMT == S_IFLNK)
                && mutate_as_guest(nr::UNLINKAT, [pfd as u64, s.name.ptr(), 0, 0, 0, 0]) == 0
        }
        MUT_RENAME => ours && rename_in(pfd, &s.name, &s.sibling),
        _ => true,
    };
    if undone && s.aside.n != 0 {
        rename_in(pfd, &s.aside, &s.name);
    }
    unsafe { sc1(nr::CLOSE, pfd as u64) };
}

/// The `Injected` record and its two `Name` records: the swapped path, then the target.
fn note(nr: u64, a0: u64, how: u64, chk: Seen, path: &[u8], target: &[u8]) {
    let ts = thread();
    let vclock_ns = ctl().vclock_ns.load(Relaxed);
    crate::log::append(&proto::Rec {
        seq: ts.seq,
        vclock_ns,
        slot: ts.slot as u16,
        kind: proto::RecKind::Injected as u8,
        class: 0,
        nr: nr as u32,
        args: [INJ_PATH_SWAP, how, 0, a0, chk.nr, chk.seq],
        ret: 0,
        out_hash: 0,
        in_hash: 0,
    });
    for n in [path, target] {
        crate::log::append(&proto::Rec::name(
            ts.seq,
            vclock_ns,
            ts.slot as u16,
            ts.pid as i64,
            n,
        ));
    }
    crate::inject::count_injected();
}
