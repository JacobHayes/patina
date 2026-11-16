//! Path swaps (`path-swap-permille`, `path-swap-at`): the runtime changes a path in the work
//! tree between a process's check of it and its use, as another process with the same uid
//! could. This module is what the runtime and the launcher agree on: which calls check and
//! which use a path, and the code that says what a swap did.
//!
//! A *check* is a call that looks at a path: `stat`, `access`, `readlink`, and `open` (a
//! program that opens a file and `fstat`s it has checked it). A *use* is a call that opens,
//! executes, enters, creates, removes, renames or changes a path. A use is eligible when its
//! path, or an ancestor of it below the work root, was named by one of the process's last
//! `WINDOW` checks.

/// How a path call takes part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Looks at a path: noted.
    Check,
    /// Opens a path: may be swapped before, and noted.
    Open,
    /// Uses a path: may be swapped before.
    Use,
}

impl Role {
    pub fn checks(self) -> bool {
        self != Role::Use
    }
    pub fn uses(self) -> bool {
        self != Role::Check
    }
}

/// Checks a process remembers: its last `WINDOW`.
pub const WINDOW: usize = 16;

/// The role of a system call, if it takes part.
pub fn role(nr: u64) -> Option<Role> {
    Some(match nr {
        // stat, lstat, newfstatat, statx, access, faccessat, faccessat2, readlink, readlinkat
        4 | 6 | 262 | 332 | 21 | 269 | 439 | 89 | 267 => Role::Check,
        // open, creat, openat, openat2
        2 | 85 | 257 | 437 => Role::Open,
        // mkdir, mkdirat, mknod, mknodat, unlink, rmdir, unlinkat
        83 | 258 | 133 | 259 | 87 | 84 | 263
        // rename, renameat, renameat2, link, linkat, symlink, symlinkat
        | 82 | 264 | 316 | 86 | 265 | 88 | 266
        // truncate, chmod, fchmodat, fchmodat2, chown, lchown, fchownat
        | 76 | 90 | 268 | 452 | 92 | 94 | 260
        // chdir, execve, execveat
        | 80 | 59 | 322 => Role::Use,
        _ => return None,
    })
}

/// A path argument: the index of its directory descriptor argument (`None`: the working
/// directory) and of the path.
pub type PathArg = (Option<usize>, usize);

/// The path arguments of a call that has a `role` (at most two).
pub fn path_args(nr: u64) -> ([PathArg; 2], usize) {
    let one = |d: Option<usize>, p: usize| ([(d, p), (None, 0)], 1);
    match nr {
        82 | 86 => ([(None, 0), (None, 1)], 2),
        264 | 316 | 265 => ([(Some(0), 1), (Some(2), 3)], 2),
        88 => one(None, 1),
        266 => one(Some(1), 2),
        257 | 437 | 262 | 332 | 269 | 439 | 267 | 258 | 259 | 263 | 268 | 452 | 260 | 322 => {
            one(Some(0), 1)
        }
        _ => one(None, 0),
    }
}

/// What a swap does to the component it picks.
pub const MUT_SYMLINK: u64 = 1;
/// Another entry of the same directory is renamed into its place.
pub const MUT_RENAME: u64 = 2;
/// It is renamed away: the name is gone.
pub const MUT_REMOVE: u64 = 3;

/// What a symlink points at: outside the work tree (`/etc/passwd` for a file, the work root's
/// parent for a directory), another entry of the same directory, or nothing.
pub const TO_OUTSIDE: u64 = 1;
pub const TO_SIBLING: u64 = 2;
pub const TO_DANGLING: u64 = 3;

/// A file outside the work tree that every sandbox has.
pub const OUTSIDE_FILE: &[u8] = b"/etc/passwd";
/// The name a swapped-out entry is renamed to, in its own directory, before the seq.
pub const ASIDE_PREFIX: &[u8] = b".patina-swap-";
/// A dangling symlink's target, relative to its directory.
pub const DANGLING: &[u8] = b".patina-swap-nothing";

/// The `how` code of an `INJ_PATH_SWAP` record.
pub const fn how(mutation: u64, target: u64, put_back: bool) -> u64 {
    mutation | target << 4 | (put_back as u64) << 8
}

/// `(mutation, target, put back)` of a `how` code.
pub const fn decode(how: u64) -> (u64, u64, bool) {
    (how & 0xf, how >> 4 & 0xf, how >> 8 & 1 != 0)
}

/// The draws' choice of a mutation, a symlink target and whether to put the path back:
/// uniform over `MUT_*`, uniform over `TO_*`, one half.
pub const fn choose(d: u64) -> (u64, u64, bool) {
    (1 + d % 3, 1 + d / 3 % 3, d / 9 % 2 == 1)
}

/// The lengths of the prefixes of `path` that end at a component and lie strictly below
/// `root` (both normalised absolute paths), shortest first: the components a swap may pick.
pub fn components<'a>(path: &'a [u8], root: &[u8]) -> impl Iterator<Item = usize> + use<'a> {
    let base = if root == b"/" { 0 } else { root.len() };
    let inside = (root == b"/" || crate::vfs::under(path, root)) && path.len() > base + 1;
    (base + 1..=path.len())
        .filter(move |&i| inside && (i == path.len() || path[i] == b'/'))
        .filter(move |&i| i > base + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps<'a>(p: &'a [u8], r: &[u8]) -> [&'a [u8]; 4] {
        let mut out: [&[u8]; 4] = [b""; 4];
        for (k, i) in components(p, r).enumerate() {
            out[k] = &p[..i];
        }
        out
    }

    #[test]
    fn components_lie_below_the_root() {
        assert_eq!(
            comps(b"/work/a/b", b"/work"),
            [&b"/work/a"[..], b"/work/a/b", b"", b""]
        );
        assert_eq!(comps(b"/work", b"/work"), [&b""[..]; 4]);
        assert_eq!(comps(b"/workx/a", b"/work"), [&b""[..]; 4]);
        assert_eq!(comps(b"/etc/passwd", b"/work"), [&b""[..]; 4]);
        assert_eq!(comps(b"/rw/d", b"/"), [&b"/rw"[..], b"/rw/d", b"", b""]);
    }

    #[test]
    fn how_round_trips_and_choices_cover_every_kind() {
        let mut seen = [[false; 4]; 4];
        for d in 0..18 {
            let (m, t, b) = choose(d);
            assert_eq!(decode(how(m, t, b)), (m, t, b));
            seen[m as usize][t as usize] = true;
        }
        for (m, row) in seen.iter().enumerate().skip(1) {
            assert!(row[1..].iter().all(|x| *x), "mutation {m}");
        }
    }
}
