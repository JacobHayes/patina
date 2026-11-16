//! `execve` and `execveat`.
//!
//! The runtime resolves what will run, so that every failure is reported to the caller as
//! the kernel would report it: the path walk (`ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`),
//! no execute permission or not a regular file (`EACCES`), neither ELF nor `#!` (`ENOEXEC`),
//! a missing ELF interpreter (`ENOENT`). `#!` lines are resolved here, at most 4 deep as the
//! kernel allows (`ELOOP` beyond). Then it sends `Exec` and re-executes itself from descriptor
//! 3004 with the resolved image as its argument; the new runtime instance starts in the same
//! task, holding the turn. A failure of that last call is `infra`.

use crate::path::{self, Kind, PathBuf};
use crate::raw::*;
use crate::state::proc;
use crate::sys::{set_class, stop_here};
use crate::trap::{args, Action, Call};
use proto::ctl::Op;
use proto::layout::FD_RT;
use proto::table::Class;

const AT_FDCWD: i64 = -100;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const X_OK: u64 = 1;
const AT_EACCESS: u64 = 0x200;
const O_RDONLY_CLOEXEC: u64 = 0o2000000;
const MAX_DEPTH: usize = 4;
const BUF: usize = 256;
/// The loader takes at most this many arguments and environment strings.
const MAX_ARGS: usize = 4096;

/// What `execve` will run: the ELF image's canonical path and the `#!` prefix of the
/// argument vector (outermost script first: interpreter, optional argument, script name).
pub struct Target {
    pub elf: PathBuf,
    /// For each `#!` level: [interpreter as written, optional argument, file name as given].
    pub levels: [[[u8; BUF]; 3]; MAX_DEPTH],
    pub lens: [[usize; 3]; MAX_DEPTH],
    pub has_arg: [bool; MAX_DEPTH],
    pub depth: usize,
}

fn copy_into(dst: &mut [u8; BUF], s: &[u8]) -> Result<usize, i64> {
    if s.len() >= BUF {
        return Err(-e::ENAMETOOLONG);
    }
    dst[..s.len()].copy_from_slice(s);
    dst[s.len()] = 0;
    Ok(s.len())
}

/// The canonical path of an open descriptor (the kernel's own name for it).
fn fd_path(fd: i64, out: &mut PathBuf) -> bool {
    let mut lp = [0u8; 32];
    let mut l = 0;
    for &c in b"/proc/self/fd/" {
        lp[l] = c;
        l += 1;
    }
    l += path::fmt_dec(&mut lp[l..], fd as u64);
    lp[l] = 0;
    let r = unsafe {
        sc4(
            89,
            lp.as_ptr() as u64,
            out.b.as_mut_ptr() as u64,
            out.b.len() as u64 - 1,
            0,
        )
    };
    if r <= 0 {
        return false;
    }
    out.n = r as usize;
    out.b[out.n] = 0;
    true
}

/// Open the file `execve` would open, with the kernel's checks and errors.
/// `p` is NUL-terminated; `flags` are `execveat`'s.
fn open_exec(dirfd: i64, p: &[u8], flags: u64) -> Result<i64, i64> {
    let ap = p.as_ptr() as u64;
    let r = unsafe {
        sc4(
            439,
            dirfd as u64,
            ap,
            X_OK,
            AT_EACCESS | (flags & (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)),
        )
    };
    if r < 0 {
        return Err(r);
    }
    let fd = if p.len() <= 1 && flags & AT_EMPTY_PATH != 0 {
        // The descriptor itself (fexecve): reopen it for reading through /proc/self/fd.
        let mut lp = PathBuf::new();
        let mut l = 0;
        for &c in b"/proc/self/fd/" {
            lp.b[l] = c;
            l += 1;
        }
        l += path::fmt_dec(&mut lp.b[l..], dirfd as u64);
        lp.b[l] = 0;
        unsafe {
            sc4(
                nr::OPENAT,
                AT_FDCWD as u64,
                lp.b.as_ptr() as u64,
                O_RDONLY_CLOEXEC,
                0,
            )
        }
    } else {
        let nofollow = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            0o400000
        } else {
            0
        };
        unsafe { sc4(nr::OPENAT, dirfd as u64, ap, O_RDONLY_CLOEXEC | nofollow, 0) }
    };
    if fd == -e::EISDIR || fd == -e::ENXIO {
        return Err(-e::EACCES);
    }
    if fd < 0 {
        return Err(fd);
    }
    let mut st = [0u64; 18];
    unsafe { sc2(5, fd as u64, st.as_mut_ptr() as u64) };
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    if (st[3] as u32) & S_IFMT != S_IFREG {
        unsafe { sc1(nr::CLOSE, fd as u64) };
        return Err(-e::EACCES);
    }
    Ok(fd)
}

/// Is the ELF image on `fd` one this runtime can load, and does its interpreter exist?
fn check_elf(fd: i64, head: &[u8]) -> Result<(), i64> {
    if head.len() < 64 || head[4] != 2 || u16::from_le_bytes([head[18], head[19]]) != 62 {
        return Err(-e::ENOEXEC);
    }
    let typ = u16::from_le_bytes([head[16], head[17]]);
    if typ != 2 && typ != 3 {
        return Err(-e::ENOEXEC);
    }
    let phoff = u64::from_le_bytes(head[32..40].try_into().unwrap());
    let phnum = u16::from_le_bytes([head[56], head[57]]) as u64;
    for i in 0..phnum.min(64) {
        let mut ph = [0u64; 7];
        let r = unsafe {
            sc4(
                nr::PREAD64,
                fd as u64,
                ph.as_mut_ptr() as u64,
                56,
                phoff + i * 56,
            )
        };
        if r != 56 {
            return Err(-e::ENOEXEC);
        }
        if ph[0] as u32 == 3 {
            // PT_INTERP: the interpreter must exist (the kernel answers ENOENT otherwise).
            let mut ip = [0u8; BUF];
            let n = (ph[4] as usize).min(BUF - 1);
            unsafe {
                sc4(
                    nr::PREAD64,
                    fd as u64,
                    ip.as_mut_ptr() as u64,
                    n as u64,
                    ph[1],
                )
            };
            ip[n] = 0;
            let r = unsafe { sc4(439, AT_FDCWD as u64, ip.as_ptr() as u64, 0, 0) };
            if r < 0 {
                return Err(if r == -e::EACCES { r } else { -e::ENOENT });
            }
        }
    }
    Ok(())
}

/// Parse a `#!` line: (interpreter, optional argument), as the kernel's `load_script` does.
fn parse_shebang(head: &[u8]) -> Result<(&[u8], Option<&[u8]>), i64> {
    let line = &head[2..];
    let end = line.iter().position(|&c| c == b'\n').unwrap_or(line.len());
    let mut l = &line[..end];
    let ws = |c: u8| c == b' ' || c == b'\t';
    while l.first().is_some_and(|&c| ws(c)) {
        l = &l[1..];
    }
    while l.last().is_some_and(|&c| ws(c) || c == 0) {
        l = &l[..l.len() - 1];
    }
    if l.is_empty() {
        return Err(-e::ENOEXEC);
    }
    let i = l.iter().position(|&c| ws(c)).unwrap_or(l.len());
    let interp = &l[..i];
    let mut rest = &l[i..];
    while rest.first().is_some_and(|&c| ws(c)) {
        rest = &rest[1..];
    }
    Ok((interp, if rest.is_empty() { None } else { Some(rest) }))
}

/// Resolve `(dirfd, path)` with `execveat` flags into a target.
pub fn resolve(dirfd: i64, path: &[u8], flags: u64, t: &mut Target) -> Result<(), i64> {
    t.depth = 0;
    let mut cur = [0u8; BUF + 1];
    let mut cur_len;
    let mut dfd = dirfd;
    let mut fl = flags;
    // The policy on the first path (later ones are interpreter paths, checked the same way).
    let mut name = PathBuf::new();
    if path.len() >= name.b.len() {
        return Err(-e::ENAMETOOLONG);
    }
    name.b[..path.len()].copy_from_slice(path);
    name.b[path.len()] = 0;
    name.n = path.len();
    loop {
        let mut norm = PathBuf::new();
        let kind = path::classify(dfd, name.b.as_ptr() as u64, &mut norm);
        let fd = match kind {
            Kind::Plain => open_exec(dfd, &name.b[..=name.n], fl)?,
            Kind::SelfExe => {
                let gp = proc().guest_path();
                let mut g = PathBuf::new();
                g.b[..gp.len()].copy_from_slice(gp);
                g.b[gp.len()] = 0;
                open_exec(AT_FDCWD, &g.b[..=gp.len()], 0)?
            }
            Kind::SelfFd(n) => open_exec(n, b"\0", AT_EMPTY_PATH)?,
            Kind::Hidden => {
                path::refuse(norm.as_bytes());
                return Err(-e::ENOENT);
            }
            Kind::NoPty => return Err(-e::ENOENT),
            Kind::Synth(_) | Kind::Random | Kind::NoTty => return Err(-e::EACCES),
        };
        let mut head = [0u8; BUF];
        let n = unsafe {
            sc4(
                nr::PREAD64,
                fd as u64,
                head.as_mut_ptr() as u64,
                BUF as u64,
                0,
            )
        };
        let n = if n < 0 { 0 } else { n as usize };
        let head = &head[..n];
        if head.len() >= 4 && &head[..4] == b"\x7fELF" {
            let ok = check_elf(fd, head);
            let named = fd_path(fd, &mut t.elf);
            unsafe { sc1(nr::CLOSE, fd as u64) };
            ok?;
            if !named {
                return Err(-e::ENOENT);
            }
            return Ok(());
        }
        unsafe { sc1(nr::CLOSE, fd as u64) };
        if head.len() < 2 || &head[..2] != b"#!" {
            return Err(-e::ENOEXEC);
        }
        if t.depth == MAX_DEPTH {
            return Err(-e::ELOOP);
        }
        let (interp, arg) = parse_shebang(head)?;
        let d = t.depth;
        t.lens[d][0] = copy_into(&mut t.levels[d][0], interp)?;
        t.has_arg[d] = arg.is_some();
        t.lens[d][1] = copy_into(&mut t.levels[d][1], arg.unwrap_or(b""))?;
        // The script's name as the kernel passes it: the path as given (execveat with a
        // descriptor: /dev/fd/N[/path]).
        let given: &[u8] = &name.b[..name.n];
        let mut fdname = [0u8; BUF];
        let given = if dfd != AT_FDCWD && (given.first() != Some(&b'/')) {
            let mut l = 0;
            for &c in b"/dev/fd/" {
                fdname[l] = c;
                l += 1;
            }
            l += path::fmt_dec(&mut fdname[l..], dfd as u64);
            if !given.is_empty() {
                fdname[l] = b'/';
                l += 1;
                let k = given.len().min(BUF - 1 - l);
                fdname[l..l + k].copy_from_slice(&given[..k]);
                l += k;
            }
            &fdname[..l]
        } else {
            given
        };
        t.lens[d][2] = copy_into(&mut t.levels[d][2], given)?;
        t.depth += 1;
        cur_len = interp.len();
        cur[..cur_len].copy_from_slice(interp);
        cur[cur_len] = 0;
        name.b[..=cur_len].copy_from_slice(&cur[..=cur_len]);
        name.n = cur_len;
        dfd = AT_FDCWD;
        fl = 0;
    }
}

/// The kernel's limit on one argument or environment string.
const MAX_ARG_STRLEN: usize = 32 * 4096;

/// The number of strings in a NULL-terminated vector.
fn count(v: u64) -> Result<usize, i64> {
    if v == 0 {
        return Ok(0);
    }
    let mut n = 0;
    // Every string is checked readable here, before the point of no return: the kernel's
    // EFAULT for one it cannot read must be the guest's answer, not a failed re-execution.
    loop {
        let s = crate::guest::get::<u64>(v + 8 * n as u64)?;
        if s == 0 {
            break;
        }
        crate::guest::strlen(s, MAX_ARG_STRLEN)?;
        n += 1;
        if n > MAX_ARGS {
            return Err(-e::E2BIG);
        }
    }
    Ok(n)
}

/// `execve(path, argv, envp)` and `execveat(dirfd, path, argv, envp, flags)`.
pub fn execve(call: &mut dyn Call) -> Action {
    let a = args(call);
    let (dirfd, p, argv, envp, flags) = if call.nr() == 59 {
        (AT_FDCWD, a[0], a[1], a[2], 0)
    } else {
        (a[0] as i32 as i64, a[1], a[2], a[3], a[4])
    };
    if p == 0 {
        return Action::Return(-e::EFAULT);
    }
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return Action::Return(-e::EINVAL);
    }
    let path = match crate::guest::cstr(p, crate::path::PATH_MAX) {
        Ok(s) => s,
        Err(r) => return Action::Return(r),
    };
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Action::Return(-e::ENOENT);
    }
    let mut t = Target {
        elf: PathBuf::new(),
        levels: [[[0; BUF]; 3]; MAX_DEPTH],
        lens: [[0; 3]; MAX_DEPTH],
        has_arg: [false; MAX_DEPTH],
        depth: 0,
    };
    if let Err(e) = resolve(dirfd, path, flags, &mut t) {
        return Action::Return(e);
    }
    let (nargs, nenv) = match (count(argv), count(envp)) {
        (Ok(a), Ok(e)) => (a, e),
        (Err(r), _) | (_, Err(r)) => return Action::Return(r),
    };
    // The new argument vector: [rt, image, (#! prefix, innermost interpreter first), argv[1..]].
    let mut v = [0u64; MAX_ARGS + 4 + 3 * MAX_DEPTH];
    let mut n = 0;
    v[n] = c"rt".as_ptr() as u64;
    n += 1;
    v[n] = t.elf.b.as_ptr() as u64;
    n += 1;
    for d in (0..t.depth).rev() {
        v[n] = t.levels[d][0].as_ptr() as u64;
        n += 1;
        if t.has_arg[d] {
            v[n] = t.levels[d][1].as_ptr() as u64;
            n += 1;
        }
    }
    if t.depth > 0 {
        // The outermost script's name replaces argv[0]; inner levels' names are the
        // interpreters already pushed (each level's file is the previous interpreter).
        v[n] = t.levels[0][2].as_ptr() as u64;
        n += 1;
        for i in 1..nargs {
            v[n] = crate::guest::get::<u64>(argv + 8 * i as u64).unwrap_or(0);
            n += 1;
        }
    } else {
        if nargs == 0 {
            // The kernel passes an empty argv; the loader needs argv0: an empty string.
            v[n] = c"".as_ptr() as u64;
            n += 1;
        }
        for i in 0..nargs {
            v[n] = crate::guest::get::<u64>(argv + 8 * i as u64).unwrap_or(0);
            n += 1;
        }
    }
    v[n] = 0;
    if n - 2 > MAX_ARGS || nenv > MAX_ARGS {
        return Action::Return(-e::E2BIG);
    }
    // Point of no return. Descriptor marks the new image cannot rebuild end the run.
    if crate::sys::timerfd::before_exec().is_err() {
        return stop_here(call);
    }
    // Stores through shared `/work` mappings of this image are recorded now, as at exit.
    crate::oplog::on_exit();
    set_class(call, Class::Virt);
    let row = proto::row(call.nr() as u32);
    crate::log::trap(row, call.nr(), &a, 0);
    let mut ign = 0u64;
    let sa = crate::state::sigact();
    for (s, act) in sa.iter().enumerate().skip(1) {
        if act[0] == crate::sys::sig::SIG_IGN {
            ign |= 1 << (s - 1);
        }
    }
    crate::sup::call_sup(Op::Exec, [ign, 0, 0, 0, 0, 0]);
    let r = unsafe {
        sc6(
            322,
            FD_RT as u64,
            c"".as_ptr() as u64,
            v.as_ptr() as u64,
            envp,
            AT_EMPTY_PATH,
            0,
        )
    };
    crate::sup::host_error(r, call.nr(), proto::ctl::HE_SYSCALL)
}

/// (New image) Descriptor marks the previous image kept in its own memory: entropy
/// descriptors and synthesised `/proc` files are found again by name.
pub fn rescan_marks() {
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            AT_FDCWD as u64,
            c"/proc/self/fd".as_ptr() as u64,
            0o2200000,
            0,
        )
    };
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { sc3(217, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let name = unsafe { crate::loader::cstr(buf.as_ptr().add(off + 19)) };
            if !name.is_empty() && name.iter().all(|c| c.is_ascii_digit()) {
                let d = path::dec(name) as i64;
                if d != fd && d < proto::layout::FD_HIDDEN_MIN as i64 {
                    let mut lp = PathBuf::new();
                    if fd_path(d, &mut lp) {
                        let s = lp.as_bytes();
                        if s == b"/dev/urandom" || s == b"/dev/random" {
                            proc().set_urandom(d, true);
                        } else if let Some(k) = s.strip_prefix(b"/memfd:patina-proc:") {
                            if k.len() >= 3 && k[..3].iter().all(|c| c.is_ascii_digit()) {
                                crate::sys::procfs::mark(
                                    d,
                                    path::Synth::from_u8(path::dec(&k[..3]) as u8),
                                );
                            }
                        }
                    }
                }
            }
            off += reclen;
        }
    }
    unsafe { sc1(nr::CLOSE, fd as u64) };
}
