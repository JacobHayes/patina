//! `execve` and `execveat`, and what the first image runs.
//!
//! The runtime resolves what will run, so that every failure is reported to the caller as
//! the kernel would report it: the path walk (`ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`),
//! no execute permission or not a regular file (`EACCES`), neither ELF nor `#!` (`ENOEXEC`),
//! a missing ELF interpreter (`ENOENT`), argument and environment vectors past the kernel's
//! bounds (`E2BIG`). `#!` lines are read as the kernel reads them
//! (`proto::exec::parse`), at most `proto::exec::MAX_DEPTH` deep (`ELOOP` beyond). Then it sends
//! `Exec` and re-executes itself from descriptor 3004 with the resolved image as its argument;
//! the new runtime instance starts in the same task, holding the turn. A failure of that last
//! call is `infra`. The first image goes through the same `resolve` (`loader::start`): a
//! program that cannot run ends the run `error`, saying why (`proto::exec::Why`).

use crate::path::{self, Kind, PathBuf};
use crate::raw::*;
use crate::state::proc;
use crate::sys::{set_class, stop_here};
use crate::trap::{args, Action, Call};
use proto::ctl::Op;
use proto::exec::{Why, BINPRM_BUF_SIZE as BUF, MAX_DEPTH};
use proto::layout::FD_RT;
use proto::table::Class;

const AT_FDCWD: i64 = -100;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const X_OK: u64 = 1;
const AT_EACCESS: u64 = 0x200;
const O_RDONLY_CLOEXEC: u64 = 0o2000000;
/// The kernel's bound on the strings and pointers `execve` copies (`bprm_stack_limits`): a
/// quarter of the stack limit the guest sees (`sys::proc`), between 128 KiB and 6 MiB.
pub const ARG_BYTES: usize = {
    let q = crate::sys::proc::STACK_LIMIT as usize / 4;
    if q < 128 << 10 {
        128 << 10
    } else if q > 6 << 20 {
        6 << 20
    } else {
        q
    }
};
/// More strings than this in the two vectors together: their pointers alone pass `ARG_BYTES`.
pub const MAX_STRINGS: usize = ARG_BYTES / 8;
/// The runtime's own argument vector: [rt, image, the `#!` prefix, the guest's arguments].
const VEC_LEN: usize = MAX_STRINGS + 4 + 2 * MAX_DEPTH;

/// What `execve` will run: the ELF image's canonical path and the `#!` prefix of the
/// argument vector (outermost script first: interpreter, optional argument; then the script
/// name). On failure, `why` and `depth` say what failed (`depth` 0: the file itself, K: the
/// K-th interpreter).
pub struct Target {
    pub elf: PathBuf,
    /// For each `#!` level: [interpreter as written, optional argument], NUL-terminated.
    levels: [[[u8; BUF]; 2]; MAX_DEPTH],
    lens: [[usize; 2]; MAX_DEPTH],
    has_arg: [bool; MAX_DEPTH],
    /// The outermost script's name as the kernel passes it, NUL-terminated.
    script: PathBuf,
    pub depth: usize,
    pub why: Why,
}

impl Target {
    pub const fn new() -> Target {
        Target {
            elf: PathBuf::new(),
            levels: [[[0; BUF]; 2]; MAX_DEPTH],
            lens: [[0; 2]; MAX_DEPTH],
            has_arg: [false; MAX_DEPTH],
            script: PathBuf::new(),
            depth: 0,
            why: Why::Errno,
        }
    }

    /// The strings the kernel puts before the caller's `argv[1..]` for a script: each level's
    /// interpreter and optional argument, innermost first, then the outermost script's name
    /// (which replaces `argv[0]`; inner levels' names are the interpreters already given).
    /// Nothing for an ELF image. Each slice is followed by a NUL in memory.
    pub fn prefix(&self, mut f: impl FnMut(&[u8])) {
        for d in (0..self.depth).rev() {
            f(&self.levels[d][0][..self.lens[d][0]]);
            if self.has_arg[d] {
                f(&self.levels[d][1][..self.lens[d][1]]);
            }
        }
        if self.depth > 0 {
            f(self.script.as_bytes());
        }
    }
}

impl Target {
    /// The script's name as the kernel passes it: the path as the caller gave it (`execveat`
    /// with a descriptor: /dev/fd/N[/path]).
    pub fn set_script(&mut self, dirfd: i64, given: &[u8]) -> Result<(), i64> {
        let s = &mut self.script;
        s.n = 0;
        if dirfd != AT_FDCWD && given.first() != Some(&b'/') {
            for &c in b"/dev/fd/" {
                s.b[s.n] = c;
                s.n += 1;
            }
            s.n += path::fmt_dec(&mut s.b[s.n..], dirfd as u64);
            if !given.is_empty() {
                s.b[s.n] = b'/';
                s.n += 1;
            }
        }
        if s.n + given.len() >= s.b.len() {
            return Err(-e::ENAMETOOLONG);
        }
        s.b[s.n..s.n + given.len()].copy_from_slice(given);
        s.n += given.len();
        s.b[s.n] = 0;
        Ok(())
    }
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
            nr::READLINKAT,
            crate::sys::fs::AT_FDCWD as u64,
            lp.as_ptr() as u64,
            out.b.as_mut_ptr() as u64,
            out.b.len() as u64 - 1,
        )
    };
    if r <= 0 {
        return false;
    }
    out.n = r as usize;
    out.b[out.n] = 0;
    true
}

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

/// Open the file `execve` would open, with the kernel's checks and errors.
/// `p` is NUL-terminated; `flags` are `execveat`'s.
fn open_exec(dirfd: i64, p: &[u8], flags: u64) -> Result<i64, (i64, Why)> {
    let ap = p.as_ptr() as u64;
    let empty = p.len() <= 1 && flags & AT_EMPTY_PATH != 0;
    let r = unsafe {
        sc4(
            nr::FACCESSAT2,
            dirfd as u64,
            ap,
            X_OK,
            AT_EACCESS | (flags & (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)),
        )
    };
    if r < 0 {
        let mut why = Why::Errno;
        if r == -e::EACCES {
            // The file's own mode, or a directory on the way (the errno alone says that).
            let mut st = proto::abi::stat::Stat::zeroed();
            let fl = flags & (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
            if unsafe { sc4(nr::NEWFSTATAT, dirfd as u64, ap, st.as_mut_ptr() as u64, fl) } == 0 {
                why = if st.mode() & S_IFMT != S_IFREG {
                    Why::NotRegular
                } else {
                    Why::NotExecutable
                };
            }
        }
        return Err((r, why));
    }
    let fd = if empty {
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
            proto::abi::open::O_NOFOLLOW
        } else {
            0
        };
        unsafe { sc4(nr::OPENAT, dirfd as u64, ap, O_RDONLY_CLOEXEC | nofollow, 0) }
    };
    if fd == -e::EISDIR || fd == -e::ENXIO {
        return Err((-e::EACCES, Why::NotRegular));
    }
    if fd == -e::EACCES {
        return Err((fd, Why::Unreadable));
    }
    if fd < 0 {
        return Err((fd, Why::Errno));
    }
    let mut st = proto::abi::stat::Stat::zeroed();
    unsafe { sc2(nr::FSTAT, fd as u64, st.as_mut_ptr() as u64) };
    if st.mode() & S_IFMT != S_IFREG {
        unsafe { sc1(nr::CLOSE, fd as u64) };
        return Err((-e::EACCES, Why::NotRegular));
    }
    Ok(fd)
}

/// Is the ELF image on `fd` one this runtime can load, and does its interpreter exist?
fn check_elf(fd: i64, head: &[u8]) -> Result<(), (i64, Why)> {
    proto::exec::elf_header(head).map_err(|w| (-e::ENOEXEC, w))?;
    let phoff = u64::from_le_bytes(head[32..40].try_into().unwrap());
    let phnum = u16::from_le_bytes([head[56], head[57]]) as u64;
    let mut loads = 0;
    for i in 0..phnum {
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
            return Err((-e::ENOEXEC, Why::ElfShort));
        }
        if ph[0] as u32 == 1 {
            loads += 1;
        }
        if ph[0] as u32 == 3 {
            // PT_INTERP: the interpreter must exist (the kernel answers ENOENT otherwise).
            let mut ip = PathBuf::new();
            let n = (ph[4] as usize).min(BUF - 1);
            unsafe {
                sc4(
                    nr::PREAD64,
                    fd as u64,
                    ip.b.as_mut_ptr() as u64,
                    n as u64,
                    ph[1],
                )
            };
            ip.n = ip.b[..n].iter().position(|&c| c == 0).unwrap_or(n);
            ip.b[ip.n] = 0;
            let r = unsafe { sc4(nr::FACCESSAT2, AT_FDCWD as u64, ip.b.as_ptr() as u64, 0, 0) };
            if r < 0 {
                if r == -e::EACCES {
                    return Err((r, Why::Errno));
                }
                path::missing(proto::vfs::MISSING_EXEC, &ip);
                return Err((-e::ENOENT, Why::ElfInterp));
            }
            interp_image(&ip)?;
        }
    }
    if loads == 0 {
        return Err((-e::ENOEXEC, Why::ElfNoLoad));
    }
    Ok(())
}

/// Whether the ELF interpreter at `ip` (NUL-terminated) is an image the runtime loads, with
/// the kernel's errors: `EIO` for a header it cannot read whole, `ELIBBAD` for one that is not
/// a 64-bit ELF image of this architecture or whose program headers are cut off.
fn interp_image(ip: &PathBuf) -> Result<(), (i64, Why)> {
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            AT_FDCWD as u64,
            ip.b.as_ptr() as u64,
            O_RDONLY_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err((fd, Why::ElfInterpBad));
    }
    let mut head = [0u8; 64];
    let n = unsafe { sc4(nr::PREAD64, fd as u64, head.as_mut_ptr() as u64, 64, 0) };
    let r = if n != 64 {
        Err((-e::EIO, Why::ElfInterpBad))
    } else if &head[..4] != b"\x7fELF" || proto::exec::elf_header(&head).is_err() {
        Err((-e::ELIBBAD, Why::ElfInterpBad))
    } else {
        let phoff = u64::from_le_bytes(head[32..40].try_into().unwrap());
        let phnum = u16::from_le_bytes([head[56], head[57]]) as u64;
        let mut ph = [0u8; 56];
        let last = phoff + phnum.saturating_sub(1) * 56;
        let got = unsafe { sc4(nr::PREAD64, fd as u64, ph.as_mut_ptr() as u64, 56, last) };
        if phnum == 0 || got != 56 {
            Err((-e::ELIBBAD, Why::ElfInterpBad))
        } else {
            Ok(())
        }
    };
    unsafe { sc1(nr::CLOSE, fd as u64) };
    r
}

/// Resolve `(dirfd, path)` with `execveat` flags into a target. On failure `t.why` and
/// `t.depth` say what failed.
pub fn resolve(dirfd: i64, path: &[u8], flags: u64, t: &mut Target) -> Result<(), i64> {
    resolve_in(dirfd, path, flags, t).map_err(|(r, why)| {
        t.why = why;
        r
    })
}

fn resolve_in(dirfd: i64, path: &[u8], flags: u64, t: &mut Target) -> Result<(), (i64, Why)> {
    t.depth = 0;
    t.why = Why::Errno;
    let mut dfd = dirfd;
    let mut fl = flags;
    // The policy on the first path (later ones are interpreter paths, checked the same way).
    let mut name = PathBuf::new();
    if path.len() >= name.b.len() {
        return Err((-e::ENAMETOOLONG, Why::Errno));
    }
    name.b[..path.len()].copy_from_slice(path);
    name.b[path.len()] = 0;
    name.n = path.len();
    // The interpreter one past the kernel's depth: opened, as the kernel does, then ELOOP.
    let mut last = false;
    loop {
        let mut norm = PathBuf::new();
        let kind = path::classify(dfd, name.b.as_ptr() as u64, &mut norm);
        let fd = match kind {
            Kind::Plain => match open_exec(dfd, &name.b[..=name.n], fl) {
                // An interpreter's name is not resolved before it is opened (the program's
                // is, `resolve`): where its symbolic links lead is checked here.
                Ok(fd) if t.depth > 0 && hidden_target(fd) => {
                    unsafe { sc1(nr::CLOSE, fd as u64) };
                    path::refuse(norm.as_bytes());
                    return Err((-e::ENOENT, Why::Hidden));
                }
                Ok(fd) => fd,
                Err((r, why)) => {
                    // An interpreter a `#!` line names (the program itself is noted by
                    // `resolve::note_missing`).
                    if r == -e::ENOENT && t.depth > 0 {
                        if name.as_bytes().last() == Some(&b'\r') {
                            return Err((r, Why::CarriageReturn));
                        }
                        if norm.n > 0 {
                            path::missing(proto::vfs::MISSING_EXEC, &norm);
                        }
                    }
                    return Err((r, why));
                }
            },
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
                return Err((-e::ENOENT, Why::Hidden));
            }
            Kind::NoPty => return Err((-e::ENOENT, Why::Errno)),
            Kind::Synth(_) | Kind::Random | Kind::NoTty => {
                return Err((-e::EACCES, Why::NotRegular))
            }
        };
        if last {
            unsafe { sc1(nr::CLOSE, fd as u64) };
            return Err((-e::ELOOP, Why::TooDeep));
        }
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
                return Err((-e::ENOENT, Why::Errno));
            }
            return Ok(());
        }
        unsafe { sc1(nr::CLOSE, fd as u64) };
        if head.is_empty() {
            return Err((-e::ENOEXEC, Why::Empty));
        }
        let script =
            proto::exec::parse(head).map_err(|n| (-e::ENOEXEC, Why::from_not_script(n)))?;
        if script.interp.is_empty() {
            // The kernel opens "": the working directory, not a regular file.
            return Err((-e::EACCES, Why::NoInterp));
        }
        let d = t.depth;
        if d == MAX_DEPTH {
            // The kernel opens this level's interpreter, then gives up.
            last = true;
            let l = script.interp.len();
            name.b[..l].copy_from_slice(script.interp);
            name.b[l] = 0;
            name.n = l;
            dfd = AT_FDCWD;
            fl = 0;
            continue;
        }
        let long = |r| (r, Why::NameTooLong);
        t.lens[d][0] = copy_into(&mut t.levels[d][0], script.interp).map_err(long)?;
        t.has_arg[d] = script.arg.is_some();
        t.lens[d][1] = copy_into(&mut t.levels[d][1], script.arg.unwrap_or(b"")).map_err(long)?;
        if d == 0 {
            t.set_script(dfd, &name.b[..name.n])
                .map_err(|r| (r, Why::NameTooLong))?;
        }
        t.depth += 1;
        let l = script.interp.len();
        name.b[..l].copy_from_slice(script.interp);
        name.b[l] = 0;
        name.n = l;
        dfd = AT_FDCWD;
        fl = 0;
    }
}

/// Whether the file open at `fd` is one Patina keeps from the program (reached through a
/// symbolic link).
fn hidden_target(fd: i64) -> bool {
    let mut real = PathBuf::new();
    let mut norm = PathBuf::new();
    fd_path(fd, &mut real)
        && matches!(
            path::classify(AT_FDCWD, real.b.as_ptr() as u64, &mut norm),
            Kind::Hidden
        )
}

/// The kernel's limit on one argument or environment string.
const MAX_ARG_STRLEN: usize = 32 * 4096;

/// The number of strings in a NULL-terminated vector, and their bytes with the NULs.
fn count(v: u64) -> Result<(usize, usize), i64> {
    if v == 0 {
        return Ok((0, 0));
    }
    let (mut n, mut bytes) = (0, 0);
    // Every string is checked readable here, before the point of no return: the kernel's
    // EFAULT for one it cannot read must be the guest's answer, not a failed re-execution.
    loop {
        let s = crate::guest::get::<u64>(v + 8 * n as u64)?;
        if s == 0 {
            break;
        }
        // No NUL within `MAX_ARG_STRLEN` bytes: longer than the kernel copies.
        let len = crate::guest::strlen(s, MAX_ARG_STRLEN)?;
        if len == MAX_ARG_STRLEN {
            return Err(-e::E2BIG);
        }
        bytes += len + 1;
        n += 1;
        if n > MAX_STRINGS {
            return Err(-e::E2BIG);
        }
    }
    Ok((n, bytes))
}

/// Vectors past `ARG_BYTES` (the guest gets `E2BIG` for vectors the kernel would refuse,
/// instead of the run failing when the runtime re-executes itself).
fn too_big(path_len: usize, nargs: usize, nenv: usize, bytes: usize) -> bool {
    let ptrs = (nargs.max(1) + nenv) * 8;
    ptrs >= ARG_BYTES || bytes + path_len + 1 > ARG_BYTES - ptrs
}

/// The memory of the runtime's argument vector (`VEC_LEN` words, mapped once per process and
/// touched as far as used; the runtime's stack does not hold it).
fn vec_scratch() -> &'static mut [u64] {
    static AT: crate::path::Global<u64> = crate::path::Global::new(0);
    let at = AT.get();
    let size = ((VEC_LEN * 8) as u64 + 4095) & !4095;
    if *at == 0 {
        let a = crate::state::priv_alloc(size, 4096);
        let r = unsafe {
            sc6(
                nr::MMAP,
                a,
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
                u64::MAX,
                0,
            )
        };
        if r as u64 != a {
            crate::sup::host_error(r, nr::MMAP, proto::ctl::HE_SYSCALL);
        }
        *at = a;
    }
    unsafe { core::slice::from_raw_parts_mut(*at as *mut u64, VEC_LEN) }
}

/// `execve(path, argv, envp)` and `execveat(dirfd, path, argv, envp, flags)`.
pub fn execve(call: &mut dyn Call) -> Action {
    let a = args(call);
    let (dirfd, p, argv, envp, flags) = if call.nr() == nr::EXECVE {
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
    let mut t = Target::new();
    if let Err(e) = resolve(dirfd, path, flags, &mut t) {
        return Action::Return(e);
    }
    if t.depth > 0 {
        // The handler's path has its symlinks resolved (`resolve::prepare`); the script's
        // name is the one the guest gave.
        let g = call.guest_args();
        let (gdir, gp) = if call.nr() == nr::EXECVE {
            (AT_FDCWD, g[0])
        } else {
            (g[0] as i32 as i64, g[1])
        };
        let given = match crate::guest::cstr(gp, crate::path::PATH_MAX) {
            Ok(s) => s,
            Err(r) => return Action::Return(r),
        };
        if let Err(r) = t.set_script(gdir, given) {
            return Action::Return(r);
        }
    }
    let ((nargs, abytes), (nenv, ebytes)) = match (count(argv), count(envp)) {
        (Ok(a), Ok(e)) => (a, e),
        (Err(r), _) | (_, Err(r)) => return Action::Return(r),
    };
    if too_big(path.len(), nargs, nenv, abytes + ebytes) {
        return Action::Return(-e::E2BIG);
    }
    // The new argument vector: [rt, image, (#! prefix, innermost interpreter first), argv[1..]].
    let v = vec_scratch();
    let mut n = 0;
    v[n] = c"rt".as_ptr() as u64;
    n += 1;
    v[n] = t.elf.b.as_ptr() as u64;
    n += 1;
    t.prefix(|s| {
        v[n] = s.as_ptr() as u64;
        n += 1;
    });
    if t.depth > 0 {
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
    // The runtime's own exec copies the image's path and the `#!` prefix besides: past the
    // host's bound (the same `ARG_BYTES`) where the guest's vector was within it, the run
    // cannot go on as the kernel would.
    let mut vbytes = 3 + t.elf.as_bytes().len() + 1 + abytes;
    t.prefix(|s| vbytes += s.len() + 1);
    if t.depth > 0 && nargs > 0 {
        // The script's own argv[0] is replaced by the prefix.
        let a0 = crate::guest::get::<u64>(argv).unwrap_or(0);
        vbytes -= crate::guest::strlen(a0, MAX_ARG_STRLEN).unwrap_or(0) + 1;
    }
    if too_big(32, n, nenv, vbytes + ebytes) {
        return stop_here(call);
    }
    // Point of no return. Descriptor marks the new image cannot rebuild end the run.
    if crate::sys::signalfd::before_exec().is_err() {
        return stop_here(call);
    }
    // Stores through shared `/work` mappings of this image are recorded now, as at exit.
    crate::oplog::on_exit();
    set_class(call, Class::Virt);
    let row = proto::row(call.nr() as u32);
    crate::log::trap(row, call, 0);
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
            nr::EXECVEAT,
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
/// descriptors and synthesised `/proc` files are found again by name, timerfds by asking the
/// supervisor about each eventfd.
pub fn rescan_marks() {
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            AT_FDCWD as u64,
            c"/proc/self/fd".as_ptr() as u64,
            proto::abi::open::O_DIRECTORY | 0o2000000, // O_CLOEXEC
            0,
        )
    };
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe {
            sc3(
                nr::GETDENTS64,
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
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
                        } else if s == b"anon_inode:[eventfd]" {
                            crate::sys::timerfd::found(d);
                        } else if let Some(k) = s.strip_prefix(b"/memfd:patina-proc:") {
                            if k.len() >= 3 && k[..3].iter().all(|c| c.is_ascii_digit()) {
                                crate::sys::procfs::mark(
                                    d,
                                    path::Synth::from_u8(path::dec(&k[..3]) as u8),
                                );
                            }
                        } else if let Some(k) = crate::sys::procfs::dir_kind(s) {
                            // A directory the policy handed out before the exec.
                            let mut st = proto::abi::stat::Stat::zeroed();
                            let r = unsafe { sc2(nr::FSTAT, d as u64, st.as_mut_ptr() as u64) };
                            if r == 0 && st.mode() & 0o170000 == 0o040000 {
                                crate::sys::procfs::mark(d, Some(k));
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
