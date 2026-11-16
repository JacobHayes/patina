//! Descriptors and file data.

use super::fs::{after_mutation, fstat_raw, vkey, Data, FsOp};
use super::*;
use crate::state::proc;
use crate::vtime::{self, Which};
use proto::layout::FD_HIDDEN_MIN;

fn entropy(call: &mut dyn Call, buf: u64, len: u64) -> i64 {
    set_class(call, Class::Virt);
    if buf == 0 {
        return -e::EFAULT;
    }
    super::misc::write_entropy(call.thread().seq, buf, len)
}

fn readv_entropy(call: &mut dyn Call) -> i64 {
    set_class(call, Class::Virt);
    let (iov, cnt) = (call.arg(1), call.arg(2));
    let seq = call.thread().seq;
    let mut total = 0u64;
    for i in 0..cnt.min(1024) {
        let Ok([base, len]) = get::<[u64; 2]>(iov + i * 16) else {
            return if total == 0 { -e::EFAULT } else { total as i64 };
        };
        let r = super::misc::write_entropy(seq.wrapping_add(i << 48), base, len);
        if r < 0 {
            return if total == 0 { r } else { total as i64 };
        }
        total += r as u64;
        if (r as u64) < len {
            break;
        }
    }
    total as i64
}

const TERMINAL_TYPE: u64 = 0x54; // 'T'
const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const FIONCLEX: u64 = 0x5450;
const FIOCLEX: u64 = 0x5451;
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFL: u64 = 4;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_SETPIPE_SZ: u64 = 1031;
/// Pipe capacity set at creation, so the host's pipe limits are not an input.
const PIPE_SIZE: u64 = 65_536;
const O_DIRECT: u64 = 0o40000;

/// Requests whose answer is a function of the file on a sandbox or host-stable filesystem.
const FILE_IOCTLS: [u64; 6] = [
    0x4004_9409, // FICLONE
    0x4020_940d, // FICLONERANGE
    0xc018_9436, // FIDEDUPERANGE
    0x8008_6601, // FS_IOC_GETFLAGS
    FS_IOC_FSGETXATTR,
    2, // FIGETBSZ
];

const FS_IOC_FSGETXATTR: u64 = 0x801c_581f;

fn ioctl(call: &mut dyn Call) -> Action {
    let req = call.arg(1) & 0xffff_ffff;
    if super::procfs::kind_of(call.arg(0) as i32 as i64).is_some()
        && (req >> 8) & 0xff != TERMINAL_TYPE
        && !matches!(req, FIONREAD | FIONBIO | FIONCLEX | FIOCLEX)
    {
        return Action::Return(-e::ENOTTY);
    }
    match req {
        FIONREAD | FIONBIO | FIONCLEX | FIOCLEX => {
            set_class(call, Class::Pass);
            pass(call)
        }
        r if FILE_IOCTLS.contains(&r) => {
            set_class(call, Class::Pass);
            pass(call)
        }
        _ if (req >> 8) & 0xff == TERMINAL_TYPE => {
            // No terminal exists in the sandbox: a valid descriptor answers ENOTTY.
            let ok = unsafe { sc2(nr::FCNTL, call.arg(0), F_GETFD) };
            Action::Return(if ok < 0 { ok } else { -e::ENOTTY })
        }
        _ => {
            // Any other request: refused as a kernel without it would (ENOTTY), on a
            // valid descriptor.
            let ok = unsafe { sc2(nr::FCNTL, call.arg(0), F_GETFD) };
            if ok < 0 {
                return Action::Return(ok);
            }
            Action::Return(refuse_request(call, b"ioctl", req, true, -e::ENOTTY))
        }
    }
}

/// Carry the per-descriptor marks (entropy, synthesised /proc file) to a duplicate.
fn copy_marks(src: i64, dst: i64) {
    let u = proc().is_urandom(src);
    proc().set_urandom(dst, u);
    super::procfs::mark(dst, super::procfs::kind_of(src));
    super::timerfd::copy(src, dst);
    crate::oplog::dup_fd(src, dst);
}

fn clear_marks(fd: i64) {
    proc().set_urandom(fd, false);
    super::procfs::mark(fd, None);
    super::timerfd::closed(fd);
}

fn dup_like(call: &mut dyn Call) -> i64 {
    let src = call.arg(0) as i32 as i64;
    // dup2/dup3 over a wire socket may close its last reference.
    let over = if call.nr() != 32 && call.arg(0) != call.arg(1) {
        super::inet::wire_idx(call.arg(1) as i32 as i64)
    } else {
        None
    };
    let r = raw(call);
    if r >= 0 {
        if let Some(i) = over {
            super::inet::mark(i);
        }
    }
    host_check(call, r);
    if r >= 0 {
        copy_marks(src, r);
        if call.nr() != 32 {
            super::io::bump(); // dup2/dup3 closed whatever was at the target number
        }
    }
    r
}

/// fcntl: descriptor flags and duplication pass; blocking lock requests become
/// one non-blocking attempt (a lock held elsewhere is blocking I/O's park); O_DIRECT is dropped.
fn fcntl(call: &mut dyn Call) -> i64 {
    let [fd, cmd, arg, ..] = args(call);
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            if arg as i64 >= FD_HIDDEN_MIN as i64 {
                return -e::EINVAL;
            }
            let r = raw(call);
            host_check(call, r);
            if r >= 0 {
                copy_marks(fd as i32 as i64, r);
            }
            r
        }
        F_SETFL if arg & O_DIRECT != 0 => {
            crate::path::refuse(b"O_DIRECT");
            unsafe { sc3(nr::FCNTL, fd, cmd, arg & !O_DIRECT) }
        }
        F_SETLKW | F_OFD_SETLKW | F_SETLK | F_OFD_SETLK => super::lock::fcntl_lock(fd, cmd, arg),
        F_SETPIPE_SZ => {
            let r = raw(call);
            host_check(call, r);
            if r == -e::EPERM && arg <= 1 << 20 {
                // Below the default pipe-max-size, EPERM means the host user's pipe page
                // accounting is over its soft limit (see pipe creation).
                crate::sup::host_error(r, call.nr(), proto::ctl::HE_HOST_LIMIT);
            }
            if r >= 0 {
                super::io::bump(); // capacity changes writability
            }
            r
        }
        // F_GETFD F_SETFD F_GETFL F_SETFL F_GETLK F_SETLK F_OFD_GETLK F_OFD_SETLK, pipe size,
        // seals, write-life hints, F_DUPFD_QUERY.
        1 | 2 | 3 | 4 | 5 | 36 | 1032 | 1033 | 1034 | 1035 | 1036 | 1037 | 1038 | 1027 => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        // Any other command: refused (EINVAL, as for an unknown command).
        _ => refuse_request(call, b"fcntl", cmd, false, -e::EINVAL),
    }
}

/// close_range never reaches the hidden descriptors.
fn close_range(call: &mut dyn Call) -> i64 {
    let [first, last, flags, ..] = args(call);
    let max = FD_HIDDEN_MIN as u64 - 1;
    if first > last {
        return -e::EINVAL;
    }
    if first > max {
        return 0;
    }
    let last = last.min(max);
    let r = unsafe { sc3(436, first, last, flags) };
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if r == 0 && flags & CLOSE_RANGE_CLOEXEC == 0 {
        for fd in first..=last {
            clear_marks(fd as i64);
        }
        super::inet::mark_all();
        super::io::bump();
    }
    r
}

/// After a successful write-like call on `fd`: file times and the operation record.
fn wrote(fd: i64, offset: Option<u64>, len: i64, data: Data) {
    wrote_ex(fd, offset, len, data, false)
}

fn wrote_ex(fd: i64, offset: Option<u64>, len: i64, data: Data, append: bool) {
    if len <= 0 {
        return;
    }
    let Some(st) = fstat_raw(fd) else { return };
    if let Some(k) = vkey(&st) {
        vtime::touch(k, Which::Modify);
    }
    if crate::path::is_work(st[0]) {
        // O_APPEND (or RWF_APPEND): the kernel wrote at the end, whatever the offset said.
        const O_APPEND: i64 = 0o2000;
        let append = append || unsafe { sc2(nr::FCNTL, fd as u64, 3) } & O_APPEND != 0;
        let offset = if append {
            Some((st[6] as i64 - len).max(0) as u64)
        } else {
            offset
        };
        let off = offset.unwrap_or_else(|| {
            let pos = unsafe { sc3(8, fd as u64, 0, 1) }; // lseek(fd, 0, SEEK_CUR)
            (pos - len).max(0) as u64
        });
        after_mutation(&FsOp::Write {
            ino: st[1],
            offset: off,
            len: len as u64,
            data,
        });
    }
}

const RWF_NOWAIT: u64 = 8;

fn write_call(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let mut a = args(call);
    if nr == 328 || nr == 327 {
        // preadv2/pwritev2: RWF_NOWAIT from the guest would expose page-cache state.
        a[5] &= !RWF_NOWAIT;
    }
    let r = unsafe { sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    host_check(call, r);
    let fd = a[0] as i32 as i64;
    match nr {
        1 => wrote(fd, None, r, Data::Buf(a[1])),
        18 => wrote(fd, Some(a[3]), r, Data::Buf(a[1])),
        20 => wrote(fd, None, r, Data::Iov(a[1], a[2])),
        296 => wrote(fd, Some(a[3]), r, Data::Iov(a[1], a[2])),
        328 => {
            const RWF_APPEND: u64 = 0x10;
            wrote_ex(
                fd,
                if a[3] as i64 == -1 { None } else { Some(a[3]) },
                r,
                Data::Iov(a[1], a[2]),
                a[5] & RWF_APPEND != 0,
            )
        }
        // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
        326 => {
            let off = if a[3] != 0 {
                Some(unsafe { *(a[3] as *const u64) }.wrapping_sub(r.max(0) as u64))
            } else {
                None
            };
            wrote(a[2] as i32 as i64, off, r, Data::InFile(a[2] as i32 as i64))
        }
        // sendfile(out_fd, in_fd, offset, count)
        40 => wrote(fd, None, r, Data::InFile(fd)),
        _ => {}
    }
    r
}

/// copy_file_range and sendfile pass between files that cannot block; with a pipe,
/// socket or anonymous object on either side they answer EINVAL (programs fall back to
/// read and write, which are attempts), and the refusal is listed in the outcome.
fn file_to_file(call: &mut dyn Call) -> i64 {
    if call.nr() == 40 {
        if let Some(i) = super::inet::wire_idx(call.arg(0) as i32 as i64) {
            if !super::io::can_block(super::io::kind_of(call.arg(1) as i32 as i64)) {
                set_class(call, Class::Attempt);
                return super::inet::sendfile(call, i); // sendfile to a wire socket
            }
        }
    }
    let (a, b) = match call.nr() {
        326 => (call.arg(0), call.arg(2)),
        _ => (call.arg(1), call.arg(0)),
    };
    for fd in [a, b] {
        if super::io::can_block(super::io::kind_of(fd as i32 as i64)) {
            ctl().note_denied(call.nr());
            set_class(call, Class::Deny(e::EINVAL as i32));
            return -e::EINVAL;
        }
    }
    write_call(call)
}

/// splice, tee, vmsplice: SPLICE_F_NONBLOCK attempts plus park (`io::splice`).
fn splice(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let r = super::io::splice(call);
    host_check(call, r);
    if call.nr() == 275 && r > 0 {
        let out = a[2] as i32 as i64;
        let off = if a[3] != 0 {
            Some(unsafe { *(a[3] as *const u64) }.wrapping_sub(r as u64))
        } else {
            None
        };
        if fstat_raw(out).is_some_and(|st| st[3] as u32 & 0o170000 == 0o100000) {
            wrote(out, off, r, Data::InFile(out));
        }
    }
    r
}

/// fsync family: durability is the tracker's; the kernel call would do nothing on tmpfs.
fn sync_call(call: &mut dyn Call) -> i64 {
    set_class(call, Class::Virt);
    crate::oplog::sync_call(call.nr(), args(call))
}

pub fn handle(call: &mut dyn Call) -> Action {
    let fd = call.arg(0) as i32 as i64;
    if matches!(call.nr(), 0 | 1 | 19 | 20 | 327 | 328) {
        // Attempt rows; on files, directories and devices they are plain passes.
        set_class(call, Class::Pass);
    }
    let (a1, a2) = (call.arg(1), call.arg(2));
    let r = match call.nr() {
        0 if proc().is_urandom(fd) => entropy(call, a1, a2),
        17 if proc().is_urandom(fd) => entropy(call, a1, a2),
        19 | 295 | 327 if proc().is_urandom(fd) => readv_entropy(call),
        3 => {
            let ino = crate::oplog::before_close(fd);
            let wire = super::inet::wire_idx(fd);
            let r = raw(call);
            if let (0, Some(i)) = (r, wire) {
                super::inet::mark(i); // the last close shows as EOF at the hidden end
            }
            if let (0, Some(ino)) = (r, ino) {
                crate::oplog::closed(ino);
            }
            if r == 0 {
                clear_marks(fd);
                super::io::bump(); // the last close of an end changes its peer; locks are released
            }
            r
        }
        32 | 33 | 292 => dup_like(call),
        72 => fcntl(call),
        73 => super::lock::flock(call),
        436 => close_range(call),
        16 => return ioctl(call),
        7 | 271 => super::poll::poll(call),
        23 | 270 => super::poll::select(call),
        232 | 281 | 441 => super::poll::epoll_wait(call),
        233 => super::poll::epoll_ctl(call),
        283 | 286 | 287 => super::timerfd::handle(call),
        0 | 1 | 19 | 20 | 327 | 328 if super::io::can_block(super::io::kind_of(fd)) => {
            let k = super::io::kind_of(fd).unwrap();
            match (k, super::inet::wire_idx(fd)) {
                (super::io::Kind::Sock, Some(i)) => super::inet::rw(call, i),
                _ => super::io::rw(call, k),
            }
        }
        1 | 18 | 20 | 296 | 328 => write_call(call),
        326 | 40 => file_to_file(call),
        275 | 276 | 278 => splice(call),
        327 => {
            let mut a = args(call);
            a[5] &= !RWF_NOWAIT;
            let r = unsafe { sc6(327, a[0], a[1], a[2], a[3], a[4], a[5]) };
            host_check(call, r);
            r
        }
        74 | 75 | 162 | 306 | 277 => sync_call(call),
        77 | 285 | 91 | 93 | 190 | 199 => {
            let r = raw(call);
            host_check(call, r);
            super::fs::fd_mutation(call, r);
            r
        }
        22 | 293 => {
            let r = raw(call);
            host_check(call, r);
            if r == 0 {
                if let Ok(p) = get::<[i32; 2]>(call.arg(0)) {
                    let sz = unsafe { sc3(nr::FCNTL, p[0] as u64, F_SETPIPE_SZ, PIPE_SIZE) };
                    if sz != PIPE_SIZE as i64 {
                        // The kernel accounts pipe pages per host user (every process of the
                        // launching user, other sandboxes included); past pipe-user-pages-soft a new
                        // pipe gets 2 pages and cannot grow. Not a sandbox answer.
                        crate::sup::host_error(
                            if sz < 0 { sz } else { -e::EPERM },
                            call.nr(),
                            proto::ctl::HE_HOST_LIMIT,
                        );
                    }
                }
            }
            r
        }
        284 | 290 | 319 | 213 | 291 => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        0 | 17 | 19 | 295 | 8 | 193 | 196 | 221 | 187 => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}
