//! System V shared memory: the segments are the supervisor's (`Op::Shm`, one table for the
//! run); their memory is a memfd it holds, which `shmat` opens as `/proc/1/fd/N` and maps at
//! an address the runtime chooses (or the program's). The process's attachments are kept
//! here (copied by `fork` with the memory, gone at `execve`) so that `shmdt` and an `munmap`
//! of a whole attachment end it. `SHM_HUGETLB` and `SHM_LOCK` are refused (`EPERM`, as for an
//! unprivileged process); `SHM_STAT`, `IPC_INFO` and `SHM_INFO` answer `EINVAL`.

use super::*;
use core::cell::UnsafeCell;
use proto::ctl::*;
use proto::layout::{PAGE, REALTIME_EPOCH_S, VCLOCK_BOOT_NS};

const SHM_HUGETLB: u64 = 0o4000;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const MAX_ATT: usize = 64;

#[derive(Clone, Copy)]
struct Att {
    addr: u64,
    len: u64,
    id: i64,
}
struct G(UnsafeCell<[Att; MAX_ATT]>);
unsafe impl Sync for G {}
static ATT: G = G(UnsafeCell::new(
    [Att {
        addr: 0,
        len: 0,
        id: 0,
    }; MAX_ATT],
));

fn att() -> &'static mut [Att; MAX_ATT] {
    unsafe { &mut *ATT.0.get() }
}

fn sup(a: [u64; 6]) -> (i64, [u64; 16]) {
    let r = crate::sup::call_sup(Op::Shm, a).ret;
    let ts = crate::state::thread();
    let w = unsafe { core::ptr::read_volatile(&(*ctl().slot(ts.slot as usize)).siginfo) };
    (r, w)
}

fn page_up(x: u64) -> u64 {
    x.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

/// The futex key id of a segment's memory: the same in every process that attaches it.
fn shared_id(id: i64) -> u64 {
    ((id as u64 ^ 0x5348_4d00).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 34) & 0x3fff_ffff
}

fn shmget(call: &mut dyn Call) -> i64 {
    let [key, size, flags, ..] = args(call);
    if flags & SHM_HUGETLB != 0 {
        return refuse_request(call, b"shmget", SHM_HUGETLB, true, -e::EPERM);
    }
    let uid = unsafe { sc0(nr::GETUID) } as u64;
    let gid = unsafe { sc0(nr::GETGID) } as u64;
    sup([
        SHMOP_GET,
        key as i32 as u64,
        size,
        flags,
        uid | gid << 32,
        0,
    ])
    .0
}

fn shmat(call: &mut dyn Call) -> i64 {
    let [id, mut addr, flags, ..] = args(call);
    if crate::state::in_vfork_child() {
        halt(call); // the attachments would be the parent's
    }
    if addr != 0 {
        if addr & (PAGE - 1) != 0 {
            if flags & SHM_RND == 0 {
                return -e::EINVAL;
            }
            addr &= !(PAGE - 1);
            if addr == 0 && flags & SHM_REMAP != 0 {
                return -e::EINVAL;
            }
        }
    } else if flags & SHM_REMAP != 0 {
        return -e::EINVAL;
    }
    let Some(slot) = att().iter().position(|a| a.addr == 0) else {
        return -e::ENOMEM;
    };
    let id = id as i32 as i64;
    let (size, w) = sup([SHMOP_AT, id as u64, 0, 0, 0, 0]);
    if size < 0 {
        return size;
    }
    let len = page_up(size as u64);
    let r = map(w[0], addr, len, flags);
    if r < 0 {
        sup([SHMOP_DT, id as u64, 0, 0, 0, 0]);
        return r;
    }
    // SHM_REMAP: attachments the new mapping replaced have ended.
    unmapped(r as u64, len);
    att()[slot] = Att {
        addr: r as u64,
        len,
        id,
    };
    super::mem::record_shared(r as u64, len, shared_id(id), 0, flags & SHM_RDONLY == 0);
    r
}

/// Map the supervisor's memfd `sfd` (opened through `/proc/1/fd`).
fn map(sfd: u64, addr: u64, len: u64, flags: u64) -> i64 {
    let ro = flags & SHM_RDONLY != 0;
    let mut p = [0u8; 32];
    let pre = b"/proc/1/fd/";
    p[..pre.len()].copy_from_slice(pre);
    let n = crate::path::fmt_dec(&mut p[pre.len()..], sfd);
    p[pre.len() + n] = 0;
    let fd = crate::fdlim::transient(|| unsafe {
        sc4(
            nr::OPENAT,
            -100i64 as u64, // AT_FDCWD
            p.as_ptr() as u64,
            if ro { 0 } else { 2 } | 0o2000000, // O_RDONLY or O_RDWR, O_CLOEXEC
            0,
        )
    });
    if fd < 0 {
        crate::sup::host_error(fd, nr::SHMAT, proto::ctl::HE_SYSCALL);
    }
    let prot = PROT_READ
        | if ro { 0 } else { PROT_WRITE }
        | if flags & SHM_EXEC != 0 { PROT_EXEC } else { 0 };
    let r = if addr != 0 {
        if super::mem::hits_runtime(addr, len) {
            -e::EINVAL
        } else {
            let f = if flags & SHM_REMAP != 0 {
                MAP_FIXED
            } else {
                MAP_FIXED_NOREPLACE
            };
            let r = unsafe { sc6(nr::MMAP, addr, len, prot, 1 | f, fd as u64, 0) };
            // An address already in use without SHM_REMAP: the kernel's EINVAL.
            if r == -e::EEXIST {
                -e::EINVAL
            } else {
                r
            }
        }
    } else {
        loop {
            let Some(a) = super::mem::take(len) else {
                break -e::ENOMEM;
            };
            let r = unsafe {
                sc6(
                    nr::MMAP,
                    a,
                    len,
                    prot,
                    1 | MAP_FIXED_NOREPLACE,
                    fd as u64,
                    0,
                )
            };
            if r != -e::EEXIST {
                break r;
            }
        }
    };
    unsafe { sc1(nr::CLOSE, fd as u64) };
    r
}

/// The attachment starting at `addr` ends (its memory already unmapped).
fn ended(i: usize) {
    let a = att()[i];
    att()[i].addr = 0;
    super::mem::forget_shared(a.addr, a.len);
    sup([SHMOP_DT, a.id as u64, 0, 0, 0, 0]);
}

fn shmdt(addr: u64) -> i64 {
    if crate::state::in_vfork_child() {
        return -e::EINVAL;
    }
    let Some(i) = att().iter().position(|a| a.addr != 0 && a.addr == addr) else {
        return -e::EINVAL;
    };
    unsafe { sc2(nr::MUNMAP, addr, att()[i].len) };
    ended(i);
    0
}

/// `[addr, addr + len)` was unmapped or mapped over: attachments it covered whole have ended.
pub fn unmapped(addr: u64, len: u64) {
    if crate::state::in_vfork_child() {
        return;
    }
    let end = addr.saturating_add(page_up(len));
    for i in 0..MAX_ATT {
        let a = att()[i];
        if a.addr != 0 && a.addr >= addr && a.addr + a.len <= end {
            ended(i);
        }
    }
}

fn realtime_s(t: u64) -> u64 {
    if t == 0 {
        0
    } else {
        ((t.saturating_sub(VCLOCK_BOOT_NS)) + REALTIME_EPOCH_S * 1_000_000_000)
            .saturating_add_signed(crate::state::clock_offset())
            / 1_000_000_000
    }
}

fn shmctl(call: &mut dyn Call) -> i64 {
    let [id, cmd, buf, ..] = args(call);
    let id = id as i32 as u64;
    match cmd & !0x100 {
        IPC_RMID => sup([SHMOP_CTL, id, SHMCTL_RMID, 0, 0, 0]).0,
        IPC_SET => {
            let perm = match get::<[u32; 6]>(buf) {
                Ok(p) => p,
                Err(e) => return e,
            };
            sup([
                SHMOP_CTL,
                id,
                SHMCTL_SET,
                perm[1] as u64,
                perm[2] as u64,
                perm[5] as u64,
            ])
            .0
        }
        IPC_STAT => {
            let (r, w) = sup([SHMOP_CTL, id, SHMCTL_STAT, 0, 0, 0]);
            if r < 0 {
                return r;
            }
            // struct shmid64_ds, as on x86_64 and arm64.
            let mut b = [0u8; 112];
            let mut p32 = |o: usize, v: u64| b[o..o + 4].copy_from_slice(&(v as u32).to_ne_bytes());
            for (k, o) in [0usize, 4, 8, 12, 16, 20].iter().enumerate() {
                p32(*o, w[k]);
            }
            p32(80, w[11]);
            p32(84, w[12]);
            b[24..26].copy_from_slice(&(w[6] as u16).to_ne_bytes());
            for (o, v) in [
                (48, w[7]),
                (56, realtime_s(w[8])),
                (64, realtime_s(w[9])),
                (72, realtime_s(w[10])),
                (88, w[13]),
            ] {
                b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
            }
            crate::guest::write(buf, &b).err().unwrap_or(0)
        }
        SHM_LOCK | SHM_UNLOCK => refuse_request(call, b"shmctl", cmd, false, -e::EPERM),
        c => refuse_request(call, b"shmctl", c, false, -e::EINVAL),
    }
}

pub fn handle(call: &mut dyn Call) -> i64 {
    match call.nr() {
        nr::SHMGET => shmget(call),
        nr::SHMAT => shmat(call),
        nr::SHMDT => shmdt(call.arg(0)),
        _ => shmctl(call),
    }
}
