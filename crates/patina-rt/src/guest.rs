//! Guest memory, read and written by the runtime without trusting the pointer.
//!
//! A guest may pass any address to a system call. The kernel answers `EFAULT` for one it
//! cannot use; the runtime must too, never fault itself. Every runtime access to memory a
//! guest named goes through `copy`: `arch::guest_copy`, whose faults `fault::on_fault`
//! recognises by their address and turns into a return of `-EFAULT` (the kernel's own
//! exception-table technique). Ranges that touch the runtime's region are refused before
//! any access (`plausible`): a guest pointer never makes the runtime write its own memory.

use proto::layout::{ALT_SIZE, RT_BASE, RT_REGION_END};

const EFAULT: i64 = 14;

pub use crate::arch::fixup;

/// Past the user address space? On arm64, above 48 bits: there a data access ignores the top
/// byte (a tagged pointer), so a value outside the runtime's region as a number can be inside
/// it as an address; the kernel answers `EFAULT` to such a pointer.
#[cfg(target_arch = "aarch64")]
fn past_user(end: u64) -> bool {
    end > 1 << 48
}
/// On x86_64 the kernel decides (4- or 5-level paging).
#[cfg(target_arch = "x86_64")]
fn past_user(_end: u64) -> bool {
    false
}

/// Is `[p, p + n)` a range a call may use? Not null, no wrap, not `past_user`, and outside
/// the runtime's region, except, for reads, the calling thread's own runtime stack: handlers
/// hand their helpers arrays they built there (a path `resolve::prepare` rewrote, the iovec
/// of a `read`). A pointer the program passes never points there: `names_runtime` refused
/// the call before its handler ran.
fn plausible(p: u64, n: usize, reading: bool) -> bool {
    let Some(end) = p.checked_add(n as u64) else {
        return false;
    };
    if p == 0 || past_user(end) {
        return false;
    }
    if !(p < RT_REGION_END && end > RT_BASE) {
        return true;
    }
    let own = crate::arch::current_sp() & !(ALT_SIZE - 1);
    reading && p >= own && end <= own + ALT_SIZE
}

// ---- system call arguments ----

/// The most bytes one call moves through one buffer (`MAX_RW_COUNT`): the kernel clamps every
/// transfer to it, so a longer length never reaches further.
const MAX_RW: u64 = 0x7fff_f000;
/// The most iovec segments (and `mmsghdr` entries) a call takes (`UIO_MAXIOV`).
const MAX_IOV: u64 = 1024;

/// Does `[p, p + n)` overlap the runtime's region? A null pointer or an empty range touches
/// nothing; lengths are clamped as the kernel clamps them.
pub fn in_region(p: u64, n: u64) -> bool {
    p != 0 && n != 0 && p < RT_REGION_END && p.saturating_add(n.min(MAX_RW)) > RT_BASE
}

/// Does the call name memory in the runtime's region, which the kernel would read or write on
/// the program's behalf? Every buffer the boundary record hashes (`Row::ins`, `Row::outs`)
/// and every other pointer it lists (`Row::refs`) is checked, with the extent the kernel may
/// touch before the call: the one rule for every call the table passes, rewrites or answers.
/// The caller answers `EFAULT`, as the kernel does for a pointer into a hole: the region
/// reads as address space nothing is mapped in. Structures the runtime cannot read here
/// (a pointer into a real hole) are left to the kernel, which answers for them itself.
pub fn names_runtime(row: &proto::table::Row, a: &[u64; 6]) -> bool {
    row.ins
        .iter()
        .chain(row.outs)
        .chain(row.refs)
        .any(|b| reaches(b.len, a[b.arg as usize], a))
}

/// After a park, before the call is attempted again: does the call being served still name
/// only program memory? Another thread may have rewritten an iovec or `msghdr` it points at.
pub fn still_clear() -> bool {
    let ts = crate::state::thread();
    if ts.call_row == 0 {
        return true;
    }
    let row = unsafe { &*(ts.call_row as *const proto::table::Row) };
    !names_runtime(row, &ts.call_args)
}

fn reaches(len: proto::table::Len, p: u64, a: &[u64; 6]) -> bool {
    use proto::table::Len::*;
    match len {
        Ret { max } => in_region(p, a[max as usize]),
        Arg(i) => in_region(p, a[i as usize]),
        Fixed(n) => in_region(p, n as u64),
        RetTimes { max, size } => in_region(p, a[max as usize].saturating_mul(size as u64)),
        ArgTimes { arg, size } => in_region(p, a[arg as usize].saturating_mul(size as u64)),
        CStr => cstr_reaches(p),
        IovRet { cnt } => iov_reaches(p, a[cnt as usize]),
        MsgIovRet => msg_reaches(p),
        Mmsg { cnt } => {
            let n = a[cnt as usize].min(MAX_IOV);
            in_region(p, n * 64) || (0..n).any(|i| msg_reaches(p + i * 64))
        }
        Indirect { lenp } => match get::<u32>(a[lenp as usize]) {
            Ok(n) => in_region(p, (n as i32).max(0) as u64),
            Err(_) => false, // the length's own entry, or the kernel, answers
        },
        FdSet { nfds } => {
            let n = a[nfds as usize] as i32;
            n > 0 && in_region(p, (n as u64).div_ceil(64) * 8)
        }
        SigPair => {
            in_region(p, 16) || get::<[u64; 2]>(p).is_ok_and(|[set, size]| in_region(set, size))
        }
        XattrArgs { size } => {
            in_region(p, a[size as usize])
                || (a[size as usize] >= 16
                    && get::<[u64; 2]>(p).is_ok_and(|[v, n]| in_region(v, n & 0xffff_ffff)))
        }
        Fcntl => match a[1] {
            // F_GETLK, F_SETLK, F_SETLKW and their OFD forms: a `struct flock`.
            5..=7 | 36..=38 => in_region(p, 32),
            // F_GET_RW_HINT, F_SET_RW_HINT, F_GET_FILE_RW_HINT, F_SET_FILE_RW_HINT: a u64.
            1035..=1038 => in_region(p, 8),
            _ => false,
        },
        Ioctl => match a[1] & 0xffff_ffff {
            // FIONBIO, FIONREAD, FS_IOC_GETFLAGS, FIGETBSZ: an int.
            0x5421 | 0x541b | 0x8008_6601 | 2 => in_region(p, 4),
            0x4020_940d => in_region(p, 32), // FICLONERANGE
            0x801c_581f => in_region(p, 28), // FS_IOC_FSGETXATTR
            // FIDEDUPERANGE: a 24-byte header, then `dest_count` 32-byte records.
            0xc018_9436 => {
                in_region(p, 24)
                    || get::<u16>(p + 16).is_ok_and(|n| in_region(p, 24 + n as u64 * 32))
            }
            _ => false, // FICLONE takes a descriptor; FIOCLEX, FIONCLEX nothing
        },
        Prctl => match a[0] {
            15 | 16 => in_region(p, 16), // PR_SET_NAME, PR_GET_NAME
            2 | 25 => in_region(p, 4),   // PR_GET_PDEATHSIG, PR_GET_TSC
            0x5356_4d41 => a[1] == 0 && cstr_reaches(a[4]), // PR_SET_VMA_ANON_NAME's name
            _ => false,
        },
        ArchPrctl => matches!(a[0], 0x1003 | 0x1004) && in_region(p, 8), // ARCH_GET_FS/GS
        // The command without FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME (FUTEX_CMD_MASK).
        Futex => match a[1] & !0x180 {
            // FUTEX_WAIT, FUTEX_WAIT_BITSET: the word and the timeout.
            0 | 9 => in_region(p, 4) || in_region(a[3], 16),
            4 => in_region(p, 4),    // FUTEX_CMP_REQUEUE: the word
            5 => in_region(a[4], 4), // FUTEX_WAKE_OP: the second word
            _ => false,              // a wake reads no word
        },
        StrVec => {
            for i in 0..MAX_STRINGS {
                if in_region(p + 8 * i, 8) {
                    return true;
                }
                match get::<u64>(p + 8 * i) {
                    Ok(0) | Err(_) => return false,
                    Ok(s) if str_reaches(s, MAX_ARG_STRLEN) => return true,
                    Ok(_) => {}
                }
            }
            false
        }
    }
}

/// `execve`'s limits: strings per vector (beyond: E2BIG first) and bytes per string.
const MAX_STRINGS: u64 = 1 << 16;
const MAX_ARG_STRLEN: u64 = 32 * 4096;

/// A path-length string (at most 4096 bytes) that runs into the region before it ends.
fn cstr_reaches(p: u64) -> bool {
    str_reaches(p, 4096)
}

/// A NUL-terminated string that runs into the region before it ends (within `max` bytes,
/// page by page as the kernel reads it).
fn str_reaches(p: u64, max: u64) -> bool {
    if p == 0 {
        return false;
    }
    let mut buf = [0u8; 256];
    let mut n = 0u64;
    while n < max {
        let at = p + n;
        let k = ((4096 - (at & 4095)) as usize).min(buf.len());
        if in_region(at, k as u64) {
            return true;
        }
        if read(at, &mut buf[..k]).is_err() || buf[..k].contains(&0) {
            return false;
        }
        n += k as u64;
    }
    false
}

/// An iovec array (count `cnt`) or one of its segments in the region.
fn iov_reaches(p: u64, cnt: u64) -> bool {
    if cnt > MAX_IOV {
        return false; // EINVAL from the kernel
    }
    if in_region(p, cnt * 16) {
        return true;
    }
    for i in 0..cnt {
        match get::<[u64; 2]>(p + i * 16) {
            Ok([base, len]) if in_region(base, len) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// A `struct msghdr`, its name, iovec array, segments or control buffer in the region.
fn msg_reaches(p: u64) -> bool {
    if in_region(p, 56) {
        return true;
    }
    let Ok([name, namelen, iov, iovlen, control, controllen, _]) = get::<[u64; 7]>(p) else {
        return false;
    };
    in_region(name, namelen & 0xffff_ffff)
        || iov_reaches(iov, iovlen)
        || in_region(control, controllen)
}

/// Copy `n` bytes from `src` to `dst`, one of which is guest memory: 0, or `-EFAULT`.
fn copy(dst: u64, src: u64, n: usize, guest: u64) -> i64 {
    if n == 0 {
        return 0;
    }
    if !plausible(guest, n, guest == src) {
        return -EFAULT;
    }
    unsafe { crate::arch::guest_copy(dst as *mut u8, src as *const u8, n) }
}

/// Read guest bytes at `p` into `buf`.
pub fn read(p: u64, buf: &mut [u8]) -> Result<(), i64> {
    match copy(buf.as_mut_ptr() as u64, p, buf.len(), p) {
        0 => Ok(()),
        r => Err(r),
    }
}

/// Write `buf` to guest memory at `p`.
pub fn write(p: u64, buf: &[u8]) -> Result<(), i64> {
    match copy(p, buf.as_ptr() as u64, buf.len(), p) {
        0 => Ok(()),
        r => Err(r),
    }
}

/// Fill `n` guest bytes at `p` with zeros.
pub fn zero(p: u64, n: usize) -> Result<(), i64> {
    let z = [0u8; 256];
    let mut off = 0;
    while off < n {
        let k = (n - off).min(z.len());
        write(p + off as u64, &z[..k])?;
        off += k;
    }
    Ok(())
}

/// Write a value to guest memory.
pub fn put<T: Copy>(p: u64, v: T) -> Result<(), i64> {
    let b = unsafe {
        core::slice::from_raw_parts(&v as *const T as *const u8, core::mem::size_of::<T>())
    };
    write(p, b)
}

/// Read a value from guest memory.
pub fn get<T: Copy>(p: u64) -> Result<T, i64> {
    let mut v = core::mem::MaybeUninit::<T>::uninit();
    let b = unsafe {
        core::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    read(p, b)?;
    Ok(unsafe { v.assume_init() })
}

/// Feed `n` guest bytes at `p` to `f` in pieces; `Err` at the first piece that cannot be read.
pub fn each(p: u64, n: u64, mut f: impl FnMut(&[u8])) -> Result<(), i64> {
    let mut buf = [0u8; 512];
    let mut off = 0u64;
    while off < n {
        let k = (n - off).min(buf.len() as u64) as usize;
        read(p + off, &mut buf[..k])?;
        f(&buf[..k]);
        off += k as u64;
    }
    Ok(())
}

/// The length of the NUL-terminated guest string at `p`, if it ends within `max` bytes
/// (`Ok(max)` if it does not), reading no further than its page boundaries require.
pub fn strlen(p: u64, max: usize) -> Result<usize, i64> {
    let mut n = 0usize;
    let mut buf = [0u8; 256];
    while n < max {
        let a = p + n as u64;
        let k = ((4096 - (a & 4095)) as usize).min(buf.len()).min(max - n);
        read(a, &mut buf[..k])?;
        if let Some(i) = buf[..k].iter().position(|&c| c == 0) {
            return Ok(n + i);
        }
        n += k;
    }
    Ok(max)
}

/// The guest string at `p` (at most `max` bytes, unterminated past that), checked readable.
pub fn cstr<'a>(p: u64, max: usize) -> Result<&'a [u8], i64> {
    let n = strlen(p, max)?;
    Ok(unsafe { core::slice::from_raw_parts(p as *const u8, n) })
}
