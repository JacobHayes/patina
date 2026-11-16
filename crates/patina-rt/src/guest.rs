//! Guest memory, read and written by the runtime without trusting the pointer.
//!
//! A guest may pass any address to a system call. The kernel answers `EFAULT` for one it
//! cannot use; the runtime must too, never fault itself. Every runtime access to memory a
//! guest named goes through `copy`: one `rep movsb` whose fault `fault::on_fault`
//! recognises by its address and turns into a return of `-EFAULT` (the kernel's own
//! exception-table technique). Ranges that touch the runtime's region are refused before
//! any access (`plausible`): a guest pointer never makes the runtime write its own memory.

use proto::layout::{ALT_SIZE, RT_BASE, RT_REGION_END};

const EFAULT: i64 = 14;

core::arch::global_asm!(
    ".pushsection .text.patina_guest_copy,\"ax\",@progbits",
    ".globl patina_guest_copy",
    "patina_guest_copy:",
    "mov rcx, rdx",
    ".globl patina_guest_copy_insn",
    "patina_guest_copy_insn:",
    "rep movsb",
    "xor eax, eax",
    "ret",
    ".globl patina_guest_copy_fixup",
    "patina_guest_copy_fixup:",
    "mov rax, -14",
    "ret",
    ".popsection",
);

extern "C" {
    fn patina_guest_copy(dst: *mut u8, src: *const u8, n: usize) -> i64;
    fn patina_guest_copy_insn();
    fn patina_guest_copy_fixup();
}

/// Called by the fault handler for a fault at `rip` in runtime text: where to resume, if the
/// fault was a guest copy's.
pub fn fixup(rip: u64) -> Option<u64> {
    let insn = patina_guest_copy_insn as *const () as u64;
    (rip == insn).then_some(patina_guest_copy_fixup as *const () as u64)
}

/// Is `[p, p + n)` a range a call may use? Not null, no wrap, and outside the runtime's
/// region, except, for reads, the calling thread's own runtime stack: `resolve::prepare`
/// hands a handler path arguments it rewrote into buffers there.
fn plausible(p: u64, n: usize, reading: bool) -> bool {
    let Some(end) = p.checked_add(n as u64) else {
        return false;
    };
    if p == 0 {
        return false;
    }
    if !(p < RT_REGION_END && end > RT_BASE) {
        return true;
    }
    let sp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack)) };
    let own = sp & !(ALT_SIZE - 1);
    reading && p >= own && end <= own + ALT_SIZE
}

/// Copy `n` bytes from `src` to `dst`, one of which is guest memory: 0, or `-EFAULT`.
fn copy(dst: u64, src: u64, n: usize, guest: u64) -> i64 {
    if n == 0 {
        return 0;
    }
    if !plausible(guest, n, guest == src) {
        return -EFAULT;
    }
    unsafe { patina_guest_copy(dst as *mut u8, src as *const u8, n) }
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
