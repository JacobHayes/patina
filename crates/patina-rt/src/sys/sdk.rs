//! The SDK channel (`proto::sdk`), answered here under the turn. Decisions are keyed draws of
//! the seed and the label; the site table is shared by every process of the run (it sits in
//! the control region) and read by the launcher after the run. The payload's hash is the trap
//! record's `in_hash`, so replay compares every label, condition and answer.

use super::*;
use crate::state::{config, thread};
use core::sync::atomic::AtomicU64;
use proto::ctl::Op;
use proto::layout::PAGE;
use proto::sdk::*;

const MAX_LEN: usize = HDR_LEN + LABEL_MAX + TEXT_MAX;

/// The payload hash of the last SDK trap, taken by `log::trap`.
static LAST_HASH: AtomicU64 = AtomicU64::new(0);

pub fn take_hash() -> u64 {
    LAST_HASH.swap(0, Relaxed)
}

fn tab() -> &'static mut SdkTab {
    unsafe { SdkTab::at(crate::state::ctl_base()) }
}

/// Copy guest memory with the kernel's checks: a bad pointer is `EFAULT`, never a fault in the
/// runtime.
fn vm(nr: u64, local: *mut u8, remote: u64, len: usize) -> Result<(), i64> {
    // The kernel's checks pass the runtime's own memory; the program's view of it is a hole.
    if crate::guest::in_region(remote, len as u64) {
        return Err(-e::EFAULT);
    }
    let l = [local as u64, len as u64];
    let r = [remote, len as u64];
    let n = unsafe {
        let pid = sc0(proto::nr::GETPID) as u64;
        sc6(nr, pid, l.as_ptr() as u64, 1, r.as_ptr() as u64, 1, 0)
    };
    if n == len as i64 {
        Ok(())
    } else {
        Err(-e::EFAULT)
    }
}

pub fn handle(call: &mut dyn Call) -> Action {
    let (op, ptr, len) = (call.arg(0), call.arg(1), call.arg(2));
    let r = match op {
        OP_HELLO => {
            let b = if tab().cfg.buggify != 0 {
                HELLO_BUGGIFY
            } else {
                0
            };
            (VERSION | b) as i64
        }
        OP_ASSERT..=OP_DECLARE => {
            let mut buf = [0u8; MAX_LEN];
            match payload(ptr, len, &mut buf) {
                Ok(h) => {
                    let n = len as usize;
                    let r = serve(call, op, &h, &mut buf[..n], ptr);
                    LAST_HASH.store(proto::rec::hash_bytes(op, &buf[..n]), Relaxed);
                    r
                }
                Err(e) => e,
            }
        }
        OP_COMPUTE_HELLO => {
            let pc = call.frame().map_or(0, |f| f.pc());
            crate::compute::hello(ptr, pc)
        }
        _ => -e::EINVAL,
    };
    Action::Return(r)
}

fn payload(ptr: u64, len: u64, buf: &mut [u8; MAX_LEN]) -> Result<Hdr, i64> {
    if !(HDR_LEN as u64..=MAX_LEN as u64).contains(&len) {
        return Err(-e::EINVAL);
    }
    if ptr == 0 {
        return Err(-e::EFAULT);
    }
    vm(nr::PROCESS_VM_READV, buf.as_mut_ptr(), ptr, len as usize)?;
    Hdr::parse(&buf[..], len as usize).ok_or(-e::EINVAL)
}

/// Fault points stay quiet before `setup-complete` when the run asks for faults after setup
/// (the mark lowers `fault_after_seq` to its own sequence number), and after a crash with
/// `faults-in-recovery = false`.
fn quiet() -> bool {
    let f = &ctl().faults.cfg;
    thread().seq < f.fault_after_seq || f.faults_off != 0
}

fn serve(call: &mut dyn Call, op: u64, h: &Hdr, buf: &mut [u8], ptr: u64) -> i64 {
    let (label, text) = buf[HDR_LEN..].split_at(h.label_len);
    let t = tab();
    let seed = config().seed;
    let want = match op {
        OP_ASSERT => matches!(
            h.kind,
            KIND_ALWAYS | KIND_SOMETIMES | KIND_REACHABLE | KIND_UNREACHABLE
        ),
        OP_BUGGIFY => h.kind == KIND_BUGGIFY,
        OP_KNOB => h.kind == KIND_KNOB,
        OP_DELAY => h.kind == KIND_DELAY,
        _ => true,
    };
    if !want {
        return -e::EINVAL;
    }
    if op == OP_MARK {
        if label == SETUP_COMPLETE && t.setup_seq == 0 {
            let seq = thread().seq;
            t.setup_seq = seq;
            let f = core::ptr::addr_of!(ctl().faults.cfg.fault_after_seq) as *mut u64;
            unsafe {
                if core::ptr::read_volatile(f) == u64::MAX {
                    core::ptr::write_volatile(f, seq);
                }
            }
        }
        return 0;
    }
    let cfg = t.cfg;
    let Some(s) = t.site(h.kind, label) else {
        // Table full (counted): the call is still answered.
        return match op {
            OP_ASSERT if fails(h) => violation(call, label, text),
            _ => 0,
        };
    };
    match op {
        OP_DECLARE => {
            SdkTab::locate(s, text);
            0
        }
        OP_ASSERT => {
            s.evaluated += 1;
            s.held += (h.kind == KIND_REACHABLE || (h.cond != 0 && !fails(h))) as u64;
            if fails(h) {
                violation(call, label, text)
            }
            0
        }
        OP_BUGGIFY | OP_DELAY => {
            let n = s.evaluated;
            s.evaluated += 1;
            let asked = if op == OP_BUGGIFY { h.a } else { -1 };
            let Some(rate) = cfg.rate(seed, s.label_hash, asked) else {
                return NEVER;
            };
            if quiet() || !cfg.fires(seed, s.label_hash, rate, n) {
                return 0;
            }
            s.held += 1;
            if op == OP_DELAY {
                let d = cfg.delay_ns(seed, s.label_hash, n, h.a.max(0) as u64);
                let now = ctl().vclock_ns.load(Relaxed);
                crate::sup::call_sup(Op::Sleep, [now.saturating_add(d), 0, 0, 0, 0, 0]);
            }
            1
        }
        OP_KNOB => {
            s.evaluated += 1;
            let v = cfg.knob(seed, s.label_hash, h.a, h.b, h.c);
            s.value = v;
            buf[8..16].copy_from_slice(&v.to_le_bytes());
            match vm(nr::PROCESS_VM_WRITEV, buf[8..16].as_mut_ptr(), ptr + 8, 8) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        _ => -e::EINVAL,
    }
}

/// A failed `always`, or an `unreachable` reached.
fn fails(h: &Hdr) -> bool {
    (h.kind == KIND_ALWAYS && h.cond == 0) || h.kind == KIND_UNREACHABLE
}

/// A failed `always`: record it, write the trap's boundary record, and end the run.
fn violation(call: &mut dyn Call, label: &[u8], detail: &[u8]) -> ! {
    let t = tab();
    if t.violation_len == 0 {
        let mut n = 0;
        for part in [label, b": ", detail] {
            let k = part.len().min(t.violation.len() - n);
            t.violation[n..n + k].copy_from_slice(&part[..k]);
            n += k;
        }
        // An empty detail: the message is the label alone.
        if detail.is_empty() {
            n = label.len();
        }
        t.violation_len = n as u64;
        t.violation_label = label.len() as u64;
    }
    let a = call.guest_args();
    LAST_HASH.store(proto::rec::hash_bytes(OP_ASSERT, t.violation()), Relaxed);
    crate::log::trap(&proto::table::SDK_ROW, call, 0);
    crate::sup::call_sup(Op::SdkViolation, [a[0], a[1], a[2], 0, 0, 0]);
    crate::sup::hang()
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Shdr {
    name: u32,
    typ: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

const SHT_NOBITS: u32 = 8;
/// Largest section read: names (`.shstrtab`) and `patina_sites`.
const NAMES_MAX: u64 = 64 << 10;
const SITES_MAX: u64 = 16 << 20;

fn pread(fd: u64, buf: *mut u8, len: u64, off: u64) -> bool {
    unsafe { sc4(proto::nr::PREAD64, fd, buf as u64, len, off) == len as i64 }
}

/// Declare the sites an image's `patina_sites` section lists (see `proto::sdk::records`). Read
/// from the file, so nothing in the guest runs and relocations do not matter. A malformed
/// section declares what it can and nothing else; it is never an error.
pub fn declare_image(fd: u64, shoff: u64, shnum: u16, shentsize: u16, shstrndx: u16) {
    if shoff == 0 || shentsize as usize != core::mem::size_of::<Shdr>() || shstrndx >= shnum {
        return;
    }
    let sh = |i: u16| -> Option<Shdr> {
        let mut s = Shdr::default();
        let n = core::mem::size_of::<Shdr>() as u64;
        pread(fd, &mut s as *mut Shdr as *mut u8, n, shoff + i as u64 * n).then_some(s)
    };
    let Some(names) = sh(shstrndx) else { return };
    if names.size > NAMES_MAX || names.size == 0 {
        return;
    }
    let Some(names_map) = map(fd, names.offset, names.size) else {
        return;
    };
    let mut found = None;
    for i in 0..shnum {
        let Some(s) = sh(i) else { break };
        let at = s.name as usize;
        let nb = names_map.bytes();
        if s.typ != SHT_NOBITS
            && at + SECTION.len() < nb.len()
            && &nb[at..at + SECTION.len()] == SECTION
            && nb[at + SECTION.len()] == 0
        {
            found = Some(s);
            break;
        }
    }
    drop(names_map);
    let Some(s) = found else { return };
    if s.size == 0 || s.size > SITES_MAX {
        return;
    }
    let Some(m) = map(fd, s.offset, s.size) else {
        return;
    };
    let t = tab();
    for (kind, label, loc) in records(m.bytes()) {
        if let Some(site) = t.site(kind, label) {
            SdkTab::locate(site, loc);
        }
    }
}

/// A private read-only mapping of part of a file, in the runtime's private region.
struct Map {
    base: u64,
    len: u64,
    skip: u64,
    size: u64,
}

impl Map {
    fn bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts((self.base + self.skip) as *const u8, self.size as usize)
        }
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe { sc2(proto::nr::MUNMAP, self.base, self.len) };
    }
}

fn map(fd: u64, off: u64, size: u64) -> Option<Map> {
    let skip = off & (PAGE - 1);
    let len = (skip + size + PAGE - 1) & !(PAGE - 1);
    let base = crate::state::priv_alloc(len, PAGE);
    let r = unsafe {
        sc6(
            proto::nr::MMAP,
            base,
            len,
            PROT_READ,
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            fd,
            off - skip,
        )
    };
    (r as u64 == base).then_some(Map {
        base,
        len,
        skip,
        size,
    })
}
