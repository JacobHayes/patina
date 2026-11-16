//! Runtime state. The runtime has no thread-local storage: per-thread state
//! sits at the base of the thread's alternate stack (found by masking the stack
//! pointer); per-process state is a static, which is safe because only the
//! thread holding the turn runs runtime code.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use proto::ctl::Ctl;
use proto::layout::*;

/// Where this image maps the control region and the boundary log read-write (`map_shared`).
/// Per-process statics: written once at image start, before anything else uses them.
static CTL_RW: AtomicU64 = AtomicU64::new(0);
static LOG_RW: AtomicU64 = AtomicU64::new(0);

/// The control region, through the runtime's read-write mapping.
#[inline]
pub fn ctl_base() -> *mut u8 {
    CTL_RW.load(Relaxed) as *mut u8
}

pub fn ctl() -> &'static Ctl {
    unsafe { Ctl::at(ctl_base()) }
}

/// Is the control region mapped yet (false only early in an image's start)?
pub fn ctl_mapped() -> bool {
    CTL_RW.load(Relaxed) != 0
}

/// The boundary log's read-write mapping (its first byte; `log::ensure` extends it).
#[inline]
pub fn log_base() -> u64 {
    LOG_RW.load(Relaxed)
}

/// Map the control region at a drawn address and reserve the published addresses of the
/// control region and the boundary log inaccessible (`proto::layout`). A program's access to
/// a published address faults (`fault::on_fault` names it); the drawn ones are written only
/// here and appear nowhere a program can read (`/proc/self/maps` hides the runtime's region).
pub fn map_shared() {
    use crate::raw::*;
    let mut r = [0u8; 8];
    // The draw comes from the host, not the seed: it decides no value the program can see.
    let n = unsafe { sc3(nr::GETRANDOM, r.as_mut_ptr() as u64, 8, 0) };
    if n != 8 {
        crate::fatal(proto::ctl::Setup::CtlMap, n.min(0));
    }
    let v = u64::from_le_bytes(r);
    let pages = RW_SPAN / PAGE;
    let ctl_rw = CTL_RW_LO + (v % pages) * PAGE;
    let log_rw = LOG_RW_LO + ((v >> 32) % pages) * PAGE;
    let size = proto::ctl::CTL_SIZE as u64;
    let maps = [
        (
            ctl_rw,
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            FD_CTL as u64,
        ),
        (
            CTL_ADDR,
            size,
            0,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            u64::MAX,
        ),
        (
            LOG_ADDR,
            LOG_GUARD,
            0,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            u64::MAX,
        ),
    ];
    for (a, len, prot, flags, fd) in maps {
        let m = unsafe { sc6(nr::MMAP, a, len, prot, flags | MAP_FIXED_NOREPLACE, fd, 0) };
        if m as u64 != a {
            crate::fatal(proto::ctl::Setup::CtlMap, m);
        }
    }
    CTL_RW.store(ctl_rw, Relaxed);
    LOG_RW.store(log_rw, Relaxed);
}

pub fn config() -> &'static proto::Config {
    &ctl().config
}

pub const TS_MAGIC: u64 = 0x7473_5f74_725f_6b70;

/// Runtime per-thread state, at the base of the alternate stack.
#[repr(C)]
pub struct ThreadState {
    pub magic: u64,
    pub slot: u32,
    pub tid: i32,
    pub pid: i32,
    /// Traps taken by this thread (CPU-time clocks are traps x charge).
    pub traps: u64,
    /// `seq` of the trap being handled.
    pub seq: u64,
    /// Class code actually applied to the current trap (a handler may change it).
    pub eff_class: u8,
    /// The guest's virtual signal mask.
    pub vmask: u64,
    /// The guest's virtual alternate stack: sp, flags, size.
    pub valt: [u64; 3],
    /// `set_tid_address` pointer and `set_robust_list` head/len.
    pub clear_tid: u64,
    pub robust: [u64; 2],
    /// Runtime-owned tid word: the kernel's clear-child-tid points here, so the kernel stores 0
    /// (and wakes it) when the task is really gone. Nonzero while the task may still run.
    pub ktid: u32,
    pub _pad: u32,
    /// Guest `CLONE_CHILD_SETTID` address, written by the child when it first holds the turn.
    pub child_settid: u64,
    /// Mask to restore after a temporary one (`sigsuspend`); valid when `has_saved` is 1.
    pub saved_mask: u64,
    pub has_saved: u64,
    /// The kernel's restart block: what `restart_syscall` continues after a signal
    /// that ran no handler. [kind, a, b, c, d]; kind 0 = none (`sys::sig::RB_*`).
    pub restart: [u64; 5],
    /// 1 in a vfork child: it shares the parent's memory, so it must not write the
    /// runtime's per-process tables (dispositions, descriptor marks); see `sigact()`.
    pub vfork: u64,
    /// A vfork child's own dispositions (copied from the parent at the clone).
    pub vf_sigact: [[u64; 4]; 65],
    /// Counter preemption (`pmu.rs`).
    pub pmu: crate::pmu::Pmu,
    /// Spin probes and the spin point (`spin.rs`).
    pub spin: crate::spin::Spin,
}

impl ThreadState {
    /// A fresh thread state (signals fields zero).
    pub const fn new(slot: u32, tid: i32, pid: i32, vmask: u64) -> ThreadState {
        ThreadState {
            magic: TS_MAGIC,
            slot,
            tid,
            pid,
            traps: 0,
            seq: 0,
            eff_class: 0,
            vmask,
            valt: [0, 2, 0], // SS_DISABLE
            clear_tid: 0,
            robust: [0, 0],
            ktid: 1,
            _pad: 0,
            child_settid: 0,
            saved_mask: 0,
            has_saved: 0,
            restart: [0; 5],
            vfork: 0,
            vf_sigact: [[0; 4]; 65],
            pmu: crate::pmu::Pmu::new(),
            spin: crate::spin::Spin::new(),
        }
    }
}

/// Is the calling thread a vfork child (sharing its parent's runtime memory)?
pub fn in_vfork_child() -> bool {
    thread().vfork != 0
}

/// The calling process's virtual dispositions: the runtime's per-process table, or a vfork
/// child's private copy (glibc's posix_spawn child resets handlers in shared memory).
#[allow(clippy::mut_from_ref)]
pub fn sigact() -> &'static mut [[u64; 4]; 65] {
    let ts = thread();
    if ts.vfork != 0 {
        &mut ts.vf_sigact
    } else {
        &mut proc().sigact
    }
}

/// A `MAP_SHARED` mapping: futex words in it are keyed by (id, offset), not address.
#[derive(Clone, Copy)]
pub struct Shared {
    pub addr: u64,
    pub len: u64,
    /// Mapping id (31 bits) and the file offset of `addr`.
    pub id: u64,
    pub off: u64,
}
pub const MAX_SHARED: usize = 256;

/// The calling thread's state (valid on the alternate stack only).
#[inline(always)]
pub fn thread() -> &'static mut ThreadState {
    let sp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    let base = sp & !(ALT_SIZE - 1);
    unsafe { &mut *(base as *mut ThreadState) }
}

pub const MAX_MOUNTS: usize = 64;
pub const URANDOM_WORDS: usize = (FD_HIDDEN_MIN as usize).div_ceil(64);

/// Runtime per-process (per image) state.
pub struct Proc {
    pub guest_path: [u8; 4096],
    pub guest_path_len: usize,
    pub brk_cur: u64,
    pub mmap_cursor: u64,
    pub priv_cursor: u64,
    pub log_mapped: u64,
    /// Virtual dispositions: handler, flags, restorer, mask (kernel `struct sigaction` layout).
    pub sigact: [[u64; 4]; 65],
    /// Descriptors open on /dev/urandom or /dev/random: reads are entropy draws.
    pub urandom: [u64; URANDOM_WORDS],
    /// Mounts in mountinfo order: (mount id, st_dev encoding).
    pub mounts: [(u64, u64); MAX_MOUNTS],
    pub nmounts: usize,
    /// Futex address-space id: the slot of the process's first thread.
    pub asid: u64,
    /// Alternate stack of each slot owned by this process (0: none), for reclamation.
    pub alt_of_slot: [u64; proto::ctl::MAX_THREADS],
    /// Reclaimed alternate stacks, reused before new ones are mapped.
    pub alt_free: [u64; proto::ctl::MAX_THREADS],
    pub nalt_free: usize,
    /// Standard-format XSAVE component offsets and sizes (CPUID 0xD), filled on use.
    pub xsave_off: [u32; 64],
    pub xsave_len: [u32; 64],
    /// The slot a `fork` child takes (written by the parent just before the real fork,
    /// read by the child in its copy).
    pub fork_slot: u64,
    /// `MAP_SHARED` mappings of this image (futex keys across processes).
    pub shared: [Shared; MAX_SHARED],
    pub nshared: usize,
}

pub struct Global<T>(UnsafeCell<T>);
unsafe impl<T> Sync for Global<T> {}

static PROC: Global<Proc> = Global(UnsafeCell::new(Proc {
    guest_path: [0; 4096],
    guest_path_len: 0,
    brk_cur: BRK_BASE,
    mmap_cursor: MMAP_TOP,
    priv_cursor: RT_PRIV,
    log_mapped: 0,
    sigact: [[0; 4]; 65],
    urandom: [0; URANDOM_WORDS],
    mounts: [(0, 0); MAX_MOUNTS],
    nmounts: 0,
    asid: 0,
    alt_of_slot: [0; proto::ctl::MAX_THREADS],
    alt_free: [0; proto::ctl::MAX_THREADS],
    nalt_free: 0,
    xsave_off: [0; 64],
    xsave_len: [0; 64],
    fork_slot: 0,
    shared: [Shared {
        addr: 0,
        len: 0,
        id: 0,
        off: 0,
    }; MAX_SHARED],
    nshared: 0,
}));

#[allow(clippy::mut_from_ref)]
pub fn proc() -> &'static mut Proc {
    unsafe { &mut *PROC.0.get() }
}

impl Proc {
    pub fn guest_path(&self) -> &[u8] {
        &self.guest_path[..self.guest_path_len]
    }
    pub fn is_urandom(&self, fd: i64) -> bool {
        (0..FD_HIDDEN_MIN as i64).contains(&fd)
            && self.urandom[fd as usize / 64] & (1 << (fd % 64)) != 0
    }
    pub fn set_urandom(&mut self, fd: i64, on: bool) {
        // A vfork child shares this table with its parent: its descriptor changes are its own.
        if in_vfork_child() {
            return;
        }
        if (0..FD_HIDDEN_MIN as i64).contains(&fd) {
            let (w, b) = (fd as usize / 64, 1u64 << (fd % 64));
            if on {
                self.urandom[w] |= b
            } else {
                self.urandom[w] &= !b
            }
        }
    }
}

/// Bump allocation in the runtime's private region.
pub fn priv_alloc(size: u64, align: u64) -> u64 {
    let p = proc();
    let a = (p.priv_cursor + align - 1) & !(align - 1);
    p.priv_cursor = a + size;
    a
}

/// Allocate and map an alternate stack, initialise its thread state.
pub fn new_alt_stack() -> u64 {
    use crate::raw::*;
    let a = priv_alloc(ALT_SIZE, ALT_SIZE);
    let r = unsafe {
        sc6(
            nr::MMAP,
            a,
            ALT_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            u64::MAX,
            0,
        )
    };
    if r as u64 != a {
        crate::fatal(proto::ctl::Setup::AltStack, r);
    }
    a
}
