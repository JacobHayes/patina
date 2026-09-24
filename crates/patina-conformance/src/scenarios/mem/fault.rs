//! Observing a memory fault without dying of it: a `SA_SIGINFO` SIGSEGV
//! handler records the fault's `si_code` and `si_addr`, then repairs the one
//! page the scenario armed it for, so the faulting access retries and
//! completes. A fault on any other page (or a second one before re-arming)
//! restores the default action first, so it kills the process instead of
//! looping.

use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

static FAULTS: AtomicUsize = AtomicUsize::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static PAGE: AtomicUsize = AtomicUsize::new(0);
static REPAIR: AtomicI32 = AtomicI32::new(0);

/// How the handler makes the armed page accessible again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repair {
    /// `mprotect` it read-write.
    Protect = 1,
    /// Map a fresh zero page over it (`MAP_FIXED`).
    Map = 2,
    /// Assign it protection key 0 read-write (`pkey_mprotect`).
    DefaultKey = 3,
}

/// A fault the handler observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub count: usize,
    pub code: i32,
    pub address: usize,
}

fn page_size() -> usize {
    crate::probe::page_size()
}

unsafe extern "C" fn on_segv(_: c_int, info: *mut siginfo_t, _: *mut c_void) {
    // SAFETY: the kernel hands a SA_SIGINFO handler its siginfo.
    let (code, address) = unsafe { ((*info).si_code, (*info).si_addr() as usize) };
    CODE.store(code, Ordering::SeqCst);
    ADDRESS.store(address, Ordering::SeqCst);
    let page = PAGE.swap(0, Ordering::SeqCst);
    let repaired = page != 0 && address >= page && address < page + page_size() && {
        let base = page as *mut c_void;
        // SAFETY: async-signal-safe system calls on the page the scenario
        // armed, which it owns.
        match REPAIR.load(Ordering::SeqCst) {
            1 => unsafe { mprotect(base, page_size(), PROT_READ | PROT_WRITE) == 0 },
            2 => unsafe {
                mmap(
                    base,
                    page_size(),
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0,
                ) == base
            },
            3 => unsafe {
                syscall(
                    Syscall::N_pkey_mprotect.number() as c_long,
                    base,
                    page_size(),
                    PROT_READ | PROT_WRITE,
                    0,
                ) == 0
            },
            _ => false,
        }
    };
    if !repaired {
        // SAFETY: restoring the default action is async-signal-safe; the
        // retried access then kills the process with the fault.
        unsafe { signal(SIGSEGV, SIG_DFL) };
    }
    FAULTS.fetch_add(1, Ordering::SeqCst);
}

/// The handler's installation; dropping it restores the previous action.
pub struct Installed {
    previous: sigaction,
}

impl Drop for Installed {
    fn drop(&mut self) {
        // SAFETY: restoring the action saved at installation.
        unsafe { sigaction(SIGSEGV, &self.previous, std::ptr::null_mut()) };
    }
}

/// Install the handler (unobserved setup).
pub fn install() -> Installed {
    FAULTS.store(0, Ordering::SeqCst);
    // SAFETY: plain sigaction registration of a handler defined above.
    unsafe {
        let mut action: sigaction = std::mem::zeroed();
        action.sa_sigaction = on_segv as *const () as sighandler_t;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&mut action.sa_mask);
        let mut previous: sigaction = std::mem::zeroed();
        assert_eq!(
            sigaction(SIGSEGV, &action, &mut previous),
            0,
            "install the SIGSEGV handler"
        );
        Installed { previous }
    }
}

/// Arm the handler to repair the page at `page` once.
pub fn arm(page: usize, repair: Repair) {
    REPAIR.store(repair as i32, Ordering::SeqCst);
    PAGE.store(page, Ordering::SeqCst);
}

/// What the handler has observed so far.
pub fn observed() -> Fault {
    Fault {
        count: FAULTS.load(Ordering::SeqCst),
        code: CODE.load(Ordering::SeqCst),
        address: ADDRESS.load(Ordering::SeqCst),
    }
}
