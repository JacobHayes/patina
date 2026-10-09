//! Linux trap arming at startup and the returning halves of the SIGSYS
//! handler. The handler frames themselves stay C (`c/posix/init.c`): guest
//! handlers they run can leave by `siglongjmp` or context restoration, and the
//! fault stop must never enter Rust. This module installs them, owns what they
//! read, and decodes and completes a trapped syscall around the C frame's
//! dispatch call.
//!
//! Syscall-user-dispatch (SUD-DESIGN.md) traps a guest's raw inline `syscall`
//! instruction into the deterministic runtime. The allowed region is glibc's
//! single executable segment, with no selector: every syscall instruction
//! outside glibc text delivers a thread-directed SIGSYS. The shim reaches the
//! kernel only through glibc host aliases, so glibc text is the exact allowed
//! region. The main thread arms here; every managed thread arms itself
//! (`crate::sud::arming`). The timestamp-counter trap (x86-64,
//! `PR_SET_TSC(PR_TSC_SIGSEGV)`) makes `rdtsc`/`rdtscp` raise a synchronous
//! SIGSEGV the C handler answers from the virtual clock (src/tsc.rs). The
//! front handler is the host disposition of every signal a guest handler
//! runs for and of the signals an instruction raises
//! (src/thread/signals/fault.rs).
use core::ffi::{c_char, c_int, c_long, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use super::linux::env_has;
use crate::sud::arming::{self, PR_SET_SYSCALL_USER_DISPATCH, Prctl};

/// The SUD kernel probe: dispatch off, all-zero arguments.
const PR_SYS_DISPATCH_OFF: core::ffi::c_ulong = 0;
/// si_code of a syscall-user-dispatch SIGSYS.
const SYS_USER_DISPATCH: i32 = 2;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

type Sigaction = unsafe extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int;
type Handler = unsafe extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void);

// The C handler frames these install, and what they read here.
unsafe extern "C" {
    fn patina_sud_sigsys(sig: c_int, info: *mut libc::siginfo_t, uc: *mut c_void);
    fn patina_fault_front(sig: c_int, info: *mut libc::siginfo_t, uc: *mut c_void);
    #[cfg(target_arch = "x86_64")]
    fn patina_tsc_sigsegv(sig: c_int, info: *mut libc::siginfo_t, uc: *mut c_void);
    fn patina_signal_frame(mask: *mut u64, stack: *mut c_void);
    fn patina_guest_sigreturn(sp: usize) -> usize;
    fn patina_fault_front_installed(handler: usize);
}

/// The main executable's text span, which every trapped site must lie in.
#[unsafe(no_mangle)]
static patina_sud_text_lo: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static patina_sud_text_hi: AtomicUsize = AtomicUsize::new(0);
/// glibc's sigaction, which the C handlers restore dispositions through.
#[unsafe(no_mangle)]
static patina_host_sigaction: AtomicUsize = AtomicUsize::new(0);
/// glibc's syscall(2): the fault stop's only vehicle, resolved beforehand.
#[unsafe(no_mangle)]
static patina_fault_host_syscall: AtomicUsize = AtomicUsize::new(0);
/// The SIGSEGV disposition the counter trap displaced.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
static mut patina_tsc_prev: libc::sigaction = unsafe { core::mem::zeroed() };

core::arch::global_asm!(
    ".hidden patina_sud_text_lo",
    ".hidden patina_sud_text_hi",
    ".hidden patina_host_sigaction",
    ".hidden patina_fault_host_syscall",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".hidden patina_tsc_prev");

pub(super) fn resolve_prctl() -> Option<Prctl> {
    let address = crate::hostapi::symbol(c"prctl") as usize;
    arming::PRCTL.store(address, Ordering::Relaxed);
    arming::prctl()
}

/// glibc's real sigaction, resolved once (the shim's own `sigaction` is the
/// guest's door).
fn real_sigaction() -> Option<Sigaction> {
    if patina_host_sigaction.load(Ordering::Relaxed) == 0 {
        let address = crate::hostapi::symbol(c"sigaction") as usize;
        patina_host_sigaction.store(address, Ordering::Relaxed);
    }
    let address = patina_host_sigaction.load(Ordering::Relaxed);
    // SAFETY: glibc's sigaction.
    (address != 0).then(|| unsafe { core::mem::transmute::<usize, Sigaction>(address) })
}

/// A host action for one of the C handlers, on the private signal stack.
fn action(handler: Handler, flags: c_int) -> libc::sigaction {
    // SAFETY: all-zero is a valid sigaction; the mask is emptied below.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = handler as usize;
    action.sa_flags = flags | libc::SA_SIGINFO | libc::SA_ONSTACK;
    // SAFETY: the action's own mask.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    action
}

/// The auxv array after the environment's terminator.
unsafe fn auxv(envp: *const *const c_char) -> *mut [usize; 2] {
    let mut walk = envp;
    unsafe {
        while !(*walk).is_null() {
            walk = walk.add(1);
        }
        walk.add(1).cast_mut().cast()
    }
}

/// PATINA_SEED from the still-intact environment, or 0.
unsafe fn env_seed(envp: *const *const c_char) -> u64 {
    let mut entry = envp;
    unsafe {
        while !(*entry).is_null() {
            if let Some(value) = core::ffi::CStr::from_ptr(*entry)
                .to_bytes()
                .strip_prefix(b"PATINA_SEED=")
            {
                return value
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .fold(0u64, |seed, byte| {
                        seed.wrapping_mul(10).wrapping_add(u64::from(byte - b'0'))
                    });
            }
            entry = entry.add(1);
        }
    }
    0
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// AT_RANDOM determinization (SUD-DESIGN.md §9 slice 3). The kernel seeds the
/// auxv AT_RANDOM entry with 16 random bytes that glibc consumes at startup
/// for the stack canary and pointer guard and that a guest can read via
/// getauxval(AT_RANDOM). glibc dereferences the pointer during startup, so it
/// is replaced in place with seed-derived bytes, not ignored. Kernel
/// independent: every managed run, before guest constructors, armed or not.
/// Then the auxv is published (`PATINA_SUD_AUXV_*`) for the PR_GET_AUXV row,
/// independently of SUD: PR_SET_TSC needs the host's page and frame sizes
/// even when the SUD probe fails.
unsafe fn determinize_at_random(envp: *const *const c_char) {
    // Domain-separate the AT_RANDOM stream from every other seeded draw.
    let mut state = unsafe { env_seed(envp) } ^ 0x5241_4E44_4F4D_0001;
    let base = unsafe { auxv(envp) };
    let mut entry = base;
    unsafe {
        while (*entry)[0] != libc::AT_NULL as usize {
            if (*entry)[0] == libc::AT_RANDOM as usize && (*entry)[1] != 0 {
                let bytes = (*entry)[1] as *mut u64;
                bytes.write_unaligned(splitmix64(&mut state));
                bytes.add(1).write_unaligned(splitmix64(&mut state));
            }
            entry = entry.add(1);
        }
        crate::sud::PATINA_SUD_AUXV_BASE.store(base as usize, Ordering::Relaxed);
        crate::sud::PATINA_SUD_AUXV_LEN
            .store(entry.add(1) as usize - base as usize, Ordering::Relaxed);
    }
}

/// Close the vDSO escape (SUD-DESIGN.md §6): AT_SYSINFO_EHDR becomes
/// AT_IGNORE, so getauxval(AT_SYSINFO_EHDR) answers 0, rustix finds no vDSO
/// and falls back to a raw clock_gettime, which SUD traps. glibc consumed the
/// auxv before this scrub (host aliases keep working).
unsafe fn scrub_vdso(envp: *const *const c_char) {
    let mut entry = unsafe { auxv(envp) };
    unsafe {
        while (*entry)[0] != libc::AT_NULL as usize {
            if (*entry)[0] == libc::AT_SYSINFO_EHDR as usize {
                (*entry)[0] = libc::AT_IGNORE as usize;
            }
            entry = entry.add(1);
        }
    }
}

/// Discover glibc's single executable segment (the allowed region) and the
/// main executable's text span, the one holding the SIGSYS handler's own code
/// (`arming::maps_regions`). /proc/self/maps is read through glibc's real open/read/close,
/// never the interposed descriptors, into a 1 MiB libc buffer; a larger map
/// fails closed rather than parse a truncated view. Ok unless exactly one
/// executable libc segment and the text span were found.
unsafe fn discover_regions() -> Result<(), ()> {
    type Open = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
    type Read = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
    type Close = unsafe extern "C" fn(c_int) -> c_int;
    let [open, read, close] = [c"open", c"read", c"close"].map(crate::hostapi::symbol);
    if open.is_null() || read.is_null() || close.is_null() {
        return Err(());
    }
    // SAFETY: glibc's open, read and close.
    let (open, read, close) = unsafe {
        (
            core::mem::transmute::<*mut c_void, Open>(open),
            core::mem::transmute::<*mut c_void, Read>(read),
            core::mem::transmute::<*mut c_void, Close>(close),
        )
    };
    const CAPACITY: usize = 1 << 20;
    let buffer = unsafe { libc::malloc(CAPACITY) }.cast::<u8>();
    if buffer.is_null() {
        return Err(());
    }
    let result = unsafe {
        let fd = open(c"/proc/self/maps".as_ptr(), libc::O_RDONLY);
        let mut total = 0;
        let read_all = fd >= 0
            && loop {
                if total >= CAPACITY {
                    break false;
                }
                match read(fd, buffer.add(total).cast(), CAPACITY - total) {
                    0 => break true,
                    n if n < 0 => break false,
                    n => total += n as usize,
                }
            };
        if fd >= 0 {
            close(fd);
        }
        if read_all {
            regions(core::slice::from_raw_parts(buffer, total))
        } else {
            Err(())
        }
    };
    unsafe { libc::free(buffer.cast()) };
    result
}

fn regions(maps: &[u8]) -> Result<(), ()> {
    let marker = patina_sud_sigsys as *const () as usize;
    let ([lo, hi], [base, end]) = arming::maps_regions(maps, marker).ok_or(())?;
    patina_sud_text_lo.store(lo, Ordering::Relaxed);
    patina_sud_text_hi.store(hi, Ordering::Relaxed);
    arming::LIBC_TEXT[0].store(base, Ordering::Relaxed);
    arming::LIBC_TEXT[1].store(end - base, Ordering::Relaxed);
    Ok(())
}

/// Main-thread SUD setup, before guest constructors. Arms only a managed run
/// on a SUD-capable kernel. The libc frame restorer is captured even for a
/// standalone run: Rust std registers handlers before reporting
/// NotUnderPatina. A standalone run (no PATINA_MODE) stays unarmed: its first
/// interposed boundary already fails closed.
pub(super) unsafe fn sud_init(envp: *const *const c_char, probe: bool) {
    let managed = unsafe { env_has(envp, b"PATINA_MODE") };
    // Kernel independent: before the probe below can return early.
    if managed {
        unsafe { determinize_at_random(envp) };
    }
    let prctl = resolve_prctl();
    let vehicles = [c"open", c"read", c"close"].map(crate::hostapi::symbol);
    let (Some(prctl), Some(sigaction)) = (prctl, real_sigaction()) else {
        return;
    };
    if vehicles.iter().any(|vehicle| vehicle.is_null()) {
        // Defensive: core glibc symbols. Leave unarmed rather than arm with a
        // missing vehicle.
        return;
    }
    // The kernel builds the frame on the thread's private signal stack: a
    // trapped syscall uses none of the guest's (src/thread/signals/frames.rs).
    let mut action = action(patina_sud_sigsys, libc::SA_NODEFER);
    if unsafe { sigaction(libc::SIGSYS, &action, core::ptr::null_mut()) } != 0 {
        crate::trap_fatal("SUD: failed to install the SIGSYS dispatch handler");
    }
    // Learn glibc's kernel-frame return vehicle once, not per guest action.
    if unsafe { sigaction(libc::SIGSYS, core::ptr::null(), &mut action) } != 0 {
        crate::trap_fatal("SUD: failed to query the signal restorer");
    }
    crate::thread::signals::patina_signal_restorer(
        action.sa_restorer.map_or(0, |restorer| restorer as usize),
    );
    if !managed {
        return;
    }
    // ld.so registered the main thread with the host kernel from glibc text
    // before this ran; take those registrations over as the main task's
    // before any guest code runs (kernel independent, like AT_RANDOM).
    crate::thread::registrations::patina_thread_registrations_adopt_main();
    // Kernel support probe: PR_SYS_DISPATCH_OFF with all-zero arguments is 0
    // on a SUD kernel and EINVAL where the feature is absent (arm64 <= 6.18,
    // pre-5.11 x86). Same process, same kernel as the guest.
    if !probe || unsafe { prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0) } != 0 {
        return; // no kernel SUD: do not arm (the pre-run gate handles refusal)
    }
    if unsafe { discover_regions() }.is_err() {
        crate::trap_fatal(
            "SUD: could not determine glibc's single executable segment and the main-executable \
             text from /proc/self/maps; refusing to arm on a guessed region",
        );
    }
    unsafe { scrub_vdso(envp) };
    // Published to the exported flag too: the config path records `sud`.
    arming::SUD.store(true, Ordering::Relaxed);
    crate::PATINA_SUD_ARMED.store(1, Ordering::Relaxed);
    arming::arm_sud();
}

/// Main-thread counter-trap setup, after `sud_init` (which resolves the host
/// vehicles and discovers the text span) and before guest constructors. Arms
/// only a managed run on an x86-64 kernel with PR_SET_TSC; anything else is a
/// deliberate no-op, and the pre-run gate refuses a binary that needs the trap.
pub(super) unsafe fn tsc_init(envp: *const *const c_char) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !env_has(envp, b"PATINA_MODE") {
            return;
        }
        let prctl = arming::prctl().or_else(resolve_prctl);
        let (Some(prctl), Some(sigaction)) = (prctl, real_sigaction()) else {
            return;
        };
        // Kernel support probe: PR_GET_TSC into local storage mutates nothing.
        let mut mode: c_int = 0;
        if prctl(
            libc::PR_GET_TSC,
            &raw mut mode as core::ffi::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            return; // no PR_SET_TSC here: leave unarmed (the gate refuses)
        }
        // The handler needs the text span to bound its decode, also where SUD
        // did not arm. Fail closed rather than arm a handler that cannot
        // validate a faulting RIP: leaving the trap unarmed after the audit
        // cleared the binary as trap-managed would make a contained escape a
        // silent one.
        if patina_sud_text_hi.load(Ordering::Relaxed) == 0 && discover_regions().is_err() {
            crate::trap_fatal(
                "TSC: could not determine the main-executable text span from /proc/self/maps; \
                 refusing to arm the timestamp-counter trap on a guessed region",
            );
        }
        let action = action(patina_tsc_sigsegv, libc::SA_NODEFER);
        if sigaction(libc::SIGSEGV, &action, &raw mut patina_tsc_prev) != 0 {
            crate::trap_fatal("TSC: failed to install the SIGSEGV trap handler");
        }
        if prctl(
            libc::PR_SET_TSC,
            libc::PR_TSC_SIGSEGV as core::ffi::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            crate::trap_fatal(
                "TSC: PR_GET_TSC succeeded but PR_SET_TSC(PR_TSC_SIGSEGV) failed; refusing to \
                 run with the timestamp counter readable",
            );
        }
        // Published to the exported flag too: the config path records `tsc`.
        arming::TSC.store(true, Ordering::Relaxed);
        crate::PATINA_TSC_ARMED.store(1, Ordering::Relaxed);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = envp;
}

/// Install the front handler for a managed run, before guest constructors (so
/// Rust std's own handlers register over it, virtually), after the counter
/// trap took SIGSEGV where it arms, and arm the main thread's private signal
/// stack. The host action carries no guest flags yet: `front_action` adds them.
pub(super) unsafe fn fault_front_init(envp: *const *const c_char) {
    if !unsafe { env_has(envp, b"PATINA_MODE") } {
        return;
    }
    let Some(sigaction) = real_sigaction() else {
        crate::trap_fatal("fault handler: sigaction could not be resolved");
    };
    let syscall = crate::hostapi::symbol(c"syscall") as usize;
    if syscall == 0 {
        crate::trap_fatal("fault handler: host syscall could not be resolved");
    }
    patina_fault_host_syscall.store(syscall, Ordering::Relaxed);
    let action = action(patina_fault_front, 0);
    for sig in [libc::SIGBUS, libc::SIGFPE, libc::SIGILL, libc::SIGTRAP] {
        if unsafe { sigaction(sig, &action, core::ptr::null_mut()) } != 0 {
            crate::trap_fatal("fault handler: failed to install a fault signal's handler");
        }
    }
    if !arming::TSC.load(Ordering::Relaxed)
        && unsafe { sigaction(libc::SIGSEGV, &action, core::ptr::null_mut()) } != 0
    {
        crate::trap_fatal("fault handler: failed to install the SIGSEGV handler");
    }
    unsafe { patina_fault_front_installed(patina_fault_front as *const () as usize) };
}

/// A provenance stop, naming the trapped syscall and its site.
fn sud_fatal(message: &str, nr: c_long, call_addr: usize) -> ! {
    crate::trap_fatal(&format!("{message} (syscall {nr} at {call_addr:#x})"))
}

/// A trapped syscall, decoded for the C handler's dispatch call.
#[repr(C)]
pub struct SudTrap {
    nr: c_long,
    args: [u64; 6],
    call_addr: usize,
    /// The interrupted stack pointer.
    sp: usize,
}

/// Decode a syscall-user-dispatch SIGSYS: synchronous, on the trapping thread,
/// at the guest's own syscall instruction (the kernel rolled it back), so
/// re-entering the runtime is sound (SUD-DESIGN.md §4.2). Provenance first:
/// a seccomp or `kill -SYS` SIGSYS, another architecture's, or a site outside
/// the main executable's text (ld.so, a DSO, the vDSO) is a named stop. A
/// guest restorer's `rt_sigreturn` resumes at the host vehicle with the
/// guest's stack pointer (`patina_guest_sigreturn`): the handler's own return
/// installs the trapped context with those registers changed, and 0 is
/// answered. Otherwise 1, with the number, six argument registers, site and
/// stack pointer in `trap`.
///
/// # Safety
/// The SIGSYS frame's own siginfo and ucontext; `trap` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_decode(
    info: *const libc::siginfo_t,
    uc: *mut libc::ucontext_t,
    trap: *mut SudTrap,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    // `si_call_addr`, `si_syscall` and `si_arch` (offsets 16, 24 and 28).
    let words = unsafe { info.cast::<crate::thread::signals::Info>().read() }.words;
    let code = words[1] as i32;
    let (call_addr, nr, arch) = (
        words[2] as usize,
        words[3] as i32 as c_long,
        (words[3] >> 32) as u32,
    );
    let fatal = |message: &str| sud_fatal(message, nr, call_addr);
    if code != SYS_USER_DISPATCH {
        fatal("SUD: SIGSYS with unexpected si_code (not syscall-user-dispatch)");
    }
    if arch != AUDIT_ARCH {
        fatal("SUD: SIGSYS with unexpected si_arch");
    }
    let text =
        patina_sud_text_lo.load(Ordering::Relaxed)..patina_sud_text_hi.load(Ordering::Relaxed);
    if !text.contains(&call_addr) {
        fatal(
            "SUD: trapped a syscall outside the main executable text (ld.so / DSO / vDSO); this \
             path is not modeled",
        );
    }
    let context = unsafe { &raw mut (*uc).uc_mcontext };
    #[cfg(target_arch = "x86_64")]
    let (registers, sp) = {
        let gregs = unsafe { &raw mut (*context).gregs };
        let reg = |index: c_int| unsafe { (*gregs)[index as usize] as u64 };
        if nr == libc::SYS_rt_sigreturn {
            let vehicle = unsafe { patina_guest_sigreturn(reg(libc::REG_RSP) as usize) };
            unsafe {
                (*gregs)[libc::REG_RIP as usize] = vehicle as i64;
                (*gregs)[libc::REG_RDI as usize] = libc::SYS_rt_sigreturn;
            }
            return 0;
        }
        (
            [
                libc::REG_RDI,
                libc::REG_RSI,
                libc::REG_RDX,
                libc::REG_R10,
                libc::REG_R8,
                libc::REG_R9,
            ]
            .map(reg),
            reg(libc::REG_RSP) as usize,
        )
    };
    #[cfg(target_arch = "aarch64")]
    let (registers, sp) = unsafe {
        if nr == libc::SYS_rt_sigreturn {
            (*context).pc = patina_guest_sigreturn((*context).sp as usize) as u64;
            (*context).regs[0] = libc::SYS_rt_sigreturn as u64;
            return 0;
        }
        let regs = (*context).regs;
        (
            [regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]],
            (*context).sp as usize,
        )
    };
    unsafe {
        trap.write(SudTrap {
            nr,
            args: registers,
            call_addr,
            sp,
        })
    };
    1
}

/// Complete a dispatched trap: the frame's mask and stack fixups, then the raw
/// return value in the syscall's return register.
///
/// # Safety
/// The SIGSYS frame's own ucontext.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_complete(uc: *mut libc::ucontext_t, ret: c_long) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    unsafe {
        patina_signal_frame(
            (&raw mut (*uc).uc_sigmask).cast(),
            (&raw mut (*uc).uc_stack).cast(),
        );
        #[cfg(target_arch = "x86_64")]
        {
            (*uc).uc_mcontext.gregs[libc::REG_RAX as usize] = ret;
        }
        #[cfg(target_arch = "aarch64")]
        {
            (*uc).uc_mcontext.regs[0] = ret as u64;
        }
    }
}

core::arch::global_asm!(".hidden patina_sud_decode", ".hidden patina_sud_complete");

// Call `handler(sig, info, uc)` with the stack pointer at `target` (16-byte
// aligned; the call pushes the return address below it), and return on the
// caller's stack. The frame pointer, which the ABI makes the handler keep,
// holds the way back. As the kernel enters a handler, a variadic callee's
// vector register count (%al) is 0.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".text",
    ".globl patina_call_guest_handler",
    ".hidden patina_call_guest_handler",
    ".type patina_call_guest_handler,@function",
    ".p2align 4",
    "patina_call_guest_handler:",
    "  .cfi_startproc",
    "  endbr64",
    "  pushq %rbp",
    "  .cfi_def_cfa_offset 16",
    "  .cfi_offset %rbp, -16",
    "  movq %rsp, %rbp",
    "  .cfi_def_cfa_register %rbp",
    "  movq %rdi, %r11",
    "  movl %esi, %edi",
    "  movq %rdx, %rsi",
    "  movq %rcx, %rdx",
    "  movq %r8, %rsp",
    "  xorl %eax, %eax",
    "  callq *%r11",
    "  movq %rbp, %rsp",
    "  popq %rbp",
    "  .cfi_def_cfa %rsp, 8",
    "  retq",
    "  .cfi_endproc",
    ".size patina_call_guest_handler, .-patina_call_guest_handler",
    options(att_syntax)
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".globl patina_call_guest_handler",
    ".hidden patina_call_guest_handler",
    ".type patina_call_guest_handler,%function",
    ".p2align 2",
    "patina_call_guest_handler:",
    "  .cfi_startproc",
    "  hint #34", // bti c
    "  stp x29, x30, [sp, #-16]!",
    "  .cfi_def_cfa_offset 16",
    "  .cfi_offset x29, -16",
    "  .cfi_offset x30, -8",
    "  mov x29, sp",
    "  .cfi_def_cfa_register x29",
    "  mov x16, x0",
    "  mov w0, w1",
    "  mov x1, x2",
    "  mov x2, x3",
    "  mov sp, x4",
    "  blr x16",
    "  mov sp, x29",
    "  .cfi_def_cfa sp, 16",
    "  ldp x29, x30, [sp], #16",
    "  .cfi_def_cfa_offset 0",
    "  .cfi_restore x29",
    "  .cfi_restore x30",
    "  ret",
    "  .cfi_endproc",
    ".size patina_call_guest_handler, .-patina_call_guest_handler",
);
