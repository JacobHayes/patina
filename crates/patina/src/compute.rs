//! Compute points (feature `compute`): the hooks of a program rebuilt with LLVM's coverage
//! pass, so Patina can switch threads and charge virtual time inside code that makes no
//! system call. The Rust counterpart of `sdk/c/patina_compute.c`, with the same wire.
//!
//! Build every crate of the program with
//!
//! ```text
//! RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
//!   -Cllvm-args=-sanitizer-coverage-trace-pc -Cllvm-args=-sanitizer-coverage-trace-loads \
//!   -Cllvm-args=-sanitizer-coverage-trace-stores" \
//!   cargo build --release --target x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu
//! ```
//!
//! with `patina-dst = { ..., features = ["compute"] }` among the dependencies. The hooks must
//! be in a crate of their own: LLVM instruments nothing in a crate that defines them. A
//! program that does not use the SDK otherwise links it with `use patina_dst as _;`.
//!
//! Each hook call is an event. Under Patina an event decrements one word of the program's own
//! memory, the cell, which the runtime refills; when it reaches 0 the thread enters the runtime
//! and the seed may switch threads there. Outside Patina the first event's call fails
//! (`ENOSYS`) and every hook is a load and a branch after it. LLVM does not instrument
//! functions whose names start with `__sanitizer_`, so the hooks and the slow path are not
//! instrumented themselves, and what they call is `#[inline(always)]`.
//!
//! The feature is off by default: a fuzzer's runtime defines the same symbols.

const OP_COMPUTE_HELLO: u64 = 8;
const OP_COMPUTE_POINT: u64 = 9;
const VERSION: u64 = 1;
/// Edges and accesses (loads and stores); LLVM's comparison hooks are not defined here.
const KINDS: u64 = 3;

// The hooks and the slow path call no function, not even `AtomicPtr::load` or `is_null`: in
// an unoptimized build those are calls to code of this crate, instrumented when it is built
// with the flags, and a hook that reaches a hook recurses until the stack runs out. Hence
// plain loads and stores of `static mut` through raw pointers. Under Patina one thread runs at
// a time; natively `CELL` changes once, from `&BOOT` to null, an aligned word store, and
// threads that race on `BOOT` before that all end in the slow path, whose answer is the same.

/// The cell before the first event: 0, so that event takes the slow path and says hello.
static mut BOOT: i64 = 0;
/// `&BOOT` until hello, then the runtime's cell, or null outside Patina.
static mut CELL: *mut i64 = &raw mut BOOT;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
fn call(op: u64, arg: u64) -> i64 {
    let r: i64;
    // SAFETY: the SDK's reserved system call; outside Patina the kernel answers ENOSYS (or a
    // sandbox EPERM). It reads and writes no program memory.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") crate::sys::SYSCALL as i64 => r,
            in("rdi") op, in("rsi") arg, in("rdx") 0, lateout("rcx") _, lateout("r11") _,
            options(nostack));
    }
    r
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[inline(always)]
fn call(op: u64, arg: u64) -> i64 {
    let r: i64;
    // SAFETY: as above; the kernel preserves every register but x0.
    unsafe {
        core::arch::asm!("svc #0", in("x8") crate::sys::SYSCALL, inlateout("x0") op as i64 => r,
            in("x1") arg, in("x2") 0, options(nostack));
    }
    r
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[inline(always)]
fn call(_op: u64, _arg: u64) -> i64 {
    -38
}

/// The slow path: the first event says hello, a cell that reached 0 is a compute point. Its
/// name keeps it out of the coverage pass.
#[unsafe(no_mangle)]
#[inline(never)]
#[cold]
extern "C" fn __sanitizer_patina_compute_slow(c: *mut i64) {
    if c == &raw mut BOOT {
        let r = call(OP_COMPUTE_HELLO, VERSION | KINDS << 8);
        // SAFETY: see above; a word store.
        unsafe { CELL = (if r > 0 { r } else { 0 }) as *mut i64 };
        return;
    }
    call(OP_COMPUTE_POINT, 0);
}

#[inline(always)]
fn event() {
    // SAFETY: `CELL` is null, `&BOOT` or the runtime's cell, a page of program memory (see
    // above). The program may store anything into its cell; no value overflows here.
    unsafe {
        let c = CELL;
        if c as usize == 0 {
            return;
        }
        let v = *c;
        if v > 1 {
            *c = v - 1;
        } else {
            *c = 0;
            __sanitizer_patina_compute_slow(c);
        }
    }
}

/// An edge.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_pc() {
    event()
}

macro_rules! access {
    ($($load:ident $store:ident),*) => {$(
        /// A load of the program's.
        #[unsafe(no_mangle)]
        pub extern "C" fn $load(_p: *const u8) {
            event()
        }
        /// A store of the program's.
        #[unsafe(no_mangle)]
        pub extern "C" fn $store(_p: *const u8) {
            event()
        }
    )*};
}
access!(
    __sanitizer_cov_load1 __sanitizer_cov_store1,
    __sanitizer_cov_load2 __sanitizer_cov_store2,
    __sanitizer_cov_load4 __sanitizer_cov_store4,
    __sanitizer_cov_load8 __sanitizer_cov_store8,
    __sanitizer_cov_load16 __sanitizer_cov_store16
);
