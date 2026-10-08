//! glibc ptrace decoding without reading ignored operands.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_int, c_long, c_void};
use linux_raw_sys::ptrace as k;

/// # Safety
/// Each request supplies the arguments it consumes; pointers obey ptrace's ABI.
#[unsafe(no_mangle)]
unsafe extern "C" fn ptrace(request: c_int, mut args: ...) -> c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mutated = super::fault(5);
    let mut pid = 0;
    let mut address = core::ptr::null_mut();
    let mut data = core::ptr::null_mut();
    let peek = matches!(
        request as u32,
        k::PTRACE_PEEKTEXT | k::PTRACE_PEEKDATA | k::PTRACE_PEEKUSR
    );
    // SAFETY: TRACEME consumes nothing. Other modeled paths need a promoted
    // pid; SEIZE also validates address/options, and PEEK consumes an address.
    unsafe {
        if request as u32 != k::PTRACE_TRACEME {
            pid = args.next_arg::<c_int>();
        }
        if mutated {
            pid = args.next_arg::<c_int>();
        }
        if peek || request as u32 == k::PTRACE_SEIZE {
            address = args.next_arg::<*mut c_void>();
        }
        if request as u32 == k::PTRACE_SEIZE {
            data = args.next_arg::<*mut c_void>();
        }
    }
    let mut word: c_long = 0;
    if peek {
        data = (&mut word as *mut c_long).cast();
    }
    // SAFETY: arguments preserve the model's pointer and signed-pid contracts.
    let result = unsafe {
        crate::sud::patina_sud_dispatch(
            crate::registry::Syscall::N_ptrace.number() as c_long,
            request as i64 as u64,
            pid as i64 as u64,
            address as u64,
            data as u64,
            0,
            0,
            0,
        )
    };
    super::deliver_signals();
    let result = super::raw_result(result);
    if result >= 0 && peek {
        super::errno(0);
        word
    } else {
        result
    }
}
