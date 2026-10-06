//! prctl operands follow the option, including required reserved zero words.
use core::ffi::{c_int, c_ulong, c_void};
use libc as k;
const PR_GET_AUXV: c_int = 0x4155_5856;
core::arch::global_asm!(
    ".globl patina_route_prctl",
    ".hidden patina_route_prctl",
    ".set patina_route_prctl, prctl",
);

/// # Safety
/// Options supply their documented pointer/unsigned-long operands and reserved words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prctl(option: c_int, mut args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mutated = super::fault(6);
    let mut words = [0u64; 4];
    // SAFETY: every branch consumes only its option's required arguments.
    unsafe {
        match option {
            k::PR_SET_NAME | k::PR_GET_NAME | k::PR_GET_PDEATHSIG => {
                words[0] = args.next_arg::<*mut c_void>() as u64;
            }
            k::PR_SET_PDEATHSIG | k::PR_SET_DUMPABLE | k::PR_SET_TIMERSLACK => {
                words[0] = args.next_arg::<c_ulong>();
                if mutated {
                    words[0] = args.next_arg::<c_ulong>();
                }
            }
            k::PR_SET_SECCOMP => {
                words[0] = args.next_arg::<c_ulong>();
                if words[0] == 2 {
                    words[1] = args.next_arg::<*mut c_void>() as u64;
                }
            }
            PR_GET_AUXV => {
                words[0] = args.next_arg::<*mut c_void>() as u64;
                for word in &mut words[1..] {
                    *word = args.next_arg::<c_ulong>();
                }
            }
            k::PR_SET_NO_NEW_PRIVS
            | k::PR_GET_NO_NEW_PRIVS
            | k::PR_SET_THP_DISABLE
            | k::PR_GET_THP_DISABLE => {
                for word in &mut words {
                    *word = args.next_arg::<c_ulong>();
                }
            }
            _ => {} // Queries and named refusals have no modeled consuming path.
        }
    }
    // SAFETY: decoded words retain the shared syscall model's contracts.
    let result = unsafe {
        crate::sud::patina_sud_dispatch(
            crate::registry::Syscall::N_prctl.number() as _,
            option as u64,
            words[0],
            words[1],
            words[2],
            words[3],
            0,
            0,
        )
    };
    super::deliver_signals();
    if result < 0 {
        super::error(result.wrapping_neg() as c_int)
    } else {
        result as c_int
    }
}
