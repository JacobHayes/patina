//! Mach task CPU-time fields; other accounting remains zero as before.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use core::mem::{offset_of, size_of};
#[repr(C)]
struct Basic32 {
    suspend_count: i32,
    virtual_size: u32,
    resident_size: u32,
    user_time: libc::time_value_t,
    system_time: libc::time_value_t,
    policy: i32,
}
#[repr(C, packed(4))]
struct Basic64 {
    suspend_count: i32,
    virtual_size: u64,
    resident_size: u64,
    user_time: libc::time_value_t,
    system_time: libc::time_value_t,
    policy: i32,
}
const _: () = {
    assert!(size_of::<Basic32>() == 32 && align_of::<Basic32>() == 4);
    assert!(offset_of!(Basic32, user_time) == 12);
    assert!(size_of::<Basic64>() == 40 && align_of::<Basic64>() == 4);
    assert!(offset_of!(Basic64, user_time) == 20);
};
#[cfg(target_arch = "aarch64")]
const BASIC64: u32 = 18;
#[cfg(not(target_arch = "aarch64"))]
const BASIC64: u32 = 5;
/// # Safety
/// Output and count obey the task_info flavor's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn task_info(
    _task: u32,
    flavor: u32,
    output: *mut i32,
    count: *mut u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if output.is_null() || count.is_null() {
        return libc::KERN_SUCCESS;
    }
    // SAFETY: caller contract supplies the count word and an output buffer of that many words;
    // flavor-specific checks below ensure the CPU-time field is in bounds.
    unsafe {
        let count = count.read() as usize;
        ptr::write_bytes(output, 0, count);
        let time = crate::time_abi::cpu_time();
        let user_time = match flavor {
            libc::MACH_TASK_BASIC_INFO if count >= libc::MACH_TASK_BASIC_INFO_COUNT as usize => {
                &raw mut (*output.cast::<libc::mach_task_basic_info>()).user_time
            }
            BASIC64 if count >= size_of::<Basic64>() / 4 => {
                &raw mut (*output.cast::<Basic64>()).user_time
            }
            4 if count >= size_of::<Basic32>() / 4 => {
                &raw mut (*output.cast::<Basic32>()).user_time
            }
            libc::TASK_THREAD_TIMES_INFO
                if count >= libc::TASK_THREAD_TIMES_INFO_COUNT as usize =>
            {
                &raw mut (*output.cast::<libc::task_thread_times_info>()).user_time
            }
            _ => return libc::KERN_SUCCESS,
        };
        let value = |nanos: u64| libc::time_value_t {
            seconds: (nanos / 1_000_000_000) as i32,
            microseconds: ((nanos % 1_000_000_000) / 1000) as i32,
        };
        user_time.write_unaligned(value(time.user_ns));
        // Every flavor above stores `system_time` right after `user_time`.
        user_time.add(1).write_unaligned(value(time.system_ns));
    }
    libc::KERN_SUCCESS
}
