#![allow(dead_code, function_casts_as_integer)]

use libc::*;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

pub static COUNT: AtomicUsize = AtomicUsize::new(0);
pub static LAST_SIG: AtomicI32 = AtomicI32::new(0);
pub static LAST_CODE: AtomicI32 = AtomicI32::new(0);
pub static LAST_PID: AtomicI32 = AtomicI32::new(0);
pub static LAST_UID: AtomicI32 = AtomicI32::new(0);

pub extern "C" fn handler(sig: c_int) {
    COUNT.fetch_add(1, Ordering::SeqCst);
    LAST_SIG.store(sig, Ordering::SeqCst);
}

pub extern "C" fn info_handler(sig: c_int, info: *mut siginfo_t, _: *mut c_void) {
    COUNT.fetch_add(1, Ordering::SeqCst);
    LAST_SIG.store(sig, Ordering::SeqCst);
    if !info.is_null() {
        unsafe {
            LAST_CODE.store((*info).si_code, Ordering::SeqCst);
            LAST_PID.store((*info).si_pid(), Ordering::SeqCst);
            LAST_UID.store((*info).si_uid() as i32, Ordering::SeqCst);
        }
    }
}

pub fn empty_set() -> sigset_t {
    unsafe {
        let mut set: sigset_t = std::mem::zeroed();
        sigemptyset(&mut set);
        set
    }
}

pub fn one_set(sig: c_int) -> sigset_t {
    unsafe {
        let mut set = empty_set();
        sigaddset(&mut set, sig);
        set
    }
}

pub fn has(set: &sigset_t, sig: c_int) -> bool {
    unsafe { sigismember(set as *const sigset_t as *mut sigset_t, sig) == 1 }
}

pub fn install(sig: c_int, flags: c_int, info: bool) {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = flags;
        sa.sa_sigaction = if info { info_handler as usize } else { handler as usize };
        assert_eq!(sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

pub fn reset() {
    COUNT.store(0, Ordering::SeqCst);
    LAST_SIG.store(0, Ordering::SeqCst);
    LAST_CODE.store(0, Ordering::SeqCst);
    LAST_PID.store(0, Ordering::SeqCst);
    LAST_UID.store(0, Ordering::SeqCst);
}

pub fn gettid() -> pid_t {
    unsafe { syscall(SYS_gettid) as pid_t }
}

pub fn short_pause() {
    std::thread::sleep(std::time::Duration::from_millis(40));
}
