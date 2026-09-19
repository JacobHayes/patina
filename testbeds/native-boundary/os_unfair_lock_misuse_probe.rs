// Unlocking a never-locked os_unfair_lock is a programmer error the real
// primitive traps on (an unlock by a non-owner). The interposer must abort
// LOUDLY and deterministically rather than silently succeed — these functions
// have no error channel, so a soft failure would be an invisible escape.
#[repr(C)]
struct OsUnfairLock(u32);
unsafe extern "C" {
    fn os_unfair_lock_unlock(lock: *mut OsUnfairLock);
}
fn main() {
    let mut lock = OsUnfairLock(0);
    unsafe {
        os_unfair_lock_unlock(&mut lock);
    }
    println!("OS_UNFAIR_LOCK_MISUSE_SURVIVED");
}
