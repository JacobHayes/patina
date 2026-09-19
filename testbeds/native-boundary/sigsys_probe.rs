// Class pairing: reserved_signals_are_stripped_from_every_host_mask.
extern "C" fn ignore(_: i32) {}
fn main() {
    unsafe extern "C" {
        fn signal(sig: i32, handler: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }
    unsafe {
        signal(31, ignore as *mut core::ffi::c_void);
    }
    panic!("reserved signal registration unexpectedly returned");
}
