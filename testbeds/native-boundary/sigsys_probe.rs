// Class pairing: reserved_signals_are_stripped_from_every_host_mask.
extern "C" fn ignore(_: i32) {}
fn main() {
    unsafe extern "C" {
        fn signal(sig: i32, handler: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }
    unsafe {
        let handler = ignore as *mut core::ffi::c_void;
        assert_eq!(signal(31, handler), core::ptr::null_mut());
        assert_eq!(signal(31, core::ptr::null_mut()), handler);
        assert_eq!(signal(31, 1usize as *mut core::ffi::c_void), core::ptr::null_mut());
        assert_eq!(signal(31, handler), 1usize as *mut core::ffi::c_void);
    }
    println!("SIGSYS guest action roundtrip");
}
