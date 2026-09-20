//! Positive controls for the shim's panic ownership boundary: guest panics stay
//! catchable in main and pthread start; Linux also covers pthread once and a
//! released signal handler.
use std::sync::atomic::{AtomicUsize, Ordering};
static CAUGHT: AtomicUsize = AtomicUsize::new(0);
fn caught() {
    assert!(std::panic::catch_unwind(|| panic!("caught guest panic")).is_err());
    CAUGHT.fetch_add(1, Ordering::SeqCst);
}
#[cfg(target_os = "linux")]
extern "C" fn once_body() { caught(); }
#[cfg(target_os = "linux")]
extern "C" fn handler(_: i32) { caught(); }
unsafe extern "C" {
    #[cfg(target_os = "linux")]
    fn pthread_once(control: *mut i32, init: extern "C" fn()) -> i32;
    #[cfg(target_os = "linux")]
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    #[cfg(target_os = "linux")]
    fn raise(sig: i32) -> i32;
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> i32;
}
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "replace" || mode == "replace-internal" {
        std::panic::set_hook(Box::new(|_| {}));
    }
    if mode == "replace-internal" {
        let mut nanos = 0;
        unsafe { patina_clock_now(1, &mut nanos); }
        panic!("planted internal panic returned");
    }
    caught();
    std::thread::spawn(caught).join().unwrap();
    #[cfg(target_os = "linux")]
    unsafe {
        let mut once = 0;
        assert_eq!(pthread_once(&mut once, once_body), 0);
        assert_ne!(signal(10, handler), usize::MAX);
        assert_eq!(raise(10), 0);
    }
    let expected = if cfg!(target_os = "linux") { 4 } else { 2 };
    assert_eq!(CAUGHT.load(Ordering::SeqCst), expected);
    println!("GUEST_PANICS_CAUGHT={expected}");
}
