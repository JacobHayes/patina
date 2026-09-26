// The main thread leaving through pthread_exit (glibc 2.39): its cleanup
// handler runs, the process lives while another thread runs, and the last
// thread to end calls exit(0), so the atexit handlers run and the status is 0.
//
// Modes (MAIN_EXIT_MODE in the environment):
//   alone     main exits with no other thread;
//   worker    a worker is still sleeping when main exits, and ends the process;
//   detached  a detached worker has ended before main exits;
//   joiner    a worker joins the main thread, and its join answers the value
//             main's pthread_exit gave.
//
// `main` is the C entry point itself (no std runtime frame, whose unwind
// guard would refuse glibc's forced unwind), and holds nothing to drop.
#![no_main]

use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct CleanupBuffer {
    routine: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    canceltype: c_int,
    prev: *mut CleanupBuffer,
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

unsafe extern "C" {
    fn pthread_create(
        thread: *mut usize,
        attr: *const c_void,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_detach(thread: usize) -> c_int;
    fn pthread_join(thread: usize, value: *mut *mut c_void) -> c_int;
    fn pthread_self() -> usize;
    fn _pthread_cleanup_push(
        buffer: *mut CleanupBuffer,
        routine: extern "C" fn(*mut c_void),
        arg: *mut c_void,
    );
    fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int;
    fn atexit(handler: extern "C" fn()) -> c_int;
}

unsafe extern "C-unwind" {
    /// Unwinds: glibc's forced unwind leaves through the caller's frame.
    fn pthread_exit(value: *mut c_void) -> !;
}

fn sleep_ms(ms: i64) {
    let request = Timespec {
        sec: 0,
        nsec: ms * 1_000_000,
    };
    unsafe { nanosleep(&request, std::ptr::null_mut()) };
}

extern "C" fn at_exit() {
    println!("MAIN_EXIT atexit");
}

extern "C" fn cleanup(_: *mut c_void) {
    println!("MAIN_EXIT cleanup");
}

extern "C" fn worker(pause: *mut c_void) -> *mut c_void {
    sleep_ms(pause as i64);
    println!("MAIN_EXIT worker");
    std::ptr::null_mut()
}

extern "C" fn joiner(main: *mut c_void) -> *mut c_void {
    let mut value = std::ptr::null_mut();
    assert_eq!(unsafe { pthread_join(main as usize, &mut value) }, 0);
    println!("MAIN_EXIT joined {}", value as usize);
    std::ptr::null_mut()
}

/// Everything before the exit, in a frame that has returned by then.
fn start_mode() {
    let mode =
        std::env::var_os("MAIN_EXIT_MODE").expect("MAIN_EXIT_MODE=alone|worker|detached|joiner");
    unsafe {
        assert_eq!(atexit(at_exit), 0);
        let mut thread = 0;
        match mode.as_encoded_bytes() {
            b"alone" => {}
            b"worker" => {
                assert_eq!(pthread_create(&mut thread, std::ptr::null(), worker, 20 as *mut c_void), 0);
            }
            b"detached" => {
                assert_eq!(pthread_create(&mut thread, std::ptr::null(), worker, std::ptr::null_mut()), 0);
                assert_eq!(pthread_detach(thread), 0);
                sleep_ms(20);
            }
            b"joiner" => {
                let main = pthread_self() as *mut c_void;
                assert_eq!(pthread_create(&mut thread, std::ptr::null(), joiner, main), 0);
            }
            _ => panic!("unknown mode"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C-unwind" fn main(_: c_int, _: *const *const c_char) -> c_int {
    start_mode();
    let mut buffer = std::mem::MaybeUninit::<CleanupBuffer>::uninit();
    unsafe {
        _pthread_cleanup_push(buffer.as_mut_ptr(), cleanup, std::ptr::null_mut());
        pthread_exit(7 as *mut c_void)
    }
}
