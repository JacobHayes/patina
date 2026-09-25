// The main thread's default name (`comm`), read through glibc's
// `pthread_getname_np`, and the name a new thread inherits. The name is the
// basename of the supervisor-fixed `argv[0]`, so it must not depend on the
// file the guest binary happens to be stored as.
use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn pthread_self() -> usize;
    fn pthread_getname_np(thread: usize, name: *mut c_char, len: usize) -> c_int;
}

fn name() -> String {
    let mut buffer = [0 as c_char; 16];
    // SAFETY: the calling thread's handle and a 16-byte buffer.
    let error = unsafe { pthread_getname_np(pthread_self(), buffer.as_mut_ptr(), buffer.len()) };
    assert_eq!(error, 0, "pthread_getname_np");
    // SAFETY: glibc NUL-terminates the name within the buffer.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let main = name();
    let worker = std::thread::spawn(name).join().unwrap();
    println!("THREAD_NAME main={main} worker={worker}");
}
