// Linux's entropy entry points in boot order, under the entropy fault. A
// `GRND_NONBLOCK` read before the pool is known ready is the only one a real
// pool can fail, with `EAGAIN`, and the kernel decides that before it looks at
// the buffer or the length. An empty `getentropy` never reaches the kernel, so
// it shows nothing about the pool. `GRND_INSECURE`, `/dev/urandom`,
// `getentropy` and a thread's first `HashMap` never fail. Once a waiting read
// returns, the pool is ready, so a later `GRND_NONBLOCK` read succeeds too.
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Read;

const GRND_NONBLOCK: u32 = 1;
const GRND_INSECURE: u32 = 4;

unsafe extern "C" {
    fn getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize;
    fn getentropy(buffer: *mut c_void, length: usize) -> i32;
}

/// A call's result, or its errno when it failed.
fn answer(result: isize) -> String {
    if result < 0 {
        format!("errno{}", std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result.to_string()
    }
}

fn main() {
    let mut buffer = [0u8; 16];
    let pointer = buffer.as_mut_ptr().cast::<c_void>();
    // SAFETY: `buffer` is writable for its length on every call below.
    let empty_getentropy = answer(unsafe { getentropy(pointer, 0) } as isize);
    let nonblocking_first = answer(unsafe { getrandom(pointer, buffer.len(), GRND_NONBLOCK) });
    let null = std::ptr::null_mut();
    let null_nonblocking = answer(unsafe { getrandom(null, buffer.len(), GRND_NONBLOCK) });
    let empty_nonblocking = answer(unsafe { getrandom(null, 0, GRND_NONBLOCK) });
    let insecure = answer(unsafe { getrandom(pointer, buffer.len(), GRND_INSECURE) });
    let mut urandom = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    urandom.read_exact(&mut buffer).expect("read /dev/urandom");
    let hashmap = std::thread::spawn(|| HashMap::<u32, u32>::from([(1, 2)]).len())
        .join()
        .unwrap();
    let entropy = answer(unsafe { getentropy(pointer, buffer.len()) } as isize);
    let nonblocking_after = answer(unsafe { getrandom(pointer, buffer.len(), GRND_NONBLOCK) });
    println!(
        "NATIVE_ENTROPY_FAULT empty_getentropy={empty_getentropy} \
nonblocking_first={nonblocking_first} null_nonblocking={null_nonblocking} \
empty_nonblocking={empty_nonblocking} insecure={insecure} hashmap={hashmap} \
getentropy={entropy} nonblocking_after={nonblocking_after}"
    );
}
