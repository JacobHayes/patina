use std::ffi::{CString, c_void};
use std::os::raw::c_char;
use std::ptr::NonNull;

unsafe extern "C" {
    fn patina_dlsym_route(symbol: *const c_char) -> *mut c_void;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

type GetRandomFn = unsafe extern "C" fn(*mut c_void, usize, u32) -> isize;
type GetEntropyFn = unsafe extern "C" fn(*mut c_void, usize) -> i32;

fn table(symbol: &str) -> *mut c_void {
    let name = CString::new(symbol).expect("symbol name carries no NUL");
    unsafe { patina_dlsym_route(name.as_ptr()) }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    // std's optional-symbol probe, dynamic loading, an unmodeled entropy symbol,
    // and ordinary host effects must all still resolve to nothing.
    for denied in [
        "__pthread_get_minstack",
        "dlopen",
        "arc4random_buf",
        "open",
        "getpid",
        "",
    ] {
        assert!(table(denied).is_null(), "dlsym allowlist leaked {denied:?}");
    }

    let getrandom_ptr = table("getrandom");
    let getentropy_ptr = table("getentropy");
    assert!(!getrandom_ptr.is_null(), "getrandom is not routed");
    assert!(!getentropy_ptr.is_null(), "getentropy is not routed");
    let getrandom: GetRandomFn = unsafe { std::mem::transmute(getrandom_ptr) };
    let getentropy: GetEntropyFn = unsafe { std::mem::transmute(getentropy_ptr) };

    // The availability probe the `getrandom` crate runs immediately after
    // resolving the pointer: a zero-length call through a dangling pointer. A
    // negative answer there makes the crate mark getrandom unavailable and take
    // the /dev/random fallback, so this exact shape has to succeed.
    let dangling = NonNull::<u8>::dangling().as_ptr().cast::<c_void>();
    assert_eq!(
        unsafe { getrandom(dangling, 0, 0) },
        0,
        "availability probe failed"
    );

    let mut from_getrandom = [0u8; 24];
    let filled = unsafe { getrandom(from_getrandom.as_mut_ptr().cast(), from_getrandom.len(), 0) };
    assert_eq!(
        filled,
        from_getrandom.len() as isize,
        "short getrandom fill"
    );

    let mut from_getentropy = [0u8; 24];
    let status = unsafe { getentropy(from_getentropy.as_mut_ptr().cast(), from_getentropy.len()) };
    assert_eq!(status, 0, "getentropy failed");

    // Successive draws off one seeded stream: neither empty nor the same block.
    assert_ne!(from_getrandom, [0u8; 24], "getrandom wrote nothing");
    assert_ne!(from_getrandom, from_getentropy, "two draws were identical");

    // Unknown GRND_* flags stay fail-closed rather than silently succeeding.
    let mut scratch = [0u8; 8];
    let rejected = unsafe { getrandom(scratch.as_mut_ptr().cast(), scratch.len(), 0x4000_0000) };
    assert_eq!(rejected, -1, "unknown getrandom flags were accepted");

    let link = {
        #[cfg(target_os = "linux")]
        {
            // RTLD_DEFAULT is NULL on glibc: the handle both the `getrandom`
            // crate and std pass. The wrapped dlsym must hand back the very
            // pointer the table holds, and must still refuse everything else.
            let name = CString::new("getrandom").unwrap();
            let resolved = unsafe { dlsym(std::ptr::null_mut(), name.as_ptr()) };
            assert_eq!(
                resolved, getrandom_ptr,
                "dlsym did not return the routed getrandom"
            );
            let name = CString::new("__pthread_get_minstack").unwrap();
            let probed = unsafe { dlsym(std::ptr::null_mut(), name.as_ptr()) };
            assert!(probed.is_null(), "dlsym leaked a host symbol");
            "wrapped"
        }
        #[cfg(not(target_os = "linux"))]
        {
            "table-only"
        }
    };

    println!(
        "NATIVE_DLSYM_ENTROPY link={link} getrandom={} getentropy={}",
        hex(&from_getrandom),
        hex(&from_getentropy)
    );
}
