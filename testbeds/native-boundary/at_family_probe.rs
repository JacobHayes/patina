// The libc *at family against a real directory descriptor -- the door a guest
// whose backend is libc (rather than raw syscalls) uses for every path it
// resolves through a capability. `symlinkat`/`readlinkat` are declared here the
// way a libc-backend crate declares them, so an uninterposed one would be an
// unknown import the pre-run audit refuses.
use std::io::Write;

unsafe extern "C" {
    fn open(path: *const u8, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn symlinkat(target: *const u8, dirfd: i32, link_path: *const u8) -> i32;
    fn readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, len: usize) -> isize;
}

// O_RDONLY | O_DIRECTORY (Linux 0o200000, macOS 0x100000).
#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(not(target_os = "linux"))]
const O_DIRECTORY: i32 = 0x0010_0000;

fn main() {
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/target.txt", b"pointed-at").unwrap();
    // SAFETY: NUL-terminated literals and a valid descriptor throughout.
    let dirfd = unsafe { open(c"/state".as_ptr().cast(), O_DIRECTORY) };
    assert!(dirfd >= 0, "opening the directory failed");

    // symlinkat resolves only the LINK side against the descriptor; the target
    // is a string the filesystem stores verbatim.
    let rc = unsafe {
        symlinkat(
            c"target.txt".as_ptr().cast(),
            dirfd,
            c"link".as_ptr().cast(),
        )
    };
    assert_eq!(rc, 0, "symlinkat through a dirfd failed");

    let mut buf = [0u8; 64];
    let len = unsafe { readlinkat(dirfd, c"link".as_ptr().cast(), buf.as_mut_ptr(), buf.len()) };
    assert!(len > 0, "readlinkat through a dirfd failed");
    let target = String::from_utf8_lossy(&buf[..len as usize]).into_owned();

    // The link resolves to the file it names, through the same directory.
    let contents = std::fs::read_to_string("/state/link").unwrap();
    assert_eq!(unsafe { close(dirfd) }, 0);

    // AT_FDCWD keeps working through the same interposers.
    let rc = unsafe {
        symlinkat(
            c"/state/target.txt".as_ptr().cast(),
            -100,
            c"/state/abs".as_ptr().cast(),
        )
    };
    assert_eq!(rc, 0, "symlinkat(AT_FDCWD) failed");
    let len = unsafe {
        readlinkat(
            -100,
            c"/state/abs".as_ptr().cast(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    let absolute = String::from_utf8_lossy(&buf[..len as usize]).into_owned();

    std::io::stdout().flush().unwrap();
    println!("NATIVE_LIBC_AT_RESULT link={target} read={contents} abs={absolute}");
}
