use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") 0i64, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn main() {
    const OPEN: i64 = 2;
    const READ: i64 = 0;
    const WRITE: i64 = 1;
    const CLOSE: i64 = 3;
    const CREAT: i64 = 85;
    const UNLINK: i64 = 87;
    const MKDIR: i64 = 83;
    const OPENAT: i64 = 257;
    const GETDENTS64: i64 = 217;
    const FCNTL: i64 = 72;
    const O_WRONLY: i64 = 0o1;
    const O_CREAT: i64 = 0o100;
    const O_TRUNC: i64 = 0o1000;
    const O_DIRECTORY: i64 = 0o200000;
    const F_GETFL: i64 = 3;
    let path = b"/legacy-open.txt\0";
    let msg = b"legacy-alias";
    // legacy open(2) create+write.
    let fd = unsafe {
        sc(
            OPEN,
            path.as_ptr() as i64,
            O_WRONLY | O_CREAT | O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0, "legacy open(create) {fd}");
    let w = unsafe { sc(WRITE, fd, msg.as_ptr() as i64, msg.len() as i64) };
    assert_eq!(w, msg.len() as i64, "write {w}");
    assert_eq!(unsafe { sc(CLOSE, fd, 0, 0) }, 0, "close");
    // legacy open(2) read-back.
    let rfd = unsafe {
        sc(OPEN, path.as_ptr() as i64, 0 /*O_RDONLY*/, 0)
    };
    assert!(rfd >= 0, "legacy open(read) {rfd}");
    let mut buf = [0u8; 32];
    let n = unsafe { sc(READ, rfd, buf.as_mut_ptr() as i64, buf.len() as i64) };
    assert_eq!(&buf[..n as usize], msg, "legacy open read-back mismatch");
    let _ = unsafe { sc(CLOSE, rfd, 0, 0) };
    // legacy creat(85): flags synthesized to O_CREAT|O_WRONLY|O_TRUNC.
    let path2 = b"/legacy-creat.txt\0";
    let cfd = unsafe { sc(CREAT, path2.as_ptr() as i64, 0o600, 0) };
    assert!(cfd >= 0, "legacy creat {cfd}");
    let _ = unsafe { sc(CLOSE, cfd, 0, 0) };
    // legacy unlink(87) removes it; a subsequent legacy open must fail.
    assert_eq!(
        unsafe { sc(UNLINK, path2.as_ptr() as i64, 0, 0) },
        0,
        "legacy unlink"
    );
    let gone = unsafe { sc(OPEN, path2.as_ptr() as i64, 0, 0) };
    assert!(
        gone < 0,
        "legacy open of unlinked path must fail, got {gone}"
    );

    // ---- directory listing through the raw rustix `Dir::read_from` dance ----
    let dir = b"/legacy-dir\0";
    assert_eq!(
        unsafe { sc(MKDIR, dir.as_ptr() as i64, 0o755, 0) },
        0,
        "legacy mkdir"
    );
    for f in [
        b"/legacy-dir/alpha\0".as_ref(),
        b"/legacy-dir/beta\0".as_ref(),
    ] {
        let cfd = unsafe { sc(OPEN, f.as_ptr() as i64, O_WRONLY | O_CREAT | O_TRUNC, 0o600) };
        assert!(cfd >= 0, "create-in-dir {cfd}");
        let _ = unsafe { sc(CLOSE, cfd, 0, 0) };
    }
    // legacy open(2) of the DIRECTORY yields a directory fd.
    let dfd = unsafe { sc(OPEN, dir.as_ptr() as i64, O_DIRECTORY, 0) };
    assert!(dfd >= 0, "legacy open(dir) {dfd}");
    // rustix Dir::read_from: fcntl(F_GETFL) then openat(dir_fd, ".", flags).
    let fl = unsafe { sc(FCNTL, dfd, F_GETFL, 0) };
    assert!(
        fl >= 0,
        "fcntl(F_GETFL) on a dir fd was EBADF before the fix, got {fl}"
    );
    let dot = b".\0";
    let dfd2 = unsafe { sc(OPENAT, dfd, dot.as_ptr() as i64, fl) };
    assert!(dfd2 >= 0, "openat(dir_fd, \".\") {dfd2}");
    // raw getdents64 over the fresh handle.
    let mut dbuf = [0u8; 1024];
    let mut names: Vec<String> = Vec::new();
    loop {
        let g = unsafe {
            sc(
                GETDENTS64,
                dfd2,
                dbuf.as_mut_ptr() as i64,
                dbuf.len() as i64,
            )
        };
        assert!(g >= 0, "getdents64 {g}");
        if g == 0 {
            break;
        }
        let mut off = 0usize;
        while off < g as usize {
            let reclen = unsafe {
                std::ptr::addr_of!((*(dbuf.as_ptr().add(off).cast::<libc::dirent64>())).d_reclen)
                    .read_unaligned()
            } as usize;
            assert!(
                reclen >= 19 && off + reclen <= g as usize,
                "bad d_reclen {reclen}"
            );
            let nb = &dbuf[off + std::mem::offset_of!(libc::dirent64, d_name)..off + reclen];
            let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
            let name = String::from_utf8_lossy(&nb[..end]).into_owned();
            if name != "." && name != ".." {
                names.push(name);
            }
            off += reclen;
        }
    }
    names.sort();
    assert_eq!(
        names,
        vec!["alpha".to_string(), "beta".to_string()],
        "legacy dir listing {names:?}"
    );
    let _ = unsafe { sc(CLOSE, dfd2, 0, 0) };
    let _ = unsafe { sc(CLOSE, dfd, 0, 0) };
    println!("LEGACY_ALIASES open+creat+unlink+getdents ok");
}
