use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn main() {
    const READ: i64 = 0;
    const WRITE: i64 = 1;
    const CLOSE: i64 = 3;
    const FSTAT: i64 = 5;
    const MKDIR: i64 = 83;
    const MKNOD: i64 = 133;
    const OPENAT: i64 = 257;
    const MKNODAT: i64 = 259;
    const NEWFSTATAT: i64 = 262;
    const GETDENTS64: i64 = 217;
    const AT_FDCWD: i64 = -100;
    const O_WRONLY: i64 = 0o1;
    const O_NONBLOCK: i64 = 0o4000;
    const O_DIRECTORY: i64 = 0o200000;
    const S_IFMT: u32 = 0o170000;
    const S_IFIFO: u32 = 0o010000;
    const DT_FIFO: u8 = 1;
    const ENXIO: i64 = -6;
    const EPERM: i64 = -1;

    let dir = b"/raw-fifo\0";
    assert_eq!(
        unsafe { sc(MKDIR, dir.as_ptr() as i64, 0o755, 0, 0) },
        0,
        "mkdir"
    );

    // Modern mknodat, and the x86_64 legacy mknod alias, both make a FIFO.
    let at_path = b"/raw-fifo/at\0";
    let rc = unsafe {
        sc(
            MKNODAT,
            AT_FDCWD,
            at_path.as_ptr() as i64,
            (S_IFIFO | 0o644) as i64,
            0,
        )
    };
    assert_eq!(rc, 0, "mknodat(S_IFIFO) {rc}");
    let legacy_path = b"/raw-fifo/legacy\0";
    let rc = unsafe {
        sc(
            MKNOD,
            legacy_path.as_ptr() as i64,
            (S_IFIFO | 0o600) as i64,
            0,
            0,
        )
    };
    assert_eq!(rc, 0, "legacy mknod(S_IFIFO) {rc}");
    // A device node has no deterministic representation: EPERM, never a host call.
    let dev_path = b"/raw-fifo/dev\0";
    let rc = unsafe {
        sc(
            MKNODAT,
            AT_FDCWD,
            dev_path.as_ptr() as i64,
            (0o020000u32 | 0o666) as i64,
            0x103,
        )
    };
    assert_eq!(
        rc, EPERM,
        "mknodat of a character device must be EPERM, got {rc}"
    );

    // raw newfstatat by PATH reports S_IFIFO with the umasked mode.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        sc(
            NEWFSTATAT,
            AT_FDCWD,
            at_path.as_ptr() as i64,
            (&raw mut st) as i64,
            0,
        )
    };
    assert_eq!(rc, 0, "newfstatat {rc}");
    let mode = st.st_mode;
    assert_eq!(mode & S_IFMT, S_IFIFO, "newfstatat st_mode {mode:o}");
    assert_eq!(
        mode & 0o7777,
        0o644,
        "mknodat mode under the modeled umask {mode:o}"
    );

    // A non-blocking read-open answers at once with no writer, and raw fstat on
    // the DESCRIPTOR reports a FIFO too (the check a sandbox makes after the
    // open, because the path check above can be raced).
    let rfd = unsafe { sc(OPENAT, AT_FDCWD, at_path.as_ptr() as i64, O_NONBLOCK, 0) };
    assert!(rfd >= 0, "non-blocking read-open of a FIFO {rfd}");
    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { sc(FSTAT, rfd, (&raw mut fst) as i64, 0, 0) },
        0,
        "fstat"
    );
    let fmode = fst.st_mode;
    assert_eq!(fmode & S_IFMT, S_IFIFO, "fstat st_mode {fmode:o}");

    // With a reader present a blocking write-open returns immediately, and raw
    // write/read carry bytes across the endpoint pair.
    let wfd = unsafe { sc(OPENAT, AT_FDCWD, at_path.as_ptr() as i64, O_WRONLY, 0) };
    assert!(wfd >= 0, "write-open with a reader present {wfd}");
    let msg = b"raw-fifo";
    let w = unsafe { sc(WRITE, wfd, msg.as_ptr() as i64, msg.len() as i64, 0) };
    assert_eq!(w, msg.len() as i64, "raw write into a FIFO {w}");
    let mut buf = [0u8; 16];
    let n = unsafe { sc(READ, rfd, buf.as_mut_ptr() as i64, buf.len() as i64, 0) };
    assert_eq!(&buf[..n as usize], msg, "raw read from a FIFO");
    let _ = unsafe { sc(CLOSE, wfd, 0, 0, 0) };
    // The last writer is gone: the next read is end-of-file, not another park.
    assert_eq!(
        unsafe { sc(READ, rfd, buf.as_mut_ptr() as i64, buf.len() as i64, 0) },
        0,
        "read after the last writer closed must be EOF"
    );
    let _ = unsafe { sc(CLOSE, rfd, 0, 0, 0) };

    // No reader at all: a non-blocking write-open is ENXIO.
    let rc = unsafe {
        sc(
            OPENAT,
            AT_FDCWD,
            at_path.as_ptr() as i64,
            O_WRONLY | O_NONBLOCK,
            0,
        )
    };
    assert_eq!(
        rc, ENXIO,
        "non-blocking write-open with no reader must be ENXIO, got {rc}"
    );

    // getdents64 reports DT_FIFO for both names.
    let dfd = unsafe { sc(OPENAT, AT_FDCWD, dir.as_ptr() as i64, O_DIRECTORY, 0) };
    assert!(dfd >= 0, "open(dir) {dfd}");
    let mut dbuf = [0u8; 1024];
    let mut seen: Vec<(String, u8)> = Vec::new();
    loop {
        let g = unsafe {
            sc(
                GETDENTS64,
                dfd,
                dbuf.as_mut_ptr() as i64,
                dbuf.len() as i64,
                0,
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
            let kind = unsafe {
                std::ptr::addr_of!((*(dbuf.as_ptr().add(off).cast::<libc::dirent64>())).d_type)
                    .read_unaligned()
            };
            let nb = &dbuf[off + std::mem::offset_of!(libc::dirent64, d_name)..off + reclen];
            let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
            let name = String::from_utf8_lossy(&nb[..end]).into_owned();
            if name != "." && name != ".." {
                seen.push((name, kind));
            }
            off += reclen;
        }
    }
    seen.sort();
    assert_eq!(
        seen,
        vec![("at".to_string(), DT_FIFO), ("legacy".to_string(), DT_FIFO)],
        "getdents64 d_type for FIFOs {seen:?}"
    );
    let _ = unsafe { sc(CLOSE, dfd, 0, 0, 0) };
    println!("RAW_FIFO mknodat+stat+nonblock+enxio+transfer+dents ok");
}
