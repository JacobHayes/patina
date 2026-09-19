use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn mode_of(path: &[u8]) -> u32 {
    const NEWFSTATAT: i64 = 262;
    const AT_FDCWD: i64 = -100;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        sc(
            NEWFSTATAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            (&raw mut st) as i64,
            0,
        )
    };
    assert_eq!(rc, 0, "newfstatat {rc}");
    st.st_mode & 0o7777
}
fn main() {
    const CLOSE: i64 = 3;
    const OPEN: i64 = 2;
    const CREAT: i64 = 85;
    const MKDIR: i64 = 83;
    const MKDIRAT: i64 = 258;
    const OPENAT: i64 = 257;
    const AT_FDCWD: i64 = -100;
    const O_WRONLY: i64 = 0o1;
    const O_CREAT: i64 = 0o100;
    const O_TRUNC: i64 = 0o1000;
    const EACCES: i64 = -13;

    // A raw openat carries its fourth argument: the file is 0o400, and the
    // SECOND open of it for writing is refused against that mode.
    let strict = b"/raw-modes-strict\0";
    let fd = unsafe {
        sc(
            OPENAT,
            AT_FDCWD,
            strict.as_ptr() as i64,
            O_WRONLY | O_CREAT,
            0o400,
        )
    };
    assert!(fd >= 0, "openat(O_CREAT, 0o400) {fd}");
    let _ = unsafe { sc(CLOSE, fd, 0, 0, 0) };
    assert_eq!(
        mode_of(strict),
        0o400,
        "raw openat creation mode {:o}",
        mode_of(strict)
    );
    let again = unsafe { sc(OPENAT, AT_FDCWD, strict.as_ptr() as i64, O_WRONLY, 0) };
    assert_eq!(
        again, EACCES,
        "a 0o400 file must not reopen for writing, got {again}"
    );

    // The umask is applied to the request, exactly as the kernel applies it.
    let wide = b"/raw-modes-wide\0";
    let fd = unsafe {
        sc(
            OPENAT,
            AT_FDCWD,
            wide.as_ptr() as i64,
            O_WRONLY | O_CREAT | O_TRUNC,
            0o666,
        )
    };
    assert!(fd >= 0, "openat(O_CREAT, 0o666) {fd}");
    let _ = unsafe { sc(CLOSE, fd, 0, 0, 0) };
    assert_eq!(mode_of(wide), 0o644, "0o666 & !0o022 {:o}", mode_of(wide));

    // x86_64 legacy open(2) and creat(2): same argument, different positions.
    let legacy = b"/raw-modes-legacy\0";
    let fd = unsafe { sc(OPEN, legacy.as_ptr() as i64, O_WRONLY | O_CREAT, 0o606, 0) };
    assert!(fd >= 0, "legacy open(O_CREAT, 0o606) {fd}");
    let _ = unsafe { sc(CLOSE, fd, 0, 0, 0) };
    assert_eq!(
        mode_of(legacy),
        0o604,
        "legacy open mode under the umask {:o}",
        mode_of(legacy)
    );
    let created = b"/raw-modes-creat\0";
    let fd = unsafe { sc(CREAT, created.as_ptr() as i64, 0o640, 0, 0) };
    assert!(fd >= 0, "legacy creat(0o640) {fd}");
    let _ = unsafe { sc(CLOSE, fd, 0, 0, 0) };
    assert_eq!(
        mode_of(created),
        0o640,
        "legacy creat mode {:o}",
        mode_of(created)
    );

    // mkdirat/mkdir carry theirs too, and a 0o500 directory refuses new names.
    let locked = b"/raw-modes-locked\0";
    assert_eq!(
        unsafe { sc(MKDIRAT, AT_FDCWD, locked.as_ptr() as i64, 0o500, 0) },
        0,
        "mkdirat"
    );
    assert_eq!(mode_of(locked), 0o500, "mkdirat mode {:o}", mode_of(locked));
    let inside = b"/raw-modes-locked/nope\0";
    let refused = unsafe {
        sc(
            OPENAT,
            AT_FDCWD,
            inside.as_ptr() as i64,
            O_WRONLY | O_CREAT,
            0o600,
        )
    };
    assert_eq!(
        refused, EACCES,
        "a 0o500 directory has no `w`, got {refused}"
    );
    let open_dir = b"/raw-modes-open\0";
    assert_eq!(
        unsafe { sc(MKDIR, open_dir.as_ptr() as i64, 0o777, 0, 0) },
        0,
        "legacy mkdir"
    );
    assert_eq!(
        mode_of(open_dir),
        0o755,
        "0o777 & !0o022 {:o}",
        mode_of(open_dir)
    );
    println!("RAW_MODES openat+open+creat+mkdirat+mkdir+umask+enforced ok");
}
