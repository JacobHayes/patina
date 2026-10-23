//! Native filesystem operations, descriptor composition, and constructor effects.

#[cfg(test)]
mod tests {
    use super::super::*;

    // The deterministic filesystem's std and libc surface, one section per call
    // family, run in one guest. With no argument every section runs; `mount`
    // reads the corpus `--mount` supplies; `pwritev_view PATH` runs that section
    // alone against a host path, for the native oracle.
    //
    // * Hard links and recursive removal (`linkat`, and the `openat`/`fdopendir`/
    //   `unlinkat` walk `remove_dir_all` takes): a write through one name is seen
    //   through the other, and the tree is gone.
    // * `flock` keys on the inode: a second open's `LOCK_EX | LOCK_NB` reports
    //   EWOULDBLOCK in libc `errno` (what std's `File::try_lock` reads), and
    //   closing the first descriptor releases the lock.
    // * POSIX record locks for the lone opener: process-scoped locks never
    //   conflict with the process's own, so `F_SETLK`/`F_SETLKW` succeed and
    //   `F_GETLK` reports `F_UNLCK`; a bogus type is EINVAL and a read lock on
    //   write-only stdout EBADF. On Linux, open-file-description locks do contend
    //   across descriptions, and release lets the second in. `struct flock` and
    //   the command numbers differ between Linux and Darwin.
    // * Positional vectored I/O: one `pwritev` of two frames lands at the offset
    //   without moving the cursor, `preadv` reads across two buffers, a read past
    //   the end is short, and stdout has no offset (`ESPIPE`).
    // * `canonicalize` (`realpath` with and without a buffer) resolves a noisy
    //   spelling of an existing directory to its canonical name.
    // * Linux `statfs`/`fstatfs`: one constant ext4-like volume for any resolving
    //   path or descriptor, ENOENT for a missing path, EBADF for a bad descriptor.
    // * Linux `pwritev` whose second segment is a shared mapping of the file the
    //   first segment wrote reads what that segment stored: Linux writes the
    //   vector through one page cache.
    const FS_SURFACE_SOURCE: &str = r#"
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn pwritev(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
    fn preadv(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn links_and_trees() {
    fs::write("/original.txt", b"one").unwrap();
    fs::hard_link("/original.txt", "/alias.txt").unwrap();
    fs::write("/original.txt", b"two-longer").unwrap();
    let via_alias = fs::read_to_string("/alias.txt").unwrap();
    fs::create_dir_all("/tree/sub/deep").unwrap();
    fs::write("/tree/top.txt", b"x").unwrap();
    fs::write("/tree/sub/mid.txt", b"y").unwrap();
    fs::write("/tree/sub/deep/leaf.txt", b"z").unwrap();
    fs::remove_dir_all("/tree").unwrap();
    println!("TREE via_alias={via_alias} tree_exists={}", fs::metadata("/tree").is_ok());
}

fn flock_contention() {
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    let try_lock = |file: &File| unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    let first = OpenOptions::new().read(true).write(true).create(true).open("/lock.db").unwrap();
    let first_lock = try_lock(&first);
    let second = File::open("/lock.db").unwrap();
    let second_lock = try_lock(&second);
    let second_errno = errno();
    drop(first);
    let third = File::open("/lock.db").unwrap();
    let third_lock = try_lock(&third);
    println!("FLOCK first={first_lock} second={second_lock}/{second_errno} third={third_lock}");
}

#[cfg(target_os = "linux")]
mod abi {
    pub const F_GETLK: i32 = 5;
    pub const F_SETLK: i32 = 6;
    pub const F_SETLKW: i32 = 7;
    pub const F_RDLCK: i16 = 0;
    pub const F_WRLCK: i16 = 1;
    pub const F_UNLCK: i16 = 2;
    #[repr(C)]
    pub struct Flock {
        pub l_type: i16,
        pub l_whence: i16,
        pub l_start: i64,
        pub l_len: i64,
        pub l_pid: i32,
    }
    pub fn whole(l_type: i16) -> Flock {
        Flock { l_type, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 }
    }
}

#[cfg(target_os = "macos")]
mod abi {
    pub const F_GETLK: i32 = 7;
    pub const F_SETLK: i32 = 8;
    pub const F_SETLKW: i32 = 9;
    pub const F_RDLCK: i16 = 1;
    pub const F_WRLCK: i16 = 3;
    pub const F_UNLCK: i16 = 2;
    #[repr(C)]
    pub struct Flock {
        pub l_start: i64,
        pub l_len: i64,
        pub l_pid: i32,
        pub l_type: i16,
        pub l_whence: i16,
    }
    pub fn whole(l_type: i16) -> Flock {
        Flock { l_start: 0, l_len: 0, l_pid: 0, l_type, l_whence: 0 }
    }
}

fn record_locks() {
    use abi::*;
    let file = OpenOptions::new().read(true).write(true).create(true).open("/locked.db").unwrap();
    let fd = file.as_raw_fd();
    let lock = |fd: i32, command: i32, mut flock: Flock| unsafe { fcntl(fd, command, &mut flock as *mut Flock) };
    let setlk = lock(fd, F_SETLK, whole(F_WRLCK));
    let mut probe = whole(F_WRLCK);
    let getlk = unsafe { fcntl(fd, F_GETLK, &mut probe as *mut Flock) };
    let setlkw = lock(fd, F_SETLKW, whole(F_RDLCK));
    let unlck = lock(fd, F_SETLK, whole(F_UNLCK));
    let bad_type = lock(fd, F_SETLK, whole(7));
    let bad_type_errno = errno();
    // A READ lock on the write-only standard output is EBADF: fcntl_setlk
    // checks the lock type against the description's access mode.
    let on_stdio = lock(1, F_SETLK, whole(F_RDLCK));
    let stdio_errno = errno();
    println!(
        "FCNTL_LOCK setlk={setlk} getlk={getlk} getlk_type={} setlkw={setlkw} unlck={unlck} bad_type={bad_type}/{bad_type_errno} stdio={on_stdio}/{stdio_errno}",
        probe.l_type
    );
    #[cfg(target_os = "linux")]
    {
        const F_OFD_GETLK: i32 = 36;
        const F_OFD_SETLK: i32 = 37;
        // errno is printed after each call and a success leaves it alone, so it
        // still reads the second opener's EAGAIN.
        let first = lock(fd, F_OFD_SETLK, whole(F_WRLCK));
        let second = OpenOptions::new().read(true).write(true).open("/locked.db").unwrap();
        let contend = lock(second.as_raw_fd(), F_OFD_SETLK, whole(F_WRLCK));
        let contend_errno = errno();
        let range = lock(fd, F_OFD_SETLK, Flock { l_len: 16, ..whole(F_WRLCK) });
        let range_errno = errno();
        let getlk = lock(fd, F_OFD_GETLK, whole(F_WRLCK));
        let getlk_errno = errno();
        let release = lock(fd, F_OFD_SETLK, whole(F_UNLCK));
        let retry = lock(second.as_raw_fd(), F_OFD_SETLK, whole(F_WRLCK));
        println!(
            "FCNTL_OFD first={first} second={contend}/{contend_errno} range={range}/{range_errno} getlk={getlk}/{getlk_errno} release={release} retry={retry}"
        );
    }
}

fn positional_vectored() {
    let mut file = OpenOptions::new().read(true).write(true).create(true).open("/wal").unwrap();
    file.write_all(b"0123456789").unwrap();
    file.seek(SeekFrom::Start(7)).unwrap();
    let fd = file.as_raw_fd();
    let frames = [
        Iovec { base: b"AB".as_ptr(), len: 2 },
        Iovec { base: b"CD".as_ptr(), len: 2 },
    ];
    let wrote = unsafe { pwritev(fd, frames.as_ptr(), 2, 2) };
    let cursor = file.stream_position().unwrap();
    let mut a = [0u8; 3];
    let mut b = [0u8; 4];
    let bufs = [
        Iovec { base: a.as_mut_ptr().cast_const(), len: 3 },
        Iovec { base: b.as_mut_ptr().cast_const(), len: 4 },
    ];
    let read = unsafe { preadv(fd, bufs.as_ptr(), 2, 1) };
    let mut whole = String::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_string(&mut whole).unwrap();
    let mut tail = [0u8; 8];
    let tail_bufs = [Iovec { base: tail.as_mut_ptr().cast_const(), len: 8 }];
    let short = unsafe { preadv(fd, tail_bufs.as_ptr(), 1, 8) };
    let espipe = unsafe { pwritev(1, frames.as_ptr(), 2, 0) };
    let espipe_errno = errno();
    println!(
        "PVEC wrote={wrote} cursor={cursor} read={read} a={} b={} file={whole} short={short} stdout={espipe}/{espipe_errno}",
        String::from_utf8_lossy(&a),
        String::from_utf8_lossy(&b)
    );
}

fn canonical() {
    fs::create_dir_all("/tmp/patina-root/fragments").unwrap();
    let direct = fs::canonicalize("/tmp/patina-root/fragments").unwrap();
    let noisy = fs::canonicalize("/tmp/patina-root/../patina-root/./fragments//").unwrap();
    println!("CANONICAL direct={} noisy={}", direct.display(), noisy.display());
}

#[cfg(target_os = "linux")]
fn volume() {
    #[repr(C)]
    #[derive(Default)]
    struct Statfs {
        f_type: i64,
        f_bsize: i64,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_fsid: [i32; 2],
        f_namelen: i64,
        f_frsize: i64,
        f_flags: i64,
        f_spare: [i64; 4],
    }
    unsafe extern "C" {
        fn statfs(path: *const u8, buf: *mut Statfs) -> i32;
        fn fstatfs(fd: i32, buf: *mut Statfs) -> i32;
    }
    fs::create_dir_all("/db").unwrap();
    fs::write("/db/wal", b"frame").unwrap();
    let mut by_path = Statfs::default();
    let path_rc = unsafe { statfs(b"/db/wal\0".as_ptr(), &mut by_path) };
    let mut missing = Statfs::default();
    let missing_rc = unsafe { statfs(b"/db/nope\0".as_ptr(), &mut missing) };
    let missing_errno = errno();
    let file = File::open("/db/wal").unwrap();
    let mut by_fd = Statfs::default();
    let fd_rc = unsafe { fstatfs(file.as_raw_fd(), &mut by_fd) };
    let mut closed = Statfs::default();
    let bad_rc = unsafe { fstatfs(4242, &mut closed) };
    println!(
        "STATFS path={path_rc} type={:#x} bsize={} namelen={} missing={missing_rc}/{missing_errno} fd={fd_rc} fd_type={:#x} bad={bad_rc}",
        by_path.f_type, by_path.f_bsize, by_path.f_namelen, by_fd.f_type
    );
}

#[cfg(target_os = "linux")]
fn pwritev_view(path: &str) {
    unsafe extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    }
    const PROT_READ_WRITE: i32 = 3;
    const MAP_SHARED: i32 = 1;
    let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path).unwrap();
    file.write_all(b"AA").unwrap();
    let view = unsafe { mmap(std::ptr::null_mut(), 2, PROT_READ_WRITE, MAP_SHARED, file.as_raw_fd(), 0) };
    assert_ne!(view as isize, -1);
    let segments = [
        Iovec { base: b"B".as_ptr(), len: 1 },
        Iovec { base: view.cast_const(), len: 1 },
    ];
    let wrote = unsafe { pwritev(file.as_raw_fd(), segments.as_ptr(), 2, 0) };
    let mapped = unsafe { std::slice::from_raw_parts(view, 2) };
    println!(
        "PWRITEV_VIEW wrote={wrote} file={} view={}",
        String::from_utf8_lossy(&fs::read(path).unwrap()),
        String::from_utf8_lossy(mapped)
    );
}

fn mount() {
    use std::os::unix::fs::MetadataExt;
    let contents = fs::read_to_string("/data.txt").expect("read mounted file");
    let metadata = fs::metadata("/data.txt").expect("stat mounted file");
    print!("{contents}mode={:o} mtime={}\n", metadata.mode() & 0o7777, metadata.mtime());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("mount") => mount(),
        #[cfg(target_os = "linux")]
        Some("pwritev_view") => pwritev_view(&args[1]),
        Some(other) => panic!("unknown mode {other}"),
        None => {
            links_and_trees();
            flock_contention();
            record_locks();
            positional_vectored();
            canonical();
            #[cfg(target_os = "linux")]
            {
                volume();
                pwritev_view("/mapped");
            }
        }
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_surface_answers_from_the_deterministic_filesystem() {
        let guest = native_build::source_guest("fs_surface", FS_SURFACE_SOURCE);
        // `linkat` and `fdopendir` are shim-defined, so they leave the import
        // table and the audit passes without an allowance.
        guest.assert_audit_clean();
        guest.assert_no_imports(&["linkat", "fdopendir"]);
        let output = guest.assert_run_success(1, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let ewouldblock = if cfg!(target_os = "macos") { 35 } else { 11 };
        let mut expected = vec![
            "TREE via_alias=two-longer tree_exists=false".to_owned(),
            format!("FLOCK first=0 second=-1/{ewouldblock} third=0"),
            "FCNTL_LOCK setlk=0 getlk=0 getlk_type=2 setlkw=0 unlck=0 bad_type=-1/22 stdio=-1/9"
                .to_owned(),
            "PVEC wrote=4 cursor=7 read=7 a=1AB b=CD67 file=01ABCD6789 short=2 stdout=-1/29"
                .to_owned(),
            "CANONICAL direct=/tmp/patina-root/fragments noisy=/tmp/patina-root/fragments"
                .to_owned(),
        ];
        if cfg!(target_os = "linux") {
            expected.push(
                "FCNTL_OFD first=0 second=-1/11 range=0/11 getlk=0/11 release=0 retry=0".to_owned(),
            );
            expected.push(
                "STATFS path=0 type=0xef53 bsize=4096 namelen=255 missing=-1/2 fd=0 fd_type=0xef53 bad=-1"
                    .to_owned(),
            );
            let native = guest.dir.path().join("native-file");
            expected.push(native_run_of(
                FS_SURFACE_SOURCE,
                guest.dir.path(),
                &["pwritev_view", native.to_str().unwrap()],
            ));
        }
        for line in expected {
            assert!(
                stdout.lines().any(|printed| printed == line),
                "missing {line:?}:\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        mount_composes_with_record_and_replay(&guest);
    }

    /// `--mount` composes with `--record`/`replay`, which hands the child two
    /// inherited descriptors at once, and a replay against a corpus that moved is
    /// refused before the guest runs, naming what moved.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn mount_composes_with_record_and_replay(guest: &common::native::Guest) {
        // A label holding what the corpus component looks like: the hash is
        // read where patina put it, not out of the label.
        const LABEL: &str = "read-mount+fsimg:label";
        let directory = guest.dir.path();
        let bin = guest.binary.to_str().unwrap();
        let workspace = native_workspace();
        let mount = directory.join("corpus");
        fs::create_dir(&mount).unwrap();
        let data = mount.join("data.txt");
        fs::write(&data, "MOUNTED-CONTENT\n").unwrap();
        let set_metadata = |mtime_secs: u64| {
            fs::set_permissions(&data, fs::Permissions::from_mode(0o640)).unwrap();
            fs::File::options()
                .write(true)
                .open(&data)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(mtime_secs))
                .unwrap();
        };
        set_metadata(1_704_067_200);
        let expected = "MOUNTED-CONTENT\nmode=640 mtime=1704067200\n";

        let trace = directory.join("mount.patina");
        let mount_arg = mount.to_str().unwrap();
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "0",
                "--mount",
                mount_arg,
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                LABEL,
                "--",
                "mount",
            ],
        );
        assert_eq!(String::from_utf8_lossy(&recorded.stdout), expected);

        // `replay` re-supplies the host corpus with --mount (a host input the trace
        // cannot carry; only its hash is in the fingerprint).
        let replay = |mount: &str, extra: &[&str]| {
            let mut args = vec![
                "replay",
                bin,
                trace.to_str().unwrap(),
                "--mount",
                mount,
                "--fingerprint",
                LABEL,
            ];
            args.extend_from_slice(extra);
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &args)
        };
        let replayed = replay(mount_arg, &[]);
        assert!(
            replayed.status.success(),
            "{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&replayed.stdout), expected);

        // The same contents restamped, as a fresh checkout leaves them: the guest
        // can see the mtime, so the supervisor refuses this corpus too, before the
        // guest runs, naming the half that moved.
        set_metadata(1_704_153_600);
        let restamped = replay(mount_arg, &["--format", "json"]);
        let envelope: serde_json::Value = serde_json::from_str(
            String::from_utf8_lossy(&restamped.stdout).trim(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "envelope was not one JSON object: {error}\nstderr:\n{}",
                String::from_utf8_lossy(&restamped.stderr)
            )
        });
        assert!(!restamped.status.success(), "{envelope:#}");
        assert_eq!(
            envelope["refusal"]["class"], "fingerprint_mismatch",
            "{envelope:#}"
        );
        assert_eq!(
            envelope["refusal"]["mismatch"], "mount_metadata",
            "{envelope:#}"
        );
        assert!(envelope["guest_exit"].is_null(), "{envelope:#}");

        // A different corpus hashes to a different image, so replay fails closed
        // naming the corpus image hash, not a generic error.
        let other_mount = directory.join("corpus-other");
        fs::create_dir(&other_mount).unwrap();
        fs::write(other_mount.join("data.txt"), "DIFFERENT-CONTENT\n").unwrap();
        let cross = replay(other_mount.to_str().unwrap(), &[]);
        let cross_stderr = String::from_utf8_lossy(&cross.stderr);
        assert!(!cross.status.success(), "{cross_stderr}");
        assert!(
            cross_stderr.contains("+fsimg:"),
            "the fingerprint mismatch must name the corpus image hash (+fsimg:):\n{cross_stderr}"
        );
    }

    /// The line a mode of `source` prints first when built with plain `rustc` and
    /// run natively, without Patina.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn native_run_of(source: &str, directory: &Path, args: &[&str]) -> String {
        let source_path = directory.join("native.rs");
        fs::write(&source_path, source).unwrap();
        let binary = directory.join("native");
        let built = Command::new("rustc")
            .args(["--edition", "2024", "-o"])
            .arg(&binary)
            .arg(&source_path)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let output = Command::new(&binary).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .expect("the native guest printed its line")
            .to_owned()
    }

    // A guest/static constructor can run before Patina's startup constructor. If it
    // reaches an effectful interposed API, fail closed with the ctor-specific
    // diagnostic rather than the misleading not-launched/runtime-missing path.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_ctor_preinit_open_reports_static_constructor_diagnostic() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("ctor_open.rs");
        fs::write(
            &source,
            r#"extern "C" fn patina_ctor() {
    let _ = std::fs::File::open("/tmp/patina-ctor-trigger");
}

#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array.00099"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
static PATINA_CTOR: extern "C" fn() = patina_ctor;

fn main() {
    println!("main should not run");
}
"#,
        )
        .unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("ctor-open");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !output.status.success(),
            "ctor pre-init open unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("interposed call before deterministic runtime initialization"),
            "missing pre-init condition:\n{stderr}"
        );
        assert!(
            stderr.contains("static constructor/ctor"),
            "missing ctor attribution:\n{stderr}"
        );
        assert!(
            stderr.contains("calling symbol: open"),
            "missing calling symbol:\n{stderr}"
        );
        assert!(
            stderr.contains("#[cfg(not(patina))]") && stderr.contains("#[cfg(not(dst))]"),
            "missing cfg-gate workaround:\n{stderr}"
        );
        assert!(
            !stderr.contains("must run under `cargo patina run`"),
            "ctor diagnostic must be distinct from not-launched message:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("main should not run"),
            "ctor failure should happen before main"
        );
    }
}
