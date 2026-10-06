//! Native filesystem operations, descriptor composition, and constructor effects.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Two threads communicating over `std::sync::mpsc` with `recv_timeout`: on macOS
    // this drives std's Darwin thread `Parker` (`park`/`park_timeout` on a
    // libdispatch semaphore), on Linux the futex Parker. The interposed dispatch
    // semaphore routes the wait through the deterministic scheduler and virtual
    // clock, so both the delivery/timeout interleaving and the timeout count are a
    // function of the seed alone — byte-identical across repeated runs and exactly
    // reproduced by record/replay — never of host wall-clock timing.
    const RECV_TIMEOUT_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let (tx, rx) = mpsc::channel::<u64>();
    let producer = thread::spawn(move || {
        for i in 0..5 {
            thread::sleep(Duration::from_millis(10));
            tx.send(i).unwrap();
        }
    });
    let mut delivered = Vec::new();
    let mut timeouts = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_millis(7)) {
            Ok(v) => delivered.push(v),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timeouts += 1;
                if delivered.len() == 5 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    println!("delivered={:?} timeouts={}", delivered, timeouts);
}
"#;

    // Part A: `recv_timeout` across two threads is byte-identical across >=3 runs at
    // multiple seeds and exactly reproduced by record/replay. Before the fix the
    // Parker blocked a real host thread on a libdispatch semaphore and read host
    // time for its timeout, escaping the scheduler entirely.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_recv_timeout_is_deterministic_across_seeds_and_replay() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("recv_timeout.rs");
        fs::write(&source, RECV_TIMEOUT_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("recv-timeout");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        for seed in ["1", "5", "9"] {
            let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
            assert!(
                baseline.contains("delivered="),
                "unexpected recv_timeout output at seed {seed}: {baseline}"
            );
            for _ in 0..2 {
                let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
                assert_eq!(
                    baseline,
                    String::from_utf8_lossy(&again.stdout),
                    "recv_timeout output is not byte-identical across runs at seed {seed}"
                );
            }
        }

        let trace = directory.path().join("recv.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "9",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "recv-timeout",
            ],
        );
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "recv-timeout",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "record and strict replay diverged"
        );
    }

    // Exercises the two std filesystem APIs that lower onto `linkat` and
    // `fdopendir` -- both unsupported native imports before this shim wave, so a
    // guest using either was refused by the pre-run audit up front.
    //
    // Part (a) hard links (`std::fs::hard_link` -> `linkat(AT_FDCWD, .., 0)`): after
    // linking, a write through one path is observed through the other, the
    // same-inode/same-content contract of a hard link (a copy would not see the
    // mutation). Part (b) recursive removal (`std::fs::remove_dir_all`, which on
    // both macOS and Linux std opens each directory with `openat(.., O_DIRECTORY)`,
    // reads it via `fdopendir`, and removes children with `unlinkat(dirfd, ..)`):
    // a nested tree is built and removed, and its absence is asserted.
    const HARD_LINK_AND_REMOVE_TREE_SOURCE: &str = r#"
use std::fs;

fn main() {
    // (a) hard link: mutate through one name, observe through the other.
    fs::write("/original.txt", b"one").unwrap();
    fs::hard_link("/original.txt", "/alias.txt").unwrap();
    fs::write("/original.txt", b"two-longer").unwrap();
    let via_alias = fs::read_to_string("/alias.txt").unwrap();

    // (b) recursive removal of a nested tree via the openat/fdopendir/unlinkat path.
    fs::create_dir_all("/tree/sub/deep").unwrap();
    fs::write("/tree/top.txt", b"x").unwrap();
    fs::write("/tree/sub/mid.txt", b"y").unwrap();
    fs::write("/tree/sub/deep/leaf.txt", b"z").unwrap();
    fs::remove_dir_all("/tree").unwrap();

    println!("via_alias={via_alias}");
    println!("tree_exists={}", fs::metadata("/tree").is_ok());
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_hard_link_and_remove_dir_all_are_supported_and_deterministic() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("hard_link_tree.rs");
        fs::write(&source, HARD_LINK_AND_REMOVE_TREE_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("hard-link-tree");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        // Audit is clean: `invoke_in` already asserts exit 0, and neither `linkat`
        // nor `fdopendir` may surface as an unsupported/unknown import or force an
        // allowance -- the strong defs drop them off the import table entirely.
        let audited = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        let audit_text = format!(
            "{}{}",
            String::from_utf8_lossy(&audited.stdout),
            String::from_utf8_lossy(&audited.stderr)
        );
        for needle in [
            "unsupported native imports",
            "unknown-import",
            "linkat",
            "fdopendir",
        ] {
            assert!(
                !audit_text.contains(needle),
                "audit must be clean but mentioned {needle:?}:\n{audit_text}"
            );
        }

        const EXPECTED: &str = "via_alias=two-longer\ntree_exists=false\n";

        // Runs deterministically: byte-identical across repeated same-seed runs at
        // several seeds. The hard link observes the mutation (same inode) and the
        // tree is gone.
        for seed in ["0", "3", "8"] {
            let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
            assert_eq!(
                baseline, EXPECTED,
                "unexpected hard-link/remove-tree output at seed {seed}: {baseline}"
            );
            for _ in 0..2 {
                let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
                assert_eq!(
                    baseline,
                    String::from_utf8_lossy(&again.stdout),
                    "output not byte-identical across runs at seed {seed}"
                );
            }
        }

        // A recorded run replays byte-identically under strict replay.
        let trace = directory.path().join("hard-link.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "8",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "hard-link-tree",
            ],
        );
        assert_eq!(String::from_utf8_lossy(&recorded.stdout), EXPECTED);
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "hard-link-tree",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "record and strict replay diverged"
        );
    }

    // A guest that reads a file the supervisor mounted into the deterministic
    // filesystem. Used to exercise `--mount` composing with `--record`/`replay`,
    // which hands the child TWO inherited descriptors at once.
    const MOUNT_READER_SOURCE: &str = r#"
use std::fs;

fn main() {
    let contents = fs::read_to_string("/data.txt").expect("read mounted file");
    print!("{contents}");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_mount_composes_with_record_and_replay_two_inherited_descriptors() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("read_mount.rs");
        fs::write(&source, MOUNT_READER_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("read-mount");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let mount = directory.path().join("corpus");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join("data.txt"), "MOUNTED-CONTENT\n").unwrap();

        let trace = directory.path().join("mount.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "0",
                "--mount",
                mount.to_str().unwrap(),
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "read-mount",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            "MOUNTED-CONTENT\n",
            "record mode with --mount did not see the mounted file"
        );

        // `replay` re-supplies the host corpus with --mount (a host input the trace
        // cannot carry; only its hash is in the fingerprint). The seed and everything
        // else come from the trace, so the run reproduces byte-identically.
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--mount",
                mount.to_str().unwrap(),
                "--fingerprint",
                "read-mount",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&replayed.stdout),
            "MOUNTED-CONTENT\n",
            "strict replay with --mount diverged from the recorded run"
        );

        // A DIFFERENT corpus at replay hashes to a different image, so the hash
        // folded into the fingerprint no longer matches and replay must fail closed —
        // and say WHY (the specific fingerprint mismatch), not abort mutely with the
        // generic "no runtime installed" line.
        let other_mount = directory.path().join("corpus-other");
        fs::create_dir(&other_mount).unwrap();
        fs::write(other_mount.join("data.txt"), "DIFFERENT-CONTENT\n").unwrap();
        let cross = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--mount",
                other_mount.to_str().unwrap(),
                "--fingerprint",
                "read-mount",
            ],
        );
        let cross_stderr = String::from_utf8_lossy(&cross.stderr);
        assert!(
            !cross.status.success(),
            "replay against a different --mount corpus must fail closed:\nstderr:\n{cross_stderr}"
        );
        assert!(
            cross_stderr.contains("failed to initialize")
                && cross_stderr.contains("fingerprint mismatch"),
            "cross-corpus replay must name the fingerprint mismatch, not abort mutely:\nstderr:\n{cross_stderr}"
        );
        // The named mismatch carries the corpus image hash (`+fsimg:<hash>`): it is
        // the recorded corpus's hash that no longer matches the substituted one, so
        // the fail-closed reason points squarely at the corpus, not a generic error.
        assert!(
            cross_stderr.contains("+fsimg:"),
            "the fingerprint mismatch must name the corpus image hash (+fsimg:):\nstderr:\n{cross_stderr}"
        );
    }

    // A guest that opens the SAME file twice and takes an advisory `flock` on each
    // descriptor. The interposed `flock` keys on the deterministic-fs inode, so the
    // second `LOCK_EX | LOCK_NB` must report EWOULDBLOCK (-1) — the contention a
    // single-opener database's open surfaces as an "already open" error — rather than
    // both succeeding as a naive always-0 stub would — and it must report it in
    // libc `errno` (EWOULDBLOCK: 11 on Linux, 35 on Darwin), which is what std's
    // `File::try_lock` reads to say `WouldBlock`; the shim keeps its own thread-local
    // errno, so a C entry that forwards a `patina_*` result without `fail_int` leaves
    // libc errno STALE (the class: every `-1`-returning interposer must translate —
    // `flock` itself did not until this pinned it; the same `fail_int` guards the
    // `fcntl` OFD arm that shares the lock table). Closing the first descriptor
    // releases the lock, so a third opener then acquires it, proving
    // release-on-close.
    const FLOCK_CONTENTION_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

fn try_lock(file: &File) -> i32 {
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) }
}

fn main() {
    let first = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/lock.db")
        .unwrap();
    let first_lock = try_lock(&first);
    let second = File::open("/lock.db").unwrap();
    let second_lock = try_lock(&second);
    let second_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    drop(first);
    let third = File::open("/lock.db").unwrap();
    let third_lock = try_lock(&third);
    println!("FLOCK first={first_lock} second={second_lock}/{second_errno} third={third_lock}");
}
"#;

    // The per-inode advisory-lock table: a second open of the same path contends the
    // first's `LOCK_EX`, and closing the first releases it. A single-opener path
    // still acquires cleanly; this is the can-fail half.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_flock_contends_on_a_second_open_and_releases_on_close() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("flock.rs");
        fs::write(&source, FLOCK_CONTENTION_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("flock");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let stdout = String::from_utf8_lossy(&run.stdout);
        let ewouldblock = if cfg!(target_os = "macos") { 35 } else { 11 };
        assert!(
            stdout.contains(&format!("FLOCK first=0 second=-1/{ewouldblock} third=0")),
            "per-inode flock must contend the second open (EWOULDBLOCK in libc errno) and release on close:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stderr),
        );
    }

    // The lone opener's POSIX record locks. A run is ONE process and process-scoped
    // record locks never conflict with locks their own process holds (POSIX merges
    // them; any close releases them all), so `F_SETLK`/`F_SETLKW` on an open regular
    // fd succeed and `F_GETLK` reports the range `F_UNLCK` — exactly what the lone
    // opener sees on the host (the open-time whole-file lock a storage engine takes
    // through rustix `fcntl_lock`). Left unmodeled, the lock was `ENOSYS` and the
    // engine aborted at unlock. The modeled answer is not a blanket 0: a bogus lock
    // type is `EINVAL` and captured stdio is `EBADF`. `struct flock` and the command
    // numbers differ between Linux and Darwin, so the guest carries both ABIs.
    const FCNTL_RECORD_LOCK_SOURCE: &str = r#"
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
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
use abi::*;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/locked.db")
        .unwrap();
    let fd = file.as_raw_fd();
    let mut lock = whole(F_WRLCK);
    let setlk = unsafe { fcntl(fd, F_SETLK, &mut lock as *mut Flock) };
    let mut probe = whole(F_WRLCK);
    let getlk = unsafe { fcntl(fd, F_GETLK, &mut probe as *mut Flock) };
    let mut again = whole(F_RDLCK);
    let setlkw = unsafe { fcntl(fd, F_SETLKW, &mut again as *mut Flock) };
    let mut unlock = whole(F_UNLCK);
    let unlck = unsafe { fcntl(fd, F_SETLK, &mut unlock as *mut Flock) };
    let mut bogus = whole(7);
    let bad_type = unsafe { fcntl(fd, F_SETLK, &mut bogus as *mut Flock) };
    let bad_type_errno = errno();
    // A READ lock on the write-only standard output is EBADF: fcntl_setlk
    // checks the lock type against the description's access mode.
    let mut stdio = whole(F_RDLCK);
    let on_stdio = unsafe { fcntl(1, F_SETLK, &mut stdio as *mut Flock) };
    let stdio_errno = errno();
    println!(
        "FCNTL_LOCK setlk={setlk} getlk={getlk} getlk_type={} setlkw={setlkw} unlck={unlck} bad_type={bad_type}/{bad_type_errno} stdio={on_stdio}/{stdio_errno}",
        probe.l_type
    );
    #[cfg(target_os = "linux")]
    {
        const F_OFD_GETLK: i32 = 36;
        const F_OFD_SETLK: i32 = 37;
        // Open-file-description locks DO contend inside one process: a second
        // open's whole-file F_OFD_SETLK meets the first's and reports EAGAIN;
        // a byte-range lock through the holder joins its own lock, and
        // F_OFD_GETLK through it finds no other owner's; the first
        // description's release lets the second acquire. (errno is printed
        // after each call and a success leaves it alone, so it still reads
        // the EAGAIN.) The second opener is read-write: a write lock needs a
        // writable description (fcntl_setlk's access-mode check answers EBADF
        // otherwise).
        let mut first = whole(F_WRLCK);
        let ofd_first = unsafe { fcntl(fd, F_OFD_SETLK, &mut first as *mut Flock) };
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/locked.db")
            .unwrap();
        let mut contend = whole(F_WRLCK);
        let ofd_second =
            unsafe { fcntl(second.as_raw_fd(), F_OFD_SETLK, &mut contend as *mut Flock) };
        let ofd_second_errno = errno();
        let mut range = Flock { l_len: 16, ..whole(F_WRLCK) };
        let ofd_range = unsafe { fcntl(fd, F_OFD_SETLK, &mut range as *mut Flock) };
        let ofd_range_errno = errno();
        let mut get = whole(F_WRLCK);
        let ofd_getlk = unsafe { fcntl(fd, F_OFD_GETLK, &mut get as *mut Flock) };
        let ofd_getlk_errno = errno();
        let mut release = whole(F_UNLCK);
        let ofd_release = unsafe { fcntl(fd, F_OFD_SETLK, &mut release as *mut Flock) };
        let mut retry = whole(F_WRLCK);
        let ofd_retry =
            unsafe { fcntl(second.as_raw_fd(), F_OFD_SETLK, &mut retry as *mut Flock) };
        println!(
            "FCNTL_OFD first={ofd_first} second={ofd_second}/{ofd_second_errno} range={ofd_range}/{ofd_range_errno} getlk={ofd_getlk}/{ofd_getlk_errno} release={ofd_release} retry={ofd_retry}"
        );
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fcntl_record_locks_are_modeled_for_the_lone_opener() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("fcntl_lock.rs");
        fs::write(&source, FCNTL_RECORD_LOCK_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("fcntl-lock");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stdout.contains(
                "FCNTL_LOCK setlk=0 getlk=0 getlk_type=2 setlkw=0 unlck=0 bad_type=-1/22 stdio=-1/9"
            ),
            "the lone opener's record locks must be taken, reported unlocked, and released — and bad input refused:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                stdout.contains(
                    "FCNTL_OFD first=0 second=-1/11 range=0/11 getlk=0/11 release=0 retry=0"
                ),
                "an OFD lock must contend across descriptions, the holder's byte-range lock and F_OFD_GETLK must succeed, and release must let the second opener in:\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }
    }

    // Positional vectored I/O: ONE `pwritev` of two frames lands at the given offset
    // without moving the cursor (a database backend batches a transaction's WAL
    // frames this way), `preadv` reads them back across two buffers, a read past
    // the end is short, and stdout has no offset (`ESPIPE`). Before these were
    // interposed, `pwritev` was the gate's planted *uninterposed* filesystem
    // representative — a guest reaching it was refused pre-run.
    const POSITIONAL_VECTORED_IO_SOURCE: &str = r#"
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
    fn preadv(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
}

fn main() {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/wal")
        .unwrap();
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
    let espipe_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!(
        "PVEC wrote={wrote} cursor={cursor} read={read} a={} b={} file={whole} short={short} stdout={espipe}/{espipe_errno}",
        String::from_utf8_lossy(&a),
        String::from_utf8_lossy(&b)
    );
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_positional_vectored_io_round_trips_through_the_deterministic_fs() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("pvec.rs");
        fs::write(&source, POSITIONAL_VECTORED_IO_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("pvec");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            stdout.contains(
                "PVEC wrote=4 cursor=7 read=7 a=1AB b=CD67 file=01ABCD6789 short=2 stdout=-1/29"
            ),
            "pwritev/preadv must be positional, cursor-independent, short at EOF, and ESPIPE on stdout:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    // `statfs`/`fstatfs` (Linux): the virtual filesystem answers as ONE constant
    // ext4-like volume for any path or descriptor that resolves, ENOENT for a
    // missing path, EBADF for a bad descriptor. A storage engine probes this on
    // every open to decide whether the path's filesystem supports its multi-process
    // coordination; left unmodeled, the call reached the HOST with a virtual path
    // and the engine refused to open at all.
    #[cfg(target_os = "linux")]
    const STATFS_SOURCE: &str = r#"
use std::os::unix::io::AsRawFd;

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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    std::fs::create_dir_all("/db").unwrap();
    std::fs::write("/db/wal", b"frame").unwrap();
    let mut by_path = Statfs::default();
    let path_rc = unsafe { statfs(b"/db/wal\0".as_ptr(), &mut by_path) };
    let mut missing = Statfs::default();
    let missing_rc = unsafe { statfs(b"/db/nope\0".as_ptr(), &mut missing) };
    let missing_errno = errno();
    let file = std::fs::File::open("/db/wal").unwrap();
    let mut by_fd = Statfs::default();
    let fd_rc = unsafe { fstatfs(file.as_raw_fd(), &mut by_fd) };
    let mut closed = Statfs::default();
    let bad_rc = unsafe { fstatfs(4242, &mut closed) };
    println!(
        "STATFS path={path_rc} type={:#x} bsize={} namelen={} missing={missing_rc}/{missing_errno} fd={fd_rc} fd_type={:#x} bad={bad_rc}",
        by_path.f_type, by_path.f_bsize, by_path.f_namelen, by_fd.f_type
    );
}
"#;

    #[cfg(target_os = "linux")]
    #[test]
    fn native_statfs_answers_as_one_virtual_volume() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("statfs.rs");
        fs::write(&source, STATFS_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("statfs");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
        stdout.contains(
            "STATFS path=0 type=0xef53 bsize=4096 namelen=255 missing=-1/2 fd=0 fd_type=0xef53 bad=-1"
        ),
        "statfs/fstatfs must answer as one virtual ext4-like volume, ENOENT a missing path, and EBADF a bad fd:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    }

    // `std::fs::canonicalize` on macOS reaches `realpath(path, NULL)` (the
    // allocating convention) and on Linux `realpath(path, buf)`; both must resolve
    // an existing guest path to the same canonical absolute spelling driven purely
    // by the deterministic filesystem. The guest canonicalizes the path two ways --
    // its exact spelling and a `..`/`.`/`//`-laden spelling of the same directory --
    // so the assertion catches both the destination==NULL ENOSYS regression and a
    // verbatim (non-canonicalizing) result.
    const CANONICALIZE_SOURCE: &str = r#"
use std::fs;

fn main() {
    fs::create_dir_all("/tmp/patina-root/fragments").unwrap();
    let direct = fs::canonicalize("/tmp/patina-root/fragments").unwrap();
    let noisy = fs::canonicalize("/tmp/patina-root/../patina-root/./fragments//").unwrap();
    println!("direct={}", direct.display());
    println!("noisy={}", noisy.display());
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_canonicalize_resolves_an_existing_guest_path_deterministically() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("canonicalize.rs");
        fs::write(&source, CANONICALIZE_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("canonicalize");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let first_stdout = String::from_utf8_lossy(&first.stdout);
        assert!(
            first_stdout.contains("direct=/tmp/patina-root/fragments")
                && first_stdout.contains("noisy=/tmp/patina-root/fragments"),
            "canonicalize must resolve both spellings to the same canonical guest path:\nstdout:\n{first_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stderr),
        );
        let second = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert_eq!(
            first.stdout,
            second.stdout,
            "a same-seed canonicalize run must be byte-identical:\nstderr:\n{}",
            String::from_utf8_lossy(&second.stderr),
        );
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
