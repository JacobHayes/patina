//! Native descriptor-table semantics and file operations Linux performs atomically:
//! appends, vectored I/O, descriptor reservation at the limit and across waits.

// Every case is a Linux descriptor-table behaviour.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::*;

    // Three threads append records to one file, each through a different append
    // spelling: `pwrite` through an `O_APPEND` description (which Linux lands at the
    // end whatever the offset), a two-segment `pwritev` through it, and a
    // two-segment `pwritev2(.., -1, RWF_APPEND)` through a plain description. Linux
    // reads the end and writes the whole call under `inode_lock`, so no record is
    // lost, overwritten, or split, whatever the interleaving.
    const CONCURRENT_APPEND_SOURCE: &str = r#"
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
    fn syscall(number: i64, ...) -> i64;
}

// glibc's `pwritev2` wrapper is not interposed; the raw syscall is.
#[cfg(target_arch = "x86_64")]
const SYS_PWRITEV2: i64 = 328;
#[cfg(target_arch = "aarch64")]
const SYS_PWRITEV2: i64 = 287;
const RWF_APPEND: i64 = 0x10;

/// `pwritev2(fd, iov, 2, -1, RWF_APPEND)`: the kernel's `pos_l`/`pos_h` pair
/// carries the position.
unsafe fn append_at_cursor(fd: i32, iov: &[Iovec; 2]) -> isize {
    unsafe { syscall(SYS_PWRITEV2, i64::from(fd), iov.as_ptr(), 2_i64, -1_i64, 0_i64, RWF_APPEND) as isize }
}
const WRITERS: usize = 3;
const ROUNDS: usize = 16;

fn record(writer: usize, round: usize) -> String {
    format!("w{writer}r{round:02}\n")
}

fn halves(bytes: &[u8]) -> [Iovec; 2] {
    let (head, tail) = bytes.split_at(bytes.len() / 2);
    [
        Iovec { base: head.as_ptr(), len: head.len() },
        Iovec { base: tail.as_ptr(), len: tail.len() },
    ]
}

fn main() {
    let path = "/appended";
    let appending = Arc::new(OpenOptions::new().create(true).append(true).open(path).unwrap());
    let plain = Arc::new(OpenOptions::new().write(true).open(path).unwrap());
    let writers: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let appending = Arc::clone(&appending);
            let plain = Arc::clone(&plain);
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let line = record(writer, round);
                    let bytes = line.as_bytes();
                    let wrote = match writer {
                        0 => appending.write_at(bytes, 0).unwrap() as isize,
                        1 => unsafe { pwritev(appending.as_raw_fd(), halves(bytes).as_ptr(), 2, 0) },
                        _ => unsafe { append_at_cursor(plain.as_raw_fd(), &halves(bytes)) },
                    };
                    assert_eq!(wrote, bytes.len() as isize, "writer {writer} round {round}");
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let contents = std::fs::read_to_string(path).unwrap();
    let mut found: Vec<&str> = contents.split_inclusive('\n').collect();
    found.sort_unstable();
    let mut expected: Vec<String> = (0..WRITERS)
        .flat_map(|writer| (0..ROUNDS).map(move |round| record(writer, round)))
        .collect();
    expected.sort_unstable();
    println!(
        "APPEND len={} expected={} intact={}",
        contents.len(),
        expected.iter().map(String::len).sum::<usize>(),
        found == expected
    );
}
"#;

    /// The `APPEND` line's `name=` field.
    fn append_field<'a>(stdout: &'a str, name: &str) -> &'a str {
        let line = stdout
            .lines()
            .find(|line| line.starts_with("APPEND "))
            .unwrap_or_else(|| panic!("no APPEND line:\n{stdout}"));
        line.split(' ')
            .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("APPEND line carries no {name}=: {line}"))
    }

    #[test]
    fn native_concurrent_appends_lose_no_bytes_under_pct_interleavings() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("concurrent_append.rs");
        fs::write(&source, CONCURRENT_APPEND_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("concurrent-append");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap();
        // The seeded scheduler, and PCT with its change points spread over the
        // run's ~150 decisions rather than the default 2000 the run never reaches.
        let pct = ["--sched-pct=2", "--sched-pct-steps", "150"];
        for schedule in [&[][..], &pct[..]] {
            for seed in ["1", "2", "3", "4"] {
                let mut args = vec!["run", bin, "--seed", seed];
                args.extend_from_slice(schedule);
                let run = invoke(workspace, &args);
                let stdout = String::from_utf8_lossy(&run.stdout);
                assert_eq!(
                    append_field(&stdout, "len"),
                    append_field(&stdout, "expected"),
                    "seed {seed} {schedule:?} lost appended bytes:\n{stdout}"
                );
                assert_eq!(
                    append_field(&stdout, "intact"),
                    "true",
                    "seed {seed} {schedule:?} overwrote or split a record:\n{stdout}"
                );
            }
        }

        let trace = directory.path().join("append.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "1",
                "--sched-pct=2",
                "--sched-pct-steps",
                "150",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "record and replay diverged"
        );
    }

    // With one number free, one thread creates a file while another takes the
    // number with `dup`. Linux reserves the number before the open walks or
    // creates anything, so whichever loses gets EMFILE, and an open that
    // answers EMFILE has created nothing, whatever the interleaving.
    const CONTENDED_LAST_NUMBER_SOURCE: &str = r#"
use std::os::fd::IntoRawFd;

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
}

const RLIMIT_NOFILE: i32 = 7;
const EMFILE: i32 = 24;
const ROUNDS: usize = 12;

fn main() {
    let mut limit = [0_u64; 2];
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
    let lowest = unsafe { dup(0) };
    assert!(lowest >= 0);
    unsafe { close(lowest) };
    let one_free = [lowest as u64 + 1, limit[1]];
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &one_free) }, 0);
    let (mut refused, mut created_anyway) = (0, 0);
    for round in 0..ROUNDS {
        let path = format!("/contended-{round}");
        let opener = {
            let path = path.clone();
            std::thread::spawn(move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map(IntoRawFd::into_raw_fd)
                    .map_err(|error| error.raw_os_error())
            })
        };
        let duplicator = std::thread::spawn(|| unsafe { dup(0) });
        let opened = opener.join().unwrap();
        let duplicate = duplicator.join().unwrap();
        if opened == Err(Some(EMFILE)) {
            refused += 1;
            if std::path::Path::new(&path).exists() {
                created_anyway += 1;
            }
        }
        if let Ok(fd) = opened {
            unsafe { close(fd) };
        }
        if duplicate >= 0 {
            unsafe { close(duplicate) };
        }
    }
    println!("CONTENDED refused={refused} created_anyway={created_anyway}");
}
"#;

    #[test]
    fn native_open_refused_at_the_descriptor_limit_creates_nothing_under_contention() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("contended_last_number.rs");
        fs::write(&source, CONTENDED_LAST_NUMBER_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("contended-last-number");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let field = |stdout: &str, name: &str| -> u64 {
            stdout
                .lines()
                .find(|line| line.starts_with("CONTENDED "))
                .and_then(|line| {
                    line.split(' ')
                        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
                })
                .unwrap_or_else(|| panic!("no CONTENDED {name}= field:\n{stdout}"))
                .parse()
                .unwrap()
        };
        let mut refused = 0;
        for seed in ["1", "2", "3"] {
            let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let stdout = String::from_utf8_lossy(&run.stdout);
            assert_eq!(
                field(&stdout, "created_anyway"),
                0,
                "seed {seed}: an open that answered EMFILE created its file:\n{stdout}"
            );
            refused += field(&stdout, "refused");
        }
        assert!(refused > 0, "no seed made the open lose the last number");
    }

    // With the table full, one thread retries an open while a peer closes the
    // descriptor that fills it. A refused open is still a boundary call and so a
    // scheduling point, so the peer runs and the retry succeeds.
    const RETRY_AT_THE_DESCRIPTOR_LIMIT_SOURCE: &str = r#"
unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
}

const RLIMIT_NOFILE: i32 = 7;
const ATTEMPTS: usize = 10_000;

fn main() {
    let mut limit = [0_u64; 2];
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
    let last = unsafe { dup(0) };
    assert!(last >= 0);
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &[last as u64 + 1, limit[1]]) }, 0);
    let closer = std::thread::spawn(move || unsafe { close(last) });
    let attempts = (1..=ATTEMPTS).find(|_| std::fs::File::create("/retried").is_ok());
    assert_eq!(closer.join().unwrap(), 0);
    println!("RETRY opened={}", attempts.is_some());
}
"#;

    #[test]
    fn native_open_retried_at_the_descriptor_limit_lets_a_closing_peer_run() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("retry_at_limit.rs");
        fs::write(&source, RETRY_AT_THE_DESCRIPTOR_LIMIT_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("retry-at-limit");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        for seed in ["1", "2", "3", "4"] {
            let run = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let stdout = String::from_utf8_lossy(&run.stdout);
            assert!(
                stdout.lines().any(|line| line == "RETRY opened=true"),
                "seed {seed}: the retrying open never let the closing peer run:\n{stdout}"
            );
        }
    }

    /// Build the single-file guest `source` as `name` under `directory`.
    fn built_guest(directory: &Path, name: &str, source: &str) -> PathBuf {
        let source_path = directory.join(format!("{name}.rs"));
        fs::write(&source_path, source).unwrap();
        let bin = directory.join(name);
        invoke(
            native_workspace(),
            &[
                "build",
                source_path.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        bin
    }

    /// The stdout lines of `output` that start with `prefix`.
    fn lines_with(output: &Output, prefix: &str) -> Vec<String> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.starts_with(prefix))
            .map(str::to_owned)
            .collect()
    }

    /// Run `bin` at each seed (the seeded scheduler, then PCT with its change
    /// points spread over a short run), and once recorded and replayed: each
    /// run's `prefix` lines must be `expected`, and the replay's the record's.
    fn assert_runs_answer(bin: &Path, prefix: &str, expected: &[&str]) {
        let workspace = native_workspace();
        let bin = bin.to_str().unwrap();
        let pct = ["--sched-pct=2", "--sched-pct-steps", "150"];
        for schedule in [&[][..], &pct[..]] {
            for seed in ["1", "2", "3"] {
                let mut args = vec!["run", bin, "--seed", seed];
                args.extend_from_slice(schedule);
                let run = invoke(workspace, &args);
                assert_eq!(
                    lines_with(&run, prefix),
                    expected,
                    "seed {seed} {schedule:?}:\n{}",
                    String::from_utf8_lossy(&run.stdout)
                );
            }
        }
        let trace = Path::new(bin).with_extension("patina");
        let mut args = vec![
            "run",
            bin,
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ];
        args.extend_from_slice(&pct);
        let recorded = invoke(workspace, &args);
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "record and replay diverged"
        );
    }

    // Three threads `writev` two-segment records through one `O_APPEND`
    // description, then three threads `readv` record-sized two-segment vectors
    // through one shared description of the result. Linux writes a vector under
    // `inode_lock` and reads one under the description's `f_pos_lock`, so no
    // record is split by another thread's segment, either way.
    const VECTORED_RECORDS_SOURCE: &str = r#"
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn writev(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize;
    fn readv(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize;
}

const THREADS: usize = 3;
const ROUNDS: usize = 16;
const HALF: usize = 3;

/// Six bytes: two halves of three.
fn record(thread: usize, round: usize) -> String {
    format!("t{thread}r{round:02}\n")
}

fn main() {
    let path = "/vectored";
    let appending = Arc::new(OpenOptions::new().create(true).append(true).open(path).unwrap());
    let writers: Vec<_> = (0..THREADS)
        .map(|thread| {
            let appending = Arc::clone(&appending);
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let line = record(thread, round);
                    let (head, tail) = line.as_bytes().split_at(HALF);
                    let iov = [
                        Iovec { base: head.as_ptr(), len: HALF },
                        Iovec { base: tail.as_ptr(), len: HALF },
                    ];
                    let wrote = unsafe { writev(appending.as_raw_fd(), iov.as_ptr(), 2) };
                    assert_eq!(wrote, line.len() as isize);
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let contents = std::fs::read_to_string(path).unwrap();
    let mut found: Vec<&str> = contents.split_inclusive('\n').collect();
    found.sort_unstable();
    let mut expected: Vec<String> = (0..THREADS)
        .flat_map(|thread| (0..ROUNDS).map(move |round| record(thread, round)))
        .collect();
    expected.sort_unstable();
    println!("VECTORED writev_records_intact={}", found == expected);

    let reading = Arc::new(OpenOptions::new().read(true).open(path).unwrap());
    let readers: Vec<_> = (0..THREADS)
        .map(|_| {
            let reading = Arc::clone(&reading);
            std::thread::spawn(move || {
                let mut whole = true;
                loop {
                    let (mut head, mut tail) = ([0u8; HALF], [0u8; HALF]);
                    let iov = [
                        Iovec { base: head.as_mut_ptr(), len: HALF },
                        Iovec { base: tail.as_mut_ptr(), len: HALF },
                    ];
                    let got = unsafe { readv(reading.as_raw_fd(), iov.as_ptr(), 2) };
                    if got <= 0 {
                        break;
                    }
                    let bytes = [&head[..], &tail[..]].concat();
                    whole &= got == 2 * HALF as isize
                        && bytes[0] == b't'
                        && bytes[2 * HALF - 1] == b'\n'
                        && !bytes[1..].contains(&b't');
                }
                whole
            })
        })
        .collect();
    let whole = readers.into_iter().all(|reader| reader.join().unwrap());
    println!("VECTORED readv_records_whole={whole}");
}
"#;

    #[test]
    fn native_vectored_file_io_moves_each_vector_in_one_step() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "vectored", VECTORED_RECORDS_SOURCE);
        assert_runs_answer(
            &bin,
            "VECTORED ",
            &[
                "VECTORED writev_records_intact=true",
                "VECTORED readv_records_whole=true",
            ],
        );
    }

    // One thread blocks in `accept` while the main thread opens a file and then
    // connects. Linux takes the accepted descriptor's number before the wait,
    // so the file numbers after it, and the connection gets its descriptor.
    const ACCEPT_RESERVES_SOURCE: &str = r#"
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

fn main() {
    let listener = UnixListener::bind("/accept.sock").unwrap();
    let acceptor = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream.into_raw_fd()));
    std::thread::sleep(Duration::from_millis(50));
    let file = std::fs::File::create("/during-accept").unwrap();
    let _client = UnixStream::connect("/accept.sock").unwrap();
    let accepted = acceptor.join().unwrap().unwrap();
    println!("ACCEPT numbered_before_the_wait={}", accepted < file.as_raw_fd());
}
"#;

    #[test]
    fn native_accept_takes_its_number_before_it_waits() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "accept-reserves", ACCEPT_RESERVES_SOURCE);
        assert_runs_answer(&bin, "ACCEPT ", &["ACCEPT numbered_before_the_wait=true"]);
    }

    // One thread blocks opening a FIFO for reading; while it waits, the main
    // thread asks about the number the open will get, opens a file and tries
    // to `dup2` it over that number, then opens the FIFO for writing. Linux
    // holds the number for the waiting open without binding it: it names
    // nothing (`EBADF`), cannot be taken over (`EBUSY`), and is the reader's
    // once the open completes.
    const FIFO_RESERVES_SOURCE: &str = r#"
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::time::Duration;

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn dup2(from: i32, to: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
}

const F_GETFD: i32 = 1;

fn errno_of(result: i32) -> i32 {
    if result < 0 { std::io::Error::last_os_error().raw_os_error().unwrap() } else { 0 }
}

fn main() {
    assert_eq!(unsafe { mkfifo(c"/fifo".as_ptr(), 0o600) }, 0);
    let next = unsafe { dup(0) };
    unsafe { close(next) };
    let reader = std::thread::spawn(|| std::fs::File::open("/fifo").unwrap().into_raw_fd());
    std::thread::sleep(Duration::from_millis(50));
    let getfd = errno_of(unsafe { fcntl(next, F_GETFD) });
    let file = std::fs::File::create("/during-fifo").unwrap();
    let dup2 = errno_of(unsafe { dup2(file.as_raw_fd(), next) });
    let writer = std::fs::OpenOptions::new().write(true).open("/fifo").unwrap();
    let read_end = reader.join().unwrap();
    println!("FIFO waiting getfd_errno={getfd} dup2_errno={dup2}");
    println!("FIFO opened reader_has_the_number={}", read_end == next);
    drop(writer);
}
"#;

    #[test]
    fn native_fifo_open_holds_its_number_unbound_while_it_waits() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "fifo-reserves", FIFO_RESERVES_SOURCE);
        assert_runs_answer(
            &bin,
            "FIFO ",
            &[
                "FIFO waiting getfd_errno=9 dup2_errno=16",
                "FIFO opened reader_has_the_number=true",
            ],
        );
    }

    // A blocking `accept` and a FIFO open interrupted by a handler that takes
    // a number: the call lets its number go before the handler runs, as the
    // kernel's `ERESTARTSYS` exit does, and a restarted call takes the lowest
    // free number again.
    const SIGNALED_WAIT_SOURCE: &str = r#"
use std::ffi::CString;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

#[repr(C)]
struct Action {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

unsafe extern "C" {
    fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    fn unlink(path: *const std::ffi::c_char) -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn pthread_self() -> usize;
    fn pthread_kill(thread: usize, sig: i32) -> i32;
    fn sigaction(sig: i32, action: *const Action, old: *mut Action) -> i32;
    fn __errno_location() -> *mut i32;
}

const SIGUSR1: i32 = 10;
const SA_RESTART: i32 = 0x1000_0000;
const O_WRONLY: i32 = 1;
const O_NONBLOCK: i32 = 0o4000;
static HANDLER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handler(_: i32) {
    HANDLER.store(unsafe { socket(1, 1, 0) }, Ordering::SeqCst);
}

/// Interrupt `wait` with a handler that takes a number, then (on restart)
/// let `partner` end the wait. Prints where the handler's number and the
/// call's answer land relative to the lowest free number before the call.
fn case(name: &str, restart: bool, wait: impl FnOnce() -> i32, partner: impl FnOnce() -> i32 + Send + 'static) {
    let first = unsafe { dup(0) };
    unsafe { close(first) };
    let action = Action {
        handler: handler as *const () as usize,
        mask: [0; 16],
        flags: if restart { SA_RESTART } else { 0 },
        restorer: 0,
    };
    assert_eq!(unsafe { sigaction(SIGUSR1, &action, std::ptr::null_mut()) }, 0);
    let me = unsafe { pthread_self() };
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(unsafe { pthread_kill(me, SIGUSR1) }, 0);
        if restart {
            std::thread::sleep(Duration::from_millis(10));
            partner()
        } else {
            -1
        }
    });
    let result = wait();
    let errno = unsafe { *__errno_location() };
    let partner = sender.join().unwrap();
    let handler = HANDLER.swap(-1, Ordering::SeqCst);
    let answer = if result >= 0 {
        format!("fd=first+{}", result - first)
    } else {
        format!("errno={errno}")
    };
    println!("SIGWAIT {name} restart={restart} handler=first+{} {answer}", handler - first);
    for fd in [handler, result, partner] {
        if fd >= 0 {
            unsafe { close(fd) };
        }
    }
}

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let listening = listener.as_raw_fd();
    let directory = std::env::args().nth(1).unwrap_or_default();
    let path = CString::new(format!("{directory}/sigwait-fifo")).unwrap();
    unsafe { unlink(path.as_ptr()) };
    assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
    for restart in [false, true] {
        case(
            "accept",
            restart,
            || unsafe { accept(listening, std::ptr::null_mut(), std::ptr::null_mut()) },
            move || std::net::TcpStream::connect(address).unwrap().into_raw_fd(),
        );
        let reader = path.clone();
        let writer = path.clone();
        case(
            "fifo_open",
            restart,
            move || unsafe { open(reader.as_ptr(), 0) },
            move || unsafe { open(writer.as_ptr(), O_WRONLY | O_NONBLOCK) },
        );
    }
    unsafe { unlink(path.as_ptr()) };
}
"#;

    #[test]
    fn native_waits_interrupted_by_a_handler_let_their_number_go_first() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "signaled-wait", SIGNALED_WAIT_SOURCE);
        assert_runs_answer(
            &bin,
            "SIGWAIT ",
            &[
                "SIGWAIT accept restart=false handler=first+0 errno=4",
                "SIGWAIT fifo_open restart=false handler=first+0 errno=4",
                "SIGWAIT accept restart=true handler=first+0 fd=first+1",
                "SIGWAIT fifo_open restart=true handler=first+0 fd=first+1",
            ],
        );
    }

    // `close_range` over the number a waiting FIFO open holds: closing leaves
    // it held, and `CLOSE_RANGE_CLOEXEC` marks the descriptor the open binds
    // there, as the kernel's bitmap marks the reserved slot.
    const FIFO_RANGE_SOURCE: &str = r#"
use std::ffi::CString;
use std::time::Duration;

unsafe extern "C" {
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    fn unlink(path: *const std::ffi::c_char) -> i32;
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn close_range(first: u32, last: u32, flags: i32) -> i32;
    fn __errno_location() -> *mut i32;
}

const F_GETFD: i32 = 1;
const O_WRONLY: i32 = 1;
const O_NONBLOCK: i32 = 0o4000;
const CLOSE_RANGE_CLOEXEC: i32 = 4;

fn main() {
    let directory = std::env::args().nth(1).unwrap_or_default();
    let path = CString::new(format!("{directory}/range-fifo")).unwrap();
    unsafe { unlink(path.as_ptr()) };
    assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
    let first = unsafe { dup(0) };
    assert_eq!(unsafe { close(first) }, 0);
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || unsafe { open(reader_path.as_ptr(), 0) });
    // The waiting reader holds `first` once a probe numbers past it.
    let held = (0..1000).any(|_| {
        let probe = unsafe { dup(0) };
        unsafe { close(probe) };
        probe > first || {
            std::thread::sleep(Duration::from_millis(1));
            false
        }
    });
    assert!(held);
    let getfd = unsafe { fcntl(first, F_GETFD) };
    let getfd_errno = unsafe { *__errno_location() };
    // Closing a range over the held number leaves it held; marking it
    // close-on-exec marks the descriptor the open binds there.
    assert_eq!(unsafe { close_range(first as u32, first as u32, 0) }, 0);
    assert_eq!(unsafe { close_range(first as u32, u32::MAX, CLOSE_RANGE_CLOEXEC) }, 0);
    let writer = unsafe { open(path.as_ptr(), O_WRONLY | O_NONBLOCK) };
    assert!(writer >= 0);
    let fd = reader.join().unwrap();
    let flags = unsafe { fcntl(fd, F_GETFD) };
    println!(
        "FIFO_RANGE getfd={getfd} errno={getfd_errno} reader=first+{} cloexec={flags}",
        fd - first
    );
    unsafe {
        close(fd);
        close(writer);
        unlink(path.as_ptr());
    }
}
"#;

    #[test]
    fn native_fifo_open_held_number_takes_close_range_updates() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "fifo-range", FIFO_RANGE_SOURCE);
        assert_runs_answer(
            &bin,
            "FIFO_RANGE ",
            &["FIFO_RANGE getfd=-1 errno=9 reader=first+0 cloexec=1"],
        );
    }

    // With one number free, one thread retries `pipe` (which needs two) while
    // a peer closes a descriptor. A refused `pipe` is a scheduling point, so
    // the peer runs and a retry succeeds.
    const PIPE_RETRY_SOURCE: &str = r#"
unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
}

const RLIMIT_NOFILE: i32 = 7;
const ATTEMPTS: usize = 10_000;

fn main() {
    let mut limit = [0_u64; 2];
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
    let last = unsafe { dup(0) };
    assert!(last >= 0);
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &[last as u64 + 2, limit[1]]) }, 0);
    let closer = std::thread::spawn(move || unsafe { close(last) });
    let mut fds = [0_i32; 2];
    let created = (1..=ATTEMPTS).any(|_| unsafe { pipe(fds.as_mut_ptr()) } == 0);
    assert_eq!(closer.join().unwrap(), 0);
    println!("PIPE_RETRY created={created}");
}
"#;

    #[test]
    fn native_pipe_retried_at_the_descriptor_limit_lets_a_closing_peer_run() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "pipe-retry", PIPE_RETRY_SOURCE);
        assert_runs_answer(&bin, "PIPE_RETRY ", &["PIPE_RETRY created=true"]);
    }

    // Every call that makes a descriptor, retried at `RLIMIT_NOFILE` while a
    // peer waits to close one: each answers `EMFILE` at the limit, and each
    // refusal is a scheduling point, so the peer runs and a retry gets its
    // number.
    const FD_RETRY_SOURCE: &str = r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn eventfd(initial: u32, flags: i32) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn timerfd_create(clock: i32, flags: i32) -> i32;
    fn signalfd(fd: i32, mask: *const u64, flags: i32) -> i32;
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn socketpair(domain: i32, kind: i32, protocol: i32, fds: *mut i32) -> i32;
    fn syscall(number: i64, ...) -> i64;
    fn getpid() -> i32;
    fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_GETFD: i64 = 438;
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const USERFAULTFD: i64 = 323;
    pub const INOTIFY_INIT1: i64 = 294;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_GETFD: i64 = 438;
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const USERFAULTFD: i64 = 282;
    pub const INOTIFY_INIT1: i64 = 26;
}

const RLIMIT_NOFILE: i32 = 7;
const F_GETFD: i32 = 1;
const F_DUPFD: i32 = 0;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const CLOCK_MONOTONIC: i32 = 1;
const UFFD_USER_MODE_ONLY: i64 = 1;
const ATTEMPTS: usize = 10_000;

/// One new descriptor, or the errno.
fn one(fd: i64) -> Result<Vec<i32>, i32> {
    if fd >= 0 {
        Ok(vec![fd as i32])
    } else {
        Err(unsafe { *__errno_location() })
    }
}

fn main() {
    let mut limit = [0_u64; 2];
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
    let pidfd = unsafe { syscall(nr::PIDFD_OPEN, getpid(), 0) } as i32;
    assert!(pidfd >= 0);
    let mask = [0_u64; 16];
    let ruleset = [1_u64, 0];
    let rows: Vec<(&str, usize, Box<dyn Fn() -> Result<Vec<i32>, i32>>)> = vec![
        ("eventfd", 1, Box::new(|| one(unsafe { eventfd(0, 0) }.into()))),
        ("epoll_create1", 1, Box::new(|| one(unsafe { epoll_create1(0) }.into()))),
        ("timerfd_create", 1, Box::new(|| one(unsafe { timerfd_create(CLOCK_MONOTONIC, 0) }.into()))),
        ("signalfd", 1, Box::new(move || one(unsafe { signalfd(-1, mask.as_ptr(), 0) }.into()))),
        ("inotify_init1", 1, Box::new(|| one(unsafe { syscall(nr::INOTIFY_INIT1, 0) }))),
        ("socket", 1, Box::new(|| one(unsafe { socket(AF_UNIX, SOCK_STREAM, 0) }.into()))),
        ("socketpair", 2, Box::new(|| {
            let mut fds = [0_i32; 2];
            match unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } {
                0 => Ok(fds.to_vec()),
                _ => Err(unsafe { *__errno_location() }),
            }
        })),
        ("dup", 1, Box::new(|| one(unsafe { dup(0) }.into()))),
        ("F_DUPFD", 1, Box::new(|| one(unsafe { fcntl(0, F_DUPFD, 0) }.into()))),
        ("pidfd_open", 1, Box::new(|| one(unsafe { syscall(nr::PIDFD_OPEN, getpid(), 0) }))),
        ("pidfd_getfd", 1, Box::new(move || one(unsafe { syscall(nr::PIDFD_GETFD, pidfd, 0, 0) }))),
        ("landlock_create_ruleset", 1, Box::new(move || {
            one(unsafe { syscall(nr::LANDLOCK_CREATE_RULESET, ruleset.as_ptr(), 16, 0) })
        })),
        ("userfaultfd", 1, Box::new(|| one(unsafe { syscall(nr::USERFAULTFD, UFFD_USER_MODE_ONLY) }))),
    ];
    for (name, needs, create) in rows {
        // `last` is the highest open number, so the table is full but for
        // `needs - 1` numbers under the limit.
        let last = unsafe { dup(0) };
        assert!((last + 1..last + 64).all(|fd| unsafe { fcntl(fd, F_GETFD) } == -1));
        let below = [last as u64 + needs as u64, limit[1]];
        assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &below) }, 0);
        let at_limit = create().err().unwrap_or(0);
        // The closer runs only once the retries start, and only when a retry
        // lets another task run.
        let go = Arc::new(AtomicBool::new(false));
        let closer = {
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                unsafe { close(last) }
            })
        };
        go.store(true, Ordering::SeqCst);
        let created = (1..=ATTEMPTS).find_map(|_| create().ok());
        assert_eq!(closer.join().unwrap(), 0);
        for fd in created.iter().flatten() {
            unsafe { close(*fd) };
        }
        assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &limit) }, 0);
        println!("FD_RETRY {name} at_limit={at_limit} created={}", created.is_some());
    }
}
"#;

    #[test]
    fn native_descriptor_creators_retried_at_the_limit_let_a_closing_peer_run() {
        let directory = tempdir().unwrap();
        let bin = built_guest(directory.path(), "fd-retry", FD_RETRY_SOURCE);
        let creators = [
            "eventfd",
            "epoll_create1",
            "timerfd_create",
            "signalfd",
            "inotify_init1",
            "socket",
            "socketpair",
            "dup",
            "F_DUPFD",
            "pidfd_open",
            "pidfd_getfd",
            "landlock_create_ruleset",
            "userfaultfd",
        ];
        let expected = creators.map(|name| format!("FD_RETRY {name} at_limit=24 created=true"));
        let expected = expected.iter().map(String::as_str).collect::<Vec<_>>();
        assert_runs_answer(&bin, "FD_RETRY ", &expected);
    }
}
