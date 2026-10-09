//! bench — halting, self-checking microworkloads for the native-versus-Patina
//! overhead benchmark (`scripts/bench.py`, `mise run bench`).
//!
//! Each workload isolates one cost, runs a fixed number of iterations, checks
//! its own result, and prints one line:
//!
//! ```text
//! BENCH_RESULT workload=<name> iters=<n> digest=<16 hex digits>
//! ```
//!
//! The digest is a pure function of the workload and `--iters`, so a native run
//! and a Patina run of the same arguments must print the same line; the runner
//! fails when they differ. A clean run also reports a `Pass` verdict carrying
//! that line's fields, and a failed self-check reports a `Violation` under the
//! workload's name and exits 1.
//!
//! Workloads:
//!
//! - `compute`: SplitMix64 steps folded into a digest, with no syscalls in the
//!   loop. Patina's cost here should be only its fixed start-up cost.
//! - `fileio`: create/write/close then open/read/close a small file per
//!   iteration under `--dir`, checking every read-back.
//! - `condvar`: two threads take strict turns on a `Mutex` + `Condvar`; every
//!   turn is a hand-off from one thread to the other.
//! - `pipe`: two threads bounce a counter through a pair of pipes.
//! - `tcp`: a loopback TCP echo of a fixed-size message per iteration.

mod doors;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use patina_dst::VerdictKind;

const USAGE: &str = "usage: bench <compute|fileio|condvar|pipe|tcp|doors> --iters N [--dir PATH]
  doors requires --class <sync|clock|mutex|pipe|pread>.
  --dir is required by fileio: the directory its files live under.";

const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const COMPUTE_SEED: u64 = 0x5eed_0000_0000_0001;
/// Files `fileio` cycles through, so the directory stays small.
const FILEIO_FILES: u64 = 8;
const FILEIO_BYTES: usize = 512;
const TCP_MESSAGE_BYTES: usize = 64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("bench: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut ops = None;
    let outcome = match options.workload.as_str() {
        "doors" => doors::run(
            options.class.as_deref().unwrap_or(""),
            options.iters,
            options.dir.as_deref(),
        )
        .map(|(digest, count)| {
            ops = Some(count);
            digest
        }),
        "compute" => compute(options.iters),
        "fileio" => fileio(options.iters, options.dir.as_deref()),
        "condvar" => condvar(options.iters),
        "pipe" => pipe(options.iters),
        "tcp" => tcp(options.iters),
        other => {
            eprintln!("bench: unknown workload {other}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(digest) => {
            let mut detail = format!(
                "workload={} iters={} digest={digest:016x}",
                options.workload, options.iters
            );
            if let Some(ops) = ops {
                detail.push_str(&format!(
                    " class={} ops={ops}",
                    options.class.as_deref().unwrap()
                ));
            }
            println!("BENCH_RESULT {detail}");
            patina_dst::verdict(VerdictKind::Pass, "bench-outcome", &detail);
            ExitCode::SUCCESS
        }
        Err(detail) => {
            patina_dst::verdict(VerdictKind::Violation, &options.workload, &detail);
            eprintln!("BENCH_VIOLATION {} {detail}", options.workload);
            ExitCode::from(1)
        }
    }
}

struct Options {
    workload: String,
    iters: u64,
    dir: Option<PathBuf>,
    class: Option<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut args = args.iter();
    let workload = args.next().ok_or("missing workload")?.clone();
    let mut iters = None;
    let mut dir = None;
    let mut class = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--iters" => {
                let n: u64 = value.parse().map_err(|_| format!("bad --iters {value}"))?;
                if n == 0 {
                    return Err("--iters must be at least 1".into());
                }
                iters = Some(n);
            }
            "--class" => class = Some(value.clone()),
            "--dir" => dir = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Options {
        workload,
        iters: iters.ok_or("--iters is required")?,
        dir,
        class,
    })
}

/// FNV-1a over 64-bit words: cheap, and order-sensitive where order matters.
struct Digest(u64);

impl Digest {
    fn new() -> Self {
        Digest(0xcbf2_9ce4_8422_2325)
    }

    fn word(&mut self, word: u64) {
        for byte in word.to_le_bytes() {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
}

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn compute(iters: u64) -> Result<u64, String> {
    let iters = std::hint::black_box(iters);
    let mut state = COMPUTE_SEED;
    let mut acc = 0u64;
    for _ in 0..iters {
        state = state.wrapping_add(GAMMA);
        acc = acc.rotate_left(5) ^ mix(state);
    }
    // SplitMix64's state is an arithmetic progression, so the loop must have
    // taken exactly `iters` steps.
    if state != COMPUTE_SEED.wrapping_add(GAMMA.wrapping_mul(iters)) {
        return Err(format!("step-count state={state:016x}"));
    }
    let mut digest = Digest::new();
    digest.word(acc);
    Ok(digest.0)
}

fn payload(i: u64) -> Vec<u8> {
    (0..FILEIO_BYTES as u64 / 8)
        .flat_map(|k| mix(i.wrapping_mul(GAMMA) ^ k).to_le_bytes())
        .collect()
}

fn fileio(iters: u64, dir: Option<&Path>) -> Result<u64, String> {
    let dir = dir.ok_or("fileio needs --dir")?;
    let root = dir.join("bench-fileio");
    fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    let mut digest = Digest::new();
    let mut buf = Vec::with_capacity(FILEIO_BYTES);
    for i in 0..iters {
        let path = root.join(format!("f{}", i % FILEIO_FILES));
        let expected = payload(i);
        File::create(&path)
            .and_then(|mut f| f.write_all(&expected))
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        buf.clear();
        File::open(&path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if buf != expected {
            return Err(format!("read-back-mismatch iteration={i}"));
        }
        digest.bytes(&buf);
    }
    fs::remove_dir_all(&root).map_err(|e| format!("remove {}: {e}", root.display()))?;
    Ok(digest.0)
}

/// `condvar`'s shared state: the turn counter (thread k acts only when
/// `turn % 2 == k`) and whether either player has failed its self-check.
const OTHER_PLAYER_FAILED: &str = "other-player-failed";

struct Turns {
    turn: u64,
    failed: bool,
}

fn condvar(iters: u64) -> Result<u64, String> {
    let shared = Arc::new((
        Mutex::new(Turns {
            turn: 0,
            failed: false,
        }),
        Condvar::new(),
    ));
    let player = |k: u64, shared: Arc<(Mutex<Turns>, Condvar)>| {
        move || -> Result<u64, String> {
            let (lock, cv) = &*shared;
            let mut seen = Digest::new();
            for round in 0..iters {
                let mut state = lock.lock().unwrap();
                while state.turn % 2 != k && !state.failed {
                    state = cv.wait(state).unwrap();
                }
                if state.failed {
                    // The other player failed; its error is the one to report.
                    return Err(OTHER_PLAYER_FAILED.to_string());
                }
                if state.turn != 2 * round + k {
                    // Wake the other player so it stops waiting for a turn
                    // that will never come, and the run fails fast.
                    state.failed = true;
                    cv.notify_all();
                    return Err(format!(
                        "turn-out-of-order player={k} round={round} turn={}",
                        state.turn
                    ));
                }
                seen.word(state.turn);
                state.turn += 1;
                cv.notify_one();
            }
            Ok(seen.0)
        }
    };
    let other = thread::spawn(player(1, Arc::clone(&shared)));
    let mine = player(0, Arc::clone(&shared))();
    let theirs = other.join().map_err(|_| "player-1-panicked".to_string())?;
    // Report the player that failed first rather than the one it woke.
    for result in [&mine, &theirs] {
        if let Err(e) = result {
            if e != OTHER_PLAYER_FAILED {
                return Err(e.clone());
            }
        }
    }
    let (mine, theirs) = (mine?, theirs?);
    let turns = shared.0.lock().unwrap().turn;
    if turns != 2 * iters {
        return Err(format!("turn-count turns={turns} expected={}", 2 * iters));
    }
    let mut digest = Digest::new();
    digest.word(mine);
    digest.word(theirs);
    Ok(digest.0)
}

fn os_pipe() -> Result<(File, File), String> {
    let mut fds = [0; 2];
    // SAFETY: `fds` is a valid two-element array for pipe(2) to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: pipe(2) succeeded, so both descriptors are open and owned here.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn pipe(iters: u64) -> Result<u64, String> {
    let (mut to_echo_rx, mut to_echo_tx) = os_pipe()?;
    let (mut back_rx, mut back_tx) = os_pipe()?;
    let echo = thread::spawn(move || -> Result<(), String> {
        let mut word = [0u8; 8];
        loop {
            match to_echo_rx.read_exact(&mut word) {
                Ok(()) => {}
                // The main thread closed its end: the run is over.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(format!("echo read: {e}")),
            }
            let reply = u64::from_le_bytes(word).wrapping_add(1);
            back_tx
                .write_all(&reply.to_le_bytes())
                .map_err(|e| format!("echo write: {e}"))?;
        }
    });
    let mut digest = Digest::new();
    let mut word = [0u8; 8];
    for i in 0..iters {
        let sent = mix(i);
        to_echo_tx
            .write_all(&sent.to_le_bytes())
            .map_err(|e| format!("write: {e}"))?;
        back_rx
            .read_exact(&mut word)
            .map_err(|e| format!("read: {e}"))?;
        let got = u64::from_le_bytes(word);
        if got != sent.wrapping_add(1) {
            return Err(format!("reply-mismatch iteration={i}"));
        }
        digest.word(got);
    }
    drop(to_echo_tx);
    echo.join()
        .map_err(|_| "echo-thread-panicked".to_string())??;
    Ok(digest.0)
}

fn tcp(iters: u64) -> Result<u64, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("server nodelay: {e}"))?;
        let mut buf = [0u8; TCP_MESSAGE_BYTES];
        loop {
            let n = stream
                .read(&mut buf)
                .map_err(|e| format!("server read: {e}"))?;
            if n == 0 {
                return Ok(());
            }
            stream
                .write_all(&buf[..n])
                .map_err(|e| format!("server write: {e}"))?;
        }
    });
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("client nodelay: {e}"))?;
    let mut digest = Digest::new();
    let mut echoed = [0u8; TCP_MESSAGE_BYTES];
    for i in 0..iters {
        let message: Vec<u8> = (0..TCP_MESSAGE_BYTES as u64 / 8)
            .flat_map(|k| mix(i ^ (k << 56)).to_le_bytes())
            .collect();
        stream
            .write_all(&message)
            .map_err(|e| format!("write: {e}"))?;
        stream
            .read_exact(&mut echoed)
            .map_err(|e| format!("read: {e}"))?;
        if echoed[..] != message[..] {
            return Err(format!("echo-mismatch iteration={i}"));
        }
        digest.bytes(&echoed);
    }
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    server
        .join()
        .map_err(|_| "server-thread-panicked".to_string())??;
    Ok(digest.0)
}
