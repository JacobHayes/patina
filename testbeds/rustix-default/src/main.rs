//! rustix-default — the syscall-user-dispatch (SUD) acceptance MRE.
//!
//! A plain std + rustix program on rustix's DEFAULT backend. On Linux that
//! backend (`linux_raw`) issues raw inline `syscall` instructions with no libc
//! wrapper — invisible to Patina's import audit, refused by its instruction
//! scan, and (before SUD) unrunnable under the deterministic runtime. Under SUD
//! every one of these calls traps into the same `patina_*` runtime entries the C
//! interposers use, so the program observes VIRTUAL time, the deterministic
//! filesystem, seed-derived entropy, and SimNet — deterministically.
//!
//! The program prints one machine-parseable `RUSTIX_RESULT …` line and exits 0
//! on success; any inconsistency panics (nonzero exit). `run-patina.sh` asserts
//! it audits as SUD-managed, is seed-stable, and records/replays byte-identical.
//! It is SUD-only: `run-patina.sh` skips it loudly on non-SUD / non-Linux hosts.

use rustix::fs::{Dir, Mode, OFlags};
use rustix::net::{
    AddressFamily, Ipv4Addr, RecvFlags, SendFlags, SocketAddrV4, SocketType,
};
use rustix::time::{clock_gettime, ClockId};

/// The virtual clock starts near zero and only advances via sleeps; a wall clock
/// would read ~1.7e18 ns. Anything under this bound proves the read was virtual.
const VIRTUAL_BOUND: u64 = 1_000_000_000_000_000;

fn mono_nanos() -> u64 {
    let ts = clock_gettime(ClockId::Monotonic);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn main() {
    // ---- clocks (raw clock_gettime) ----
    let t0 = mono_nanos();
    // A realtime read also routes through the virtual clock.
    let real = clock_gettime(ClockId::Realtime);
    assert!(t0 < VIRTUAL_BOUND, "monotonic clock must be virtual: {t0}");
    assert!(
        (real.tv_sec as u64) < VIRTUAL_BOUND / 1_000_000_000,
        "realtime clock must be virtual"
    );

    // ---- sleep (raw clock_nanosleep) advances virtual time ----
    let dur = std::time::Duration::from_millis(5);
    // std::thread::sleep lowers to rustix nanosleep on the linux_raw backend.
    std::thread::sleep(dur);
    let t1 = mono_nanos();
    assert!(t1 >= t0 + 4_000_000, "virtual time must advance over sleep: {t0}->{t1}");
    assert!(t1 < VIRTUAL_BOUND, "post-sleep clock must be virtual: {t1}");

    // ---- filesystem (raw openat/write/read/close/statx) ----
    let path = "/rustix-probe.txt";
    let payload = b"rustix-default-mre";
    {
        let fd = rustix::fs::open(
            path,
            OFlags::CREATE | OFlags::WRONLY | OFlags::TRUNC,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("raw openat (create) must succeed");
        let n = rustix::io::write(&fd, payload).expect("raw write");
        assert_eq!(n, payload.len(), "short write");
    }
    let read_back = {
        let fd = rustix::fs::open(path, OFlags::RDONLY, Mode::empty()).expect("raw openat (read)");
        // statx (raw) reports the size we just wrote.
        let stat = rustix::fs::fstat(&fd).expect("raw fstat");
        assert_eq!(stat.st_size as usize, payload.len(), "fstat size mismatch");
        let mut buf = vec![0u8; payload.len()];
        let n = rustix::io::read(&fd, &mut buf).expect("raw read");
        buf.truncate(n);
        buf
    };
    assert_eq!(&read_back, payload, "read-back content mismatch");

    // ---- directory iteration (raw getdents64 over a SUD directory fd) ----
    // Create a directory with two files, then iterate it with rustix `Dir`,
    // which opens the directory fd and issues raw getdents64.
    let dir_path = "/rustix-dir";
    rustix::fs::mkdir(dir_path, Mode::RWXU).expect("raw mkdirat");
    for name in ["alpha", "beta"] {
        let full = format!("{dir_path}/{name}");
        let fd = rustix::fs::open(&full, OFlags::CREATE | OFlags::WRONLY, Mode::RUSR | Mode::WUSR)
            .expect("raw openat in dir");
        drop(fd);
    }
    let dir_fd = rustix::fs::open(dir_path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("raw openat (directory) must yield a directory fd under SUD");
    let mut dir = Dir::read_from(&dir_fd).expect("Dir::read_from (raw getdents64)");
    let mut entries: Vec<String> = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "." && name != ".." {
            entries.push(name);
        }
    }
    entries.sort();
    assert_eq!(entries, vec!["alpha".to_string(), "beta".to_string()], "getdents64 listing");

    // ---- entropy (raw getrandom) ----
    let mut rnd = [0u8; 8];
    let filled = rustix::rand::getrandom(&mut rnd, rustix::rand::GetRandomFlags::empty())
        .expect("raw getrandom");
    assert_eq!(filled, rnd.len(), "getrandom short fill");

    // ---- basic UDP loopback over SimNet (raw socket/bind/sendto/recvfrom) ----
    // Bind a fixed loopback port so the send target is known without depending
    // on the getsockname address type; getsockname is still called for coverage.
    let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567);
    let sock = rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None)
        .expect("raw socket");
    rustix::net::bind(&sock, &local).expect("raw bind");
    let _bound = rustix::net::getsockname(&sock).expect("raw getsockname");
    let datagram = b"ping";
    let sent = rustix::net::sendto(&sock, datagram, SendFlags::empty(), &local).expect("raw sendto");
    assert_eq!(sent, datagram.len(), "short sendto");
    let mut rbuf = [0u8; 16];
    // rustix `recvfrom` reports (bytes copied, full datagram length, sender).
    let (rn, _dgram_len, _from) =
        rustix::net::recvfrom(&sock, &mut rbuf, RecvFlags::empty()).expect("raw recvfrom");
    assert_eq!(&rbuf[..rn], datagram, "UDP loopback payload mismatch");
    drop(sock);

    // ---- basic TCP socket lifecycle over the net rows (no blocking handshake:
    // the full accept/connect dance is covered by the interposed pubsub testbed;
    // here we exercise socket/setsockopt/bind/getsockname/listen/close raw) ----
    let tcp = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
        .expect("raw tcp socket");
    rustix::net::sockopt::set_socket_reuseaddr(&tcp, true).expect("raw setsockopt SO_REUSEADDR");
    rustix::net::bind(&tcp, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("raw tcp bind");
    rustix::net::listen(&tcp, 8).expect("raw listen");
    drop(tcp);

    let rand_hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "RUSTIX_RESULT fs={} dents={} rand={} udp_port={}",
        std::str::from_utf8(&read_back).unwrap(),
        entries.join(","),
        rand_hex,
        local.port(),
    );
}
