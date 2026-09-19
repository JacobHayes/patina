// A real tokio current-thread runtime driving an async socketpair ping-pong.
// UnixStream::pair lowers to socketpair(2); tokio's IO driver registers the
// endpoints with mio's selector (kqueue on macOS, epoll on Linux) and wakes
// itself through mio's Waker (EVFILT_USER / eventfd) — all serviced by the
// deterministic reactor + net shim. parking_lot rides its interposed platform
// primitive (os_unfair_lock on macOS, futex-via-syscall on Linux), and rustix
// — carried onto its libc backend by the injected --cfg rustix_use_libc —
// reaches the deterministic FS through the interposed openat/openat64.
use std::io::Read;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).await.unwrap();
            b.write_all(b"pong").await.unwrap();
            buf
        });
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).await.unwrap();
        let server_got = server.await.unwrap();
        (buf, server_got)
    });

    let lock = parking_lot::Mutex::new(0u64);
    *lock.lock() += 41;
    let lock_val = *lock.lock() + 1;

    std::fs::write("/tmp/patina-tokio-probe-data", b"rustix-ok").unwrap();
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        "/tmp/patina-tokio-probe-data",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let mut contents = String::new();
    std::fs::File::from(fd)
        .read_to_string(&mut contents)
        .unwrap();

    println!(
        "NATIVE_TOKIO_RESULT client_got={} server_got={} lock={} rustix_read={}",
        std::str::from_utf8(&out.0).unwrap(),
        std::str::from_utf8(&out.1).unwrap(),
        lock_val,
        contents
    );
}
