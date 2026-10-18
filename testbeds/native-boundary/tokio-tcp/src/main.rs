// A tokio TCP ping-pong over loopback, the shape of a tokio server and its
// client in one process. `TOKIO_TCP_MODE` picks the runtime:
//   current  one current-thread runtime: the task that parks in the reactor
//            (epoll on Linux, kqueue on macOS) is the one doing the I/O, so a
//            delayed segment reaches it only if the park ends at its delivery;
//   multi    two workers: the I/O driver parks in the reactor on one worker
//            while another accepts, registers and drives the sockets;
//   default  `new_multi_thread()` as most programs build it, sized from the
//            CPU count: it also reports how many workers the runtime has and
//            how many of their threads started;
//   stall    a current-thread server reading a connection its client never
//            writes to, with no timer armed: nothing can ever wake the reactor.
// A `current` exchange runs under a 1 s timeout, so a reactor that wakes only
// on its timers shows up as an exchange that took the whole second. A `multi`
// or `default` one arms no timer, so a wake the reactor misses leaves it parked
// for good.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn ping_pong() -> [u8; 4] {
    let listener = TcpListener::bind("127.0.0.1:7000").await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let mut stream = TcpStream::connect("127.0.0.1:7000").await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    server.await.unwrap();
    reply
}

async fn stall() {
    let listener = TcpListener::bind("127.0.0.1:7000").await.unwrap();
    let _client = TcpStream::connect("127.0.0.1:7000").await.unwrap();
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf).await;
    unreachable!("the client never writes");
}

/// The runtime threads that started, workers and any blocking-pool thread.
static STARTED: AtomicUsize = AtomicUsize::new(0);

/// Wait until every worker's thread has started, then report the count.
async fn report_workers() {
    let workers = tokio::runtime::Handle::current().metrics().num_workers();
    while STARTED.load(Ordering::SeqCst) < workers {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    println!(
        "NATIVE_TOKIO_WORKERS workers={workers} started={}",
        STARTED.load(Ordering::SeqCst)
    );
}

fn main() {
    let mode = std::env::var("TOKIO_TCP_MODE").unwrap_or_default();
    let runtime = match mode.as_str() {
        "current" | "stall" => tokio::runtime::Builder::new_current_thread(),
        "multi" => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(2);
            builder
        }
        "default" => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.on_thread_start(|| {
                STARTED.fetch_add(1, Ordering::SeqCst);
            });
            builder
        }
        other => panic!("unknown mode {other:?}: current, multi, default or stall"),
    }
    .enable_all()
    .build()
    .unwrap();
    if mode == "stall" {
        runtime.block_on(stall());
    }
    let (reply, elapsed) = runtime.block_on(async {
        let start = Instant::now();
        let reply = if mode == "current" {
            tokio::time::timeout(Duration::from_secs(1), ping_pong())
                .await
                .expect("the exchange finished within 1 s")
        } else {
            ping_pong().await
        };
        let elapsed = start.elapsed();
        if mode == "default" {
            report_workers().await;
        }
        (reply, elapsed)
    });
    println!(
        "NATIVE_TOKIO_TCP_RESULT reply={} elapsed_us={}",
        std::str::from_utf8(&reply).unwrap(),
        elapsed.as_micros()
    );
}
