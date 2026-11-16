//! W2 tokio-mt: stock tokio multi-thread runtime with 4 workers. An echo server and 16
//! clients in one process, timers, an interval, `spawn_blocking` file writes, a 5 s
//! `tokio::time::timeout` on a read nobody answers, and a child process.
//!
//!     tokio-mt local [CLIENTS] [MSGS]   echo over AF_UNIX stream sockets (tokio::net::Unix*)
//!     tokio-mt net   [CLIENTS] [MSGS]   echo over TCP on 127.0.0.1 (tokio::net::Tcp*)
//!
//! Every read of a client is wrapped in a 5 s timeout: a timeout is counted and the client
//! keeps waiting (so a partition shows as timeouts followed by recovery). A connection error
//! ends that client and is printed. Lines starting with "~ " depend on the schedule or time.
//! The last line is "done".

use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};

trait Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Conn for T {}

static TIMEOUTS: AtomicU64 = AtomicU64::new(0);

async fn serve<C: Conn>(mut c: C) {
    let mut buf = [0u8; 256];
    loop {
        let n = match c.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        for b in &mut buf[..n] {
            b.make_ascii_uppercase();
        }
        if c.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// One client: MSGS requests, each echoed back upper-cased. Returns the bytes checked.
async fn client<C: Conn>(mut c: C, i: usize, msgs: usize) -> io::Result<usize> {
    let mut total = 0;
    for k in 0..msgs {
        let msg = format!("client {i:02} message {k:03} {}\n", "x".repeat((i * 7 + k * 3) % 40));
        c.write_all(msg.as_bytes()).await?;
        let want = msg.to_ascii_uppercase();
        let mut got = vec![0u8; want.len()];
        let mut have = 0;
        while have < got.len() {
            match timeout(Duration::from_secs(5), c.read(&mut got[have..])).await {
                Err(_) => {
                    TIMEOUTS.fetch_add(1, Relaxed);
                }
                Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
                Ok(Ok(n)) => have += n,
                Ok(Err(e)) => return Err(e),
            }
        }
        if got != want.as_bytes() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad echo at message {k}")));
        }
        total += got.len();
        sleep(Duration::from_millis(1 + ((i * 7 + k) % 5) as u64)).await;
    }
    Ok(total)
}

async fn echo_test(net: bool, clients: usize, msgs: usize) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, io::Result<usize>)>();
    let path = std::env::current_dir().unwrap().join(format!("w2-echo-{}.sock", std::process::id()));
    if net {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((c, _)) = ln.accept().await {
                tokio::spawn(serve(c));
            }
        });
        for i in 0..clients {
            let tx = tx.clone();
            tokio::spawn(async move {
                let r = match tokio::net::TcpStream::connect(addr).await {
                    Ok(c) => client(c, i, msgs).await,
                    Err(e) => Err(e),
                };
                let _ = tx.send((i, r));
            });
        }
    } else {
        let _ = std::fs::remove_file(&path);
        let ln = tokio::net::UnixListener::bind(&path).expect("bind");
        tokio::spawn(async move {
            while let Ok((c, _)) = ln.accept().await {
                tokio::spawn(serve(c));
            }
        });
        for i in 0..clients {
            let tx = tx.clone();
            let path = path.clone();
            tokio::spawn(async move {
                let r = match tokio::net::UnixStream::connect(&path).await {
                    Ok(c) => client(c, i, msgs).await,
                    Err(e) => Err(e),
                };
                let _ = tx.send((i, r));
            });
        }
    }
    drop(tx);
    let mut order = Vec::new();
    let (mut ok, mut bytes) = (0, 0);
    let mut errs = Vec::new();
    while let Some((i, r)) = rx.recv().await {
        order.push(i.to_string());
        match r {
            Ok(n) => {
                ok += 1;
                bytes += n;
            }
            Err(e) => errs.push((i, format!("{:?}", e.kind()))),
        }
    }
    if !net {
        let _ = std::fs::remove_file(&path);
    }
    errs.sort();
    for (i, k) in &errs {
        println!("client {i} error: {k}");
    }
    println!("echo ({}): {ok} of {clients} clients ok, {bytes} bytes checked", if net { "tcp" } else { "unix" });
    println!("timeouts during echo: {}", TIMEOUTS.load(Relaxed));
    println!("~ client completion order {}", order.join(" "));
}

async fn blocking_files() {
    let dir = std::env::current_dir().unwrap().join(format!("w2-files-{}", std::process::id()));
    let mut hs = Vec::new();
    for i in 0..8 {
        let dir = dir.clone();
        hs.push(tokio::task::spawn_blocking(move || -> io::Result<u64> {
            use std::io::Write;
            std::fs::create_dir_all(&dir)?;
            let tmp = dir.join(format!("f{i}.tmp"));
            let mut f = std::fs::File::create(&tmp)?;
            for k in 0..32 {
                writeln!(f, "blocking file {i} line {k}")?;
            }
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, dir.join(format!("f{i}")))?;
            Ok(std::fs::metadata(dir.join(format!("f{i}")))?.len())
        }));
    }
    let (mut n, mut size, mut errs) = (0, 0, Vec::new());
    for (i, h) in hs.into_iter().enumerate() {
        match h.await.expect("join") {
            Ok(s) => {
                n += 1;
                size += s;
            }
            Err(e) => errs.push(format!("file {i}: {:?}", e.kind())),
        }
    }
    for e in &errs {
        println!("spawn_blocking error: {e}");
    }
    println!("spawn_blocking files: {n} written, {size} bytes, {} errors", errs.len());
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

async fn timers() {
    let t0 = Instant::now();
    let mut iv = tokio::time::interval(Duration::from_millis(100));
    for _ in 0..5 {
        iv.tick().await;
    }
    println!("interval: 5 ticks, elapsed >= 400ms: {}", t0.elapsed() >= Duration::from_millis(400));
    // A read nobody answers, under a 5 s timeout.
    let (mut a, _b) = tokio::net::UnixStream::pair().expect("pair");
    let t1 = Instant::now();
    let mut buf = [0u8; 8];
    match timeout(Duration::from_secs(5), a.read(&mut buf)).await {
        Err(_) => println!("timeout 5s: fired, elapsed >= 5s: {}", t1.elapsed() >= Duration::from_secs(5)),
        Ok(r) => println!("timeout 5s: did not fire: {r:?}"),
    }
    // Many concurrent sleeps on several workers.
    let shared = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for i in 0..32u64 {
        let s = shared.clone();
        hs.push(tokio::spawn(async move {
            sleep(Duration::from_millis(10 * (i % 7))).await;
            s.fetch_add(i, Relaxed);
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
    println!("32 sleepers: sum {}", shared.load(Relaxed));
}

async fn child() {
    match tokio::process::Command::new("seq").args(["-s", " ", "1", "6"]).output().await {
        Ok(o) => println!("tokio::process seq: {} status {:?}", String::from_utf8_lossy(&o.stdout).trim(), o.status.code()),
        Err(e) => println!("tokio::process error: {:?}", e.kind()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("local");
    let clients = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(16);
    let msgs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().expect("runtime");
    rt.block_on(async {
        let t0 = Instant::now();
        let e = tokio::spawn(echo_test(mode == "net", clients, msgs));
        let f = tokio::spawn(blocking_files());
        let t = tokio::spawn(timers());
        let c = tokio::spawn(child());
        e.await.unwrap();
        f.await.unwrap();
        t.await.unwrap();
        c.await.unwrap();
        println!("~ virtual elapsed {:?}", t0.elapsed());
    });
    drop(rt);
    println!("done");
}
