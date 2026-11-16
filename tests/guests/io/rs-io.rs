// blocking I/O item 8 (std): mpsc channels feeding a UnixStream pair, a UnixListener with
// accept/connect, and a UnixDatagram pair. Prints totals only (schedule-independent).
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    // mpsc -> UnixStream -> reader.
    let (tx, rx) = mpsc::channel::<u64>();
    let (mut a, b) = UnixStream::pair().unwrap();
    let producers: Vec<_> = (0..4u64)
        .map(|p| {
            let tx = tx.clone();
            thread::spawn(move || {
                for i in 0..500u64 {
                    tx.send(p * 1_000_000 + i).unwrap();
                }
            })
        })
        .collect();
    drop(tx);
    let writer = thread::spawn(move || {
        let mut n = 0;
        for v in rx {
            writeln!(a, "{v}").unwrap();
            n += 1;
        }
        n
    });
    let reader = thread::spawn(move || {
        let mut sum = 0u64;
        let mut lines = 0;
        for l in BufReader::new(b).lines() {
            sum += l.unwrap().parse::<u64>().unwrap();
            lines += 1;
        }
        (lines, sum)
    });
    for p in producers {
        p.join().unwrap();
    }
    let sent = writer.join().unwrap();
    let (lines, sum) = reader.join().unwrap();
    println!("stream sent {sent} lines {lines} sum {sum}");
    assert_eq!(lines, 2000);

    // Listener on /work, 8 clients, echo.
    let path = "/work/rs-io.sock";
    let l = UnixListener::bind(path).unwrap();
    let server = thread::spawn(move || {
        let mut total = 0usize;
        for _ in 0..8 {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            total += buf.len();
            s.write_all(&buf).unwrap();
        }
        total
    });
    let clients: Vec<_> = (0..8)
        .map(|c| {
            thread::spawn(move || {
                let mut s = UnixStream::connect(path).unwrap();
                let msg = vec![c as u8; 100_000 + c * 1000];
                s.write_all(&msg).unwrap();
                s.shutdown(std::net::Shutdown::Write).unwrap();
                let mut back = Vec::new();
                s.read_to_end(&mut back).unwrap();
                assert_eq!(back, msg);
                back.len()
            })
        })
        .collect();
    let echoed: usize = clients.into_iter().map(|c| c.join().unwrap()).sum();
    println!("listener served {} echoed {echoed}", server.join().unwrap());

    // Datagrams with a receive timeout.
    let (d1, d2) = UnixDatagram::pair().unwrap();
    d2.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    let s = thread::spawn(move || {
        for i in 0..50u8 {
            d1.send(&[i; 64]).unwrap();
        }
    });
    let mut got = 0;
    let mut buf = [0u8; 128];
    loop {
        match d2.recv(&mut buf) {
            Ok(n) => {
                assert_eq!(n, 64);
                assert_eq!(buf[0], got);
                got += 1;
            }
            Err(e) => {
                println!("datagrams {got} then {:?}", e.kind());
                break;
            }
        }
    }
    s.join().unwrap();
    assert_eq!(got, 50);
    println!("rs-io ok");
}
