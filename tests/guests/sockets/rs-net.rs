// Rust std::net: a TcpListener on an ephemeral port, a thread per accepted connection,
// four client threads that each send 50 framed requests and check the echoed replies, then
// half-close and read the server's summary. Also an IPv6 listener and the options std sets.
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn serve(mut s: TcpStream) -> u64 {
    s.set_nodelay(true).unwrap();
    let mut total = 0u64;
    let mut buf = [0u8; 4096];
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
        s.write_all(&buf[..n]).unwrap();
    }
    s.write_all(format!("total {total}\n").as_bytes()).unwrap();
    total
}

fn client(port: u16, id: u32) -> u64 {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_nodelay(true).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    assert_eq!(c.peer_addr().unwrap().port(), port);
    let mut sum = 0u64;
    for i in 0..50u32 {
        let msg = format!("client {id} request {i:03}\n");
        c.write_all(msg.as_bytes()).unwrap();
        let mut back = vec![0u8; msg.len()];
        c.read_exact(&mut back).unwrap();
        assert_eq!(back, msg.as_bytes());
        sum += back.iter().map(|&b| b as u64).sum::<u64>();
    }
    c.shutdown(Shutdown::Write).unwrap();
    let mut rest = String::new();
    c.read_to_string(&mut rest).unwrap();
    assert!(rest.starts_with("total "), "summary {rest:?}");
    sum
}

fn main() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut hs = Vec::new();
        for _ in 0..4 {
            let (s, peer) = l.accept().unwrap();
            assert!(peer.ip().is_loopback());
            hs.push(thread::spawn(move || serve(s)));
        }
        hs.into_iter().map(|h| h.join().unwrap()).sum::<u64>()
    });
    let cs: Vec<_> = (0..4).map(|id| thread::spawn(move || client(port, id))).collect();
    let sum: u64 = cs.into_iter().map(|h| h.join().unwrap()).sum();
    let served = server.join().unwrap();

    // IPv6 loopback, and a refused connect.
    let l6 = TcpListener::bind("[::1]:0").unwrap();
    let p6 = l6.local_addr().unwrap().port();
    let t = thread::spawn(move || {
        let (mut s, _) = l6.accept().unwrap();
        s.write_all(b"v6").unwrap();
    });
    let mut c6 = TcpStream::connect(("::1", p6)).unwrap();
    let mut b = String::new();
    c6.read_to_string(&mut b).unwrap();
    t.join().unwrap();
    let refused = TcpStream::connect(("127.0.0.1", 1)).unwrap_err().kind();
    println!("rs-net served {served} checksum {sum} v6 {b} refused {refused:?}");
}
