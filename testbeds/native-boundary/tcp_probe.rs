use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

fn main() {
    let ipv6 = TcpListener::bind("[::1]:9300").is_err();
    // DNS is modeled now, so this probe asserts the resolver's contract rather
    // than its former blanket refusal: a name outside the run's host table is
    // NXDOMAIN, and `localhost` resolves without any table at all.
    let nxdomain = TcpStream::connect("absent.internal:9300").is_err();

    let listener = TcpListener::bind("127.0.0.1:9300").unwrap();
    let server = thread::spawn(move || {
        let (mut stream, peer) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        let reply = String::from_utf8(request).unwrap().to_uppercase();
        stream.write_all(reply.as_bytes()).unwrap();
        peer.to_string()
    });

    let mut client = TcpStream::connect("localhost:9300").expect("localhost resolves");
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    let peer = server.join().unwrap();
    println!(
        "NATIVE_TCP_RESULT reply={reply} peer={peer} ipv6_closed={ipv6} dns_nxdomain={nxdomain}"
    );
}
