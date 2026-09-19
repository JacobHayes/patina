// Ordinary std::net::UdpSocket datagrams routed through Patina's SimNet. Three
// worker threads each send their id to a collector; the collector logs the
// arrival order, which is decided by the deterministic scheduler — stable per
// seed and varying across seeds. A blocking recv on the empty collector parks
// the task through the baton and is woken when a worker sends. No host network
// symbol is called: the sockets are fully virtual. No explicit Patina init.
use std::net::UdpSocket;
use std::thread;

fn main() {
    let collector = UdpSocket::bind("127.0.0.1:9000").unwrap();
    let mut workers = Vec::new();
    for id in 0..3u8 {
        let port = 9001 + u16::from(id);
        let sock = UdpSocket::bind(format!("127.0.0.1:{port}")).unwrap();
        workers.push(thread::spawn(move || {
            sock.send_to(&[b'0' + id], "127.0.0.1:9000").unwrap();
        }));
    }
    let mut order = String::new();
    let mut buf = [0u8; 4];
    for _ in 0..3 {
        let (_n, _from) = collector.recv_from(&mut buf).unwrap();
        order.push(char::from(buf[0]));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    println!("NATIVE_UDP_RESULT order={order}");
}
