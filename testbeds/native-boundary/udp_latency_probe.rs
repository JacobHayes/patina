use std::net::UdpSocket;
use std::thread;
use std::time::Instant;

fn main() {
    let receiver = UdpSocket::bind("127.0.0.1:9100").unwrap();
    let receiver_thread = thread::spawn(move || {
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let (n, _from) = receiver.recv_from(&mut buf).unwrap();
        let elapsed = started.elapsed();
        println!(
            "NATIVE_UDP_LATENCY_RECV elapsed_ns={} bytes={n}",
            elapsed.as_nanos()
        );
        let payload = String::from_utf8(buf[..n].to_vec()).unwrap();
        (elapsed.as_nanos(), payload)
    });

    let sender = UdpSocket::bind("127.0.0.1:9101").unwrap();
    sender.send_to(b"ping", "127.0.0.1:9100").unwrap();
    let (elapsed_ns, payload) = receiver_thread.join().unwrap();
    println!("NATIVE_UDP_LATENCY_RESULT elapsed_ns={elapsed_ns} payload={payload}");
}
