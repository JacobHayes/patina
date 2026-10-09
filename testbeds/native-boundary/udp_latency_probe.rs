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
            "NATIVE_UDP_LATENCY_RECV elapsed_us={} bytes={n}",
            elapsed.as_micros()
        );
        let payload = String::from_utf8(buf[..n].to_vec()).unwrap();
        // In microseconds: the latency, give or take the calls charged
        // around it (each costs nanoseconds of virtual time).
        (elapsed.as_micros(), payload)
    });

    let sender = UdpSocket::bind("127.0.0.1:9101").unwrap();
    sender.send_to(b"ping", "127.0.0.1:9100").unwrap();
    let (elapsed_us, payload) = receiver_thread.join().unwrap();
    println!("NATIVE_UDP_LATENCY_RESULT elapsed_us={elapsed_us} payload={payload}");
}
