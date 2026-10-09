use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// A receiver polls a non-blocking UDP socket, reading the clock between
// attempts, while its peer sleeps 1 ms and then sends. The peer starts its
// delay only after the receiver's first receive found nothing, so the poll
// always waits on the sleeping peer, natively too. Natively the poll spins
// until the datagram arrives. Under Patina the empty receives are no progress,
// so the clock reads keep the advance-on-spin streak, the rescue brings
// virtual time to the sleeper's deadline, and the datagram arrives. Before
// progress was classified by outcome, every empty receive reset the streak and
// the poll never let virtual time move.
fn main() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let address = receiver.local_addr().unwrap();
    let (release, released) = mpsc::channel::<()>();
    let sender = thread::spawn(move || {
        released.recv().unwrap();
        thread::sleep(Duration::from_millis(1));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"ping", address).unwrap();
    });
    let mut buffer = [0u8; 16];
    let first = receiver.recv_from(&mut buffer).map(|_| ()).map_err(|error| error.kind());
    let start = Instant::now();
    release.send(()).unwrap();
    let mut polls = 0u64;
    let received = loop {
        match receiver.recv_from(&mut buffer) {
            Ok((len, _)) => break len,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                polls += 1;
                let _ = Instant::now();
            }
            Err(error) => panic!("recv_from failed: {error}"),
        }
    };
    let waited = start.elapsed() >= Duration::from_millis(1);
    sender.join().unwrap();
    println!(
        "NATIVE_POLL_CLOCK_RESULT first_empty={} payload={} polled={} waited_1ms={waited}",
        first == Err(ErrorKind::WouldBlock),
        String::from_utf8_lossy(&buffer[..received]),
        polls > 0,
    );
}
