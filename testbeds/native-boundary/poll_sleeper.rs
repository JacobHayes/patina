use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// A receiver polls a non-blocking UDP socket and does nothing else, while its
// peer sleeps 1 ms and then sends. The peer starts its delay only after the
// receiver's first receive found nothing, so the poll always waits on the
// sleeping peer, natively too, where the polling burns the CPU time that
// moves the clock. Under Patina every receive is charged, and the empty ones
// are escalated, so virtual time reaches the sleeper's deadline. Before calls
// were charged, a poll that never read the clock never let time move.
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
    release.send(()).unwrap();
    let mut polls = 0u64;
    let received = loop {
        match receiver.recv_from(&mut buffer) {
            Ok((len, _)) => break len,
            Err(error) if error.kind() == ErrorKind::WouldBlock => polls += 1,
            Err(error) => panic!("recv_from failed: {error}"),
        }
    };
    sender.join().unwrap();
    println!(
        "NATIVE_POLL_SLEEPER_RESULT first_empty={} payload={} polled={}",
        first == Err(ErrorKind::WouldBlock),
        String::from_utf8_lossy(&buffer[..received]),
        polls > 0,
    );
}
