use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// Two threads over mpsc with recv_timeout. On macOS this drives std's Darwin
// thread Parker (park/park_timeout on a libdispatch semaphore); the shim
// interposes those semaphores and routes the wait through the deterministic
// scheduler + virtual clock, so the delivery/timeout interleaving and the
// timeout count are a function of the seed alone.
fn main() {
    let (tx, rx) = mpsc::channel::<u64>();
    let producer = thread::spawn(move || {
        for i in 0..5 {
            thread::sleep(Duration::from_millis(10));
            tx.send(i).unwrap();
        }
    });
    let mut delivered = Vec::new();
    let mut timeouts = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_millis(7)) {
            Ok(v) => delivered.push(v),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timeouts += 1;
                if delivered.len() == 5 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    println!("NATIVE_RECV_TIMEOUT_RESULT delivered={delivered:?} timeouts={timeouts}");
}
