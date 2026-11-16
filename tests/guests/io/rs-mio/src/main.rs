// Readiness through mio: a Poll over 8 mio UnixStream pairs and a Waker, fed
// by worker threads; events are printed in the order the loop saw them.
use mio::net::UnixStream;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const PAIRS: usize = 8;
const MSGS: usize = 50;
const WAKE: Token = Token(1000);

fn main() {
    let mut poll = Poll::new().unwrap();
    let waker = Arc::new(Waker::new(poll.registry(), WAKE).unwrap());
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    for i in 0..PAIRS {
        let (mut a, b) = UnixStream::pair().unwrap();
        poll.registry().register(&mut a, Token(i), Interest::READABLE).unwrap();
        ours.push(a);
        theirs.push(b);
    }
    let done = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = theirs
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let waker = waker.clone();
            let done = done.clone();
            thread::spawn(move || {
                // The mio stream is non-blocking: retry on WouldBlock with a short sleep.
                let mut b = b;
                for m in 0..MSGS {
                    let msg = format!("p{i}m{m};");
                    let mut off = 0;
                    while off < msg.len() {
                        match b.write(&msg.as_bytes()[off..]) {
                            Ok(n) => off += n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(std::time::Duration::from_millis(1)),
                            Err(e) => panic!("{e}"),
                        }
                    }
                    if m % 10 == 9 {
                        thread::yield_now();
                    }
                }
                done.fetch_add(1, Ordering::SeqCst);
                waker.wake().unwrap();
                b
            })
        })
        .collect();
    let mut events = Events::with_capacity(64);
    let mut got = vec![0usize; PAIRS];
    let want: Vec<usize> = (0..PAIRS).map(|i| (0..MSGS).map(|m| format!("p{i}m{m};").len()).sum()).collect();
    let mut wakes = 0;
    while got != want || done.load(Ordering::SeqCst) < PAIRS {
        poll.poll(&mut events, None).unwrap();
        for ev in events.iter() {
            if ev.token() == WAKE {
                wakes += 1;
                println!("wake");
                continue;
            }
            let i = ev.token().0;
            let mut buf = [0u8; 4096];
            let mut n = 0;
            loop {
                match ours[i].read(&mut buf) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("{e}"),
                }
            }
            got[i] += n;
            println!("readable {i} {n}");
        }
    }
    let _streams: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    println!("rs-mio ok bytes {} wakes>0 {}", got.iter().sum::<usize>(), wakes > 0);
}
