// tokio multi-thread runtime: an echo server task accepting on 127.0.0.1:0 and 20
// client tasks, each with 50 request/reply round trips, on 4 worker threads.
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut conns = Vec::new();
        for _ in 0..20 {
            let (s, _) = l.accept().await.unwrap();
            conns.push(tokio::spawn(async move {
                s.set_nodelay(true).unwrap();
                let (r, mut w) = s.into_split();
                let mut r = BufReader::new(r);
                let mut line = String::new();
                let mut n = 0u64;
                loop {
                    line.clear();
                    if r.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    n += 1;
                    w.write_all(line.as_bytes()).await.unwrap();
                }
                n
            }));
        }
        let mut t = 0;
        for c in conns {
            t += c.await.unwrap();
        }
        t
    });
    let mut clients = Vec::new();
    for id in 0..20u32 {
        clients.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut sum = 0u64;
            for i in 0..50u32 {
                let msg = format!("task {id:02} message {i:03}\n");
                s.write_all(msg.as_bytes()).await.unwrap();
                let mut back = vec![0u8; msg.len()];
                s.read_exact(&mut back).await.unwrap();
                assert_eq!(back, msg.as_bytes());
                sum += back.iter().map(|&b| b as u64).sum::<u64>();
            }
            s.shutdown().await.unwrap();
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            sum
        }));
    }
    let mut sum = 0u64;
    for c in clients {
        sum += c.await.unwrap();
    }
    let lines = server.await.unwrap();
    // A timer racing a read that never completes: the timeout fires in virtual time.
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p2 = l2.local_addr().unwrap().port();
    let mut c2 = TcpStream::connect(("127.0.0.1", p2)).await.unwrap();
    let (_s2, _) = l2.accept().await.unwrap();
    let mut b = [0u8; 1];
    let t = tokio::time::timeout(std::time::Duration::from_secs(3), c2.read(&mut b)).await;
    println!("tokio-echo lines {lines} checksum {sum} idle read timed out {}", t.is_err());
}
