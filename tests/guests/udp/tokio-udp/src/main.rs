//! tokio UdpSocket: an echo server task and client tasks that retry on a timeout; a
//! connected socket to a port nobody holds (ConnectionRefused on recv).
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = srv.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 1500];
        loop {
            let (n, from) = srv.recv_from(&mut b).await.unwrap();
            srv.send_to(&b[..n], from).await.unwrap();
        }
    });
    let mut tasks = vec![];
    for c in 0..4 {
        tasks.push(tokio::spawn(async move {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.connect(addr).await.unwrap();
            let mut resends = 0;
            let mut b = [0u8; 64];
            for k in 0..20 {
                let msg = format!("c{c} m{k:02}");
                loop {
                    s.send(msg.as_bytes()).await.unwrap();
                    match timeout(Duration::from_millis(50), s.recv(&mut b)).await {
                        Ok(Ok(n)) if &b[..n] == msg.as_bytes() => break,
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => panic!("recv: {e}"),
                        Err(_) => resends += 1,
                    }
                }
            }
            resends
        }));
    }
    let mut resends = 0;
    for t in tasks {
        resends += t.await.unwrap();
    }
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    dead.connect("127.0.0.1:9").await.unwrap();
    dead.send(b"x").await.unwrap();
    let r = timeout(Duration::from_secs(1), dead.recv(&mut [0u8; 8])).await;
    let refused = matches!(r, Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused);
    println!("tokio udp: answers 80 resends {resends} refused {refused}");
    assert!(refused, "{r:?}");
}
