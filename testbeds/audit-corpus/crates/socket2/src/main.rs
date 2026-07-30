
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
fn main() {
    let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    s.bind(&addr.into()).unwrap();
    s.listen(128).unwrap();
    println!("bound");
}
