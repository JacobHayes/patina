//! Shared socket-ID allocation across datagram and stream operations.

use super::*;
use patina_dst_driver_api::NetDriver;
#[test]
fn tcp_ids_and_udp_ids_share_one_deterministic_counter() {
    let mut net = SimNet::new();
    let udp = net.bind("udp").unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let accepted = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(udp, SocketId(1));
    assert_eq!(listener, SocketId(2));
    assert_eq!(client, SocketId(3));
    assert_eq!(accepted, SocketId(4));
}
