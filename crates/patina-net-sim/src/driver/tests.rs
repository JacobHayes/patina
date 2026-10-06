//! Datagram routing, delivery, readiness, and stream lifecycle tests.

use super::*;
#[test]
fn packets_observe_delivery_time_and_can_reorder() {
    let mut net = SimNet::new();
    let left = net.bind("left").unwrap();
    let right = net.bind("right").unwrap();
    net.send(left, "right", b"late", 20).unwrap();
    net.send(left, "right", b"early", 10).unwrap();
    assert_eq!(net.recv(right, 9).unwrap(), None);
    assert_eq!(net.recv(right, 10).unwrap().unwrap().bytes, b"early");
    assert_eq!(net.recv(right, 20).unwrap().unwrap().bytes, b"late");
}

#[test]
fn next_delivery_reports_the_earliest_future_arrival_and_ignores_dropped_packets() {
    let mut net = SimNet::builder()
        .base_latency_nanos(5)
        .partition("left", "blocked")
        .build()
        .unwrap();
    let left = net.bind("left").unwrap();
    let right = net.bind("right").unwrap();
    net.bind("blocked").unwrap();
    net.send(left, "right", b"late", 20).unwrap();
    net.send(left, "right", b"early", 10).unwrap();
    net.send(left, "blocked", b"lost", 1).unwrap();
    assert_eq!(net.next_delivery(right, 0).unwrap(), Some(15));
    assert_eq!(net.next_delivery(right, 15).unwrap(), Some(25));
    assert_eq!(net.next_delivery(right, 25).unwrap(), None);
    assert_eq!(
        net.next_delivery(SocketId(999), 0).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
}

#[test]
fn next_delivery_after_close_sees_no_packets() {
    let mut net = SimNet::new();
    let sender = net.bind("sender").unwrap();
    let receiver = net.bind("receiver").unwrap();
    net.send(sender, "receiver", b"data", 100).unwrap();
    assert_eq!(net.next_delivery(receiver, 0).unwrap(), Some(100));
    net.close(receiver).unwrap();
    let rebound = net.bind("receiver").unwrap();
    assert_eq!(net.next_delivery(rebound, 0).unwrap(), None);
}

#[test]
fn close_keeps_in_flight_sends_and_drops_undelivered_arrivals() {
    let mut net = SimNet::new();
    let sender = net.bind("sender").unwrap();
    let receiver = net.bind("receiver").unwrap();
    net.send(sender, "receiver", b"reply", 0).unwrap();
    net.close(sender).unwrap();
    assert_eq!(net.recv(receiver, 0).unwrap().unwrap().bytes, b"reply");
    assert_eq!(
        net.send(receiver, "sender", b"gone", 0)
            .unwrap()
            .disposition,
        SendDisposition::Unreachable
    );
}

#[test]
fn a_wildcard_bind_receives_traffic_dialed_at_any_address_on_its_port() {
    // The producer-side enabler: ordinary server code binds INADDR_ANY as it
    // would in production, and a client that resolved a name to some virtual
    // IP reaches it by dialing that IP.
    let mut net = SimNet::new();
    let server = net.bind("0.0.0.0:80").unwrap();
    let client = net.bind("10.0.0.9:5000").unwrap();
    net.send(client, "10.0.0.5:80", b"hello", 0).unwrap();
    let datagram = net.recv(server, 0).unwrap().expect("wildcard delivery");
    assert_eq!(datagram.bytes, b"hello");
    assert_eq!(datagram.from, "10.0.0.9:5000");

    // TCP takes the same route.
    let listener = net.tcp_listen("0.0.0.0:81", 4).unwrap();
    let stream = net.tcp_connect("10.0.0.9:5001", "10.0.0.5:81", 0).unwrap();
    let accepted = net
        .tcp_accept(listener, 0)
        .unwrap()
        .expect("wildcard TCP accept");
    assert_eq!(accepted.peer, "10.0.0.9:5001");
    net.tcp_send(stream, b"ping", 0).unwrap();
    assert_eq!(
        net.tcp_recv(accepted.socket, 8, 0).unwrap().unwrap(),
        b"ping"
    );
}

#[test]
fn an_exact_binding_always_wins_over_a_wildcard_one() {
    let mut net = SimNet::new();
    let wildcard = net.bind("0.0.0.0:80").unwrap();
    let exact = net.bind("10.0.0.5:80").unwrap();
    let client = net.bind("10.0.0.9:5000").unwrap();
    net.send(client, "10.0.0.5:80", b"exact", 0).unwrap();
    assert!(
        net.recv(wildcard, 0).unwrap().is_none(),
        "the wildcard socket must not steal an exactly-bound address"
    );
    assert_eq!(net.recv(exact, 0).unwrap().unwrap().bytes, b"exact");
}

#[test]
fn the_wildcard_rule_never_invents_a_route() {
    // A port with no wildcard listener stays unroutable, and a non-`ip:port`
    // address (the explicit API binds bare labels) is exact-match only.
    let mut net = SimNet::new();
    net.bind("0.0.0.0:80").unwrap();
    let client = net.bind("10.0.0.9:5000").unwrap();
    let unreachable = |report: SendReport| {
        report.disposition == SendDisposition::Unreachable && report.copies == 0
    };
    assert!(
        unreachable(net.send(client, "10.0.0.5:81", b"nope", 0).unwrap()),
        "no wildcard listener on port 81"
    );
    net.bind("server").unwrap();
    assert!(
        unreachable(net.send(client, "other-label", b"nope", 0).unwrap()),
        "a bare label has no wildcard form"
    );
    assert_eq!(
        net.tcp_connect("10.0.0.9:5001", "10.0.0.5:80", 0)
            .unwrap_err()
            .code,
        ErrorCode::ConnectionRefused,
        "a datagram wildcard bind is not a TCP listener"
    );
}

#[test]
fn a_dual_stack_wildcard_takes_both_families_after_their_own_wildcards() {
    let mut net = SimNet::new();
    let any = net.bind("*:80").unwrap();
    let v4 = net.bind("127.0.0.1:5000").unwrap();
    let v6 = net.bind("[::1]:5000").unwrap();
    net.send(v4, "127.0.0.1:80", b"four", 0).unwrap();
    net.send(v6, "[::1]:80", b"six", 0).unwrap();
    assert_eq!(net.recv(any, 0).unwrap().unwrap().bytes, b"four");
    assert_eq!(net.recv(any, 0).unwrap().unwrap().bytes, b"six");
    let only_v6 = net.bind("[::]:80").unwrap();
    net.send(v6, "[::1]:80", b"own", 0).unwrap();
    assert_eq!(net.recv(only_v6, 0).unwrap().unwrap().bytes, b"own");
    assert!(net.recv(any, 0).unwrap().is_none());
}

#[test]
fn a_shared_binding_hands_each_sender_to_one_fixed_member() {
    let mut net = SimNet::new();
    let first = net.bind_shared("127.0.0.1:80").unwrap();
    let second = net.bind_shared("127.0.0.1:80").unwrap();
    assert_eq!(
        net.bind("127.0.0.1:80").unwrap_err().code,
        ErrorCode::AlreadyBound,
        "an unshared bind cannot join a shared binding"
    );
    let senders: Vec<SocketId> = (0..8)
        .map(|port| net.bind(&format!("127.0.0.1:{}", 6000 + port)).unwrap())
        .collect();
    for sender in &senders {
        for _ in 0..2 {
            net.send(*sender, "127.0.0.1:80", b"x", 0).unwrap();
        }
    }
    let mut drained = |member| {
        let mut from = Vec::new();
        while let Some(datagram) = net.recv(member, 0).unwrap() {
            from.push(datagram.from);
        }
        from
    };
    let (a, b) = (drained(first), drained(second));
    assert_eq!(a.len() + b.len(), 16);
    assert!(!a.is_empty() && !b.is_empty(), "both members take traffic");
    assert!(
        a.iter().all(|from| !b.contains(from)),
        "a sender's datagrams all go to one member"
    );
    net.close(first).unwrap();
    net.send(senders[0], "127.0.0.1:80", b"y", 0).unwrap();
    assert!(
        net.recv(second, 0).unwrap().is_some(),
        "the survivor takes it all"
    );
}

#[test]
fn peeks_leave_the_data_queued() {
    let mut net = SimNet::new();
    let sender = net.bind("a").unwrap();
    let receiver = net.bind("b").unwrap();
    net.send(sender, "b", b"datagram", 0).unwrap();
    assert_eq!(net.peek(receiver, 0).unwrap().unwrap().bytes, b"datagram");
    assert_eq!(net.recv(receiver, 0).unwrap().unwrap().bytes, b"datagram");
    assert!(net.peek(receiver, 0).unwrap().is_none());

    let listener = net.tcp_listen("127.0.0.1:80", 1).unwrap();
    let client = net
        .tcp_connect("127.0.0.1:5000", "127.0.0.1:80", 0)
        .unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"hello", 0).unwrap();
    net.tcp_send(client, b" world", 0).unwrap();
    assert_eq!(net.tcp_peek(server, 8, 0).unwrap().unwrap(), b"hello wo");
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap().unwrap(),
        b"hello world"
    );
    assert_eq!(net.tcp_peek(server, 8, 0).unwrap(), None);
    net.tcp_shutdown(client, ShutdownHow::Write).unwrap();
    assert_eq!(net.tcp_peek(server, 8, 0).unwrap(), Some(Vec::new()));
}

#[test]
fn readiness_counts_arrivals_and_reports_the_peer_fin_while_data_is_queued() {
    let mut net = SimNet::new();
    let sender = net.bind("a").unwrap();
    let receiver = net.bind("b").unwrap();
    for _ in 0..2 {
        net.send(sender, "b", b"xyz", 0).unwrap();
    }
    let before = net.readiness(receiver, 0).unwrap();
    assert_eq!((before.arrivals, before.pending), (2, 3));
    net.recv(receiver, 0).unwrap();
    assert_eq!(
        net.readiness(receiver, 0).unwrap().arrivals,
        2,
        "a read is no arrival"
    );

    let listener = net.tcp_listen("127.0.0.1:80", 1).unwrap();
    let client = net
        .tcp_connect("127.0.0.1:5000", "127.0.0.1:80", 0)
        .unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"ab", 0).unwrap();
    net.tcp_shutdown(client, ShutdownHow::Write).unwrap();
    let queued = net.readiness(server, 0).unwrap();
    assert!(queued.peer_write_closed && !queued.read_eof);
    assert_eq!((queued.arrivals, queued.pending), (2, 2));
    net.tcp_recv(server, 1, 0).unwrap();
    assert_eq!(net.readiness(server, 0).unwrap().arrivals, 2);
}

/// The FIN follows the bytes sent before it: while any of them is still
/// in flight the peer's shutdown has not arrived, so a reactor that
/// trusted it would report a readable stream whose receive would block.
#[test]
fn a_peer_shutdown_arrives_after_the_bytes_it_follows() {
    let mut net = SimNet::builder().base_latency_nanos(10).build().unwrap();
    let listener = net.tcp_listen("127.0.0.1:80", 1).unwrap();
    let client = net
        .tcp_connect("127.0.0.1:5000", "127.0.0.1:80", 0)
        .unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"ab", 0).unwrap();
    net.tcp_shutdown(client, ShutdownHow::Write).unwrap();
    let in_flight = net.readiness(server, 5).unwrap();
    assert!(!in_flight.readable && !in_flight.peer_write_closed);
    assert_eq!((in_flight.arrivals, in_flight.pending), (0, 0));
    let arrived = net.readiness(server, 10).unwrap();
    assert!(arrived.readable && arrived.peer_write_closed);
    assert_eq!((arrived.arrivals, arrived.pending), (2, 2));
}

/// A connected datagram socket takes only its peer's datagrams to its
/// local address; another sender's goes to an unconnected socket on the
/// port or is unreachable, and a release takes everything again.
#[test]
fn a_connected_datagram_socket_admits_only_its_peer() {
    let mut net = SimNet::new();
    let receiver = net.bind("0.0.0.0:7").unwrap();
    let peer = net.bind("127.0.0.1:8").unwrap();
    let stranger = net.bind("127.0.0.1:9").unwrap();
    net.connect_datagram(receiver, "127.0.0.1:7", Some("127.0.0.1:8"))
        .unwrap();
    let from_peer = net.send(peer, "127.0.0.1:7", b"p", 0).unwrap();
    assert_eq!(from_peer.disposition, SendDisposition::Queued);
    let refused = net.send(stranger, "127.0.0.1:7", b"s", 0).unwrap();
    assert_eq!(refused.disposition, SendDisposition::Unreachable);
    let other_address = net.send(peer, "10.0.0.1:7", b"a", 0).unwrap();
    assert_eq!(other_address.disposition, SendDisposition::Unreachable);
    assert_eq!(net.recv(receiver, 0).unwrap().unwrap().bytes, b"p");
    assert!(net.recv(receiver, 0).unwrap().is_none());
    net.connect_datagram(receiver, "", None).unwrap();
    net.send(stranger, "127.0.0.1:7", b"s", 0).unwrap();
    assert_eq!(net.recv(receiver, 0).unwrap().unwrap().bytes, b"s");
}

/// A wildcard-bound socket connected from its routed source is found
/// by its whole 4-tuple ahead of an unconnected socket bound at that
/// exact address (the kernel rehashes it there); a stranger's datagram
/// still reaches the exact one.
#[test]
fn a_connected_wildcard_member_outranks_an_exact_open_binding() {
    let mut net = SimNet::new();
    let wildcard = net.bind_shared("0.0.0.0:7").unwrap();
    let exact = net.bind_shared("127.0.0.1:7").unwrap();
    let peer = net.bind("127.0.0.1:8").unwrap();
    let stranger = net.bind("127.0.0.1:9").unwrap();
    net.connect_datagram(wildcard, "127.0.0.1:7", Some("127.0.0.1:8"))
        .unwrap();
    net.send(peer, "127.0.0.1:7", b"p", 0).unwrap();
    net.send(stranger, "127.0.0.1:7", b"s", 0).unwrap();
    assert_eq!(net.recv(wildcard, 0).unwrap().unwrap().bytes, b"p");
    assert_eq!(net.recv(exact, 0).unwrap().unwrap().bytes, b"s");
    assert!(net.recv(wildcard, 0).unwrap().is_none());
}

#[test]
fn duplicate_bind_is_rejected() {
    let mut net = SimNet::new();
    net.bind("addr").unwrap();
    assert_eq!(net.bind("addr").unwrap_err().code, ErrorCode::AlreadyBound);
}

#[test]
fn tcp_connect_accept_and_transfer_round_trip() {
    let mut net = SimNet::new();
    let listener = net.tcp_listen("127.0.0.1:80", 8).unwrap();
    let client = net
        .tcp_connect("127.0.0.1:49152", "127.0.0.1:80", 0)
        .unwrap();
    let accepted = net.tcp_accept(listener, 0).unwrap().unwrap();
    assert_eq!(accepted.peer, "127.0.0.1:49152");
    net.tcp_send(client, b"hello", 0).unwrap();
    net.tcp_send(client, b" world", 0).unwrap();
    assert_eq!(
        net.tcp_recv(accepted.socket, 64, 0).unwrap().unwrap(),
        b"hello world"
    );
    net.tcp_send(accepted.socket, b"reply", 0).unwrap();
    assert_eq!(net.tcp_recv(client, 64, 0).unwrap().unwrap(), b"reply");
}

#[test]
fn tcp_connect_without_listener_or_full_backlog_is_refused() {
    let mut net = SimNet::builder()
        .partition("127.0.0.1:1", "127.0.0.1:2")
        .build()
        .unwrap();
    assert_eq!(
        net.tcp_connect("127.0.0.1:1", "127.0.0.1:9", 0)
            .unwrap_err()
            .code,
        ErrorCode::ConnectionRefused
    );
    net.tcp_listen("127.0.0.1:2", 1).unwrap();
    assert_eq!(
        net.tcp_connect("127.0.0.1:1", "127.0.0.1:2", 0)
            .unwrap_err()
            .code,
        ErrorCode::ConnectionRefused
    );
    net.tcp_listen("127.0.0.1:3", 1).unwrap();
    net.tcp_connect("127.0.0.1:4", "127.0.0.1:3", 0).unwrap();
    assert_eq!(
        net.tcp_connect("127.0.0.1:5", "127.0.0.1:3", 0)
            .unwrap_err()
            .code,
        ErrorCode::ConnectionRefused
    );
}

#[test]
fn tcp_backpressure_caps_the_inbox_and_reads_reopen_it() {
    let mut net = SimNet::builder().tcp_buffer_bytes(4).build().unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"abcdef", 0).unwrap(), 4);
    assert_eq!(net.tcp_send(client, b"z", 0).unwrap(), 0);
    assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"ab");
    assert_eq!(net.tcp_send(client, b"xy", 0).unwrap(), 2);
    assert_eq!(net.tcp_recv(server, 16, 0).unwrap().unwrap(), b"cdxy");
}

#[test]
fn tcp_half_close_drains_buffered_data_then_reads_eof() {
    let mut net = SimNet::new();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"abc", 0).unwrap();
    net.tcp_shutdown(client, ShutdownHow::Write).unwrap();
    assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"ab");
    assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"c");
    assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"");
    assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"");
    net.tcp_send(server, b"back", 0).unwrap();
    assert_eq!(net.tcp_recv(client, 8, 0).unwrap().unwrap(), b"back");
    assert_eq!(
        net.tcp_send(client, b"again", 0).unwrap_err().code,
        ErrorCode::BrokenPipe
    );
}

#[test]
fn tcp_shutdown_read_discards_and_peer_sends_are_swallowed() {
    let mut net = SimNet::new();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"queued", 0).unwrap();
    net.tcp_shutdown(server, ShutdownHow::Read).unwrap();
    assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"");
    assert_eq!(net.tcp_send(client, b"discarded", 0).unwrap(), 9);
}

#[test]
fn tcp_close_resets_pending_and_gracefully_eofs_established() {
    let mut net = SimNet::new();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    net.close(listener).unwrap();
    assert_eq!(
        net.tcp_recv(client, 1, 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
    assert_eq!(
        net.tcp_send(client, b"x", 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );

    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client2", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"data", 0).unwrap();
    net.close(client).unwrap();
    assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"data");
    assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"");
    assert_eq!(
        net.tcp_send(server, b"late", 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
}

#[test]
fn tcp_next_delivery_reports_future_segments() {
    let mut net = SimNet::new();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"later", 100).unwrap();
    assert_eq!(net.next_delivery(server, 0).unwrap(), Some(100));
    assert_eq!(net.tcp_recv(server, 16, 99).unwrap(), None);
    assert_eq!(net.tcp_recv(server, 16, 100).unwrap().unwrap(), b"later");
    assert_eq!(net.next_delivery(server, 100).unwrap(), None);
}
