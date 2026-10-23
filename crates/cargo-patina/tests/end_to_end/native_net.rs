//! Native TCP and DNS modeling, latency, faults, and replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    // One networking guest; `NET_MODE` picks the scenario.
    //
    // `wildcard` — a guest bound to INADDR_ANY is reached by a client dialing a
    //   specific virtual IP, over UDP and TCP. This runs through the shim, not
    //   just SimNet: the shim keeps its own address-keyed tables to decide which
    //   blocked task to wake, so a routing rule applied only in the driver
    //   delivers the datagram and then hangs on a receive nothing wakes.
    // `resolve` — ordinary `std::net` name lookup (getaddrinfo) of a defined and
    //   an undefined name, timed on the virtual clock.
    // `connect` — the producer side: a wildcard-bound listener reached purely by
    //   resolving a name to a virtual IP.
    // `latency` — one TCP echo round trip, timed on the virtual clock.
    // `echo` — a loopback TCP stream of eight 2-byte segments answered with
    //   their checksum: a reliable stream never loses data, so the result is
    //   invariant under the net fault knobs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const NET_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

fn wildcard() {
    let server = UdpSocket::bind("0.0.0.0:7100").expect("udp wildcard bind");
    let receiver = thread::spawn(move || {
        let mut buf = [0u8; 16];
        let (len, from) = server.recv_from(&mut buf).expect("recv_from");
        (String::from_utf8_lossy(&buf[..len]).into_owned(), from.to_string())
    });
    let client = UdpSocket::bind("10.0.0.9:7200").expect("udp client bind");
    // Sleep before sending so the receiver parks in its blocking recv first;
    // otherwise the datagram is already queued and the shim's wake path is
    // never exercised.
    thread::sleep(Duration::from_millis(1));
    client.send_to(b"udp-ping", "10.0.0.5:7100").expect("send_to");
    let (udp_payload, udp_from) = receiver.join().unwrap();

    let listener = TcpListener::bind("0.0.0.0:7101").expect("tcp wildcard bind");
    let acceptor = thread::spawn(move || {
        let (mut sock, peer) = listener.accept().expect("accept");
        let mut got = [0u8; 8];
        sock.read_exact(&mut got).expect("read_exact");
        sock.write_all(b"tcp-pong").expect("reply");
        (String::from_utf8_lossy(&got).into_owned(), peer.to_string())
    });
    thread::sleep(Duration::from_millis(1));
    let mut stream = TcpStream::connect("10.0.0.5:7101").expect("tcp connect");
    stream.write_all(b"tcp-ping").expect("write");
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).expect("read reply");
    let (tcp_payload, tcp_peer) = acceptor.join().unwrap();
    println!(
        "NET_RESULT udp={udp_payload} udp_from={udp_from} tcp={tcp_payload} tcp_peer={tcp_peer} reply={}",
        String::from_utf8_lossy(&reply)
    );
}

fn lookup(name: &str) -> Result<String, String> {
    match (name, 9400).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => Ok(addr.ip().to_string()),
            None => Err("empty".to_string()),
        },
        Err(error) => Err(format!("{:?}", error.kind())),
    }
}

fn resolve() {
    let started = Instant::now();
    let defined = lookup("db.internal");
    let elapsed = started.elapsed().as_nanos();
    let undefined = lookup("absent.internal");
    println!("NET_RESULT defined={defined:?} undefined={undefined:?} elapsed_nanos={elapsed}");
}

fn connect() {
    let listener = TcpListener::bind("0.0.0.0:9400").expect("wildcard bind");
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut got = [0u8; 4];
        sock.read_exact(&mut got).expect("read");
        sock.write_all(b"pong").expect("reply");
    });
    let mut client = TcpStream::connect("db.internal:9400").expect("connect by name");
    client.write_all(b"ping").expect("write");
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("read reply");
    server.join().unwrap();
    println!("NET_RESULT connected={}", String::from_utf8_lossy(&reply));
}

fn latency() {
    let listener = TcpListener::bind("127.0.0.1:6124").expect("bind");
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut got = [0u8; 4];
        sock.read_exact(&mut got).expect("read_exact");
        sock.write_all(&got).expect("reply");
    });
    let mut client = TcpStream::connect("127.0.0.1:6124").expect("connect");
    let started = Instant::now();
    client.write_all(b"ping").expect("write");
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("read reply");
    let elapsed = started.elapsed().as_nanos();
    server.join().unwrap();
    assert_eq!(&reply, b"ping");
    println!("NET_RESULT elapsed_nanos={elapsed}");
}

fn echo() {
    let listener = TcpListener::bind("127.0.0.1:6123").expect("bind");
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut got = vec![0u8; 16];
        sock.read_exact(&mut got).expect("read_exact");
        let sum: u32 = got.iter().map(|&b| b as u32).sum();
        sock.write_all(&sum.to_le_bytes()).expect("reply");
        sum
    });
    let mut client = TcpStream::connect("127.0.0.1:6123").expect("connect");
    for i in 0u8..8 {
        client.write_all(&[i, i.wrapping_add(100)]).expect("write");
    }
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("read reply");
    let sum = server.join().unwrap();
    println!("NET_RESULT sum={} reply={}", sum, u32::from_le_bytes(reply));
}

fn main() {
    match std::env::var("NET_MODE").expect("NET_MODE").as_str() {
        "wildcard" => wildcard(),
        "resolve" => resolve(),
        "connect" => connect(),
        "latency" => latency(),
        "echo" => echo(),
        other => panic!("unknown mode {other}"),
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_net_routes_resolves_and_applies_latency_and_faults() {
        let guest = native_build::source_guest("net", NET_SOURCE);
        let entry = "db.internal=10.0.0.5";
        let run = |seed: &str, mode: &str, flags: &[&str]| {
            let mode = format!("NET_MODE={mode}");
            let mut args = vec!["--seed", seed, "--env", &mode];
            args.extend_from_slice(flags);
            common::native::assert_success(guest.command("run", &args))
        };
        let result = |output: &Output| stdout_line_with(output, "NET_RESULT");
        let elapsed_of = |output: &Output| -> u64 {
            result(output)
                .rsplit_once("elapsed_nanos=")
                .expect("elapsed_nanos=N")
                .1
                .parse()
                .expect("elapsed nanos")
        };
        let assert_applied = |output: &Output, report: &str| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(report) && stderr.contains("vacuous=0"),
                "the {report} must prove the knob fired:\n{stderr}"
            );
        };

        let wildcard = result(&run("3", "wildcard", &[]));
        for field in [
            "udp=udp-ping",
            "udp_from=10.0.0.9:7200",
            "tcp=tcp-ping",
            // The TCP client never bound, so the connect chose its source as the
            // kernel does: the address of the interface routing to 10.0.0.5
            // (`eth0`, 10.0.0.1) and an ephemeral port.
            "tcp_peer=10.0.0.1:",
            "reply=tcp-pong",
        ] {
            assert!(wildcard.contains(field), "missing {field}: {wildcard}");
        }

        // A defined name resolves through the host table and an undefined one is
        // NXDOMAIN, at only the resolution calls' own charges.
        let resolved = run("1", "resolve", &["--dns-entry", entry]);
        let line = result(&resolved);
        assert!(
            line.contains(r#"defined=Ok("10.0.0.5")"#) && line.contains("undefined=Err"),
            "host table did not drive resolution: {line}"
        );
        assert!(
            elapsed_of(&resolved) < 10_000,
            "a knob-free resolution must cost no virtual time: {line}"
        );
        let failed = run(
            "1",
            "resolve",
            &["--dns-entry", entry, "--dns-fail-permille", "1000"],
        );
        assert!(
            result(&failed).contains("defined=Err"),
            "{}",
            result(&failed)
        );
        assert_applied(&failed, "PATINA_DNS_FAULT_REPORT");
        // The latency knob is virtual time inside the guest, and a flag-free
        // replay restores both the host table and the knob from the trace.
        let delayed = guest.assert_run_success(
            1,
            &[
                "--env",
                "NET_MODE=resolve",
                "--dns-entry",
                entry,
                "--dns-latency-nanos",
                "1000000..1000000",
            ],
        );
        assert!(
            (1_000_000..1_000_000 + 10_000).contains(&elapsed_of(&delayed)),
            "the DNS latency knob was not observable in the guest: {}",
            result(&delayed)
        );
        let connected = run("2", "connect", &["--dns-entry", entry]);
        assert!(
            result(&connected).contains("connected=pong"),
            "a resolved name did not reach the wildcard-bound listener"
        );

        // A zero-latency link completes the round trip in the calls' own charges;
        // with a base latency each segment (request and reply) carries it.
        assert!(elapsed_of(&run("5", "latency", &[])) < 10_000);
        let elapsed = elapsed_of(&run("5", "latency", &["--net-latency-nanos", "1000000"]));
        assert!(
            elapsed >= 2_000_000,
            "TCP base latency is inert on the stream path: round trip took {elapsed}ns"
        );

        // The net fault knobs bite on the TCP stream path: the faulted run is
        // deterministic and replays, the schedule follows the seed and differs
        // from the fault-free run, yet the reliable stream's result is invariant.
        let faults = [
            "--net-jitter-nanos",
            "1000..50000",
            "--net-drop-permille",
            "100",
        ];
        let mut fault_flags = vec!["--env", "NET_MODE=echo"];
        fault_flags.extend(faults);
        let (faulted, trace) = guest.assert_recorded(1, &fault_flags);
        assert_applied(&faulted, "PATINA_NET_FAULT_REPORT");
        assert!(
            !String::from_utf8_lossy(&faulted.stderr).contains("net fault knobs inert"),
            "the vacuity warning must not fire when faults applied"
        );
        let record = |seed: &str, flags: &[&str], name: &str| {
            let other = guest.dir.path().join(name);
            let mut args = flags.to_vec();
            args.extend(["--record", other.to_str().unwrap()]);
            (run(seed, "echo", &args), fs::read(&other).unwrap())
        };
        let faulted_trace = fs::read(&trace).unwrap();
        let (_, reseeded) = record("2", &faults, "fault-seed2.patina");
        assert_ne!(
            faulted_trace, reseeded,
            "a different seed must draw a different fault schedule"
        );
        let (clean, clean_trace) = record("1", &[], "nofault.patina");
        assert_ne!(
            faulted_trace, clean_trace,
            "the fault knobs must perturb the TCP trace"
        );
        assert_eq!(
            result(&faulted),
            result(&clean),
            "TCP faults must reorder or delay but never lose data"
        );
    }
}
