//! Native TCP and DNS modeling, latency, faults, and replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    // TCP *stream* path — the surface the `--net-jitter-nanos`/`--net-drop-permille`
    // knobs historically ignored.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const TCP_ECHO_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
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
    println!("TCP_ECHO_RESULT sum={} reply={}", sum, u32::from_le_bytes(reply));
}
"#;

    // A guest that binds INADDR_ANY, reached by a client dialing a specific virtual
    // IP — the producer-side enabler for name resolution (a resolved name yields an
    // address the server never had to know about). This must run through the SHIM,
    // not just SimNet: the shim keeps its own address-keyed tables to decide which
    // blocked task to wake, so a routing rule applied only in the driver delivers the
    // datagram and then hangs forever on a receive nothing wakes.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const WILDCARD_BIND_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

fn main() {
    // UDP: bind the wildcard, receive a datagram addressed to a specific IP.
    let server = UdpSocket::bind("0.0.0.0:7100").expect("udp wildcard bind");
    let receiver = thread::spawn(move || {
        let mut buf = [0u8; 16];
        let (len, from) = server.recv_from(&mut buf).expect("recv_from");
        (String::from_utf8_lossy(&buf[..len]).into_owned(), from.to_string())
    });
    let client = UdpSocket::bind("10.0.0.9:7200").expect("udp client bind");
    // Sleep before sending so the receiver definitely reaches its blocking
    // recv and PARKS first. Without this the datagram is already queued when
    // the receiver first looks, and the wake path — the half of the routing
    // rule that lives in the shim's own address-keyed tables — is never
    // exercised at all.
    thread::sleep(Duration::from_millis(1));
    client.send_to(b"udp-ping", "10.0.0.5:7100").expect("send_to");
    let (udp_payload, udp_from) = receiver.join().unwrap();

    // TCP: same shape, and the reply proves both wake directions work.
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
        "WILDCARD_RESULT udp={udp_payload} udp_from={udp_from} tcp={tcp_payload} tcp_peer={tcp_peer} reply={}",
        String::from_utf8_lossy(&reply)
    );
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_wildcard_bound_guest_is_reachable_at_any_address_on_its_port() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("wildcard.rs");
        fs::write(&source, WILDCARD_BIND_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("wildcard");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap().to_owned();
        let output = invoke(workspace, &["run", &bin, "--seed", "3"]);
        let line = stdout_line_with(&output, "WILDCARD_RESULT");
        assert!(
            line.contains("udp=udp-ping")
            && line.contains("udp_from=10.0.0.9:7200")
            && line.contains("tcp=tcp-ping")
            // The TCP client never bound, so the connect chose its source as
            // the kernel does: the address of the interface routing to
            // 10.0.0.5 (`eth0`, 10.0.0.1) and an ephemeral port; what matters
            // is that the acceptor learned it.
            && line.contains("tcp_peer=10.0.0.1:")
            && line.contains("reply=tcp-pong"),
            "wildcard-bound guest did not see the traffic dialed at a specific IP: {line}"
        );
    }

    // DNS end to end: the guest resolves through ordinary `std::net` name lookup
    // (getaddrinfo under the hood), so this proves the interposer, the host table,
    // both fault knobs, and the recorded-resolution replay in one guest.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const DNS_SOURCE: &str = r#"
use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Instant;

fn resolve(name: &str) -> Result<String, String> {
    match (name, 9400).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => Ok(addr.ip().to_string()),
            None => Err("empty".to_string()),
        },
        Err(error) => Err(format!("{:?}", error.kind())),
    }
}

fn main() {
    match env::args().nth(1).expect("mode").as_str() {
        "resolve" => {
            let started = Instant::now();
            let defined = resolve("db.internal");
            let elapsed = started.elapsed().as_nanos();
            let undefined = resolve("absent.internal");
            println!(
                "DNS_RESULT defined={defined:?} undefined={undefined:?} elapsed_nanos={elapsed}"
            );
        }
        "connect" => {
            // The producer side: the server binds INADDR_ANY and the client
            // reaches it purely by resolving a name to a virtual IP.
            use std::io::{Read, Write};
            use std::net::TcpListener;
            use std::thread;
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
            println!("DNS_RESULT connected={}", String::from_utf8_lossy(&reply));
        }
        other => panic!("unknown mode {other}"),
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_dns_resolves_the_host_table_injects_faults_and_replays_flag_free() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("dns.rs");
        fs::write(&source, DNS_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("dns");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap().to_owned();
        let entry = "db.internal=10.0.0.5";

        // Baseline: a DEFINED name resolves to its address and an undefined one is
        // NXDOMAIN. Both are ordinary `std` name lookups through the interposer.
        let resolved = invoke(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "1",
                "--dns-entry",
                entry,
                "--",
                "resolve",
            ],
        );
        let line = stdout_line_with(&resolved, "DNS_RESULT");
        assert!(
            line.contains(r#"defined=Ok("10.0.0.5")"#) && line.contains("undefined=Err"),
            "host table did not drive resolution: {line}"
        );
        // Only the resolution's own calls' charges (under a microsecond each).
        let elapsed_in = |line: &str| -> u64 {
            line.rsplit_once("elapsed_nanos=")
                .unwrap()
                .1
                .parse()
                .unwrap()
        };
        let charged = elapsed_in(&line);
        assert!(
            charged < 10_000,
            "a knob-free resolution must cost no virtual time: {line}"
        );

        // The failure knob turns a defined name's resolution into an error, and the
        // report proves it was applied rather than silently inert.
        let failed = invoke(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "1",
                "--dns-entry",
                entry,
                "--dns-fail-permille",
                "1000",
                "--",
                "resolve",
            ],
        );
        let line = stdout_line_with(&failed, "DNS_RESULT");
        assert!(
            line.contains("defined=Err"),
            "the DNS failure knob did not reach the guest: {line}"
        );
        let stderr = String::from_utf8_lossy(&failed.stderr);
        assert!(
            stderr.contains("PATINA_DNS_FAULT_REPORT") && stderr.contains("vacuous=0"),
            "the DNS fault report must prove the knob fired:\n{stderr}"
        );

        // The latency knob shows up as virtual time inside the guest.
        let trace = directory.path().join("dns.patina");
        let delayed = invoke(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "1",
                "--dns-entry",
                entry,
                "--dns-latency-nanos",
                "1000000..1000000",
                "--record",
                trace.to_str().unwrap(),
                "--",
                "resolve",
            ],
        );
        let delayed_line = stdout_line_with(&delayed, "DNS_RESULT");
        // The latency, and the calls' charges it does not already cover.
        assert!(
            (1_000_000..1_000_000 + 10_000).contains(&elapsed_in(&delayed_line)),
            "the DNS latency knob was not observable in the guest: {delayed_line}"
        );

        // Flag-free replay restores BOTH the host table and the knobs from the
        // trace, and a re-supplied table is refused.
        let replayed = invoke(workspace, &["replay", &bin, trace.to_str().unwrap()]);
        assert_eq!(stdout_line_with(&replayed, "DNS_RESULT"), delayed_line);
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                &bin,
                trace.to_str().unwrap(),
                "--dns-entry",
                entry,
            ],
        );
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("--dns-entry"));

        // The producer side end to end: resolve a name, reach a wildcard-bound
        // listener that never knew the name existed.
        let connected = invoke(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "2",
                "--dns-entry",
                entry,
                "--",
                "connect",
            ],
        );
        assert!(
            stdout_line_with(&connected, "DNS_RESULT").contains("connected=pong"),
            "a resolved name did not reach the wildcard-bound listener"
        );
    }

    // The TCP round trip, timed on the virtual clock. `--net-latency-nanos` was a
    // datagram-only knob in practice: SimNet configured a base latency but skipped it
    // on the stream path, so a managed TCP guest saw zero link delay however the
    // operator set it. This guest reports the virtual time an echo round trip takes,
    // which is the operator-visible consequence.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const TCP_LATENCY_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

fn main() {
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
    println!("TCP_LATENCY_RESULT elapsed_nanos={elapsed}");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_tcp_base_latency_delays_the_stream_round_trip() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("tcp_latency.rs");
        fs::write(&source, TCP_LATENCY_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("tcp-latency");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap().to_owned();
        let elapsed_of = |output: &std::process::Output| -> u128 {
            stdout_line_with(output, "TCP_LATENCY_RESULT")
                .rsplit_once('=')
                .expect("elapsed_nanos=N")
                .1
                .parse()
                .expect("elapsed nanos")
        };

        // Control: a zero-latency link completes the round trip in the calls'
        // own charges (under a microsecond each).
        let clean = invoke(workspace, &["run", &bin, "--seed", "5"]);
        assert!(elapsed_of(&clean) < 10_000);

        // MUST delay: each of the two segments (request and reply) carries the base
        // latency, so the round trip costs at least twice it.
        let delayed = invoke(
            workspace,
            &["run", &bin, "--seed", "5", "--net-latency-nanos", "1000000"],
        );
        let elapsed = elapsed_of(&delayed);
        assert!(
            elapsed >= 2_000_000,
            "TCP base latency is inert on the stream path: round trip took {elapsed}ns"
        );
    }

    // TCP-stream fault injection end to end. The datagram-only reputation of the net
    // fault knobs was a real bug (they were inert on the stream path); this locks in
    // the fixed contract: on the SimNet TCP path the knobs (a) reproduce a
    // same-seed run byte-identically, (b) record + strict-replay byte-identically,
    // (c) differ across seeds, (d) differ from the no-fault run at the same seed
    // (non-vacuity — the fault is not silently ignored), while NEVER losing data (a
    // reliable stream: the checksum is invariant), and (e) the default-on vacuity
    // diagnostic reports the faults as APPLIED (`vacuous=0`) and stays silent — no
    // "net fault knobs inert" warning — precisely because they now bite.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_tcp_stream_faults_are_deterministic_replayable_and_non_vacuous() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("tcp_echo.rs");
        fs::write(&source, TCP_ECHO_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("tcp-echo");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let bin_str = bin.to_str().unwrap().to_owned();
        let trace_path = |name: &str| directory.path().join(name);
        let run_fault = |seed: &str, trace: &Path| {
            invoke(
                workspace,
                &[
                    "run",
                    &bin_str,
                    "--seed",
                    seed,
                    "--record",
                    trace.to_str().unwrap(),
                    "--net-jitter-nanos",
                    "1000..50000",
                    "--net-drop-permille",
                    "100",
                ],
            )
        };

        let f1 = trace_path("fault1.patina");
        let f2 = trace_path("fault2.patina");
        let nf = trace_path("nofault.patina");
        let f_seed2 = trace_path("fault_seed2.patina");

        let out1 = run_fault("1", &f1);
        let out2 = run_fault("1", &f2);
        let out_seed2 = run_fault("2", &f_seed2);
        let out_nofault = invoke(
            workspace,
            &[
                "run",
                &bin_str,
                "--seed",
                "1",
                "--record",
                nf.to_str().unwrap(),
            ],
        );

        let result1 = stdout_line_with(&out1, "TCP_ECHO_RESULT");
        // (a) same-seed byte-identical: identical result line AND identical trace.
        assert_eq!(
            result1,
            stdout_line_with(&out2, "TCP_ECHO_RESULT"),
            "same-seed fault runs must produce the same result line"
        );
        let f1_bytes = fs::read(&f1).unwrap();
        assert_eq!(
            f1_bytes,
            fs::read(&f2).unwrap(),
            "same-seed fault runs must record byte-identical traces"
        );

        // (b) record + strict replay byte-identical.
        let replayed = invoke(workspace, &["replay", &bin_str, f1.to_str().unwrap()]);
        assert_eq!(
            result1,
            stdout_line_with(&replayed, "TCP_ECHO_RESULT"),
            "strict replay of a faulted TCP run must reproduce the result line"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stderr).contains("net fault knobs inert"),
            "replay of a genuinely-faulted run must not raise the vacuity warning"
        );

        // (c) different seed differs.
        assert_ne!(
            f1_bytes,
            fs::read(&f_seed2).unwrap(),
            "a different seed must draw a different fault schedule"
        );
        let _ = &out_seed2;

        // (d) non-vacuity: the faulted trace differs from the no-fault trace at the
        // same seed — the knobs are NOT silently ignored on the stream path.
        assert_ne!(
            f1_bytes,
            fs::read(&nf).unwrap(),
            "the fault knobs must perturb the TCP trace (non-vacuity)"
        );

        // Reliability: a stream never loses data, so the checksum is invariant
        // across the fault and no-fault runs.
        assert_eq!(
            result1,
            stdout_line_with(&out_nofault, "TCP_ECHO_RESULT"),
            "TCP faults must reorder/delay but never lose data — result invariant"
        );

        // (e) the default-on diagnostic reports the faults as applied and stays
        // silent (no false-positive vacuity warning).
        let stderr1 = String::from_utf8_lossy(&out1.stderr);
        assert!(
            stderr1.contains("PATINA_NET_FAULT_REPORT") && stderr1.contains("vacuous=0"),
            "the net fault report must show the faults were applied:\nstderr:\n{stderr1}"
        );
        assert!(
            !stderr1.contains("net fault knobs inert"),
            "the vacuity warning must NOT fire when faults actually applied:\nstderr:\n{stderr1}"
        );
    }
}
