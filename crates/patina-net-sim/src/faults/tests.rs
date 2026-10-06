//! Seeded network faults, delivery schedules, and vacuity diagnostics tests.

use crate::SimNet;
use patina_dst_abi::{ErrorCode, SendDisposition};
use patina_dst_driver_api::NetDriver;
use patina_dst_rng_seeded::{domain_seed, fault_domain};
use std::collections::BTreeSet;
#[test]
fn partitions_drop_without_silently_routing_to_the_host() {
    let mut net = SimNet::builder()
        .partition("left", "right")
        .build()
        .unwrap();
    let left = net.bind("left").unwrap();
    let right = net.bind("right").unwrap();
    let report = net.send(left, "right", b"lost", 0).unwrap();
    assert_eq!(report.disposition, SendDisposition::DroppedByPartition);
    assert_eq!(report.copies, 0);
    assert_eq!(net.recv(right, u64::MAX).unwrap(), None);
}

/// Send `count` numbered datagrams at send-time zero and drain them in
/// delivery order, returning the sequence numbers actually received.
fn delivered_order(net: &mut SimNet, count: u32) -> Vec<u32> {
    let tx = net.bind("tx").unwrap();
    let rx = net.bind("rx").unwrap();
    for seq in 0..count {
        net.send(tx, "rx", &seq.to_le_bytes(), 0).unwrap();
    }
    let mut received = Vec::new();
    while let Some(datagram) = net.recv(rx, u64::MAX).unwrap() {
        received.push(u32::from_le_bytes(datagram.bytes.try_into().unwrap()));
    }
    received
}

#[test]
fn jitter_reorders_datagrams_deterministically_per_seed() {
    // A seed that reorders: the received order differs from the send order,
    // and is byte-identical across two runs of the same configuration.
    let mut first = SimNet::builder()
        .fault_seed(7)
        .jitter_nanos(0, 1000)
        .build()
        .unwrap();
    let mut second = SimNet::builder()
        .fault_seed(7)
        .jitter_nanos(0, 1000)
        .build()
        .unwrap();
    let order_a = delivered_order(&mut first, 8);
    let order_b = delivered_order(&mut second, 8);
    assert_eq!(order_a, order_b, "same seed must reproduce delivery order");
    assert_eq!(order_a.len(), 8, "no jitter run should drop datagrams");
    let in_order: Vec<u32> = (0..8).collect();
    // At least one seed in a small sweep must actually reorder, proving the
    // knob is not vacuous.
    let any_reordered = (0..16u64).any(|seed| {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .jitter_nanos(0, 1000)
            .build()
            .unwrap();
        delivered_order(&mut net, 8) != in_order
    });
    assert!(any_reordered, "jitter never reordered across seeds");
}

#[test]
fn zero_jitter_preserves_send_order() {
    let mut net = SimNet::builder().jitter_nanos(0, 0).build().unwrap();
    assert_eq!(delivered_order(&mut net, 8), (0..8).collect::<Vec<_>>());
}

#[test]
fn drop_permille_loses_datagrams_deterministically_and_extremes_are_total() {
    // Certain drop loses everything; zero drop keeps everything.
    let mut all = SimNet::builder().drop_permille(1000).build().unwrap();
    assert!(delivered_order(&mut all, 8).is_empty());
    let mut none = SimNet::builder().drop_permille(0).build().unwrap();
    assert_eq!(delivered_order(&mut none, 8), (0..8).collect::<Vec<_>>());

    // A partial probability drops some but not all, reproducibly per seed.
    let received_a = {
        let mut net = SimNet::builder()
            .fault_seed(3)
            .drop_permille(500)
            .build()
            .unwrap();
        delivered_order(&mut net, 32)
    };
    let received_b = {
        let mut net = SimNet::builder()
            .fault_seed(3)
            .drop_permille(500)
            .build()
            .unwrap();
        delivered_order(&mut net, 32)
    };
    assert_eq!(received_a, received_b, "drops must reproduce per seed");
    assert!(
        received_a.len() < 32 && !received_a.is_empty(),
        "half-probability drop should lose some but not all of 32 datagrams, got {}",
        received_a.len()
    );
}

#[test]
fn dropped_send_reports_bytes_written_but_queues_nothing() {
    let mut net = SimNet::builder().drop_permille(1000).build().unwrap();
    let tx = net.bind("tx").unwrap();
    net.bind("rx").unwrap();
    let report = net.send(tx, "rx", b"payload", 0).unwrap();
    assert_eq!(report.written, 7);
    assert_eq!(report.copies, 0);
    assert_eq!(report.disposition, SendDisposition::DroppedByFault);
    assert_eq!(net.queued_packets(), 0);
}

// --- TCP stream fault injection (jitter + drop-retransmit) ---

/// Open one client->server stream, send each payload as its own segment
/// (retrying through backpressure without advancing time), then drain the
/// server at `t=u64::MAX` (all deadlines due). Returns the concatenated
/// delivered bytes — the byte content and order the receiver observes.
fn tcp_stream_delivered(net: &mut SimNet, payloads: &[&[u8]]) -> Vec<u8> {
    let listener = net.tcp_listen("server", payloads.len().max(1)).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    for payload in payloads {
        let mut offset = 0;
        while offset < payload.len() {
            offset += net.tcp_send(client, &payload[offset..], 0).unwrap();
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = net.tcp_recv(server, 4096, u64::MAX).unwrap() {
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(&chunk);
    }
    out
}

#[test]
fn tcp_base_latency_delays_delivery_without_fault_knobs() {
    let mut net = SimNet::builder().base_latency_nanos(50).build().unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"latency", 0).unwrap(), 7);
    assert_eq!(net.tcp_recv(server, 16, 49).unwrap(), None);
    assert_eq!(net.next_delivery(server, 0).unwrap(), Some(50));
    assert_eq!(net.tcp_recv(server, 16, 50).unwrap().unwrap(), b"latency");
}

#[test]
fn tcp_jitter_delays_delivery_preserves_order_and_reproduces_per_seed() {
    // A nonzero jitter floor pushes every segment past t=0.
    let mut net = SimNet::builder()
        .fault_seed(9)
        .jitter_nanos(1_000, 5_000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 8).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"aa", 0).unwrap(), 2);
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap(),
        None,
        "jitter must delay TCP delivery past the send instant"
    );
    assert_eq!(net.tcp_recv(server, 16, u64::MAX).unwrap().unwrap(), b"aa");

    // Same seed reproduces byte-for-byte; order preserved; nothing lost.
    let payloads: [&[u8]; 4] = [b"aa", b"bb", b"cc", b"dd"];
    let mut first = SimNet::builder()
        .fault_seed(9)
        .jitter_nanos(1_000, 5_000)
        .build()
        .unwrap();
    let mut second = SimNet::builder()
        .fault_seed(9)
        .jitter_nanos(1_000, 5_000)
        .build()
        .unwrap();
    let delivered = tcp_stream_delivered(&mut first, &payloads);
    assert_eq!(
        delivered,
        tcp_stream_delivered(&mut second, &payloads),
        "same seed must reproduce the delivered byte stream"
    );
    assert_eq!(
        delivered, b"aabbccdd",
        "TCP is reliable and in-order: jitter reorders across streams, never within one"
    );
    let report = first.fault_report().unwrap();
    assert!(report.send_ops >= 4);
    assert!(report.jitter_applied > 0, "jitter must register as applied");
    assert!(!report.is_vacuous());
}

#[test]
fn tcp_drop_retransmits_and_never_loses_data() {
    // Certain drop: every segment exhausts the retransmit budget, so
    // delivery is delayed, but a reliable stream still delivers every byte.
    let mut net = SimNet::builder()
        .fault_seed(1)
        .drop_permille(1000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"reliable", 0).unwrap(), 8);
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap(),
        None,
        "a dropped segment is retransmitted (delayed), not readable immediately"
    );
    assert_eq!(
        net.tcp_recv(server, 16, u64::MAX).unwrap().unwrap(),
        b"reliable",
        "TCP drop must never lose data"
    );
    let report = net.fault_report().unwrap();
    assert_eq!(report.drops_applied, 1);
    assert_eq!(report.jitter_applied, 0, "no jitter knob was configured");
}

#[test]
fn tcp_jitter_delivery_time_varies_across_seeds() {
    fn first_delivery(seed: u64) -> u64 {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .jitter_nanos(1, 1_000_000)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"x", 0).unwrap();
        net.next_delivery(server, 0)
            .unwrap()
            .expect("a delayed segment has a future delivery time")
    }
    // Different seeds draw different jitter, so the delivery schedule differs
    // — the fault is not a constant.
    let distinct = (0..8u64).map(first_delivery).collect::<BTreeSet<_>>();
    assert!(
        distinct.len() > 1,
        "jitter delivery time must vary across seeds, got {distinct:?}"
    );
}

#[test]
fn tcp_without_fault_knobs_perturbs_nothing() {
    // The knobs-off default draws no fault RNG and delivers immediately, so
    // every pre-fault TCP test stays byte-identical.
    let mut net = SimNet::new();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    net.tcp_send(client, b"hi", 0).unwrap();
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap().unwrap(),
        b"hi",
        "no delay without fault knobs"
    );
    assert!(
        net.fault_report().is_none(),
        "a network with no knob live models no faults and must not be diagnosable"
    );
}

#[test]
fn fault_report_is_vacuous_exactly_on_the_silent_inertness_signature() {
    use patina_dst_driver_api::NetFaultReport;
    // The signature the pre-fix inert TCP path produced: a knob armed to
    // perturb, traffic occurred, yet zero effects — the bug this diagnostic
    // exists to catch.
    assert!(
        NetFaultReport {
            send_ops: 5,
            drop_vacuity_diagnosable: true,
            drops_applied: 0,
            ..NetFaultReport::default()
        }
        .is_vacuous()
    );
    // Faults actually landed.
    assert!(
        !NetFaultReport {
            send_ops: 5,
            drop_vacuity_diagnosable: true,
            drops_applied: 3,
            ..NetFaultReport::default()
        }
        .is_vacuous()
    );
    // A knob whose rate over the traffic it saw never expected a fire —
    // silence is ordinary sampling, not inertness.
    assert!(
        !NetFaultReport {
            send_ops: 5,
            ..NetFaultReport::default()
        }
        .is_vacuous()
    );
    // No fault-eligible traffic — nothing to perturb.
    assert!(!NetFaultReport::default().is_vacuous());
    assert!(!NetFaultReport::default().had_opportunities());

    // The reason the report is PER CLASS. Before Wave E one merged
    // `faults_applied` counter answered for every knob, so this shape —
    // drops landing while an equally-live jitter knob applied nothing —
    // read as "faults applied" and the inert class stayed invisible.
    let merged_would_have_hidden_it = NetFaultReport {
        send_ops: 100,
        drop_vacuity_diagnosable: true,
        drops_applied: 30,
        jitter_vacuity_diagnosable: true,
        jitter_applied: 0,
        ..NetFaultReport::default()
    };
    assert!(merged_would_have_hidden_it.is_vacuous());
    // Each remaining class fires the verdict on its own.
    for report in [
        NetFaultReport {
            latency_vacuity_diagnosable: true,
            send_ops: 10,
            ..NetFaultReport::default()
        },
        NetFaultReport {
            duplicate_vacuity_diagnosable: true,
            send_ops: 10,
            ..NetFaultReport::default()
        },
        NetFaultReport {
            connect_refuse_vacuity_diagnosable: true,
            connect_ops: 10,
            ..NetFaultReport::default()
        },
        NetFaultReport {
            reset_vacuity_diagnosable: true,
            stream_ops: 10,
            ..NetFaultReport::default()
        },
        NetFaultReport {
            partition_vacuity_diagnosable: true,
            send_ops: 10,
            ..NetFaultReport::default()
        },
    ] {
        assert!(report.is_vacuous(), "{report:?} must be vacuous");
        assert!(report.had_opportunities());
    }
}

// --- Wave E: connection-level and duplication faults ---

#[test]
fn duplicated_datagrams_arrive_twice_with_independent_delivery_times() {
    let mut net = SimNet::builder()
        .fault_seed(5)
        .duplicate_permille(1000)
        .jitter_nanos(1, 1_000)
        .build()
        .unwrap();
    let tx = net.bind("tx").unwrap();
    let rx = net.bind("rx").unwrap();
    let report = net.send(tx, "rx", b"once?", 0).unwrap();
    assert_eq!(report.copies, 2);
    assert_eq!(report.delivery_nanos.len(), 2);
    assert_ne!(
        report.delivery_nanos[0], report.delivery_nanos[1],
        "each copy draws its own jitter, so the twins separate in time"
    );
    assert_eq!(net.recv(rx, u64::MAX).unwrap().unwrap().bytes, b"once?");
    assert_eq!(
        net.recv(rx, u64::MAX).unwrap().unwrap().bytes,
        b"once?",
        "the duplicate must be observable at the receiver"
    );
    let fault_report = net.fault_report().unwrap();
    assert_eq!(fault_report.duplicates_applied, 1);
    assert!(!fault_report.is_vacuous());
}

#[test]
fn duplication_is_seed_deterministic_and_varies_across_seeds() {
    fn duplicated(seed: u64) -> Vec<usize> {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .duplicate_permille(500)
            .build()
            .unwrap();
        let tx = net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        (0..32)
            .map(|index| net.send(tx, "rx", &[index as u8], 0).unwrap().copies)
            .collect()
    }
    for seed in 0..16 {
        assert_eq!(duplicated(seed), duplicated(seed), "seed {seed}");
    }
    let distinct = (0..16u64).map(duplicated).collect::<BTreeSet<_>>();
    assert!(distinct.len() > 1, "duplication must vary across seeds");
    let one_run = duplicated(3);
    assert!(one_run.contains(&2) && one_run.contains(&1));
}

#[test]
fn connect_refusal_fires_only_on_connects_that_would_have_succeeded() {
    let mut net = SimNet::builder()
        .fault_seed(2)
        .connect_refuse_permille(1000)
        .build()
        .unwrap();
    // No listener: refused by semantics, and NOT counted as a fault
    // opportunity — the injector cannot claim credit for it.
    assert_eq!(
        net.tcp_connect("client", "absent", 0).unwrap_err().code,
        ErrorCode::ConnectionRefused
    );
    assert_eq!(net.fault_report().unwrap().connect_ops, 0);

    net.tcp_listen("server", 4).unwrap();
    let error = net.tcp_connect("client", "server", 0).unwrap_err();
    assert_eq!(error.code, ErrorCode::ConnectionRefused);
    assert!(error.message.contains("injected"), "{error:?}");
    let report = net.fault_report().unwrap();
    assert_eq!(report.connect_ops, 1);
    assert_eq!(report.connects_refused, 1);
    assert!(!report.is_vacuous());
}

#[test]
fn connect_refusal_is_seed_deterministic_and_leaves_the_listener_usable() {
    fn refusals(seed: u64) -> Vec<bool> {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .connect_refuse_permille(500)
            .build()
            .unwrap();
        net.tcp_listen("server", 64).unwrap();
        (0..32)
            .map(|index| {
                net.tcp_connect(&format!("client-{index}"), "server", 0)
                    .is_err()
            })
            .collect()
    }
    for seed in 0..16 {
        assert_eq!(refusals(seed), refusals(seed), "seed {seed}");
    }
    let one_run = refusals(1);
    assert!(
        one_run.contains(&true) && one_run.contains(&false),
        "a half-rate refusal must both refuse and admit: {one_run:?}"
    );
    assert!((0..16u64).map(refusals).collect::<BTreeSet<_>>().len() > 1);
}

#[test]
fn an_injected_reset_tears_down_both_directions() {
    let mut net = SimNet::builder()
        .fault_seed(1)
        .reset_permille(1000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(
        net.tcp_send(client, b"doomed", 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
    // The peer sees the reset too: a reset is not one-sided.
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
    assert_eq!(
        net.tcp_send(client, b"again", 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
    let report = net.fault_report().unwrap();
    assert_eq!(report.stream_ops, 1, "the reset op is the only opportunity");
    assert_eq!(report.resets_injected, 1);
    assert!(!report.is_vacuous());
}

#[test]
fn a_receiving_endpoint_can_be_reset_and_would_block_polls_do_not_draw() {
    let mut net = SimNet::builder()
        .fault_seed(1)
        .reset_permille(1000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    // A poll with nothing to read is not a data operation, so it neither
    // draws nor counts — a reset must not get likelier the harder a guest
    // spins.
    assert_eq!(net.tcp_recv(server, 16, 0).unwrap(), None);
    assert_eq!(net.fault_report().unwrap().stream_ops, 0);
    assert_eq!(
        net.tcp_send(client, b"x", 0).unwrap_err().code,
        ErrorCode::ConnectionReset
    );
}

#[test]
fn reset_is_seed_deterministic_and_varies_across_seeds() {
    fn sends_before_reset(seed: u64) -> usize {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .reset_permille(200)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        for index in 0..64 {
            if net.tcp_send(client, b"x", 0).is_err() {
                return index;
            }
            // Drain so the small buffer never becomes the limiting factor.
            let _ = net.tcp_recv(server, 64, u64::MAX);
        }
        64
    }
    for seed in 0..8 {
        assert_eq!(sends_before_reset(seed), sends_before_reset(seed));
    }
    let distinct = (0..16u64).map(sends_before_reset).collect::<BTreeSet<_>>();
    assert!(distinct.len() > 1, "reset timing must vary across seeds");
}

#[test]
fn a_partition_that_names_unused_addresses_is_vacuous() {
    // The operator-error signature: a partition spelled for addresses this
    // run never uses blocks nothing, and a clean result would otherwise read
    // as "tested under partition".
    let mut net = SimNet::builder()
        .partition("10.0.0.1:1", "10.0.0.2:2")
        .build()
        .unwrap();
    let tx = net.bind("tx").unwrap();
    net.bind("rx").unwrap();
    for _ in 0..8 {
        net.send(tx, "rx", b"through", 0).unwrap();
    }
    let report = net.fault_report().unwrap();
    assert!(report.partition_vacuity_diagnosable);
    assert_eq!(report.partition_blocks, 0);
    assert!(report.is_vacuous());

    // A partition that matches the traffic blocks it, and is not vacuous.
    let mut net = SimNet::builder().partition("tx", "rx").build().unwrap();
    let tx = net.bind("tx").unwrap();
    net.bind("rx").unwrap();
    for _ in 0..8 {
        net.send(tx, "rx", b"blocked", 0).unwrap();
    }
    let report = net.fault_report().unwrap();
    assert_eq!(report.partition_blocks, 8);
    assert!(!report.is_vacuous());
}

#[test]
fn the_base_latency_class_catches_a_send_path_that_ignores_it() {
    // Defect 2's signature, now a first-class report row: the knob is set,
    // sends happened, and the path applied it zero times. A TCP send that
    // skipped `base_latency_nanos` (as the pre-Wave-A stream path did) lands
    // exactly here instead of reading clean.
    let mut net = SimNet::builder().base_latency_nanos(50).build().unwrap();
    let listener = net.tcp_listen("server", 8).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    for _ in 0..8 {
        net.tcp_send(client, b"x", 0).unwrap();
        let _ = net.tcp_recv(server, 64, u64::MAX);
    }
    let report = net.fault_report().unwrap();
    assert!(report.latency_vacuity_diagnosable);
    assert_eq!(report.latency_applied, 8);
    assert!(!report.is_vacuous());
}

#[test]
fn each_net_fault_class_draws_from_its_own_substream() {
    // The property with teeth: a class's decisions must not depend on how
    // much OTHER traffic the run pushed. The connect-refusal verdicts for a
    // fixed sequence of connects are identical whether or not datagrams are
    // interleaved between them — a refusal decision taken from the shared
    // drop/jitter stream would be shifted by every intervening datagram.
    //
    // Note the direction: this compares runs whose CONNECT sequence is
    // identical. Comparing drop verdicts across armed/unarmed TCP knobs
    // would prove nothing, because a refused connect removes the stream
    // sends that follow it and so changes the workload itself.
    fn refusals(with_datagram_traffic: bool) -> Vec<bool> {
        let mut net = SimNet::builder()
            .fault_seed(11)
            .drop_permille(500)
            .jitter_nanos(1, 1_000)
            .connect_refuse_permille(500)
            .build()
            .unwrap();
        let tx = net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        net.tcp_listen("server", 64).unwrap();
        (0..32u8)
            .map(|index| {
                if with_datagram_traffic {
                    for _ in 0..3 {
                        net.send(tx, "rx", &[index], 0).unwrap();
                    }
                }
                net.tcp_connect(&format!("c-{index}"), "server", 0).is_err()
            })
            .collect()
    }
    let quiet = refusals(false);
    assert_eq!(quiet, refusals(true));
    assert!(
        quiet.contains(&true) && quiet.contains(&false),
        "the control must actually have drawn both ways, or this proves nothing"
    );

    // And the streams are not merely independent objects: they are keyed to
    // DIFFERENT domains, so two classes never draw identical sequences.
    let seeds = BTreeSet::from([
        7,
        domain_seed(7, fault_domain::NET_DUPLICATE),
        domain_seed(7, fault_domain::NET_CONNECT_REFUSE),
        domain_seed(7, fault_domain::NET_RESET),
    ]);
    assert_eq!(seeds.len(), 4, "net fault substreams must not alias");
}
