//! Seeded network faults, delivery schedules, and vacuity diagnostics tests.

use crate::SimNet;
use patina_dst_abi::{ErrorCode, SendDisposition};
use patina_dst_driver_api::NetDriver;
use std::collections::BTreeSet;
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
fn jitter_reorders_datagrams_across_seeds_and_zero_jitter_preserves_order() {
    let in_order: Vec<u32> = (0..8).collect();
    let mut net = SimNet::builder().jitter_nanos(0, 0).build().unwrap();
    assert_eq!(delivered_order(&mut net, 8), in_order);
    // At least one seed in a small sweep must actually reorder, without
    // losing anything, proving the knob is not vacuous.
    let any_reordered = (0..16u64).any(|seed| {
        let mut net = SimNet::builder()
            .fault_seed(seed)
            .jitter_nanos(0, 1000)
            .build()
            .unwrap();
        let order = delivered_order(&mut net, 8);
        assert_eq!(order.len(), 8, "jitter must not drop datagrams");
        order != in_order
    });
    assert!(any_reordered, "jitter never reordered across seeds");
}

#[test]
fn drop_permille_loses_datagrams_and_extremes_are_total() {
    // Certain drop loses everything, reports the bytes written and queues
    // nothing; zero drop keeps everything.
    let mut all = SimNet::builder().drop_permille(1000).build().unwrap();
    let tx = all.bind("tx").unwrap();
    all.bind("rx").unwrap();
    let report = all.send(tx, "rx", b"payload", 0).unwrap();
    assert_eq!(report.written, 7);
    assert_eq!(report.copies, 0);
    assert_eq!(report.disposition, SendDisposition::DroppedByFault);
    assert_eq!(all.queued_packets(), 0);
    let mut none = SimNet::builder().drop_permille(0).build().unwrap();
    assert_eq!(delivered_order(&mut none, 8), (0..8).collect::<Vec<_>>());

    // A partial probability drops some but not all.
    let mut net = SimNet::builder()
        .fault_seed(3)
        .drop_permille(500)
        .build()
        .unwrap();
    let received = delivered_order(&mut net, 32);
    assert!(
        received.len() < 32 && !received.is_empty(),
        "half-probability drop should lose some but not all of 32 datagrams, got {}",
        received.len()
    );
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

/// Base latency delays a TCP segment to exactly its delivery time, which
/// `next_delivery` reports until the segment is read; the report counts
/// every send it delayed, so a send path that skipped the latency would
/// read as vacuous rather than clean.
#[test]
fn tcp_base_latency_delays_delivery_and_is_reported_per_send() {
    let mut net = SimNet::builder().base_latency_nanos(50).build().unwrap();
    let listener = net.tcp_listen("server", 8).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"latency", 100).unwrap(), 7);
    assert_eq!(net.tcp_recv(server, 16, 149).unwrap(), None);
    assert_eq!(net.next_delivery(server, 0).unwrap(), Some(150));
    assert_eq!(net.tcp_recv(server, 16, 150).unwrap().unwrap(), b"latency");
    assert_eq!(net.next_delivery(server, 150).unwrap(), None);
    for _ in 0..7 {
        net.tcp_send(client, b"x", 0).unwrap();
        let _ = net.tcp_recv(server, 64, u64::MAX);
    }
    let report = net.fault_report().unwrap();
    assert!(report.latency_vacuity_diagnosable);
    assert_eq!(report.latency_applied, 8);
    assert!(!report.is_vacuous());
}

#[test]
fn tcp_jitter_delays_delivery_preserves_order_and_varies_across_seeds() {
    // A nonzero jitter floor pushes every segment past t=0, and TCP stays
    // reliable and in-order: jitter reorders across streams, never within one.
    let payloads: [&[u8]; 4] = [b"aa", b"bb", b"cc", b"dd"];
    let mut net = SimNet::builder()
        .fault_seed(9)
        .jitter_nanos(1_000, 5_000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    assert_eq!(net.tcp_send(client, b"aa", 0).unwrap(), 2);
    assert_eq!(
        net.tcp_recv(server, 16, 0).unwrap(),
        None,
        "jitter must delay TCP delivery past the send instant"
    );
    assert_eq!(net.tcp_recv(server, 16, u64::MAX).unwrap().unwrap(), b"aa");
    let mut net = SimNet::builder()
        .fault_seed(9)
        .jitter_nanos(1_000, 5_000)
        .build()
        .unwrap();
    assert_eq!(tcp_stream_delivered(&mut net, &payloads), b"aabbccdd");
    let report = net.fault_report().unwrap();
    assert!(report.send_ops >= 4);
    assert!(report.jitter_applied > 0, "jitter must register as applied");
    assert!(!report.is_vacuous());

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
    let distinct = (0..8u64).map(first_delivery).collect::<BTreeSet<_>>();
    assert!(
        distinct.len() > 1,
        "jitter delivery time must vary across seeds, got {distinct:?}"
    );
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
    // The inertness signature: a knob armed to perturb, traffic occurred,
    // yet zero effects.
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

    // The report is per class: drops landing while an equally live jitter
    // knob applied nothing is still vacuous, so one live class never hides
    // an inert one.
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

    // A partial rate both duplicates and does not, differently per seed.
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
    let one_run = duplicated(3);
    assert!(one_run.contains(&2) && one_run.contains(&1));
    let distinct = (0..16u64).map(duplicated).collect::<BTreeSet<_>>();
    assert!(distinct.len() > 1, "duplication must vary across seeds");
}

#[test]
fn stream_sends_are_no_opportunity_for_the_datagram_only_duplicate_class() {
    let mut net = SimNet::builder()
        .fault_seed(5)
        .duplicate_permille(1000)
        .build()
        .unwrap();
    let payloads = [b"segment".as_slice(); 64];
    tcp_stream_delivered(&mut net, &payloads);
    let tcp_only = net.fault_report().unwrap();
    assert!(tcp_only.send_ops >= 64);
    assert_eq!(tcp_only.duplicates_applied, 0);
    assert!(
        !tcp_only.duplicate_vacuity_diagnosable,
        "a TCP-only run offers duplication nothing to copy"
    );
    assert!(!tcp_only.is_vacuous());

    let tx = net.bind("tx").unwrap();
    net.bind("rx").unwrap();
    for _ in 0..5 {
        net.send(tx, "rx", b"datagram", 0).unwrap();
    }
    let with_datagrams = net.fault_report().unwrap();
    assert!(with_datagrams.duplicate_vacuity_diagnosable);
    assert_eq!(with_datagrams.duplicates_applied, 5);
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

    // A half rate both refuses and admits, leaving the listener usable, and
    // its verdicts vary across seeds.
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
    let one_run = refusals(1);
    assert!(
        one_run.contains(&true) && one_run.contains(&false),
        "a half-rate refusal must both refuse and admit: {one_run:?}"
    );
    assert!((0..16u64).map(refusals).collect::<BTreeSet<_>>().len() > 1);
}

#[test]
fn an_injected_reset_tears_down_both_directions_and_idle_polls_never_draw() {
    let mut net = SimNet::builder()
        .fault_seed(1)
        .reset_permille(1000)
        .build()
        .unwrap();
    let listener = net.tcp_listen("server", 1).unwrap();
    let client = net.tcp_connect("client", "server", 0).unwrap();
    let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
    // A poll with nothing to read is not a data operation, so it neither
    // draws nor counts: a reset must not get likelier the harder a guest
    // spins.
    assert_eq!(net.tcp_recv(server, 16, 0).unwrap(), None);
    assert_eq!(net.fault_report().unwrap().stream_ops, 0);
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

    // At a partial rate the reset lands at a seed-dependent point.
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
    let distinct = (0..16u64).map(sends_before_reset).collect::<BTreeSet<_>>();
    assert!(distinct.len() > 1, "reset timing must vary across seeds");
}

#[test]
fn a_partition_drops_matching_traffic_and_is_vacuous_on_unused_addresses() {
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

    // A partition that matches the traffic drops it rather than routing it
    // anywhere, and is not vacuous.
    let mut net = SimNet::builder().partition("tx", "rx").build().unwrap();
    let tx = net.bind("tx").unwrap();
    let rx = net.bind("rx").unwrap();
    for _ in 0..8 {
        let report = net.send(tx, "rx", b"blocked", 0).unwrap();
        assert_eq!(report.disposition, SendDisposition::DroppedByPartition);
        assert_eq!(report.copies, 0);
    }
    assert_eq!(net.recv(rx, u64::MAX).unwrap(), None);
    let report = net.fault_report().unwrap();
    assert_eq!(report.partition_blocks, 8);
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
}
