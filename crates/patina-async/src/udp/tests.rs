//! Tests for simulated UDP delivery.

use super::*;
use crate::{block_on, spawn, yield_now};
use patina_dst_abi::ClockKind;
use patina_dst_net_sim::SimNet;
use patina_dst_runtime::{RuntimeBuilder, RuntimeConfig};
use patina_dst_wrapper_latency::LatencyNet;

#[test]
fn udp_echo_under_latency_advances_exactly_to_delivery() {
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(10))
        .with_default_drivers()
        .with_network(LatencyNet::new(SimNet::new(), 1).latency_nanos(50))
        .build()
        .unwrap();
    let payload = block_on(&mut ctx, async {
        let server = UdpSocket::bind("server").await?;
        let client = UdpSocket::bind("client").await?;
        let recv = spawn("udp-recv", async move {
            let datagram = server.recv().await?;
            let now = with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))?;
            assert_eq!(now, patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS + 50);
            assert_eq!(datagram.delivery_nanos, now);
            Ok::<_, RuntimeError>(datagram.bytes)
        })?;
        yield_now().await;
        client.send_to("server", b"ping").await?;
        recv.await?
    })
    .unwrap()
    .unwrap();
    assert_eq!(payload, b"ping");
    ctx.finish().unwrap();
}
