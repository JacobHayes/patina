//! Tests for simulated TCP, backpressure, and record/replay.

use super::*;
use crate::{block_on, spawn, yield_now};
use patina_dst_abi::ClockKind;
use patina_dst_net_sim::SimNet;
use patina_dst_runtime::{RuntimeBuilder, RuntimeConfig};
use patina_dst_wrapper_latency::LatencyNet;
use std::cell::RefCell;
use std::fs;
use std::rc::Rc;

async fn tcp_echo_scenario(order: Rc<RefCell<Vec<&'static str>>>) -> Result<Vec<u8>, RuntimeError> {
    let listener = TcpListener::listen("server", 8).await?;
    let server = spawn("server", {
        let order = Rc::clone(&order);
        async move {
            let stream = listener.accept().await?;
            order.borrow_mut().push("server-accepted");
            let bytes = stream.read(16).await?;
            order.borrow_mut().push("server-read");
            stream.write_all(&bytes).await?;
            Ok::<_, RuntimeError>(())
        }
    })?;
    let client = spawn("client", {
        let order = Rc::clone(&order);
        async move {
            let stream = TcpStream::connect("client", "server").await?;
            stream.write_all(b"hello").await?;
            order.borrow_mut().push("client-wrote");
            let echoed = stream.read(16).await?;
            Ok::<_, RuntimeError>(echoed)
        }
    })?;
    let echoed = client.await??;
    server.await??;
    Ok(echoed)
}

#[test]
fn async_tcp_echo_over_simnet() {
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(8))
        .with_default_drivers()
        .with_network(SimNet::new())
        .build()
        .unwrap();
    let order = Rc::new(RefCell::new(Vec::new()));
    let echoed = block_on(&mut ctx, tcp_echo_scenario(Rc::clone(&order)))
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"hello");
    // The reader (server) is spawned before the writer and its `read` blocks
    // until the client's bytes arrive, so it must observe them only after the
    // client's write — a real park + peer-wake ordering, not just presence.
    let log = order.borrow();
    let wrote = log
        .iter()
        .position(|event| *event == "client-wrote")
        .expect("client recorded its write");
    let read = log
        .iter()
        .position(|event| *event == "server-read")
        .expect("server recorded its read");
    assert!(
        wrote < read,
        "server must observe the payload only after the client wrote it: {log:?}"
    );
    drop(log);
    ctx.finish().unwrap();
}

#[test]
fn tcp_latency_uses_timed_net_delivery() {
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(9))
        .with_default_drivers()
        .with_network(LatencyNet::new(SimNet::new(), 1).latency_nanos(75))
        .build()
        .unwrap();
    block_on(&mut ctx, async {
        let listener = TcpListener::listen("server", 1).await?;
        let client = TcpStream::connect("client", "server").await?;
        let server = listener.accept().await?;
        client.write_all(b"x").await?;
        assert_eq!(server.read(8).await?, b"x");
        let now = with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))?;
        assert_eq!(now, patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS + 75);
        Ok::<_, RuntimeError>(())
    })
    .unwrap()
    .unwrap();
    ctx.finish().unwrap();
}

#[test]
fn tcp_backpressure_wakes_writer_when_reader_drains() {
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(11))
        .with_default_drivers()
        .with_network(SimNet::builder().tcp_buffer_bytes(4).build().unwrap())
        .build()
        .unwrap();
    let data: Vec<u8> = (0..12).collect();
    let received = block_on(&mut ctx, {
        let data = data.clone();
        async move {
            let listener = TcpListener::listen("server", 1).await?;
            let client = TcpStream::connect("client", "server").await?;
            let server = listener.accept().await?;
            let writer = spawn("writer", async move {
                client.write_all(&data).await?;
                Ok::<_, RuntimeError>(())
            })?;
            let mut out = Vec::new();
            while out.len() < 12 {
                let chunk = server.read(3).await?;
                out.extend_from_slice(&chunk);
                yield_now().await;
            }
            writer.await??;
            Ok::<_, RuntimeError>(out)
        }
    })
    .unwrap()
    .unwrap();
    assert_eq!(received, (0..12).collect::<Vec<u8>>());
    ctx.finish().unwrap();
}

fn run_recorded_echo(config: RuntimeConfig) -> Result<Vec<u8>, RuntimeError> {
    let mut ctx = RuntimeBuilder::new(config)
        .with_default_drivers()
        .with_network(SimNet::new())
        .build()?;
    let result = block_on(
        &mut ctx,
        tcp_echo_scenario(Rc::new(RefCell::new(Vec::new()))),
    )?;
    let finish = ctx.finish();
    match (result, finish) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run), Err(finalize)) => Err(RuntimeError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

#[test]
fn record_replay_byte_identity_for_echo() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.patina");
    let second = dir.path().join("second.patina");
    assert_eq!(
        run_recorded_echo(RuntimeConfig::record(12, &first, "async-echo-v1")).unwrap(),
        b"hello"
    );
    assert_eq!(
        run_recorded_echo(RuntimeConfig::record(12, &second, "async-echo-v1")).unwrap(),
        b"hello"
    );
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    assert_eq!(
        run_recorded_echo(RuntimeConfig::replay(&first, "async-echo-v1")).unwrap(),
        b"hello"
    );
}

#[test]
fn replay_rejects_divergent_echo_payload() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.patina");
    run_recorded_echo(RuntimeConfig::record(13, &trace, "async-echo-v1")).unwrap();
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::replay(&trace, "async-echo-v1"))
        .with_default_drivers()
        .with_network(SimNet::new())
        .build()
        .unwrap();
    let result = block_on(&mut ctx, async {
        let listener = TcpListener::listen("server", 8).await?;
        let server = spawn("server", async move {
            let stream = listener.accept().await?;
            let bytes = stream.read(16).await?;
            stream.write_all(&bytes).await?;
            Ok::<_, RuntimeError>(())
        })?;
        let client = spawn("client", async move {
            let stream = TcpStream::connect("client", "server").await?;
            stream.write_all(b"jello").await?;
            stream.read(16).await
        })?;
        let echoed = client.await??;
        server.await??;
        Ok::<_, RuntimeError>(echoed)
    });
    assert!(matches!(result, Err(RuntimeError::Trace(_))));
}
